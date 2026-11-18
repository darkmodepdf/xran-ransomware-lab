"""Fit and evaluate a fixed API-only configuration on prepared report traces."""

import argparse
import hashlib
import json
import math
import os
import platform
import random
import time
from collections import Counter
from pathlib import Path

import torch
from torch.nn.utils.rnn import pad_sequence

from .core import (
    EARLY_OBSERVATIONS, SequenceModel, choose_threshold, earliness, encode,
    first_alert, load_traces, sample_early_endpoints, sample_endpoints,
    score_blocks, train_vocabulary,
)


ALPHAS = (0.05, 0.01)


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def atomic_torch(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    torch.save(value, temporary)
    with temporary.open("r+b") as stream:
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def checkpoint(run_dir, identity, model, optimizer, epoch, cursor, step, device):
    pointer = run_dir / "recovery.json"
    last = json.loads(pointer.read_text(encoding="utf-8"))["slot"] if pointer.exists() else 1
    slot = 1 - last
    path = run_dir / f"recovery-{slot}.pt"
    atomic_torch(path, {
        "identity": identity,
        "model": model.state_dict(),
        "optimizer": optimizer.state_dict(),
        "epoch": epoch,
        "cursor": cursor,
        "step": step,
        "python_rng": random.getstate(),
        "torch_rng": torch.get_rng_state(),
        "cuda_rng": torch.cuda.get_rng_state(device) if device.type == "cuda" else None,
    })
    atomic_json(pointer, {"slot": slot, "sha256": digest(path), "step": step})
    print(f"Checkpoint committed at step {step}", flush=True)


def restore(run_dir, identity, model, optimizer, device):
    pointer = json.loads((run_dir / "recovery.json").read_text(encoding="utf-8"))
    if pointer.get("slot") not in (0, 1):
        raise ValueError("Unknown recovery slot")
    path = run_dir / f"recovery-{pointer['slot']}.pt"
    if digest(path) != pointer["sha256"]:
        raise ValueError("Recovery checkpoint checksum mismatch")
    state = torch.load(path, map_location="cpu", weights_only=True)
    if identity != state["identity"] or pointer["step"] != state["step"]:
        raise ValueError("Recovery state is incompatible with this dataset, code, endpoint manifest or configuration")
    model.load_state_dict(state["model"])
    optimizer.load_state_dict(state["optimizer"])
    random.setstate(state["python_rng"])
    torch.set_rng_state(state["torch_rng"])
    if device.type == "cuda":
        torch.cuda.set_rng_state(state["cuda_rng"], device)
    return state["epoch"], state["cursor"], state["step"]


def make_endpoints(train, encoded, limit, data_seed, policy="standard", early_loss_weight=1.0):
    rng = random.Random(data_seed)
    sampler = sample_early_endpoints if policy == "early" else sample_endpoints
    positions = {trace.trace_id: sampler(len(encoded[trace.trace_id]), limit, rng) for trace in train}
    endpoints = []
    scale = max(1.0, early_loss_weight)
    for trace in train:
        selected = positions[trace.trace_id]
        factors = [(early_loss_weight if position <= EARLY_OBSERVATIONS else 1.0) / scale for position in selected]
        total = math.fsum(factors)
        label = float(trace.label == "RANSOMWARE")
        endpoints.extend((trace.trace_id, position, label, factor / total) for position, factor in zip(selected, factors))
    return positions, endpoints


def fit_counts(model, endpoints, encoded, args):
    from scipy.sparse import csr_matrix
    from sklearn.linear_model import LogisticRegression
    from sklearn.preprocessing import StandardScaler

    rows, columns, values = [], [], []
    for row, (trace_id, position, _, _) in enumerate(endpoints):
        start = ((position - 1) // args.block_size) * args.block_size
        for token, count in Counter(encoded[trace_id][start:position]).items():
            rows.append(row)
            columns.append(token)
            values.append(count)
    matrix = csr_matrix((values, (rows, columns)), shape=(len(endpoints), model.coefficient.numel()), dtype="float64")
    weights = [weight for _, _, _, weight in endpoints]
    scaler = StandardScaler(with_mean=False).fit(matrix, sample_weight=weights)
    classifier = LogisticRegression(C=args.regularization, max_iter=2000, random_state=args.seed)
    classifier.fit(scaler.transform(matrix), [label for _, _, label, _ in endpoints], sample_weight=weights)
    if classifier.n_iter_.max() >= classifier.max_iter:
        raise ValueError("Counts model did not converge")
    with torch.no_grad():
        model.coefficient.copy_(torch.as_tensor(classifier.coef_[0] / scaler.scale_))
        model.bias.fill_(classifier.intercept_[0])


def fit_neural(model, endpoints, encoded, args, identity, device, started):
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)
    epoch, cursor, step = restore(args.run_dir, identity, model, optimizer, device) if args.resume else (0, 0, 0)
    last_save = time.monotonic()
    mean_weight = sum(endpoint[3] for endpoint in endpoints) / len(endpoints)
    while epoch < args.epochs:
        model.train()
        last_loss = None
        order = list(range(len(endpoints)))
        random.Random(args.seed + epoch).shuffle(order)
        while cursor < len(order):
            if args.stop_after_steps and step >= args.stop_after_steps:
                checkpoint(args.run_dir, identity, model, optimizer, epoch, cursor, step, device)
                return False
            if args.budget_minutes and (time.monotonic() - started) >= (args.budget_minutes - args.reserve_minutes) * 60:
                checkpoint(args.run_dir, identity, model, optimizer, epoch, cursor, step, device)
                return False
            batch_ids = order[cursor:cursor + args.batch_size]
            sequences, labels, weights = [], [], []
            for index in batch_ids:
                trace_id, position, label, weight = endpoints[index]
                start = ((position - 1) // args.block_size) * args.block_size
                sequences.append(torch.tensor(encoded[trace_id][start:position], dtype=torch.long))
                labels.append(label)
                weights.append(weight / mean_weight)
            lengths = torch.tensor([sequence.numel() - 1 for sequence in sequences], device=device)
            tokens = pad_sequence(sequences, batch_first=True).to(device)
            model.zero_grad(set_to_none=True)
            logits = model(tokens)[torch.arange(len(batch_ids), device=device), lengths]
            loss = torch.nn.functional.binary_cross_entropy_with_logits(
                logits, torch.tensor(labels, device=device), weight=torch.tensor(weights, device=device),
            )
            if not torch.isfinite(loss).item():
                raise ValueError(f"Nonfinite training loss at step {step}")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0, error_if_nonfinite=True)
            optimizer.step()
            last_loss = loss.item()
            cursor += len(batch_ids)
            step += 1
            if time.monotonic() - last_save >= args.checkpoint_seconds:
                checkpoint(args.run_dir, identity, model, optimizer, epoch, cursor, step, device)
                last_save = time.monotonic()
        epoch += 1
        cursor = 0
        loss_status = "resumed at epoch boundary" if last_loss is None else f"last batch loss {last_loss:.6f}"
        print(f"Epoch {epoch}/{args.epochs}, step {step}, {loss_status}", flush=True)
        checkpoint(args.run_dir, identity, model, optimizer, epoch, cursor, step, device)
        last_save = time.monotonic()
    return True


def score_roles(model, traces, encoded, args, device):
    def scores_for(trace):
        return list(score_blocks(model, encoded[trace.trace_id], args.block_size, device))

    tune_benign = [max(scores_for(trace)) for trace in traces if trace.role == "tune" and trace.label == "BENIGN" and encoded[trace.trace_id]]
    tune_threshold = choose_threshold(tune_benign, args.target_fpr)
    grid_values = []
    caught_early = 0
    for trace in traces:
        if trace.role == "tune" and trace.label == "RANSOMWARE" and encoded[trace.trace_id]:
            scores = scores_for(trace)
            alert = first_alert(scores, tune_threshold)
            grid_values.append(earliness(alert, len(scores)))
            caught_early += alert is not None and alert <= EARLY_OBSERVATIONS
    tune = {
        "threshold": tune_threshold,
        "grid_mean": sum(grid_values) / len(grid_values),
        "positives": len(grid_values),
        "early120": caught_early / len(grid_values),
        "objective": args.tune_objective,
    }
    tune["objective_value"] = tune["early120" if args.tune_objective == "early120" else "grid_mean"]
    thresholds = []
    if not args.skip_test:
        calibration = [max(scores_for(trace)) for trace in traces if trace.role == "calibrate" and encoded[trace.trace_id]]
        alphas = tuple(dict.fromkeys((args.target_fpr, ALPHAS[1])))
        thresholds = [choose_threshold(calibration, alpha) for alpha in alphas]
    return tune, thresholds, scores_for


def evaluate_test(traces, thresholds, scores_for, destination):
    counts = [Counter() for _ in thresholds]
    temporary = destination.with_suffix(".jsonl.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for trace in traces:
            if trace.role != "test":
                continue
            scores = scores_for(trace)
            for threshold, count in zip(thresholds, counts):
                alert = first_alert(scores, threshold)
                record = {
                    "trace_id": trace.trace_id, "group_id": trace.group_id, "label": trace.label,
                    "alpha": threshold["alpha"], "first_observation": alert, "caught": alert is not None,
                    "observed_horizon": len(scores), "capped": len(scores) < len(trace.apis),
                }
                stream.write(json.dumps(record, allow_nan=False) + "\n")
                count[(trace.label, "all")] += 1
                count[(trace.label, "eligible")] += bool(scores)
                count[(trace.label, "alerts")] += alert is not None
    os.replace(temporary, destination)
    return [
        {"alpha": threshold["alpha"], "strata": {
            label: {"n": count[(label, "eligible")], "valid_empty": count[(label, "all")] - count[(label, "eligible")],
                    "alerts": count[(label, "alerts")], "alert_rate": count[(label, "alerts")] / count[(label, "eligible")] if count[(label, "eligible")] else None}
            for label in ("BENIGN", "RANSOMWARE", "OTHER_MALWARE")}}
        for threshold, count in zip(thresholds, counts)
    ]


def main(argv=None):
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__, epilog="Input JSONL: {trace_id,label,role,group_id,apis:[ordered API strings]}. A development smoke uses provenance-separated train/tune/calibrate/test roles; use --skip-test for tuning runs.")
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--architecture", choices=("cnn", "gru", "counts"), default="cnn")
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--block-size", type=int, default=1024)
    parser.add_argument("--horizon", type=int, default=0, help="Maximum retained observations per trace. Zero keeps all.")
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument("--data-seed", type=int, default=771, help="Fixed endpoint seed, common to all model/seed fits.")
    parser.add_argument("--endpoints-per-trace", type=int, default=16)
    parser.add_argument("--endpoint-policy", choices=("standard", "early"), default="standard",
                        help="Early samples more endpoints through observation 120, with coverage in 121-256, 257-512 and later.")
    parser.add_argument("--early-loss-weight", type=float, default=1.0,
                        help="Loss multiplier for endpoints through observation 120, normalized within each trace.")
    parser.add_argument("--target-fpr", type=float, default=ALPHAS[0],
                        help="Nominal benign FPR cap for tuning and primary final calibration; default 0.05.")
    parser.add_argument("--tune-objective", choices=("grid", "early120"), default="grid",
                        help="Report the requested objective for external selection. early120 counts positive tuning traces alerted by observation 120.")
    parser.add_argument("--batch-size", type=int, default=32)
    parser.add_argument("--learning-rate", type=float, default=1e-3)
    parser.add_argument("--regularization", type=float, default=1.0, help="Counts model inverse regularization strength C.")
    parser.add_argument("--checkpoint-seconds", type=float, default=600)
    parser.add_argument("--budget-minutes", type=float, default=0, help="Total training process budget. Zero disables it.")
    parser.add_argument("--reserve-minutes", type=float, default=30)
    parser.add_argument("--stop-after-steps", type=int, default=0, help="Pause after this global optimizer step for a resume smoke.")
    parser.add_argument("--cpu-threads", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--skip-test", action="store_true", help="Fit/tune only, with no calibration or test scoring.")
    args = parser.parse_args(argv)
    if min(args.epochs, args.block_size, args.endpoints_per_trace, args.batch_size, args.cpu_threads) < 1:
        parser.error("epochs, block size, endpoints, batch size and CPU threads must be positive")
    real_settings = (args.learning_rate, args.regularization, args.checkpoint_seconds, args.budget_minutes, args.reserve_minutes)
    if any(not math.isfinite(value) for value in real_settings) or min(real_settings[:3]) <= 0 or min(real_settings[3:]) < 0:
        parser.error("invalid learning rate, regularization, checkpoint interval or budget")
    if not math.isfinite(args.early_loss_weight) or args.early_loss_weight <= 0:
        parser.error("early loss weight must be positive and finite")
    if not 0 <= args.target_fpr < 1:
        parser.error("target FPR must be in [0,1)")
    if min(args.horizon, args.stop_after_steps, args.seed, args.data_seed) < 0 or (args.budget_minutes and args.budget_minutes <= args.reserve_minutes):
        parser.error("invalid horizon, step limit, seed or budget reserve")
    if args.architecture == "counts" and (args.resume or args.stop_after_steps or args.device == "cuda"):
        parser.error("counts uses the CPU solver without step checkpoints")
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    torch.set_num_threads(args.cpu_threads)
    torch.use_deterministic_algorithms(True)
    device = torch.device(args.device)
    if device.type == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA device requested but unavailable")
    if args.resume:
        if not args.run_dir.is_dir() or (args.run_dir / "metrics.json").exists():
            raise ValueError("Resume requires an incomplete run directory")
    else:
        args.run_dir.mkdir(parents=True, exist_ok=False)
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    traces, data_hash = load_traces(args.data)
    train = sorted((trace for trace in traces if trace.role == "train" and trace.apis), key=lambda trace: trace.trace_id)
    support = Counter((trace.role, trace.label) for trace in traces if trace.apis)
    if not (support[("train", "RANSOMWARE")] and sum(support[("train", label)] for label in ("BENIGN", "OTHER_MALWARE"))):
        raise ValueError("Training needs nonempty positive and negative traces")
    required = [("tune", "BENIGN"), ("tune", "RANSOMWARE")]
    if not args.skip_test:
        required += [("calibrate", "BENIGN"), ("test", "BENIGN"), ("test", "RANSOMWARE")]
    for role, label in required:
        if not support[(role, label)]:
            raise ValueError(f"Missing nonempty {label} traces in {role}")
    vocabulary = train_vocabulary(train, args.horizon)
    encoded = {trace.trace_id: encode(trace.apis, vocabulary, args.horizon) for trace in traces}
    positions, endpoints = make_endpoints(
        train, encoded, args.endpoints_per_trace, args.data_seed,
        args.endpoint_policy, args.early_loss_weight,
    )
    config = {key: value for key, value in vars(args).items() if key not in {
        "data", "run_dir", "resume", "stop_after_steps", "budget_minutes", "reserve_minutes", "checkpoint_seconds",
    }}
    identity = {
        "config": config, "data_sha256": data_hash, "torch": str(torch.__version__),
        "device_name": torch.cuda.get_device_name(0) if device.type == "cuda" else platform.machine(),
        "code_sha256": {name: digest(Path(__file__).with_name(name)) for name in ("train.py", "core.py")},
        "endpoints_sha256": hashlib.sha256(json.dumps(positions).encode()).hexdigest(),
    }
    model = SequenceModel(args.architecture, len(vocabulary) + 2).to(device)
    if not args.resume:
        atomic_json(args.run_dir / "endpoints.json", positions)
        atomic_json(args.run_dir / "run_identity.json", identity)
    if args.architecture == "counts":
        fit_counts(model, endpoints, encoded, args)
    elif not fit_neural(model, endpoints, encoded, args, identity, device, started):
        print("Run stopped at a recoverable optimizer boundary. Resume with the same data and configuration.", flush=True)
        return
    tune, thresholds, scores_for = score_roles(model, traces, encoded, args, device)
    bundle_path = args.run_dir / "bundle.pt"
    atomic_torch(bundle_path, {
        "version": 1, "identity": identity, "vocabulary": vocabulary,
        "architecture": args.architecture, "block_size": args.block_size, "horizon": args.horizon,
        "state_dict": {key: tensor.cpu() for key, tensor in model.state_dict().items()}, "thresholds": thresholds,
    })
    bundle_hash = digest(bundle_path)
    atomic_json(args.run_dir / "frozen.json", {"bundle_sha256": bundle_hash, "thresholds": thresholds, "identity": identity})
    metrics = {"identity": identity, "bundle_sha256": bundle_hash, "tune": tune, "thresholds": thresholds}
    if not args.skip_test:
        metrics["test"] = evaluate_test(traces, thresholds, scores_for, args.run_dir / "test_alerts.jsonl")
    atomic_json(args.run_dir / "metrics.json", metrics)
    print(f"Completed {args.architecture}. Results: {args.run_dir / 'metrics.json'}", flush=True)


if __name__ == "__main__":
    main()
