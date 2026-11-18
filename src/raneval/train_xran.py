"""Train one frozen XRan candidate without opening calibration/test outcomes.

Example: python -m raneval.train_xran --data-dir data/processed/xran-original
    --out runs/xran-original/counts-lr001 --model counts --seed 17 --epochs 10

Each invocation is one candidate. Configuration selection belongs to the campaign
runner and must rank seed-17 tune results before any final calibration/evaluation.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import time
from pathlib import Path

import numpy as np
import torch
from torch import nn

from .xran_metrics import binary_metrics, calibrate
from .xran_models import (
    atomic_json, atomic_torch, build_model, digest, export_bundle,
    model_config, predict_endpoint, validate_tokens,
)


def tune_summary(model, tokens, labels, batch_size):
    scores = predict_endpoint(tokens, {"model": model}, batch_size=batch_size)
    point = calibrate(scores[labels == 0], alpha=0.05)
    measured = binary_metrics(labels, scores, point["threshold"])
    return {"operating_point": point, **measured}


def candidate_rank(summary, parameter_count, config_id):
    """Ascending lexical key: recall, AUC, fitted parameter count, config ID."""
    metrics = summary["metrics"]
    return (-metrics["recall"], -metrics["roc_auc"], int(parameter_count), str(config_id))


def software_identity():
    return {"python": platform.python_version(), "numpy": np.__version__, "torch": str(torch.__version__)}


def capture_rng():
    numpy_state = np.random.get_state()
    return {
        "python": random.getstate(), "torch": torch.get_rng_state(),
        "numpy": {"name": numpy_state[0], "keys": numpy_state[1].tolist(),
                  "pos": numpy_state[2], "has_gauss": numpy_state[3], "cached_gaussian": numpy_state[4]},
        "cuda": torch.cuda.get_rng_state_all() if torch.cuda.is_available() else [],
    }


def restore_rng(state):
    random.setstate(state["python"])
    torch.set_rng_state(state["torch"])
    value = state["numpy"]
    np.random.set_state((value["name"], np.array(value["keys"], dtype=np.uint32),
                         value["pos"], value["has_gauss"], value["cached_gaussian"]))
    if state["cuda"]:
        if not torch.cuda.is_available() or len(state["cuda"]) != torch.cuda.device_count():
            raise ValueError("Resume requires the same CUDA device count")
        torch.cuda.set_rng_state_all(state["cuda"])


def checkpoint(out, identity, model, optimizer, scaler, progress):
    pointer_path = out / "recovery.json"
    previous_slot = json.loads(pointer_path.read_text(encoding="utf-8"))["slot"] if pointer_path.exists() else 1
    slot = 1 - previous_slot
    path = out / f"recovery-{slot}.pt"
    start = time.monotonic()
    atomic_torch(path, {"schema": "xran-recovery-v1", "identity": identity,
                        "model": model.state_dict(), "optimizer": optimizer.state_dict(),
                        "scheduler": None, "scaler": scaler.state_dict(), "rng": capture_rng(),
                        "progress": progress})
    atomic_json(pointer_path, {"schema": "xran-recovery-pointer-v1", "slot": slot,
                               "sha256": digest(path), "step": progress["step"]})
    return time.monotonic() - start


def restore(out, identity, model, optimizer, scaler):
    pointer = json.loads((out / "recovery.json").read_text(encoding="utf-8"))
    if pointer.get("schema") != "xran-recovery-pointer-v1" or pointer.get("slot") not in (0, 1):
        raise ValueError("Invalid XRan recovery pointer")
    path = out / f"recovery-{pointer['slot']}.pt"
    if digest(path) != pointer["sha256"]:
        raise ValueError("XRan recovery checksum mismatch")
    state = torch.load(path, map_location="cpu", weights_only=True)
    if state.get("schema") != "xran-recovery-v1" or state["identity"] != identity:
        raise ValueError("Resume identity differs: data, code, configuration or software changed")
    if state["progress"]["step"] != pointer["step"]:
        raise ValueError("Recovery cursor and pointer disagree")
    model.load_state_dict(state["model"])
    optimizer.load_state_dict(state["optimizer"])
    scaler.load_state_dict(state["scaler"])
    restore_rng(state["rng"])
    return state["progress"]


def epoch_order(length, seed, epoch):
    # A local generator avoids consuming dropout or other model random state.
    generator = torch.Generator(device="cpu").manual_seed(seed * 1_000_003 + epoch)
    return torch.randperm(length, generator=generator).numpy()


def run(args):
    started = time.monotonic()  # Includes all setup/loading/validation in this call.
    if args.epochs < 1 or args.epochs > 10 or args.batch_size < 1 or args.lr <= 0 or args.weight_decay < 0:
        raise ValueError("Require 1–10 epochs, positive batch/lr, and nonnegative weight decay")
    if not (0 <= args.reserve_minutes < args.budget_minutes) or args.checkpoint_minutes <= 0:
        raise ValueError("Training budget must exceed its nonnegative reserve; checkpoint interval must be positive")
    if args.stop_after_steps is not None and args.stop_after_steps < 1:
        raise ValueError("stop-after-steps must be positive")
    if args.threads < 1 or args.elapsed_before_minutes < 0:
        raise ValueError("Invalid thread count or pre-consumed session time")
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    torch.set_num_threads(args.threads)
    torch.use_deterministic_algorithms(True)
    torch.backends.cudnn.benchmark = False
    torch.backends.cudnn.deterministic = True
    torch.backends.cuda.matmul.allow_tf32 = False
    torch.backends.cudnn.allow_tf32 = False
    device = torch.device(args.device)
    if device.type not in {"cpu", "cuda"} or device.type == "cuda" and not torch.cuda.is_available():
        raise ValueError("Requested CPU/CUDA device is unavailable")
    if device.type == "cuda":
        torch.cuda.set_device(device)
    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)

    data_dir, out = Path(args.data_dir), Path(args.out)
    hashes = {name: digest(data_dir / name) for name in ("encoded.npz", "groups.jsonl", "vocabulary.json", "manifest.json")}
    vocabulary = json.loads((data_dir / "vocabulary.json").read_text(encoding="utf-8"))
    if vocabulary.get("schema") != "xran-vocabulary-v1" or vocabulary.get("pad_id") != 0 or vocabulary.get("unk_id") != 1:
        raise ValueError("Unsupported XRan vocabulary")
    with np.load(data_dir / "encoded.npz", allow_pickle=False) as prepared:
        roles = prepared["roles"]
        # Only these two role arrays are materialized as model/metric inputs.
        train_mask, tune_mask = roles == 0, roles == 1
        encoded = prepared["tokens"]
        labels = prepared["labels"]
        train_tokens = validate_tokens(encoded[train_mask], vocabulary["size"])
        tune_tokens = validate_tokens(encoded[tune_mask], vocabulary["size"])
        train_labels, tune_labels = labels[train_mask], labels[tune_mask]
        del encoded, labels, roles
    for name, target in (("train", train_labels), ("tune", tune_labels)):
        if set(np.unique(target).tolist()) != {0, 1}:
            raise ValueError(f"Both binary classes are required in {name}")
    config = model_config(args.model, vocabulary["size"], args.view)
    model = build_model(config).to(device)
    # Explicit AdamW: decoupled weight decay on every fitted parameter, no scheduler.
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    amp_enabled = device.type == "cuda" and args.model != "counts" and not args.no_amp
    scaler = torch.amp.GradScaler("cuda", enabled=amp_enabled)
    source_files = {name: digest(Path(__file__).parent / name)
                    for name in ("train_xran.py", "xran_models.py", "xran_metrics.py")}
    identity = {
        "config": config, "seed": args.seed, "epochs": args.epochs, "batch_size": args.batch_size,
        "optimizer": "AdamW", "lr": args.lr, "weight_decay": args.weight_decay,
        "scheduler": None, "loss": "unweighted_BCEWithLogitsLoss", "gradient_clip_norm": 1.0,
        "amp": "fp16" if amp_enabled else "disabled", "device_type": device.type,
        "threads": args.threads, "data_hashes": hashes, "source_hashes": source_files,
        "software": software_identity(), "config_id": args.config_id or f"{args.model}-{args.view}-lr{args.lr:g}-wd{args.weight_decay:g}",
        "epoch_selection": "tune_recall_at_provisional_5pct_then_auc_then_earliest_epoch",
        "fit_roles": ["train"], "selection_roles": ["tune"],
    }
    out.mkdir(parents=True, exist_ok=True)
    if args.resume:
        progress = restore(out, identity, model, optimizer, scaler)
    else:
        if (out / "recovery.json").exists() or (out / "run.json").exists():
            raise ValueError("Run directory already initialized; use --resume or a fresh --out")
        progress = {"epoch": 0, "cursor": 0, "step": 0, "history": [], "best": None,
                    "best_model": None, "elapsed_seconds": 0.0, "epoch_loss_sum": 0.0,
                    "epoch_examples": 0, "max_step_seconds": 0.0, "max_save_seconds": 0.0,
                    "max_tune_seconds": 0.0}
        atomic_json(out / "run.json", identity)
    # On resume, elapsed-before denotes additional session time outside this run.
    previous_elapsed = progress["elapsed_seconds"] + args.elapsed_before_minutes * 60
    elapsed = lambda: previous_elapsed + time.monotonic() - started
    deadline = args.budget_minutes * 60
    last_save = time.monotonic()
    loss_function = nn.BCEWithLogitsLoss()
    status = "complete"
    parameter_count = sum(parameter.numel() for parameter in model.parameters())

    def save():
        nonlocal last_save
        progress["elapsed_seconds"] = elapsed()
        duration = checkpoint(out, identity, model, optimizer, scaler, progress)
        progress["max_save_seconds"] = max(progress["max_save_seconds"], duration)
        last_save = time.monotonic()
        print(json.dumps({"event": "checkpoint", "step": progress["step"], "epoch": progress["epoch"],
                          "cursor": progress["cursor"], "seconds": round(duration, 3)}), flush=True)

    while progress["epoch"] < args.epochs:
        order = epoch_order(len(train_tokens), args.seed, progress["epoch"])
        while progress["cursor"] < len(order):
            reserve = max(args.reserve_minutes * 60,
                          2 * progress["max_save_seconds"] + progress["max_tune_seconds"] + 2 * progress["max_step_seconds"])
            if elapsed() >= deadline - reserve:
                status = "budget_stopped"
                break
            if args.stop_after_steps is not None and progress["step"] >= args.stop_after_steps:
                status = "step_stopped"
                break
            step_start = time.monotonic()
            index = order[progress["cursor"]:progress["cursor"] + args.batch_size]
            batch = torch.from_numpy(train_tokens[index]).to(device)
            target = torch.as_tensor(train_labels[index], dtype=torch.float32, device=device)
            model.train()
            optimizer.zero_grad(set_to_none=True)
            with torch.autocast(device_type=device.type, dtype=torch.float16, enabled=amp_enabled):
                logits = model(batch)
                loss = loss_function(logits, target)
            if not torch.isfinite(loss):
                raise FloatingPointError("Nonfinite training loss; checkpoint is preserved for diagnosis")
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            gradient_norm = nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            if not torch.isfinite(gradient_norm):
                if not amp_enabled:
                    raise FloatingPointError("Nonfinite training gradient")
            scaler.step(optimizer)
            scaler.update()
            if device.type == "cuda":
                torch.cuda.synchronize(device)
            progress["cursor"] += len(index)
            progress["step"] += 1
            progress["epoch_examples"] += len(index)
            progress["epoch_loss_sum"] += float(loss.detach().cpu()) * len(index)
            progress["max_step_seconds"] = max(progress["max_step_seconds"], time.monotonic() - step_start)
            if time.monotonic() - last_save >= args.checkpoint_minutes * 60:
                save()
        if status != "complete":
            break
        tune_started = time.monotonic()
        summary = tune_summary(model, tune_tokens, tune_labels, args.batch_size)
        progress["max_tune_seconds"] = max(progress["max_tune_seconds"], time.monotonic() - tune_started)
        summary.update({"epoch": progress["epoch"] + 1, "step": progress["step"],
                        "train_loss": progress["epoch_loss_sum"] / progress["epoch_examples"]})
        progress["history"].append(summary)
        if progress["best"] is None or candidate_rank(summary, parameter_count, "") < candidate_rank(progress["best"], parameter_count, ""):
            progress["best"] = summary
            progress["best_model"] = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
        print(json.dumps({"event": "epoch", "epoch": summary["epoch"], "loss": summary["train_loss"],
                          "tune_recall": summary["metrics"]["recall"], "tune_auc": summary["metrics"]["roc_auc"]}), flush=True)
        progress["epoch"] += 1
        progress["cursor"] = 0
        progress["epoch_loss_sum"] = 0.0
        progress["epoch_examples"] = 0
        save()
    save()
    exported = None
    if progress["best_model"] is not None:
        model.load_state_dict(progress["best_model"])
        provenance = {**identity, "selected_epoch": progress["best"]["epoch"],
                      "selected_tune": progress["best"], "training_status": status,
                      "completed_epochs": progress["epoch"], "completed_steps": progress["step"]}
        export_bundle(out / "bundle", model, config, vocabulary, provenance)
        exported = "bundle/bundle.json"
    result = {"schema": "xran-training-result-v1", "status": status, "identity": identity,
              "step": progress["step"], "completed_epochs": progress["epoch"],
              "batch_cursor": progress["cursor"], "parameters": parameter_count,
              "best": progress["best"], "history": progress["history"],
              "elapsed_seconds": elapsed(), "bundle": exported,
              "max_step_seconds": progress["max_step_seconds"], "max_save_seconds": progress["max_save_seconds"],
              "max_tune_seconds": progress["max_tune_seconds"],
              "peak_gpu_bytes": torch.cuda.max_memory_allocated(device) if device.type == "cuda" else None}
    atomic_json(out / "result.json", result)
    print(json.dumps({"event": "finished", "status": status, "step": progress["step"], "bundle": exported}), flush=True)
    return result


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--data-dir", required=True)
    value.add_argument("--out", required=True)
    value.add_argument("--model", choices=("counts", "cnn", "gru"), required=True)
    value.add_argument("--view", choices=("all", "api", "missingness"), default="all")
    value.add_argument("--device", default="cpu")
    value.add_argument("--seed", type=int, default=17)
    value.add_argument("--epochs", type=int, default=10)
    value.add_argument("--batch-size", type=int, default=128)
    value.add_argument("--lr", type=float, default=0.001)
    value.add_argument("--weight-decay", type=float, default=0.0001)
    value.add_argument("--threads", type=int, default=2)
    value.add_argument("--budget-minutes", type=float, default=120)
    value.add_argument("--reserve-minutes", type=float, default=30)
    value.add_argument("--elapsed-before-minutes", type=float, default=0)
    value.add_argument("--checkpoint-minutes", type=float, default=10)
    value.add_argument("--stop-after-steps", type=int)
    value.add_argument("--config-id")
    value.add_argument("--no-amp", action="store_true")
    value.add_argument("--resume", action="store_true")
    return value


if __name__ == "__main__":
    run(parser().parse_args())
