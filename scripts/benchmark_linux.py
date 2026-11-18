"""Fit and compare causal detectors on one fixed, recorded Linux holdout."""

import argparse
from collections import Counter, defaultdict
from importlib.metadata import version
import json
import math
from pathlib import Path
import random
from statistics import median
import time

import torch

from raneval import core, train as training
from raneval.core import (
    EARLY_OBSERVATIONS, SequenceModel, choose_threshold, encode, first_alert,
    load_traces, score_blocks, train_vocabulary,
)
from raneval.train import atomic_json, atomic_torch, digest, fit_counts, fit_neural, make_endpoints


ARCHITECTURES = ("counts", "cnn", "gru")
BENIGN = "BENIGN"
RANSOMWARE = "RANSOMWARE"


def validate_cohort(traces, audit, data_digest, horizon):
    if not isinstance(audit, dict) or audit.get("training_jsonl_sha256") != data_digest:
        raise ValueError("The cohort audit does not match the prepared data")
    provenance = audit["trace_provenance"]
    if set(provenance) != {trace.trace_id for trace in traces}:
        raise ValueError("Cohort metadata must cover exactly the prepared traces")
    support = Counter((trace.role, trace.label) for trace in traces if trace.apis)
    required = [("train", BENIGN), ("train", RANSOMWARE), ("calibrate", BENIGN),
                ("test", BENIGN), ("test", RANSOMWARE)]
    for role, label in required:
        if not support[(role, label)]:
            raise ValueError(f"Cohort needs nonempty {label} traces in {role}")

    capture_roles = {}
    family_roles = {}
    benign_workloads = {}
    prefix_roles = {}
    for trace in traces:
        if trace.label not in (BENIGN, RANSOMWARE):
            raise ValueError(f"Unexpected label for the binary benchmark: {trace.label}")
        if not trace.apis:
            raise ValueError(f"Benchmark traces require observed events: {trace.trace_id}")
        meta = provenance[trace.trace_id]
        capture = meta.get("capture")
        detail_key = "family" if trace.label == RANSOMWARE else "workload"
        detail = meta.get(detail_key)
        if any(not isinstance(value, str) or not value.strip() for value in (capture, detail)):
            raise ValueError(f"Trace {trace.trace_id} needs a capture and {detail_key}")
        if capture_roles.setdefault(capture, trace.role) != trace.role:
            raise ValueError(f"Capture crosses statistical roles: {capture}")
        if trace.label == RANSOMWARE and family_roles.setdefault(detail, trace.role) != trace.role:
            raise ValueError(f"Ransomware family crosses statistical roles: {detail}")
        if trace.label == BENIGN and benign_workloads.setdefault(capture, detail) != detail:
            raise ValueError(f"Benign capture has ambiguous workload labels: {capture}")
        prefix = trace.apis[:horizon]
        if prefix and prefix_roles.setdefault(prefix, trace.role) != trace.role:
            raise ValueError("An exact scored event sequence crosses statistical roles")
        timing = meta.get("elapsed_ms")
        if timing is not None and (
            not isinstance(timing, list) or len(timing) != len(trace.apis)
            or any(type(value) not in (int, float) or not math.isfinite(value) or value < 0 for value in timing)
            or (timing and timing[0] != 0) or any(left > right for left, right in zip(timing, timing[1:]))
        ):
            raise ValueError(f"Invalid event timing for {trace.trace_id}")
    return provenance, support, capture_roles, family_roles


def summarize_positives(records):
    caught = [row for row in records if row["first_event"] is not None]
    timings = [row["first_ms"] for row in caught if row["first_ms"] is not None]
    return {
        "alerts": len(caught),
        "total": len(records),
        "early_alerts": sum(row["first_event"] <= EARLY_OBSERVATIONS for row in caught),
        "misses": len(records) - len(caught),
        "shorter_than_early": sum(row["observed_events"] < EARLY_OBSERVATIONS for row in records),
        "median_first_event": median(row["first_event"] for row in caught) if caught else None,
        "median_first_ms": median(timings) if timings and len(timings) == len(caught) else None,
    }


def evaluate_model(model, traces, provenance, encoded, args):
    device = torch.device("cpu")

    def scores(trace):
        return score_blocks(model, encoded[trace.trace_id], args.block_size, device)

    maxima = defaultdict(float)
    for trace in traces:
        if trace.role == "calibrate" and encoded[trace.trace_id]:
            capture = provenance[trace.trace_id]["capture"]
            maxima[capture] = max(maxima[capture], max(scores(trace)))
    threshold = choose_threshold(maxima.values(), args.target_fpr)
    benign = defaultdict(dict)
    positives = defaultdict(list)
    records = []
    for trace in traces:
        if trace.role != "test" or not encoded[trace.trace_id]:
            continue
        alert = first_alert(scores(trace), threshold)
        meta = provenance[trace.trace_id]
        timing = meta.get("elapsed_ms")
        record = {"trace_id": trace.trace_id, "label": trace.label, "capture": meta["capture"],
                  "first_event": alert, "first_ms": timing[alert - 1] if timing and alert else None,
                  "observed_events": len(encoded[trace.trace_id])}
        if trace.label == BENIGN:
            record["workload"] = meta["workload"]
            capture_alerts = benign[meta["workload"]]
            previous = capture_alerts.get(meta["capture"], False)
            capture_alerts[meta["capture"]] = previous or alert is not None
        elif trace.label == RANSOMWARE:
            record["family"] = meta["family"]
            positives[meta["family"]].append(record)
        records.append(record)
    benign_workloads = {key: {"alerts": sum(captures.values()), "total": len(captures)}
                       for key, captures in benign.items()}
    families = {key: summarize_positives(positives[key]) for key in sorted(positives)}
    ransomware = [row for group in positives.values() for row in group]
    summary = {
        "calibration": {"alerts": threshold["alerts"], "total": threshold["n"],
                        "allowed": math.floor(threshold["n"] * threshold["alpha"]),
                        "threshold": threshold["tau"], "mode": threshold["mode"]},
        "benign_test": {key: sum(workload[key] for workload in benign_workloads.values())
                        for key in ("alerts", "total")},
        "ransomware_test": summarize_positives(ransomware),
    }
    return summary, families, benign_workloads, records, threshold


def compare(args):
    traces, data_digest = load_traces(args.data)
    audit = json.loads(args.audit.read_text(encoding="utf-8"))
    provenance, support, capture_roles, family_roles = validate_cohort(traces, audit, data_digest, args.horizon)
    args.run_dir.mkdir(parents=True, exist_ok=False)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(args.cpu_threads)
    device = torch.device("cpu")
    train = sorted((trace for trace in traces if trace.role == "train" and trace.apis),
                   key=lambda trace: trace.trace_id)
    vocabulary = train_vocabulary(train, args.horizon)
    encoded = {trace.trace_id: encode(trace.apis, vocabulary, args.horizon) for trace in traces}
    positions, endpoints = make_endpoints(train, encoded, args.endpoints_per_trace, args.data_seed,
                                          args.endpoint_policy, args.early_loss_weight)
    config = {key: value for key, value in vars(args).items() if not isinstance(value, Path)}
    identity = {"config": config, "data_sha256": data_digest, "audit_sha256": digest(args.audit),
                "packages": {name: version(name) for name in ("torch", "scipy", "scikit-learn")},
                "code_sha256": {Path(path).name: digest(Path(path))
                                for path in (__file__, core.__file__, training.__file__)}}
    atomic_json(args.run_dir / "manifest.json", identity)
    atomic_json(args.run_dir / "endpoints.json", positions)
    models = []
    family_results = defaultdict(dict)
    workload_results = defaultdict(dict)
    for architecture in ARCHITECTURES:
        print(f"Fitting {architecture}", flush=True)
        run_dir = args.run_dir / architecture
        run_dir.mkdir()
        options = argparse.Namespace(**{**vars(args), "run_dir": run_dir})
        model_identity = {**identity, "architecture": architecture}
        random.seed(args.seed)
        torch.manual_seed(args.seed)
        model = SequenceModel(architecture, len(vocabulary) + 2).to(device)
        if architecture == "counts":
            fit_counts(model, endpoints, encoded, options)
        elif not fit_neural(model, endpoints, encoded, options, model_identity, device, time.monotonic()):
            raise RuntimeError(f"Training stopped before evaluation for {architecture}")
        summary, families, workloads, records, threshold = evaluate_model(model, traces, provenance, encoded, args)
        atomic_json(run_dir / "test-alerts.json", records)
        bundle = run_dir / "bundle.pt"
        atomic_torch(bundle, {"version": 1, "identity": model_identity, "architecture": architecture,
                             "vocabulary": vocabulary, "block_size": args.block_size, "horizon": args.horizon,
                             "state_dict": model.state_dict(), "thresholds": [threshold]})
        models.append({"id": architecture, **summary, "bundle_sha256": digest(bundle)})
        for family, result in families.items():
            family_results[family][architecture] = result
        for workload, result in workloads.items():
            workload_results[workload][architecture] = result

    positive_test = [trace for trace in traces if trace.role == "test" and trace.label == RANSOMWARE and trace.apis]
    support_by_role = {f"{role}/{label}": count for (role, label), count in sorted(support.items())}
    limitations = [
        *audit.get("limitations", []),
        "The false-alert budget is enforced on separate calibration captures. The realized test rate can differ.",
        "First-alert medians include detected traces only. Early recall counts missed traces in the denominator.",
        f"Scoring uses up to {args.horizon:,} retained events per trace. A miss means no alert in the scored horizon.",
    ]
    allowed = models[0]["calibration"]["allowed"]
    if not allowed:
        limitations.append("The calibration cohort is small enough that the nominal budget permits zero calibration alerts.")
    result = {
        "schema": "raneval-linux-benchmark-v1",
        "title": audit.get("title", "Fresh Linux benchmark"),
        "method": (
            "All three architectures were fit on the same training traces with a fixed configuration. "
            "Each threshold uses the maximum score per separate benign calibration capture. "
            "The holdout measures first alert on each ransomware event stream and any alert per benign capture. "
            "Elapsed time starts at the first retained operation when timestamps are available."
        ),
        "provenance": audit.get("provenance", []),
        "limitations": limitations,
        "budget": {"target_rate": args.target_fpr, "unit": "benign capture"},
        "early_event_horizon": EARLY_OBSERVATIONS,
        "models": models,
        "families": [{"name": name, "total": row["counts"]["total"], "models": row}
                     for name, row in sorted(family_results.items())],
        "benign_workloads": [{"name": name, "total": row["counts"]["total"], "models": row}
                             for name, row in sorted(workload_results.items())],
        "evaluation": {**identity, "support_by_role": support_by_role,
                       "capture_counts": dict(Counter(capture_roles.values())),
                       "family_roles": family_roles,
                       "unique_positive_test_early_prefixes": len({trace.apis[:EARLY_OBSERVATIONS]
                                                                  for trace in positive_test})},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(args.output, result)
    print(f"Wrote benchmark to {args.output}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--audit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--target-fpr", default=0.05, type=float)
    parser.add_argument("--epochs", default=20, type=int)
    parser.add_argument("--horizon", default=2048, type=int)
    parser.add_argument("--cpu-threads", default=1, type=int)
    parser.set_defaults(seed=123, data_seed=771, endpoints_per_trace=16, endpoint_policy="early",
                        early_loss_weight=2.0, block_size=256, regularization=1.0, learning_rate=1e-3,
                        batch_size=32, checkpoint_seconds=600, stop_after_steps=0, budget_minutes=0, resume=False)
    args = parser.parse_args()
    if not 0 <= args.target_fpr < 1 or min(args.epochs, args.horizon, args.cpu_threads) < 1:
        parser.error("A budget in [0, 1) and positive epochs, horizon and CPU thread count are required")
    if args.output.resolve() in (args.data.resolve(), args.audit.resolve()):
        parser.error("Use a separate output path for the benchmark report")
    compare(args)


if __name__ == "__main__":
    main()
