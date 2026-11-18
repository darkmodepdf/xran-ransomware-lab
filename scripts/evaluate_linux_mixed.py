"""Evaluate frozen Linux GRUs on archived ransomware and fresh benign syscall recordings."""

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
import random
from statistics import median

from scipy.stats import binomtest
from sklearn import metrics
import torch

from benchmark_linux_context import BENIGN, DEVICE, RANSOMWARE, read_contextual
from raneval.context import context_rows
from raneval.context_score import load_context_bundle, score_context_blocks
from raneval.core import EARLY_OBSERVATIONS, encode, score_blocks
from raneval.score import load_bundle
from raneval.train import atomic_json


MODELS = {"gru_refit": load_bundle, "gru_context": load_context_bundle}
WARMUP = 128
MIX_SEED = 82613


def case(trace, events, provenance):
    detail = "family" if trace.label == RANSOMWARE else "workload"
    return {"case_id": trace.trace_id, "class": trace.label, "group": provenance[trace.trace_id][detail],
            "events": events[trace.trace_id], "elapsed_ms": provenance[trace.trace_id]["elapsed_ms"],
            "sources": [trace.trace_id], "onset": 1 if trace.label == RANSOMWARE else None}


def isolate(benign, positive):
    ordered = []
    for index in range(len(positive) + 1):
        start = index * len(benign) // (len(positive) + 1)
        end = (index + 1) * len(benign) // (len(positive) + 1)
        ordered.extend(benign[start:end])
        if index < len(positive):
            ordered.append(positive[index])
    return ordered


def namespace(events, prefix):
    return [{**event, **{key: prefix + event[key] for key in ("actor", "file", "directory")
                        if event[key] is not None}} for event in events]


def mix(background, injected, horizon, number):
    if len(background["events"]) < WARMUP + EARLY_OBSERVATIONS:
        raise ValueError(f'Background has insufficient retained operations: {background["case_id"]}')
    first = namespace(background["events"], "background/")
    second = namespace(injected["events"], "injected/")
    pairs = min((horizon - WARMUP) // 2, len(first) - WARMUP, len(second))
    events = first[:WARMUP]
    for offset in range(pairs):
        events.extend((second[offset], first[WARMUP + offset]))
    label = injected["class"]
    return {"case_id": f"mix-{number:03}", "class": label, "group": injected["group"],
            "events": events, "elapsed_ms": None, "sources": [background["case_id"], injected["case_id"]],
            "onset": WARMUP + 1 if label == RANSOMWARE else None}


def mix_cohort(benign, positive, horizon):
    eligible = [item for item in benign if len(item["events"]) >= WARMUP + EARLY_OBSERVATIONS]
    rng = random.Random(MIX_SEED)
    rng.shuffle(eligible)
    backgrounds = [next(item for item in eligible if item["group"] == group)
                   for group in sorted({item["group"] for item in eligible})]
    if len(backgrounds) != len(positive):
        raise ValueError("Expected one eligible benign background per archived positive")
    reserved = {item["case_id"] for item in backgrounds}
    remaining = [item for item in eligible if item["case_id"] not in reserved]
    mixed_benign = [mix(first, second, horizon, index)
                    for index, (first, second) in enumerate(zip(remaining[::2], remaining[1::2]), 1)]
    mixed_positive = [mix(first, second, horizon, index)
                      for index, (first, second) in enumerate(zip(backgrounds, positive), len(mixed_benign) + 1)]
    return isolate(mixed_benign, mixed_positive)


def score_case(item, bundle, model, threshold, contextual, mixed):
    events = item["events"]
    tokens = encode([event["op"] for event in events], bundle["vocabulary"])
    if contextual:
        rows = context_rows(events, bundle["block_size"])
        probabilities = list(score_context_blocks(model, tokens, rows, bundle["block_size"], DEVICE))
    else:
        probabilities = list(score_blocks(model, tokens, bundle["block_size"], DEVICE))
    hits = [index for index, value in enumerate(probabilities, 1) if threshold is not None and value >= threshold]
    alert = hits[0] if hits else None
    onset = item["onset"]
    post_onset = next((index for index in hits if index >= onset), None) if onset is not None else None
    consumed = None if post_onset is None else (post_onset - WARMUP + 1) // 2 if mixed else post_onset
    time = item["elapsed_ms"]
    data = {key: value for key, value in item.items() if key not in {"events", "elapsed_ms"}}
    return {**data, "scored_events": len(probabilities), "peak_score": max(probabilities), "first_alert": alert,
            "elapsed_ms": time[alert - 1] if alert is not None and time is not None else None,
            "premature": alert is not None and onset is not None and alert < onset,
            "first_alert_after_onset": post_onset, "ransomware_events_at_alert": consumed}


def interval(successes, total):
    result = binomtest(successes, total).proportion_ci(confidence_level=0.95, method="exact")
    return [float(result.low), float(result.high)]


def finite(value):
    if isinstance(value, dict):
        return {key: finite(item) for key, item in value.items()}
    return None if isinstance(value, float) and not math.isfinite(value) else value


def summarize(rows):
    truth = [int(row["class"] == RANSOMWARE) for row in rows]
    estimate = [int(row["first_alert"] is not None) for row in rows]
    probabilities = [row["peak_score"] for row in rows]
    tn, fp, fn, tp = map(int, metrics.confusion_matrix(truth, estimate, labels=[0, 1]).ravel())
    positive = [row for row in rows if row["class"] == RANSOMWARE]
    early = [row for row in positive if not row["premature"] and row["ransomware_events_at_alert"] is not None
             and row["ransomware_events_at_alert"] <= EARLY_OBSERVATIONS]
    after_onset = [row for row in positive if row["first_alert_after_onset"] is not None]
    durations = [row["elapsed_ms"] for row in positive if row["elapsed_ms"] is not None]
    groups = defaultdict(list)
    for row in rows:
        groups[(row["class"], row["group"])].append(row)
    return {
        "confusion": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "classification": finite(metrics.classification_report(
            truth, estimate, labels=[0, 1], target_names=["benign", "ransomware"],
            output_dict=True, zero_division=float("nan"))),
        "balanced_accuracy": float(metrics.balanced_accuracy_score(truth, estimate)),
        "specificity": tn / (tn + fp), "false_positive_rate": fp / (tn + fp),
        "false_negative_rate": fn / (tp + fn), "negative_predictive_value": tn / (tn + fn) if tn + fn else None,
        "matthews_correlation": float(metrics.matthews_corrcoef(truth, estimate)),
        "cohens_kappa": float(metrics.cohen_kappa_score(truth, estimate)),
        "roc_auc": float(metrics.roc_auc_score(truth, probabilities)),
        "average_precision": float(metrics.average_precision_score(truth, probabilities)),
        "recall_95ci_exact": interval(tp, tp + fn), "fpr_95ci_exact": interval(fp, fp + tn),
        "early_by_ransomware_event_120": len(early), "premature_alerts": sum(row["premature"] for row in positive),
        "ransomware_post_onset_alerts": len(after_onset),
        "median_alert_ransomware_events": median(row["ransomware_events_at_alert"] for row in after_onset)
        if after_onset else None,
        "median_alert_ms": median(durations) if durations else None,
        "groups": [{"class": label, "name": group, "total": len(members),
                    "alerts": sum(row["first_alert"] is not None for row in members)}
                   for (label, group), members in sorted(groups.items())],
    }


def run(args):
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    reference = json.loads((args.models / "benchmark.json").read_bytes())
    frozen = {model["id"]: model["bundle_sha256"] for model in reference["models"]}
    horizon = reference["evaluation"]["horizon"]
    traces, provenance, events, benign_hash = read_contextual(args.benign, BENIGN, horizon)
    benign = [case(row, events, provenance) for row in traces if row.role == "test"]
    traces, provenance, events, positive_hash = read_contextual(args.positive, RANSOMWARE, horizon)
    if positive_hash != reference["evaluation"]["positive_sha256"]:
        raise ValueError("Expected the frozen CRIBA regression dataset")
    positive = [case(row, events, provenance) for row in traces if row.role == "test"]
    if len(benign) != 100 or len(positive) != 5:
        raise ValueError("Expected 100 fresh benign and five known positive cases")
    cases = {"capture_order": isolate(benign, positive), "event_interleaving": mix_cohort(benign, positive, horizon)}
    report = {"schema": "raneval-linux-mixed-v1", "benign_sha256": benign_hash, "positive_sha256": positive_hash,
              "models_source": str(args.models), "early_ransomware_events": EARLY_OBSERVATIONS,
              "horizon": horizon, "warmup": WARMUP, "mix_seed": MIX_SEED, "models": {}}
    for name, loader in MODELS.items():
        bundle, model, sha256 = loader(args.models / f"{name}.pt", DEVICE, frozen[name])
        threshold, = [item for item in bundle["thresholds"] if item["alpha"] == 0.05]
        report["models"][name] = {"bundle_sha256": sha256, "threshold": threshold, "cohorts": {}}
        for cohort, ordered in cases.items():
            mixed = cohort == "event_interleaving"
            rows = [score_case(item, bundle, model, threshold["tau"], name == "gru_context", mixed)
                    for item in ordered]
            summary = summarize(rows)
            report["models"][name]["cohorts"][cohort] = {"summary": summary, "cases": rows}
            print(f'{name} {cohort}: {summary["confusion"]}', flush=True)
    atomic_json(args.output, report)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", type=Path, default=Path("runs/linux-gru-context-bounded"))
    parser.add_argument("--benign", type=Path, default=Path("data/processed/linux-mixed-benign-v5.jsonl"))
    parser.add_argument("--positive", type=Path, default=Path("data/processed/linux-gru-context-criba.jsonl"))
    parser.add_argument("--output", type=Path, required=True)
    run(parser.parse_args())
