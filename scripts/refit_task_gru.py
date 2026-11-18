"""Adapt a frozen GRU readout to independent task histories using capture labels."""

import argparse
from collections import defaultdict
import copy
import json
from pathlib import Path

import torch
import torch.nn.functional as F

from refit_linux_gru import gru_states
from raneval.core import choose_threshold, encode
from raneval.score import load_bundle
from raneval.train import atomic_json, atomic_torch, digest


PENALTIES = (0.001, 0.01, 0.1)
STEPS = 250


def read_rows(path, roles, label):
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if label == "RANSOMWARE" and any(row.get("actor_identity", {}).get("actor_field") != "tid" for row in rows):
        raise ValueError("Task readout training requires explicit DIO tid actor provenance")
    chosen = [row for row in rows if row["role"] in roles]
    if any(row["label"] != label for row in chosen):
        raise ValueError("Unexpected capture label")
    return chosen


@torch.no_grad()
def task_states(row, bundle, model):
    events = row["events"][:bundle["horizon"]]
    positions = defaultdict(list)
    for index, event in enumerate(events):
        actor = event["actor"]
        if not isinstance(actor, str) or not actor:
            raise ValueError("Missing task identity")
        positions[actor].append(index)
    features = torch.empty((len(events), 128))
    for indices in positions.values():
        tokens = encode([events[index]["op"] for index in indices], bundle["vocabulary"])
        features[indices] = gru_states(model, tokens, bundle["block_size"])
    return features


def losses(head, positive, negative):
    # A positive capture needs an observed suspicious task prefix. Helpers
    # carry no individual positive label. Each source capture has equal mass.
    positives = []
    for states in positive:
        logits = head(states).flatten()
        positives.append(torch.stack([F.softplus(-logits[:min(stop, len(logits))].max())
                                      for stop in (30, 60, 120)]).mean())
    negatives = []
    for states in negative:
        logits = head(states).flatten()
        negatives.append(0.8 * F.softplus(logits.max()) + 0.2 * F.softplus(logits).mean())
    return 0.5 * torch.stack(positives).mean() + 0.5 * torch.stack(negatives).mean()


def run(args):
    if args.out.exists():
        raise ValueError("Use a fresh output directory")
    torch.set_num_threads(1)
    torch.manual_seed(99481)
    torch.use_deterministic_algorithms(True)
    bundle, model, checksum = load_bundle(args.base, torch.device("cpu"))
    positive_rows = read_rows(args.positive, {"train"}, "RANSOMWARE")
    benign_train = [row for path in args.benign for row in read_rows(path, {"train"}, "BENIGN")]
    benign_tune = [row for path in args.benign for row in read_rows(path, {"tune"}, "BENIGN")]
    if len(positive_rows) != 9 or any(row["family"] in {"DarkSide", "Erebus"} for row in positive_rows):
        raise ValueError("Expected nine original training captures only")
    all_rows = positive_rows + benign_train + benign_tune
    if len({row["trace_id"] for row in all_rows}) != len(all_rows):
        raise ValueError("Repeated capture identity")
    args.out.mkdir(parents=True)
    provenance = {"base_sha256": checksum, "positive_sha256": digest(args.positive),
                  "benign_sha256": {str(path): digest(path) for path in args.benign},
                  "training_positive_ids": [row["trace_id"] for row in positive_rows],
                  "training_benign_ids": [row["trace_id"] for row in benign_train],
                  "tuning_benign_ids": [row["trace_id"] for row in benign_tune],
                  "seed": 99481, "steps": STEPS, "penalties": PENALTIES,
                  "label_unit": "capture", "actor_field": "source task identity",
                  "positive_objective": "mean softplus negative maximum logit at capture prefixes 30,60,120",
                  "negative_objective": "0.8 maximum prefix loss plus 0.2 mean prefix loss",
                  "class_weight": 0.5, "capture_weight": "equal within class",
                  "backbone": "frozen inherited GRU, prior model selection provenance still applies",
                  "code_sha256": digest(Path(__file__))}
    atomic_json(args.out / "manifest.json", provenance)
    positive = [task_states(row, bundle, model)[:120] for row in positive_rows]
    negative = []
    endpoint_receipt = {}
    for row in benign_train:
        states = task_states(row, bundle, model)
        with torch.no_grad():
            logits = model.head(states).flatten()
            indices = sorted(set(torch.linspace(0, len(states) - 1, min(64, len(states))).long().tolist()
                                 + torch.topk(logits, min(64, len(states))).indices.tolist()))
        negative.append(states[indices])
        endpoint_receipt[row["trace_id"]] = [index + 1 for index in indices]
    tune = [task_states(row, bundle, model) for row in benign_tune]
    atomic_json(args.out / "training-endpoints.json", endpoint_receipt)
    print(f"Frozen task states ready for {len(positive)} positive, {len(negative)} benign train and {len(tune)} benign tune captures.",
          flush=True)
    candidates = []
    chosen = None
    initial = copy.deepcopy(model.head)
    for penalty in PENALTIES:
        head = copy.deepcopy(initial)
        optimizer = torch.optim.Adam(head.parameters(), lr=0.005)
        for _ in range(STEPS):
            optimizer.zero_grad()
            regularization = sum((value - anchor.detach()).square().sum()
                                 for value, anchor in zip(head.parameters(), initial.parameters()))
            objective = losses(head, positive, negative) + penalty * regularization
            if not torch.isfinite(objective):
                raise ValueError("Nonfinite readout objective")
            objective.backward()
            optimizer.step()
        with torch.no_grad():
            tune_maxima = [head(states).double().sigmoid().max().item() for states in tune]
            threshold = choose_threshold(tune_maxima, 0.05)
            early_scores = [head(states).flatten().double().sigmoid().tolist() for states in positive]
            tau = threshold["tau"]
            alerts = [next((index for index, score in enumerate(scores, 1)
                            if tau is not None and score >= tau), None) for scores in early_scores]
            early = sum(alert is not None for alert in alerts)
            # Uses original training positives and historical benign tuning only.
            rank = (-early, sum(alert or 121 for alert in alerts), sum(tune_maxima) / len(tune_maxima))
        receipt = {"penalty": penalty, "training_early_detected": early, "training_first_events": alerts,
                   "benign_tune_threshold": threshold, "mean_benign_tune_peak": rank[-1], "rank": list(rank)}
        candidates.append(receipt)
        print(json.dumps(receipt), flush=True)
        if chosen is None or rank < chosen[0]:
            chosen = (rank, head.state_dict(), penalty)
    model.head.load_state_dict(chosen[1])
    exported = {**bundle, "state_dict": model.state_dict(), "thresholds": [],
                "identity": {"variant": "gru_task", "training_manifest_sha256": digest(args.out / "manifest.json")},
                "inference_scope": "actor", "calibration_required": "session maximum across all actor scores"}
    destination = args.out / "gru_task.pt"
    atomic_torch(destination, exported)
    atomic_json(args.out / "selection.json", {"chosen_penalty": chosen[2], "candidates": candidates,
                                              "bundle_sha256": digest(destination),
                                              "positive_selection_scope": "original training captures only",
                                              "thresholds": "must be calibrated on independent benign sessions"})
    print(f"Frozen bundle {destination}, sha256 {digest(destination)}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=Path("runs/linux-gru-context-bounded/gru_refit.pt"))
    parser.add_argument("--positive", type=Path, default=Path("data/processed/linux-gru-context-criba-tid.jsonl"))
    parser.add_argument("--benign", type=Path, nargs="+", default=[
        Path("data/processed/linux-context-benign.jsonl"), Path("data/processed/linux-context-benign-v4.jsonl")])
    parser.add_argument("--out", type=Path, default=Path("runs/linux-task-refit"))
    run(parser.parse_args())
