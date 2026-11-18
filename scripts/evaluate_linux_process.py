"""Compare pooled and per-task frozen detectors at a session-level alarm budget."""

import argparse
from collections import defaultdict
import json
from pathlib import Path
import random
import shutil
from statistics import median

import torch

from benchmark_linux_context import BENIGN, RANSOMWARE, read_contextual
from evaluate_linux_mixed import namespace, interval
from raneval.context import context_rows
from raneval.context_score import ContextStreamingScorer, load_context_bundle, score_context_blocks
from raneval.core import choose_threshold, encode, score_blocks
from raneval.score import StreamingScorer, load_bundle
from raneval.process_score import ProcessStreamingScorer
from raneval.train import atomic_json, digest


DEVICE = torch.device("cpu")
HORIZON = 2048
EARLY = 120
SCHEDULES = ((128, 1), (128, 3), (256, 1), (256, 3))
MODELS = {"counts": "Event count", "cnn": "CNN", "gru_refit": "GRU refit", "gru_context": "GRU + context"}


def sources(path, label):
    traces, provenance, events, checksum = read_contextual(path, label, HORIZON)
    return [{"id": item.trace_id, "role": item.role, "label": label,
             "group": provenance[item.trace_id]["family" if label == RANSOMWARE else "workload"],
             "events": events[item.trace_id]} for item in traces], checksum


def pairs(rows, seed):
    shuffled = list(rows)
    random.Random(seed).shuffle(shuffled)
    return list(zip(shuffled[::2], shuffled[1::2]))


def schedule(background, injected, warmup, ratio, identity):
    first = namespace(background["events"], "background/")
    second = namespace(injected["events"], "injected/")
    if len(first) < warmup:
        raise ValueError("Source shorter than prespecified warmup")
    events = first[:warmup]
    source_positions = [(background["id"], i) for i in range(warmup)]
    background_position = warmup
    positive_position = 0
    while len(events) < HORIZON and positive_position < len(second) and background_position < len(first):
        events.append(second[positive_position])
        source_positions.append((injected["id"], positive_position))
        positive_position += 1
        for _ in range(ratio):
            if len(events) >= HORIZON or background_position >= len(first):
                break
            events.append(first[background_position])
            source_positions.append((background["id"], background_position))
            background_position += 1
    return {"id": identity, "positive": injected["label"] == RANSOMWARE,
            "family": injected["group"] if injected["label"] == RANSOMWARE else None,
            "background": background["id"], "injected": injected["id"],
            "warmup": warmup, "ratio": ratio, "events": events, "positions": source_positions}


def probabilities(events, bundle, model, contextual, runtime=False):
    if runtime:
        scorer = (ContextStreamingScorer if contextual else StreamingScorer)({**bundle, "horizon": 0}, model, DEVICE)
        return [scorer.step(event if contextual else event["op"]) for event in events]
    tokens = encode([event["op"] for event in events], bundle["vocabulary"])
    if contextual:
        return list(score_context_blocks(model, tokens, context_rows(events, bundle["block_size"]),
                                         bundle["block_size"], DEVICE))
    return list(score_blocks(model, tokens, bundle["block_size"], DEVICE))


def actor_scores(source, bundle, model, contextual, runtime=False):
    if runtime:
        scorer = ProcessStreamingScorer(bundle, model, DEVICE)
        return [scorer.step(event)["score"] for event in source["events"]]
    positions = defaultdict(list)
    for index, event in enumerate(source["events"]):
        actor = event["actor"]
        if not isinstance(actor, str) or not actor:
            raise ValueError("Per-task inference requires observed actor identity")
        positions[actor].append(index)
    scores = [None] * len(source["events"])
    for indices in positions.values():
        events = [source["events"][index] for index in indices]
        for index, value in zip(indices, probabilities(events, bundle, model, contextual)):
            scores[index] = value
    return scores


def scores_for(session, scope, cache, bundle, model, contextual, runtime=False):
    if scope == "actor":
        return [cache[source][index] for source, index in session["positions"]]
    return probabilities(session["events"], bundle, model, contextual, runtime)


def outcome(session, scores, threshold, scope):
    tau = threshold["tau"]
    hits = [index for index, value in enumerate(scores) if tau is not None and value >= tau]
    first = hits[0] if hits else None
    positive = session["positive"]
    injection_hits = [index for index in hits if session["positions"][index][0] == session["injected"]]
    after_hits = [index for index in hits if index >= session["warmup"]]
    attributed = injection_hits if scope == "actor" else after_hits
    first_attributed = attributed[0] if positive and attributed else None
    positive_count = None
    if first_attributed is not None:
        positive_count = sum(source == session["injected"] for source, _ in session["positions"][:first_attributed + 1])
    benign_hits = [index for index in hits if session["positions"][index][0] == session["background"]]
    row = {key: value for key, value in session.items() if key not in {"events", "positions"}}
    return {**row, "score": max(scores), "events": len(scores),
            "first_alert": first + 1 if first is not None else None,
            "first_actor": session["events"][first]["actor"] if first is not None else None,
            "first_alert_on_injected": session["positions"][first][0] == session["injected"] if first is not None else None,
            "first_after_onset": first_attributed + 1 if first_attributed is not None else None,
            "positive_events_at_alert": positive_count,
            "premature": first is not None and positive and first < session["warmup"],
            "benign_actor_alert": bool(benign_hits) if positive and scope == "actor" else None}


def summary(rows, scope):
    benign = [row for row in rows if not row["positive"]]
    positive = [row for row in rows if row["positive"]]
    fp = sum(row["first_alert"] is not None for row in benign)
    tp = sum(row["first_after_onset"] is not None for row in positive)
    early = sum(row["positive_events_at_alert"] is not None and row["positive_events_at_alert"] <= EARLY
                for row in positive)
    families = []
    for family in sorted({row["family"] for row in positive}):
        subset = [row for row in positive if row["family"] == family]
        timings = [row["positive_events_at_alert"] for row in subset if row["positive_events_at_alert"] is not None]
        families.append({"name": family, "total": len(subset), "detected": len(timings),
                         "early": sum(value <= EARLY for value in timings),
                         "median_positive_events": median(timings) if timings else None})
    timings = [row["positive_events_at_alert"] for row in positive if row["positive_events_at_alert"] is not None]
    return {
        "benign_test": {"alerts": fp, "total": len(benign), "fpr": fp / len(benign),
                        "fpr_95ci_exact": interval(fp, len(benign))},
        "positive_test": {"sessions": len(positive), "unique_captures": len({row["injected"] for row in positive}),
                          "correct_actor_alerts": tp if scope == "actor" else None,
                          "post_onset_alerts": tp, "early_correct_actor_alerts": early if scope == "actor" else None,
                          "early_alerts": early,
                          "benign_actor_alerts": sum(bool(row["benign_actor_alert"]) for row in positive)
                          if scope == "actor" else None,
                          "premature_alerts": sum(row["premature"] for row in positive),
                          "median_positive_events": median(timings) if timings else None},
        "confusion": {"tp": tp, "fn": len(positive) - tp, "tn": len(benign) - fp, "fp": fp},
        "families": families,
    }


def run(args):
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    benign, benign_hash = sources(args.benign, BENIGN)
    positive, positive_hash = sources(args.positive, RANSOMWARE)
    positive_rows = [json.loads(line) for line in args.positive.read_text().splitlines() if line]
    if any(row.get("actor_identity", {}).get("actor_field") != "tid" for row in positive_rows):
        raise ValueError("Per-task evaluation requires positive Linux task IDs, declared actor_field='tid'")
    positive = [item for item in positive if item["role"] == "test"]
    calibration_sources = [item for item in benign if item["role"] == "calibrate"]
    test_sources = [item for item in benign if item["role"] == "test"]
    if len(calibration_sources) != 100 or len(test_sources) != 100 or len(positive) != 5:
        raise ValueError("Expected 100 calibration, 100 fresh benign test and five known positive sources")
    old = set()
    exclusions = json.loads(args.benign.with_suffix(".meta.json").read_bytes())["exclusion_source_hashes"]
    for name, checksum in exclusions.items():
        path = args.benign.parent / name
        if digest(path) != checksum:
            raise ValueError(f"Prior cohort hash changed: {path}")
        old.update(tuple(json.loads(line)["apis"][:HORIZON]) for line in path.read_text().splitlines() if line)
    seen = set()
    for source in benign:
        sequence = tuple(event["op"] for event in source["events"])
        if sequence in old or sequence in seen:
            raise ValueError("New benign cohort has repeated capped sequence")
        seen.add(sequence)
    cal_pairs = pairs(calibration_sources, 712)
    test_pairs = pairs(test_sources, 912)
    backgrounds = [next(row for row in test_sources if row["group"] == group)
                   for group in sorted({row["group"] for row in test_sources})]
    active_schedules = SCHEDULES[:args.schedule_count]
    active_models = {name: MODELS[name] for name in args.model_ids}
    if args.adapted_bundle:
        active_models["gru_task"] = "GRU trained by task"
    primary = active_schedules[0]
    calibration = [schedule(a, b, *primary, f"cal-{index:03}") for index, (a, b) in enumerate(cal_pairs)]
    cases = {}
    for warmup, ratio in active_schedules:
        key = f"warmup{warmup}-background{ratio}"
        control = [schedule(a, b, warmup, ratio, f"{key}-benign-{index:03}")
                   for index, (a, b) in enumerate(test_pairs)]
        attacked = [schedule(a, b, warmup, ratio, f"{key}-{a['id']}-{b['id']}")
                    for a in backgrounds for b in positive]
        cases[key] = control + attacked
    prior = json.loads((args.models / "benchmark.json").read_bytes())
    expected = {row["id"]: row["bundle_sha256"] for row in prior["models"]}
    if args.adapted_bundle:
        expected["gru_task"] = digest(args.adapted_bundle)
    positive_derivation = None
    if positive_hash != prior["evaluation"]["positive_sha256"]:
        reference_path = Path("data/processed/linux-gru-context-criba.jsonl")
        if digest(reference_path) != prior["evaluation"]["positive_sha256"]:
            raise ValueError("Pinned original context archive changed")
        originals = {row["trace_id"]: row for row in
                     map(json.loads, reference_path.read_text().splitlines())}
        derived = list(map(json.loads, args.positive.read_text().splitlines()))
        if {row["trace_id"] for row in derived} != originals.keys():
            raise ValueError("Derived positive capture membership differs")
        for row in derived:
            old_row = originals[row["trace_id"]]
            for key in ("apis", "elapsed_ms", "label", "role", "group_id", "source", "source_member"):
                if row[key] != old_row[key]:
                    raise ValueError(f"Derived positive projection changed {key}")
            if [{k: v for k, v in e.items() if k != "actor"} for e in row["events"]] != [
                    {k: v for k, v in e.items() if k != "actor"} for e in old_row["events"]]:
                raise ValueError("Derived positive changed non-actor context")
            if row.get("actor_identity", {}).get("actor_field") != "tid":
                raise ValueError("Derived positive requires declared task identity")
        positive_derivation = {"original_sha256": prior["evaluation"]["positive_sha256"],
                               "actor_field": "tid", "verified_equal_fields": "All events except actor identity"}
    reuse = None
    if args.reuse:
        reuse = json.loads((args.reuse / "benchmark.json").read_bytes())
        if (reuse["benign_sha256"] != benign_hash or reuse["source_bundles"] != {
                name: expected[name] for name in active_models} or reuse["schedules"] != [list(x) for x in active_schedules]
                or reuse.get("runtime_scoring", False) != args.runtime):
            raise ValueError("Cached comparison has different benign data, models or schedules")
        expected_models = len(active_models) * 2 - int(bool(args.adapted_bundle))
        if len(reuse["models"]) != expected_models or positive_derivation is None:
            raise ValueError("Reuse requires a complete prior comparison and validated actor-only derivation")
    manifest = {
        "schema": "raneval-linux-process-v1", "benign_sha256": benign_hash, "positive_sha256": positive_hash,
        "source_bundles": {name: expected[name] for name in active_models}, "positive_derivation": positive_derivation,
        "bundle_paths": {name: str(args.adapted_bundle if name == "gru_task" else args.models / f"{name}.pt")
                         for name in active_models},
        "code_sha256": digest(Path(__file__)), "schedules": active_schedules, "session_horizon": HORIZON,
        "scorer_sha256": {name: digest(Path("src/raneval") / name)
                         for name in ("core.py", "score.py", "context.py", "context_score.py", "process_score.py")},
        "pytorch": str(torch.__version__), "threads": 1,
        "runtime_scoring": args.runtime,
        "actor_identity": "Linux task ID within each capture, namespaced by independent capture",
        "source_order": "successful calls in completion order",
        "budget": {"target_rate": 0.05, "unit": "any alert in a two-source benign session"},
        "calibration_sessions": len(calibration), "test_control_sessions": len(test_pairs),
        "positive_captures": 5, "positive_trials_per_schedule": 25,
        "primary_schedule": next(iter(cases)),
        "calibration_sources": [item["id"] for item in calibration_sources],
        "test_sources": [item["id"] for item in test_sources],
        "positive_sources": [item["id"] for item in positive],
        "preselected_observer": "gru_task_actor" if args.adapted_bundle else "gru_context_actor",
        "reused_comparison_sha256": digest(args.reuse / "benchmark.json") if reuse else None,
        "limitations": [
            "Five archived positives were previously used in model selection. The 25 combinations reuse them.",
            "Mixed schedules are deterministic replays of independently recorded calls.",
            "Source capture and collector differ by class. Correct actor means an actor in the archived positive source.",
            "The formal calibration unit is a session of at most 2048 operations with two source workloads.",
            "Secondary schedules reuse thresholds from the primary schedule. Their alarm rates are measured independently.",
        ],
    }
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out / "manifest.json").exists():
        raise FileExistsError("Use a fresh output directory")
    atomic_json(args.out / "manifest.json", manifest)
    result = {**manifest, "title": "Separate history for each Linux task", "models": []}
    all_sources = backgrounds + positive if reuse else calibration_sources + test_sources + positive
    for name, label in active_models.items():
        contextual = name == "gru_context"
        loader = load_context_bundle if contextual else load_bundle
        bundle_path = args.adapted_bundle if name == "gru_task" else args.models / f"{name}.pt"
        bundle, model, checksum = loader(bundle_path, DEVICE, expected[name])
        cache = {row["id"]: actor_scores(row, bundle, model, contextual, args.runtime) for row in all_sources}
        for scope in (("actor",) if name == "gru_task" else ("pooled", "actor")):
            identity = f"{name}_{scope}"
            previous = next((item for item in reuse["models"] if item["id"] == identity), None) if reuse else None
            if previous:
                calibration_path = args.reuse / f"{identity}-calibration.json"
                threshold = json.loads(calibration_path.read_bytes())["threshold"]
                if threshold["tau"] != previous["calibration"]["threshold"]:
                    raise ValueError("Cached calibration threshold differs from report")
                shutil.copyfile(calibration_path, args.out / calibration_path.name)
            else:
                cal = [scores_for(row, scope, cache, bundle, model, contextual, args.runtime) for row in calibration]
                threshold = choose_threshold([max(values) for values in cal], 0.05)
                atomic_json(args.out / f"{identity}-calibration.json", {
                    "threshold": threshold, "sessions": [{"id": row["id"], "peak": max(values)}
                                                         for row, values in zip(calibration, cal)]})
            schedules = {}
            for key, sessions in cases.items():
                previous_rows = {row["id"]: row for row in previous["schedules"][key]["cases"]} if previous else {}
                rows = []
                for row in sessions:
                    if previous and (not row["positive"] or scope == "pooled" and not contextual):
                        cached = previous_rows[row["id"]]
                        if any(cached[field] != row[field] for field in ("injected", "background", "ratio", "warmup")):
                            raise ValueError("Cached source pairing differs")
                        rows.append(cached)
                    else:
                        rows.append(outcome(row, scores_for(row, scope, cache, bundle, model, contextual, args.runtime), threshold, scope))
                schedules[key] = {**summary(rows, scope), "cases": rows}
            primary_summary = {key: value for key, value in schedules[manifest["primary_schedule"]].items()
                               if key != "cases"}
            record = {"id": identity, "label": label + (" per task" if scope == "actor" else " shared history"),
                      "scope": scope, "bundle_sha256": checksum,
                      "calibration": {"alerts": threshold["alerts"], "total": threshold["n"],
                                      "threshold": threshold["tau"], "allowed": 2},
                      **primary_summary, "schedules": schedules}
            result["models"].append(record)
            print(f"{identity}: cal {threshold['alerts']}/50, {record['confusion']}, early "
                  f"{record['positive_test']['early_alerts']}/25", flush=True)
            if identity == manifest["preselected_observer"]:
                atomic_json(args.out / "observer.json", {
                    "schema": "raneval-process-operating-point-v1",
                    "model_id": identity, "original_bundle_sha256": checksum, "scope": "actor",
                    "bundle_sha256": checksum, "threshold": threshold["tau"], "block_size": bundle["block_size"],
                    "session_horizon": HORIZON, "calibration": record["calibration"],
                    "runtime_scoring": args.runtime, "pytorch": str(torch.__version__),
                    "scorer_sha256": manifest["scorer_sha256"],
                    "calibration_unit": manifest["budget"]["unit"], "calibration_horizon": HORIZON,
                    "actor_capacity": 1024,
                })
        atomic_json(args.out / "benchmark.json", result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models", type=Path, default=Path("runs/linux-gru-context-bounded"))
    parser.add_argument("--benign", type=Path, default=Path("data/processed/linux-process-benign-v6.jsonl"))
    parser.add_argument("--positive", type=Path, default=Path("data/processed/linux-gru-context-criba-tid.jsonl"))
    parser.add_argument("--out", type=Path, default=Path("runs/linux-process-benchmark/results"))
    parser.add_argument("--reuse", type=Path, help="Reuse unchanged calibration and controls for an actor-only positive derivation")
    parser.add_argument("--model-ids", nargs="+", choices=tuple(MODELS), default=list(MODELS))
    parser.add_argument("--schedule-count", type=int, choices=(1, 2, 4), default=4)
    parser.add_argument("--adapted-bundle", type=Path, help="Frozen version-1 GRU trained on task-scoped inputs")
    parser.add_argument("--runtime", action="store_true", help="Calibrate and evaluate with the deployed streaming arithmetic")
    run(parser.parse_args())
