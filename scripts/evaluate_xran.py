"""Evaluate a frozen XRan campaign using CPU float32, one report per call.

Calibration positives remain reserved and are never scored. Re-running an
unchanged completed export verifies receipts and returns it without refitting.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import itertools
import json
import os
import platform
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from raneval.xran_data import load_prepared
from raneval.xran_metrics import binary_metrics, calibrate
from raneval.xran_models import atomic_json, digest, load_bundle, predict_endpoint


LIMITATIONS = [
    "Reconstruction using the released XRan features; original model settings and splits are unavailable.",
    "Windows feature vectors are endpoint reports, not live Linux telemetry or timed API streams.",
    "Feature-group independence does not establish executable, family, temporal, or source independence.",
    "The source identifies the class; source artifacts and missingness may explain some classification performance.",
    "The 5% benign calibration budget does not guarantee 5% false positives on test or future inputs.",
    "No time-to-detection, encryption damage, files saved, prevention, or unseen-family estimate is supported.",
    "The SOREL release contains 8,443 rows rather than the paper's 7,703; PRF semantics are unknown.",
]


def canonical_hash(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def within(root, relative):
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError("Campaign run path escapes campaign directory")
    return candidate


def verify_campaign(campaign, campaign_dir, data_dir):
    """Verify all frozen inputs and tune selection before opening test scores."""
    if campaign.get("schema") != "xran-campaign-complete-v1" or campaign.get("test_outcomes_opened") is not False:
        raise ValueError("Expected a completed campaign with unopened test outcomes")
    ledger = campaign.get("files")
    if not isinstance(ledger, dict) or not ledger:
        raise ValueError("Campaign file ledger is missing")
    for name, checksum in ledger.items():
        if not isinstance(name, str) or "\\" in name or Path(name).is_absolute() or ".." in Path(name).parts:
            raise ValueError("Invalid campaign file ledger path")
        if digest(within(campaign_dir, name)) != checksum:
            raise ValueError(f"Campaign file ledger checksum mismatch: {name}")
    for name, field in (("protocol.json", "protocol_sha256"), ("selection.json", "selection_sha256")):
        if name not in ledger or campaign.get(field) != ledger[name]:
            raise ValueError(f"Campaign {name} checksum binding mismatch")
    protocol_bytes = (campaign_dir / "protocol.json").read_bytes()
    protocol = json.loads(protocol_bytes)
    selection = json.loads((campaign_dir / "selection.json").read_bytes())
    if protocol.get("schema") != "xran-campaign-protocol-v1" or selection.get("schema") != "xran-campaign-selection-v1":
        raise ValueError("Unsupported campaign protocol or selection schema")
    # The submitted Windows package uses CRLF; atomic_json in Linux uses LF.
    # Accept only that exact byte-normalization difference, preserving the
    # original recorded hash and a canonical JSON semantic hash in the receipt.
    lf_bytes = protocol_bytes.replace(b"\r\n", b"\n")
    variants = {hashlib.sha256(lf_bytes).hexdigest(): "LF",
                hashlib.sha256(lf_bytes.replace(b"\n", b"\r\n")).hexdigest(): "CRLF"}
    source_protocol_hash = selection.get("protocol_sha256")
    if source_protocol_hash not in variants:
        raise ValueError("Frozen selection protocol is not semantically bound to campaign protocol")
    if selection.get("primary") != campaign.get("primary") or selection.get("selection_frozen_at") != campaign.get("selection_frozen_at"):
        raise ValueError("Campaign primary selection differs from the frozen tune selection")
    if protocol.get("primary_seed") != 17 or protocol.get("calibration_alpha") != 0.05:
        raise ValueError("Unsupported primary seed or calibration budget")
    data_hashes = {}
    for variant, expected in protocol["datasets"].items():
        if variant not in {"primary", "api-component"}:
            raise ValueError("Unknown protocol data variant")
        directory = data_dir if variant == "primary" else data_dir / variant
        manifest = json.loads((directory / "manifest.json").read_bytes())
        if manifest["identity_sha256"] != expected:
            raise ValueError("Protocol and prepared dataset identity differ")
        data_hashes[variant] = {name: digest(directory / name)
                               for name in ("encoded.npz", "groups.jsonl", "vocabulary.json", "manifest.json")}

    def verify_record(entry):
        folder = entry["run"]
        required = [f"{folder}/{name}" for name in ("result.json", "bundle/bundle.json", "bundle/weights.pt", "bundle/vocabulary.json")]
        if any(name not in ledger for name in required):
            raise ValueError("Selected/candidate run files are absent from the campaign ledger")
        if entry.get("result_sha256") != ledger[required[0]] or entry.get("bundle_sha256") != ledger[required[1]]:
            raise ValueError("Selected/candidate run hashes differ from the campaign ledger")
        result = json.loads(within(campaign_dir, required[0]).read_bytes())
        metadata = json.loads(within(campaign_dir, required[1]).read_bytes())
        if result.get("status") != "complete" or result.get("completed_epochs") != protocol["epochs"]:
            raise ValueError("Campaign contains an incomplete training run")
        identity = result["identity"]
        if any(identity.get(key) != entry[key] for key in ("seed", "lr", "config_id")):
            raise ValueError("Campaign job and fitted configuration disagree")
        if identity["config"]["kind"] != entry["model"] or identity["config"]["view"] != entry["view"]:
            raise ValueError("Campaign job and fitted feature/model representation disagree")
        if any(identity.get(key) != protocol[key] for key in ("epochs", "batch_size", "weight_decay")):
            raise ValueError("Fit hyperparameters differ from the frozen protocol")
        if identity.get("data_hashes") != data_hashes.get(entry["data_variant"]):
            raise ValueError("Campaign fit data differs from frozen prepared inputs")
        if entry.get("best") != result.get("best") or entry.get("parameters") != result.get("parameters"):
            raise ValueError("Campaign tune outcomes differ from fitted run results")
        provenance = metadata.get("provenance", {})
        if any(provenance.get(key) != value for key, value in identity.items()) or provenance.get("selected_tune") != result["best"]:
            raise ValueError("Bundle provenance differs from fitted run identity")
        if metadata.get("weights_sha256") != ledger[required[2]] or metadata.get("vocabulary_sha256") != ledger[required[3]]:
            raise ValueError("Bundle weights/vocabulary differ from the campaign ledger")

    candidates = selection.get("candidates", [])
    expected_grid = {(model, float(lr), f"{model}-lr{number}")
                     for model, rates in protocol["learning_rates"].items() for number, lr in enumerate(rates)}
    actual_grid = {(entry["model"], float(entry["lr"]), entry["config_id"]) for entry in candidates}
    if actual_grid != expected_grid or len(candidates) != len(expected_grid):
        raise ValueError("Candidate set differs from the prespecified tuning grid")
    for entry in candidates:
        if entry["seed"] != 17 or entry["view"] != "all" or entry["data_variant"] != "primary" or entry["id"] != entry["model"]:
            raise ValueError("Invalid primary tuning candidate")
        verify_record(entry)
    selected = {entry["id"]: entry for entry in campaign["primary"]}
    for model, entry in selected.items():
        alternatives = [item for item in candidates if item["model"] == model]
        best = min(alternatives, key=lambda item: (-item["best"]["metrics"]["recall"],
                   -item["best"]["metrics"]["roc_auc"], item["parameters"], item["config_id"]))
        if entry != best:
            raise ValueError("Primary model is not the frozen tune-ranked candidate")
    stability = campaign.get("stability", [])
    expected_stability = {(model, seed) for model in selected for seed in protocol["stability_seeds"]}
    if {(entry["id"], entry["seed"]) for entry in stability} != expected_stability or len(stability) != len(expected_stability):
        raise ValueError("Stability runs differ from frozen seed policy")
    for entry in stability:
        choice = selected[entry["id"]]
        if any(entry[key] != choice[key] for key in ("model", "view", "lr", "config_id", "data_variant")):
            raise ValueError("Stability run changed the tune-selected configuration")
        verify_record(entry)
    diagnostics = campaign.get("diagnostics", [])
    if {entry["id"] for entry in diagnostics} != set(protocol["diagnostics"]) or len(diagnostics) != len(protocol["diagnostics"]):
        raise ValueError("Diagnostic runs differ from frozen protocol")
    diagnostic_views = {"counts_api": ("api", "primary"), "counts_missingness": ("missingness", "primary"),
                        "counts_api_component": ("api", "api-component")}
    for entry in diagnostics:
        if (entry["view"], entry["data_variant"]) != diagnostic_views.get(entry["id"]) or entry["model"] != "counts" or entry["seed"] != 17 or entry["lr"] != selected["counts"]["lr"]:
            raise ValueError("Diagnostic configuration differs from frozen protocol")
        verify_record(entry)
    return {"all_campaign_file_hashes_verified": True, "files_verified": len(ledger),
            "selected_run_hashes_verified": True, "tune_selection_reproduced": True,
            "protocol_sha256": campaign["protocol_sha256"], "selection_sha256": campaign["selection_sha256"],
            "source_protocol_sha256": source_protocol_hash, "source_protocol_line_endings": variants[source_protocol_hash],
            "protocol_semantic_sha256": canonical_hash(protocol),
            "protocol_binding": "Exact JSON bytes, allowing only LF/CRLF newline conversion"}


def peak_memory_bytes():
    """Whole-process high-water RSS, not an estimate of model-only memory."""
    if os.name == "nt":
        class Counters(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        process = ctypes.windll.kernel32.GetCurrentProcess()
        if ctypes.windll.psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
            return int(counters.PeakWorkingSetSize)
        return None
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value if sys.platform == "darwin" else value * 1024)
    except (ImportError, OSError):
        return None


def runtime_manifest():
    from raneval import xran_data, xran_metrics, xran_models
    return {
        "schema": "xran-runtime-v1", "backend": "pytorch-cpu", "device": "cpu", "batch_size": 1,
        "threads": 1, "dtype": "float32", "sigmoid": "torch.float32; lossless conversion to Python binary64",
        "deterministic_algorithms": True, "mkldnn_enabled": bool(torch.backends.mkldnn.enabled),
        "python": platform.python_version(), "torch": str(torch.__version__), "numpy": np.__version__,
        "platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
        "source_hashes": {"xran_models.py": digest(xran_models.__file__), "xran_metrics.py": digest(xran_metrics.__file__),
                          "xran_data.py": digest(xran_data.__file__), "evaluate_xran.py": digest(__file__)},
    }


def write_jsonl(path, records):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(json.dumps(record, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def named_metrics(labels, scores, threshold):
    measured = binary_metrics(labels, scores, threshold)
    classes = measured["metrics"]["class_report"]
    if "healthy" in classes:
        classes["benign"] = classes.pop("healthy")
    return measured


def model_predictions(indices, prepared, scores, threshold):
    records = []
    for index, score in zip(indices, scores):
        group = prepared["groups"][int(index)]
        records.append({"group_id": group["id"], "feature_sha256": group["feature_sha256"],
                        "role": "test" if int(prepared["roles"][index]) == 3 else "calibration_benign",
                        "label": int(prepared["labels"][index]), "sources": group["sources"],
                        "multiplicity": int(prepared["multiplicities"][index]),
                        "score": float(score), "alarm": threshold is not None and bool(score >= threshold)})
    return records


def check_run(entry, campaign_dir, data_dir, prepared):
    run_dir = within(campaign_dir, entry["run"])
    result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
    if result.get("schema") != "xran-training-result-v1" or result.get("status") != "complete":
        raise ValueError(f"Cannot evaluate incomplete training run: {entry['run']}")
    bundle = load_bundle(run_dir / "bundle", device="cpu")
    provenance = bundle["metadata"]["provenance"]
    if provenance.get("training_status") != "complete" or provenance.get("seed") != entry["seed"]:
        raise ValueError("Campaign selection and exported fit provenance disagree")
    for name in ("encoded.npz", "groups.jsonl", "vocabulary.json", "manifest.json"):
        if provenance.get("data_hashes", {}).get(name) != digest(data_dir / name):
            raise ValueError(f"Model fitted on different prepared data: {name}")
    if bundle["vocabulary"] != prepared["vocabulary"]:
        raise ValueError("Exported and prepared vocabularies differ")
    if result["identity"] != {key: provenance[key] for key in result["identity"]}:
        raise ValueError("Run identity and bundle identity disagree")
    if result["best"] != provenance.get("selected_tune"):
        raise ValueError("Selected tune epoch was changed after training")
    return bundle, result


def evaluate_model(entry, campaign_dir, data_dir, prepared, out, runtime_hash, category):
    identifier = entry["id"]
    if not re.fullmatch(r"[a-z0-9_-]+", identifier):
        raise ValueError("Invalid campaign model ID")
    artifact_id = f"{category}-{identifier}-seed{entry['seed']}"
    bundle, result = check_run(entry, campaign_dir, data_dir, prepared)
    fit = bundle["metadata"]["provenance"]
    labels, roles = prepared["labels"], prepared["roles"]
    calibration_indices = np.flatnonzero((roles == 2) & (labels == 0))
    test_indices = np.flatnonzero(roles == 3)
    if not len(calibration_indices) or set(np.unique(labels[test_indices]).tolist()) != {0, 1}:
        raise ValueError("Evaluation requires benign calibration and both test classes")
    print(json.dumps({"event": "evaluate", "id": artifact_id, "test_groups": len(test_indices)}), flush=True)
    calibration_scores = predict_endpoint(prepared["tokens"][calibration_indices], bundle, batch_size=1)
    point = calibrate(calibration_scores, 0.05)
    threshold = point["threshold"]
    test_started = time.perf_counter()
    test_scores = predict_endpoint(prepared["tokens"][test_indices], bundle, batch_size=1)
    elapsed_test = time.perf_counter() - test_started
    measured = named_metrics(labels[test_indices], test_scores, threshold)

    # Reload exported tensors and independently rescore the entire same test set.
    independent = load_bundle(bundle["path"], device="cpu")
    rescored = predict_endpoint(prepared["tokens"][test_indices], independent, batch_size=1)
    if not np.array_equal(test_scores, rescored):
        raise ValueError("Independent CPU reload/rescore parity failed")
    checked = named_metrics(labels[test_indices], rescored, threshold)
    if checked != measured:
        raise ValueError("Independent confusion/metric reproduction failed")
    del independent

    calibration_file = f"{artifact_id}-calibration.jsonl"
    test_file = f"{artifact_id}-test.jsonl"
    write_jsonl(out / calibration_file, model_predictions(calibration_indices, prepared, calibration_scores, threshold))
    write_jsonl(out / test_file, model_predictions(test_indices, prepared, test_scores, threshold))
    operating_point = {
        "schema": "xran-operating-point-v1", "task": "ransomware_vs_benign",
        "unit": "unique_released_feature_vector", "comparator": ">=", **point,
        "bundle_sha256": bundle["bundle_sha256"], "runtime_sha256": runtime_hash,
        "preprocessing_sha256": bundle["metadata"]["vocabulary_sha256"],
        "data_manifest_sha256": fit["data_hashes"]["manifest.json"],
        "calibration_predictions": calibration_file, "calibration_predictions_sha256": digest(out / calibration_file),
        "candidate_rule": "smallest admissible cutoff from 0 and nextafter(distinct score,+infinity), excluding values above 1",
        "positive_calibration": "reserved and not scored",
    }
    point_file = f"{artifact_id}-operating-point.json"
    atomic_json(out / point_file, operating_point)

    sources = sorted({source for index in test_indices for source in prepared["groups"][int(index)]["sources"]})
    by_source = []
    for source in sources:
        selected = np.array([source in prepared["groups"][int(index)]["sources"] for index in test_indices])
        by_source.append({"source": source, "groups": int(selected.sum()),
                          **named_metrics(labels[test_indices][selected], test_scores[selected], threshold)})
    api_empty = prepared["missing_counts"][test_indices, 0] == 500
    strata = {}
    for name, selected in (("api_empty", api_empty), ("api_nonempty", ~api_empty)):
        strata[name] = {"groups": int(selected.sum()), **named_metrics(labels[test_indices][selected], test_scores[selected], threshold)}
    metrics = measured["metrics"]
    memory = peak_memory_bytes()
    model = {
        "id": identifier, "label": {"counts": "Count logistic", "cnn": "CNN", "gru": "GRU"}.get(identifier, identifier.replace("_", " ")),
        "seed": entry["seed"], "status": "evaluated", **measured,
        "threshold": threshold, "alarm_enabled": point["alarm_enabled"], "calibration": point,
        "source_metrics": by_source, "strata": strata,
        "class_report": metrics["class_report"], "intervals": metrics["intervals"],
        "undefined_reasons": metrics["undefined_reasons"],
        "bundle_sha256": bundle["bundle_sha256"], "runtime_sha256": runtime_hash,
        "operating_point_path": point_file, "operating_point_sha256": digest(out / point_file),
        "predictions_path": test_file, "predictions_sha256": digest(out / test_file),
        "provenance": {"run": entry["run"], "bundle_path": f"{entry['run']}/bundle",
                       "config": bundle["metadata"]["config"], "data_variant": entry.get("data_variant", "primary"),
                       "data_manifest_sha256": fit["data_hashes"]["manifest.json"],
                       "selected_epoch": fit["selected_epoch"], "selection_roles": fit["selection_roles"],
                       "source_hashes": fit["source_hashes"], "fit_software": fit["software"],
                       "fit_device": fit["device_type"], "fit_amp": fit["amp"]},
        "performance": {"batch_size": 1, "device": "cpu", "threads": 1,
                        "test_inference_seconds": elapsed_test,
                        "mean_report_latency_ms": elapsed_test * 1000 / len(test_indices),
                        "latency_scope": "full test loop including Python dispatch and tensor conversion; inference cost, not detection time",
                        "model_weights_bytes": (bundle["path"] / "weights.pt").stat().st_size,
                        "parameters": result["parameters"], "process_peak_rss_bytes": memory,
                        "memory_scope": "whole evaluator process high-water RSS, including loaded data and prior models"},
        "verification": {"independent_reload_rescore_exact": True, "independently_rescored_test_groups": len(test_indices),
                         "calibration_recomputed_from_saved_scores": calibrate(calibration_scores.tolist(), 0.05) == point},
    }
    return model, {"indices": test_indices, "labels": labels[test_indices], "scores": test_scores,
                   "decisions": test_scores >= threshold if threshold is not None else np.zeros(len(test_indices), dtype=bool)}


def paired_comparisons(primary_predictions, replicates=1000):
    """Paired, class-stratified feature-group bootstrap, with fixed seed."""
    comparisons = []
    rng = np.random.default_rng(20261117)
    for first, second in itertools.combinations(sorted(primary_predictions), 2):
        left, right = primary_predictions[first], primary_predictions[second]
        if not np.array_equal(left["indices"], right["indices"]):
            raise ValueError("Paired models do not share the exact same test groups")
        labels = left["labels"]
        deltas = {"recall": [], "fpr": [], "accuracy": []}
        positive, negative = np.flatnonzero(labels == 1), np.flatnonzero(labels == 0)
        difference = left["decisions"].astype(float) - right["decisions"].astype(float)
        for _ in range(replicates):
            pos = rng.choice(positive, len(positive), replace=True)
            neg = rng.choice(negative, len(negative), replace=True)
            deltas["recall"].append(float(difference[pos].mean()))
            deltas["fpr"].append(float(difference[neg].mean()))
            deltas["accuracy"].append(float((difference[pos].sum() - difference[neg].sum()) / len(labels)))
        measured = {"recall": float(difference[positive].mean()), "fpr": float(difference[negative].mean()),
                    "accuracy": float((difference[positive].sum() - difference[negative].sum()) / len(labels))}
        comparisons.append({"first": first, "second": second, "difference": "first minus second", "replicates": replicates,
                            "seed": 20261117, "method": "paired class-stratified feature-group percentile bootstrap 95%",
                            "metrics": {name: {"difference": measured[name], "interval": np.quantile(values, [0.025, 0.975]).tolist()}
                                        for name, values in deltas.items()}})
    return comparisons


def evaluate(data_dir, campaign_dir, out):
    data_dir, campaign_dir, out = Path(data_dir), Path(campaign_dir), Path(out)
    campaign_path = campaign_dir / "campaign-complete.json"
    campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
    primary = campaign.get("primary", [])
    if {entry["id"] for entry in primary} != {"counts", "cnn", "gru"} or len(primary) != 3:
        raise ValueError("A frozen campaign must select exactly counts, CNN and GRU")
    if any(entry["seed"] != 17 for entry in primary):
        raise ValueError("Primary campaign models must use seed 17")
    campaign_verification = verify_campaign(campaign, campaign_dir, data_dir)
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    runtime = runtime_manifest()
    selected_inputs = {}
    data_inputs = {}
    for category in ("primary", "stability", "diagnostics"):
        for entry in campaign.get(category, []):
            run_dir = within(campaign_dir, entry["run"])
            selected_inputs[f"{category}/{entry['id']}/{entry['seed']}"] = {
                name: digest(run_dir / name) for name in ("result.json", "bundle/bundle.json", "bundle/weights.pt", "bundle/vocabulary.json")}
            variant = entry.get("data_variant", "primary")
            if variant not in {"primary", "api-component"}:
                raise ValueError("Unknown frozen data variant")
            variant_dir = data_dir if variant == "primary" else data_dir / variant
            data_inputs[variant] = {name: digest(variant_dir / name)
                                    for name in ("encoded.npz", "groups.jsonl", "vocabulary.json", "manifest.json")}
    identity = {"campaign_sha256": digest(campaign_path), "runtime_identity_sha256": canonical_hash(runtime),
                "data_manifest_sha256": digest(data_dir / "manifest.json"),
                "selected_inputs": selected_inputs, "data_inputs": data_inputs}
    out.mkdir(parents=True, exist_ok=True)
    lock_path = out / "evaluation-lock.json"
    if lock_path.exists():
        if json.loads(lock_path.read_text(encoding="utf-8")) != identity:
            raise ValueError("Evaluation input selection/data/runtime changed after lock; preserve the original export")
    else:
        atomic_json(lock_path, identity)
    receipt_path = out / "verification.json"
    if receipt_path.exists():
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if receipt["identity"] != identity:
            raise ValueError("Completed evaluation identity mismatch")
        for name, checksum in receipt["artifacts"].items():
            if digest(within(out, name)) != checksum:
                raise ValueError("Completed evaluation artifact checksum mismatch")
        return json.loads((out / "evaluation.json").read_text(encoding="utf-8"))
    prepared = load_prepared(data_dir)
    datasets = {"primary": prepared}
    atomic_json(out / "runtime.json", runtime)
    runtime_hash = digest(out / "runtime.json")
    results = {"primary": [], "stability": [], "diagnostics": []}
    primary_predictions = {}
    seen = set()
    for category in results:
        for entry in campaign.get(category, []):
            key = (category, entry["id"], entry["seed"])
            if key in seen:
                raise ValueError("Duplicate campaign evaluation entry")
            seen.add(key)
            variant = entry.get("data_variant", "primary")
            if variant not in {"primary", "api-component"}:
                raise ValueError("Unknown frozen data variant")
            variant_dir = data_dir if variant == "primary" else data_dir / variant
            if variant not in datasets:
                datasets[variant] = load_prepared(variant_dir)
            model, predictions = evaluate_model(entry, campaign_dir, variant_dir, datasets[variant], out, runtime_hash, category)
            results[category].append(model)
            if category == "primary":
                primary_predictions[entry["id"]] = predictions
    manifest = prepared["manifest"]
    report = {
        "schema": "xran-endpoint-evaluation-v1", "generated_at": datetime.now(timezone.utc).isoformat(),
        "nominal_fpr_budget": 0.05, "campaign_sha256": identity["campaign_sha256"],
        "runtime_sha256": runtime_hash, "runtime_path": "runtime.json",
        "campaign_verification": campaign_verification,
        "dataset": {"name": "XRan released processed feature dataset", "platform": "Windows",
                    "raw_rows": manifest["input_rows_accounted"], "cohort_groups": manifest["group_count"],
                    "test_groups": int((prepared["roles"] == 3).sum()),
                    "sources": [{"name": name, "count": count} for name, count in manifest["source_group_counts"].items()],
                    "source_count_unit": "retained feature groups; groups may belong to multiple sources",
                    "data_quality": {"quarantined_groups": manifest["quarantined_groups"],
                                     "quarantined_rows": manifest["quarantined_rows"],
                                     "retained_original_rows": manifest["retained_original_rows"],
                                     "rejected_rows": manifest["rejected_rows"],
                                     "api_overlap": manifest["api_overlap"]},
                    "split_seed": manifest["split_seed"], "split_kind": manifest["split_kind"],
                    "role_class_counts": manifest["role_class_counts"], "manifest_sha256": identity["data_manifest_sha256"]},
        "models": results["primary"],
        "diagnostics": {"stability": results["stability"], "feature_and_split_sensitivity": results["diagnostics"],
                        "seed_policy": "17 primary; 29 and 43 repeat tune-selected configurations with independent calibration; no best test seed",
                        "paired_comparisons": paired_comparisons(primary_predictions)},
        "limitations": LIMITATIONS,
    }
    atomic_json(out / "evaluation.json", report)
    artifacts = {path.name: digest(path) for path in out.iterdir() if path.is_file() and path.name != "verification.json" and not path.name.endswith(".tmp")}
    atomic_json(receipt_path, {"schema": "xran-evaluation-verification-v1", "identity": identity,
                              "artifacts": artifacts, "all_independent_rescores_exact": True,
                              "campaign_verification": campaign_verification,
                              "models_evaluated": sum(map(len, results.values()))})
    print(json.dumps({"event": "evaluation_complete", "report": str(out / "evaluation.json"),
                      "models": sum(map(len, results.values()))}), flush=True)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--campaign-dir", required=True)
    parser.add_argument("--out", required=True)
    arguments = parser.parse_args()
    evaluate(arguments.data_dir, arguments.campaign_dir, arguments.out)
