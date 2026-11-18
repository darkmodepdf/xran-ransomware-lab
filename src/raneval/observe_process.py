"""Observe Linux task behavior using an explicitly calibrated per-task model."""

import argparse
import json
import math
from pathlib import Path
import sys

import torch

from .context_score import load_context_bundle
from .process_score import ProcessStreamingScorer
from .score import load_bundle


def observe(stream, scorer, threshold, session_horizon, output):
    first_alert = None
    maximum = 0.0
    seen = 0
    last_time = -1.0
    for line in stream:
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict) or event.get("schema") != "raneval-observed-syscall-v1":
            raise ValueError("Expected the versioned Linux observed-call schema")
        if (event.get("order") != "observed" or type(event.get("sequence")) is not int
                or event["sequence"] != seen + 1):
            raise ValueError("Observed calls must have contiguous delivery sequence numbers")
        timestamp = event.get("time_ms")
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < max(0, last_time):
            raise ValueError("Invalid displayed observation time")
        if type(event.get("completion_time_ns")) is not int or event["completion_time_ns"] < 0:
            raise ValueError("Expected an exact nonnegative completion timestamp")
        result = scorer.step(event)
        seen += 1
        last_time = timestamp
        maximum = max(maximum, result["score"])
        alert = threshold is not None and result["score"] >= threshold
        if alert and first_alert is None:
            first_alert = {**result, "elapsed_ms": timestamp}
        print(json.dumps({**result, "op": event["op"], "alert": alert, "elapsed_ms": timestamp,
                          "within_calibration_horizon": seen <= session_horizon}, allow_nan=False),
              file=output, flush=True)
    if not seen:
        raise ValueError("No completed operations received")
    return {"observed_events": seen, "scored_events": seen, "active_tasks": scorer.active_actor_count,
            "first_alert": first_alert, "max_score": maximum,
            "beyond_calibration_horizon": max(0, seen - session_horizon)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--operating-point", type=Path, required=True)
    parser.add_argument("--max-actors", type=int, default=1024)
    args = parser.parse_args()
    point = json.loads(args.operating_point.read_bytes())
    if point.get("schema") != "raneval-process-operating-point-v1" or point.get("scope") != "actor":
        raise ValueError("Expected a calibrated per-task operating point")
    if point.get("runtime_scoring") is not True:
        raise ValueError("Operating point must be calibrated using the deployed streaming scorer")
    if point.get("model_id") not in {"counts_actor", "cnn_actor", "gru_refit_actor", "gru_context_actor", "gru_task_actor"}:
        raise ValueError("Unknown per-task model identifier")
    threshold = point["threshold"]
    if threshold is not None and (type(threshold) not in (int, float)
                                  or not math.isfinite(threshold) or not 0 <= threshold <= 1):
        raise ValueError("Invalid frozen cutoff")
    horizon = point["session_horizon"]
    if type(horizon) is not int or horizon <= 0:
        raise ValueError("Expected a finite calibration session horizon")
    torch.set_num_threads(1)
    device = torch.device("cpu")
    loader = load_context_bundle if point["model_id"] == "gru_context_actor" else load_bundle
    bundle, model, checksum = loader(args.bundle, device, point["bundle_sha256"])
    if point["block_size"] != bundle["block_size"]:
        raise ValueError("Reset policy differs from the operating point")
    scorer = ProcessStreamingScorer(bundle, model, device, args.max_actors)
    summary = observe(sys.stdin, scorer, threshold, horizon, sys.stdout)
    print(json.dumps({"summary": {**summary, "bundle_sha256": checksum, "threshold": threshold,
                                 "operating_point": point["model_id"],
                                 "calibration_unit": point["calibration_unit"],
                                 "collection_order": "observed", "calibration_order": "completed",
                                 "operating_point_validated_for_observed_order": False}}, allow_nan=False))


if __name__ == "__main__":
    main()
