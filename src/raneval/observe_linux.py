"""Score a stream of completed Linux file operations with a frozen contextual GRU."""

import argparse
import json
import math
import sys
from pathlib import Path

import torch

from .context_score import ContextStreamingScorer, load_context_bundle


def observe(stream, scorer, threshold, horizon, output):
    first_alert = None
    maximum = None
    last_ms = -1.0
    observed = 0
    scored = 0
    for line_number, line in enumerate(stream, 1):
        if not line.strip():
            continue
        event = json.loads(line)
        if not isinstance(event, dict):
            raise ValueError(f"Expected a completed syscall object on line {line_number}")
        timestamp = event.get("time_ms")
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < max(last_ms, 0):
            raise ValueError(f"Invalid completion time on line {line_number}")
        last_ms = timestamp
        observed += 1
        if horizon and scored >= horizon:
            continue
        score = scorer.step(event)
        scored += 1
        maximum = score if maximum is None else max(maximum, score)
        crossed = threshold is not None and score >= threshold
        if crossed and first_alert is None:
            first_alert = {"event": scored, "elapsed_ms": timestamp}
        print(json.dumps({"event": scored, "op": event["op"], "elapsed_ms": timestamp,
                          "score": score, "alert": crossed}, allow_nan=False), file=output, flush=True)
    if not scored:
        raise ValueError("The observation stream supplied no completed file operations")
    return {"observed_events": observed, "scored_events": scored, "max_score": maximum,
            "first_alert": first_alert}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--expected-sha256")
    args = parser.parse_args(argv)

    torch.set_num_threads(1)
    device = torch.device("cpu")
    bundle, model, checksum = load_context_bundle(args.bundle, device, args.expected_sha256)
    thresholds = [item for item in bundle["thresholds"] if item["alpha"] == 0.05]
    if len(thresholds) != 1:
        raise ValueError("Expected one frozen threshold for the 5% target")
    threshold = thresholds[0]["tau"]
    summary = observe(sys.stdin, ContextStreamingScorer(bundle, model, device),
                      threshold, bundle["horizon"], sys.stdout)
    print(json.dumps({"summary": {**summary, "threshold": threshold, "bundle_sha256": checksum}},
                     allow_nan=False), flush=True)


if __name__ == "__main__":
    main()
