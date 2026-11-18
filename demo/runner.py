"""Compare two write-gate policies using disposable generated files."""

import argparse
import hashlib
import json
import math
import random
import sys
import tempfile
import time
from pathlib import Path


MAX_OBSERVATIONS = 120
MAX_BUNDLE_BYTES = 65_536
MARKER = b"\nDEMO: harmless marker\n"
DEMO_SCORES = [0.06, 0.21, 0.38, 0.74, 0.85, 0.88, 0.91, 0.93, 0.95, 0.96]


def validate_scores(bundle):
    if not isinstance(bundle, dict):
        raise ValueError("score bundle must be a JSON object")
    scores = bundle.get("scores")
    threshold = bundle.get("threshold")
    run_id = bundle.get("run_id")
    if not isinstance(scores, list) or not 1 <= len(scores) <= MAX_OBSERVATIONS:
        raise ValueError(f"provide 1–{MAX_OBSERVATIONS} scores")
    for value in [*scores, threshold]:
        if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
            raise ValueError("scores and threshold must be finite numbers in [0, 1]")
    if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 128:
        raise ValueError("run_id must be a nonempty string of at most 128 characters")
    return scores, threshold, run_id


def read_bundle():
    data = sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1)
    if len(data) > MAX_BUNDLE_BYTES:
        raise ValueError("score bundle is larger than 64 KiB")
    return validate_scores(json.loads(data))


def digests(paths):
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def append_marker(path):
    with path.open("ab") as fixture:
        fixture.write(MARKER)


def run_pair(observations, threshold, *, observe, seed, delay_ms, on_step=None):
    """Apply the same schedule twice and close the enforcement gate after an alert."""
    random_bytes = random.Random(seed)
    first_alert = None
    alert_elapsed_ms = None
    gate_closed_elapsed_ms = None
    observed_scores = []
    with tempfile.TemporaryDirectory(prefix="raneval-demo-") as directory:
        roots = {mode: Path(directory) / mode for mode in ("monitor_only", "enforce")}
        for root in roots.values():
            root.mkdir()
        paths = {mode: [] for mode in roots}
        for index in range(1, len(observations) + 1):
            data = random_bytes.randbytes(256)
            for mode, root in roots.items():
                path = root / f"fixture-{index:03d}.bin"
                path.write_bytes(data)
                paths[mode].append(path)
        before = {mode: digests(files) for mode, files in paths.items()}
        if before["monitor_only"] != before["enforce"]:
            raise RuntimeError("paired fixtures have different initial bytes")

        started = time.perf_counter_ns()
        for index, observation in enumerate(observations, start=1):
            append_marker(paths["monitor_only"][index - 1])
            blocked = first_alert is not None
            if not blocked:
                append_marker(paths["enforce"][index - 1])

            # The scheduled writes are attempted before the observation's score can alert.
            score = observe(observation)
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError(f"Observation {index} produced a score outside [0, 1]")
            observed_scores.append(score)
            alert_now = first_alert is None and threshold is not None and score >= threshold
            if alert_now:
                first_alert = index
                alert_elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
                gate_closed_elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            if on_step is not None:
                on_step(index, score, blocked, alert_now)
            if delay_ms and index < len(observations):
                time.sleep(delay_ms / 1000)

        modes = {}
        for mode, files in paths.items():
            after = digests(files)
            modified = [name for name, digest in after.items() if digest != before[mode][name]]
            modes[mode] = {"modified_files": modified, "final_sha256": after}

    return {
        "seed": seed,
        "scheduled_writes": len(observations),
        "threshold": threshold,
        "observed_scores": observed_scores,
        "first_alert_observation": first_alert,
        "alert_elapsed_ms": alert_elapsed_ms,
        "gate_closed_elapsed_ms": gate_closed_elapsed_ms,
        "blocked_writes": 0 if first_alert is None else len(observations) - first_alert,
        "initial_sha256": before["monitor_only"],
        **modes,
    }


def show_step(index, score, blocked, alert_now):
    gate_result = "blocked" if blocked else "committed"
    print(f"{index:03d}  score={score:.4f}  monitor=committed  enforce={gate_result}", flush=True)
    if alert_now:
        print(f"     ALERT at observation {index}. Gate closed for subsequent writes.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--delay-ms", type=int, choices=range(1001), default=300, metavar="0..1000")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--scores-stdin", action="store_true", help="Read a precomputed score bundle from stdin")
    source.add_argument("--model-bundle", type=Path, help="Frozen model artifact for live CPU inference")
    parser.add_argument("--bundle-sha256", help="Required checksum for a frozen model bundle")
    parser.add_argument("--apis", type=Path, help="Ordered API-name JSONL for live model inference")
    parser.add_argument("--alpha", type=float, help="Select a frozen nominal FPR threshold (default 0.05)")
    parser.add_argument("--reference-scores", type=Path, help="Offline score JSONL and adjacent metadata for a parity check")
    parser.add_argument("--json", action="store_true", help="Print a JSON result without live commentary")
    args = parser.parse_args()

    if args.model_bundle is None and any(value is not None for value in (
        args.apis, args.bundle_sha256, args.alpha, args.reference_scores,
    )):
        parser.error("--apis, --bundle-sha256, --alpha and --reference-scores require --model-bundle")

    try:
        if args.model_bundle is not None:
            if args.apis is None or args.bundle_sha256 is None:
                parser.error("--model-bundle requires --apis and --bundle-sha256")
            from model_adapter import load_live_replay

            observations, observe, metadata, verify = load_live_replay(
                args.model_bundle,
                args.apis,
                args.bundle_sha256,
                alpha=0.05 if args.alpha is None else args.alpha,
                reference_scores=args.reference_scores,
                max_observations=MAX_OBSERVATIONS,
            )
            threshold = metadata["frozen_threshold"]["tau"]
            run_id = metadata["bundle_sha256"]
            score_origin = "live_model_on_api_trace"
        elif args.scores_stdin:
            observations, threshold, run_id = read_bundle()
            metadata, verify = {}, None
            score_origin = "precomputed_scores"
        else:
            observations, threshold, run_id = DEMO_SCORES, 0.70, "synthetic-gate-fixture"
            metadata, verify = {}, None
            score_origin = "synthetic_fixture"

        if not args.json:
            threshold_label = "never alert" if threshold is None else f"{threshold:g}"
            print(f"Score source: {score_origin} ({run_id!r}). Threshold: {threshold_label}", flush=True)
        result = run_pair(
            observations,
            threshold,
            observe=observe if args.model_bundle is not None else float,
            seed=args.seed,
            delay_ms=args.delay_ms,
            on_step=None if args.json else show_step,
        )
        if verify is not None:
            metadata["offline_parity"] = verify(result)
    except (ValueError, OSError, ImportError) as exc:
        parser.error(str(exc))

    if args.json:
        print(json.dumps({"score_origin": score_origin, "run_id": run_id, **metadata, **result}, indent=2))
    else:
        monitor = len(result["monitor_only"]["modified_files"])
        enforce = len(result["enforce"]["modified_files"])
        print(f"Modified fixtures confirmed by SHA-256. Monitor-only: {monitor}. Enforce: {enforce}.")
        print(f"Blocked subsequent writes: {result['blocked_writes']}.")
        if "offline_parity" in metadata:
            maximum_error = metadata["offline_parity"]["max_absolute_score_difference"]
            print(f"Offline parity verified. Maximum absolute score difference: {maximum_error:.3g}.")


if __name__ == "__main__":
    main()
