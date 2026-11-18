"""Load verified frozen artifacts and compare live scores with offline replay."""

import hashlib
import json
import math
import re


MAX_API_BYTES = 65_536
PARITY_TOLERANCE = 1e-6


def read_trace(path, max_observations):
    with path.open("rb") as stream:
        data = stream.read(MAX_API_BYTES + 1)
    if len(data) > MAX_API_BYTES:
        raise ValueError("API trace is larger than 64 KiB")
    records = [json.loads(line.decode("utf-8")) for line in data.split(b"\n") if line.strip()]
    if not 1 <= len(records) <= max_observations:
        raise ValueError(f"Provide 1–{max_observations} observed API records for this demo")
    if any(not isinstance(api, str) or not api.strip() for api in records):
        raise ValueError("Every API trace record must be a nonempty JSON string")
    return records, hashlib.sha256(data).hexdigest()


def read_reference(path, expected_metadata, observation_count):
    sidecar = path.with_suffix(path.suffix + ".meta.json")
    metadata = json.loads(sidecar.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("Offline score metadata must be an object")
    for key, expected in expected_metadata.items():
        if metadata.get(key) != expected:
            raise ValueError(f"Offline replay metadata differs for {key}")
    if metadata.get("observed_horizon") != observation_count:
        raise ValueError("Offline replay and demo observation counts differ")
    records = []
    with path.open(encoding="utf-8") as stream:
        for index, line in enumerate(stream, start=1):
            if index > observation_count:
                raise ValueError("Offline replay contains extra observations")
            row = json.loads(line)
            if not isinstance(row, dict) or row.get("observation_index") != index:
                raise ValueError(f"Offline replay is missing ordered observation {index}")
            score = row.get("score")
            if type(score) not in (int, float) or not 0 <= score <= 1 or not math.isfinite(score):
                raise ValueError(f"Offline score {index} must be a finite number in [0, 1]")
            records.append(score)
    if len(records) != observation_count:
        raise ValueError("Offline replay is missing observations")
    threshold = metadata["threshold"]["tau"]
    first_alert = next((index for index, score in enumerate(records, 1) if threshold is not None and score >= threshold), None)
    if "first_observation" not in metadata or metadata["first_observation"] != first_alert:
        raise ValueError("Offline alert metadata does not match the offline scores")
    return records, first_alert


def verify_replay(result, expected, expected_alert):
    actual = result["observed_scores"]
    if len(actual) != len(expected):
        raise ValueError("Offline replay and demo score counts differ")
    maximum_difference = max(abs(left - right) for left, right in zip(actual, expected))
    if maximum_difference > PARITY_TOLERANCE:
        raise ValueError(f"Offline and live scores differ by up to {maximum_difference:.3g}")
    if result["first_alert_observation"] != expected_alert:
        raise ValueError("Offline and live first-alert observations differ")
    return {
        "observations_checked": len(expected),
        "max_absolute_score_difference": maximum_difference,
        "first_alert_observation": expected_alert,
    }


def load_live_replay(bundle_path, trace_path, checksum, *, alpha, reference_scores, max_observations):
    if re.fullmatch(r"[0-9a-f]{64}", checksum) is None:
        raise ValueError("Use the frozen lowercase 64-character SHA-256 checksum")
    observations, trace_digest = read_trace(trace_path, max_observations)

    import torch
    from raneval.score import StreamingScorer, load_bundle

    torch.set_num_threads(1)
    device = torch.device("cpu")
    bundle, model, verified_digest = load_bundle(bundle_path, device, checksum)
    thresholds = [item for item in bundle["thresholds"] if item["alpha"] == alpha]
    if len(thresholds) != 1:
        raise ValueError(f"Bundle has no unique frozen threshold for alpha={alpha}")
    threshold = thresholds[0]
    if bundle["horizon"] and len(observations) > bundle["horizon"]:
        raise ValueError("Demo trace is longer than the frozen replay horizon")
    scorer = StreamingScorer(bundle, model, device)
    metadata = {
        "bundle_sha256": verified_digest,
        "api_trace_sha256": trace_digest,
        "architecture": bundle["architecture"],
        "frozen_threshold": threshold,
    }
    verify = None
    if reference_scores is not None:
        expected, first_alert = read_reference(
            reference_scores,
            {
                "bundle_sha256": verified_digest,
                "api_trace_sha256": trace_digest,
                "architecture": bundle["architecture"],
                "threshold": threshold,
            },
            len(observations),
        )

        def verify(result):
            return verify_replay(result, expected, first_alert)

    return observations, scorer.step, metadata, verify
