"""Run an interactive, fixture-only comparison of a simulated lock gate."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import stat
import string
import time

from model_adapter import load_live_replay, read_trace


ROOT = Path("/tmp/raneval-interactive")
INPUTS = Path("/inputs")
SEED = 42
MAX_OBSERVATIONS = 120
SUFFIX = ".sim-locked"
MODES = ("control", "protected")


def fixture_name(index):
    return f"fixture-{index:03d}.txt"


def fixture_payloads(count):
    generator = random.Random(SEED)
    alphabet = string.ascii_letters + string.digits
    for index in range(1, count + 1):
        content = "".join(generator.choices(alphabet, k=96))
        yield fixture_name(index), f"Synthetic demo file {index:03d}\nRandom payload: {content}\n".encode("ascii")


def require_directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError(f"Expected a real demo directory at {path}")


def read_owned_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"Expected a regular demo file at {path.name}")
    return path.read_bytes()


def save_json(path, data):
    pending = path.with_suffix(".pending")
    with pending.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, allow_nan=False)
        stream.write("\n")
    pending.replace(path)


def initialize(root, inputs, mode):
    trace, trace_hash = read_trace(inputs / "apis.jsonl", MAX_OBSERVATIONS)
    try:
        root.mkdir()
    except FileExistsError:
        raise ValueError("This container already has demo state. Recreate it for fresh fixtures.") from None
    fixtures = root / "files"
    fixtures.mkdir()
    before = {}
    for name, data in fixture_payloads(len(trace)):
        with (fixtures / name).open("xb") as stream:
            stream.write(data)
        before[name] = hashlib.sha256(data).hexdigest()
    state = {
        "mode": mode,
        "seed": SEED,
        "total_files": len(trace),
        "api_trace_sha256": trace_hash,
        "initial_sha256": before,
    }
    save_json(root / "initial.json", state)
    return state


def load_state(root, mode):
    require_directory(root)
    require_directory(root / "files")
    state = json.loads(read_owned_file(root / "initial.json"))
    if state["mode"] != mode or state["seed"] != SEED or not 1 <= state["total_files"] <= MAX_OBSERVATIONS:
        raise ValueError("Demo state does not match this container")
    expected = {name: hashlib.sha256(data).hexdigest() for name, data in fixture_payloads(state["total_files"])}
    if state["initial_sha256"] != expected:
        raise ValueError("Initial fixture manifest differs from the seeded fixtures")
    return state


def inventory(fixtures, before):
    listed = {path.name for path in fixtures.iterdir()}
    if len(listed) != len(before):
        raise ValueError("Unexpected number of demo fixture files")
    after = {}
    locked = []
    for name in before:
        candidates = listed.intersection((name, name + SUFFIX))
        if len(candidates) != 1:
            raise ValueError(f"Unexpected fixture layout for {name}")
        actual = candidates.pop()
        after[name] = hashlib.sha256(read_owned_file(fixtures / actual)).hexdigest()
        if actual.endswith(SUFFIX):
            locked.append(name)
    return locked, after


def simulate(root, inputs, mode, delay_ms):
    state = load_state(root, mode)
    fixtures = root / "files"
    initial = state["initial_sha256"]
    trace, trace_hash = read_trace(inputs / "apis.jsonl", MAX_OBSERVATIONS)
    if len(trace) != state["total_files"] or trace_hash != state["api_trace_sha256"]:
        raise ValueError("Recorded trace changed after initialization")
    marker = root / "started"
    if marker.exists():
        raise ValueError("Simulation already started. Recreate the container to replay from the beginning.")
    locked, before = inventory(fixtures, initial)
    if locked or before != initial:
        raise ValueError("Demo fixtures differ from the initial state")

    observe = verify = threshold = None
    metadata = {}
    if mode == "protected":
        frozen = json.loads((inputs / "frozen.json").read_bytes())
        trace, observe, metadata, verify = load_live_replay(
            inputs / "bundle.pt", inputs / "apis.jsonl", frozen["bundle_sha256"],
            alpha=0.05, reference_scores=inputs / "scores.jsonl", max_observations=MAX_OBSERVATIONS,
        )
        if metadata["api_trace_sha256"] != trace_hash:
            raise ValueError("Recorded trace changed while loading the model")
        threshold = metadata["frozen_threshold"]["tau"]

    try:
        with marker.open("x", encoding="ascii") as stream:
            stream.write("Simulation started\n")
    except FileExistsError:
        raise ValueError("Another simulation already started in this container") from None

    alert = None
    scores = []
    blocked = 0
    for index, api in enumerate(trace, 1):
        name = fixture_name(index)
        if alert is None:
            target = fixtures / name
            marked = fixtures / (name + SUFFIX)
            content = read_owned_file(target)
            if marked.exists() or hashlib.sha256(content).hexdigest() != initial[name]:
                raise ValueError(f"Fixture changed during the simulation: {name}")
            target.rename(marked)
            action = f"simulated lock  {name}{SUFFIX}"
        else:
            blocked += 1
            action = f"blocked         {name}"
        score_label = ""
        if observe is not None:
            score = observe(api)
            if not math.isfinite(score) or not 0 <= score <= 1:
                raise ValueError(f"Model produced an invalid score at observation {index}")
            scores.append(score)
            score_label = f"score={score:.6f}  "
        print(f"{index:03d}  {score_label}{action}", flush=True)
        # The current fixture action precedes its score, so the gate applies from the next action.
        if alert is None and threshold is not None and scores[-1] >= threshold:
            alert = index
            print(f"ALERT at observation {index}. The gate blocks the remaining simulated locks.", flush=True)
        if delay_ms and index < len(trace):
            time.sleep(delay_ms / 1000)

    locked, after = inventory(fixtures, initial)
    if after != initial or len(locked) + blocked != len(trace):
        raise ValueError("Final fixture integrity or gate counts differ from the expected simulation")
    result = {
        **metadata,
        "simulated_locks": len(locked),
        "denied_locks": blocked,
        "first_alert_observation": alert,
        "observed_scores": scores,
        "final_sha256": after,
    }
    if verify is not None:
        result["offline_parity"] = verify(result)
    save_json(root / "result.json", result)
    return result


def summarize(root, mode):
    state = load_state(root, mode)
    if (root / "result.json").exists():
        result = json.loads(read_owned_file(root / "result.json"))
        phase = "complete"
    elif (root / "started").exists():
        # ls can show progress during the run without racing an inventory/hash snapshot.
        return {**state, "phase": "started_unfinished"}
    else:
        result = {}
        phase = "ready"
    locks, checksums = inventory(root / "files", state["initial_sha256"])
    return {**state, **result, "phase": phase, "simulated_locks": len(locks),
            "untouched_files": state["total_files"] - len(locks),
            "integrity_ok": checksums == state["initial_sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create identical random text fixtures in this container")
    replay = commands.add_parser("simulate", help="Replay the fixed fixture workload")
    replay.add_argument("--delay-ms", type=int, choices=range(1001), metavar="0..1000", default=75)
    status = commands.add_parser("status", help="Show live fixture state and verification counts")
    status.add_argument("--json", action="store_true", help="Print the full machine-readable result")
    args = parser.parse_args()
    mode = os.environ.get("RANEVAL_DEMO_MODE")
    if mode not in MODES:
        parser.error("Container must set RANEVAL_DEMO_MODE=control or protected")
    try:
        if args.command == "init":
            state = initialize(ROOT, INPUTS, mode)
            print(f"{mode}: generated {state['total_files']} dummy text files in {ROOT / 'files'}")
            return
        if args.command == "simulate":
            simulate(ROOT, INPUTS, mode, args.delay_ms)
        result = summarize(ROOT, mode)
    except (OSError, ValueError, KeyError, RuntimeError, ImportError) as exc:
        parser.error(str(exc))
    if args.command == "status" and args.json:
        print(json.dumps(result, indent=2, allow_nan=False))
    elif result["phase"] == "started_unfinished":
        print(f"{mode}: a run started and has yet to record a complete result. Inspect the files with ls.")
    else:
        print(f"{mode}: {result['phase']}. Simulated locks {result['simulated_locks']}/{result['total_files']}. "
              f"Untouched names {result['untouched_files']}. Original bytes intact: {result['integrity_ok']}.")
        if result["phase"] == "complete":
            print(f"First alert: {result['first_alert_observation']}. Blocked actions: {result['denied_locks']}.")


if __name__ == "__main__":
    main()
