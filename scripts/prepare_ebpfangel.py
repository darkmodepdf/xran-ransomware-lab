"""Prepare native Linux event sequences from the pinned ebpfangel telemetry release."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import urlopen


REPOSITORY = "https://github.com/TomasPhilippart/ebpfangel"
REVISION = "d5e7d3cdebf19474722a97a6238b8f737d16b7d0"
RAW_URL = f"https://raw.githubusercontent.com/TomasPhilippart/ebpfangel/{REVISION}"
PID_OFFSET = 10_000  # The publisher numbers captures independently in each source partition.
EVENT_NAMES = {0: "open", 1: "create", 2: "delete", 3: "encrypt"}
ROLE_PRIORITY = {"train": 0, "tune": 1, "calibrate": 2, "test": 3}
FAMILY_ROLES = {"REvil": "train", "IceFire": "train", "Monti": "tune", "AvosLocker": "test"}

# File names and Git blob IDs from the pinned publisher tree. Unknown-family
# captures are audited without entering the cohort. Named attack captures need
# a resolved publisher PID before their data is used.
CAPTURES = {
    "logs/training/1_blackmatterlog.csv": ("BlackMatter", "659919a488f9eb2c9f3a608042c2ad321b604160"),
    "logs/training/2_log2.csv": (None, "86bf6c1f2aeec6716997962f73ada7d339abf398"),
    "logs/training/3_revilog2.csv": ("REvil", "014556aeba120d8871b6552da7a8e4006182badc"),
    "logs/training/4_log.csv": (None, "d642096592327ec0697901c8eac3b27281c94262"),
    "logs/training/5_log4.csv": (None, "987acf8f790f22744ee1cef56658e902de2a9f20"),
    "logs/training/6_revilog.csv": ("REvil", "80a9938185a8b50549d914024c6f8263326b6be0"),
    "logs/training/7_log3.csv": (None, "99ce313f0abed45818582cc9ebf0c7e03680697c"),
    "logs/training/8_iFire.csv": ("IceFire", "6e44bf8452de930eff723e74166cb37ee71e0384"),
    "logs/training/90_Avoslocker0.csv": ("AvosLocker", "6b7a8a49edc223594538f859f08f91887a98d3d5"),
    "logs/training/91_Avoslocker1.csv": ("AvosLocker", "0c8f6aa2a3d9db212141265644e80f2b5fd4d952"),
    "logs/training/92_Benign0.csv": ("BENIGN", "af321d3faab510c0dd17ed59ad574b645398911e"),
    "logs/training/93_Benign1.csv": ("BENIGN", "122431474f2262b670c87206eae1d95d70b3dabd"),
    "logs/training/94_cl0p.csv": ("Cl0p", "9cef32c6191ecff38a5f858b52306ef05b9eca95"),
    "logs/training/95_REvil0.csv": ("REvil", "f91eccaa8e0192221c99fb5c341b96146dcf36b9"),
    "logs/training/96_REvil1.csv": ("REvil", "38b4b7d8fe2698273a4abcd3c2714ad36350f5c1"),
    "logs/testing/1_benignlog.csv": ("BENIGN", "891d03df1ae34f192b9537eff3ddb7f304ea53bf"),
    "logs/testing/2_revilog1.csv": ("REvil", "e996005daf7f9601528923f464cba86ffe3d09c3"),
    "logs/testing/3_log0.csv": (None, "370c92a917a8f90c25c5e5cd459e54168c74a503"),
    "logs/testing/90_Avoslocker2.csv": ("AvosLocker", "0ffffb35eafbaee8e182703f1bc47f6284aa1e43"),
    "logs/testing/91_Avoslocker3.csv": ("AvosLocker", "129e631d622b1408a79a8586b1f0768567accde1"),
    "logs/testing/92_Benign2.csv": ("BENIGN", "303e89042db4619bac7116310d9e08ac3159545a"),
    "logs/testing/93_BlackMatter.csv": ("BlackMatter", "fff34879e044af01d16c9757393297ec5a03a6d8"),
    "logs/testing/94_HelloKitty.csv": ("HelloKitty", "2e28d7ed127384808855899454bdef3411a56f3e"),
    "logs/testing/95_IceFire.csv": ("IceFire", "ddd38f55baa1bc21365bed75d36c2a2169e69f36"),
    "logs/testing/96_Monti.csv": ("Monti", "cc6334e8a72a1ea7b03f980cb30014930d4a6da0"),
    "logs/testing/97_REvil2.csv": ("REvil", "0c2b3c3168c6446c2f71f252881ec320f0c4d711"),
}
CLEAN_ROLES = {
    "logs/training/92_Benign0.csv": "train",
    "logs/training/93_Benign1.csv": "calibrate",
    "logs/testing/92_Benign2.csv": "calibrate",
    "logs/testing/1_benignlog.csv": "test",
}
SOURCE_FILES = {
    **{name: blob for name, (_, blob) in CAPTURES.items()},
    "data/training_labels.csv": "138d7aeb161648fb22c97692ca9d4e5e07f063fa",
    "data/testing_labels.csv": "954df0d9ed1b511ae657dde1e20899440968f1ae",
    "machinelearning/dataprep.py": "b42564062a8c67930bd5b074d90ef68de85cd288",
    "LICENSE": "b4e0f43af908552ca4ab239ce82d5801d2615231",
}


def blob_id(content):
    digest = hashlib.sha1(f"blob {len(content)}\0".encode())
    digest.update(content)
    return digest.hexdigest()


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_suffix(path.suffix + ".partial")
    partial.write_bytes(content)
    partial.replace(path)


def verify_sources(root, download):
    def verify(entry):
        name, expected = entry
        path = root / name
        content = path.read_bytes() if path.is_file() else b""
        if blob_id(content) != expected and download:
            with urlopen(f"{RAW_URL}/{name}", timeout=30) as stream:
                content = stream.read(30_000_001)
            if blob_id(content) != expected:
                raise ValueError(f"Publisher blob verification failed for {name}")
            atomic_write(path, content)
        if blob_id(content) != expected:
            raise ValueError(f"Missing or changed publisher file {name}; rerun with --download")
        return name, hashlib.sha256(content).hexdigest()

    with ThreadPoolExecutor(max_workers=6) as workers:
        return dict(workers.map(verify, SOURCE_FILES.items()))


def read_capture(path, limit):
    prefixes = defaultdict(list)
    lengths = Counter()
    prior_timestamps = {}
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as stream:
        rows = csv.DictReader(stream)
        if not {"TS", "PID", "TYPE"}.issubset(rows.fieldnames or []):
            raise ValueError(f"Expected TS, PID and TYPE in {path}")
        for row in rows:
            pid, timestamp = int(row["PID"]), int(row["TS"])
            if pid <= 0 or timestamp < prior_timestamps.get(pid, 0):
                raise ValueError(f"Invalid PID or per-process event order at {path}:{rows.line_num}")
            prior_timestamps[pid] = timestamp
            event = EVENT_NAMES[int(row["TYPE"])]
            if lengths[pid] < limit:
                prefixes[pid].append(event)
            lengths[pid] += 1
    return prefixes, lengths


def stable_id(kind, *fields):
    return hashlib.sha256("/".join((kind, REVISION, *map(str, fields))).encode()).hexdigest()[:24]


def prepare(root, limit):
    traces = []
    capture_audit = {}
    label_audit = {}
    positive_audit = []
    trace_provenance = {}
    for partition in ("training", "testing"):
        with (root / f"data/{partition}_labels.csv").open(encoding="utf-8-sig", newline="") as stream:
            labels = {int(row["PID"]) for row in csv.DictReader(stream)}
        paths = sorted(name for name in CAPTURES if name.startswith(f"logs/{partition}/"))
        matches = defaultdict(list)
        captures = []
        for index, name in enumerate(paths):
            prefixes, lengths = read_capture(root / name, limit)
            for pid in lengths:
                publisher_pid = pid + index * PID_OFFSET
                if publisher_pid in labels:
                    matches[publisher_pid].append((name, pid))
            captures.append((name, prefixes, lengths))

        ambiguous = {pid: choices for pid, choices in matches.items() if len(choices) != 1}
        if ambiguous:
            raise ValueError(f"Ambiguous {partition} publisher label assignments: {ambiguous}")
        positives_by_capture = defaultdict(set)
        for ((name, pid),) in matches.values():
            positives_by_capture[name].add(pid)
        label_audit[partition] = {
            "published_positive_pids": len(labels),
            "resolved_positive_pids": len(matches),
            "unresolved_publisher_pids": sorted(labels - matches.keys()),
        }

        for name, prefixes, lengths in captures:
            family = CAPTURES[name][0]
            positives = positives_by_capture[name]
            capture_role = CLEAN_ROLES.get(name) if family == "BENIGN" else FAMILY_ROLES.get(family) if positives else None
            if family == "BENIGN" and positives:
                raise ValueError(f"Publisher positive PID in a named clean capture: {name}")
            disposition = "included" if capture_role else "unknown_family" if family is None else "no_resolved_positive_pid"
            capture_audit[name] = {
                "family": family,
                "role": capture_role,
                "disposition": disposition,
                "events": sum(lengths.values()),
                "pids": len(lengths),
                "publisher_positive_pids": len(positives),
            }
            if capture_role is None:
                continue

            group_id = stable_id("capture", name) if family == "BENIGN" else stable_id("family", family)
            for pid, prefix in sorted(prefixes.items()):
                trace_id = stable_id("process", name, pid)
                label = "RANSOMWARE" if pid in positives else "BENIGN"
                row = dict(trace_id=trace_id, label=label, role=capture_role, group_id=group_id, apis=prefix)
                traces.append((name, row))
                trace_provenance[trace_id] = dict(capture=name, family=family, observed_events=lengths[pid])
                if label == "RANSOMWARE":
                    positive_audit.append(dict(trace_id=trace_id, capture=name, family=family, role=capture_role,
                                               events=lengths[pid], retained_events=len(prefix)))

    # The shared loader forbids exact sequence reuse across statistical roles.
    # Preserve test first, then calibration, so duplicate removal cannot thin
    # those cohorts in favor of training or tuning.
    strongest_role = {}
    for _, row in traces:
        key = tuple(row["apis"])
        rank = ROLE_PRIORITY[row["role"]]
        strongest_role[key] = max(rank, strongest_role.get(key, rank))
    retained = []
    role_counts = Counter()
    removed = Counter()
    for capture, row in traces:
        key = f'{row["role"]}/{row["label"]}'
        if ROLE_PRIORITY[row["role"]] != strongest_role[tuple(row["apis"])]:
            removed[key] += 1
            continue
        retained.append(row)
        role_counts[key] += 1
        capture_audit[capture]["retained_pids"] = capture_audit[capture].get("retained_pids", 0) + 1

    for role in ROLE_PRIORITY:
        for label in ("BENIGN", "RANSOMWARE") if role != "calibrate" else ("BENIGN",):
            if not role_counts[f"{role}/{label}"]:
                raise ValueError(f"Empty {role}/{label} cohort after duplicate filtering")
    kept_ids = {row["trace_id"] for row in retained}
    for entry in positive_audit:
        entry["retained"] = entry["trace_id"] in kept_ids

    return retained, {
        "source_repository": REPOSITORY,
        "source_revision": REVISION,
        "source_license": "MIT",
        "schema_version": "ebpfangel-sequences-v1",
        "max_observations": limit,
        "event_vocabulary": EVENT_NAMES,
        "family_roles": FAMILY_ROLES,
        "trace_count": len(retained),
        "role_counts": dict(role_counts),
        "cross_role_duplicate_exclusions": dict(removed),
        "publisher_labels": label_audit,
        "captures": capture_audit,
        "positive_traces": positive_audit,
        "trace_provenance": {trace_id: info for trace_id, info in trace_provenance.items() if trace_id in kept_ids},
        "limitations": [
            "Named ransomware captures contribute positives only where the publisher PID resolves in the raw CSV.",
            "Other PIDs in those captures are publisher-negative background and share a capture group.",
            "Only selected eBPF events are observed. The trace does not establish successful file modifications.",
            "PID-level alert counts are descriptive because processes within a capture are correlated.",
            "Duplicate removal can alter the distribution of processes in the earlier statistical roles.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", type=Path, default=Path("data/raw/ebpfangel"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--audit", type=Path, required=True)
    parser.add_argument("--max-observations", type=int, default=2048)
    parser.add_argument("--download", action="store_true", help="Fetch missing or invalid pinned source CSVs")
    args = parser.parse_args()
    if args.max_observations < 1 or args.output.resolve() == args.audit.resolve():
        parser.error("Use a positive observation limit and distinct output and audit paths")
    hashes = verify_sources(args.raw, args.download)
    rows, audit = prepare(args.raw, args.max_observations)
    contents = "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in rows).encode()
    audit["source_sha256"] = hashes
    audit["training_jsonl_sha256"] = hashlib.sha256(contents).hexdigest()
    atomic_write(args.output, contents)
    atomic_write(args.audit, (json.dumps(audit, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps({"trace_count": audit["trace_count"], "role_counts": audit["role_counts"]}, sort_keys=True))


if __name__ == "__main__":
    main()
