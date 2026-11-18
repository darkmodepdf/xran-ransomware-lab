"""Pinned XRan CSV preparation, feature identities, splits and train-only encoding.

The row identifiers and feature hashes identify released feature rows, never
executables. All string values, positions, case and literal PRF are preserved.
"""
from __future__ import annotations

import collections
import csv
import hashlib
import io
import json
import math
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

import numpy as np

COMMIT = "2cfebbfe45d3ed47b0204096186877e5991d6324"
SPLIT_SEED = 20261117
ROLES = ("train", "tune", "calibration", "test")
VIEWS = {"api": (0, 500), "dll": (500, 510), "mutex": (510, 520)}
HEADER = ([f"ApiCall_{i}" for i in range(500)] +
          [f"Dll_{i}" for i in range(10)] + [f"Mutex_{i}" for i in range(10)])
PINNED_SHA256 = {
    "ISOT": "2617002b3c6d30fe54f1c42ee2f0d1a925fe683a33540e311c02747b6c389fc8",
    "Sorel20M": "e86f5f2e7eb4e09f063276a82366a8d84febee5b95893f52553225976b2618c6",
    "VirusShare": "18686643ba6fc530d946f944667b20fc8b73c02320f1555f86b511e3c155eec0",
    "Benign": "0fb4258318f7aedb79097842ccbd40d85e5892fa9e3431ad4698823328d3bccb",
}
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_FIELD_CHARACTERS = 64 * 1024


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                      sort_keys=True, allow_nan=False).encode("utf-8")


def fingerprint(cells: Iterable[str]) -> str:
    """Exactly the existing flat-cell audit hash, with no normalization."""
    return hashlib.sha256(canonical_json(list(cells))).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(canonical_json(value) + b"\n")


def _write_jsonl(path: Path, values: Iterable[object]) -> None:
    with path.open("wb") as stream:
        for value in values:
            stream.write(canonical_json(value) + b"\n")


@dataclass(frozen=True)
class FeatureRow:
    row_id: str
    source: str
    label: int
    cells: tuple[str, ...]
    feature_sha256: str
    api_sha256: str

    @classmethod
    def create(cls, row_id: str, source: str, label: int,
               cells: Iterable[str]) -> "FeatureRow":
        values = tuple(cells)
        if len(values) != 520 or any(not isinstance(cell, str) for cell in values):
            raise ValueError("XRan rows require exactly 520 strings")
        if label not in (0, 1):
            raise ValueError("XRan labels must be 0 or 1")
        return cls(row_id, source, int(label), values, fingerprint(values),
                   fingerprint(values[:500]))

    @property
    def quality(self) -> dict:
        return {"empty_counts": {name: self.cells[a:b].count("")
                                  for name, (a, b) in VIEWS.items()},
                "prf_counts": {name: self.cells[a:b].count("PRF")
                                for name, (a, b) in VIEWS.items()},
                "all_empty": all(cell == "" for cell in self.cells),
                "parse_status": "valid"}


def read_release(manifest: str | Path, *, require_pinned: bool = True
                 ) -> tuple[list[FeatureRow], list[dict]]:
    """Verify archives before reading; malformed-width records enter a ledger.

    Integrity, encoding, header and CSV syntax errors abort: a corrupt member
    cannot be safely assigned row identities. No archive is extracted.
    require_pinned=False permits synthetic manifests only (used by tests).
    """
    manifest = Path(manifest)
    inventory = json.loads(manifest.read_text(encoding="utf-8"))
    if require_pinned:
        if inventory.get("commit") != COMMIT:
            raise ValueError("Unpinned release commit")
        if {a["name"]: a["sha256"] for a in inventory["archives"]} != PINNED_SHA256:
            raise ValueError("Unpinned archive identity")
        if len(inventory["archives"]) != 4:
            raise ValueError("Expected the four original XRan archives")
    rows, rejected = [], []
    old_limit = csv.field_size_limit(MAX_FIELD_CHARACTERS)
    try:
        for entry in sorted(inventory["archives"], key=lambda a: a["name"]):
            source, label = entry["name"], entry["label"]
            if label not in (0, 1) or (require_pinned and label != (source != "Benign")):
                raise ValueError(f"Invalid release-source label: {source}")
            relative = PurePosixPath(entry["path"])
            if relative.is_absolute() or len(relative.parts) != 1 or "\\" in entry["path"]:
                raise ValueError("Archive path must be a filename within its manifest folder")
            archive_path = manifest.parent / entry["path"]
            size = archive_path.stat().st_size
            if size > MAX_ARCHIVE_BYTES or size != entry["bytes"]:
                raise ValueError(f"Archive size mismatch: {source}")
            content = archive_path.read_bytes()
            digest = hashlib.sha256(content).hexdigest()
            blob = hashlib.sha1(b"blob " + str(size).encode("ascii") + b"\0" + content).hexdigest()
            if digest != entry["sha256"] or blob != entry["git_blob"]:
                raise ValueError(f"Archive integrity mismatch: {source}")
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                members = archive.infolist()
                if len(members) != 1 or not members[0].filename.lower().endswith(".csv"):
                    raise ValueError(f"Expected one CSV member: {source}")
                member = members[0]
                member_path = PurePosixPath(member.filename)
                if (member_path.is_absolute() or ".." in member_path.parts or
                        "\\" in member.filename or member.flag_bits & 1 or
                        member.file_size > MAX_MEMBER_BYTES):
                    raise ValueError(f"Unsafe or oversized member: {source}")
                # Reading the complete member verifies its ZIP CRC before parsing.
                payload = archive.read(member)
                if len(payload) != member.file_size:
                    raise ValueError(f"Member size mismatch: {source}")
                text = payload.decode("utf-8-sig", errors="strict")
                parser = csv.reader(io.StringIO(text, newline=""), delimiter=";", strict=True)
                if next(parser, None) != HEADER:
                    raise ValueError(f"Invalid ordered 520-column header: {source}")
                for number, cells in enumerate(parser, start=1):
                    row_id = f"{digest}:{member.filename}:{number}"
                    if len(cells) != 520:
                        rejected.append({"row_id": row_id, "source": source,
                                         "label": label, "reason": "invalid_width",
                                         "observed_cells": len(cells), "expected_cells": 520})
                    else:
                        rows.append(FeatureRow.create(row_id, source, label, cells))
    finally:
        csv.field_size_limit(old_limit)
    return rows, rejected


def build_groups(rows: Iterable[FeatureRow]) -> tuple[list[dict], list[dict]]:
    buckets: dict[str, list[FeatureRow]] = collections.defaultdict(list)
    row_ids: set[str] = set()
    for row in rows:
        if row.row_id in row_ids:
            raise ValueError(f"Duplicate provenance row_id: {row.row_id}")
        row_ids.add(row.row_id)
        buckets[row.feature_sha256].append(row)
    groups, quarantine = [], []
    for digest, members in sorted(buckets.items()):
        members.sort(key=lambda row: row.row_id)
        representative = members[0]
        if any(row.cells != representative.cells for row in members):
            raise ValueError("Feature fingerprint collision")
        labels = sorted({row.label for row in members})
        group = {"id": digest, "feature_sha256": digest,
                 "api_sha256": representative.api_sha256,
                 "representative_row_id": representative.row_id,
                 "source": representative.source,
                 "sources": sorted({row.source for row in members}),
                 "source_multiplicities": dict(sorted(collections.Counter(
                     row.source for row in members).items())),
                 "labels": labels, "label": labels[0] if len(labels) == 1 else None,
                 "multiplicity": len(members),
                 "original_row_ids": [row.row_id for row in members],
                 "quality": representative.quality, "row": representative}
        reasons = []
        if len(labels) > 1:
            reasons.append("conflicting_full_vector_labels")
        if representative.quality["all_empty"]:
            reasons.append("all_empty")
        if reasons:
            group["quarantine_reasons"] = reasons
            quarantine.append(group)
        else:
            groups.append(group)
    return groups, quarantine


def _public_group(group: dict) -> dict:
    return {key: value for key, value in group.items() if key != "row"}


def _largest_remainders(total: int) -> list[int]:
    # Exact integer arithmetic avoids floating-point tie-breaking artifacts.
    numerators = [total * weight for weight in (6, 1, 1, 2)]
    counts = [number // 10 for number in numerators]
    order = sorted(range(4), key=lambda i: (-(numerators[i] % 10), i))
    for index in order[:total - sum(counts)]:
        counts[index] += 1
    return counts


def make_split(groups: list[dict], seed: int = SPLIT_SEED, *,
               api_components: bool = False, require_all_classes: bool = True) -> dict:
    """Allocate source/label strata by deterministic largest-remainder counts."""
    if len({group["id"] for group in groups}) != len(groups):
        raise ValueError("Input groups must be unique")
    units: dict[str, list[dict]] = collections.defaultdict(list)
    for group in groups:
        nonempty_api = group["quality"]["empty_counts"]["api"] != 500
        key = ("api:" + group["api_sha256"] if api_components and nonempty_api
               else "full:" + group["id"])
        units[key].append(group)
    strata: dict[tuple, list[dict]] = collections.defaultdict(list)
    components = []
    for members in units.values():
        ids = sorted(group["id"] for group in members)
        component_id = fingerprint(ids) if api_components else ids[0]
        labels = sorted({group["label"] for group in members})
        sources = sorted({source for group in members for source in group["sources"]})
        component = {"id": component_id, "group_ids": ids, "labels": labels,
                     "sources": sources, "mixed_label": len(labels) > 1}
        components.append(component)
        strata[(tuple(labels), tuple(sources))].append(component)
    assignments, stratum_report = {}, []
    for (labels, sources), members in sorted(strata.items()):
        members.sort(key=lambda item: hashlib.sha256(
            f"{seed}|{item['id']}".encode("ascii")).hexdigest())
        counts = _largest_remainders(len(members))
        offset = 0
        for role_id, count in enumerate(counts):
            for component in members[offset:offset + count]:
                component["role_id"] = role_id
                component["role"] = ROLES[role_id]
                for group_id in component["group_ids"]:
                    assignments[group_id] = role_id
            offset += count
        stratum_report.append({"labels": list(labels), "sources": list(sources),
                               "units": len(members), "role_units": dict(zip(ROLES, counts))})
    role_classes = {role: {"0": 0, "1": 0} for role in ROLES}
    for group in groups:
        role_classes[ROLES[assignments[group["id"]]]][str(group["label"])] += 1
    if require_all_classes and any(count == 0 for counts in role_classes.values()
                                   for count in counts.values()):
        raise ValueError(f"A required role/class is empty: {role_classes}")
    return {"schema": "xran-split-v1", "seed": seed,
            "kind": "api-component-sensitivity" if api_components else "full-vector-primary",
            "role_ids": dict(zip(ROLES, range(4))), "fractions": [0.6, 0.1, 0.1, 0.2],
            "assignments": assignments, "strata": stratum_report,
            "role_class_counts": role_classes,
            "components": sorted(components, key=lambda component: component["id"])}


def token_key(view: str, value: str) -> str:
    return canonical_json([view, value]).decode("utf-8")


def _cells(row: FeatureRow | dict | Iterable[str]) -> tuple[str, ...]:
    if isinstance(row, FeatureRow):
        return row.cells
    if isinstance(row, dict):
        if "row" in row:
            return _cells(row["row"])
        if "cells" in row:
            return tuple(row["cells"])
        return tuple(row["api"]) + tuple(row["dll"]) + tuple(row["mutex"])
    return tuple(row)


def fit_vocabulary(train_rows: Iterable[FeatureRow | dict]) -> dict:
    keys = set()
    count = 0
    for row in train_rows:
        cells = _cells(row)
        if len(cells) != 520 or any(not isinstance(value, str) for value in cells):
            raise ValueError("Vocabulary inputs must contain 520 strings")
        count += 1
        for view, (start, stop) in VIEWS.items():
            keys.update(token_key(view, value) for value in cells[start:stop] if value != "")
    if count == 0:
        raise ValueError("Cannot fit vocabulary on an empty training cohort")
    tokens = {key: index for index, key in enumerate(sorted(keys), start=2)}
    return {"schema": "xran-vocabulary-v1", "pad_id": 0, "unk_id": 1,
            "size": len(tokens) + 2, "tokens": tokens, "fit_role": "train",
            "fit_group_count": count,
            "key_encoding": 'compact ensure_ascii=False JSON [view,exact_string]',
            "normalization": "none; preserve case/whitespace/PRF; empty string maps to PAD"}


def encode_views(row: FeatureRow | dict | Iterable[str], vocabulary: dict) -> np.ndarray:
    cells = _cells(row)
    if len(cells) != 520 or any(not isinstance(value, str) for value in cells):
        raise ValueError("XRan inputs require exactly 520 strings")
    if (vocabulary.get("schema") != "xran-vocabulary-v1" or
            vocabulary.get("pad_id") != 0 or vocabulary.get("unk_id") != 1):
        raise ValueError("Unsupported XRan vocabulary")
    encoded = np.zeros(520, dtype=np.int64)
    for view, (start, stop) in VIEWS.items():
        for position in range(start, stop):
            value = cells[position]
            if value != "":
                encoded[position] = vocabulary["tokens"].get(token_key(view, value), 1)
    return encoded


def _write_npz(path: Path, arrays: dict[str, np.ndarray]) -> None:
    """Portable NPZ with fixed ZIP metadata, sorted entries and no pickle."""
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, array in sorted(arrays.items()):
            buffer = io.BytesIO()
            np.lib.format.write_array(buffer, np.ascontiguousarray(array), allow_pickle=False)
            entry = zipfile.ZipInfo(name + ".npy", date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.create_system = 3
            entry.external_attr = 0o600 << 16
            archive.writestr(entry, buffer.getvalue(), compress_type=zipfile.ZIP_DEFLATED,
                             compresslevel=6)


def _summary(groups: list[dict], arrays: dict[str, np.ndarray]) -> dict:
    result = {}
    for role_id, role in enumerate(ROLES):
        role_mask = arrays["roles"] == role_id
        sources = sorted({source for g in groups for source in g["sources"]})
        role_summary = {"groups": int(role_mask.sum()), "sources": {}}
        for source in ["ALL", *sources]:
            selected = role_mask & np.array([source == "ALL" or source in g["sources"]
                                             for g in groups], dtype=bool)
            tokens = arrays["tokens"][selected]
            quality = arrays["missing_counts"][selected]
            role_summary["sources"][source] = {
                "groups": int(selected.sum()),
                "labels": {str(label): int(np.sum(arrays["labels"][selected] == label))
                           for label in (0, 1)},
                "api_empty_groups": int(np.sum(quality[:, 0] == 500)),
                "views": {view: {"unknown_cells": int(np.sum(tokens[:, start:stop] == 1)),
                                  "nonempty_cells": int(np.sum(tokens[:, start:stop] != 0)),
                                  "empty_cells": int(np.sum(tokens[:, start:stop] == 0)),
                                  "unknown_rate_nonempty": (float(np.sum(tokens[:, start:stop] == 1) /
                                      np.sum(tokens[:, start:stop] != 0))
                                      if np.any(tokens[:, start:stop] != 0) else None)}
                          for view, (start, stop) in VIEWS.items()}}
        result[role] = role_summary
    return result


def _save_prepared(output: Path, groups: list[dict], quarantine: list[dict],
                   rejected: list[dict], split: dict, inputs: dict) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    groups = sorted(groups, key=lambda group: group["id"])
    assignments = split["assignments"]
    vocabulary = fit_vocabulary(group for group in groups if assignments[group["id"]] == 0)
    arrays = {"tokens": np.stack([encode_views(group, vocabulary) for group in groups]),
              "labels": np.array([group["label"] for group in groups], dtype=np.uint8),
              "roles": np.array([assignments[group["id"]] for group in groups], dtype=np.uint8),
              "missing_counts": np.array([[group["quality"]["empty_counts"][view] for view in VIEWS]
                                           for group in groups], dtype=np.uint16),
              "multiplicities": np.array([group["multiplicity"] for group in groups], dtype=np.uint32)}
    public_groups = [{**_public_group(group), "role_id": assignments[group["id"]],
                      "role": ROLES[assignments[group["id"]]]} for group in groups]
    api_buckets: dict[str, list[dict]] = collections.defaultdict(list)
    for group in public_groups:
        if group["quality"]["empty_counts"]["api"] != 500:
            api_buckets[group["api_sha256"]].append(group)
    api_overlap = [{"api_sha256": digest, "groups": [g["id"] for g in members],
                    "roles": sorted({g["role"] for g in members}),
                    "labels": sorted({g["label"] for g in members}),
                    "cross_role": len({g["role"] for g in members}) > 1}
                   for digest, members in sorted(api_buckets.items()) if len(members) > 1]
    _write_npz(output / "encoded.npz", arrays)
    _write_jsonl(output / "groups.jsonl", public_groups)
    _write_jsonl(output / "quarantine.jsonl", map(_public_group, quarantine))
    _write_jsonl(output / "rejections.jsonl", rejected)
    _write_jsonl(output / "api-overlap.jsonl", api_overlap)
    _write_json(output / "vocabulary.json", vocabulary)
    _write_json(output / "split.json", split)
    _write_json(output / "quality-report.json", _summary(groups, arrays))
    filenames = ["encoded.npz", "groups.jsonl", "quarantine.jsonl", "rejections.jsonl",
                 "api-overlap.jsonl", "vocabulary.json", "split.json", "quality-report.json"]
    manifest = {"schema": "xran-prepared-v1", "inputs": inputs,
                "split_kind": split["kind"], "split_seed": split["seed"],
                "role_ids": dict(zip(ROLES, range(4))),
                "group_count": len(groups), "retained_original_rows": sum(g["multiplicity"] for g in groups),
                "quarantined_groups": len(quarantine),
                "quarantined_rows": sum(g["multiplicity"] for g in quarantine),
                "rejected_rows": len(rejected),
                "input_rows_accounted": sum(g["multiplicity"] for g in groups + quarantine) + len(rejected),
                "role_class_counts": split["role_class_counts"],
                "source_group_counts": dict(sorted(collections.Counter(
                    source for group in groups for source in group["sources"]).items())),
                "api_overlap": {"nonempty_collision_groups": len(api_overlap),
                                "cross_role_collisions": sum(item["cross_role"] for item in api_overlap),
                                "mixed_label_collisions": sum(len(item["labels"]) > 1 for item in api_overlap)},
                "array_schema": {name: {"shape": list(array.shape), "dtype": str(array.dtype),
                                        "raw_sha256": hashlib.sha256(array.tobytes(order="C")).hexdigest()}
                                 for name, array in arrays.items()},
                "array_notes": {"tokens": "exact API[500] || DLL[10] || Mutex[10]; PAD=0, UNK=1",
                                "missing_counts": "blank-string counts in api,dll,mutex order",
                                "multiplicities": "original valid rows represented by each full-vector group"},
                "artifacts": {name: {"sha256": sha256_file(output / name),
                                     "bytes": (output / name).stat().st_size} for name in filenames},
                "calibration_policy": "Only label=0 calibration groups fit thresholds; label=1 is reserved and unused",
                "identity_limit": "feature hashes and row IDs do not establish executable/family independence"}
    manifest["identity_sha256"] = hashlib.sha256(canonical_json(manifest)).hexdigest()
    _write_json(output / "manifest.json", manifest)
    return manifest


def prepare_release(raw_manifest: str | Path, output: str | Path,
                    seed: int = SPLIT_SEED) -> dict:
    raw_manifest, output = Path(raw_manifest), Path(output)
    rows, rejected = read_release(raw_manifest)
    groups, quarantine = build_groups(rows)
    if (len(rows), len(groups), len(quarantine), sum(g["multiplicity"] for g in quarantine)) != (30171, 22445, 24, 825):
        raise ValueError("Pinned XRan cohort differs from the independently verified audit")
    if rejected:
        raise ValueError("Pinned release unexpectedly contains rejected rows")
    isot_first = next(row for row in rows if row.source == "ISOT" and row.row_id.endswith(":1"))
    if isot_first.feature_sha256 != "33540ac665eed5a816c87f28b47a330c369c3b103460a552f269510b51d53382":
        raise ValueError("ISOT flat-vector golden hash mismatch")
    inputs = {"commit": COMMIT, "raw_manifest_sha256": sha256_file(raw_manifest),
              "archive_sha256": PINNED_SHA256, "code_sha256": sha256_file(Path(__file__)),
              "feature_hash": "SHA256(UTF8(compact JSON flat 520 exact strings, ensure_ascii=False))"}
    primary = _save_prepared(output, groups, quarantine, rejected, make_split(groups, seed), inputs)
    sensitivity = _save_prepared(output / "api-component", groups, quarantine, rejected,
                                 make_split(groups, seed, api_components=True), inputs)
    return {"primary": primary, "api_component": sensitivity}


def load_prepared(path: str | Path, *, verify: bool = True) -> dict:
    path = Path(path)
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema") != "xran-prepared-v1":
        raise ValueError("Unsupported prepared XRan schema")
    if verify:
        identity = {key: value for key, value in manifest.items() if key != "identity_sha256"}
        if hashlib.sha256(canonical_json(identity)).hexdigest() != manifest["identity_sha256"]:
            raise ValueError("Prepared manifest identity mismatch")
        for name, metadata in manifest["artifacts"].items():
            if Path(name).name != name or sha256_file(path / name) != metadata["sha256"]:
                raise ValueError(f"Prepared artifact mismatch: {name}")
    with np.load(path / "encoded.npz", allow_pickle=False) as archive:
        arrays = {name: archive[name] for name in archive.files}
    groups = [json.loads(line) for line in (path / "groups.jsonl").read_text(encoding="utf-8").splitlines()]
    if arrays["tokens"].shape != (len(groups), 520):
        raise ValueError("Prepared row alignment mismatch")
    for name, metadata in manifest["array_schema"].items():
        array = arrays[name]
        if list(array.shape) != metadata["shape"] or str(array.dtype) != metadata["dtype"]:
            raise ValueError(f"Prepared array schema mismatch: {name}")
        if verify and hashlib.sha256(array.tobytes(order="C")).hexdigest() != metadata["raw_sha256"]:
            raise ValueError(f"Prepared array identity mismatch: {name}")
    return {**arrays, "groups": groups, "manifest": manifest,
            "vocabulary": json.loads((path / "vocabulary.json").read_text(encoding="utf-8"))}
