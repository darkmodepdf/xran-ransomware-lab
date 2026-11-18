"""Convert extracted EN2025 CAPE reports to an audited, grouped API cohort."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from functools import lru_cache
from hashlib import file_digest, sha256
from heapq import merge
import json
import os
from pathlib import Path
import random
import re
import sys
import tempfile


LABEL_ALIASES = {
    "BENIGN": "BENIGN",
    "RANSOMWARE": "RANSOMWARE",
    "RAT": "OTHER_MALWARE",
    "SPYWARE": "OTHER_MALWARE",
    "OTHER_MALWARE": "OTHER_MALWARE",
}
FRACTIONS = {
    "BENIGN": {"train": 0.40, "tune": 0.10, "calibrate": 0.25, "test": 0.25},
    "RANSOMWARE": {"train": 0.60, "tune": 0.20, "test": 0.20},
    "OTHER_MALWARE": {"train": 0.60, "tune": 0.20, "test": 0.20},
}
SOURCE_RECORD = "https://zenodo.org/records/18218588"
HEX_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
IDENTITY_FIELDS = ("sample_sha256", "raw_sha256", "full_sequence_sha256", "retained_sequence_sha256")
CACHE_VERSION = "en2025-report-v1"
SIMPLE_CALL_FIELDS = {"api", "timestamp", "time", "arguments", "status", "return", "return_value", "repeated"}


@dataclass
class ParsedTrace:
    label: str
    apis: list[str]
    audit: dict


@dataclass(frozen=True)
class VerifiedCacheEntry:
    path: Path
    raw_sha256: str
    cache_sha256: str
    source_revision: tuple[int, int, int]


def file_revision(stat) -> tuple[int, int, int]:
    return stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def canonical_bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def byte_hash(value: bytes) -> str:
    return sha256(value).hexdigest()


def parse_time(value) -> tuple[str, Decimal] | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        return None
    return parse_time_scalar(str(value))


@lru_cache(maxsize=16384)
def parse_time_scalar(value: str) -> tuple[str, Decimal] | None:
    if len(value) < 10 or value[4:5] != "-" or value[7:8] != "-":
        try:
            number = Decimal(value)
        except InvalidOperation:
            return None
        return ("numeric", number) if number.is_finite() else None
    # Date-only values cannot establish interprocess call order.
    if len(value) == 10:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace(",", "."))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        clock = "naive_datetime"
        origin = datetime(1970, 1, 1)
    else:
        clock = "zoned_datetime"
        origin = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = parsed - origin
    return clock, Decimal((delta.days * 86400 + delta.seconds) * 10**6 + delta.microseconds)


def sample_hash(report: dict) -> str | None:
    target = report.get("target")
    if not isinstance(target, dict):
        return None
    file_meta = target.get("file")
    hashes = [target.get("sha256")]
    if isinstance(file_meta, dict):
        hashes.append(file_meta.get("sha256"))
    valid = {item.lower() for item in hashes if isinstance(item, str) and HEX_SHA256.fullmatch(item)}
    if len(valid) > 1:
        raise ValueError("conflicting SHA-256 fields in report target")
    return next(iter(valid), None)


def parse_report(report, limit: int) -> tuple[list[str], dict]:
    if not isinstance(report, dict):
        raise ValueError("CAPE report is not an object")
    behavior = report.get("behavior")
    if not isinstance(behavior, dict) or not isinstance(behavior.get("processes"), list):
        raise ValueError("missing behavior.processes array")
    processes = behavior["processes"]
    streams = []
    timestamp_kinds = set()
    counts = Counter()
    clock_regressed = False
    for process_index, process in enumerate(processes):
        if not isinstance(process, dict) or not isinstance(process.get("calls"), list):
            raise ValueError(f"process {process_index} has no calls array")
        calls = []
        previous = None
        for call_index, call in enumerate(process["calls"]):
            if not isinstance(call, dict) or not isinstance(call.get("api"), str) or not call["api"].strip():
                raise ValueError(f"invalid API name at process {process_index}, call {call_index}")
            found = parse_time(call.get("timestamp", call.get("time")))
            clock = None
            if found is not None:
                kind, clock = found
                timestamp_kinds.add(kind)
                counts["timestamped_calls"] += 1
                if previous is not None and previous[0] == kind and previous[1] > clock:
                    clock_regressed = True
                previous = found
            counts["calls"] += 1
            counts["argument_fields"] += int(isinstance(call.get("arguments"), (list, dict)))
            counts["status_fields"] += int("status" in call or "return" in call or "return_value" in call)
            counts["repeat_fields"] += int("repeated" in call)
            calls.append((clock, process_index, call_index, sys.intern(call["api"].strip())))
        if calls:
            streams.append(calls)

    ties = 0
    if not streams:
        order = "empty"
        ordered = iter(())
    elif len(streams) == 1:
        order = "single_process_report_order"
        ordered = iter(streams[0])
    elif counts["timestamped_calls"] == counts["calls"] and len(timestamp_kinds) == 1 and not clock_regressed:
        order = "timestamp_merge_unverified_clock"
        ordered = merge(*streams)
    else:
        order = "process_concatenation_unverified"
        ordered = (call for stream in streams for call in stream)

    apis = []
    previous_clock = None
    full_sequence = sha256()
    for index, (clock, _, _, api) in enumerate(ordered):
        full_sequence.update(json.encoder.encode_basestring(api).encode("utf-8") + b"\n")
        if index < limit:
            apis.append(api)
        if order == "timestamp_merge_unverified_clock" and previous_clock == clock:
            ties += 1
        previous_clock = clock

    audit = {
        "sample_sha256": sample_hash(report),
        "process_count": len(processes),
        "process_count_with_calls": len(streams),
        "api_call_count": counts["calls"],
        "retained_observations": len(apis),
        "horizon_truncated": counts["calls"] > limit,
        "full_sequence_sha256": full_sequence.hexdigest(),
        "retained_sequence_sha256": byte_hash(canonical_bytes(apis)),
        "observation_order": order,
        "timestamp_forms": sorted(timestamp_kinds),
        "timestamped_call_count": counts["timestamped_calls"],
        "timestamp_regression_detected": clock_regressed,
        "timestamp_tie_count": ties,
        "calls_with_arguments": counts["argument_fields"],
        "calls_with_status_or_return": counts["status_fields"],
        "calls_with_repeat_field": counts["repeat_fields"],
    }
    return apis, audit


def decode_report(data: bytes, limit: int, decoder: str) -> tuple[list[str], dict]:
    if decoder == "orjson":
        import orjson

        try:
            fast = orjson.loads(data)
        except orjson.JSONDecodeError:
            pass  # The standard decoder defines the accepted language and error messages.
        else:
            selected, parsed = parse_report(fast, limit)
            if "numeric" not in parsed["timestamp_forms"]:
                return selected, parsed
            del fast
    return parse_report(json.loads(data, parse_float=Decimal), limit)


def parse_report_stream(path: Path, limit: int) -> tuple[list[str], dict]:
    """Project the same CAPE fields before decoding very large report arguments."""
    import ijson

    process_prefix = "behavior.processes.item"
    calls_prefix = process_prefix + ".calls"
    call_prefix = calls_prefix + ".item"
    fields_prefix = call_prefix + "."
    process = None
    call = None
    root = {}
    with path.open("rb") as stream:
        try:
            for prefix, event, value in ijson.parse(stream, buf_size=1024 * 1024):
                if prefix == "behavior" and event == "start_map":
                    root["behavior"] = {}
                elif prefix == "behavior.processes" and event == "start_array":
                    root["behavior"]["processes"] = []
                elif prefix == process_prefix and event == "start_map":
                    process = {}
                    root["behavior"]["processes"].append(process)
                elif prefix == process_prefix and event not in {"map_key", "end_map"}:
                    raise ValueError("streamed CAPE process is not an object")
                elif prefix == calls_prefix and event == "start_array":
                    process["calls"] = []
                elif prefix == call_prefix and event == "start_map":
                    call = {}
                    process["calls"].append(call)
                elif prefix == call_prefix and event not in {"map_key", "end_map"}:
                    raise ValueError("streamed CAPE call is not an object")
                elif prefix == "target" and event == "start_map":
                    root["target"] = {}
                elif prefix == "target.file" and event == "start_map":
                    root["target"]["file"] = {}
                elif prefix == "target.sha256" and event == "string":
                    root["target"]["sha256"] = value
                elif prefix == "target.file.sha256" and event == "string":
                    root["target"]["file"]["sha256"] = value
                elif prefix.startswith(fields_prefix):
                    key = prefix[len(fields_prefix):]
                    if key in SIMPLE_CALL_FIELDS and event not in {"map_key", "end_map", "end_array"}:
                        # Preserve inspected types without allocating unused argument payloads.
                        call[key] = {} if event == "start_map" else [] if event == "start_array" else value
        except ijson.JSONError as exc:
            raise ValueError(f"invalid streamed CAPE JSON: {exc}") from exc
    return parse_report(root, limit)


def read_report(path: Path, label: str, relative_path: str, limit: int, bytes_limit: int,
                cache_dir: Path | None = None, decoder: str = "stdlib", stream_over: int = 0,
                verified_entry: VerifiedCacheEntry | None = None) -> ParsedTrace:
    audit = {"source_report": relative_path, "source_label": label}
    try:
        stat = path.stat()
        audit["raw_bytes"] = stat.st_size
        directory_hash = path.parent.name.lower() if HEX_SHA256.fullmatch(path.parent.name) else None
        if directory_hash:
            audit.update(sample_sha256=directory_hash, sample_sha256_source="member_directory")
        if audit["raw_bytes"] > bytes_limit:
            raise ValueError(f"report exceeds configured {bytes_limit} byte limit")
        streamed = bool(stream_over and audit["raw_bytes"] > stream_over)
        verified_cache_bytes = None
        if verified_entry is not None and file_revision(stat) == verified_entry.source_revision:
            try:
                candidate = verified_entry.path.read_bytes()
                if byte_hash(candidate) == verified_entry.cache_sha256 and file_revision(path.stat()) == file_revision(stat):
                    verified_cache_bytes = candidate
            except OSError:
                pass
        if verified_cache_bytes is not None:
            cached_path = verified_entry.path
            audit.update(raw_sha256=verified_entry.raw_sha256, identity_lookup="verified_extraction_stat_cache")
        elif cache_dir is not None or streamed:
            with path.open("rb") as stream:
                audit["raw_sha256"] = file_digest(stream, "sha256").hexdigest()
            raw_hash = audit["raw_sha256"]
            cached_path = cache_dir / raw_hash[:2] / f"{raw_hash}-{limit}-{CACHE_VERSION}.json" if cache_dir else None
            audit["identity_lookup"] = "raw_sha256"
        else:
            data = path.read_bytes()
            audit["raw_sha256"] = byte_hash(data)
            cached_path = None
            audit["identity_lookup"] = "raw_sha256"
        if verified_cache_bytes is not None or (cached_path is not None and cached_path.is_file()):
            cached = json.loads(verified_cache_bytes if verified_cache_bytes is not None else cached_path.read_bytes())
            selected = [sys.intern(name) for name in cached["apis"]]
            parsed = cached["audit"]
            if byte_hash(canonical_bytes(selected)) != parsed["retained_sequence_sha256"]:
                raise ValueError("cached report prefix checksum differs")
        elif streamed:
            selected, parsed = parse_report_stream(path, limit)
            if cached_path is not None:
                write_atomic(cached_path, [canonical_bytes({"apis": selected, "audit": parsed}) + b"\n"], cache=True)
        else:
            if cached_path is not None:
                data = path.read_bytes()
                if byte_hash(data) != audit["raw_sha256"]:
                    raise ValueError("report changed between hashing and parsing")
            selected, parsed = decode_report(data, limit, decoder)
            if cached_path is not None:
                write_atomic(cached_path, [canonical_bytes({"apis": selected, "audit": parsed}) + b"\n"], cache=True)
        reported_hash = parsed["sample_sha256"]
        if directory_hash and reported_hash and directory_hash != reported_hash:
            raise ValueError("sample directory SHA-256 differs from CAPE target SHA-256")
        parsed["sample_sha256"] = reported_hash or directory_hash
        parsed["sample_sha256_source"] = (
            "cape_target_and_member_directory" if reported_hash and directory_hash else
            "cape_target" if reported_hash else "member_directory" if directory_hash else None
        )
        audit.update(parsed)
        audit["status"] = "parsed" if selected else "empty"
        return ParsedTrace(label, selected, audit)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        audit.update(status="invalid", error=str(exc))
        return ParsedTrace(label, [], audit)


def group_traces(traces: list[ParsedTrace]) -> dict[str, list[ParsedTrace]]:
    parents = list(range(len(traces)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    seen = {}
    for index, trace in enumerate(traces):
        for field in IDENTITY_FIELDS:
            value = trace.audit[field]
            if value is not None:
                other = seen.setdefault((field, value), index)
                parents[find(index)] = find(other)

    components = defaultdict(list)
    for index, trace in enumerate(traces):
        components[find(index)].append(trace)
    result = {}
    for component in components.values():
        identity = sorted({item.audit["raw_sha256"] for item in component})
        group_id = "en2025-group-" + byte_hash(canonical_bytes(identity))
        for item in component:
            item.audit["candidate_group_id"] = group_id
        result[group_id] = component
    return result


def development_identities(path: Path, limit: int) -> tuple[dict[str, set], str]:
    content = path.read_bytes()
    audit = json.loads(content)
    if audit.get("source_record") != SOURCE_RECORD or not audit.get("reports"):
        raise ValueError("development audit must identify EN2025 and contain report inventory")
    fields = {field: set() for field in IDENTITY_FIELDS}
    for record in audit["reports"]:
        for field in IDENTITY_FIELDS:
            if field == "retained_sequence_sha256" and limit != audit.get("max_observations"):
                continue
            value = record.get(field)
            if isinstance(value, str) and HEX_SHA256.fullmatch(value):
                fields[field].add(value.lower())
        # Earlier audits did not save the member-directory identity of an over-limit report.
        parts = str(record.get("source_report", "")).split("/")
        if len(parts) >= 2 and parts[-1] == "report.json" and HEX_SHA256.fullmatch(parts[-2]):
            fields["sample_sha256"].add(parts[-2].lower())
    if not fields["sample_sha256"] and not fields["raw_sha256"]:
        raise ValueError("development audit contains no usable sample or report identities")
    return fields, byte_hash(content)


def select_trace_rows(groups: dict[str, list[ParsedTrace]], seed: int, prior: dict[str, set] | None = None
                      ) -> tuple[list[dict], list[str]]:
    by_collection = defaultdict(list)
    for group_id, component in sorted(groups.items()):
        forced_train = False
        if prior is not None:
            for item in component:
                matches = [field for field, values in prior.items() if item.audit.get(field) in values]
                item.audit["development_identity_matches"] = matches
                forced_train |= bool(matches)
            for item in component:
                item.audit["development_group_forced_train"] = forced_train
        if len({item.label for item in component}) > 1:
            for item in component:
                item.audit["status"] = "excluded_cross_label_group"
            continue
        # Retain the most complete available report per exact-identity component.
        representatives = sorted(component, key=lambda item: (
            item.audit["observation_order"] == "process_concatenation_unverified",
            -len(item.apis), item.audit["raw_sha256"], item.audit["source_report"],
        ))
        representative, *duplicates = representatives
        for item in duplicates:
            item.audit["status"] = "excluded_duplicate"
        collection = representative.audit["source_collection"] if prior is not None else representative.label
        by_collection[collection].append((group_id, representative, forced_train))

    rows = []
    errors = []
    present_labels = {record.label for records in by_collection.values() for _, record, _ in records}
    for missing in sorted({"BENIGN", "RANSOMWARE"} - present_labels):
        errors.append(f"{missing} has no usable groups")
    for collection, selected in sorted(by_collection.items()):
        label = selected[0][1].label
        fractions = FRACTIONS[label]
        forced = [item for item in selected if item[2]]
        fresh = [item for item in selected if not item[2]]
        required_fresh = len(fractions) - bool(forced)
        if len(fresh) < required_fresh:
            errors.append(f"{collection} has {len(fresh)} fresh groups for {required_fresh} disjoint roles after development protection")
            continue
        random.Random(f"{seed}:{collection}").shuffle(fresh)
        total = len(selected)
        assigned = dict.fromkeys(fractions, 1)
        assigned["train"] = max(1, len(forced))
        for _ in range(total - sum(assigned.values())):
            role = max(fractions, key=lambda key: total * fractions[key] - assigned[key])
            assigned[role] += 1
        cursor = 0
        for role, count in assigned.items():
            original = forced if role == "train" else []
            fresh_count = count - len(original)
            for group_id, trace, _ in original + fresh[cursor:cursor + fresh_count]:
                trace_id = "en2025-" + trace.audit["raw_sha256"]
                trace.audit.update(status="included", trace_id=trace_id, role=role, group_id=group_id)
                rows.append({"trace_id": trace_id, "label": label, "role": role, "group_id": group_id, "apis": trace.apis})
            cursor += fresh_count
    return sorted(rows, key=lambda row: row["trace_id"]), errors


def write_atomic(path: Path, lines, *, cache: bool = False) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    checksum = sha256()
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", delete=False) as stream:
            temp_path = Path(stream.name)
            for line in lines:
                stream.write(line)
                checksum.update(line)
        try:
            os.link(temp_path, path)
        except FileExistsError:
            if not cache:
                raise
            with path.open("rb") as stream:
                if file_digest(stream, "sha256").digest() != checksum.digest():
                    raise ValueError("concurrent raw-hash cache entries differed") from None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    return checksum.hexdigest()


def verified_extraction_members(roots) -> dict[Path, int] | None:
    """Check archive identity and inventory, retaining extracted members now unavailable."""
    from download_en2025 import ARCHIVES

    members = {}
    for source_label, _, root in roots:
        source = source_label.lower()
        manifest_path = root.parent / f"{source}-extraction.json"
        if not manifest_path.is_file() or source not in ARCHIVES:
            return None
        manifest = json.loads(manifest_path.read_bytes())
        expected_bytes, expected_md5 = ARCHIVES[source]
        if (manifest.get("source"), manifest.get("archive"), manifest.get("archive_bytes"), manifest.get("md5")) != (
            SOURCE_RECORD, f"{source}.7z", expected_bytes, expected_md5,
        ):
            return None
        name = re.compile(rf"{re.escape(source)}/([0-9a-f]{{64}})/report\.json\Z")
        listed = set()
        for record in manifest.get("member_inventory", []):
            match = name.fullmatch(record.get("member", ""))
            if match and record.get("status") == "extracted_report":
                path = root / match[1] / "report.json"
                if path in members:
                    return None
                members[path] = record.get("expanded_bytes")
                listed.add(path)
        present = {path for path in root.glob("**/report.json") if path.is_file()}
        if not listed or not present.issubset(listed):
            return None
    return members


def build_verified_cache_index(roots, cache_dir: Path, limit: int,
                               members: dict[Path, int] | None = None) -> dict[Path, VerifiedCacheEntry]:
    """Index newly extracted, immutable members without a second cold raw-file read."""
    if members is None:
        members = verified_extraction_members(roots)
    if members is None:
        return {}
    sources = defaultdict(list)
    for path, size in members.items():
        sources[path.parent.name].append((path, size))

    refs = defaultdict(list)
    cache_name = re.compile(rf"([a-f0-9]{{64}})-{limit}-{re.escape(CACHE_VERSION)}\.json\Z")
    for cached_path in sorted(cache_dir.glob("*/*.json")):
        match = cache_name.fullmatch(cached_path.name)
        if not match:
            continue
        try:
            contents = cached_path.read_bytes()
            sample = json.loads(contents)["audit"].get("sample_sha256")
            if sample in sources:
                refs[sample].append((cached_path, match[1], byte_hash(contents)))
        except (OSError, ValueError, KeyError, TypeError):
            continue

    indexed = {}
    for sample, candidates in sources.items():
        if len(candidates) != 1 or len(refs[sample]) != 1:
            continue
        (path, expected_size), = candidates
        (cached_path, raw_hash, cache_hash), = refs[sample]
        try:
            stat = path.stat()
            published = cached_path.stat().st_mtime_ns
        except OSError:
            continue
        if (not path.is_symlink() and stat.st_size == expected_size and published >= max(stat.st_mtime_ns, stat.st_ctime_ns)
                and path.resolve().is_relative_to(path.parent.parent.resolve())):
            indexed[path] = VerifiedCacheEntry(cached_path, raw_hash, cache_hash, file_revision(stat))
    return indexed


def iter_reports(roots, pattern: str, limit: int, bytes_limit: int, cache_dir: Path | None,
                 progress_every: int, decoder: str = "stdlib", stream_over: int = 0,
                 verified_cache: dict[Path, VerifiedCacheEntry] | None = None,
                 verified_members: dict[Path, int] | None = None):
    for index, (source_label, label, root) in enumerate(roots, 1):
        present = {path for path in root.glob(pattern) if path.is_file()}
        expected = {path for path in verified_members or () if path.is_relative_to(root)
                    and path.relative_to(root).match(pattern)}
        candidates = sorted(present | expected)
        if not candidates:
            raise ValueError(f"no report JSON matched {pattern!r} in source root {root}")
        root_path = root.resolve()
        for count, path in enumerate(candidates, 1):
            reference = f"{source_label.lower()}-{index}/{path.relative_to(root).as_posix()}"
            if not path.resolve().is_relative_to(root_path):
                raise ValueError(f"report resolves outside its collection root: {reference}")
            entry = verified_cache.get(path) if verified_cache else None
            if path in expected and not path.is_file():
                report = ParsedTrace(label, [], {
                    "source_report": reference, "source_label": label,
                    "sample_sha256": path.parent.name, "sample_sha256_source": "member_directory",
                    "raw_bytes": verified_members[path], "status": "unavailable_extracted_member",
                    "error": "Verified extraction manifest lists this report, but no file is available to parse",
                })
            else:
                report = read_report(path, label, reference, limit, bytes_limit, cache_dir, decoder, stream_over, entry)
            report.audit["source_collection"] = source_label
            yield report
            if progress_every and (count % progress_every == 0 or count == len(candidates)):
                print(f"{source_label}: read {count}/{len(candidates)} reports", file=sys.stderr, flush=True)


def prepare(roots, pattern: str, output: Path, audit_path: Path, seed: int, limit: int, bytes_limit: int,
            skip_invalid: bool, development_audit: Path | None = None, cache_dir: Path | None = None,
            progress_every: int = 0, decoder: str = "stdlib", stream_over: int = 0,
            verified_extraction_cache: bool = False) -> dict:
    if output.resolve() == audit_path.resolve() or output.exists() or audit_path.exists():
        raise ValueError("output and audit must be distinct new files")
    prior, prior_sha = development_identities(development_audit, limit) if development_audit else (None, None)
    members = verified_extraction_members(roots) if verified_extraction_cache else None
    if verified_extraction_cache and members is None:
        raise ValueError("could not verify archive identities and extracted member inventories")
    indexed = build_verified_cache_index(roots, cache_dir, limit, members) if verified_extraction_cache else None
    reports = list(iter_reports(roots, pattern, limit, bytes_limit, cache_dir, progress_every, decoder, stream_over,
                                indexed, members))

    valid = [trace for trace in reports if trace.audit["status"] == "parsed"]
    rows, errors = select_trace_rows(group_traces(valid), seed, prior)
    if prior is not None:
        included_collections = {trace.audit["source_collection"] for trace in reports if trace.audit["status"] == "included"}
        for missing in sorted({source_label for source_label, _, _ in roots} - included_collections):
            errors.append(f"{missing} has no included samples in expanded cohort")
        if any(trace.audit.get("development_group_forced_train") and trace.audit.get("role") in {"tune", "calibrate", "test"}
               for trace in reports):
            raise AssertionError("a previous development group crossed into an evaluation role")
    invalid_count = sum(trace.audit["status"] in {"invalid", "unavailable_extracted_member"} for trace in reports)
    if invalid_count and not skip_invalid:
        errors.append(f"{invalid_count} malformed or unreadable report(s), see audit")
    output_sha256 = None
    if not errors:
        output_sha256 = write_atomic(output, (canonical_bytes(row) + b"\n" for row in rows))
    summaries = defaultdict(Counter)
    for row in rows:
        summaries[row["label"]][row["role"]] += 1
    source_statuses = defaultdict(Counter)
    source_roles = defaultdict(Counter)
    for trace in reports:
        source_statuses[trace.audit["source_collection"]][trace.audit["status"]] += 1
        if trace.audit["status"] == "included":
            source_roles[trace.audit["source_collection"]][trace.audit["role"]] += 1
    input_manifest = sorted((trace.audit["source_report"], trace.audit.get("raw_sha256")) for trace in reports)
    audit = {
        "schema_version": "en2025-expansion-v1" if prior is not None else "en2025-development-pilot-v1",
        "source_record": SOURCE_RECORD,
        "source_license": "MIT (Zenodo/DataCite record)",
        "scope": "expanded exact-identity-grouped cohort" if prior is not None else "development pilot",
        "seed": seed,
        "max_observations": limit,
        "report_glob": pattern,
        "max_report_bytes": bytes_limit,
        "uncached_decoder": decoder,
        "stream_over_bytes": stream_over,
        "verified_extraction_stat_cache_enabled": verified_extraction_cache,
        "identity_lookup_counts": dict(Counter(trace.audit.get("identity_lookup", "unavailable") for trace in reports)),
        "malformed_quarantine_enabled": skip_invalid,
        "input_manifest_sha256": byte_hash(canonical_bytes(input_manifest)),
        "training_jsonl_sha256": output_sha256,
        "assignment_counts": {key: dict(value) for key, value in summaries.items()},
        "source_assignment_counts": {key: dict(value) for key, value in source_roles.items()},
        "source_statuses": {key: dict(value) for key, value in source_statuses.items()},
        "development_audit_sha256": prior_sha,
        "development_identity_counts": {field: len(values) for field, values in prior.items()} if prior else None,
        "development_forced_train_count": sum(trace.audit.get("development_group_forced_train", False)
                                              and trace.audit.get("role") == "train" for trace in reports),
        "statuses": dict(Counter(trace.audit["status"] for trace in reports)),
        "ordering_counts": dict(Counter(trace.audit.get("observation_order", "unavailable") for trace in reports)),
        "errors": errors,
        "limitations": [
            "Groups connect matching sample SHA-256, report SHA-256, full API sequence, or exact retained API prefix. Near-duplicate and family independence are unverified.",
            "When the prior development audit is supplied, all members of any matching group are excluded from tuning, calibration and test. Roles remain conditional on the observed cohort.",
            "Class labels come from archive roles. The preparation does not infer family labels.",
            "Source call ordering is preserved within each process. Interprocess clock semantics remain unverified.",
            "Multi-process traces with missing or inconsistent clocks use report-order process concatenation.",
            "Retained records are emitted as one API token each. Repeats are inventoried, not expanded.",
            "No confirmed file modifications or causal damage outcomes are produced by this script.",
        ],
        "reports": [trace.audit for trace in reports],
    }
    write_atomic(audit_path, [json.dumps(audit, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"])
    if errors:
        raise ValueError(" | ".join(errors))
    return audit


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--root", type=Path, help="root with named BENIGN/RANSOMWARE/RAT/SPYWARE subdirectories")
    inputs.add_argument("--class-root", action="append", metavar="LABEL=PATH", help="repeat for each extracted collection")
    parser.add_argument("--glob", default="**/*.json", help="relative report selection glob")
    parser.add_argument("--output", type=Path, help="new training JSONL")
    parser.add_argument("--audit", type=Path, help="new audit JSON")
    parser.add_argument("--seed", type=int, default=20261116)
    parser.add_argument("--max-observations", type=int, default=4096)
    parser.add_argument("--max-report-mib", type=int, default=256)
    parser.add_argument("--skip-invalid", action="store_true", help="explicitly quarantine invalid reports and retain audit")
    parser.add_argument("--development-audit", type=Path, help="prior audit; force matching groups into train")
    parser.add_argument("--cache-dir", type=Path, help="cache parsed records keyed by report SHA-256 and horizon")
    parser.add_argument("--cache-only", action="store_true", help="parse selected classes for later cohort assembly")
    parser.add_argument("--progress-every", type=int, default=0, help="log progress every N reports per source")
    parser.add_argument("--decoder", choices=("stdlib", "orjson"), default="stdlib")
    parser.add_argument("--stream-over-mib", type=int, default=0,
                        help="use ijson above this size when uncached, zero disables streaming")
    parser.add_argument("--verified-extraction-cache", action="store_true",
                        help="reuse unambiguous newly extracted member indices, otherwise hash raw reports")
    args = parser.parse_args()
    if args.max_observations < 1 or args.max_report_mib < 1 or min(args.progress_every, args.stream_over_mib) < 0:
        parser.error("report and observation limits must be positive")
    try:
        if args.root is not None:
            entries = [(path.name.upper(), path) for path in sorted(args.root.iterdir())
                       if path.is_dir() and path.name.upper() in LABEL_ALIASES]
        else:
            entries = []
            for value in args.class_root:
                label, separator, path = value.partition("=")
                if not separator or not path:
                    raise ValueError("class-root must use LABEL=PATH")
                entries.append((label.upper(), Path(path)))
        roots = []
        for source_label, path in entries:
            if source_label not in LABEL_ALIASES or not path.is_dir():
                raise ValueError(f"invalid collection root: {source_label}={path}")
            roots.append((source_label, LABEL_ALIASES[source_label], path))
        bytes_limit = args.max_report_mib * 1024 * 1024
        stream_over = args.stream_over_mib * 1024 * 1024
        try:
            if args.decoder == "orjson":
                import orjson
            if stream_over:
                import ijson
        except ImportError as exc:
            raise ValueError(f"optional decoder dependency missing: {exc.name}") from exc
        if args.cache_only:
            if args.cache_dir is None or not roots or args.output or args.audit or args.development_audit or args.verified_extraction_cache:
                raise ValueError("cache-only requires cache-dir and sources, without output, audit or development-audit")
            statuses = Counter(trace.audit["status"] for trace in iter_reports(
                roots, args.glob, args.max_observations, bytes_limit, args.cache_dir, args.progress_every,
                args.decoder, stream_over,
            ))
            print(json.dumps({"cached_report_statuses": dict(statuses)}, sort_keys=True))
            if statuses["invalid"] and not args.skip_invalid:
                raise ValueError("malformed report(s) found while caching")
            return
        if args.output is None or args.audit is None:
            raise ValueError("cohort preparation requires output and audit paths")
        if args.verified_extraction_cache and args.cache_dir is None:
            raise ValueError("verified-extraction-cache requires cache-dir")
        if not {"BENIGN", "RANSOMWARE"}.issubset({label for _, label, _ in roots}):
            raise ValueError("both benign and ransomware collections are required")
        audit = prepare(roots, args.glob, args.output, args.audit, args.seed, args.max_observations,
                        bytes_limit, args.skip_invalid, args.development_audit, args.cache_dir, args.progress_every,
                        args.decoder, stream_over, args.verified_extraction_cache)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps({key: audit[key] for key in ("assignment_counts", "training_jsonl_sha256", "statuses")}, sort_keys=True))


if __name__ == "__main__":
    main()
