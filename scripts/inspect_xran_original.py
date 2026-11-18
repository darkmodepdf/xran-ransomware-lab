"""Download and audit the four author-associated XRan feature archives.

Standard library only. Archives are pinned to a Git commit and verified against
their Git blob IDs before reading. No extraction or execution is performed.
"""
from __future__ import annotations

import argparse
import collections
import csv
import datetime as dt
import hashlib
import io
import itertools
import json
import re
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath


COMMIT = "2cfebbfe45d3ed47b0204096186877e5991d6324"
REPOSITORY = "https://github.com/sibelgulmez/XRan"
SOURCES = [
    {"name": "ISOT", "directory": "ransomware", "bytes": 84220,
     "git_blob": "278ad024a8930e28f2c797d3777e643067bcc521", "paper_rows": 668, "paper_id": "RD3", "label": 1},
    {"name": "Sorel20M", "directory": "ransomware", "bytes": 820534,
     "git_blob": "7eb6ca4312e1876aa1b67144434c5e1be3a0063a", "paper_rows": 7703, "paper_id": "RD2", "label": 1},
    {"name": "VirusShare", "directory": "ransomware", "bytes": 1417993,
     "git_blob": "b52cc196ac6cff46c2104da98131ceaddeb122e8", "paper_rows": 6263, "paper_id": "RD1", "label": 1},
    {"name": "Benign", "directory": "benign", "bytes": 2102636,
     "git_blob": "ce068681a4dd8e354be4353697e9e3a954053344", "paper_rows": 14797, "paper_id": "BD", "label": 0},
]
VIEWS = {"api": (0, 500), "dll": (500, 510), "mutex": (510, 520)}
HEADER = ([f"ApiCall_{i}" for i in range(500)] +
          [f"Dll_{i}" for i in range(10)] + [f"Mutex_{i}" for i in range(10)])
PREFIXES = [16, 32, 64, 128, 256, 500]
INTEGER = re.compile(r"[+-]?\d+\Z")
DECIMAL = re.compile(r"[+-]?(?:\d+\.\d*|\d*\.\d+)(?:[eE][+-]?\d+)?\Z")
HASHLIKE = re.compile(r"(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")


def fingerprint(cells: list[str]) -> str:
    return hashlib.sha256(json.dumps(cells, ensure_ascii=False,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def json_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def verified_archive(root: Path, source: dict, offline: bool) -> tuple[Path, dict]:
    name = source["name"] + ".zip"
    path = root / name
    url = f"https://raw.githubusercontent.com/sibelgulmez/XRan/{COMMIT}/{source['directory']}/{name}"
    if path.exists():
        data = path.read_bytes()
    elif offline:
        raise FileNotFoundError(path)
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "XRan-feature-audit/1.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            data = response.read(source["bytes"] + 1)
    git_blob = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
    if len(data) != source["bytes"] or git_blob != source["git_blob"]:
        raise ValueError(f"Archive provenance mismatch: {path}")
    if not path.exists():
        with path.open("xb") as output:
            output.write(data)
    return path, {**source, "path": path.name, "url": url,
                  "sha256": hashlib.sha256(data).hexdigest(), "verified_git_blob": git_blob}


def new_view_stats(width: int) -> dict:
    return {"width": width, "tokens": collections.Counter(), "nonempty_per_row": collections.Counter(),
            "leading_empty": collections.Counter(), "trailing_empty": collections.Counter(),
            "internal_empty_rows": 0, "whitespace_only_cells": 0, "trim_changed_cells": 0,
            "numeric_integer_cells": 0, "numeric_decimal_cells": 0, "hashlike_cells": 0,
            "embedded_delimiter_cells": 0, "embedded_newline_cells": 0,
            "max_token_characters": 0, "empty_by_position": [0] * width,
            "prf_by_position": [0] * width,
            "all_empty_rows": 0, "all_present_rows": 0, "prf_cells": 0, "prf_rows": 0,
            "nonempty_nonprf_per_row": collections.Counter(), "leading_prf": collections.Counter(),
            "trailing_prf": collections.Counter(), "prf_only_rows": 0}


def update_view(stats: dict, cells: list[str]) -> int:
    nonempty = [i for i, token in enumerate(cells) if token != ""]
    n = len(nonempty)
    stats["nonempty_per_row"][n] += 1
    stats["all_empty_rows"] += n == 0
    stats["all_present_rows"] += n == len(cells)
    leading = nonempty[0] if n else len(cells)
    trailing = len(cells) - nonempty[-1] - 1 if n else len(cells)
    stats["leading_empty"][leading] += 1
    stats["trailing_empty"][trailing] += 1
    stats["internal_empty_rows"] += bool(n and any(cells[i] == "" for i in range(nonempty[0], nonempty[-1])))
    prf = cells.count("PRF")
    stats["prf_cells"] += prf
    stats["prf_rows"] += prf > 0
    stats["prf_only_rows"] += prf > 0 and prf == n
    stats["nonempty_nonprf_per_row"][n - prf] += 1
    stats["leading_prf"][len(list(itertools.takewhile(lambda x: x == "PRF", cells)))] += 1
    stats["trailing_prf"][len(list(itertools.takewhile(lambda x: x == "PRF", reversed(cells))))] += 1
    for i, token in enumerate(cells):
        if token == "":
            stats["empty_by_position"][i] += 1
            continue
        stats["tokens"][token] += 1
        stats["prf_by_position"][i] += token == "PRF"
        stats["whitespace_only_cells"] += token.strip() == ""
        stats["trim_changed_cells"] += token.strip() != token
        stats["numeric_integer_cells"] += bool(INTEGER.fullmatch(token))
        stats["numeric_decimal_cells"] += bool(DECIMAL.fullmatch(token))
        stats["hashlike_cells"] += bool(HASHLIKE.fullmatch(token))
        stats["embedded_delimiter_cells"] += ";" in token
        stats["embedded_newline_cells"] += "\n" in token or "\r" in token
        stats["max_token_characters"] = max(stats["max_token_characters"], len(token))
    return n


def finish_view(stats: dict) -> dict:
    tokens = stats.pop("tokens")
    folded = collections.defaultdict(set)
    for token in tokens:
        folded[token.casefold()].add(token)
    variants = [sorted(v) for v in folded.values() if len(v) > 1]
    stats.update({"unique_nonempty_tokens": len(tokens), "nonempty_cells": sum(tokens.values()),
                  "empty_cells": sum(stats["empty_by_position"]),
                  "top_tokens": [{"token": k, "cells": v} for k, v in tokens.most_common(20)],
                  "case_variant_groups": len(variants), "case_variant_examples": variants[:10],
                  "literal_missing_candidate_cells": {k: tokens[k] for k in ("NaN", "nan", "None", "null", "NULL", "NA", "N/A", "0", "-", "PRF") if tokens[k]}})
    for key in ("nonempty_per_row", "leading_empty", "trailing_empty", "nonempty_nonprf_per_row", "leading_prf", "trailing_prf"):
        stats[key] = dict(sorted(stats[key].items()))
    return stats


def duplicate_summary(groups: dict, labels: dict[str, int]) -> dict:
    duplicate_groups = [refs for refs in groups.values() if len(refs) > 1]
    cross_source = [refs for refs in duplicate_groups if len({source for source, _ in refs}) > 1]
    conflicts = [refs for refs in duplicate_groups if len({labels[source] for source, _ in refs}) > 1]
    within = {}
    for source in labels:
        counts = [sum(ref[0] == source for ref in refs) for refs in groups.values()]
        within[source] = {"unique_groups": sum(c > 0 for c in counts),
                          "duplicate_groups": sum(c > 1 for c in counts),
                          "rows_in_duplicate_groups": sum(c for c in counts if c > 1),
                          "duplicate_excess_rows": sum(c - 1 for c in counts if c > 1)}
    pairwise = {}
    for a, b in itertools.combinations(labels, 2):
        shared = [refs for refs in groups.values() if any(s == a for s, _ in refs) and any(s == b for s, _ in refs)]
        pairwise[f"{a}__{b}"] = {"shared_groups": len(shared), "rows_from_first": sum(s == a for refs in shared for s, _ in refs),
                                  "rows_from_second": sum(s == b for refs in shared for s, _ in refs)}
    examples = []
    for digest, refs in sorted(groups.items(), key=lambda item: (-len(item[1]), item[0]))[:10]:
        if len(refs) < 2:
            continue
        examples.append({"sha256": digest, "rows": len(refs), "sources": dict(collections.Counter(s for s, _ in refs)),
                         "row_references_first_10": refs[:10]})
    return {"unique_groups": len(groups), "duplicate_groups": len(duplicate_groups),
            "rows_in_duplicate_groups": sum(map(len, duplicate_groups)),
            "duplicate_excess_rows": sum(len(refs) - 1 for refs in duplicate_groups),
            "cross_source_groups": len(cross_source), "rows_in_cross_source_groups": sum(map(len, cross_source)),
            "conflicting_label_groups": len(conflicts), "rows_in_conflicting_label_groups": sum(map(len, conflicts)),
            "within_source": within, "pairwise_sources": pairwise, "largest_duplicate_examples": examples,
            "conflicting_group_examples": [{"sha256": digest, "rows": len(refs),
                                              "sources": dict(collections.Counter(s for s, _ in refs)),
                                              "row_references_first_10": refs[:10]}
                                             for digest, refs in groups.items()
                                             if len({labels[s] for s, _ in refs}) > 1][:20]}


def write_report(path: Path, audit: dict) -> None:
    lines = ["# XRan original feature-archive audit", "", f"Generated {audit['generated_utc']}. All rows of the four author-associated processed archives were read; no model was trained.", "",
             f"Repository: [{REPOSITORY}]({REPOSITORY}/tree/{COMMIT}); pinned commit `{COMMIT}`. Exact archive bytes and Git blob IDs were verified before CSV parsing. These are processed features, not original executable samples or complete sandbox reports.", "",
             "## Inventory and schema", "", "| Archive | Paper ID | Observed rows | Paper rows | Columns | Full-row unique groups |", "|---|---|---:|---:|---:|---:|"]
    for source in audit["sources"]:
        lines.append(f"| {source['name']} | {source['paper_id']} | {source['rows']:,} | {source['paper_rows']:,} | {source['header_width']} | {audit['duplicates']['full']['within_source'][source['name']]['unique_groups']:,} |")
    mismatches = [s for s in audit["sources"] if not s["matches_paper_row_count"]]
    for source in mismatches:
        unique = audit["duplicates"]["full"]["within_source"][source["name"]]["unique_groups"]
        lines += ["", f"**Cohort discrepancy:** {source['name']} contains {source['rows']:,} data rows, {source['rows'] - source['paper_rows']:+,} versus the paper's {source['paper_rows']:,}. Its {unique:,} unique full vectors do not explain that paper count by simple exact deduplication. The release is retained intact; the paper's exact cohort cannot be reconstructed from these columns."]
    lines += ["", "Each archive contains one UTF-8, semicolon-delimited CSV. The shared header is `ApiCall_0`–`ApiCall_499`, `Dll_0`–`Dll_9`, `Mutex_0`–`Mutex_9` (520 categorical string positions). Every CSV row is retained in this audit. Labels are inferred from archive membership (three ransomware sources = 1, Benign = 0); no label column exists.", "",
              "There are no sample-hash, family, timestamp, process/thread, file-path argument, duration, or outcome columns. Row number is an archive-local locator, not an executable identity. The row fingerprint below is a feature-content hash, not a sample hash. Date-like and hash-like substrings in mutex names are feature text; they do not supply trustworthy sample dates or identities.", "", "## Missing features and observed tokens", "",
              "Empty strings are counted as missing cells without silently dropping rows. `PRF` is counted separately and preserved as a token: its semantics are not established by this CSV audit. Literal string missing-value candidates are recorded separately. Case is preserved. API position order is available within the fixed 500-column representation; wall-clock order and online feature availability are not.", "",
              "| Source | Empty API rows | Empty DLL rows | Empty mutex rows | All 520 empty | API PRF cells | API unique strings |", "|---|---:|---:|---:|---:|---:|---:|"]
    for source in audit["sources"]:
        v = source["views"]
        lines.append(f"| {source['name']} | {v['api']['all_empty_rows']:,} | {v['dll']['all_empty_rows']:,} | {v['mutex']['all_empty_rows']:,} | {source['all_features_empty_rows']:,} | {v['api']['prf_cells']:,} | {v['api']['unique_nonempty_tokens']:,} |")
    sorel = next(s for s in audit["sources"] if s["name"] == "Sorel20M")
    lines += ["", f"Sorel20M contains only {sorel['views']['api']['unique_nonempty_tokens']} distinct API strings and {sorel['views']['dll']['unique_nonempty_tokens']} distinct DLL strings. {sorel['views']['api']['all_present_rows']:,} API rows contain all 500 positions and {sorel['views']['api']['all_empty_rows']} contain none. This strong source signature requires source-aware interpretation; it is not evidence of model quality.", "",
              "PRF appears in " + "; ".join(f"{s['name']}: {s['views']['api']['prf_rows']} rows ({s['views']['api']['prf_only_rows']} with only PRF among nonempty API cells)" for s in audit["sources"]) + ". Per-position PRF counts and leading/trailing PRF histograms are in the JSON. PRF-only is an observation, not an assumption that PRF is padding."]
    lines += ["", "API examples include `GetSystemTimeAsFileTime`, `NtOpenFile`, and `LdrGetProcedureAddress`. DLL examples include `kernel32dll` and `KERNEL32DLL`; case variants and repeated positions exist. Mutex examples include `LocalDDrawCheckExclMode` and `RasPbFile`. Other mutex strings encode environment-specific paths, SIDs, and date-like text; these can be collection shortcuts rather than ransomware mechanisms.", "",
              "The JSON records every per-view length histogram, leading/trailing blank count, internal blank row count, position-specific missing count, token cardinality, common token, numeric/hash-like token count, and case-variant diagnostic. Blank padding and absent collection cannot be distinguished semantically from the CSV alone.", "", "## Exact feature duplicates and label conflicts", "",
              "Hashes use SHA-256 over UTF-8 JSON arrays of exact parsed cells, with `ensure_ascii=False` and compact separators. No case folding, blank removal, reordering, or token normalization is applied. These are exact feature collisions, not proof that two executables are the same. Blank views are included in the primary view-level collision counts and separately excluded in nonempty-view summaries.", "",
              "| Representation | Unique groups | Duplicate groups | Duplicate excess rows | Cross-source groups | Conflicting-label groups | Rows in conflicting groups |", "|---|---:|---:|---:|---:|---:|---:|"]
    for name in ["full", "api", "dll", "mutex"]:
        d = audit["duplicates"][name]
        lines.append(f"| {name} | {d['unique_groups']:,} | {d['duplicate_groups']:,} | {d['duplicate_excess_rows']:,} | {d['cross_source_groups']:,} | {d['conflicting_label_groups']:,} | {d['rows_in_conflicting_label_groups']:,} |")
    lines += ["", "| API prefix positions | Unique groups | Conflicting-label groups | Rows in conflicting groups |", "|---:|---:|---:|---:|"]
    for prefix in PREFIXES:
        d = audit["duplicates"][f"api_prefix_{prefix}"]
        lines.append(f"| {prefix} | {d['unique_groups']:,} | {d['conflicting_label_groups']:,} | {d['rows_in_conflicting_label_groups']:,} |")
    lines += ["", "The row index maps each row to the full-feature and per-view hashes, lengths, source, inferred label, and all prefix hashes. It permits deterministic group splits without relying on row order. The JSON contains within-source duplicate counts, each source-pair overlap, and bounded examples of conflicting groups.", "", "## Consequences for architecture and evaluation", "",
              "- Build a report-level Windows classifier over the fixed multiview representation, with explicit missing-view handling. Keep source out of predictive inputs.",
              "- Group exact full-feature duplicates before any split. Quarantine conflicting-label full-feature groups under a documented rule; never resolve their labels by majority vote after seeing the test set. For API-only evaluation, disclose projection collisions and group them in a separately labeled sensitivity analysis; do not automatically delete conflicting API projections because DLL/mutex evidence can distinguish their full vectors.",
              "- Fit vocabulary and all data-derived transforms only on training rows. Preserve unknown-token and missing-view handling. Source-specific vocabulary, missingness, PRF, and environment strings require ablations and source-stratified reporting.",
              "- Ordinary random row splits can place exact representations in both train and test. Source holdouts remain imperfect: all benign rows come from one author-provided archive, and executable identity, family, and time splits cannot be verified.",
              "- Prefix experiments are offline truncations of a processed API sequence. Full DLL/mutex vectors cannot be assumed observable at an early API prefix. The release does not establish damage onset, time-to-detection, process attribution, live Linux syscalls, or online false alarms per hour.",
              "- These dataset checks constrain experiments; they are not measured model accuracy or proof of generalization.", "", "## Reproduction", "",
              "Run `python scripts/inspect_xran_original.py --offline` from the project root after download. Omit `--offline` only to retrieve a missing one of the four pinned archives. Existing archive bytes are checked and never overwritten.", "",
              "Artifacts: `data/raw/xran-original/manifest.json`, `data/processed/xran-original-audit.json`, and `data/processed/xran-original-row-index.csv`. The archive README documents provenance and scope. No additional dataset is downloaded, no executable is extracted, and no malware is run."]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    raw_dir = args.root / "data/raw/xran-original"
    processed = args.root / "data/processed"
    raw_dir.mkdir(parents=True, exist_ok=True)
    processed.mkdir(parents=True, exist_ok=True)
    labels = {s["name"]: s["label"] for s in SOURCES}
    group_names = ["full", *VIEWS, *[f"{v}_nonempty" for v in VIEWS], *[f"api_prefix_{p}" for p in PREFIXES]]
    groups = {name: collections.defaultdict(list) for name in group_names}
    combined_tokens = {name: collections.Counter() for name in VIEWS}
    manifest = {"repository": REPOSITORY, "commit": COMMIT, "archive_role": "author-associated processed feature CSVs",
                "archives": []}
    audit = {"generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "repository": REPOSITORY,
             "commit": COMMIT, "delimiter": ";", "encoding": "utf-8-sig", "header": HEADER,
             "labels": {"method": "inferred from repository archive membership; absent from CSV", "by_source": labels},
             "metadata_available": {"sample_hash": False, "family": False, "timestamp": False,
                                    "process_id": False, "thread_id": False, "event_arguments": False,
                                    "damage_outcome": False},
             "fingerprint_specification": "SHA256(UTF8(json.dumps(exact parsed cell list, ensure_ascii=False, separators=(',', ':'))))",
             "sources": []}
    csv.field_size_limit(1_000_000)
    index_path = processed / "xran-original-row-index.csv"
    with index_path.open("w", encoding="utf-8", newline="") as index_file:
        fields = ["source", "row_number", "label", "full_sha256", "api_sha256", "dll_sha256", "mutex_sha256",
                  "api_nonempty", "dll_nonempty", "mutex_nonempty", "api_prf", *[f"api_prefix_{p}_sha256" for p in PREFIXES]]
        index_writer = csv.DictWriter(index_file, fieldnames=fields)
        index_writer.writeheader()
        for source in SOURCES:
            archive_path, receipt = verified_archive(raw_dir, source, args.offline)
            manifest["archives"].append(receipt)
            stats = {**source, "archive_sha256": receipt["sha256"], "rows": 0, "row_widths": collections.Counter(),
                     "all_features_empty_rows": 0, "missing_view_patterns": collections.Counter(),
                     "views": {name: new_view_stats(end - start) for name, (start, end) in VIEWS.items()},
                     "examples": []}
            with zipfile.ZipFile(archive_path) as archive:
                members = archive.infolist()
                if len(members) != 1 or members[0].filename != source["name"] + ".csv":
                    raise ValueError(f"Unexpected ZIP directory: {archive_path}")
                if any(PurePosixPath(m.filename).is_absolute() or ".." in PurePosixPath(m.filename).parts or m.file_size > 80_000_000 for m in members):
                    raise ValueError(f"Unsafe or oversized ZIP member: {archive_path}")
                stats["zip_directory"] = [{"name": m.filename, "uncompressed_bytes": m.file_size,
                                           "compressed_bytes": m.compress_size, "crc32": f"{m.CRC:08x}"} for m in members]
                member_hash = hashlib.sha256()
                with archive.open(members[0]) as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        member_hash.update(chunk)
                stats["csv_sha256"] = member_hash.hexdigest()
                with archive.open(members[0]) as stream:
                    reader = csv.reader(io.TextIOWrapper(stream, encoding="utf-8-sig", newline=""), delimiter=";", strict=True)
                    header = next(reader)
                    if header != HEADER:
                        raise ValueError(f"Unexpected feature header: {source['name']}")
                    stats["header_width"] = len(header)
                    for row_number, cells in enumerate(reader, start=1):
                        stats["rows"] += 1
                        stats["row_widths"][len(cells)] += 1
                        if len(cells) != len(HEADER):
                            raise ValueError(f"Malformed row: {source['name']}:{row_number}, width {len(cells)}")
                        ref = (source["name"], row_number)
                        full_hash = fingerprint(cells)
                        groups["full"][full_hash].append(ref)
                        indexed = {"source": source["name"], "row_number": row_number, "label": source["label"], "full_sha256": full_hash}
                        lengths = {}
                        for name, (start, end) in VIEWS.items():
                            view = cells[start:end]
                            digest = fingerprint(view)
                            groups[name][digest].append(ref)
                            n = update_view(stats["views"][name], view)
                            lengths[name] = n
                            if n:
                                groups[f"{name}_nonempty"][digest].append(ref)
                            indexed[f"{name}_sha256"] = digest
                            indexed[f"{name}_nonempty"] = n
                        indexed["api_prf"] = cells[:500].count("PRF")
                        for prefix in PREFIXES:
                            digest = fingerprint(cells[:prefix])
                            groups[f"api_prefix_{prefix}"][digest].append(ref)
                            indexed[f"api_prefix_{prefix}_sha256"] = digest
                        index_writer.writerow(indexed)
                        stats["all_features_empty_rows"] += all(n == 0 for n in lengths.values())
                        stats["missing_view_patterns"]["|".join(f"{name}={'present' if n else 'empty'}" for name, n in lengths.items())] += 1
                        if row_number <= 3:
                            stats["examples"].append({"row_number": row_number, "api_first_12": cells[:12],
                                                       "dll": cells[500:510], "mutex_first_3": [v[:160] for v in cells[510:513]],
                                                       "nonempty_lengths": lengths})
            stats["matches_paper_row_count"] = stats["rows"] == source["paper_rows"]
            for name, view in stats["views"].items():
                combined_tokens[name].update(view["tokens"])
                finish_view(view)
                assert sum(view["nonempty_per_row"].values()) == stats["rows"]
                assert view["nonempty_cells"] + view["empty_cells"] == stats["rows"] * view["width"]
                assert sum(view["prf_by_position"]) == view["prf_cells"]
            stats["row_widths"] = dict(stats["row_widths"])
            stats["missing_view_patterns"] = dict(stats["missing_view_patterns"])
            audit["sources"].append(stats)
            print(json.dumps({"source": source["name"], "rows": stats["rows"], "paper_count_match": stats["matches_paper_row_count"],
                              "empty_views": {name: view["all_empty_rows"] for name, view in stats["views"].items()},
                              "all_features_empty": stats["all_features_empty_rows"]}), flush=True)
    audit["total_rows"] = sum(s["rows"] for s in audit["sources"])
    audit["label_counts"] = {str(label): sum(s["rows"] for s in audit["sources"] if s["label"] == label) for label in (0, 1)}
    audit["combined_unique_tokens"] = {name: len(tokens) for name, tokens in combined_tokens.items()}
    audit["duplicates"] = {name: duplicate_summary(group, labels) for name, group in groups.items()}
    assert audit["duplicates"]["api"] == audit["duplicates"]["api_prefix_500"]
    assert audit["duplicates"]["full"]["unique_groups"] + audit["duplicates"]["full"]["duplicate_excess_rows"] == audit["total_rows"]
    audit["row_index"] = {"path": "data/processed/xran-original-row-index.csv", "rows": audit["total_rows"],
                           "sha256": hashlib.sha256(index_path.read_bytes()).hexdigest()}
    json_write(raw_dir / "manifest.json", manifest)
    json_write(processed / "xran-original-audit.json", audit)
    write_report(args.root / "output/research/xran-original-data-audit.md", audit)
    (raw_dir / "README.md").write_text(
        "# Pinned XRan original feature archives\n\n"
        f"Source: {REPOSITORY}, commit `{COMMIT}`.\n\n"
        "Only the four author-associated processed archives are retained here: ISOT.zip, Sorel20M.zip, VirusShare.zip, Benign.zip. "
        "These contain semicolon-delimited categorical feature CSVs, not executable samples. They were inspected without extraction or execution. "
        "No additional datasets are part of this download.\n\n"
        "`manifest.json` records original URLs, expected byte lengths, SHA-256, and Git blob SHA-1. "
        "The repeatable inspector rejects mismatched existing archives and never overwrites archive bytes. "
        "Treat the ZIPs as immutable source evidence. Attribution and upstream usage terms remain with the upstream repository and original dataset providers; "
        "this audit does not establish an independent redistribution license.\n\n"
        "Reproduce with `python scripts/inspect_xran_original.py --offline` from the project root. "
        "See `data/processed/xran-original-audit.json`, `data/processed/xran-original-row-index.csv`, "
        "and `output/research/xran-original-data-audit.md` for complete-row inspection and limitations.\n",
        encoding="utf-8")
    print(json.dumps({"total_rows": audit["total_rows"], "label_counts": audit["label_counts"],
                      "full_duplicate_summary": {k: v for k, v in audit["duplicates"]["full"].items()
                                                 if k not in ("within_source", "pairwise_sources", "largest_duplicate_examples", "conflicting_group_examples")}}), flush=True)


if __name__ == "__main__":
    main()
