# XRan original feature-archive audit

Generated 2026-11-17T12:33:59.529021+00:00. All rows of the four author-associated processed archives were read; no model was trained.

Repository: [https://github.com/sibelgulmez/XRan](https://github.com/sibelgulmez/XRan/tree/2cfebbfe45d3ed47b0204096186877e5991d6324); pinned commit `2cfebbfe45d3ed47b0204096186877e5991d6324`. Exact archive bytes and Git blob IDs were verified before CSV parsing. These are processed features, not original executable samples or complete sandbox reports.

## Inventory and schema

| Archive | Paper ID | Observed rows | Paper rows | Columns | Full-row unique groups |
|---|---|---:|---:|---:|---:|
| ISOT | RD3 | 668 | 668 | 520 | 640 |
| Sorel20M | RD2 | 8,443 | 7,703 | 520 | 4,632 |
| VirusShare | RD1 | 6,263 | 6,263 | 520 | 5,201 |
| Benign | BD | 14,797 | 14,797 | 520 | 12,023 |

**Cohort discrepancy:** Sorel20M contains 8,443 data rows, +740 versus the paper's 7,703. Its 4,632 unique full vectors do not explain that paper count by simple exact deduplication. The release is retained intact; the paper's exact cohort cannot be reconstructed from these columns.

Each archive contains one UTF-8, semicolon-delimited CSV. The shared header is `ApiCall_0`–`ApiCall_499`, `Dll_0`–`Dll_9`, `Mutex_0`–`Mutex_9` (520 categorical string positions). Every CSV row is retained in this audit. Labels are inferred from archive membership (three ransomware sources = 1, Benign = 0); no label column exists.

There are no sample-hash, family, timestamp, process/thread, file-path argument, duration, or outcome columns. Row number is an archive-local locator, not an executable identity. The row fingerprint below is a feature-content hash, not a sample hash. Date-like and hash-like substrings in mutex names are feature text; they do not supply trustworthy sample dates or identities.

## Missing features and observed tokens

Empty strings are counted as missing cells without silently dropping rows. `PRF` is counted separately and preserved as a token: its semantics are not established by this CSV audit. Literal string missing-value candidates are recorded separately. Case is preserved. API position order is available within the fixed 500-column representation; wall-clock order and online feature availability are not.

| Source | Empty API rows | Empty DLL rows | Empty mutex rows | All 520 empty | API PRF cells | API unique strings |
|---|---:|---:|---:|---:|---:|---:|
| ISOT | 420 | 10 | 116 | 0 | 2,334 | 154 |
| Sorel20M | 29 | 28 | 29 | 0 | 0 | 16 |
| VirusShare | 1,413 | 951 | 4,203 | 147 | 2,167 | 252 |
| Benign | 866 | 1,493 | 10,952 | 45 | 1,212 | 240 |

Sorel20M contains only 16 distinct API strings and 10 distinct DLL strings. 8,414 API rows contain all 500 positions and 29 contain none. This strong source signature requires source-aware interpretation; it is not evidence of model quality.

PRF appears in ISOT: 245 rows (54 with only PRF among nonempty API cells); Sorel20M: 0 rows (0 with only PRF among nonempty API cells); VirusShare: 45 rows (2 with only PRF among nonempty API cells); Benign: 66 rows (1 with only PRF among nonempty API cells). Per-position PRF counts and leading/trailing PRF histograms are in the JSON. PRF-only is an observation, not an assumption that PRF is padding.

API examples include `GetSystemTimeAsFileTime`, `NtOpenFile`, and `LdrGetProcedureAddress`. DLL examples include `kernel32dll` and `KERNEL32DLL`; case variants and repeated positions exist. Mutex examples include `LocalDDrawCheckExclMode` and `RasPbFile`. Other mutex strings encode environment-specific paths, SIDs, and date-like text; these can be collection shortcuts rather than ransomware mechanisms.

The JSON records every per-view length histogram, leading/trailing blank count, internal blank row count, position-specific missing count, token cardinality, common token, numeric/hash-like token count, and case-variant diagnostic. Blank padding and absent collection cannot be distinguished semantically from the CSV alone.

## Exact feature duplicates and label conflicts

Hashes use SHA-256 over UTF-8 JSON arrays of exact parsed cells, with `ensure_ascii=False` and compact separators. No case folding, blank removal, reordering, or token normalization is applied. These are exact feature collisions, not proof that two executables are the same. Blank views are included in the primary view-level collision counts and separately excluded in nonempty-view summaries.

| Representation | Unique groups | Duplicate groups | Duplicate excess rows | Cross-source groups | Conflicting-label groups | Rows in conflicting groups |
|---|---:|---:|---:|---:|---:|---:|
| full | 22,469 | 1,178 | 7,702 | 24 | 24 | 825 |
| api | 8,254 | 1,560 | 21,917 | 16 | 14 | 4,972 |
| dll | 5,006 | 1,963 | 25,165 | 95 | 83 | 9,282 |
| mutex | 6,454 | 557 | 23,717 | 61 | 43 | 16,392 |

| API prefix positions | Unique groups | Conflicting-label groups | Rows in conflicting groups |
|---:|---:|---:|---:|
| 16 | 1,831 | 60 | 10,426 |
| 32 | 2,343 | 50 | 9,812 |
| 64 | 3,346 | 57 | 7,383 |
| 128 | 4,645 | 52 | 6,399 |
| 256 | 6,738 | 28 | 5,105 |
| 500 | 8,254 | 14 | 4,972 |

The row index maps each row to the full-feature and per-view hashes, lengths, source, inferred label, and all prefix hashes. It permits deterministic group splits without relying on row order. The JSON contains within-source duplicate counts, each source-pair overlap, and bounded examples of conflicting groups.

## Consequences for architecture and evaluation

- Build a report-level Windows classifier over the fixed multiview representation, with explicit missing-view handling. Keep source out of predictive inputs.
- Group exact full-feature duplicates before any split. Quarantine conflicting-label full-feature groups under a documented rule; never resolve their labels by majority vote after seeing the test set. For API-only evaluation, disclose projection collisions and group them in a separately labeled sensitivity analysis; do not automatically delete conflicting API projections because DLL/mutex evidence can distinguish their full vectors.
- Fit vocabulary and all data-derived transforms only on training rows. Preserve unknown-token and missing-view handling. Source-specific vocabulary, missingness, PRF, and environment strings require ablations and source-stratified reporting.
- Ordinary random row splits can place exact representations in both train and test. Source holdouts remain imperfect: all benign rows come from one author-provided archive, and executable identity, family, and time splits cannot be verified.
- Prefix experiments are offline truncations of a processed API sequence. Full DLL/mutex vectors cannot be assumed observable at an early API prefix. The release does not establish damage onset, time-to-detection, process attribution, live Linux syscalls, or online false alarms per hour.
- These dataset checks constrain experiments; they are not measured model accuracy or proof of generalization.

## Reproduction

Run `python scripts/inspect_xran_original.py --offline` from the project root after download. Omit `--offline` only to retrieve a missing one of the four pinned archives. Existing archive bytes are checked and never overwritten.

Artifacts: `data/raw/xran-original/manifest.json`, `data/processed/xran-original-audit.json`, and `data/processed/xran-original-row-index.csv`. The archive README documents provenance and scope. No additional dataset is downloaded, no executable is extracted, and no malware is run.
