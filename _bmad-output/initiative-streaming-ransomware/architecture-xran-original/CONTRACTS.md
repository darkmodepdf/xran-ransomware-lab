# XRan feature and experiment contracts

Status: proposed implementation contract, grounded in the downloaded release. Only acquisition and inspection have run. These schemas are distinct from the old API-stream and Linux-task schemas.

## Canonical row — `xran-feature-row-v1`

| Field | Rule |
|---|---|
| `row_id` | Archive SHA-256, member path, and 1-based data-row number; header is excluded from the count. Stable provenance identity, not an executable hash. |
| `source` | `VirusShare`, `Sorel20M`, `ISOT`, or `Benign`; audit-only. |
| `label` | `RANSOMWARE` for the first three source archives, `BENIGN` for the fourth. Record `label_basis=release_source`; never infer family. |
| `api`, `dll`, `mutex` | Arrays of exactly 500, 10 and 10 decoded CSV strings, respectively. Preserve empty strings, case, whitespace and punctuation. |
| `feature_sha256` | SHA-256 of UTF-8 `json.dumps(api+dll+mutex, ensure_ascii=False, separators=(',', ':'))`. This is the existing audit/index `full_sha256`; source/class/row identity excluded. |
| `api_sha256` | Same canonical hashing rule applied to the API array alone. Used to measure ablation overlap, not an executable identity. |
| `sample_sha256`, `family`, `timestamps`, `processes`, `file_outcomes` | `null` for this release; never populate from filenames or token guesses. |
| `quality` | Empty counts by view, all-empty flag, parse status, and literal-PRF counts. These are audit fields; only the explicit missingness diagnostic consumes missing counts. |

Adapter requires semicolon delimiter, exact ordered headers, 520 cells per row, bounded field/member sizes and archive CRC/Git-blob/SHA checks. Decode UTF-8 with BOM handling only at file start; do not silently repair malformed encodings or pad short rows. Reject malformed rows into an audit ledger with a source and reason. Original archives remain byte-identical.

## Group and split — `xran-split-v1`

Full-vector conflicts (both labels in one fingerprint) and all-empty vectors enter quarantine. Each remaining fingerprint contributes one representative, selected by lexicographically smallest `row_id`, with every original member retained in the audit. One fingerprint has one role. Exact grouping is feature identity only; missing executable identifiers remain a limitation.

For seed `20261117`, strata are `(label, sorted distinct source names within the group)`. Within each stratum sort groups by SHA-256 of `seed|feature_sha256`, then allocate 60/10/10/20 percent to train/tune/calibrate/test using largest remainders, ties in that listed role order. Tiny strata may have zero groups in a role; the split report must expose this. Fail before training if any required overall role/class is empty. Positive calibration groups are reserved, excluded from threshold fitting and all later selection. Persist exact role counts and a manifest hash before fitting.

A sensitivity experiment groups nonempty identical API arrays as well as identical full vectors into connected components, keeps those components in one role, and reports mixed-label components without relabeling. Empty-API rows do not form one universal component. For this experiment only, the allocation unit is the connected component and the stratum is `(sorted distinct labels, sorted distinct sources)` of that component. Apply the same seed, component-hash sort and largest-remainder allocation to component counts; retain each constituent full-vector group's original label. Only benign members of calibration components fit thresholds; positive members remain reserved. Record resulting row/group/class imbalance and fail if a required overall role/class is empty. This is a separately frozen split, never a test-driven repair. It tests API-only duplication risk; it does not establish sample independence.

## Encoding and model interfaces

`fit_vocabulary(train_rows) -> VocabularyManifest`; `encode_views(row, vocabulary) -> int64[520]`. Namespace each nonempty string with its view. `PAD=0`, `UNK=1`; all remaining IDs come from a sorted train-only token set. The report row's source and label are not arguments to the model. Unknown rates are measured separately on each role/source/view. API-only diagnostics replace every DLL/mutex position with PAD. They retain API-empty examples in the denominator and report this stratum separately.

`predict_endpoint(encoded_rows, frozen_bundle) -> float[B]`: sigmoid of one binary logit, exactly one finite score in `[0,1]` per complete row. Count uses `log1p` token counts, ignores PAD, includes UNK and applies a linear binary head with no additional feature scaling. CNN and GRU read the same 520 serialized positions with a fixed zero PAD embedding; this ordering is a feature layout, not a timeline. The GRU advances through all 520 positions, including PAD, and its final hidden state feeds the head. CNN uses the fixed positional tensor. No last-nonempty-token packing may remove positions without a new declared representation version. Logit conversion/sigmoid precision is part of the deployment backend manifest.

Bundle schema `xran-endpoint-bundle-v1` includes architecture/config, weights, vocabulary, normalization policy, dataset/group/split hashes, seed, software/backend versions and fit/tune provenance. It must be rejected by old streaming loaders. An operating-point file binds bundle/runtime/preprocessing hashes, comparator `>=`, task `ransomware_vs_benign`, unit `unique_released_feature_vector`, target `0.05`, calibration size/alert count and threshold. A disabled threshold is represented explicitly, never as NaN/Infinity.

Calibration selects the **smallest** admissible cutoff from `0` and `nextafter(s, +infinity)` for each distinct calibration score `s`, comparing the exact deployed scores converted losslessly to Python binary64. Candidates above `1` are excluded. An admissible candidate has at most `floor(0.05*n)` alarms under `score >= threshold`. If none exists, use `threshold=null, alarm_enabled=false`, giving zero alarms. Reject an empty calibration cohort. This handles ties deterministically and forbids silently choosing an arbitrary always-negative threshold. Store calibration scores and the chosen candidate so an independent checker can reproduce the decision.

## Metrics — `xran-endpoint-evaluation-v1`

Use ransomware as positive and benign as negative. Save every group prediction plus source membership and true label in the evaluation output. Include TP/FN/TN/FP; accuracy, ransomware precision/recall/F1, specificity, FPR, FNR, balanced accuracy, MCC, ROC-AUC and average precision (AP). Do not mislabel AP as trapezoidal PR-AUC. Include the negative-class classification report and support. Undefined denominators produce `null` plus a reason, not an invented zero.

Report calibration target/actual rate and test FPR/recall with explicitly named 95% intervals, group counts, all exclusions, confusion matrices by source where meaningful, and paired model comparisons resampled by feature group. Show both distinct-group primary metrics and optional row-multiplicity-weighted descriptive metrics. Repeated feature rows are not independent test cases. Report no family generalization estimate without family identities.

Performance measurements include model size, CPU inference latency and memory using a declared batch size/environment. They are inference costs, not attack-to-alert times. No timestamp, damage, encryption or prevention fields may be synthesized. Position-prefix experiments, if later run, use their own schema and the title “available-position sensitivity.”

## Dashboard/API boundary

The proposed XRan service exposes `GET /api/xran/metadata`, `GET /api/xran/evaluation`, and `POST /api/xran/classify` for exactly one validated 520-field sample. Classify requests contain only `schema="xran-classify-request-v1"`, `model_id` from the exported metadata allowlist, and string arrays `api[500]`, `dll[10]`, `mutex[10]`. Reject extra fields, wrong lengths/types and more than 1 MiB of request data. Reject an entirely empty 520-field input with HTTP 422 and code `uninformative_sample`; an empty API view with nonempty DLL/mutex evidence remains valid. The response contains `schema="xran-classify-response-v1"`, `model_id`, `bundle_sha256`, `runtime_sha256`, `score`, `threshold`, `alarm_enabled` and `decision` (`ALERT` or `NO_ALERT`). Decision is ALERT iff alarms are enabled and the exact score meets the cutoff. Errors return an HTTP 4xx/5xx and `{code,message}`; they never become benign predictions.

Retrospective sample selection identifies a fixed exported example; classifier inputs contain only its views. Explanation output identifies method, feature view, perturbation budget and model hash. Removing a feature and observing a score change is an association diagnostic, not proof that the feature caused malicious behavior.

Metrics and example labels are read-only exports. The service never retrains, recalibrates, downloads binaries or changes evidence from a UI action. The UI distinguishes published paper numbers from measured local results and shows an untrained state until a real export exists.
