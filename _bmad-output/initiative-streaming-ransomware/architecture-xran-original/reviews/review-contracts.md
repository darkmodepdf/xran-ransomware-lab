# Contract and integration review

Reviewed: 2026-11-17. Lens: BMad good-spine rubric plus adversarial integration across data, model, evaluation and UI owners. Verdict: **the dataset-grounded direction is sound; resolve the concrete seams below before independent implementation starts.** This review does not request more datasets or features.

Scope: `architecture-xran-original.md`, `CONTRACTS.md`, `EXECUTION-PLAN.md`, initiative requirements, implemented inspector and emitted audit/index, plus current project entry points. The BMad mechanical spine linter returned `ok=true`, zero findings. Semantic review found issues the linter cannot detect. The independent audit receipt confirms all 30,171 rows were reread, including exact row/view hashes; no model result exists yet.

## High-priority findings

### H1 — Hash identity disagreed with the already implemented producer; root has corrected the contract

- **Evidence:** inspector `fingerprint(cells)` hashes the flat 520-cell list, and the index names this `full_sha256`. The first contract draft instead hashed nested `[api,dll,mutex]` as `feature_sha256`.
- **Divergence:** a data implementer following the contract and an evaluator consuming the existing index obtain different identities for every row, then different hashed splits and bundle lineage. Identical group counts would conceal the mismatch.
- **Fix:** use `json.dumps(api+dll+mutex, ensure_ascii=False, separators=(',', ':'))` and explicitly alias it to existing `full_sha256`. Root applied this while the review was running; the corrected text was re-read.
- **Verification required:** one golden real row must match the index hash, and full preparation must reconcile all hashes with the independently verified row index. Do not merely check group counts.
- **Disposition:** corrected in draft; retain implementation regression check.

### H2 — Calibration allows arbitrarily conservative results and leaves score semantics open

- **Evidence:** AD-5 requires only at most `floor(.05*n)` alarms; the model interface promises one finite ransomware score without a range or logit-to-score rule. Ties and disabled thresholds are mentioned but no exact selection algorithm is given.
- **Divergence:** two evaluators can select a useful lowest admissible cutoff or a never-alert cutoff and both satisfy the current rule. A trainer can export logits while UI/evaluation assumes probabilities; all values may be finite, so shape checks do not detect the mismatch.
- **Fix:** define `score = sigmoid(logit)` for neural models and positive-class logistic probability for counts, finite in `[0,1]`, represented at a stated comparison precision and never rounded before thresholding. Define the smallest admissible cutoff over a complete candidate set (for example observed scores and their next representable value in comparison precision, plus a tagged never-alert state). Freeze exact `>=` behavior for ties, saturated scores, `n=0`, and nonfinite outputs. Use the same algorithm for provisional tune cutoffs and final calibration.
- **Verification required:** all-equal scores, score=1 ties, fewer than 20 calibration units, zero allowed alarms, disabled cutoff, and score serialization roundtrip. A test must prove the selected cutoff is the lowest admissible candidate, rather than merely obeying the alarm cap; no positive calibration labels are needed.
- **Disposition:** autofix contract before evaluator/model handoff.

### H3 — The API sensitivity allocator has no definition for its mixed-label components

- **Evidence:** primary allocation strata are `(label, sorted distinct sources)`, assuming one label per group. The API sensitivity joins nonempty API-identical vectors into components and says to retain/report mixed-label components without relabeling. The acquired data contain 13 nonempty API conflict groups involving 2,244 rows before primary quarantine, so this is an observed case rather than a hypothetical one.
- **Divergence:** one implementer may majority-label the component, another quarantine it, another split by row label. The last leaks identical API representations across roles; the first two change the cohort. A calibration loader could accidentally consume positive members if it treats a component as benign.
- **Fix:** either explicitly defer the sensitivity until its separate protocol is frozen, or define component identity, mixed-label strata, role allocation, and membership weighting now. A workable rule is one component per role with its complete label-composition stratum; retain original row/group labels and permit only benign full-vector members in calibration. Never relabel the component. State whether uncertainty resamples those components and whether test denominators are full vectors or components.
- **Verification required:** a fixture with two different full vectors sharing a nonempty API sequence but opposing labels, plus an empty-API fixture that must not join every API-empty row.
- **Disposition:** autofix or explicitly gate; do not leave to parallel agents independently.

## Medium-priority findings

### M1 — The data audit recommends an architecture different from the accepted spine

The generated audit's “Consequences” recommends one API branch plus separate DLL/mutex branches, while AD-2/AD-4 and CONTRACTS specify one concatenated 520-position input for the primary reconstruction. The audit also says to group/quarantine on the actual API representation, while the contract retains mixed-label components for a sensitivity experiment. Since the spine cites the audit as controlling the usable cohort, a model owner could follow either instruction. Mark the audit as observations plus nonbinding recommendations, and identify the spine/contracts as authoritative for model layout and quarantine policy. Align or explicitly supersede those two recommendations; no new network is needed.

### M2 — API/UI messages are not yet an interchange contract

`POST /api/xran/classify` accepts a “520-field sample,” but no JSON request/response shape is provided. It could mean a flat list, a keyed object, or three arrays; raw strings versus encoded IDs is also not explicit at the HTTP boundary. Return fields for score, predicted class, operating point, bundle and view evidence are absent. The dashboard fixture owner and API owner can comply yet fail to connect.

Add one versioned request example using raw `api[500]`, `dll[10]`, `mutex[10]` strings, exact-length validation and no label/source fields accepted as inference inputs. Add one response example binding score, prediction, model/bundle ID, operating-point ID and explanation status. Define errors for old bundle, missing export, malformed sample, and an all-empty vector. Because all-empty vectors are excluded from the model cohort, they should produce an explicit unscorable result or documented out-of-cohort status rather than an ordinary validated benchmark prediction. Export metadata/evaluation schema IDs and model IDs must join without positional assumptions.

### M3 — Training choices need a single freeze artifact before fitting

The plan says to freeze a small tuning grid and seed policy later, while separate units can implement alongside Task 2. Important unspecified choices are count transformation/scaling and PAD inclusion, neural PAD embedding/pooling behavior, CNN padding/flattening, GRU readout position, exact tune selection metric/tie-breaks, whether all three seeds are reported, and which seed/model powers the dashboard. These choices need not be recovered from XRan, but must be recorded once before fitting and exported with every model. Use `protocol.json` as the gate artifact with an owner and required keys; evaluation/UI must consume its model IDs and selection policy. Do not select the deployed winner from test performance.

This is an implementation freeze requirement, not a recommendation to introduce more architectures. Preserve the agreed serialized 520 positions; no model may quietly pack away blanks. Count omission of PAD versus a neural zero embedding must be explicit so missingness interpretation is reviewable.

### M4 — Current project entry points still direct the next worker to Linux

At review time, `CodexContext/randsom.md` calls the Linux task-history architecture authoritative, its goal is early Linux detection, README starts with the Linux dashboard, and the former architecture retains `status: final`. The new spine alone says it replaces this direction. A new worker following the required persistent context can therefore act against the new scope without reading the new file.

Before handoff, update context and decision log, put a short current-XRan pointer at the README top, and mark the old architecture/plan as historical or superseded for the active experiment. Preserve historical evidence and working demo commands. This is documentation routing, not deletion or modification of old experiments.

### M5 — Optional sensitivity runs lack the same pre-test freeze gate as the primary run

Task 4 introduces deduplication sensitivity and source-held-out ransomware checks “if supported” while evaluating test results. The primary plan already freezes splits/configurations, but these optional experiments have no exact cohort/selection/calibration rule. Decide feasibility and protocol on source metadata/development before revealing the primary test; otherwise report them as post-test exploratory experiments in separate versions. Do not apply a primary threshold to a new source-held-out training model, and do not silently replace the main held-out result.

## Good-spine checklist outcome

| Dimension | Assessment |
|---|---|
| Real divergence points | Data lineage, feature meaning, independence limits and platform claims are correctly identified; hash/calibration/API seams needed tightening. |
| Enforceable ADs | AD-1, AD-2, primary AD-3, AD-7/8 have useful rejection conditions. AD-5 needs the exact cutoff rule; AD-4 needs the owned protocol freeze. |
| Deferred choices | Missing author metadata is honestly deferred. PAD/selection/API payload choices are implementation-blocking and should not remain implicit. |
| Brownfield consistency | New schema and artifact namespace prevent old weight reuse; current entry points still need supersession pointers. |
| Requirement coverage | X1–X6 are represented. The new release does not permit the earlier live detector objective; the plan states that boundary explicitly. |
| Environment/operations | Local CPU, conditional Kaggle, full-state recovery, deployment runtime parity, localhost/read-only service and durable exports are covered proportionately. |
| Missingness and conflicts | Symmetric full-vector quarantine and retained API-empty multiview rows are appropriate. All 192 entirely empty rows already belong to the 825 conflicting rows, so exclusions must not be added twice; updated plan states this correctly. |
| Supported claims | Endpoint Windows feature classification, not Linux detection/early warning/prevention, is consistently bounded. SOREL's 8,443-versus-7,703 discrepancy prevents exact cohort reproduction. |

## Minimum acceptance for this review

Resolve H2/H3, preserve the H1 corrected hash plus fixture requirement, establish the inference/API/protocol freeze points, and make active-document precedence unambiguous. The remaining work can proceed as the already planned data → model/evaluation → dashboard slices. No additional dataset, model family, live collector or malware execution is required to close these findings.
