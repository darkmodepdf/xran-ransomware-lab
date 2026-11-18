# XRan Original Dataset Implementation Plan

> For agentic workers: use the installed BMad build workflow for each task, with disjoint file ownership for parallel agents. This project has no Git repository; record artifact hashes and verification receipts instead of claiming commits. Read the architecture and contracts before implementation.

**Goal:** Train and demonstrate a reproducible ransomware-versus-benign classifier using only the released XRan dataset.

**Architecture:** Immutable acquisition, audit and feature-group splits feed fresh count/CNN/GRU endpoint models. Calibrate the deployed scorer independently and export measured results to a lightweight Linux-hosted dashboard. Windows feature data remains labeled as Windows data.

**Tech stack:** Existing Python/PyTorch tooling; standard-library CSV/ZIP inspection; the existing Debian slim and ONNX CPU serving pattern after new-model export parity passes. Kaggle remains conditional on data-use permission and actual environment preflight.

**Spec:** [Architecture](architecture-xran-original.md) and [contracts](CONTRACTS.md).

## Material Passport

- Origin skills: BMad architecture, writing-plans, academic research experiment planning.
- Date: 2026-11-17.
- Verification status: source and data inspection executed; training, export and new dashboard are planned.
- Version: `xran-original-plan-v1`.

## Global constraints

- Only pinned XRan release data enters this experiment. No previous model weights, vocabularies, thresholds or external negatives.
- Preserve `API[500] || DLL[10] || Mutex[10]`, blanks and literal `PRF`; unknown semantics are not guessed.
- Primary endpoint predictions use a nominal 5% calibration target per distinct released feature vector; actual test false alarms remain measured outcomes.
- No unseen-family, live Linux, time-to-detection or files-saved claim from these CSVs.
- Keep raw files unchanged; every derived artifact identifies its inputs, configuration and code.
- Unavailable MD stays unavailable. Do not add other malware from a convenient source.

## Review focus

- A duplicate or contradictory feature row must not leak across roles or silently be relabeled.
- API-empty samples with DLL/mutex evidence must remain measurable; all-empty exclusion must apply to both classes.
- Unknown tokens, mixed case and literal PRF must behave identically during training and serving.
- A changed inference backend must not reuse a numerically incompatible cutoff.
- The dashboard must never show historical Linux results as results from the new XRan model.

## Completed discovery

- [x] Identify the supplied base paper and verify the public paper-associated release.
- [x] Download the four pinned feature archives and verify expected sizes and Git blob identities.
- [x] Inspect the actual 520-column layout and confirm absent temporal/process metadata.
- [x] Complete the all-row audit and independently reconcile totals, duplicates and source-specific missingness before freezing the cohort.

The [data audit](../../../output/research/xran-original-data-audit.md) records actual release counts and discrepancies with the paper. Source documentation alone does not establish exact experiment reproduction.

Verified release totals: 30,171 rows; 15,374 ransomware and 14,797 benign. SOREL has 8,443 rows, rather than the paper's 7,703. There are 22,469 distinct full vectors, 7,702 duplicate excess rows, and 24 full-vector groups with conflicting labels involving 825 rows. The 192 entirely empty rows are included in those conflicts, not an additional exclusion. The defined full-vector quarantine would leave 22,445 distinct groups before splitting; preparation has not yet created that model cohort. Independent inspection checked all rows and hashes. The user-provided root `benign.7z` is byte-identical to the previous EN2025 archive and is excluded from the new experiment.

## Task 1 — Freeze the valid cohort and grouping

**Owner:** data agent. **Files:** create `src/raneval/xran_data.py`, `scripts/prepare_xran.py`, `tests/test_xran_data.py`; consume existing `scripts/inspect_xran_original.py` and audited raw archives.

**Interface:** `read_release(manifest) -> rows, rejection_ledger`; `build_groups(rows) -> groups, quarantine`; `make_split(groups, seed=20261117) -> split_manifest` as defined in CONTRACTS.

- [ ] Write fixtures for semicolon quoting, UTF-8 BOM, exactly 520 headers/cells, literal PRF, case variants, blank API/full rows, duplicates crossing sources, and full-vector label conflicts. Golden check: ISOT data row 1 must retain the existing flat-vector SHA-256 `33540ac665eed5a816c87f28b47a330c369c3b103460a552f269510b51d53382`.
- [ ] Implement bounded parsing, provenance, hash grouping, symmetric quarantine and deterministic splits.
- [ ] Run `python -m unittest discover -s tests -p test_xran_data.py -v`; require all cases pass and every input row lands in a counted disposition.
- [ ] Prepare twice and compare output hashes; assert full-vector groups never cross roles. Save per-source counts, duplicate multiplicity, missingness, conflict and API-overlap ledgers.

**Done:** a frozen, auditable feature-group cohort and split exist. This is not an executable/family split.

## Task 2 — Encode features and implement endpoint baselines

**Owner:** model agent, after Task 1 interface freezes. **Files:** create `src/raneval/xran_models.py`, `src/raneval/train_xran.py`, `tests/test_xran_models.py`, `runs/xran-original/protocol.json`.

**Interface:** `fit_vocabulary(train_rows)`, `encode_views(row, vocabulary)`, `predict_endpoint(encoded_rows, bundle)`; one score per complete report.

- [ ] Test vocabulary isolation, unknowns, view namespaces, retained blank positions, output shape, finite logits and rejection of old streaming bundles.
- [ ] Add count-logistic, two-layer CNN and unidirectional GRU with fresh weights. Declare architecture settings explicitly; paper omissions remain assumptions.
- [ ] Freeze a small tuning grid and seeds `[17,29,43]` before fitting. Suggested starting capacity: 64-dimensional embeddings; two CNN layers with 64 filters, kernels 5 and 3, dropout 0.2, max-pool 2, dense 64; GRU hidden size 64. These are implementation choices, not recovered paper settings.
- [ ] Finalize one `protocol.json` before fitting: exact model/PAD settings, batch/epoch/optimizer/search grid, split hashes, diagnostic inclusion, scoring backend, explanation method and seed policy. Use seed 17 for the primary comparison; seeds 29 and 43 repeat the selected configuration as stability checks with their own independent calibration. Never select a best test seed.
- [ ] Rank configurations using seed-17 tune recall at a provisional tune-only 5% cutoff; ties use tune ROC-AUC, then fewer fitted parameters, then lexical config ID. The final calibration/test roles remain untouched. Save all considered configurations, not just the selected one.
- [ ] Add API-only and missingness-only diagnostic baselines. Report source predictability/missingness differences and API overlap; do not call high accuracy evidence of generalization by itself.
- [ ] Run `python -m unittest discover -s tests -p test_xran_models.py -v` and a small real-data train/save/load/resume smoke test. No full campaign until the smoke test passes.

**Done:** model and preprocessing contracts pass, and all model choices are frozen before calibration/test.

## Task 3 — Train with recoverable Kaggle or local execution

**Owner:** training operations, after Tasks 1–2. **Files:** create `scripts/package_kaggle_xran.py`, `runs/xran-original/environment.json`, complete checkpoint and export manifests.

- [ ] Record the dataset-use permission basis before uploading data or derivatives. Until resolved, use local CPU experiments; do not treat a private notebook as automatic permission.
- [ ] Inspect actual GPU/VRAM, CPU/RAM, disk, installed packages, quota, notebook session limit and network policy. The docs page was consulted during planning but did not expose readable current limits; no numeric service limit is assumed here.
- [ ] Use the existing recovery pattern: model, optimizer, scheduler, applicable scaler, RNG, epoch/step and data progress. Preserve config, input/split/vocabulary hashes and package versions.
- [ ] Benchmark one GPU. This compact dataset may not benefit from DDP; prefer independent model/seed jobs on a second GPU. If DDP is justified, shard batches and preserve global effective batch size.
- [ ] Start with FP16 on T4 where stable. Use a configurable total budget bounded by the verified session limit; allow up to 10 hours only when permitted, reserving at least 30 minutes for evaluation/export. Small experiments should finish substantially earlier.
- [ ] Test interruption/resume before unattended Save & Run All. Save recovery checkpoints every 10–20 minutes and before stopping, with measured disk/export headroom. `/kaggle/input` stays read-only; outputs go to `/kaggle/working`.
- [ ] Retrieve outputs and verify hashes/accessibility before marking training complete. Record whether execution actually used CPU or GPU.

**Done:** fresh XRan-only bundles and recovery artifacts are verified. No GPU result is claimed until executed.

## Task 4 — Export, calibrate and evaluate once

**Owner:** evaluation agent; can implement interfaces alongside Task 2, then run after Task 3. **Files:** create `src/raneval/xran_score.py`, `scripts/evaluate_xran.py`, `tests/test_xran_evaluation.py`, `runs/xran-original/evaluation/`.

- [ ] Test TP/FN/TN/FP accounting, undefined metric handling, score ties, tiny calibration cohorts, source membership, and old-bundle rejection.
- [ ] Select and freeze the serving backend. Verify raw logits/scores and classification decisions after export, including examples near a threshold.
- [ ] Calibrate each model on the same benign calibration groups using its actual serving arithmetic. Bind threshold to backend, dtype, model and preprocessing hashes.
- [ ] Evaluate the locked test once. Save the full classification report, confusion matrix, ROC-AUC, AP, actual FPR, recall intervals, per-source outcomes, inference latency/memory and artifact sizes.
- [ ] Include the same-group API-only/missingness diagnostics and separately frozen API-component sensitivity. Decide any source-held-out ransomware experiment in `protocol.json` before fitting or opening test scores; otherwise defer it to a separate prespecified study. A source-held-out test is not an unseen-family test, and shared benign provenance remains disclosed.
- [ ] Independently rescore all test groups and recompute confusion/calibration receipts from frozen artifacts. Run the real-data suite; report failures instead of replacing the test split.

**Done:** a verified comparison exists with results justified by the available data, including negative findings.

## Task 5 — Build the XRan dashboard slice

**Owner:** dashboard agent; layout/API fixtures can be prepared in parallel after CONTRACTS freeze. **Files:** create `demo/xran_dashboard/`, `scripts/stage_xran_dashboard.py`, `tests/test_xran_export.py`; reuse existing static styling and secure local Docker serving patterns.

- [ ] Add dataset/source/missingness overview, model comparison, confusion matrix and per-class metrics, selected-sample classification, and view-level explanations.
- [ ] Show paper-reported values separately from newly measured results. Mark source identity, missing metadata, feature-group split and known count discrepancies.
- [ ] Test unsupported schema, corrupt/mismatched model or cutoff, unknown tokens, API-empty rows, and untrained/no-export state.
- [ ] Build a small read-only nonroot Debian slim image with CPU inference. Bind to localhost; mount frozen artifacts read-only. Do not include training dependencies or raw executables in the image.
- [ ] Verify the complete classify→score→explanation→metrics flow against frozen outputs, plus desktop/mobile controls. Show no live protection or files-saved animation for this endpoint-only data.

**Done:** a user can inspect an XRan sample, understand the model's prediction and see measured model performance without confusing it with the earlier Linux demo.

## Task 6 — Gate any raw-report extension

**Owner:** root plus data/evaluation agents, only when new original data arrives. **Files:** a separate raw audit and versioned extension plan.

- [ ] Record the user's archive/source and reconcile membership with the released cohort; inspect reports without executing samples.
- [ ] Verify API timing/order, repeats, process relationships, successful effects and time of first DLL/mutex observation.
- [ ] Require prefix-invariance tests before temporal scoring. Keep endpoint and temporal model identities/results separate.
- [ ] Permit only metrics supported by verified fields. If original membership or chronology cannot be established, retain the endpoint plan and document the unresolved gate.

## Parallel execution and monitoring

Data/schema work runs first. After the contract freezes, model implementation, evaluation implementation and dashboard fixtures can run independently in three owned areas; root integrates and checks each result. Training depends on validated data/models, final evaluation depends on trained/exported bundles, and dashboard publication depends on verified evaluation. No agent changes another agent's owned files without coordination. Each handoff includes exact artifacts, command results, failures and assumptions.

The current deliverable is acquisition/analysis plus a reviewed plan. It does not authorize claims that the planned models or dashboard have already been built or trained.
