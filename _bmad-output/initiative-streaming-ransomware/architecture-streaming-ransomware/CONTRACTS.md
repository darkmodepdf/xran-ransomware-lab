# Data and evaluation contracts v1.0

2026-11-16. Normative implementation specification; field availability is not yet verified. Nullable means unknown, never zero. Serialize schema/version/hash identifiers in every derived artifact. Final pilot-dependent settings must be frozen before model outcomes.

## Modules and interfaces

| Module | Owns | Interface/output |
|---|---|---|
| ingest | Source bytes and provenance | Archive member -> TraceManifest; no model-specific filtering |
| adapters | Source-schema interpretation | Raw report -> CanonicalEvent batches and diagnostics |
| ordering | Observation semantics | Events -> ordered Observation stream or ineligibility reason |
| identity | File/handle lifetimes | Observations -> resolved identities with confidence |
| outcomes | Qualifying modification rule | Resolved events -> ModificationLedger and eligibility |
| splits | Membership and independent groups | Trace manifests -> immutable role manifest |
| features | Causal model input and vocabulary | `reset_trace(); reset_block(); observe(observation) -> ModelInput` |
| models | Fitting and score state | `reset_trace(); reset_block(); step(ModelInput) -> score`; batch-prefix reference |
| replay | Shared history/horizon and timing | Frozen model + stream -> score/alert rows |
| calibrate | Threshold only | Benign calibration maxima + alpha -> ThresholdRecord |
| evaluate | Joined outcomes and uncertainty | Alerts + ledger + manifests -> result tables |

Dependencies flow from raw data toward outputs. Evaluation may read features/predictions and outcomes; features/models cannot import outcomes, labels-at-inference, or evaluation. Notebook cells call package functions rather than reimplementing them.

## Artifact contracts

All IDs are stable strings; event ordinals are zero-based, observation indices are one-based for equations. Timestamps use nullable integer microseconds relative to an explicitly recorded origin. Persist finite scores in [0,1] as float64: sigmoid of the neural logit or logistic-regression positive-class output. They are risk scores, not asserted calibrated probabilities. Preserve unrounded values; missing/invalid scores fail the run, not silently become negative predictions. ThresholdRecord uses either `mode="threshold", tau=<finite number>` or JSON-safe `mode="never_alert", tau=null`; do not serialize infinity/NaN.

| Record | Required fields |
|---|---|
| TraceManifest | trace_id, raw_sha256, archive/member reference, source_version, sample_hash nullable, declared_class, label_provenance, family nullable + provenance, duplicate_group, parser/schema_version, parse_status, completeness_reason, quality_flags |
| CanonicalEvent | trace_id, raw_event_ref, process_instance_id, thread_id nullable, raw_ordinal, API_name, original_timestamp nullable, timestamp_semantics, arguments_needed_for_identity, return_status, success={true,false,unknown}, repeat_raw, repeat_semantics, ordering_quality |
| Observation | trace_id, observation_index, event_refs, completion_time nullable, order_quality, repeat_block flag, logical_call_count nullable, availability_semantics |
| ModificationLedger | trace_id, observation_index, event_ref, file_id nullable, operation, success_certainty, identity_certainty, origin={existing,new,unknown}, eligibility, ambiguity_reason |
| SplitManifest | trace_id, role={train,tune,calibrate,test}, pilot_member boolean, group_id, family_provenance, split_version, exclusion_reason nullable; pilot groups must have role=train |
| Prediction | run_id, model_id, trace_id, observation_index, score, input_prefix_hash, protocol_hash, processing_duration nullable |
| Alert | run_id, trace_id, threshold_id, first_observation nullable, delivered_time nullable, caught flag, observed_horizon, truncation flags |
| RunManifest | source/split/schema/vocab/config/code hashes, environment lock, seed, hardware, selected model config, checkpoint refs, status and failure reason |

Store heavy event/outcome/prediction tables as partitioned Parquet; manifests/configuration as UTF-8 JSON. Publish artifacts via temporary write, validation, then atomic completion marker. Consumers read completed artifacts only. A changed input/rule produces a new artifact version and run directory, not an overwrite. Dense score files are streamed by shard and can be discarded after validated summaries only if the replay can deterministically regenerate them.

Primary ModelInput v1 is exactly one `api_id: int32` per Observation. Each observation represents one retained API-call record or one collapsed repeat record of that same API; its `event_refs` are provenance, not a variable-length model token list. Do not combine different APIs into one observation. Tie groups remain separate observations under the frozen tie policy. Adapter alias/hook deduplication rules choose one canonical API name deterministically; an ambiguous record is rejected from the primary replay cohort. Repeat counts are metadata for outcome/quality accounting, not additional model tokens in v1. Thus W and N count observations, not inferred repeated calls. Mixed-repeat semantics across reports are recorded and stratified.

Replay resets trace state once at trace start. Immediately before observations 1, W+1, 2W+1, etc., it calls BOTH `features.reset_block()` and `model.reset_block()`. The count baseline, CNN running pool, GRU hidden state, Transformer cache and position counter all reset together. The model receives only the API token; trace IDs, observation indices and hashes are control/provenance fields, not learned features. A regression fixture crossing W must show no influence of the earlier block on post-reset scores.

Block resets never reset trace-wide file identities, modification counts, first-alert state or calibration maxima. The primary count baseline uses raw sparse within-block counts with training-fitted variance scaling and no centering, no TF-IDF and no log transform. All models consume the same frozen endpoint manifest; weight each endpoint by the inverse endpoint count of its trace before any explicitly recorded training-only class weighting.

## Ordering and file accounting

Preserve per-thread order. Use source-supported global completed-event order when available; record deterministic tie-breaking as an assumption, not recovered truth. Do not sort away contradictory timestamps. The primary cohort must support the selected sample-wide observation semantics; ambiguous ties receive a predefined alternative-order sensitivity.

Validate the exact report producer's repeat convention. If intermediate timing or argument identities were lost, the repeat block is one atomic observation. Count all observable completed modifications in it before a post-block alert. Do not expand it into fictitious individual events. If changing file targets were lost, mark the file outcome unresolved.

Handle key: process instance + handle value + generation/lifetime; follow explicit duplication and close events. File IDs follow supported rename identity. Conservative path normalization must preserve unresolved aliases rather than guess. Treat failed writes as no confirmed modification, unknown status as unknown, and repeated writes to the same file as one distinct file. Multiple hooks for the same operation require a documented deduplication rule. Pre-existing, newly created and unknown-origin files remain separate categories.

Primary D_i(t) counts distinct identities with confirmed qualifying modifications observed by t, under the frozen target rule. Unless victim-file evidence exists, use all resolved filesystem-file targets and report origin/categories; do not assert user data loss. Non-file devices/pipes are excluded by a documented type rule. Known notes/temp files can be reported separately; excluding them from a victim-file sensitivity must be prespecified. Quality-ineligible traces remain in overall detection reporting, with damage outcome missing, not zero.

Exact primary damage metrics require all potentially qualifying operations within the locked horizon to have resolved status, target type and file identity; missing evidence that could change D makes the trace damage-ineligible, even if its pooled resolution rate exceeds 95%. Unknown file origin alone does not disqualify the all-files metric. Freeze eligibility before fitting and apply it equally to every model. In a secondary incomplete-data cohort, confirmed distinct identities are only a lower bound: do not count a trace as successful within b on that lower bound alone. Report interval-valued outcomes only when a defensible upper bound exists; otherwise state unknown and show missingness/selection bias. Neither uncertain traces nor unresolved operations disappear from coverage denominators.

## Splits and fitting

Targets before filtering/group constraints:

| Collection | Train | Tune | Benign calibration | Test |
|---|---:|---:|---:|---:|
| Benign (919) | 368 | 92 | 230 | 229 |
| Ransomware (733) | 440 | 147 | 0 | 146 |
| Other malware (1,608) | 965 | 322 | 0 | 321 |

Groups take precedence over these targets. Remove exact duplicates and form near-duplicate connected components before assigning roles; retain lineage/duplicate counts in the manifest. Use class-blind, fixed similarity rules; publish cross-label conflicts for adjudication. Family labels, where independently trustworthy, define disjoint ransomware train/tune/test groups. Group benign product/version lineages where known. Unknown-family groups support only group-held-out claims. Pilot groups belong only to training/development.

The fit task is binary. Other-malware FPR is separate from benign FPR; any pooled negative rate states weights. Do not report three-class F1. The test class mixture is not a production prevalence estimate. Tune hyperparameters on tune only; freeze the selected configuration before calibration. No test features fit vocabulary/scalers. Threshold calibration does not fit weights or select architecture.

## Replay, calibration and metrics

Primary alert rule k=1. Shared block size W, observation horizon H, model input policy and reset behavior come from a frozen protocol manifest. For each trace, score after each available observation. Post-observation alerts include that observation's modifications. Stop first-alert search at its first crossing; continue outcome accounting to terminal observation for descriptive burden. Ideal replay excludes processing delay; engineering replay uses measured arrivals/service duration and counts modifications through alert delivery. Do not invent arrival times if absent.

Calibration replay always scores the entire locked horizon, independent of any tentative threshold. Test replay may stop model scoring after the first fixed-threshold crossing when only first-alert outcomes are needed; any stored maximum-prefix score requires a full-horizon scoring pass. Different roles must not accidentally reuse early-stopped maxima.

Valid reports with zero observations are recorded as valid-empty, with no score and no alert. Exclude them from primary fitting, calibration and earliness cohorts; publish their class counts and separate all-parseable detection results (empty ransomware traces are missed). Never divide by N=0 or treat missing/failed reports as valid-empty. The calibration sample count is the actual number of eligible nonempty benign traces after these rules, not the nominal allocation. Report empty benign traces separately rather than diluting the primary FPR denominator.

For each eligible calibration benign trace, q_i = max_t score_i(t). With n traces, choose the smallest candidate threshold whose number of q_i >= tau is at most floor(alpha*n). Candidates are 0, observed q_i values, their float64 next-representable values still within [0,1], and finally the never-alert mode. Use float64 comparison for the frozen score files and record score precision. Conservative ties may yield lower than nominal FPR. Empty calibration, nonfinite scores, missing horizons or incompatible manifests are hard failures.

Primary alpha=.05; exploratory alpha=.01. Each final model/seed receives its own threshold. Report actual test benign FPR with exact binomial intervals and group-aware sensitivity when dependence is present. With n=230, zero observed alarms yields a one-sided 95% binomial upper bound `1 - .05**(1/230)` approximately 1.29%; this illustrates uncertainty, not a claim about our unrun model.

Let T_i be first-alert observation (infinity if missed), N_i the locked observed horizon in observations, and D_i(t) the cumulative resolved modification count.

- Observed burden B_i = D_i(T_i) if caught, D_i(N_i) if missed; unavailable ledger stays missing.
- Success within modification budget: S_D(b) = mean[ T_i <= N_i AND D_i(T_i) <= b ].
- Success within trace fraction: S_E(u) = mean[ T_i <= N_i AND T_i/N_i <= u ].

Use the same prespecified damage-eligible ransomware cohort for the primary RQ2 comparison: nonempty, exact-outcome traces with at least one confirmed qualifying modification within the locked horizon. Also report overall detection across all parseable ransomware and strata for inactive, truncated and damage-ineligible cases. For secondary nonempty inactive cohorts a missed zero-activity trace is a failure in both success curves; valid-empty traces have no defined trace fraction and are reported separately. Final length is permitted only in retrospective evaluation, never model input.

Starting grids: b={0,1,5,10,25,50}; u={.01,.05,.10,.25,.50,1}. If the detector-blind pilot shows b has no useful range, revise before locking or fail feasibility. A scalar ranking uses the unweighted mean success across each locked grid. Explain that grids encode priorities. Sensitivity damage grid: {0,1,2,4,8,16,32,64}, plus family-weighted summaries. Report curves and pairwise differences; three-model rank correlation alone cannot establish the claim.

For each model report five-seed variability separately from test-sample uncertainty. Pair comparisons by trace; bootstrap the same ransomware family/group clusters across models, averaging seed-level differences within each resample. Use 2,000 bootstrap replicates, fixed seed, and two-sided 95% percentile intervals. Test FPR uses two-sided 95% exact binomial intervals, plus group-aware sensitivity as applicable. Report trace-weighted primary and equal-family secondary summaries when family labels exist. Intervals are conditional on the trained models and frozen calibration thresholds; they do not capture all calibration uncertainty. Add a prespecified calibration-group resampling sensitivity if feasible; otherwise state this limitation. Do not treat seeds as independent datasets or ignore small group counts.

A primary directional comparison is CNN versus GRU at alpha=.05 using the two locked grid-mean summaries. Compute CNN-minus-GRU differences for both summaries; declare a supported reversal only if their two-sided 95% paired intervals lie entirely on opposite sides of zero. Otherwise report descriptive/suggestive/inconclusive differences or crossing curves. Counts comparisons and other pairwise/grid/alpha results are supporting/exploratory unless a multiplicity procedure is preregistered. A reversal is conditional on this cohort, summary and calibration policy; it is not universal superiority, and achieved test FPR differences remain visible.

## Dependency and runtime contract

Choose exact versions from a tested local/Kaggle-compatible lock in M1. Documentation reference versions observed on 2026-11-16: [Python 3.12.16](https://docs.python.org/3.12/), [PyTorch 2.15](https://docs.pytorch.org/docs/2.15/notes/serialization.html), [scikit-learn 1.9.1](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html), [PyArrow 26.0.1](https://arrow.apache.org/docs/python/index.html). These do not constitute a tested installation set. Prefer existing compatible Kaggle PyTorch/CUDA; pin additions narrowly. CAPE's [current documentation](https://capev2.readthedocs.io/en/latest/) does not prove EN2025 used the same producer version; adapter semantics must be checked against reports.

Package modules, CLI entry points and filesystem layout are implementation seeds, not already existing code:

```text
src/raneval/{ingest,adapters,ordering,identity,outcomes,splits,features,models,replay,calibrate,evaluate}/
configs/{pilot,protocol,models,runs}/
tests/{fixtures,unit,integration}/
data/{raw,canonical,manifests}/
runs/<run_id>/{manifest,checkpoints,predictions,metrics}/
notebooks/kaggle_runner.ipynb
reports/{audit,figures,tables}/
```

Proposed CLI verbs: audit, canonicalize, build-ledger, split, fit, replay, calibrate, evaluate, report. Each accepts a manifest/config path and writes a new artifact ID. No command silently downloads data, changes splits or fits on test.
