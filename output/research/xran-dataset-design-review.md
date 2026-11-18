# XRan-only architecture: independent design constraints

Date: 2026-11-17. Status: design review informed by the parallel acquisition audit; no model training or deployment was performed for the new experiment. The acquisition agent downloaded the public processed release and checked its file identities. This reviewer owns only this memo.

## Decision in one paragraph

Rebuild around the downloaded author-associated XRan processed release. Its four archives provide both ransomware and benign source classes, represented as 520-column string rows. The primary target is paper-inspired endpoint classification using `API[500] || DLL[10] || Mutex[10]`. The available rows lack the timestamps, process identities and operation arguments needed to reconstruct live observation or file outcomes. Prefix experiments on these rows can measure position sensitivity, but cannot yet establish real early detection. Neither Windows feature classification nor Linux-hosted Docker replay establishes Linux ransomware detection. Previously trained EN2025, ebpfangel, and CRIBA checkpoints, vocabularies, thresholds, and results must not become evidence for this new XRan-only experiment.

## Evidence and boundaries

This memo uses the supplied [XRan reading notes](XRan-reading-notes.md), which identify paper pages and tables, and the prior [architecture](../../_bmad-output/initiative-streaming-ransomware/architecture-streaming-ransomware/architecture-streaming-ransomware.md), [contracts](../../_bmad-output/initiative-streaming-ransomware/architecture-streaming-ransomware/CONTRACTS.md), and [execution plan](../../_bmad-output/initiative-streaming-ransomware/architecture-streaming-ransomware/EXECUTION-PLAN.md). Paper facts below are extracted from those notes; this reviewer did not independently re-extract the PDF. Current release facts were supplied by the acquisition agent's direct file inspection; its final manifest and audit are authoritative for row counts and checksums.

The public [sibelgulmez/XRan repository](https://github.com/sibelgulmez/XRan/tree/2cfebbfe45d3ed47b0204096186877e5991d6324) cites the base paper. At commit `2cfebbfe45d3ed47b0204096186877e5991d6324`, the acquisition agent downloaded `VirusShare.zip`, `Sorel20M.zip`, `ISOT.zip` and `Benign.zip` and verified byte sizes/Git blob identities. Each contains one semicolon-delimited CSV, with headers `ApiCall_0..499`, `Dll_0..9`, and `Mutex_0..9`. Cells are strings, including empty strings. No row-level label, sample hash, family, timestamp, process ID or API argument columns are present; class labels derive from archive provenance. This is a processed feature release, not a raw process-event corpus.

The inspection also found API-empty rows with populated DLL/mutex fields, the API token `PRF` with unverified semantics, case variations in DLL names, and environment-looking mutex strings. Preserve raw values and mark these findings before deciding normalization or padding. Do not assume that `PRF` means padding or discard API-empty rows from the multiview cohort. Source/class confounding and identifier memorization require explicit diagnostics.

The paper reports RD1: 6,263 VirusShare ransomware executables; RD2: 7,703 SOREL-20M ransomware binaries selected by tags; RD3: 668 ISOT ransomware behavioral reports; BD: 14,797 benign Windows programs; and MD: 6,263 other-malware samples (Table 2, pp. 7–8). These are reported population counts, not acquired or usable counts. The pooled ransomware collection is 14,634 samples by arithmetic, not a fourth independent source. Two binary tasks are described: ransomware versus benign, and ransomware versus other malware. The second task is optional unless its original negative cohort can also be obtained.

The paper's strengths for this project are a concrete multimodal behavioral representation, separate negative-class questions, an API-only ablation, and explicit explanation examples including errors. Its central limitations for rebuilding are incomplete preprocessing/model specification, unclear reconciliation of 80/10/10 splitting with 10-fold cross-validation, absent reported family/source separation, and conflicting pooled benign metrics. Preserve Table 4's 99.0% accuracy / 1.0% FPR and Table 6's 98.2% / 4.7% as unresolved reported values; 99.4% is TPR, not accuracy. None is a new benchmark target that our code has already reproduced.

## 1. Acquisition is a model gate

“The base-paper dataset” now resolves to the pinned author-associated processed release and its acquisition manifest. The paper says its data are available on request (p. 17), but that statement does not negate the public processed release discovered in this task. Raw reports, executable identities, original split membership, and the other-malware cohort remain separate availability questions. The release's association with the paper does not by itself recover those missing records.

| Acquired artifact | What can proceed | What remains blocked |
|---|---|---|
| **Current: author-associated 520-column CSVs from three ransomware sources plus benign** | Endpoint schema/duplicate audit, archive-provenance labels, declared count/CNN/GRU reconstruction | Exact original split/model reproduction; verified sample/family independence; chronological early detection; file outcomes |
| Original labeled ransomware and benign reports/features, with membership provenance | Schema audit, grouping, declared reconstruction | Exact reproduction until preprocessing, split, and model details are resolved |
| Original RD3 ransomware reports only | Malware-side schema/quality analysis | Binary fitting, benign calibration, FPR, specificity, precision, balanced comparison |
| Raw executables for both classes, without the original reports | Hash/label inventory and acquisition planning | Behavioral training until a separately designed Windows collection campaign exists |
| Provider data with different membership or newly collected negatives | A documented related-data proposal | Claiming the actual XRan cohort; including it without a scope decision |
| Published metrics or screenshots only | Literature analysis | Reproduced classification or trained deployment |

For every archive/member record: source URL/request provenance, access time, release/version, terms, archive and member checksums, sample executable hash if present, declared class and label basis, family and its provenance, producer/schema version, OS/sandbox metadata, capture ID/time if present, and parse status. Record whether a file is a raw report, a precomputed sequence, a binary, or a summary. Count missing members and failures by source/class; do not fill gaps with other projects' data.

Both classes are present by archive provenance, so endpoint preparation need not wait for author contact. Finish the row counts, malformed-row audit and duplicate analysis before fixing split sizes. Randomly selecting modern benign software does not recreate BD, and is unnecessary for the current endpoint experiment. Missing original sample hashes mean archive membership cannot establish every executable identity or original pairing. Resolve the paper's RD2-versus-MD balancing ambiguity only if pursuing the separate other-malware task.

## 2. The feature contract must distinguish endpoint from early evidence

The paper concatenates three feature sequences, not one globally time-interleaved stream. Its 520 slots do not mean 520 chronological actions. The first mutex slot at position 510 may have been observed much earlier or later than the API events. GRU steps through this serialized vector cannot automatically be interpreted as wall-clock progress.

Before fitting, freeze:

- Token namespaces (`api:`, `dll:`, `mutex:`), normalization/case rules, training-only vocabulary, unknown-token handling, and explicit padding.
- Which end is retained when truncating; “first 500/10/10” is a declared assumption unless the source/code confirms it.
- Whether duplicates are retained, first occurrence is used, or reports already collapse repeats. Do not invent missing events when expanding repeat counters.
- Whether missing/unsupported features can be distinguished from observed empty sequences. Missingness may identify collection source and must be audited by class.
- Ordering within each feature type and how calls across processes/threads are combined. Ties or uncertain order need a deterministic rule and a quality flag.
- Whether model units are reports, executables, captures, or processes. Sample-level labels do not establish that every child process, helper, or early prefix is malicious.

For the present release, these rules operate on supplied string positions. Preserve an immutable raw view and create declared transforms from it. Do not infer timestamps or per-process streams from column indices. Existing blanks, `PRF`, normalization and missing-view behavior need measured distributions; unavailable upstream extraction choices remain limitations rather than guessed facts.

Keep report names, file paths to downloaded samples, class directories, malware family labels, sandbox signatures, antivirus verdicts, report duration, and final sequence length outside learned inputs unless an explicitly justified experiment requires a causal version. Final trace length can be used retrospectively in evaluation, not to tell the model how far through execution it is.

**Causal-prefix test:** for any prefix boundary `t`, features and scores computed from the raw report cut at `t` must equal those computed from the complete report with the same boundary. Changing or deleting events after `t` must not alter the result. Merely hiding later API positions while retaining full-report DLL/mutex lists fails this test.

DLL and mutex fields in final report summaries support endpoint classification. They support early classification only when their first observable occurrence can be reconstructed from trusted event records under the same clock/order policy. If that cannot be established, omit them from the early track and explicitly retain the endpoint result as a different experiment.

Do not inherit the previous Linux TID router or its reset intervals. XRan's process aggregation is insufficiently specified; preserve raw process identity if available, but do not silently reinterpret a report as independent labeled tasks. The old 1,024-event blocks, later 256-event task resets, and 2,048-event calibration horizon are unrelated design choices, not XRan requirements.

## 3. Recommended architecture and comparisons

Retain useful infrastructure boundaries: immutable ingestion, a source adapter, quality audit, grouped split manifest, training-only encoding, model fitting, frozen scoring, calibration, evaluation, and a versioned export. Reuse software only after its semantics match this contract. Use a new experiment/artifact namespace so old weights and thresholds cannot be loaded accidentally.

| Track | Input | Models and fair comparison | Supported interpretation |
|---|---|---|---|
| A: XRan-inspired endpoint reconstruction | Declared 500 API / 10 DLL / 10 mutex slots from the available report | Count/logistic baseline, declared two-layer CNN, compact GRU; same samples and features | Classification after the chosen feature collection; GRU is an extension |
| A ablation | API-only, then full combined representation; optional DLL-only and mutex-only | Same split, tuning effort and operating-point policy | Added information from feature groups; feature-source confounding remains testable |
| B0: optional released-position sensitivity | First `k` supplied API columns, with exact feature access stated; do not use future full-view fields in a purported causal score | Same models, same row groups and position grid | Sensitivity to visible feature positions; neither verified elapsed time nor protection |
| B1: true early API extension, blocked pending raw evidence | Prefixes of observed API records under a validated availability/ordering policy | Prefix counts, prefix CNN, unidirectional GRU; identical prefix endpoints and per-report weighting | Detection by observed API-event budget; an extension beyond paper endpoint evaluation |
| B1 multiview extension, blocked pending raw evidence | Only DLL/mutex evidence available at each API boundary | All compared models receive the same causal evidence | Whether multiview evidence helps early detection under the measured availability policy |

For Track A, the count baseline ignores order but receives the same allowed tokens and truncation. CNN and GRU have access to order within the serialized feature blocks; report that serialization explicitly. A typed multi-branch network would be a further extension, not a silent reconstruction of the concatenated CNN. Use padding masks consistently and do not treat arbitrary integer token IDs as meaningful numeric distances without declaring that encoding choice.

For a later Track B1, a CNN may recompute each truncated prefix or use a verified causal implementation; no future token may influence the prefix score. The GRU is unidirectional. If the first-500 limit is retained, scoring ends there; continuous operation beyond that bound needs a separately calibrated policy. Equal total training weight per report prevents a long report from becoming many independent training examples. Prefix labels are weak supervision inherited from the eventual sample label and do not locate malicious onset. The present CSVs do not establish the availability/order premises required for this track.

Start with one small declared configuration for each baseline and a bounded tuning search. Keep hyperparameters, trial budgets, seeds, checkpoint selection and prefix sampling explicit. The paper's stated Adam/BCE/10 epochs can be an approximate-reconstruction setting; undocumented channel counts, kernels, dropout, embeddings, batch size and learning rate remain implementation assumptions. New choices may be sensible without being “exact XRan.”

## 4. Split and calibration requirements

The independent unit is an executable/sample lineage or related capture group, not a prefix. All prefixes and repeated captures of one sample belong to one role. Deduplicate before splitting, keeping counts and provenance. Record exact binary hashes where available, exact report hashes, and a documented class-blind behavioral-duplicate rule. Investigate cross-label duplicates rather than assigning them by convenience.

For the downloaded CSVs, sample lineage is unavailable: the enforceable minimum is an exact 520-cell feature-row fingerprint group, with separate API-only, DLL-only and mutex-only overlap diagnostics. Identical feature rows may represent different binaries, so call them feature duplicates rather than proven duplicate executables. A fingerprint must exclude archive name, row index and class. Whole API-empty rows share an API-only view and need explicit cohort handling. Exact feature grouping prevents obvious repeated-row leakage but does not establish independent infections or family separation. Report the resulting split as feature-group held out with unknown sample/family overlap.

Useful split metadata include executable hashes, capture linkage, family labels with provenance, source provider, sandbox/OS/version, collection date, and benign product/version lineage. Metadata absence limits claims; it does not authorize invented family identities. If legitimate variants share a hash or lineage, group them. A family-disjoint evaluation requires trustworthy family labels; a time-disjoint claim requires trustworthy sample/capture dates.

Use separate train, tune, benign calibration and test groups when the number of independent units supports them. Train fits all transforms and weights; tune selects configurations; calibration chooses operating points; test estimates performance once. Preserve the acquisition/schema pilot as development data. Do not apply both 80/10/10 and 10-fold cross-validation ambiguously: choose one declared procedure, or keep a separate paper-like random-split sensitivity whose weaker scope is explicit.

A common nominal FPR budget is useful for comparing the three models but is not part of exact XRan reproduction. For endpoint scoring calibrate endpoint scores. For early replay calibrate each benign report's maximum score over the entire fixed observation schedule, with frozen ties and alert rule. A threshold controlling per-prefix error does not control the probability that any prefix alarms. Calibrate each seed/model independently at the same nominal budget, then show achieved test FPR; these will not generally be identical.

Sample sizes must be based on independent groups actually acquired. FPR resolution is `1/n` for `n` calibration units. With zero alarms in 100 independent benign test units, the one-sided 95% binomial upper bound is about 2.95%; zero observed errors is not zero risk. If a grouped split is too small, report descriptive uncertainty rather than relax identity grouping to meet a target count.

Source/class confounding deserves a specific audit: compare report schemas, missingness, token namespaces, trace lengths and collection environments by class/provider; examine simple metadata-only diagnostics outside the primary detector. A source-held-out sensitivity helps only where label coverage permits it. Having all benign samples from BD and ransomware from other providers may make collection effects inseparable from class; this limits conclusions even if a random split scores highly.

## 5. Permitted metrics depend on acquired evidence

| Evidence present | Permitted result | Result that remains unsupported |
|---|---|---|
| Labels and endpoint features for both classes | Confusion matrix, recall, FPR/specificity, accuracy, precision/F1 at stated prevalence, ROC/PR summaries | Early warning, real-time performance, prevention |
| Valid causal API order | First-alert API index, recall by fixed event budgets, miss fraction, actual benign any-alert FPR | Wall-clock time or malicious-onset lead time without clocks/onset labels |
| Valid event availability timestamps | First-alert time from a declared origin; measured replay service latency separately | Time before encryption unless encryption onset is independently labeled |
| Resolved successful file operations and stable identities | Distinct observed modified-file counts, with clear existing/new/unknown strata | Files corrupted, irrecoverable loss, or files saved without content/outcome evidence |
| Matched file-content outcomes and validated intervention experiment | Bounded claims for the measured file outcomes and intervention | General prevention across hosts/workloads |

Report numerator/denominator, class composition, exclusions, empty reports and collection failures. Preserve all parseable ransomware in overall detection accounting, including inactive or truncated cases. Missing file ground truth is missing, never zero damage. A miss remains a miss even if its recording contains no resolved file modification.

Use paired comparisons on the same held-out units. Separate random-seed variation from sample/group uncertainty; do not count seeds or prefixes as independent infections. Family/group resampling must reflect the actual available grouping and its small-sample limits. Precision on a balanced benchmark is conditional on that balance and is not a deployment prevalence claim.

File outcomes and event timestamps are absent from the current release. Therefore the primary deliverable is endpoint classification; use only position-sensitivity wording for experiments on truncated columns. A real event-budget objective is a later extension requiring raw evidence and a recorded scope decision. Do not silently replace a file-protection research question with “percent of trace consumed.” Total trace fraction is a retrospective description whose denominator was unknown at alert time.

## 6. Platform and demonstration boundary

These are Windows API, DLL and mutex observations. Running training or a replay service on Linux does not change the telemetry domain. A Linux Docker dashboard can host an exported scorer and replay recorded Windows reports; it should display “recorded Windows behavior replay.” No mapping of Linux syscall names to Windows APIs can establish equivalent fitted inputs.

A safe bounded Docker demonstration can play an approved trace, score it using the frozen vocabulary/model/threshold, and close a cooperating writer's gate on seeded dummy files. Check exported-versus-reference score/alert parity, gate closure, and before/after hashes. Label any pacing as replay pacing if genuine timestamps are absent. This proves a control path on that fixture; blocked dummy writes are not estimated victims saved in the original infection.

If only executables are acquired, collecting fresh behavioral reports is a different dependency: a properly isolated Windows sandbox/VM, declared instrumentation and OS, controlled collection protocol for both classes, and trace validation. A Linux Docker container is not a substitute for this Windows execution environment or a claim of safe live malware containment. Do not execute downloaded binaries as part of the report-first audit.

## 7. Kaggle gates and stop conditions

Do not reserve a long GPU run before data identity, both-class coverage, parsing, grouping and experiment semantics are resolved. Prepared token tensors and manifests should be small enough to audit before training. Inspect the actual Kaggle GPU/VRAM, CPU/RAM, disk, existing packages, internet access, account quota, session limit, applicable rules and source-data redistribution terms at run time; this review has not verified a current account or session.

For these small 520-position models, measure CPU and one-GPU throughput before choosing two-GPU execution. Independent model/seed jobs may be simpler than DDP. If DDP is used, require one process per GPU, distributed sharding, preserved effective batch, coordinated stop/save and a tested full-state resume. Two T4s do not pool memory. Check T4 FP16 compatibility and stability rather than assuming native BF16 support.

Start the total budget before setup and include already consumed session time. Use a configurable 10-hour budget only if the verified limit permits it, reserve at least 30 minutes and increase that reserve using measured save/evaluation/export times. Save recoverable state every roughly 10–20 minutes: model, optimizer, scheduler, scaler where relevant, RNG, step/data progress, and all data/split/vocabulary/config/package identities. Verify a restart/resume smoke test and durable saved outputs before an unattended campaign. No GPU validation is implied by this design memo.

## Open questions that change the architecture

1. What are the audited row counts, malformed rows, empty-view rates and same-/cross-class feature-duplicate groups in the four acquired CSVs, and how closely do these counts match the paper?
2. Can original executable identities, original split membership, raw reports, and the separate MD cohort be obtained later? They are not columns in the current release.
3. What does `PRF` mean, and which blanks are padding, unknown collection, or observed absence? Can upstream truncation/repeat/process aggregation rules be recovered?
4. How many usable feature groups remain after grouping, and what degree of unavoidable source/class confounding limits their interpretation? Sample/family/date/lineage grouping is not available from these CSVs.
5. Can raw event evidence later establish API order, cross-process timing, and DLL/mutex first-observation availability? This decides whether Track B1 can ever proceed.
6. Can raw reports plus outcomes later establish file identity, operation success and content changes? No modification-burden result is currently supported.
7. Do access terms permit local processing, private Kaggle upload, checkpoint release and publication of derived examples?

## Acceptance checklist for the next architecture revision

The revised documents should name the pinned processed release and unresolved raw-data gaps; include the complete row/feature audit and both-class counts; replace unrelated EN2025/Linux defaults; separate endpoint reconstruction from optional position sensitivity and blocked true early extensions; define feature-duplicate split groups and their independence limitations; freeze calibration; and explicitly gate file-outcome and platform claims. Finish with an actionable parser/split pilot before model training. Existing public negatives support endpoint work; missing provenance/raw fields must not be filled with another dataset.

Method assistance: this review used the scientific-critical-thinking skill. Reference metadata was checked against the current arXiv record: Kassis, T., Agarwal, V., He, Y., Patel, D., and Brueckner, A. M. (2026), *Scientific Agent Skills: A Library of Procedural Knowledge for Research Agents*, current record v2. [DOI](https://doi.org/10.48550/arXiv.2609.00065). This is procedural attribution, not empirical evidence about ransomware detection.
