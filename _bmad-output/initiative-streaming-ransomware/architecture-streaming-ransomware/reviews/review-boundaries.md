# Boundary review

Reviewed 2026-11-16: EXECUTION-PLAN.md, CONTRACTS.md and architecture-streaming-ransomware.md. Scope: whether independently implemented modules can obey the documents yet disagree on shared state, inputs or measurement. No code or dataset behavior was executed. Main documents were not edited by this reviewer.

Verdict: the pipeline separation is sound and covers the earlier audit well. Three shared contracts need resolution before independent implementation; two smaller lifecycle clarifications should land with them.

## B1 - Define the exact observation-to-model-input mapping

**Priority: high.** CONTRACTS.md lines 15 and 31 name ModelInput without defining it, while Observation contains plural event_refs and nullable logical_call_count. EXECUTION-PLAN.md line 95 measures W in observations. One builder could feed one token for a compressed repeated call, another could repeat the token logical_call_count times, and a third could emit each event_ref as a token. All appear compatible with the prose but change context length, training inputs, compute and alarm opportunities.

**Fix:** define the primary input item and the policy for observations that contain multiple different APIs. A minimal starting rule is one API token per source repeated-call record, no multiplicity feature and no synthetic intra-record alerts; reject/reroute unsupported mixed-API atomic records. Alternatively define ordered token batches, a shared boundary-aware encoder interface and no intra-batch scores. Whichever is chosen, distinguish repeat observations from W-sized context segments, declare W/H units, and version the representation. Specify how any retained repeat count affects the count baseline so it receives the same information as other models. Add a golden compressed-record example showing exact tokens, context indices and score count.

## B2 - Reset model inputs and state consistently without resetting outcomes

**Priority: high.** CONTRACTS.md line 15 gives features.reset(trace), while line 16 gives models.reset(block). EXECUTION-PLAN.md line 95 requires common block-prefix histories. An incremental count feature builder could retain counts from earlier blocks while GRU/CNN state resets, despite following those signatures. Conversely, a broad reset could accidentally clear file identities or cumulative modified-file sets.

**Fix:** define lifecycle operations and ownership explicitly: begin_trace initializes all per-trace state; begin_context resets model state, causal input accumulators, counts, position indices, CNN buffers/max and caches; observe updates identity/outcomes for the full trace independently. Trace-level first-alert latch, calibration running maximum, file-handle state and cumulative modification ledger persist across context boundaries. Declare context number and within-context index formulas for one-based observation indices. Training endpoint replay starts at that endpoint's context start, never at an arbitrary sequence start. Add a W+1 fixture proving model-state reset and outcome-state persistence.

## B3 - Partial outcome resolution needs a metric rule

**Priority: high.** EXECUTION-PLAN.md line 84 proposes >=95% qualifying-event identity/status resolution, while CONTRACTS.md lines 48 and 74-75 count confirmed resolved modifications and then test budget success. A trace can pass 95% coverage yet have an unresolved successful write before its alarm. An evaluator can count only known identities and report success at b=0 or b=1 although the unresolved event might modify another file. This conflicts with the intent that unknown is not zero unless the resolved-only lower-bound nature is explicitly reflected in the claim.

**Fix:** define outcome completeness per prefix and event eligibility precisely. For primary exact-budget curves, require the frozen cohort to have outcome-resolved qualifying events through the whole horizon (selection detector-blind). Alternatively compute lower/upper burden bounds and classify budget success as certain/possible/failed; do not present possible success as certain. A resolved-only curve is permissible if prominently called a lower-bound modification proxy and accompanied by unresolved coverage, but it must not imply verified success within a true file-modification budget. Distinguish unknown status, unknown identity and known duplicate-target events. Keep partial traces in overall detection. Add a fixture with one resolved file and one unresolved modifying event.

## B4 - Full score pass versus thresholded first-alert pass

**Priority: medium.** CONTRACTS.md line 66 says stop first-alert search on crossing, while calibration at line 68 requires each benign trace's maximum across the complete observation horizon. The document should make the two modes explicit so an implementation does not reuse early-stopped score files for later thresholds or sensitivity analyses.

**Fix:** replay-to-scores/calibration mode consumes the full horizon and retains running maxima, independent of any threshold. Thresholded evaluation may derive first crossing from completed scores; if it runs online it must still retain the required terminal accounting and cannot claim reusable full score coverage. Add coverage metadata to prediction artifacts and fail calibration on incomplete prediction horizons. Context reset must never reset trace-level maxima.

## B5 - Pilot is a provenance tag, not an ambiguous fifth fit role

**Priority: medium.** CONTRACTS.md line 33 includes role=pilot and says pilot groups become train/development only. The target split and loader rules otherwise use four roles. Two split builders could either leave the 100 pilot records unassigned or reassign them into tune, affecting both totals and model selection.

**Fix:** use immutable is_pilot/provenance membership plus a final role in {train,tune,calibrate,test}, or document an explicit provisional-to-final manifest transition. Keep pilot duplicate groups out of calibration and test; fix whether they may enter tune or only train before allocating counts. Each final trace must have exactly one role or an explicit exclusion. Pilot choice and assignment remain versioned.

## Coverage and accepted tradeoffs

- Raw/outcome/feature separation and future-suffix tests directly address leakage concerns.
- Inclusive triggering-event accounting is clear and correct under post-completion observation semantics.
- Repeat timing ambiguity, process ordering, missing family labels, and inactive/truncated traces have honest fallback paths.
- W-sized resets are a reasonable declared engineering tradeoff; they need the precise lifecycle above and a boundary sensitivity because attack context can span segments.
- The pilot/manual-timeline gates are appropriate. Their numeric targets are engineering screening criteria, not estimates of metric validity or statistical power.
- No schema-specific CAPE field semantics should be promoted from current documentation to verified EN2025 behavior before the pilot.

## Targeted recheck - 2026-11-16

Re-read the revised CONTRACTS.md and matching EXECUTION-PLAN.md sections. All five prior findings are resolved at the architecture-contract level:

- **B1 resolved:** exactly one int32 API token per retained call/repeat observation; event_refs are provenance; mixed APIs are not merged; W/N count observations; repeat counts do not enter models.
- **B2 resolved:** explicit feature/model block resets at observations 1, W+1, etc.; counts, pooling, hidden states and caches reset together; file identity/outcome, first-alert and calibration-max state persist. A boundary regression fixture is required.
- **B3 resolved:** primary exact outcomes require complete qualifying-operation resolution over the frozen horizon; partial records produce bounds/unknown, never exact budget success. G2 now distinguishes pipeline coverage from exact-cohort eligibility.
- **B4 resolved:** full-horizon scoring is mandatory for calibration and any maximum-prefix artifact; early-stopped first-alert runs cannot supply those maxima.
- **B5 resolved:** pilot_member is a provenance flag and every pilot group has final role=train; final roles are unambiguous.

The new valid-empty-trace, immutable endpoint-manifest, bounded float64 score and never-alert serialization rules introduce no substantive boundary conflict found in this targeted recheck. Source-schema semantics and exact pilot-dependent settings remain deliberately deferred gates, not verified implementation facts. No additional blocker identified; executable equivalence and golden-fixture tests are still required during implementation.
