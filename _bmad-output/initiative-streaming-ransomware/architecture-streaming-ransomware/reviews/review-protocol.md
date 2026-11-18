# Protocol review

Reviewed 2026-11-16: EXECUTION-PLAN.md, CONTRACTS.md, architecture-streaming-ransomware.md against the earlier plan audit. Planning review only; no data or experiments executed.

Verdict: the original major audit findings are addressed. Resolve the following implementation-contract gaps before calling the protocol frozen.

## P1 - Partial outcome resolution can make success curves optimistic

**Where:** EXECUTION-PLAN G2; CONTRACTS, Ordering and file accounting / Replay, calibration and metrics.

G2 allows a primary cohort with 95% qualifying-event identity/status resolution, while D counts only resolved identities and S_D treats that count as an exact budget outcome. Event-level resolution does not bound distinct-file error: 95 known writes could all affect one file, while five unresolved writes affect five different files. Different alert positions can therefore have different unmeasured burden, and a zero/low-budget success may be unearned even though the trace passes G2. The general statement that unknown is missing does not specify how this case is implemented.

**Fix:** make primary exact-budget analysis require complete relevant modification resolution through the evaluated prefix (or complete-trace resolution for a model-independent cohort), and retain partial traces as missing/exploratory; alternatively define explicit lower/upper burden bounds and only count a definite success when the upper bound is within budget. Where repeat compression prevents a finite upper bound, success must remain unknown rather than count as true. Define the coverage denominator using attempted qualifying operations including unknown statuses. Keep the 95% threshold as an engineering audit target, not proof of exact budget eligibility.

## P2 - Zero-observation traces have no defined calibration or evaluation behavior

**Where:** CONTRACTS, q_i=max_t score_i(t), N_i and S_E; overall detection cohort definition.

The protocol retains parseable inactive traces, which can include zero API observations. Such a trace has no maximum prefix score and T/N is undefined at N=0. It is unclear whether it is a benign no-alert success, an acquisition failure, or an excluded sample; inconsistent handling would affect denominators and FPR.

**Fix:** define zero-observation reports as a named stratum with a specific inclusion rule. A defensible default is no model opportunity/no alert, reported separately, excluded from the primary streaming calibration/evaluation cohort, with exclusions included in the data-flow accounting. If retained in an overall detection denominator, explicitly define no-alert outcome without evaluating the fraction formula. Do not silently turn an empty maximum into a finite model score.

## P2 - Feature-state reset interface does not match the shared block-history rule

**Where:** CONTRACTS modules table, features `reset(trace)` versus models `reset(block)`; EXECUTION-PLAN section 5.

The primary design requires every model to see only the current block prefix, but the feature module has only a trace reset. Incremental API counts/scaling state can therefore persist across block boundaries while neural states reset, violating feature/history parity.

**Fix:** add an explicit feature `reset_block(block_id)` or make replay supply stateless block-prefix inputs; distinguish trace-persistent provenance from block-local features. Add a test with the same block after different preceding blocks: its feature vectors and reset-state predictions must match.

## P2 - Ranking sensitivity and uncertainty decision still have unspecified parameters

**Where:** CONTRACTS, grids and paired bootstrap paragraphs.

The text calls a log-spaced damage-grid sensitivity 'prespecified' but gives neither the grid nor a deterministic rule to derive it, and 'paired differences support opposite directions' lacks a confidence level/decision criterion. These are easy to choose after seeing results, weakening the freeze contract.

**Fix:** include exact sensitivity-grid values (or a detector-blind pilot algorithm), interval confidence level/method, and the reversal rule in the frozen protocol manifest. For example, two-sided 95% paired family-bootstrap intervals for the preselected CNN-minus-GRU scalar contrasts must exclude zero in opposite directions; otherwise describe a point-estimate reversal as inconclusive. Keep other grid/pairwise analyses exploratory as already planned.

No additional architecture expansion is recommended. These are contract clarifications, not reasons to add more models or infrastructure.
