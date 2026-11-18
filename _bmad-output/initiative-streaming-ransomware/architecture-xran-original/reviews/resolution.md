# Review resolution — 2026-11-17

All actionable architecture review findings were reconciled before handoff.

| Finding | Resolution |
|---|---|
| Nested/flat feature hashes diverged | Contract now matches implemented flat520 hash; ISOT row1 golden test added and independently verified. |
| Threshold could arbitrarily suppress every alert | Defined bounded sigmoid scores, smallest admissible candidate, exact comparator/ties, and explicit disabled cutoff. |
| Mixed-label API components did not fit allocation strata | Defined component strata by label/source sets, component allocation, retained member labels and benign-only calibration. |
| Parallel service/model units lacked interface detail | Fixed request/response keys, model allowlist, size/type checks, all-empty422, PAD handling and count transform. |
| Model/seed/diagnostic choice could use test feedback | Required pre-fit protocol, primary seed17,29/43stability and exact tune ranking. Optional source holdouts must be declared before fitting. |
| Audit recommendations could conflict with architecture | Advisory report/template reconciled; original executed inspector preserved by hash. |
| Existing context/README still prioritized Linux | Both lead with XRan-only scope. Old initiative and decision entries marked historical/superseded. |

Evidence review found no remaining material source/technology blocker for the design. These are verified plans and acquired data, not executed model-training or deployment results. Exact paper cohort/split equivalence, MD, raw chronology and upload terms remain explicitly unresolved.
