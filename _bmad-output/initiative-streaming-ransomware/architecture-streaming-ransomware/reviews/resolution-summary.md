# Architecture review disposition

2026-11-16. Reviews assessed the documents, not executed data or model code.

| Finding | Resolution |
|---|---|
| Observation could encode one/many tokens | Exactly one API token per retained call/repeat observation; provenance references are not input tokens |
| Feature/model block resets diverged | Both reset together; trace-level ledger, alert and maxima persist |
| Partial resolution looked like exact damage | Exact primary cohort requires full qualifying-operation resolution; incomplete data is lower bound/unknown |
| Pilot role transition ambiguous | Final roles are train/tune/calibrate/test, with pilot_member flag constrained to train |
| Calibration could stop at first crossing | Full-horizon maxima required; early stopping only for fixed-threshold test alert search |
| Training-prefix populations differed | One frozen endpoint manifest reused by every model and seed |
| Score domain and no-alert serialization unspecified | [0,1] float64 persisted scores; explicit JSON never_alert mode |
| Empty traces caused undefined maxima/fractions | Valid-empty strata reported; excluded from primary nonempty fitting/calibration/earliness |
| Ranking/statistical rules underspecified | Fixed grids, 95% intervals, paired primary contrast and directional reversal rule |
| Source paths and count transform unclear | Relative paths corrected; raw counts and variance scaling without centering specified |

All actionable review findings have been incorporated. Boundary reviewer independently rechecked the revisions and found no remaining substantive incompatibility. Mechanical spine lint passed with zero findings. Local document links are checked separately at finalization. Package compatibility, raw-data semantics, actual GPU behavior, and novelty remain future verification gates; no execution claim follows from this document review.
