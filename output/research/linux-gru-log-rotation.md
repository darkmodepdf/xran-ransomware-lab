# GRU log-rotation follow-up

Completed 2026-11-17. [Live comparison](http://127.0.0.1:8765/#comparison) · [Dashboard report](../../runs/linux-gru-refit/benchmark-dashboard.json) · [Saved alert rows](../../runs/linux-gru-refit/gru_refit-alerts.json)

## Evaluation

The fresh benign campaign produced 32 training, 20 tuning, 44 calibration and 44 test captures. Each of the last two splits included 12 log rotations, balanced across rename-and-compress, copy-and-truncate and delayed-compression variants. All 140 capped event sequences are distinct and have no exact overlap with the previous benchmark. The log rotations share a Python startup prefix. These captures repeat workloads in one local Docker environment. [Capture metadata](../../data/processed/linux-gru-rotation-benign.meta.json)

The refit keeps the original recurrent and embedding weights and learns a new readout from previous training captures and fresh hard negatives. It prioritizes high-scoring benign prefixes and early positive training prefixes. The selection used the new tuning captures and the five previously evaluated DarkSide and Erebus recordings. Selection was recorded before fresh calibration and test. Each comparable model used its own threshold from the same 44 fresh calibration captures at a nominal 5% cap. This allows two calibration alerts per model. [Selection receipt](../../runs/linux-gru-refit/selection.json)

## Results

| GRU configuration | Fresh calibration alarms | Fresh log rotation alarms | All fresh benign alarms | Known DarkSide by event 120 | Known Erebus by event 120 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Original weights, earlier threshold | Earlier calibration | 12 / 12 | 13 / 44 | 3 / 3 at event 28 | 2 / 2 at event 101 |
| Original weights, fresh calibration | 2 / 44 | 4 / 12 | 4 / 44 | 0 / 3 | 2 / 2 at event 108 |
| Refit readout, fresh calibration | 1 / 44 | 4 / 12 | 4 / 44 | 3 / 3 at event 6 | 2 / 2 at event 30 |

The first row uses the earlier threshold to score the same fresh benign test captures and the previously evaluated ransomware set. Recalibration reduced the log-rotation alarm count by eight. Both freshly calibrated GRUs flagged the same four log-rotation runs while the refit recovered DarkSide alerts and accelerated Erebus alerts. Overall fresh benign false alarms were 9.1% for both models. The realized test rates are separate from the nominal calibration cap.

The fresh holdout contains benign captures. All public CRIBA DarkSide and Erebus captures had been used in the previous benchmark. The other audited sources lacked compatible success or completion data or had unverified family coverage. The named-family results establish preservation on known recordings used during tuning. Fresh ransomware recall and latency remain unmeasured. [Positive-source audit](linux-gru-positive-holdout-audit.md)

## Verification

Reloaded all four saved bundles and independently reproduced the fresh calibration thresholds, 44 fresh test alert outcomes and five known alert positions for each model. Verified that the refit retained the original embedding and GRU weights. The Docker comparison endpoint matched the verified report. Desktop and 390 px browser checks passed, and the replay still alerted at event 26 and verified 358 preserved dummy files. [Browser screenshot](../../runs/linux-gru-refit/comparison-dashboard.png)
