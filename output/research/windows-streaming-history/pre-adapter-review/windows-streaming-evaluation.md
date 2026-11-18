# Windows streaming baseline

```json
{
  "candidates": [
    {
      "weight_decay": 0.001,
      "tune_sampled_prefix_auroc": 0.7813390313390314
    },
    {
      "weight_decay": 0.01,
      "tune_sampled_prefix_auroc": 0.6353276353276353
    },
    {
      "weight_decay": 0.1,
      "tune_sampled_prefix_auroc": 0.6317663817663817
    }
  ],
  "selected_weight_decay": 0.001,
  "threshold": 0.8979676155142287,
  "runtime_numeric_max_error": 1.1102230246251565e-16,
  "assignments": {
    "train": 198,
    "tune": 53,
    "calibrate": 55,
    "test": 54
  },
  "events_processed": 1649745,
  "sampled_training_instances": 52768,
  "window_horizon": 128,
  "history_evictions": 1491645,
  "conflicting_groups": [],
  "metrics": {
    "tune": {
      "sessions": 53,
      "benign": 26,
      "ransomware": 27,
      "tp": 0,
      "fp": 0,
      "tn": 26,
      "fn": 27,
      "auroc": 0.7877492877492878
    },
    "calibrate": {
      "sessions": 55,
      "benign": 28,
      "ransomware": 27,
      "tp": 1,
      "fp": 0,
      "tn": 28,
      "fn": 26,
      "auroc": 0.8485449735449736
    },
    "test": {
      "sessions": 54,
      "benign": 27,
      "ransomware": 27,
      "tp": 1,
      "fp": 0,
      "tn": 27,
      "fn": 26,
      "auroc": 0.8806584362139918
    }
  },
  "limitations": [
    "Development subset only; test is locked within already inspected development captures, not an external holdout.",
    "Exact raw/sample/full API sequence groups are transitive and disjoint; family/near-duplicate/source independence is unverified.",
    "Capture labels supervise a maximum instance score, never every ransomware prefix or child.",
    "One linear baseline, weak labels, small calibration cohort, no recall guarantees.",
    "CAPE vs native fixture collector/domain shift is unmeasured. Actual invalid files may receive no model alert.",
    "Paths, names, scenario, oracle, bytes and timestamps excluded from learned inputs. Target identities used only as bounded equality counts."
  ]
}
```
