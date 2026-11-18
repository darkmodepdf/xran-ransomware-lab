---
status: in-progress
route: full
date: 2026-11-17
---

# Expanded EN2025 Implementation Plan

**Goal**: Test whether retrained CNN and GRU models alert by observation 120 more often while preserving benign and other-malware false-alarm counts.

**Architecture**: Reuse the existing causal sequence models and split contracts. Evaluate original checkpoints, expanded-data refits and validation-selected candidates on the same fresh test partition. Run model fits on private Kaggle infrastructure.

**Spec**: [Architecture and evaluation contracts](architecture-streaming-ransomware/CONTRACTS.md) and the user's expanded-cohort request.

- [ ] **Cohort**. Verify all four publisher archives. In `scripts/prepare_en2025.py`, audit exclusions, exact-identity grouping and prior-development membership. Assign pilot groups to training only. Preserve the 2,048-observation cap and separate benign, ransomware and other-malware evaluation counts. Given the four archives, when preparation completes, every selected report has a disposition and no prior pilot group enters validation or test.
- [ ] **Training**. In `src/raneval/train.py` and `core.py`, retain the pilot defaults. Add early-focused prefix sampling and a selectable 120-observation tuning objective. Run six fixed three-epoch single-seed fits: CNN/GRU with W=256 standard, W=256 early, and W=1,024 early. Smoke-test resume and existing scoring compatibility.
- [ ] **Evaluation**. In `src/raneval/expanded.py`, expose the train and tune partitions to fitting only. Choose each candidate from tune results at a 2% nominal benign budget, favoring no increase in benign or other-malware alarms versus the expanded refit. Record the selection before test scoring. Recalibrate all weights on fresh benign data at 2%, with 1% and 5% secondary. Report old frozen 5% thresholds separately. Evaluate detection by 120/256/512 and by end of observation. Report paired differences and uncertainty. A candidate meets the empirical target if early recall improves without more benign or other-malware alerts and without lower overall recall than its matched, recalibrated pilot model. Expanded-data refits isolate the effect of model changes.
- [ ] **Kaggle**. In `scripts/package_kaggle_expanded.py`, publish the compact derived cohort to a private Kaggle dataset and submit only a private GPU notebook. Include pinned source/input hashes and frozen pilot weights, environment diagnostics, bounded runtime and recovery exports. Given a completed notebook, verify GPU identity, checkpoints, held-out alert counts and the exact comparison against the output manifests.
- [ ] **Results**. Document class counts, actual false alarms and early detection, including mixed/negative findings. Keep pilot test numbers as historical context and base conclusions on the common fresh cohort. Update project context and decisions.

**Verification**: `python -m unittest discover -s scripts -p test_prepare_en2025.py -v`, `python -m unittest discover -s tests -v` with the existing torch environment, a small end-to-end CPU run, followed by actual Kaggle output checks. Hazards covered include duplicate leakage, mutable thresholds, different scoring horizons, misreporting nominal versus achieved false alarms, and a run exiting before final evidence exists.
