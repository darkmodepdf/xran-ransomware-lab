---
title: Fresh XRan endpoint models and recoverable training
type: feature
ticket: ''
created: '2026-11-17'
status: in-progress
baseline_revision: NO_VCS
route: oneshot
route_source: pinned
risk: medium
review: quick
review_source: pinned
lenses_ran: []
review_loop_iteration: 0
followup_review_recommended: false
context: []
warnings: []
deferred: []
---

<intent-contract>

## Intent

**Problem:** The pinned XRan released vectors have no fresh reproducible endpoint classifier. Historical Linux artifacts cannot supply this experiment.

**Approach:** Implement fresh count logistic, CNN and full-position GRU models over the frozen 520-column representation. Train on train only, select epochs/configurations using tune only, and export hash-bound bundles. Save optimizer, scaler, random state, epoch permutation/cursor and best model so interruption/resume preserves the run.

</intent-contract>

## Implementation Notes

Oneshot route is appropriate because architecture and data contract are already frozen. Own only model/trainer/tests plus this build receipt. Root owns the campaign protocol and final evaluation. Use PAD0/UNK1, namespaced train vocabulary, fixed zero PAD embedding, GRU advancing through all 520 positions. Missingness diagnostic uses three fractions of blank cells. Read historical train.py only for atomic checkpoint conventions; no old weights/vocabulary/data imported. No VCS available.

## Plan Change Log

## Review Triage Log

## Verification

- `.venv-raneval/Scripts/python.exe -m unittest discover -s tests -p test_xran_models.py -v` with PYTHONPATH=src: architectures, blank/unknown/view semantics, bundle verification, exact CPU interruption/resume and tune cutoff must pass.
- Real-data bounded CPU fitting: train/save/load/resume over prepared XRan data, report actual steps and artifact hashes. No GPU execution claim without execution.
