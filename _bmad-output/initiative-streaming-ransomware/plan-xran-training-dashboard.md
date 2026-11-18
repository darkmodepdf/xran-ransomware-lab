---
title: XRan Kaggle training and dashboard metrics
type: feature
ticket: ''
created: 2026-11-17
status: in-progress
baseline_revision: NO_VCS
route: full
route_source: auto
risk: high
review: thorough
review_source: auto
lenses_ran: []
review_loop_iteration: 0
followup_review_recommended: false
context: [architecture-xran-original/CONTRACTS.md, architecture-xran-original/EXECUTION-PLAN.md]
warnings: []
deferred: []
---

<intent-contract>

## Intent

Implement the approved XRan-only plan, train count/CNN/GRU on Kaggle and show real held-out performance/confusion matrices. Current user instruction changes the future container target to lightweight Windows; training and discrimination between healthy and ransomware samples take priority now.

## Boundaries & Constraints

Use only the pinned four XRan archives and fresh weights. Exclude full-vector label conflicts and prevent exact group leakage. Preserve string identities/520 positions and independent train/tune/benign-calibration/test roles. User explicitly authorizes private Kaggle upload/training; record source/citation and do not publish the dataset. Do not represent this authorization as a publisher license grant. Current classifiers are endpoint Windows-feature models, not proven live prevention. Existing historical work is preserved. Windows Docker deployment is deferred; the new dashboard runs natively on Windows for review.

| Scenario | Input / state | Expected behavior | Error handling |
|---|---|---|---|
| Repeated/conflicting rows | Original release | Unique clean groups, complete exclusion ledger, no group crossing | Invalid archive/schema fails |
| API-empty but other views present | Valid520 fields | Train/score and include in metrics | All-empty input rejected |
| Training interruption | Saved current step | Resume optimizer/RNG/data state equivalently | Incompatible identity fails |
| New model at5% target | Held-out benign calibration | Reproducible lowest admissible cutoff | Ties and disabled threshold explicit |
| Dashboard without data | No frozen report | Honest unavailable state | No placeholder metrics |
| Frozen report available | Three models, same test cohort | Metrics and confusion matrices agree with receipts | Mismatched schema/counts rejected |

</intent-contract>

## Code Map

- `scripts/inspect_xran_original.py`: pinned archive audit; keep original sources unchanged.
- New `xran_data.py`, preparation CLI and tests: data agent.
- New `xran_models.py`, `train_xran.py` and tests: model agent.
- New `xran_metrics.py`, evaluation/packaging CLI and tests: root.
- New `demo/xran_dashboard/` and tests: dashboard agent; reuse historical styling, preserve old service.
- Existing `package_kaggle_expanded.py`: private dataset attachment, submission state and hash patterns; do not reuse old models/data.

## Tasks & Acceptance

- [x] Prepare and verify primary/API-component data artifacts twice.
- [x] Implement models, recoverable trainer and real-data restart smoke.
- [x] Freeze protocol before model fitting; inspect actual Kaggle GPU/resources/quota.
- [ ] Run private GPU fits, retrieve completed bundles and verify recovery/manifests.
- [ ] Calibrate/evaluate deployment-equivalent endpoint scoring and independently reproduce metrics.
- [ ] Serve verified XRan metrics/confusion matrices and check desktop/mobile UI.
- [ ] Update runbook, evidence and persistent context with actual results/limits.

Given identical raw inputs, preparation produces identical identities and role membership. Given frozen fits, the final cutoff uses only benign calibration groups. Given test labels and scores, confusion totals and displayed metrics reproduce independently. Given a completed Kaggle run, downloaded model hashes and actual GPU metadata verify training rather than merely submission. Given the dashboard, all three model matrices and comparisons show those measured results.

## Implementation Notes

Parallel ownership follows the user's explicit request for concurrent subagents; root monitors and integrates all handoffs. The old plan's Linux container and generic approval requirements are superseded by the current Windows-later and private-Kaggle instructions. No Docker engine/container-mode change is needed for this phase.

On 2026-11-17 the [original campaign](https://www.kaggle.com/code/vishwasbollam/raneval-xran-models-1117-130145) failed before fitting. Kaggle unpacked the attached archive, and the driver expected the archive file. Verified the nine actual downloaded files, corrected the loader and submitted [the retry](https://www.kaggle.com/code/vishwasbollam/raneval-xran-models-retry-1117-153248) with the same frozen data, protocol and training code. The retry worker polls it and publishes the verified report to the native viewer on [port 8766](http://127.0.0.1:8766/). The retry is in progress.

## Plan Change Log

- Accept the Kaggle unpacked dataset layout after exact file verification. Reuse the original data attachment and protocol in the retry. Give the retry worker its own receipts and publish to the existing dashboard report path.

## Review Triage Log

## Verification

- `PYTHONPATH=src python -m unittest discover -s tests -v`: relevant data, metrics, training/recovery and API tests pass.
- Real prepared-cohort deterministic hash check and independent group/role audit.
- Kaggle hardware preflight, restart smoke, completed output checksums and independent inference/metric replay.
- HTTP report equality, confusion totals, browser model controls and desktop/mobile layout.
