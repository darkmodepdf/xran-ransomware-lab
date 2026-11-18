---
title: Native file behavior training and concurrent detection
type: feature
created: 2026-11-18
status: built
baseline_revision: NO_VCS
route: full
route_source: auto
risk: high
review: quick
review_source: pinned
lenses_ran: [quick]
context: []
---

<frozen-after-approval>

## Intent

Implement the previously proposed richer native file telemetry and varied harmless training campaigns, retrain, and honestly test destructive-process detection alongside genuine traffic. The user's explicit implementation request approves this scope; preserve the frozen EN2025 model as a comparator. Do not repeat architecture approval.

## Boundaries & Constraints

Always use measured post-operation telemetry, owned six-file fixture roots, separate PID/incarnation histories, independent validity evidence, campaign-level partitions, separate tuning/calibration/test, exact exported-runtime parity, and explicit misses. Retain lightweight stdlib Docker inference. Preserve original historical XRan and EN2025 artifacts. Never run malware, traverse host files, expose arbitrary paths/commands, use kind/job/fixture names/validity/markers as learned inputs, synthesize missing EN2025 fields, tune on test results, or force alerts. No claim of real-world ransomware coverage from native fixtures.

## I/O & Edge-Case Matrix

| Scenario | Input/state | Expected behavior | Error handling |
|---|---|---|---|
| Measured operations | native read/write/truncate | real requested/completed bytes, offsets and pre/post sizes | reject invalid bounds |
| Concurrent or delayed activity | distinct actors or benign warmup within actor | isolated scores unchanged by interleaving; onset measured independently | reject identity/sequence changes |
| Missing enriched telemetry | historical event | explicit unavailable native-model score, no assumed zero behavior | preserved legacy model works |
| Benign lookalikes | save/overwrite, append, rotate, copy-like | calibration/test measure false alerts without relabeling | report ambiguity |
| Frozen model | exported bundle | reproduce training-library scores and decisions | reject hash/schema mismatch |

</frozen-after-approval>

## Code Map

- `demo/windows_streaming/agent.py`: safe owned fixture subprocess/supervisor; telemetry implementation agent already owns this file and native telemetry tests. API `Agent.start` accepts optional bounded `campaign` with variant, seed, cycles, delay, warmup. Variants benign append/save/rotate/copy; destructive truncate/overwrite/sparse. Event fields `byte_offset`, `file_size_before`, `file_size_after`, `file_offset_after`, `requested_bytes`, `completed_bytes`. Coordinate with agent `/root/telemetry_campaigns_v2`.
- `src/raneval/windows_stream.py`: preserve legacy Model/Router contract and default History; support native model via lazy dispatch/history factory to separate new module `windows_native.py`.
- `scripts/train_windows_native.py`: new measured campaign collection/training/export/evaluation CLI, no generated feature-only traces. sklearn available in training environment only.
- `demo/windows_streaming/server.py`, `static/app.js`, Dockerfile: model metadata/availability/rich telemetry display; preserve authentication/allowlists. Legacy default model stays available; new native bundle can be separate selectable file.
- `tests/test_windows_*.py`: existing safety, HTTP and native cleanup suite must continue passing.

## Tasks & Acceptance

- [x] Native telemetry agent completes observed measurements, bounded variants, independent validity and real operation tests.
- [x] Implement bounded native feature histories excluding missingness/failure shortcuts and all labels; use offsets/sizes, append/overwrite/truncate coverage, ordered per-file transitions and spread. Document limits of indistinguishable benign operations.
- [x] Collect reproducible real native campaigns with randomized fixture sizes/content/pacing and benign hard negatives. Freeze campaign assignments before fitting, no window leakage. Include delayed same-PID cases and held-out seeds/variants; report variant holdouts honestly when shared templates limit independence.
- [x] Fit small nonlinear baseline(s), tune on tuning operating-point recall, calibrate only benign calibration session maxima under a predeclared budget (zero observed calibration alerts acceptable), export dependency-free tree inference and verify parity. No adaptive threshold changes after test.
- [x] Evaluate frozen model on all held-out native actor streams, isolated and interleaved, plus fresh actual concurrent default workers and warmup. Record TP/FN/FP/TN, onset-qualified alert timing, invalid files before alert, per-variant results and CPU/runtime/bundle size. Do not claim unavailable metrics.
- [x] Integrate native model selection and honest cohort-specific dashboard metrics; preserve legacy model and evaluate EN2025 separately, unavailable enriched fields never scored as complete.
- [x] Run meaningful feature/validation/parity/routing tests, full existing tests, Docker build and real HTTP concurrent smoke. Save report and reproducible commands.

Acceptance: Given real campaign workers, when collection completes, then telemetry agrees with file outcomes and roots are cleaned. Given frozen partition manifests, when training runs, then no actor/campaign spans roles. Given interleaved unrelated traffic, then actor predictions equal isolated replay. Given a trained bundle, then exported inference agrees numerically with training inference. Given concurrent workers, then report actual detections and misses without scenario-driven alerts. Given test results, then preserve the cutoff and report benign lookalike errors rather than changing targets.

## Implementation Notes

Completed all execution tasks. Final v2: 230 actual native campaigns; fresh test TP24/FN0/FP2/TN30, calibration0/48, fixed cutoff0.742904033012732. Full101 tests pass. Both review EOF issues fixed with regressions; no findings deferred. Frozen inference and EN2025 hashes verified; exact isolated/interleaved and library/runtime parity. Docker HTTP902 events have zero score discrepancy. Original destructive worker alerts at event4 with1invalid fixture; delayed same-PID overwrite alerts at55 with2invalid; concurrent genuine workers stay quiet. Browser reloaded and visibly confirmed new metrics, online agent, peak/earlier alerts, measurements and process suspicion. Report: output/research/windows-native-training-results.md. Native agent runs in foreground tool session42834. No VCS commit or remote operations.

High risk reflects misleading security claims if validation leaks. This is a research lab, not production endpoint protection. No VCS exists. Telemetry implementation is delegated; remaining implementation uses this plan as its sole source. Primary agent performs independent verification and report review.

## Plan Change Log

## Review Triage Log

## Verification

- `$env:PYTHONPATH='src'; .\.venv-raneval\Scripts\python.exe -m unittest discover -s tests -v` -- all native and legacy tests pass.
- Training CLI collection/train/evaluate commands recorded in report -- distinct campaign roles, frozen calibration, per-variant metrics, parity and interleaving assertions.
- `node --check demo/windows_streaming/static/app.js` -- syntax passes.
- Docker build, health and authenticated actual native concurrent worker scoring -- report exact inference parity and independent fixture evidence.

## Empirical iteration 2 (2026-11-18)

V1 test12/18 and0/24 falsealerts preserved. Actual default concurrent HTTP worker missed, delayed overwrite detected onlyafter6invalidfiles. Broaden training data content profiles for BOTH classes and include sparse destructive variants, then use fresh campaignseeds/partitions/calibration/test under experimentv2. Never modify the cutoff after opening its test. Preserve v1test as diagnostic evidence and model snapshot. This is data coverage improvement within user-authorized implementation, not a rule or label-driven alert. Runtimefeatures remain unchanged.

Review quick pass1: medium/patch ? zero-byte successful read beyond EOF is valid but rejected; gate EOF bound on positive completed bytes and add regression. No trained feature changes for existing campaigns.

Quick review pass2: medium/patch ? zero-byte writes beyond EOF need not extend the file; native validation incorrectly rejects them. Apply completed_bytes>0 guard to write bounds in both native runtime versions and regression-test zero and positive completion. No collected campaign has zero-byte writes; learned features/cutoff remain unchanged.
