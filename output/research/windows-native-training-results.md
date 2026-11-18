# Measured native behavior: implementation and results

Date: 2026-11-18. This is a controlled Windows fixture experiment, not a real ransomware or system-wide endpoint benchmark.

## Outcome

Implemented enriched native file telemetry, varied real native training campaigns, bounded causal features, portable forest inference, calibration and fresh evaluation. The active Docker service now loads the new native model. The frozen EN2025 model and its original 1/27 result remain unchanged.

**Final fresh campaign test: 24/24 destructive campaigns detected, 2/32 benign campaigns falsely alerted.** Both errors are retained. Actual concurrent Docker/HTTP tests also detect the original default destructive worker and a same-PID delayed-onset overwrite worker, while their concurrent genuine workers stay below the cutoff.

| Fresh concurrent HTTP workload | Peak score | First invalid event | First model alert | Invalid files at first alert |
|---|---:|---:|---:|---:|
| Default genuine append | 0.04413 | None | None | — |
| Default destructive truncate/rewrite | 0.96438 | 3 | 4 | 1 |
| Genuine saves alongside delayed destructive work | 0.46392 | 27 (transient save state) | None | — |
| Same-PID genuine warmup, then destructive overwrite | 0.99924 | 51 | 55 | 2 |

The cutoff was already frozen at **0.742904033012732**. It was not changed after campaign test or HTTP results. The default worker starts from a78-byte fixture and writes26-byte invalid contents after truncation. It is represented by compact-content training campaigns; this smoke test verifies real transport/concurrency and that workload, not unseen behavior generalization. Genuine saves can temporarily invalidate a fixture before completing the save; validity is not an alert rule.

## What changed

`demo/windows_streaming/agent.py` records actual pre-operation positions/sizes and post-flush outcomes: requested/completed bytes, offsets, file sizes, entropy before/after and changed-byte fraction. A read requesting 16 KiB can complete fewer bytes. Resize is not mislabeled as a completed write. The independent supervisor still hashes and validates files between acknowledged operations.

All operations remain inside the six-file generated, owned, capped temporary inventory. There is no malware, encryption, arbitrary host-file access or host process monitoring. Campaign profiles include JSON and checksummed generated binary fixtures, compact/repetitive contents and structured contents. The same legitimate fixture generator serves both labels. Benign workloads include append, full saves, rotation/truncation and copy-like rewrites; destructive variants include truncation, full overwrite and partial overwrite. Some destructive campaigns first perform genuine work within the same PID.

`src/raneval/windows_native.py` computes **26 features over the last 128 events per actor**. These describe append/overwrite/truncation, measured coverage, size changes, ordered per-file transitions, target spread, actual changed-byte fraction and entropy delta. Three features preserve a file's measured size across read → truncate → write, so replacing an 85-byte file with 25 bytes is distinguishable from restoring 85 bytes after a rotation.

The feature named `mean_changed_original_coverage` is union coverage of overwritten original ranges plus the currently missing suffix. It measures operation coverage, not proven byte inequality or encryption; measured changed-byte fraction and independent fixture validity are separate.

The learned model is a **32-tree random forest**, selected depth 7/minimum leaf 4. The container uses exported JSON trees and standard-library traversal, not sklearn, NumPy or Torch. Model schema `windows-native-forest-v2` is versioned; archived v1 runtime/model and legacy EN2025 inference remain supported. Missing required native measurements yield unavailable scores, not invented zero features or automatic alerts.

Worker kind, campaign/profile/seed/warmup, paths, fixture names, literal target hashes, validity and fixed marker contents are excluded from features. Target identities support equality only. Absolute entropy, unresolved-handle fractions and failure fractions are not native model features. Campaign labels/onset evidence supervise fitting and evaluate timing offline; inference receives only observed operation measurements.

The dashboard displays the native cohort's evaluation, current and peak actor scores, earlier model alerts and measured offsets/sizes. File validity and process suspicion have separate columns. Suspicion associates fixtures with an alerted actor; it does not establish that every fixture is corrupted.

## Experiments and partition integrity

The first native experiment collected 132 campaigns. Its fresh test detected 12/18 destructive campaigns with 0/24 benign false alerts, but all six sparse cases were missed. The frozen EN2025 comparator detected 0/18 on those same native streams. A subsequent actual HTTP test revealed another miss: the original fixed-content default destructive worker scored only 0.242 below cutoff 0.705. Delayed random overwrites alerted only after all six fixtures were invalid. These results, source and model remain in `runs/windows-native-campaigns-20261118/`; they became diagnostic development evidence for experiment 2.

Experiment 2 broadened content profiles for both labels, represented sparse behavior in training, and added the causal replacement-size measurements. It used a new manifest and fresh seeds, frozen before collection:

| Role | Whole native campaigns |
|---|---:|
| Train | 84 |
| Tune | 42 |
| Benign calibration | 48 |
| Fresh test | 56: 24 destructive, 32 benign |

All seven operation variants occur in training. Mixed, compact and repetitive profiles occur in development; the structured-content profile is test-only. All 230 campaign IDs/seeds are unique; entire PID/incarnation histories stay within their role. Templates and fixture grammars are still shared, so these are not independent malware-family or production workload holdouts. Compact benign cases can have identical measured prefixes across seeds; campaign separation does not imply template independence.

Ten forest candidates and the selection policy were declared in the manifest before collection. Selection uses onset-qualified tuning recall at a cutoff above benign tuning maxima, then false alerts, delay and complexity. The selected model's final cutoff is immediately above the largest benign **calibration** session maximum. Trees, feature order, horizon and cutoff were frozen before opening final test data; an inference-only hash proves they stayed unchanged. Adding measured evaluation metadata changes the bundle hash but does not change inference.

Final manifest SHA-256: `cdb2a5524bd9422663c718cf03686f982816dec18b416c485c82ee68d6e5ef6a`.

## Final errors, timing and comparisons

| Test variant | Destructive detected | Benign false alerts |
|---|---:|---:|
| Truncate | 8/8 | — |
| Full overwrite | 8/8 | — |
| Partial/sparse overwrite | 8/8 | — |
| Append | — | 1/8 |
| Save | — | 0/8 |
| Rotate | — | 1/8 |
| Copy | — | 0/8 |

The two false positives are `test-benign-append-mixed-0` (first alert event31, peak0.757898) and `test-benign-rotate-mixed-0` (event208, peak0.746313). Their labels were not changed and the cutoff was not raised after seeing them. Zero calibration alerts across 48 campaigns did not guarantee zero future alerts: the observed benign test false-alert proportion is 6.25%.

The 24 onset-qualified detections have median event delay 0, range 0–8 events. There are no alerts during destructive campaigns' genuine warmup. Zero event delay means scoring after the first damaging operation has completed, not preventing it. The number of already invalid fixtures immediately before the alerting operation ranges 0–2. In the actual HTTP smoke, one or two fixtures are invalid when the alert is produced. These workers continue after detection; no containment or restoration is implemented.

The unchanged EN2025 classifier detects **0/24** destructive campaigns and flags **0/32** benign campaigns on this same final native test. This is a valid same-cohort comparator. It does not mean the new native model has improved the historical EN2025 1/27 result: historical reports lack the richer required measurements and are not scored as if they contained them.

## Verification and resource measurements

- All **101 repository tests passed**; native tests actually ran on Windows. Tests cover real measurement consistency, benign hard negatives, delayed same-PID activity, cleanup, partition policy, excluded labels, missing telemetry, actor isolation and model validation. Review found valid zero-byte EOF reads/writes rejected; both runtime versions now accept them and regression tests reject positive out-of-bounds completions. No review finding is deferred.
- sklearn and exported runtime agree exactly on scores and decisions. Random interleaving of all held-out actor streams reproduces isolated scores exactly. Read-only replay reproduces the saved results without fitting or cutoff changes.
- Independent verification compared the final inference fields with the pre-test snapshot, confirmed the frozen EN2025 hash and checked all 230 owned roots were cleaned.
- The actual Docker/HTTP test processed **902 events**, with **0.0 score discrepancy**, no service errors, and all owned roots removed. All four workers completed.
- Host full Router inference, including feature construction, replayed 8,186 test events in approximately 0.891 CPU seconds (~9,191 events/CPU-second). This is a local microbenchmark, excludes collection/network and is not a production throughput guarantee.
- Bundle size: **214,089 bytes**. Docker reports approximately **178 MB** image size; `docker image inspect` separately reports43,319,777 bytes. Idle container memory was about **19.7 MiB**. Runtime is nonroot, read-only, capability-dropped, limited to128 MiB/one CPU, and bound to localhost8767. Training libraries and raw campaigns are excluded from the image.

The live service is `raneval-windows-native` at `http://127.0.0.1:8767/`, with the existing session credentials. A foreground native agent is running in the tool session; its lifetime depends on that session. The existing browser tab was reloaded and visibly confirmed v2 metrics, the online agent, earlier-alert/peak-score display, measured telemetry and separate process suspicion. The standard launcher starts a new session when the existing service is stopped; it will refuse to take over a busy port.

## Reproduction and artifacts

```powershell
$env:PYTHONPATH='src'
# New output directory; do not overwrite the recorded experiment.
.\.venv-raneval\Scripts\python.exe scripts/train_windows_native.py all --experiment v2 --out runs/windows-native-repeat --bundle runs/windows-native-repeat/native-model.json
# Replay the recorded final experiment, without fitting.
.\.venv-raneval\Scripts\python.exe scripts/train_windows_native.py evaluate --experiment v2 --out runs/windows-native-campaigns-v2-20261118 --bundle demo/windows_streaming/native-model.json
.\.venv-raneval\Scripts\python.exe -m unittest discover -s tests -v
node --check demo/windows_streaming/static/app.js
docker build -f demo/windows_streaming/Dockerfile -t windows-stream-lab-native .
```

For an isolated running service with no other agent connected, `scripts/verify_windows_native_http.py --credentials <local-credentials.json> --out <new-report.json>` executes the two actual concurrent pairs and checks transport parity. Never put credentials in source or reports.

Final evidence directory: `runs/windows-native-campaigns-v2-20261118/`: frozen manifest, source snapshots, compressed measured records, collection log, `frozen-before-test.json`, `frozen-inference.json`, `native-model.json`, `evaluation.json`, `evaluation-replay.json`, `http-verification.json`, `independent-verification.json`, and `tests.log`.

Final model payload SHA-256: `01b3497ca418991033fba338b301b5b823cf6ccedddecc81b82f9f9915a0e3cc`.

## Practical limit

This implementation detects these controlled damaging behaviors alongside genuine calls, using a learned model and measured file semantics. It does not monitor arbitrary Windows applications, prove ransomware intent, guarantee unseen behavior detection, stop corruption, or establish a production false-alarm rate. Equivalent observed benign/destructive behavior can remain indistinguishable. The next validation priority is broader legitimate workload coverage and independent collectors/workloads, preserving the measured two false alerts as regressions rather than tuning them away on the test set.
