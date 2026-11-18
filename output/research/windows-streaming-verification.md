# Windows streaming laboratory verification

Verified 2026-11-18 (Asia/Calcutta).

- Full unittest discovery: **83 passed**; JavaScript and PowerShell syntax checks passed. Actual native Windows concurrent/stop/failure-cleanup tests ran.
- Full audit: 360 development reports, 1,775 process occurrences and 5,944,179 calls; every report projected. Audit is scoped to the extracted development subset, not the full publisher release.
- Four independent-review findings fixed: outcome-aware rename tracking, unnamed handle reuse, actor identity binding, and partial startup cleanup. Regression coverage added. Full regeneration found no changed source hashes, counters, projections, weights, cutoff or evaluation. Historical results and exact comparison preserved.
- Integration caught and fixed omitted truncation telemetry, reload authentication loss, stale connection-error display, and boundary oversized-request transport behavior. The bounded 413 test passed 20 consecutive isolated runs and the final full suite.
- Docker runs nonroot65534, read-only root, dropped capabilities, no-new-privileges, one CPU,128MiB memory limit and64-PID limit; host port binds127.0.0.1:8767 only. No host writable bind or Docker socket. Docker image list reports177MB; measured idle/container memory approximately19MiB (not a peak-load guarantee).
- Final UI started real benign and destructive native worker processes. They completed288 and360 events respectively. All12 fixtures changed;6 benign fixtures remained valid and6 destructive fixtures were invalid. No ingestion errors, rejected events or model alerts. The detector missed the simulated destructive worker; independent validity checks exposed this honestly.
- Windows versus Linux Docker scoring over all13,243 benign calibration prefixes: maximum absolute difference2.22e-16, zero decision flips, zero calibration alerts on either backend.
- Desktop/full-page screenshot and390px mobile check saved; document width375px within390px viewport. Viewport override reset. Ordinary authenticated reload preserves access.
- Measured development-test model: TP1,FN26,FP0,TN27; recall1/27, session AUROC0.8806584362. Weak labels, small cohort and CAPE/native domain shift mean this is an experimental lab, not reliable ransomware protection. No threshold/scenario manipulation was used to create alerts.

Receipts: `runs/windows-streaming-verification/verification.json`, `tests-final.log`, `calibration-backend-parity.json`, `live-state-final.json`, `dashboard-desktop.jpg`, `dashboard-mobile.jpg`. Credentials are local runtime secrets and are intentionally not reproduced in this report.

Start future sessions with `demo/windows_streaming/launch.ps1`; see its README. The verified current service/container and native agent remain available; the completed fixture workers have stopped and their generated temporary roots were cleaned up. Current manually verified container is `raneval-windows-stream`; stopping that container closes the current service, and its native supervisor exits on transport loss.
