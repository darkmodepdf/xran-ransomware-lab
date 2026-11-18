# Readable live dashboard

Implemented and verified on 2026-11-18 at the existing localhost8767 lab.

The dashboard now starts with one **Run side-by-side demo** action. Each process has its own score chart, threshold, current/peak score, retained model verdict and first-alert event. Six file tiles show independently observed integrity. Current-demo summary counts and a short milestone timeline replace the raw alert stream. Older workers, file hashes, PID/actor identifiers and model internals remain accessible in secondary views. Saved evaluation24/24 detected and2/32 benign falsealerts is explicitly separate from live counts.

Charts contain actual server-recorded points, including gaps for unavailable scores. The service keeps512 points per actor for8recent actors and96 milestones. First alerts and first invalid/restored-file observations are retained without repeated-alert spam. An earlier alert remains visible after the current score drops. Scope selection, keyboard focus, expanded details and authentication survive normal polling/reloads.

The trained bundle, feature extraction and cutoff are unchanged. Workload/scenario names do not determine alert badges. Invalid files remain visible even without model suspicion, and no-alert is not presented as proof of safety.

Verification:

- 4 new state/history tests and7 existing HTTP/native integration tests passed.
- JavaScript syntax and targeted client checks passed for null-score chart gaps, retained alerts, missing evidence, comparison requests, duplicate-submit protection, stable detail keys, section-link authentication, stale-poll rejection, single-worker additions and lifecycle notices.
- Actual browser comparison started exactly2 native workers, recorded648 events/history points, showed1 flagged process and6 invalid fixtures, and retained first alert at event4.
- Details remained open and keyboard focus stayed on the same summary during live polling. No browser console errors were observed.
- Section-fragment reload preserved authenticated access. Phone390px and default desktop layouts have no horizontal page overflow. Temporary viewport override was reset.
- Model SHA remained `01b3497ca418991033fba338b301b5b823cf6ccedddecc81b82f9f9915a0e3cc`.

Review findings fixed: section hashes mistaken for credentials, queued-card keys changing on first telemetry, prior unrelated jobs mislabeled as current, and stale poll responses clearing newly started job IDs. Browser QA additionally fixed stale queued notices after completion. No finding is deferred.

Evidence: `runs/windows-dashboard-redesign-20261118/{state.json,verification.json,comparison.jpg,mobile.jpg}`. The container `raneval-windows-native` serves the new UI; native agent tool session56572 remains connected. Current observations are in-memory; restarting the lab clears them.
