---
title: Understandable live Windows detection dashboard
type: feature
created: 2026-11-18
status: built
baseline_revision: NO_VCS
route: full
route_source: auto
risk: medium
review: quick
review_source: pinned
lenses_ran: [quick]
context: []
---

<frozen-after-approval>

## Intent

The user finds the dashboard difficult to understand and visualize. Redesign the current local Windows lab around a clear story: launch a safe side-by-side workload, follow each process's measured model score, see whether it was flagged, and inspect independently observed file damage. The existing request authorizes implementing this reversible UI improvement; no design approval gate is needed.

## Boundaries & Constraints

Keep trained model, features, cutoff, native worker behaviors, authentication and fixed allowlisted controls unchanged. Use only actual server observations for charts and activity. Worker kind is a scenario label, never a model conclusion; no-alert never means safe. Score is a model score, not calibrated probability. Show process suspicion separately from measured file integrity. Preserve historical test evidence including24/24 and2/32falsealerts and clear controlled-workload scope. No external fonts/assets/dependencies. Accessible, responsive plain HTML/CSS/JS, still lightweight Docker. Keep secrets out of UI/logs/URLs except existing authorized fragment/sessionStorage flow.

## I/O & Edge-Case Matrix

| Scenario | State | Expected behavior | Error handling |
|---|---|---|---|
| Empty session | no workers/files | informative empty view and one clear run-both CTA | no invented results |
| Side-by-side run | actual genuine/destructive workers | separate readable process cards, real score histories, threshold, model verdict, six file tiles each | partial start failure explained |
| Completed run | score drops after earlier alert | retain flagged verdict and peak/first-alert facts | never imply prior alert vanished |
| Invalid file | independent validity check | file invalid status independent of model flag | missing evidence marked unknown |
| Offline/unavailable | agent offline, model missing or transport failure | explicit connection/error state; unavailable scores, disable relevant controls | prevent duplicate submissions |
| Phone/keyboard | narrow viewport and keyboard navigation | no page overflow, visible focus, charts described in text, accessible labels | no color-only meaning |

</frozen-after-approval>

## Code Map

- `demo/windows_streaming/static/index.html`, `style.css`, `app.js`: frontend implementation agent owns these. Existing poll750ms/API/control allowlist and token behavior retained. No framework or inline scripts/styles (CSP).
- `demo/windows_streaming/server.py`: root agent adds bounded actual history/milestone API enrichment; frontend consumes contract below. Worker/model code unchanged.
- `tests/test_windows_integration.py`: root adds meaningful state/history/first-alert regressions; existing HTTP and real worker suite retained.
- Dockerfile already copies static files and service; root rebuilds and verifies existing authenticated browser and controls with actual workers.

## API additions (root-owned)

Existing `/api/state` fields remain. Each actor additionally has `history` as actual ordered `{seq,score,time,op}` points (bounded512, only8mostrecent actors retain chart history), `first_alert_seq`, `first_alert_time`, `invalid_files_at_first_alert`; existing `peak_score`, `ever_alert`, `file_telemetry`, `score_available` remain. A null score is unavailable. Snapshot `activity` is bounded milestones `{id,time,type,job,actor?,seq?,file?,score?,message}`; types worker_started, worker_completed, worker_stopped, worker_failed, model_alert, file_invalid, file_restored. File milestones are first invalid and first restore per fixture, not every repeated mutation. Unknown job/actor history must render gracefully. Existing data must also render if additions missing.

## Tasks & Acceptance

- [x] Rewrite three static files into a polished, understandable dashboard. Prefer calm light canvas, dark slim brand/navigation area, clear hierarchy, generous spacing, restrained red/green semantics. Top summary: running workers, flagged processes, invalid files and events in current view. One primary 'Run side-by-side demo' action, secondary start genuine/start destructive and owned-worker stop. Explain that files are generated and the model observes rather than prevents changes.
- [x] Present a simple Windows activity → per-process history → model → dashboard flow; explain original XRan is separate in technical details, active native streaming model drives this screen.
- [x] Give each worker a chart of actual risk score (0–100 model score, not confidence), threshold line, clear flagged/not flagged/unavailable status, lifecycle, first alert and current/peak score. Six understandable file tiles show intact/changed-valid/invalid/unknown independently; hashes/PID/raw IDs belong in expandable technical details.
- [x] Bounded, human-readable milestone activity timeline; no repeated alert spam. Keep current demo clearly scoped versus older sessions. Provide a way to inspect older/all activity without overwhelming main view; batch redraw should preserve keyboard focus and expanded details during polling.
- [x] Show historical evaluation in a secondary validation section:24/24 destructive,2/32 benign falsealerts, controlled native tests; never present as live counts or production recall.
- [x] Add backend history/milestone records and tests, rebuild Docker, confirm real one-click pair, correct model-only decisions, first-alert retention, actual charts/files and current auth reload. Check narrow viewport and no JS errors. Preserve model SHA.

Acceptance: Given one click on comparison, then exactly two owned worker starts occur and live observations populate separate cards. Given completed default workers, then model-flagged destructive actor and unflagged genuine actor remain legible even if latest score falls. Given file damage without model alert, then damage remains visible independently. Given offline state or null model score, then UI never fabricates safe/flagged status. Given keyboard user, then controls/details retain focus while polling. Given old activity, then current run summaries have explicit scope.

## Implementation Notes

Completed frontend/backend/deployment. Eleven targeted backend/native tests pass, client checks pass, actual one-click browser pair648events with1flagged/6invalid/firstalert4. Desktop/mobile no overflow; focus/details retained during actual live polling, authenticated section reload passes; no JS console errors. Model SHA unchanged. Screenshots and final state saved under runs/windows-dashboard-redesign-20261118. Foreground native agent session56572 connected. No VCS available; no commit/remote operation.

No VCS. Root owns backend/tests/deployment and independent verification; implementation subagent owns static frontend files. No model or threshold changes authorized by this UI task.

## Review Triage Log

| Finding | Verdict | Resolution |
|---|---|---|
| Section anchors overwrite saved credential on reload | high | Recognize64hex launcher tokens only; retain ordinary section fragments; browser reload authenticated. |
| Queued-to-observed cards switch focus/details key | medium | Stable job key; live focus/details preservation verified. |
| Last unrelated workers falsely selected as current demo | medium | Empty current scope until explicitly started; saved IDs filtered, all history separately accessible. |
| Old in-flight poll erases newly started demo IDs | medium | Control-generation check discards stale responses/errors; targeted async regression. |
| Successful queued notice persists after completion | medium | Lifecycle-driven informational messages; completion verified in browser. |

All findings fixed; no deferrals. Single-worker controls preserve already active current workers; the comparison CTA resets to exactly its own new pair.

## Verification

- `node --check demo/windows_streaming/static/app.js`.
- `$env:PYTHONPATH='src'; .\.venv-raneval\Scripts\python.exe -m unittest discover -s tests -p test_windows_integration.py -v`.
- Docker build, authenticated HTTP state/history and actual browser side-by-side workload; desktop/mobile layout and console check. Screenshot of final visible result.
