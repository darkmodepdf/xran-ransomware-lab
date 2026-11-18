---
title: EN2025-audited Windows streaming detector laboratory
type: feature
ticket: ''
created: 2026-11-17
updated: 2026-11-18
status: built
baseline_revision: NO_VCS
route: full
route_source: auto
risk: high
review: quick
review_source: pinned
lenses_ran: [quick]
review_loop_iteration: 0
context: [_bmad-output/initiative-streaming-ransomware/research-streaming-simulator/selection-windows-option-b.md, tmp/en2025-investigation.json]
---

<frozen-after-approval>

## Intent

Audit existing EN2025 raw reports for process/file tracking, then deliver an honest first streaming detector: bounded native Windows workers, separate process histories, model-driven alerts and file evidence, with lightweight Docker inference/UI. The user explicitly authorized proceeding on this architecture and auditing before implementation; no further architecture-choice approval is needed.

## Boundaries & Constraints

Audit all 360 locally extracted development reports with bounded-memory parsing, explicitly distinguish this subset from the 1,652 publisher benign/ransomware reports. Preserve raw hashes and report every error/exclusion. Retain actor incarnation, thread, observed order, API-specific outcomes and file-handle lifecycle; pending calls and requested bytes are not completed damage. Never execute malware or original paths. Preserve historical XRan/Linux components. Generated fixture operations only; no arbitrary host paths/commands, recursive traversal, encryption, host PID killing, Docker socket or writable host mounts. Fresh trained baseline is sufficient for this first usable milestone; no guaranteed recall or automatic scenario-based alerts. Ground truth never enters model features. Captures have weak session labels, not per-call malicious truth. Windows workers execute actual operations; the container only scores and serves UI. No Kaggle/upload required.

## I/O & Edge-Case Matrix

| Scenario | Input/state | Expected behavior | Error |
|---|---|---|---|
| Concurrent workers | interleaved actor events | each actor matches its isolated scores | reject missing identity/sequence gaps |
| CAPE lifecycle | open/read/write/close, reused handle, pending/failure, rename | causal tracking; unknown stays unknown; no speculative damage | explicit counters |
| File evidence | benign append vs fixture-invalidating rewrite | changed and invalid are distinct from model suspicion | verify fixture hashes/validity independently |
| Controls | authorized local worker start/stop | only allowlisted bounded child workloads | reject auth/origin/path/size errors |
| No model/worker | missing bundle or offline agent | clear unavailable status, no fake score | no fallback alerts |
| Model present | frozen weights and calibrated cutoff | backend-identical predictions and measured report | reject bad schema/hash/nonfinite values |

</frozen-after-approval>

## Code Map

- `scripts/prepare_en2025.py`: existing identity/time helpers; token-only projection discards needed context, do not change old contract.
- `scripts/extract_en2025_reports.py`, `data/pilot-reports/*-extraction.json`: verified 180/class selection, immutable archive evidence. `.venv-raneval` has ijson3.6.0, NumPy, sklearn, Torch.
- `tmp/en2025-investigation.json`: bounded real-field inventory. NtRead/Write return0x103 is pending even status=true; Length requested only; setters need class-specific interpretation.
- New `src/raneval/windows_events.py`, `scripts/audit_en2025_streaming.py`: streamed CAPE projection, lifecycle audit, compact training events and audit report.
- New `src/raneval/windows_stream.py`, `scripts/train_windows_stream.py`: bounded actor features, fresh multiple-instance/session-level baseline fitting, exact lightweight runtime, calibration/evaluation.
- New `demo/windows_streaming/`: server/static UI, native agent/workers, Dockerfile, launcher, runbook. Reuse existing UI styling vocabulary, not old models/endpoints.
- New `tests/test_windows_*.py`: meaningful adapter, routing, integrity, auth and HTTP/worker integration.

## Tasks & Acceptance

- [x] Implement audit/projection first; run all local reports and save `data/processed/en2025-streaming/audit.json` plus `output/research/en2025-streaming-audit.md` before choosing supported features. Preserve source hashes, coverage denominators, PID/handle/timestamp/repeat ambiguity, unknown targets, sample/sequence duplicates and capture-level labels. No silent cap/exclusion.
- [x] Freeze shared normalized-event contract and bounded per-actor causal features; keep paths/names/scenario/oracle outside learned inputs. Explicit horizon/overflow telemetry. Split original captures by transitive exact identity/sequence groups before windows. Fit a small fresh baseline using capture-level multiple-instance pooling rather than declaring every ransomware prefix malicious. Select on tune; benign session maxima set threshold; lock test and record metrics/limits.
- [x] Implement native Windows agent and generated-fixture worker subprocesses with real synchronous operations and authenticated bounded localhost communication. Agent supervises only its own children, supplies true PID/incarnation, tracks independent file validity and cleans up its owned workspace safely. UI controls trigger allowlisted jobs, never host commands.
- [x] Build Docker standard-library HTTP service plus dependency-minimal numeric inference and plain UI. Start/stop benign/destructive workers on demand; live actor scores, alert log, file integrity/attribution and missing-data/errors. Model-based misses remain visible. Polling or SSE is acceptable. Bind host port8767 to localhost. No training libs/raw datasets in image.
- [x] Run audit, train/export/evaluate, native concurrent scenario, HTTP/API tests, Docker build/run/network parity and desktop/mobile browser checks. If Docker unavailable, start installed Desktop hidden and check supported mode without changing engine/security configuration. Resolve obtainable failures; document any external blocker precisely.

Acceptance:
- Given local reports, when audited, then every selected file has a disposition and coverage reports use actual denominators.
- Given shuffled unrelated actor traffic, when scored, then per-actor scores are identical to isolated replay.
- Given fixture workers, when actual writes occur, then ledger/validity agree with filesystem outcomes and are independent of scores.
- Given trained artifacts, when reloaded into shipped runtime, then scores/decisions/calibration reproduce; test metrics and weak-label/domain-shift limits are visible.
- Given running container/agent, when UI starts mixed activity, then actual Windows workers produce live scores/file evidence and stop cleanly; untrained/unavailable states never invent results.

## Implementation Notes

Completed audit, fresh capture-level baseline, native workers, authenticated inference/UI, launcher, documentation and Docker verification. Full83-test suite passed after reviewed corrections. Detailed evidence: ../../output/research/windows-streaming-verification.md. The first baseline has poor recall1/27; UI shows it and independent fixture validity, including live misses. No real malware executed; no external upload or VCS commit.

No VCS is available. The accepted user instruction authorizes implementation; preserve reviewable plan and evidence rather than repeat approval. Audit precedes model/runtime work. Implementation agent executes phases sequentially, reports progress, and may make routine design choices within these boundaries.

## Plan Change Log

## Review Triage Log

Final verification: all four quick-review fixes validated with regressions and unchanged regenerated artifacts. Additional verified patch: bounded413-body drain resolves reproduced Windows10053 reset;83-test suite now passes. UI authentication reload, truncation telemetry and stale transport-error corrections were validated during integration. No review finding deferred. Model quality remains an explicitly measured limitation, not an unreported success claim.

Independent quick review, pass 1:

| Finding | Verdict | Route | Evidence/action |
|---|---|---|---|
| Failed/pending rename clears binding | medium | patch | Projector mutates handle map regardless of outcome; gate invalidation on confirmed success and test failure/pending preservation. |
| Unnamed successful handle rebind inherits old path | high | patch | Open path falls back to existing map before replacement; a new binding without path must be unknown. Reproject and refit to keep artifacts consistent. |
| Same actor accepts different PID/incarnation | high | patch | Router keys only actor string; bind identity at first event, reject changes before mutation. |
| Startup failure leaves fixture workspace | medium | patch | Workspace exists before Popen and job registration; catch shown startup failures and clean only owned created inventory. |

All four are verified defects with small fixes inside existing interfaces; no user intent change is required. Existing audit totals and scores remain historical until corrected data is regenerated.

## Verification

- `PYTHONPATH=src .venv-raneval/Scripts/python.exe -m unittest discover -s tests -v`: all old/new tests pass; Windows integration actually runs on this host.
- `scripts/audit_en2025_streaming.py --help`, documented audit/train commands: real report dispositions, frozen model and saved evaluation.
- `node --check demo/windows_streaming/static/app.js`: syntax passes.
- Docker build and localhost health/event parity; native worker smoke and browser result screenshot. Capture exact commands/evidence in runbook and final report.
