---
type: technical
topic: streaming detector dataset and simulator architecture
decision: choose replay-first or live controlled-workload implementation
status: complete
created: 2026-11-17
updated: 2026-11-17
source: primary web sources and separately identified local inspection
claims: {unverified: 3}
---

# Streaming ransomware demonstration: implementation choices

## Recommendation

Choose Option B, a controlled Linux workload laboratory, if the priority is to watch real file operations and simulated damage while a detector scores concurrent processes. Build its replay adapter first as an internal milestone. Choose Option A if a reproducible recorded-call demonstration is sufficient and minimal implementation complexity is the priority.

Neither option executes malware. Neither reuses the XRan weights for Linux syscalls. Keep the XRan endpoint dashboard and benchmark as a separate result.

The strongest immediate dataset fit is CRIBA plus newly recorded benign workloads. CRIBA's publisher releases Linux I/O traces; its paper describes process/thread context, syscall arguments and file correlations. [1][2] A local raw-record spot-check confirms the necessary basic fields, but full file-lifecycle and label audits are still required. Public logs alone do not supply a trustworthy per-file encryption ground truth.

## Option A: streamed trace replay and virtual file effects

Mix selected benign and ransomware recordings through a seeded scheduler. Preserve each source's event order and qualify actor and file identifiers with the source recording. Synthetic pacing is explicit; original within-source timestamps remain evidence rather than a claimed shared timeline.

Each event updates only the corresponding actor state. A trained streaming model emits an actual score. The engine maintains a virtual file ledger, mapping recorded targets to generated fixture IDs and applying declared simulated effects only for eligible modifying operations. Reads must never mark a file corrupted. Unknown paths or outcomes remain unknown.

Advantages: simplest packaging; exact replay; pause/step/rate controls; no kernel tracing permissions. Limitation: neither actors nor file effects constitute the original program executing. Fixture effects cannot establish historical ransomware damage or prevented damage.

Use this when the goal is to demonstrate streaming classification and attribution on recorded behavior. Windows EN2025 replay can replace the Linux adapter if Windows API vocabulary is essential, after its own audit and model training.

## Option B: live controlled workers and real fixture effects

Run separate benign worker processes alongside bounded ransomware-like workers. Benign workers perform real saves, copies, archive operations and log rotation. Ransomware-like workers perform bounded marker rewrites, renames or truncations on disposable, pre-generated fixture IDs only. No encryption executable, recursive host traversal, persistence or network activity is required.

A shared instrumented file-operation library executes real syscalls inside each worker and emits telemetry after the actual result is known. A central coordinator authenticates worker identity through local channels or OS peer credentials; it must not trust a client-supplied PID. Every worker cooperatively checks its gate before its next action. The library restricts operations to the generated fixture manifest and rejects path traversal, symlinks and arbitrary targets. This is an instrumented workload laboratory, not an arbitrary-process kernel monitor. Optional development-time tracing can check telemetry/OS parity; do not make privileged tracing a runtime prerequisite.

Use the same event projection for recorded training traces and live telemetry where semantics match. Preserve differences rather than fabricating missing fields. Archived versus live collection is a domain shift; successful replay does not prove live detection. Synthetic destructive workers validate mechanics and robustness, not unseen-malware generalization.

Advantages: actual concurrent processes, real fixture mutations, precise experimental ground truth, meaningful live feedback. Costs: more work on identity, scheduling, file lifecycles and data collection; synthetic behavior may differ from archived attacks.

## Open questions and reversibility

Option selection remains with the user. Both options share the same normalized event API, model interface and file ledger, so A can become B without replacing the detector UI. The strongest argument against B is the simulation-to-real-data gap and the amount of collection work; A has narrower but easier-to-verify claims. If Windows API semantics are mandatory, choose A with audited EN2025 data, or accept a separate Windows agent rather than describing Linux operations as Windows calls.

CRIBA positive diversity is small, Multi-Log contents/access are unverified, EN2025 file-handle completeness is unaudited, and archive/live recorder bias remains unresolved. No independent publisher evidence establishes that our proposed model will achieve a particular detection rate.

## Dataset screen

| Candidate | Fit | Limits and decision |
|---|---|---|
| CRIBA | Linux events with task/process and file context; strongest initial fit for both options. [1][2] | Local pinned cohort has five families and 14 recording runs. This count is from existing local adapters, not a new publisher-wide audit. Limited diversity among ransomware samples and prior exposure to these recordings limit generalization claims. |
| Fresh controlled benign recordings | Same recorder and schema as the live demo | Collect backup/copy, archive creation, SQLite, log rotation, document saves and harmless bulk rewrites. Split by original workload run before windows or mixtures. Generated campaign records are new local evidence, not a public external dataset. |
| EN2025 | Alternative for Windows API replay based on local CAPE inspection (local reference L1 below). The publisher lists benign/ransomware/other-malware logs and excludes executable binaries. [3] | Rich CAPE report fields exist in a local spot-check; handle/path/outcome coverage needs audit. Raw release is large; use a compact audited subset. Windows replay in Linux is logical event playback, not actual Windows execution. |
| Multi-Log | Publisher advertises 60 ransomware and 55 benign disk applications. [4] | Acquisition redirected to sign-in during research. Keep as a candidate for broader validation, not a verified training dependency. Family, file mapping, contents and dataset license scope remain unresolved. |
| GuardFS | Potential alternate source for process/file attempted-access behavior. [5] | Paper describes interception before access. Do not merge attempted operations with successful completed operations without an explicitly versioned representation and separate evaluation. |
| XRan | Keep current endpoint baseline | Its local contract lacks process IDs, event timestamps and file outcomes. It cannot support the requested streaming/file-attribution claims by itself. |

## Shared inference and file attribution design

Pipeline: event source -> versioned normalized event -> actor router -> causal features/model -> frozen session-level alert policy -> event stream to UI. Separately, successful operation results feed a file ledger and independent fixture verifier.

Event fields: session_id, sequence, process_instance, task_instance when available, operation, stable_file_id, source/destination names when known, call/completion time when available, observed-order index, result, bytes_written. Null means unknown. Raw timestamp and monotonic display time are separate. Do not sort a live stream using future events.

Process identity is session plus PID plus incarnation; capture-local identity is explicitly weaker. Maintain process histories and optional task subhistories, and aggregate thread alerts to the owning process. Evaluate both scopes: prior local experiments show thread/process distinctions matter. Related-process and shared-file aggregation is an extension, not an assumed solved capability.

Reuse the actor-routing concepts in src/raneval/process_score.py, but adapt the event and lifecycle contracts. Keep bounded state, explicit retirement, observable overflow/drop errors and an explicit duration/alarm horizon. Train new count-based models and small causal CNN/GRU models on the new representation. Compare recent windows with longer history; select using tuning sessions. Do not assume GRU is superior or ensemble old and new scores without calibration.

Candidate features: operation frequencies and transitions, successful writes/renames/truncations, distinct regular files touched/modified, read-then-change patterns, repeated versus distributed modifications and relative operation volume. Avoid learning literal PID, process name, filename extension, campaign name or source collector. File identity may support relational counts without becoming a learned label shortcut. Optional content features require a separate data audit and expensive-operation budget.

Model input excludes scenario selection, injected-label flags, attack start time, damage oracle, baseline hashes, and actor/file names encoding the class. A separate evaluator receives those fields; the UI may reveal truth only as an evaluation overlay. Running an attack scenario must not force an alert.

Keep three independent file attributes rather than one color pretending to prove causation:

- Integrity: unchanged, changed, deleted, renamed or unknown; SHA-256 validates generated contents and the mutation ledger records short-lived changes.
- Model attribution: no alert, touched by flagged actor, or attribution unknown.
- Fixture oracle: intended benign change versus destructive simulation effect, available only in evaluation view.

A changed hash alone is not corruption: normal software changes files too. Define corruption only against a known fixture validity/expected-content rule. Preserve file identity through rename and descriptor reuse; the existing path-based adapter needs improvement. Record transient writes even when a final hash returns to its initial value. A successful write does not prove encryption, and telemetry loss makes completeness unknown.

Initial mode is alert-only. An optional containment demo closes the cooperative worker gate for a flagged actor and records future denied fixture operations; unrelated workers continue. Completed writes before the alert cannot be claimed prevented. No arbitrary host process termination is proposed.

## Lightweight deployment and interface

Proposed runtime: Linux Python slim image, CPU ONNX Runtime plus NumPy, small HTTP service, plain HTML/CSS/JavaScript and server-sent events. Train/export outside the runtime image; exclude PyTorch, datasets, compilers and notebook tools. ONNX export or quantization is conditional on parity checks; calibrate on the exact shipped backend. Quantization is optional, not a promised compatibility/performance improvement. [7]

Use a read-only root and model, nonroot user, no host writable mount or Docker socket, disposable bounded tmpfs for fixtures, dropped capabilities, localhost port binding, and CPU/memory/process limits. Docker documents these runtime controls. [6] The exact configuration must be integration-tested. Artifact export can be explicit after a run.

Initial unmeasured engineering targets: <=200 MiB compressed image, <=512 MiB total container memory, one CPU, bounded actor/file counts, and a declared 100 events/s stress scenario without silent loss. Benchmark before claiming these figures. Linux Docker can run on the Windows desktop, but its genuine operations are Linux syscalls. A true Windows collector would be a separate native-agent/VM option. [8]

Controls: start/stop benign workloads, start/stop destructive simulation or selected trace, concurrency, pacing, attack delay, seed, pause/step replay, reset, and alert-only/fixture-containment mode. Views: per-process scores, task drilldown, call timeline, file ledger, alert evidence, event loss and CPU/memory, plus clearly labeled replay versus live and optional truth overlay. Record misses and false alarms visibly. No always-red attack scenario or hard-coded model scores.

## Verification and implementation sequence

1. Audit source archives and licenses; freeze versioned actor/file/event semantics. Retain raw identities/return values and full available sequences rather than inheriting the old 2,048-event cap silently. Audit label provenance; capture labels do not label every helper task or early event malicious.
2. Build deterministic replay, per-process/task routing and file ledger; verify known fixtures for interleaving, same-process benign prelude, multi-threading, PID/descriptor reuse, rename, failures, missing paths, ordering and dropped events. No accuracy claims at this milestone.
3. Split the original captures into training, tuning, calibration, and test sets before creating windows or mixtures. Keep all reused recordings labeled regression cases. Generate separate benign campaigns using the live recorder. Calibrate maximum/aggregate alerts across all actors per bounded session on the deployment runtime. Longer monitoring needs its own exposure-based false-alert evaluation.
4. Train baseline and neural candidates; assess with matched benign-only mixtures, several background loads and start offsets, and per-family results. Report actor-qualified recall, false alerts per session/hour with exposure, event/time-to-alert, and fixture changes before alert. A slow false alarm after damage must not count as successful early detection.
5. For B, add actual workers and their instrumented file-operation library, then independently compare requested actions, completed results, emitted telemetry and fixture outcomes. Test synthetic variants absent from training. Add optional containment after alert-only verification.
6. Export frozen inference and recalibrate on ONNX; integrate UI, measure runtime constraints, replay every score/decision from saved receipts, and make the two modes' evidence boundaries visible.

Acceptance requires actual model-driven alerts and honest misses, no scenario leakage, process-specific histories invariant to unrelated interleaving, correct fixture attribution, reproducible calibration, no silent telemetry loss, and measured resource figures. High unseen-ransomware recall remains an empirical objective, not a prerequisite to showing a truthful research demo.

## Sources

| Ref | Supports | Publisher / source | Date | Accessed | Confidence |
|---|---|---|---|---|---|
| [1] | Released Linux traces and framework | [CRIBA repository](https://github.com/dsrhaslab/criba) | pinned local revision b5e006a | 2026-11-17 | medium; primary source |
| [2] | Process/thread/file context and five-family study | [CRIBA SRDS paper](https://jtpaulo.github.io/assets/files/2023/criba-srds23-taniaesteves.pdf) | 2023 | 2026-11-17 | medium; same publisher as [1] |
| [3] | Windows logs, cohort counts, no executable binaries | [EN2025](https://zenodo.org/records/18218588) | 2026-01 | 2026-11-17 | medium; publisher claim plus local schema spot-check |
| [4] | Advertised cohort and trace types | [Multi-Log dataset](https://www.multi-log.com/dataset/) | not stated | 2026-11-17 | medium for listing; contents unverified |
| [5] | Before-access collection semantics | [GuardFS paper](https://arxiv.org/html/2401.17917v1) | 2024-01 | 2026-11-17 | medium; primary paper |
| [6] | Container runtime controls | [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run) | rolling | 2026-11-17 | medium; official documentation |
| [7] | Quantization mechanisms, not parity guarantees | [ONNX Runtime quantization](https://onnxruntime.ai/docs/how-to/quantization.html) | rolling | 2026-11-17 | medium; official documentation |
| [8] | Linux/Windows container modes | [Docker Desktop on Windows](https://docs.docker.com/desktop/setup/install/windows-install/) | rolling | 2026-11-17 | medium; official documentation |

Local inspection references: src/raneval/process_score.py; scripts/prepare_context_criba.py; scripts/prepare_linux_benchmark.py; architecture-xran-original/CONTRACTS.md; output/research/linux-process-architecture.md. These support implementation reuse and known limitations only; they are not external validation of research claims.

L1: locally inspected EN2025 CAPE schema: data/pilot-reports/ransomware/7124f6f197e503f77b3bbb136391b12d79a0e248e697506184aaf19b2df8eb7e/report.json (127,121 bytes). This is one record, not an archive-wide coverage assertion.

## Freshness

The citation checker found no dangling references; a fresh-context verifier checked primary-source support and requested the EN2025 Windows/CAPE assertion be tied to local inspection, now recorded as L1. Three load-bearing dataset claims remain independently unverified in the claims ledger; primary-source support is not independent model validation.

Computed freshness recheck: 2026-12-01 for rolling acquisition/runtime checks, using last-checked month as the baseline rather than claiming that official documentation was first published then. Recheck earlier before implementation. Docker daemon inspection during this proposal could not connect to the Linux engine; no engine switch or daemon launch was attempted.

Dataset metadata and acquisition: recheck before download/training. Runtime compatibility and image targets: recheck at implementation and each export. Published recording semantics remain historical source facts. Current external claims have primary-source support, without independent detector-quality validation. No accuracy or resource prediction is presented as measured evidence.
