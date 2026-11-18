# Windows streaming laboratory

Use **Run side-by-side demo** in the dashboard to start both workers. The current
demo has separate process charts, model verdicts, first-alert events and six
independent file-integrity tiles per worker. Use **All recorded workers** for
older runs. Raw identities/hashes and model details are expandable; saved test
results are separate from live counts. See `output/research/windows-dashboard-redesign.md`
for the verified interaction and responsive-layout results.

The default service now loads `native-model.json`, trained on measured harmless
Windows fixture campaigns. `model.json` remains the frozen EN2025 linear baseline;
use `server.py --model demo/windows_streaming/model.json` to explicitly compare it.
Native campaign results and historical capture results measure different cohorts
and must not be presented as a direct ransomware recall improvement.

The native model uses observed offsets, file-size changes, overwrite coverage,
ordered transitions, target spread and content-change summaries. It does not use
worker kind, campaign variant, filenames, fixture validity or a scenario switch.
Historical events without the required native measurements yield unavailable
native scores. The workers cooperate with the collector; this is not system-wide
monitoring of arbitrary Windows processes.

The UI shows live measurements, peak scores, previous model alerts and process
suspicion alongside independently checked file validity. An actor alert associates
suspicion with that actor's fixtures; it does not prove that each file is corrupted.

Reproduce the native campaign experiment in a fresh output directory:

```powershell
$env:PYTHONPATH='src'
.\.venv-raneval\Scripts\python.exe scripts/train_windows_native.py all --experiment v2 --out runs/windows-native-campaigns-repeat --bundle runs/windows-native-campaigns-repeat/native-model.json
```

Campaign manifests are frozen before collection. Whole campaigns, including their
actor histories, are separated into train, tune, benign calibration and test roles.
The final experiment uses new seeds and a held-out structured-content profile.
All operation variants are represented in training; these are template-based
behavior tests, not independent ransomware-family holdouts. The earlier experiment
with test-only copy/sparse variants is preserved separately as diagnostic evidence. Benign saves,
rotations and high-entropy generated binary fixtures are included as hard negatives.
Benign rotation can temporarily empty a file; that is not relabeled malicious.
No threshold is adjusted to make the default destructive worker alert.

The supervisor exposes the original bounded two-button workload in the UI. Richer
campaign settings are internal research inputs, not arbitrary HTTP commands or
host-file access. All campaigns operate on the same six-file owned inventory and
clean it up safely.

Native experiment and integration evidence is recorded in
`output/research/windows-native-training-results.md`.

Run from the repository in native Windows PowerShell:

```powershell
.\demo\windows_streaming\launch.ps1
```

Docker Desktop must be running in Linux container mode. The launcher builds the small inference image, maps **127.0.0.1:8767 only**, generates separate random control and agent credentials, opens the authenticated UI, and runs the native Windows supervisor. Press Ctrl+C in that PowerShell session to stop its owned workers and service. `-NoBrowser` prints the session URL without opening it. `-NativeServer` runs the same service through installed Python, useful when Docker is unavailable. The existing `.venv-raneval` is preferred; otherwise Python on PATH is used. Inference and workers use only the standard library. Do not share the session URL or credentials.

The browser token is passed through a URL fragment and removed from the address bar after initial load. It persists in tab-scoped sessionStorage so ordinary reloads preserve authentication; a new token fragment replaces the previous value. It is not placed in localStorage. UI control and state endpoints require the control credential. Agent ingestion and command polling require a distinct agent credential. Requests with another Origin or Host, oversized bodies, malformed events, sequence gaps, missing identity, arbitrary paths, unknown worker kinds, or unknown jobs are rejected. No CORS allowance is exposed. The public health endpoint exposes availability only.

Click **Start benign append** and **Start invalidating rewrite** to run concurrent processes. Each receives six generated JSONL fixtures in a fresh dedicated temporary folder. Benign appends remain valid JSONL; rewrites perform a synchronous truncate and fixed invalid-content write. Operations include open/read/resize/write/close; each is emitted after completion. An inherited pipe acknowledgement pauses the next operation while the supervisor independently reads, hashes and validates the fixed fixture inventory. Scores are computed per PID/incarnation and use no scenario or validity fields. The UI deliberately shows invalid files even when the model misses them. Stop buttons affect the supervisor's own subprocess objects only.

Workers run 12 rounds over six fixtures, normally about five seconds, with an absolute 30-second supervisor limit. At most four workers and 32 queued commands are allowed. Each fixture is capped at 16 KiB; the output queue holds 1,024 events. Cleanup validates the exact generated temporary-root identity and ownership marker, deletes its fixed known files, and removes that directory without recursive traversal. Unexpected entries or links block cleanup and surface an error. No original report pathname, malware executable, host command, user directory, encryption routine, recursive filesystem walk, Docker socket or writable host mount is used.

The runtime retains 128 events per actor and explicitly counts horizon evictions. It allows 512 actor histories and rejects overflow instead of merging or silently discarding actors. Job history is capped at 128; restart the lab for a new session after capacity is reached. Alerts/errors retain the latest 100 entries. These are in-memory laboratory views, not a durable incident store. Agent loss becomes visible after five seconds. A missing or invalid model yields unavailable scores and no synthetic alerts. On transport failure the agent exits and stops its owned children; do not interpret the last displayed evidence as a later filesystem observation.

Reproduce the historical audit and frozen EN2025 baseline:

```powershell
$env:PYTHONPATH='src'
.venv-raneval/Scripts/python.exe scripts/audit_en2025_streaming.py --help
.venv-raneval/Scripts/python.exe scripts/audit_en2025_streaming.py
.venv-raneval/Scripts/python.exe scripts/train_windows_stream.py
.venv-raneval/Scripts/python.exe -m unittest discover -s tests -v
node --check demo/windows_streaming/static/app.js
```

The audit reads every call in all 360 extracted reports, with streaming parsing and no observation cap. It hashes the raw files and saves a disposition for each. The development subset comprises 180 benign and 180 ransomware captures, distinct from the publisher's 1,652 benign/ransomware reports. Audit outputs are `data/processed/en2025-streaming/audit.json` and `output/research/en2025-streaming-audit.md`; per-report gzip projections are beside the audit. Raw reports, old XRan models and historical Linux components are preserved. Training dependencies are available in `.venv-raneval`; ijson is required for audit, NumPy/Torch/scikit-learn for training. They are excluded from the image.

The audit found 5,944,179 calls from 1,775 process occurrences, and projected 1,649,745 file/lifecycle events. Of 264,472 I/O calls, 255,660 have file-candidate targets. No reliable completed-byte count exists. The 570 pending calls, 172,541 handle-name conflicts, 143,106 handle rebindings, 19,056 unresolved handle duplicates and 37 unknown rename destinations constrain attribution. Paths are never evidence of guaranteed regular-file contents or confirmed damage. Repeats remain ambiguous and are not expanded. See [EVENTS.md](EVENTS.md) for the event contract.

Transitive exact raw/sample/full-API-sequence groups are assigned before windows. There are two duplicate sequence groups and no raw/sample duplicate groups. Roles contain 198 train, 53 tune, 55 calibration and 54 test captures. Model fitting minimizes a capture-level maximum-instance logistic loss; ransomware capture labels never label every prefix or child process malicious. Train/tune selection samples the first, every sixteenth and final actor prefixes; calibration and final reported evaluation score every prefix through the shipped runtime. Three regularization values are compared on tune only. The cutoff is strictly above the maximum benign calibration-session score across 28 benign sessions. Test never selects weights or cutoff.

The resulting cutoff is **0.8979676155**. Locked development-test results are **1 true positive, 26 false negatives, 0 false positives and 27 true negatives**, with session AUROC **0.88066**. This conservative first baseline has poor recall: 1/27 ransomware captures detected. Do not treat AUROC as its operational recall. Runtime/export numerical discrepancy is at most 1.11e-16. Details and limitations are saved in `evaluation.json`, `split.json`, and `output/research/windows-streaming-evaluation.md`. The JSON model includes schema, ordered features, horizon, parameters, calibration and a verified payload SHA256. No pickle or training framework is needed for scoring.

The test role is internal to previously inspected development captures. Family, near-duplicate and source independence are unverified. CAPE reports and native scripted fixtures have different collectors and behavior distributions; this demonstration does not establish real ransomware generalization. Historical baseline inputs exclude bytes, clocks, path/name strings, scenarios and fixture validity. Bounded target-equality counts are used, never the hash value itself. There is no scenario-based alert or guaranteed detection.

Manual container parity commands (the launcher provides the normal path):

```powershell
# Set distinct random WINDOWS_STREAM_TOKEN and WINDOWS_AGENT_TOKEN environment values first.
docker build -f demo/windows_streaming/Dockerfile -t windows-stream-lab .
docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --cpus 1 -p 127.0.0.1:8767:8767 -e WINDOWS_STREAM_TOKEN -e WINDOWS_AGENT_TOKEN windows-stream-lab
# In a second native Windows PowerShell session with the same agent token:
.venv-raneval/Scripts/python.exe demo/windows_streaming/agent.py
```

The Dockerfile-specific ignore file limits build context to runtime modules, the service, static files and frozen model. The image runs as UID 65534. The container serves inference/UI only; all actual fixture operations execute in native Windows children. No Docker engine or security-mode change is required.

Verification completed locally: the streaming audit processed 360/360 reports without errors or exclusions; deterministic training/export/evaluation completed twice; adapter, HTTP and actual concurrent Windows-worker tests passed; JavaScript syntax passed. Native tests verify 288 benign and 360 destructive events, 72 actual truncations with matching independently observed zero-byte invalid fixtures, changed hashes, content validity and owned-root cleanup. Docker/network parity, full-suite results and desktop/mobile evidence are recorded separately in the final verification report.
