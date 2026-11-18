# RanEval ransomware detection pilots and response demos

## Windows streaming laboratory

The new streaming track audits EN2025 Windows reports and runs harmless native Windows fixture workers alongside Docker inference and UI. It keeps process histories separate and checks file integrity independently of model scores. No malware is executed.

```powershell
.\demo\windows_streaming\launch.ps1
```

Read the [runbook](demo/windows_streaming/README.md), [event contract](demo/windows_streaming/EVENTS.md), and [data audit](output/research/en2025-streaming-audit.md). The first experimental baseline has poor detection recall; its measured results and limitations are shown in the interface and [evaluation](output/research/windows-streaming-evaluation.md). This is a controlled workload lab, not validated live ransomware protection. XRan endpoint results and historical Linux experiments below remain separate.

## Current direction: XRan original dataset only

The active plan now uses only the public paper-associated XRan feature release. The four pinned archives are in `data/raw/xran-original/`; all 30,171 rows have been inspected. They contain 500 API, 10 DLL and 10 mutex feature positions describing Windows programs. The downloaded SOREL cohort differs from the paper's count, and exact duplicate/conflicting vectors require grouping before training.

[Data audit](output/research/xran-original-data-audit.md) · [New architecture](_bmad-output/initiative-streaming-ransomware/architecture-xran-original/architecture-xran-original.md) · [Implementation plan](_bmad-output/initiative-streaming-ransomware/architecture-xran-original/EXECUTION-PLAN.md)

```powershell
.\.venv-raneval\Scripts\python.exe scripts/inspect_xran_original.py --offline
```

Acquisition and analysis are complete. New model training and the XRan dashboard are planned. The primary task is endpoint ransomware-versus-benign classification; these CSVs do not establish live Linux detection or damage prevented. The root `benign.7z` provided on 2026-11-17 matches the existing EN2025 archive and is outside this new dataset scope. All Linux/EN2025 instructions and results below are historical work, separate from the new XRan plan.

## Run the Linux dashboard

The dashboard replays recorded Linux events through a Kaggle-trained CNN and compares two identical generated file sets. One lane records every marker write. The protected lane blocks writes after the first alert. The browser shows the score, threshold, alert position, replay rate, and final file-integrity checks. [Linux architecture](_bmad-output/initiative-streaming-ransomware/architecture-linux-demo/architecture-linux-demo.md)

From the workspace root with Docker Desktop running in Linux-container mode:

```powershell
docker build -f demo/linux_dashboard/Dockerfile -t raneval-linux-dashboard .
.\demo\linux_dashboard\run.ps1 -InputDirectory 'runs\linux-dashboard-inputs'
```

Open [the dashboard](http://127.0.0.1:8765/), choose **Ransomware trace**, and start the replay. Use **Benign control** for the matching control and **100 events/s** for the paced stress run. The launcher binds the port to localhost and mounts the prepared inputs read-only. If the demo is already running, open the dashboard directly.

### Reproduce the Linux training and export

```powershell
python scripts/prepare_ebpfangel.py --download --output data/processed/ebpfangel-linux.jsonl --audit data/processed/ebpfangel-linux-audit.json
python scripts/package_kaggle_pilot.py --profile linux --epochs 5 --data data/processed/ebpfangel-linux.jsonl --notice data/raw/ebpfangel/LICENSE --out runs/kaggle-linux-pilot --push
kaggle kernels output <owner>/<linux-notebook-slug> --path runs/kaggle-linux-pilot-outputs
```

Use the notebook slug returned by Kaggle and download after the notebook status is complete. Use fresh directory names for repeat attempts. Stage the frozen bundle with CPU PyTorch, `onnx==1.20.1`, and `onnxruntime==1.23.2` in the local Python environment:

```powershell
$env:PYTHONPATH = 'src'
python scripts/stage_linux_demo.py --data data/processed/ebpfangel-linux.jsonl --audit data/processed/ebpfangel-linux-audit.json --runs runs/kaggle-linux-pilot-outputs --out runs/linux-dashboard-inputs
```

The export checks downloaded artifact hashes and requires streaming PyTorch and ONNX Runtime to agree on the alert position for the selected traces. Read `verification.json` for the model selection, held-out counts, and parity results. The published traces cover selected Linux event types and a small number of independent captures. [ebpfangel research](https://ebpfangel.philippart.me/Ransomware_Detection_using_Machine_Learning_with_eBPF.pdf)

### Reproduce the fresh Linux comparison

The [Model comparison tab](http://127.0.0.1:8765/#comparison) reads a staged `benchmark.json`. The workflow below reproduces the initial CRIBA and `strace` comparison. The current report includes the contextual GRU follow-up. [Comparison protocol](_bmad-output/initiative-streaming-ransomware/plan-fresh-linux-benchmark.md)

To record a new benign cohort in Docker and prepare the archived captures from PowerShell:

```powershell
Get-Content -Raw scripts/linux_benchmark_collector.Dockerfile | docker build -t raneval-linux-benchmark-collector -
New-Item -ItemType Directory -Force data/processed | Out-Null
$benchmarkScripts = (Resolve-Path scripts).Path
$benchmarkData = (Resolve-Path data/processed).Path
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only `
    --cpus 2 --memory 512m --pids-limit 96 --tmpfs /work:rw,noexec,nosuid,nodev,size=192m `
    --mount "type=bind,source=$benchmarkScripts,target=/scripts,readonly" `
    --mount "type=bind,source=$benchmarkData,target=/out" `
    raneval-linux-benchmark-collector python -B /scripts/capture_linux_benign.py --output /out/linux-benchmark-benign.jsonl
python scripts/prepare_linux_benchmark.py extract --download --output data/processed/linux-benchmark-criba.jsonl
python scripts/prepare_linux_benchmark.py merge --positive data/processed/linux-benchmark-criba.jsonl --benign data/processed/linux-benchmark-benign.jsonl --output data/processed/linux-benchmark.jsonl --audit data/processed/linux-benchmark-audit.json
```

Use a Python environment with CPU PyTorch, SciPy and scikit-learn to run the fits. Use a fresh `--run-dir` for each run. To reproduce the published comparison exactly, reuse the frozen prepared traces and audit. Recapturing the workloads produces a fresh benchmark.

```powershell
$env:PYTHONPATH = 'src'
python scripts/benchmark_linux.py --data data/processed/linux-benchmark.jsonl --audit data/processed/linux-benchmark-audit.json --run-dir runs/linux-benchmark/models --output runs/linux-benchmark/benchmark.json
Copy-Item -LiteralPath runs/linux-benchmark/benchmark.json -Destination runs/linux-dashboard-inputs/benchmark.json
```

Build and launch the dashboard as described above. The comparison displays the realized calibration and test counts alongside the nominal 5% target. CRIBA and `strace` retain a common projection of successful operations, with different collectors and host environments. Reported delays start at the first retained operation. [CRIBA traces](https://github.com/dsrhaslab/criba/tree/main/traces)

### Reproduce the GRU log-rotation follow-up

Use the initial benchmark artifacts and the frozen benign follow-up recording at `data/processed/linux-gru-rotation-benign.jsonl`. To recapture the cohort, use the collector above with the following Python invocation inside the container. A new capture campaign can produce different event order and timing.

```text
python -B /scripts/capture_linux_benign.py --output /out/linux-gru-rotation-benign.jsonl --campaign gru-rotation-v2 --seed 118092 --workers 4 --per-role 5 8 8 --tune-per-workload 3 --rotation-per-role 12 12 12 --rotation-tune 8 --diverse-rotation --exclude /out/linux-benchmark-benign.jsonl --exclude /out/linux-benchmark.jsonl
```

Fit the readout and stage its comparison with CPU PyTorch. Use a fresh `--out` directory for each fit.

```powershell
$env:PYTHONPATH = 'src'
python scripts/refit_linux_gru.py --benign data/processed/linux-gru-rotation-benign.jsonl --out runs/linux-gru-refit-reproduction
Copy-Item -LiteralPath runs/linux-gru-refit-reproduction/benchmark.json -Destination runs/linux-dashboard-inputs/benchmark.json
```

The follow-up scores a fresh benign holdout and includes a separate check on the previously evaluated DarkSide and Erebus captures. [Follow-up evidence](output/research/linux-gru-log-rotation.md)

### Reproduce the contextual Linux GRU

The contextual GRU adds a learned correction based on recent task and file activity to the frozen GRU refit. The comparison uses completed Linux syscalls from Docker workloads and previously recorded CRIBA ransomware traces. The test threshold for each model is calibrated on the same separate benign cohort with a 5% per-capture alert budget.

Prepare the archived context and run the benchmark in a CPU PyTorch environment. It uses the prior comparison and refit artifacts plus the frozen benign cohorts `data/processed/linux-context-benign.jsonl` and `data/processed/linux-context-benign-v4.jsonl`. Use a fresh output directory for each fit.

```powershell
$env:PYTHONPATH = 'src'
python scripts/prepare_context_criba.py
python scripts/benchmark_linux_context.py --out runs/linux-gru-context-reproduction
python scripts/benchmark_linux_context.py --bounded --benign data/processed/linux-context-benign-v4.jsonl --additional-prior-benign data/processed/linux-context-benign.jsonl --out runs/linux-gru-context-bounded-reproduction
Copy-Item -LiteralPath runs/linux-gru-context-bounded-reproduction/benchmark.json -Destination runs/linux-dashboard-inputs/benchmark.json
```

Use the following collector invocation with the mounts from the initial comparison to record a new cohort.

```text
python -B /scripts/capture_linux_benign.py --output /out/linux-context-benign.jsonl --scratch /work --workers 4 --per-role 5 8 8 --tune-per-workload 3 --rotation-per-role 12 12 12 --rotation-tune 8 --diverse-rotation --campaign gru-context-v3 --seed 768201 --context --exclude /out/linux-benchmark-benign.jsonl --exclude /out/linux-benchmark.jsonl --exclude /out/linux-gru-rotation-benign.jsonl
```

For the second campaign, use output `/out/linux-context-benign-v4.jsonl`, campaign `gru-context-v4`, seed `1418201`, and also exclude `/out/linux-context-benign.jsonl`.

To score a live, generated benign log rotation, pipe completed events from the collector into the frozen contextual model. The scorer emits NDJSON with per-event scores and a final capture summary.

```powershell
$env:PYTHONPATH = 'src'
$benchmarkScripts = (Resolve-Path scripts).Path
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only `
    --cpus 1 --memory 128m --pids-limit 32 --tmpfs /work:rw,noexec,nosuid,nodev,size=64m `
    --mount "type=bind,source=$benchmarkScripts,target=/scripts,readonly" `
    raneval-linux-benchmark-collector python -B /scripts/capture_linux_benign.py `
    --observe 'Log rotation' --rotation-variant copy-and-truncate --seed 917226 |
    python -m raneval.observe_linux --bundle runs/linux-gru-context-bounded/gru_context.pt
```

Both runs and the live check are documented in the [contextual GRU evidence](output/research/linux-context-gru.md).

### Score each Linux task separately

The [task-history architecture](output/research/linux-process-architecture.md) describes separate recurrent and file-context state per observed actor. The comparison calibrates the maximum alarm across all tasks in each benign session. Use the frozen input cohort to reproduce the measured routing comparison with a fresh output directory.

```powershell
$env:PYTHONPATH = 'src'
python scripts/evaluate_linux_process.py --runtime --out runs/linux-process-reproduction
```

The final comparison uses the task-ID positive projection and a task-adapted GRU. Reproduce its fit and evaluation with separate output folders.

```powershell
python scripts/prepare_context_criba.py --actor-field tid --output data/processed/linux-gru-context-criba-tid.jsonl
python scripts/refit_task_gru.py --out runs/linux-task-refit-reproduction
python scripts/evaluate_linux_process.py --runtime --positive data/processed/linux-gru-context-criba-tid.jsonl --benign data/processed/linux-process-benign-v7.jsonl --adapted-bundle runs/linux-task-refit-reproduction/gru_task.pt --model-ids counts gru_refit --schedule-count 2 --out runs/linux-process-v7-reproduction
```

For a continuous harmless workload, use the collector's versioned observed-order stream and the per-task operating-point file.

```powershell
$env:PYTHONPATH = 'src'
$benchmarkScripts = (Resolve-Path scripts).Path
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges --read-only `
    --cpus 1 --memory 128m --pids-limit 32 --tmpfs /work:rw,noexec,nosuid,nodev,size=64m `
    --mount "type=bind,source=$benchmarkScripts,target=/scripts,readonly" `
    raneval-linux-benchmark-collector python -B /scripts/capture_linux_benign.py `
    --observe 'Log rotation' --rotation-variant copy-and-truncate --seed 917226 |
    python -m raneval.observe_process --bundle runs/linux-task-refit/gru_task.pt `
    --operating-point runs/linux-process-benchmark/results-v7-stream/observer.json
```

Each output identifies the scored task. Scoring continues beyond 2,048 calls, and output marks observations beyond the finite calibration horizon. The current archive comparison and this live observed-order path have distinct event-order contracts.

## EN2025 Windows-telemetry pilot

RanEval trains a defensive classifier on recorded Windows API telemetry. EN2025 supplies the labeled reports. Kaggle runs the CNN and GRU and saves their weights and calibration thresholds. Docker runs the frozen scorer and a live response gate on generated dummy files. The [execution plan](_bmad-output/initiative-streaming-ransomware/architecture-streaming-ransomware/EXECUTION-PLAN.md) defines the full research benchmark.

## Prepare EN2025

The [publisher](https://zenodo.org/records/18218588) provides CAPE logs under the MIT license. The pilot uses the benign and ransomware classes. The input consists of parsed API names, exact-identity grouping and archive labels. Family independence, modification ground truth, and cross-process timestamp semantics require further audit before the locked study.

Run from the workspace root with Python 3.11+ and `tar` with 7z support:

```text
python scripts/download_en2025.py --out data/raw/en2025 benign ransomware
python scripts/extract_en2025_reports.py --out data/pilot-reports --limit-per-class 180 data/raw/en2025/benign.7z data/raw/en2025/ransomware.7z
python scripts/prepare_en2025.py --root data/pilot-reports --glob "**/report.json" --max-observations 2048 --skip-invalid --output data/processed/en2025-pilot-clean.jsonl --audit data/processed/en2025-pilot-clean-audit.json
```

The downloader validates publisher checksums. Extraction selects regular `report.json` members by seeded member-name hash. The preparation audit accounts for every exclusion, including one report above the 256 MiB decoder limit in the selected cohort. Check the audit before submitting a training run. Use a fresh output directory or new output names for each revision. API names enter the model. Raw arguments, executable filenames and report verdicts stay local.

## Run the private GPU pilot

Use the installed Kaggle CLI with your configured account. Check `kaggle quota` and verify accelerator access before submitting. The packager creates a private, internet-disabled job containing code and compact tokenized report sequences. It requests T4, records the actual GPU and software versions, caps the job at 30 minutes, and interrupts then resumes the first model before exporting results. It writes the upload payload only under the ignored `runs/` directory. [Kaggle notebook documentation](https://www.kaggle.com/docs/notebooks)

```text
python scripts/package_kaggle_pilot.py --data data/processed/en2025-pilot-clean.jsonl --out runs/kaggle-pilot --epochs 3 --push
kaggle kernels status <owner>/<pilot-slug>
kaggle kernels output <owner>/<pilot-slug> --path runs/kaggle-pilot-outputs
```

Check `environment.json` and `pilot-complete.json` in the downloaded outputs. Each model should export `bundle.pt`, `frozen.json`, `metrics.json` and `test_alerts.jsonl`. Check the bundle hash against `frozen.json`. These are development results under this pilot's split and prefix cap. The locked benchmark adds the other-malware negative strata, independently supported groups, repeated seeds, file accounting and uncertainty estimates.

## Show the detector responding in Docker

Follow the [demo runbook](demo/README.md) to run the built-in fixture or feed the frozen scorer an API trace from the development cohort. The fixture generator uses a fixed seed to make the initial files byte-identical in both modes. The writer appends harmless markers until the gate closes. The report records score and alert timing and compares file hashes.

For a recorded trace, stage the downloaded bundle and a tuning trace with `stage_demo.py`. Its fixed hash rule chooses a trace without inspecting scores. Run once for each label and show the observed outcome, including a missed alert if it occurs. Linux file operations are the demonstration workload. The model receives recorded Windows API observations. Include the alerting write in the count and verify the subsequent denied targets retain their initial SHA-256 hashes.

With `src` on `PYTHONPATH` and CPU PyTorch installed:

```text
python scripts/stage_demo.py --data data/processed/en2025-pilot-clean.jsonl --model runs/kaggle-pilot-outputs/cnn --label RANSOMWARE --out runs/demo-ransomware
python scripts/stage_demo.py --data data/processed/en2025-pilot-clean.jsonl --model runs/kaggle-pilot-outputs/cnn --label BENIGN --out runs/demo-benign
```

The existing local CPU pilot already has two staged EN2025 traces. With Docker Desktop running, show the live score, writes, alert and gate state from PowerShell at the repository root:

```powershell
.\demo\run-live.ps1 -InputDirectory 'runs\demo-en2025-cpu-ransomware'
.\demo\run-live.ps1 -InputDirectory 'runs\demo-en2025-cpu-benign'
```

The Kaggle checkpoint is staged locally for the original two traces and an illustrative alert example. Both original 120-observation windows completed without an alert. The illustrative tuning trace was selected for an early alert using the frozen CNN and threshold. It verifies that the write gate closes when the model alerts. [Pilot and demo evidence](output/research/en2025-pilot-evidence.md)

```powershell
.\demo\run-live.ps1 -InputDirectory 'runs\demo-cnn-alert-example'
.\demo\run-live.ps1 -InputDirectory 'runs\demo-benign'
```

Build `raneval-model-demo` first if the image is missing. The [demo README](demo/README.md) has the build command.
