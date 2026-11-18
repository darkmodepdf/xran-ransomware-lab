# Research map and historical context

The project evolved through several separate datasets, collectors and model families. A newer track does not retroactively improve an older track's metrics. Dates and limitations in original reports remain part of the record.

| Track | Primary records | Code/demo |
|---|---|---|
| Current native Windows forest | [Native training results](../output/research/windows-native-training-results.md), [dashboard redesign](../output/research/windows-dashboard-redesign.md), [current results](RESULTS.md) | [Native trainer](../scripts/train_windows_native.py), [runtime](../src/raneval/windows_native.py), [dashboard runbook](../demo/windows_streaming/README.md) |
| Historical Windows streaming baseline | [EN2025 audit](../output/research/en2025-streaming-audit.md), [evaluation](../output/research/windows-streaming-evaluation.md), [miss analysis](../output/research/windows-streaming-miss-analysis.md), [verification](../output/research/windows-streaming-verification.md) | [Trainer](../scripts/train_windows_stream.py), [frozen baseline](../demo/windows_streaming/model.json) |
| Original XRan processed features | [Reading notes](../output/research/XRan-reading-notes.md), [source audit](../output/research/xran-original-source-audit.md), [content audit](../output/research/xran-original-data-audit.md), [design review](../output/research/xran-dataset-design-review.md) | [Inspector](../scripts/inspect_xran_original.py), [preparation](../scripts/prepare_xran.py), [training](../src/raneval/train_xran.py), [evaluation](../scripts/evaluate_xran.py) |
| Early EN2025 CNN/GRU pilot | [Pilot evidence](../output/research/en2025-pilot-evidence.md) | [Pilot packaging](../scripts/package_kaggle_pilot.py), [original demo](../demo/README.md) |
| Linux replay and benchmark | [Dashboard evidence](../output/research/linux-dashboard-evidence.md), [fresh benchmark](../output/research/fresh-linux-benchmark.md), [independent audit](../output/research/linux-independent-audit.md) | [Linux dashboard](../demo/linux_dashboard/), [benchmark](../scripts/benchmark_linux.py) |
| Linux contextual/task GRU follow-ups | [Log rotation](../output/research/linux-gru-log-rotation.md), [context GRU](../output/research/linux-context-gru.md), [process architecture](../output/research/linux-process-architecture.md), [mixed test](../output/research/linux-gru-mixed-test.md) | [Context benchmark](../scripts/benchmark_linux_context.py), [task evaluation](../scripts/evaluate_linux_process.py) |

The [preserved root README](../README.legacy.md) retains older acquisition, Kaggle, Linux capture/export and replay recipes in their original location so relative source links resolve. It includes statements about then-planned work and local checkpoints; it is historical context, not current release status. Some linked local PDFs and generated inputs are deliberately excluded from source publication.

[_bmad-output](../_bmad-output/) retains planning and design decisions. [Architecture for original XRan](../_bmad-output/initiative-streaming-ransomware/architecture-xran-original/architecture-xran-original.md) and [Linux design](../_bmad-output/initiative-streaming-ransomware/architecture-linux-demo/architecture-linux-demo.md) describe those tracks. Plans are not execution evidence; read result reports and compact [experiment receipts](experiments/) for observed outcomes.

Current open validation work: broader legitimate application coverage, independent collectors, equivalent trustworthy measurements outside cooperating workers, independently sourced destructive behaviors, and retained false-positive regressions. Nothing in the current native result supplies missing original XRan weights, a missing other-malware cohort, ransomware-family independence or production containment.

## Portable XRan endpoint results

Three selected project-trained endpoint bundles (counts, CNN and GRU) are included under [models](../models/README.md), with the [model manifest](../models/manifest.json). Candidate/stability runs and raw training datasets remain separate. Original author weights are not claimed.

The read-only XRan dashboard can display the bundled real evaluation without data acquisition or training:

```powershell
.\.venv\Scripts\python.exe demo/xran_dashboard/server.py --report docs/experiments/xran-endpoint/evaluation.json --port 8766
```

Open [the local endpoint dashboard](http://127.0.0.1:8766/). This serves saved endpoint metrics; it is separate from native workers on port 8767 and does not provide sample classification.
