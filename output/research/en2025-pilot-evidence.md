# EN2025 pilot and Docker demonstration evidence

2026-11-16. The [runbook](../../README.md) reproduces the preparation, training, and demonstration. The [EN2025 publisher](https://zenodo.org/records/18218588) supplies the CAPE report archives used here.

## Corpus

Publisher checksums matched both archives. Seeded selection retained 180 regular report members per class from 919 benign and 733 ransomware reports. The [preparation audit](../../data/processed/en2025-pilot-clean-audit.json) accounts for 357 included traces, two exact duplicates, and one report larger than 256 MiB. Sequences are capped at 2,048 observations and grouped by exact identity. Included trace data SHA-256 is `331b84141773b98cf9dc2b3223395084b61d1659d2e1f4da38fe836c00b92b36`.

| Class | Train | Tune | Calibrate | Pilot test |
|---|---:|---:|---:|---:|
| Benign | 72 | 18 | 45 | 45 |
| Ransomware | 106 | 36 | 0 | 35 |

This binary development cohort excludes the other-malware strata. Multi-process clock interpretation and family independence remain unverified. File-modification counts in the demo refer to its own generated files. The EN2025 corpus has yet to pass the research measurement gates for real file outcomes.

## Local training and response demonstration

The CPU CNN ran three epochs with seed 123, 256-observation reset blocks and a 2,048-observation cap. At its nominal 5% calibration budget, it alerted on 23 of 35 ransomware pilot test traces and 2 of 45 benign pilot test traces. The [metrics file](../../runs/cpu-pilot-cnn/metrics.json) includes the threshold and exploratory setting. These are limited development results from one seed and one grouped split. An interrupted CPU run resumed from optimizer step two and matched the uninterrupted run's weights, thresholds and test alert rows exactly.

The two Docker fixtures were selected from the tuning partition by a fixed hash rule that did not read scores. Each used the first 120 API observations. The frozen model gave the same first-alert result as offline CPU replay in both cases.

| Recorded input | Alert observation | Monitor-only files modified | Enforced files modified | Writes blocked |
|---|---:|---:|---:|---:|
| Ransomware trace | 41 | 120 | 41 | 79 |
| Benign trace | None | 120 | 120 | 0 |

The positive fixture's 79 blocked files retained their original SHA-256 hashes. The maximum absolute live/offline score difference across the two runs was below `7e-8`. The container was unprivileged, had no network, used a read-only root filesystem, and wrote fixture data only into ephemeral storage. The trace is recorded Windows telemetry and the writes are benign marker appends. [Ransomware-trace demo result](../../runs/en2025-cpu-ransomware-demo.json) · [Benign control result](../../runs/en2025-cpu-benign-demo.json)

## Completed GPU job, verified 2026-11-17

Both the Kaggle CUDA preflight and private EN2025 pilot completed. The runtime exposed two Tesla T4s, with one GPU used per fit. The CNN and GRU each finished three epochs and 267 optimizer steps. The CNN stopped at step two and resumed on Kaggle. The downloaded model and recovery checkpoint hashes match their manifests, and both run identities match the submitted training source and cohort hash. [Kaggle pilot](https://www.kaggle.com/code/vishwasbollam/raneval-en2025-pilot-1116182249) · [GPU environment](../../runs/kaggle-pilot-outputs/environment.json) · [Execution log](../../runs/kaggle-pilot-outputs/raneval-en2025-pilot-1116182249.log)

| Model | Nominal calibration budget | Ransomware pilot test alerts | Benign pilot test alerts |
|---|---:|---:|---:|
| CNN | 5% | 18/35 (51.4%) | 1/45 (2.2%) |
| GRU | 5% | 25/35 (71.4%) | 5/45 (11.1%) |
| CNN | 1% | 12/35 (34.3%) | 0/45 (0.0%) |
| GRU | 1% | 8/35 (22.9%) | 1/45 (2.2%) |

At the 5% nominal setting, both models triggered on 2/45 Kaggle calibration traces. CPU replay reproduced all 80 test first-alert positions per model at both thresholds. On the calibration set, the 5% GRU threshold triggered on 3/45 traces on the CPU runtime, one more than on Kaggle. Calibration counts belong to the scoring environment where they were measured. The pilot uses one seed and a 357-trace development cohort. The GRU's higher test recall at the 5% nominal setting came with a higher achieved false-alarm rate. [CNN metrics](../../runs/kaggle-pilot-outputs/cnn/metrics.json) · [GRU metrics](../../runs/kaggle-pilot-outputs/gru/metrics.json)

## Docker replay of the Kaggle checkpoints

Neither Kaggle model alerted during the fixed first 120 observations of the originally selected ransomware trace or the benign control. Over the ransomware trace's full 2,048 retained observations, the CNN first alerted at 269 and the GRU at 146 on CPU replay. Both blind Docker runs therefore allowed all 120 dummy writes. [CNN ransomware fixture](../../runs/en2025-gpu-ransomware-demo.json) · [CNN benign control](../../runs/en2025-gpu-benign-demo.json) · [GRU ransomware fixture](../../runs/en2025-gpu-gru-ransomware-demo.json) · [GRU benign control](../../runs/en2025-gpu-gru-benign-demo.json)

To show the gate closing with the GPU-trained CNN, a separate illustrative example was selected from the tuning set. Fourteen of 36 eligible ransomware tuning traces had a crossing before the last of their first 120 observations. The example was the lowest `demo-v1` hash among those traces. It alerted at observation 12 using the original frozen threshold. Monitor-only modified 120 dummy files and enforcement modified 12. All 108 denied files retained their starting SHA-256 values. Docker's first alert matched offline replay, and the maximum absolute score difference was below `4e-8`. This outcome-selected case illustrates the response path. The fixed fixtures and pilot test metrics supply the observations before illustrative selection. [Selection details](../../runs/demo-cnn-alert-example/selection.json) · [Paired demo results](../../runs/en2025-gpu-cnn-alert-example-demo.json)
