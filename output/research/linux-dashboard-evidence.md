# Linux dashboard pilot evidence

## Cohort and Kaggle training

The pinned ebpfangel capture audit retained 855 process traces. Thirteen ransomware traces from REvil and IceFire entered training, one Monti trace entered tuning, two clean captures contributed 252 calibration traces, and four AvosLocker captures contributed positive test traces. The audit records 18 unresolved publisher PIDs and 17 resolved positives without a family attribution. Duplicate sequences across roles were removed from the earlier roles. [Cohort audit](../../data/processed/ebpfangel-linux-audit.json) · [Publisher paper](https://ebpfangel.philippart.me/Ransomware_Detection_using_Machine_Learning_with_eBPF.pdf)

A private, internet-disabled Kaggle run trained the CNN and GRU sequentially on one Tesla T4. The environment exposed two T4s with 14.56 GiB each, four CPU cores, Python 3.13.16, PyTorch 2.11.0 and CUDA 13.0. The CNN stopped and resumed at optimizer step 2. Both fits completed five epochs and 435 steps. The driver recorded 63.9 seconds after startup. The model and recovery checkpoint hashes matched the downloaded manifests. [Kaggle notebook](https://www.kaggle.com/code/vishwasbollam/raneval-linux-ebpf-pilot-1117030534) · [Saved pilot manifest](../../runs/kaggle-linux-pilot-outputs/pilot-complete.json)

| Model | Ransomware alerted by event 120 | First alert on each positive | Benign alerts |
| --- | ---: | ---: | ---: |
| CNN | 4 / 4 | 35 | 6 / 405 |
| GRU | 4 / 4 | 55 | 6 / 405 |

At the nominal 5% calibration point, each model alerted on 12 of 252 calibration processes. All six benign test alerts per model were in one of five test captures. The four positive test traces came from one family and share their first 120 events. These counts describe this development pilot. CPU PyTorch exactly reproduced all 409 saved GPU test alert positions for each model at the primary threshold. The dashboard CNN was selected by tuning recall by event 120, with tuning earliness as the tiebreaker. [Verified model results](../../runs/linux-dashboard-inputs/verification.json)

### Event-count baseline diagnostic

On 2026-11-17, the existing CPU logistic regression was fitted on the same frozen cohort with the same 256-event blocks, 2,048-event horizon and early endpoint weighting. Its separately calibrated nominal 5% threshold triggered 10 of 252 calibration traces. It alerted at event 17 on all four positive test traces and on 13 of 405 benign process traces across three of five test captures. The CNN alerted later on those positives and produced six benign alerts in one capture. The count model missed event 120 on the single positive tuning trace at its tuning threshold. This was a retrospective diagnostic on the existing split. A new family- and host-held-out evaluation can test the trade-off across independent captures. [Baseline implementation](../../src/raneval/train.py#L100)

## Docker replay

The container used Debian Bookworm slim with CPU ONNX Runtime, a read-only root, unprivileged UID 10001, one CPU, a 384 MiB memory cap and ephemeral dummy-file storage. Docker image inspect reported 110,348,694 bytes. Docker image list reported 476 MB for the new image and 1.43 GB for the existing Torch demo.

The fixed 384-event ransomware fixture comes from Monti tuning telemetry. The benign fixture comes from a held-out clean capture. CPU PyTorch and ONNX Runtime agreed on both alert positions. The maximum absolute score difference across both fixtures and the reset check was 1.29 × 10⁻⁷. The frozen CNN threshold was 0.9882745555918545. [Fixture manifest](../../runs/linux-dashboard-inputs/manifest.json)

| Recorded trace | Input pacing | Achieved events/s | First alert | Monitor-only files modified | Gated files modified | Writes blocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Monti | 100 events/s | 92.2 | 26 | 384 | 26 | 358 |
| Monti | Unpaced | 3,860 | 26 | 384 | 26 | 358 |
| Benign control | 100 events/s | 92.2 | None | 384 | 384 | 0 |

Each lane attempted the same scheduled marker writes. At 100 events/s configured, the alert arrived after 266 ms in this run. SHA-256 checks confirmed that all 358 blocked targets retained their starting contents. The unpaced result measures this local demo and its generated workload. [Replay timings and file hashes](../../runs/linux-dashboard-replay-evidence.json) · [Browser screenshot](../../runs/linux-dashboard-result.png)
