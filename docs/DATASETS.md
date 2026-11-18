# Datasets, provenance and rights

The default native demo needs no downloaded reports, malware samples or external dataset. Raw inputs, archives, generated streams and private credentials stay outside the published source. A source checkout includes runtime models and compact evidence, not the author's complete local research environment.

| Track | Source and acquisition | Scope and rights boundary |
|---|---|---|
| Native Windows fixtures | Generated locally by [agent.py](../demo/windows_streaming/agent.py) and [campaign trainer](../scripts/train_windows_native.py) | Harmless owned JSONL/checksummed generated binary fixtures; shared templates, not real malware families |
| Original XRan processed release | [Pinned author-associated release](https://github.com/sibelgulmez/XRan/tree/2cfebbfe45d3ed47b0204096186877e5991d6324), inspected by [inspect_xran_original.py](../scripts/inspect_xran_original.py) | Four compressed API/DLL/mutex CSV cohorts; no explicit release license was found in the saved audit. Public access does not grant redistribution permission. |
| EN2025 | [Zenodo record 18218588](https://zenodo.org/records/18218588); [download helper](../scripts/download_en2025.py), [extractor](../scripts/extract_en2025_reports.py) | Saved audit records MIT for publisher reports; retain upstream notices and verify record terms. No executable malware is needed for report processing. |
| ebpfangel Linux | [Upstream repository](https://github.com/TomasPhilippart/ebpfangel); [preparation helper](../scripts/prepare_ebpfangel.py) pins source objects and LICENSE | Saved preparation metadata records MIT; retain the exact upstream notice for material acquired. |
| CRIBA Linux | [Trace source](https://github.com/dsrhaslab/criba/tree/main/traces); [preparation helper](../scripts/prepare_linux_benchmark.py) pins revision | Recorded trace evidence; check upstream terms and provenance before redistribution. No blanket dataset license is assigned here. |
| Generated Linux benign cohorts | [capture_linux_benign.py](../scripts/capture_linux_benign.py) | Controlled Docker workloads; recapture changes timing/order and does not recreate archived ransomware captures. |

## Original XRan is separate from native streaming

The inspected processed release contains 30,171 rows with 500 API, 10 DLL and 10 mutex positions. Counts and duplicate/conflicting vectors require the [content audit](../output/research/xran-original-data-audit.md); the downloaded SOREL count differs from the paper. Group exact duplicate/conflicting representations before splits. The release lacks the paper's VX Heaven other-malware cohort, raw Cuckoo reports, published split manifests and original trained weights.

These are Windows endpoint features, even when fitting/inference runs in Linux. They do not establish native Linux telemetry, per-operation byte damage, process-level causal attribution or live detection latency. Local XRan training code is a project implementation; do not label it original author code/weights. [Source access audit](../output/research/xran-original-source-audit.md).

## EN2025 audit boundary

The historical streaming audit processed 360 development reports (180 per class), 5,944,179 source calls and 1,649,745 projected file/lifecycle events. This is a subset of the publisher's corpus. Completed-byte counts are not reliably available; handle ambiguity, pending calls and unknown destinations constrain attribution. Capture class labels do not label every process/prefix as malicious. [Audit](../output/research/en2025-streaming-audit.md), [event contract](../demo/windows_streaming/EVENTS.md).

Acquire explicitly, for example with the Research environment:

```powershell
python scripts/download_en2025.py --out data/raw/en2025 benign ransomware
python scripts/extract_en2025_reports.py --out data/pilot-reports --limit-per-class 180 data/raw/en2025/benign.7z data/raw/en2025/ransomware.7z
```

Review source notices and audits before using subsequent preparation/training scripts. The native quickstart does not call these commands.

## Redistribution

Third-party PDFs, archives, raw reports and upstream sample collections are not granted a new license by this repository. Do not commit downloaded papers, datasets, Kaggle credentials or payloads. Citation/access statements in historical notes do not override provider agreements. See [NOTICE](../NOTICE). Saved provenance supports understanding experiments; it is not legal authorization to redistribute upstream content.
