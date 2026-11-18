# Fresh Linux ransomware benchmark

Completed 2026-11-17. [Model comparison dashboard](http://127.0.0.1:8765/#comparison) · [Machine-readable report](../../runs/linux-benchmark/benchmark.json) · [Dashboard screenshot](../../runs/linux-benchmark/comparison-dashboard.png)

## Cohort and protocol

The 25 training captures include nine published CRIBA captures from AvosLocker, RansomEXX and REvil, and 16 locally recorded benign captures. The positive holdout contains three DarkSide and two Erebus captures. The benign holdout has eight captures each of tree backup, archive compression, Python bytecode builds, SQLite updates and log rotation. Each captured run is one alert unit. [CRIBA trace artifacts](https://github.com/dsrhaslab/criba/tree/b5e006ae9628e3a5361697adb9e6bb3086862660/traces) · [Cohort audit](../../data/processed/linux-benchmark-audit.json)

The corpus uses the first 2,048 successful operations from a shared seven-category projection in completion order. Paths and timestamps are outside the feature input. The scorer resets its context every 256 events. The benchmark fits all three architectures locally on CPU using fixed settings. Each threshold uses the maximum score per separate benign calibration capture and a nominal 5% target. Floor rounding permits one of 33 calibration captures to alert. [Training manifest](../../runs/linux-benchmark/models/manifest.json)

Exact cross-role sequence deduplication removed 11 log rotation captures. It left one log rotation calibration capture and none in training. The eight log rotation test captures contain two distinct capped sequences. The 40 benign test captures contain 34 distinct capped sequences. The five ransomware holdouts contain four distinct first-120-event prefixes. No exact capped sequence crosses statistical roles.

## Results

| Model | Calibration false alarms | Detected by event 120 | Detected within horizon | Median first alert among detections | Benign test false alarms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Event count | 1 / 33 | 0 / 5 | 1 / 5 | 256 | 0 / 40 |
| CNN | 0 / 33 | 3 / 5 | 3 / 5 | 29 | 0 / 40 |
| GRU | 1 / 33 | 5 / 5 | 5 / 5 | 28 | 9 / 40 |

The CNN caught all three DarkSide runs at event 29 and missed both Erebus runs. The GRU caught DarkSide at event 28 and Erebus at event 101. Its test false alarms were 8 of 8 log rotations and 1 of 8 Python builds. The GRU's realized test false-alarm rate was 22.5%. The CNN used zero calibration alarms because the boundary scores tied.

CRIBA SysTracer and local `strace` recordings come from different collectors and execution environments. The labels are coupled to those sources. Benign captures repeat workloads on one local environment, and ransomware captures repeat two published test families. The elapsed times start with the first retained successful operation. The benchmark supports comparison on these recordings. Host-level false-alarm rates, whole-execution latency and file damage need separate measurements.

## Verification

Verified the publisher archive hashes and a byte-identical cohort rebuild. Independently rescored all 33 calibration and 45 test captures from each of the three saved bundles. All thresholds, alert positions and aggregate counts matched the report. The live Docker endpoint served the verified JSON, browser checks covered desktop, mobile and keyboard navigation, and the original replay still produced event 26 and 358 hash-verified blocked marker writes. [Report](../../runs/linux-benchmark/benchmark.json)
