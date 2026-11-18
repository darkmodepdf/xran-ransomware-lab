---
status: done
route: full
date: 2026-11-17
---

# Fresh Linux model comparison

Compare the count model, causal CNN and GRU on the same first 2,048 retained operations per recorded run. Use the existing training implementation, a 256-event reset, fixed fit settings and the 120-event early-alert endpoint. Freeze separate thresholds for each architecture under a shared nominal 5% false-alarm budget on benign calibration captures. Count one alarm per capture and report achieved calibration and test counts, misses, event positions, and available recorded time separately.

- [x] Prepare checksummed CRIBA run telemetry. Fit on AvosLocker, REvil and RansomEXX. Reserve all complete DarkSide and Erebus captures for test. Record family, capture provenance, event ordering and any source errors. Use one trace per capture. The inputs contain recorded calls only.
- [x] Record independent invocations of five busy benign workloads inside a disposable Linux container. Include tree copy, archive compression, SQLite writes, Python bytecode builds and log rotation. Split seeds into train, benign calibration and test before scoring. Use only completed successful operations projected to the same seven token categories used for CRIBA. Record tracing and container provenance. Acknowledge the source/collector and host differences and benign repeats on one local environment.
- [x] Run three fixed CPU fits in `scripts/benchmark_linux.py`. Check capture and family separation, input identity, calibration limits, full test coverage and deterministic model/result evidence. Export JSON with aggregate metrics, per-family detection and per-workload false alarms.
- [x] Serve the result alongside the existing replay in `demo/linux_dashboard`. Confirm old bundles and replay require no benchmark file, and verify the actual model comparison in Docker and the browser with the new result. Document the run commands and [evidence](../../output/research/fresh-linux-benchmark.md).
