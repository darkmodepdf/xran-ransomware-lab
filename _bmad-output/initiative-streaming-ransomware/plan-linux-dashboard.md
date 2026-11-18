---
status: done
route: full
risk: medium
date: 2026-11-17
---

# Linux dashboard implementation plan

**Goal.** Show a trained Linux ransomware detector alerting during recorded-event replay and verify that the alert blocks later dummy-file writes in a lightweight Docker container.

**Architecture.** Use grouped ebpfangel process traces for training and evaluation. Run the existing causal CNN and GRU in a private Kaggle T4 job. Export the tuning-selected network to ONNX, then replay selected traces and verify the result from a loopback dashboard.

**Spec.** [Linux demo architecture](architecture-linux-demo/architecture-linux-demo.md).

## Code map and checks

- [x] `scripts/prepare_ebpfangel.py` reads source-pinned CSVs and maps only verified PIDs. The audit accounts for unresolved labels and keeps captures, families, and exact duplicates from crossing roles.
- [x] `scripts/package_kaggle_pilot.py` adds a Linux profile. The CNN and GRU trained with early-prefix weighting and benign calibration. Downloaded weights, recovery checkpoints, held-out alert counts and model selection verified.
- [x] `scripts/stage_linux_demo.py` verifies bundle identity and exports a dynamic ONNX block endpoint. PyTorch and ONNX agreed on both staged alert outcomes. The fixed tuning trace and benign control carry source provenance, hashes, and parity evidence.
- [x] `demo/linux_dashboard/` serves the trained replay from a Python slim container. Paced and unpaced Monti replays preserved every blocked-write target by SHA-256. The benign control passed in Docker and the browser. Image size, timing, and hashes are recorded in the [evidence report](../../output/research/linux-dashboard-evidence.md).

## Review focus

Labels or capture metadata used as features, cross-split trace reuse, changing calibration after seeing test output, a mismatch between the two scoring implementations, and file claims beyond the disposable marker workload.
