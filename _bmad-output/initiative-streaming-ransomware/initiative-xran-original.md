---
type: initiative
title: Rebuild around the original XRan dataset
parent: none
created: 2026-11-17
---

# Requirements

- X1: Use only the base paper's dataset. The supplied base paper is XRan (Gulmez et al., 2024). This supersedes using EN2025, CRIBA, ebpfangel or newly generated benign workloads for the active experiment.
- X2: Start with downloading, verifying and analyzing actual available data, then let its fields and quality determine the architecture.
- X3: Plan a reproducible comparison of count, CNN and GRU with independent tuning, benign calibration and test roles. Preserve the user's nominal 5% false-alarm target and report actual measured results.
- X4: Deliver a simple dashboard demo in a lightweight Linux image. State clearly when the underlying observations describe Windows programs.
- X5: Explain supported findings and limitations simply. Do not claim early detection or prevention where the acquired dataset cannot measure them.
- X6: Keep Kaggle training in the plan with verified access, resource, recovery and export gates. Assess any raw dataset the user provides before extending the classification experiment to live behavior.

# Deliverables

- [Downloaded data audit](../../output/research/xran-original-data-audit.md)
- [Source verification](../../output/research/xran-original-source-audit.md)
- [Architecture](architecture-xran-original/architecture-xran-original.md)
- [Data and inference contracts](architecture-xran-original/CONTRACTS.md)
- [Execution plan](architecture-xran-original/EXECUTION-PLAN.md)

The earlier Linux demo remains available as historical work. Its data, metrics and model artifacts are not part of this XRan-only evaluation.
