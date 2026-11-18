---
type: initiative
title: Damage-aware evaluation of streaming ransomware detectors
parent: none
---

# Historical initiative requirements

Active scope changed on 2026-11-17. [XRan-only requirements](initiative-xran-original.md) and the [new architecture](architecture-xran-original/architecture-xran-original.md) now control new work. The requirements and companions below describe earlier completed or deferred experiments.

- R1: Deliver an end-to-end architecture and execution plan that repairs the supplied guide's measurement, causal replay, fairness, and statistical gaps.
- R2: Preserve a focused research question comparing observed modification burden and trace-fraction earliness under a fixed nominal trace-level false-alarm budget.
- R3: Make raw-data feasibility a gate, document defensible fallback branches, and prevent unverified damage or prevention claims.
- R4: Specify module ownership, schemas, train/tune/calibration/test separation, benchmark models, tests, reproducibility, compute, milestones and completion criteria.
- R5: Use XRan as a documented baseline inspiration, not a claimed exact reproduction. Keep source PDFs unchanged.
- R6: Train the API detector on an EN2025 development cohort in a private Kaggle GPU job and verify retrieval of the frozen bundle. The locked benchmark depends on validated data and measurement.
- R7: Demonstrate the frozen detector and a write gate in Docker on generated dummy files. Drive inference with recorded Windows API calls and compare monitor-only and enforcement runs.

# Companions

- [Execution plan](architecture-streaming-ransomware/EXECUTION-PLAN.md)
- [Architecture](architecture-streaming-ransomware/architecture-streaming-ransomware.md)
- [Contracts and protocol](architecture-streaming-ransomware/CONTRACTS.md)
- [Kaggle and Docker runbook](../../README.md)
- [Prior audit](../../output/research/plan-audit.md)
