# Technology, references and clarity review

Reviewed 2026-11-16: EXECUTION-PLAN.md, CONTRACTS.md, architecture-streaming-ransomware.md. Read-only review of main documents; reviewed the source-verification evidence already supplied by the parent rather than repeating a broad literature search.

Verdict: no blocking unsupported technology/version or deployment claim found. The documents correctly distinguish documentation reference versions from a tested compatible installation, leave Kaggle limits explicitly unverified, require an environment lock/smoke test, and avoid claiming model training, data validation or novelty has already happened. The single-package offline architecture fits the stated team and workload better than a service platform.

## Actionable findings

1. **Medium — prefix training contract is not directly implementable for scikit-learn LogisticRegression.** EXECUTION-PLAN section 5 says the same endpoints are used across models, but then specifies 16 endpoints per trace *per epoch*. Neural models can resample by epoch; LogisticRegression fits a fixed feature matrix and does not share that epoch API. Two builders could give LR only one endpoint set and neural models many distinct sets. Freeze one endpoint set per trace/training seed for v1 (all models consume it; neural epochs revisit it), or specify a common finite union/weighted schedule that every model consumes. Log the exact training-prefix manifest.

2. **Medium — score-domain and no-alert serialization need one explicit representation.** CONTRACTS defines finite scores and a minimum score-domain boundary but model examples say one logit and the interface only says score. State whether replay persists logits or sigmoid scores, and encode no-alert threshold as a tagged sentinel rather than non-standard JSON infinity. This prevents model/calibrator mismatch without requiring probability-calibration claims.

3. **Low — architecture frontmatter sources are labels rather than resolvable paths.** `sources: [initiative-streaming-ransomware.md, plan-audit.md, XRan-reading-notes.md]` points to files not in the spine's directory. Use `../initiative-streaming-ransomware.md`, `../../../output/research/plan-audit.md`, and `../../../output/research/XRan-reading-notes.md`, or explicitly declare these human labels. Working Markdown companion links elsewhere are correct.

4. **Low — exact API-only feature scaling can be pinned early.** The LR entry says train-fitted scaling but not whether count features are raw, normalized, log-transformed or standardized. Leave implementation flexibility only if this is a tuning choice in the protocol; otherwise choose a concrete train-fitted sparse-safe transform. This affects baseline interpretability and prevents a hidden tuning dimension.

## Evidence boundaries retained correctly

- Published EN2025 counts/storage are attributed to the publisher, not asserted as audited working counts.
- Current CAPE documentation is not assumed to describe the dataset's actual producer version.
- Runtime dependencies are not upgraded just to match documentation versions.
- Kaggle capacity/session/quota gates precede long runs; checkpoint recovery and durable retrieval are separate checks.
- Literature leads are explicitly pending full novelty review.
- The 8-10 week schedule is an effort estimate, conditional on feasibility.
- No executable malware collection, production response or prevention claim is included in this plan.
