# Plan audit - 2026-11-16

Scope: all six pages of the supplied 'Project Guide (Tightened Parts 1–2) Damage-Aware Evaluation of Streaming Ransomware Detectors.pdf'. Parts 3 onward and the original checklist were not supplied. This is a methodological audit, not an executed data audit or exhaustive novelty review. Source PDFs unchanged.

Verdict: promising research question; proceed to data feasibility and measurement validation before model training. Publication readiness is not established.

## Strengths

Outcome-focused comparison; trace-level rather than prefix-level false alarms; validation-only thresholds; retention of undetected ransomware; family holdouts; willingness to report negative results; explanation treated as optional.

## Required changes

1. **Damage validity (2.4, 2.6):** API names alone identify modification attempts, not destroyed user files. Require successful return status, process-scoped handle lifetime resolution, path normalization and rename identity tracking, victim-file eligibility, and distinction between existing files and newly created notes/temp files. Audit representative reports manually. Without content evidence, call the metric an observed file-modification proxy, not files ruined.
2. **Alert boundary (2.4):** score after event t implies event t already occurred. Count qualifying modifications through t inclusive. Distinguish entry/return logging and same-timestamp ordering. Separate zero-latency replay from realizable alert time with processing/backlog delays.
3. **Causal inputs (2.2):** reconstruct DLLs/mutexes only from events available at each prefix; full-report summaries can leak future behavior. Fix process/thread ordering, horizon, context window, repeated-event semantics, prefix training distribution, and sampling weights. A causal mask alone does not settle these. Train vocabulary on training data only.
4. **Baseline fairness (1.5, 2.2):** same splits are insufficient if feature access differs. Compare all architectures with API-only inputs; report a separately labeled XRan-style multi-view adaptation if timestamped DLL/mutex data exist. Contrast full-trace-trained and prefix-trained CNNs. This is not exact XRan reproduction or direct numerical comparability with XRan's original dataset.
5. **Low-FPR calibration (2.4):** specify distinct fitting/tuning/calibration data, candidate thresholds, ties, consecutive-alert k, and evaluation horizon. Same validation FPR budget does not ensure identical test FPR. Report achieved test FPR with intervals. With 100 benign calibration traces, FPR steps are 1%; zero errors has a one-sided 95% binomial upper bound about 2.95%, illustrating why 0.5% calibration is weak with small sets.
6. **Task definition (2.3-2.5):** a single ransomware score defines binary ransomware versus non-ransomware classification, not three-class predictions. Keep BENIGN and OTHER_MALWARE as separate negative evaluation strata; three-class macro-F1 needs an explicit three-class head and decision rule.
7. **Undetected/censored cases (2.4):** terminal observed damage is the full recorded burden, not true worst-case future damage. A short or inactive missed trace can score zero. Define success within damage budget b as alert observed AND damage at alert <= b, denominator all eligible ransomware traces. Misses must remain failures in this curve. Separately report terminal burden, observation horizon, never-caught rate, and inactive/truncated strata.
8. **RQ2/statistics (1.4, 2.5):** define trace-fraction metric, aggregation, ties and miss handling before results. Use paired model differences on the same traces and uncertainty clustered by family when appropriate. Seed SD alone is not a significance test. With only 3-4 model rankings, rank correlations are coarse. A rank reversal demonstrates different evaluation objectives, not by itself that the other metric is invalid.
9. **Data feasibility (2.3, 2.6):** EN2025 published counts total 3,260, not 3,180; document exclusions. Verify raw-report schema, family labels, timestamp quality, file identities, compression semantics, usable sample counts and damage distributions. Do not treat absence of family labels as permission to call clusters families. Switching to trace fraction if damage is unusable changes the central question.
10. **Scope (2.1, 2.7):** move Transformer to should-have; first validate measurement with count baseline, CNN, GRU. API-name-to-stage mapping is ambiguous; attribution sums are not automatically stage probabilities or a risk timeline. Log edits do not prove function preservation, and delay edits are irrelevant to models without timing inputs. Keep these stretch items out of the core claim.

## External checks

- [EN2025 publisher record](https://zenodo.org/records/18218588): 919 benign, 733 ransomware, 816 RAT, 792 spyware; 77.9 GB expanded, 2.6 GB archives. These are published counts, not independently audited usable reports.
- [EarlyMalDetect full text](https://arxiv.org/html/2407.13355v1): GPT-2 sequence prediction plus an attention-based recurrent detector; should not be described simply as the same causal Transformer classifier proposed here. Full novelty comparison remains outstanding.
- [Rhode, Burnap and Wedgbury, 2021](https://orca.cardiff.ac.uk/id/eprint/145509/8/8933681.pdf): real-time behavioral detection/process killing with measured file-corruption outcomes. Relevant prior art beyond the plan's two named leads. Its existence does not establish duplication of the exact proposed ranking experiment.
- [Nayak et al. 2026](https://arxiv.org/abs/2604.17522): located; full methodological comparison not completed.

## Suggested next milestone

Produce a report parser and measurement audit, a dataset inclusion/exclusion manifest, a concrete split/calibration plan, and a small hand-checked set of event-to-file-to-damage timelines. Freeze the measurement protocol only after this feasibility work, before detector-result inspection. Then train a minimal baseline set. No implementation or dataset download was performed in this audit.
