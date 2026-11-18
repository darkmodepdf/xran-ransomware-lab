# Linux GRU mixed-case benchmark

## Dataset and selection

The positive cases are five genuine Linux ransomware recordings from CRIBA. Three are DarkSide and two are Erebus. CRIBA preserves completed kernel file calls, return values, and the task and file context needed by the frozen models. The five recordings were used in earlier model evaluation and selection. They are regression cases. [CRIBA dataset](https://github.com/dsrhaslab/criba)

The negative cases are 100 fresh Debian Docker runs captured with `strace` on one WSL2 kernel. They contain 24 log rotations and 19 each of tree backup, archive compression, Python bytecode builds, and SQLite updates. Every rotation variant appears eight times. The workloads operated on generated files and issued genuine kernel calls. The collector found no exact sequence overlap with the five prior benchmark inputs. It captured ten additional reserved runs that never entered scoring. [Collector metadata](../../data/processed/linux-mixed-benign-v5.meta.json)

CRIBA was selected for schema compatibility and verified provenance. The reviewed ELFEN reports lacked usable return values for reads, writes, renames and unlinks. The GuardFS traces recorded attempted operations before completion. The Multi-Log publisher lists ransomware and benign captures, but its archive contents and compatibility remain unverified. A published IoT trace index cross-matches four REvil and one RansomEXX recording with ELFEN family labels. Both families appeared in training, and the corresponding records' completion-time compatibility and sample independence remain unverified. No fresh ransomware recording with the required semantics was verified for this run. [Source audit](linux-gru-positive-holdout-audit.md) · [Multi-Log dataset](https://www.multi-log.com/dataset/) · [IoT trace index](https://zenodo.org/records/24216931)

## Test design

The GRU refit cutoff was 0.932335303109786 and the bounded context cutoff was 0.9147550881836888, each frozen from the nominal 5% benign calibration. This run reused the weights, operation vocabulary, 256-event state resets, and 2,048-event maximum horizon. A case was predicted positive if any retained score reached its cutoff. AUC and average precision use the maximum score for each case. Average precision summarizes the precision–recall curve without linear interpolation. Scores are used for ranking.

- **Separate captures in mixed order.** Insert the five archived positives at roughly even intervals among the 100 benign cases. Start new model state at every capture boundary.
- **Same-stream stress test.** Use 128 real benign operations for warm-up, then alternate operations from two real recordings in one model stream while preserving each recording’s event order. Five positive streams inject one archived case into one benign background. The 47 controls combine two clean recordings each. Each fresh recording contributes to at most one mixed stream, leaving one unused. Task, file, and directory IDs are namespaced by recording so they cannot collide. This constructed schedule has no shared wall-clock timeline. The two tests reuse source recordings and their metrics must be read individually.

## Confusion counts and classification metrics

| Setting and model | True negatives | False positives | False negatives | True positives |
|---|---:|---:|---:|---:|
| Separate captures, either GRU | 98 | 2 | 0 | 5 |
| Same-stream, GRU refit | 35 | 12 | 4 | 1 |
| Same-stream, bounded context | 34 | 13 | 4 | 1 |

| Metric | Separate captures, either GRU | Same-stream refit | Same-stream bounded context |
|---|---:|---:|---:|
| Accuracy | 98.10% | 69.23% | 67.31% |
| Balanced accuracy | 99.00% | 47.23% | 46.17% |
| Ransomware precision (PPV) | 71.43% | 7.69% | 7.14% |
| Ransomware recall (sensitivity) | 100.00% | 20.00% | 20.00% |
| Ransomware F1 | 83.33% | 11.11% | 10.53% |
| Benign precision (NPV) | 100.00% | 89.74% | 89.47% |
| Benign recall (specificity) | 98.00% | 74.47% | 72.34% |
| Benign F1 | 98.99% | 81.40% | 80.00% |
| False-positive rate | 2.00% | 25.53% | 27.66% |
| False-negative rate | 0.00% | 80.00% | 80.00% |
| Macro precision | 85.71% | 48.72% | 48.31% |
| Macro recall | 99.00% | 47.23% | 46.17% |
| Macro F1 | 91.16% | 46.25% | 45.26% |
| Weighted precision | 98.64% | 81.85% | 81.56% |
| Weighted recall | 98.10% | 69.23% | 67.31% |
| Weighted F1 | 98.24% | 74.64% | 73.32% |
| Matthews correlation | 0.837 | −0.038 | −0.051 |
| Cohen’s kappa | 0.824 | −0.032 | −0.042 |
| ROC-AUC | 1.000 | 0.494 | 0.506 |
| Average precision | 1.000 | 0.183 | 0.185 |
| Exact 95% interval for recall | 47.82–100.00% | 0.51–71.64% | 0.51–71.64% |
| Exact 95% interval for false-positive rate | 0.24–7.04% | 13.94–40.35% | 15.62–42.64% |

The intervals are descriptive under an independent-binomial assumption. Repeated workload types, one benign Linux environment, five reused positive captures from two families, and class-correlated collection tools limit inference. Precision and accuracy depend on the class balance in each constructed cohort.

## Early alerts and errors

- **Separate captures.** Both GRUs alerted on all three DarkSide cases at event 24 and both Erebus cases at event 31. Median elapsed time from first recorded completion was 6.67 ms. Both false alarms came from log rotation, 2 of 24. The other 76 benign runs produced no alerts.
- **Same-stream stress test.** Both models detected the same Erebus case at its 47th retained ransomware operation and missed all three DarkSide recordings and the other Erebus case. The first alerts were at mixed-stream events 222 and 221 for refit and context respectively. There were zero alerts before the first ransomware operation in positive streams. Twelve refit and thirteen bounded-context controls alerted even though both inputs were benign.

The test supports scoring the known captures individually. Sharing recurrent state across concurrent task streams was unreliable under the tested schedule. These results measure classification on recorded operations. They cannot establish how the models perform on a new ransomware family, on a new host, or how many file modifications would be prevented.

An independent audit verified the frozen bundle hashes, capture provenance, threshold decisions, ranked metrics and same-stream pairings. Stream and batch scoring agreed on all 24 sampled first-alert positions.

[Full per-case results and metrics](../../runs/linux-gru-mixed/metrics.json) · [Evaluation script](../../scripts/evaluate_linux_mixed.py)

To re-score the frozen inputs from the project root, use the existing CPU PyTorch environment with SciPy and scikit-learn.

```powershell
$env:PYTHONPATH = 'src'
python scripts/evaluate_linux_mixed.py --output runs/linux-gru-mixed/metrics-reproduction.json
```
