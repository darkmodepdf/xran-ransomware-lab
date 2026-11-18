# Windows streaming detector: miss investigation

Date: 2026-11-18. Scope: frozen streaming baseline, not the original 520-feature endpoint XRan classifiers. No production model, cutoff, or service was changed during this investigation.

## Conclusion

Two distinct problems explain the result. The zero-observed-false-alarm calibration policy puts the cutoff just above a common score shared by benign and ransomware captures. More fundamentally, the learned linear model rewards unresolved handles and failed calls while assigning very low scores to successful operations on attributed files. The controlled destructive worker uses the latter operations. Separate process histories work, but the representation and learned decision function do not distinguish its destructive behavior.

Replayed all 360 development captures and 1,649,745 projected events and reproduced TP=1, FN=26, FP=0, TN=27. Ran genuine and destructive native workers concurrently against the same frozen inference implementation. Verified the deployed model file stayed unchanged.

## 1. What is actually being evaluated

The streaming detector is a 22-feature logistic baseline over each actor's last 128 events. It is not the earlier endpoint CNN. Features are operation/outcome/target-kind proportions, target equality counts, unordered read/write target overlap, and window occupancy. It has no ordered sequence encoder, byte offsets, file size changes, overwrite coverage, append distinction, or content-change measurements.

Training uses weak capture labels and a hard maximum over sampled actor windows: a ransomware capture needs only one high-scoring window, from any actor. Selection uses tuning AUROC. The deployed cutoff is the next floating-point value above the maximum of 28 benign calibration session maxima. Calibration ransomware captures do not determine that cutoff. Capture-level detection is not evidence that the destructive actor was detected at the destructive operation.

Sources: `src/raneval/windows_stream.py`, `scripts/train_windows_stream.py` and the frozen `demo/windows_streaming/{model,evaluation,split}.json`.

## 2. The cutoff explains many recorded misses, but cannot solve the native case

| Policy | Cutoff | Calibration benign alerts | Test ransomware detected | Test benign alerts |
|---|---:|---:|---:|---:|
| Frozen deployed policy | 0.8979676155142287 | 0/28 | 1/27 | 0/27 |
| Offline diagnostic: allow at most floor(5% * 28) calibration alerts | 0.46567501851549253 | 1/28 | 20/27 | 1/27 |
| Offline diagnostic: fixed 0.5 | 0.5 | 1/28 | 18/27 | 1/27 |

The diagnostic 5% policy is calculated from benign calibration scores, not by searching test recall. Its observed test result is nevertheless a post-hoc diagnostic, not a validated replacement or a future false-alarm guarantee. No diagnostic cutoff was deployed.

The highest benign calibration score is 0.8979676155142285, produced by the first projected event of an actor: a successful duplication with an unresolved target. Fifteen of the 27 ransomware test captures have exactly the same maximum, also at their first actor event with that signature. All fifteen fall just below the cutoff. There is no information in these identical scores with which to separate the two labels. Discarding the benign example merely to increase recall is unjustified.

Only one test positive exceeds the cutoff. Its peak is 0.9171636510 at a first-event failed close with an unresolved target. That maximizing window contains no successful known-file mutation. Thus the one reported true positive does not validate detection of corruption.

Threshold tuning must remain separate from fitting and final evaluation; see the [official scikit-learn threshold guide](https://scikit-learn.org/stable/modules/classification_threshold.html).

## 3. The learned shortcuts are visible in the weights and peak windows

Selected weights below are contributions to the logit per unit feature, not probabilities:

| Feature | Weight |
|---|---:|
| Failed-call fraction | +2.54194 |
| Unknown-target fraction | +2.24986 |
| Duplicate-call fraction | +1.09179 |
| Write-call fraction | +0.94135 |
| Attributed-file-candidate fraction | -0.92883 |
| Full-window occupancy | -0.79154 |
| Resize-call fraction | -0.00000291 |

An unresolved duplicated or closed handle may refer to a general object, not a file. Missing attribution is not proof of ransomware. Nevertheless, these features dominate this fitted model. Correctly recorded truncation contributes essentially nothing.

Of the 27 ransomware test peaks, 24 windows contain no successful attributed-file write/resize/delete/rename record; 17 peak at the first actor event. Peak operations are duplicate (18), close (6), open (3). In training, 94/99 ransomware maxima likewise contain no such mutation and 67/99 peak at the first actor event. These observations support a shortcut-learning explanation for the hard-max weak-label objective; they do not establish the actual malicious actor or onset in the source captures.

## 4. Concurrent native workers: a stronger failure than the cutoff

| Worker | Events | Peak model score | Final invalid fixtures | Model alert |
|---|---:|---:|---:|---|
| Genuine | 288 | 0.125998 | 0/6 | No |
| Destructive | 360 | 0.120702 | 6/6 | No |

Both ran actual synchronous Windows file operations in separate processes. Genuine cycles are open/read/write/close. Destructive cycles add resize/truncate. All recorded operations succeed and have attributed file-candidate targets. Fixture integrity checks provide independent ground truth; they are not model inputs. Owned temporary fixture directories were removed after completion.

The genuine worker's peak exceeds the destructive worker's peak. No cutoff on these session maxima can flag the destructive worker while keeping this genuine worker quiet.

There is also a mathematical bound, stronger than this example. Under all-successful, all-file-candidate events, operation proportions sum to one and the other normalized features are at most one. For the frozen weights, a generous upper bound is:

```
z <= bias + weight(file_candidate) + max(operation weights)
     + sum(positive weights of equality/occupancy features)
score <= sigmoid(z) = 0.32861007086889676
```

This relaxes joint feature constraints, so the achievable maximum can be lower. It is below both the deployed 0.898 cutoff and the diagnostic 0.466 cutoff. Therefore this model cannot alert on any stream satisfying those assumptions, even with more calls. Background traffic in other processes cannot fix that: routing correctly keeps it out of the worker's history.

## 5. The seven misses remaining under the diagnostic 5% policy

| Sample SHA prefix | Peak | Projected file/lifecycle events | Successful attributed candidate mutation records |
|---|---:|---:|---:|
| d32c6aac | 0.36773 | 21,762 | 211 writes |
| b43853b0 | 0.18836 | 399 | 8 writes |
| 54d1845b | 0.21813 | 14,328 | 452 writes |
| d0dd0f | 0.46568 | 24 | 0 |
| e133 | 0.18037 | 208 | 0 |
| 7ccd | 0.34099 | 186 | 0 |
| acf361 | 0.37476 | 50 | 0 |

These are event-record counts, not completed bytes, encrypted files, or proven corruption. Four full captures lack any successful attributed candidate mutation of the counted kinds. They require an observability investigation, not silent exclusion or relabeling. The other three demonstrate failure even when writes are observed. Full identifiers and counts are in the case artifact below.

## 6. Recommended implementation sequence

1. **Measure file semantics before increasing model size.** Extend native telemetry with actual offsets, sizes before/after, bytes completed when available, append versus overwrite, truncation amount, and per-file ordered transitions. Aggregate overwrite coverage, distinct changed files, directory spread, and short/long histories per process. Preserve unknown values explicitly. Reaudit EN2025 raw fields before claiming historical support: reliable completed-byte counts are unavailable in the current audit, and the projection does not expose these richer measurements. Never synthesize absent historical measurements as ground truth.

2. **Build representative controlled native campaigns.** Include harmless fixture overwrites, truncation, copy-and-replace, delayed onset and varied pacing/file counts, alongside real benign saves, copying, log rotation/truncation and compaction-like workloads. Include benign warm-up in the same PID as subsequent destructive operations, as well as separate concurrent processes. Vary filenames, fixture sizes, payloads and execution patterns. Scenario labels, fixed invalid markers, fixture validity checks and job names must remain outside inference. Split entire campaigns and related templates before producing windows; hold out variants. Use the independent integrity oracle to measure actual damage and timing, not to trigger alerts.

3. **Replace the shortcut-prone training setup and compare models.** Ablate generic unresolved-handle/failure signals and audit their source dependence. Train with broad benign-prefix coverage and controlled onset labels where available; avoid labeling every historical ransomware prefix or child malicious. Compare richer-feature nonlinear baselines with a small causal sequence model. For weak historical labels, evaluate smoother/top-k pooling rather than relying solely on a hard maximum. Model capacity alone cannot recover missing file semantics. Keep common-feature EN2025 evaluation and enriched native evaluation separate; explicitly measure the collector/domain gap instead of merging incompatible fields.

4. **Select for the deployment objective.** Select using actor/onset-qualified recall at a declared false-alarm budget, rather than overall capture AUROC alone. Calibrate on separate representative benign traffic including concurrency and long sessions, using the exact shipped inference implementation. The 28-session calibration cohort is too small to establish reliable operational false-alarm rates. Do not lower the threshold until the demo worker lights up.

5. **Require fresh evidence before shipping.** Keep this frozen detector as the regression baseline. Since these 27 test positives have now been inspected, use fresh held-out captures/campaigns for final claims, grouping related samples and collector/template variants. Report destructive-actor recall, false alerts per host-hour/session, delay from destructive onset, files changed before alert, unattributed-event coverage, and CPU/memory. A valid model may still miss a scenario; report that outcome. Distinguishing intent is impossible when benign and destructive activities have identical observed representations, so acceptance requires discriminating measured behavior, not forced alerts.

The recommended next milestone is telemetry enrichment plus the controlled native campaign dataset, followed by a model comparison and independent calibration. Merely changing the cutoff would improve this retrospective capture metric without solving the user's live detection goal.

## Reproduction and evidence

From the repository root, use a new output directory (the script refuses to overwrite an existing one):

```powershell
.\.venv-raneval\Scripts\python.exe scripts/diagnose_windows_stream.py --native --out runs/windows-streaming-diagnostics-repeat
```

- Diagnostic CLI: `scripts/diagnose_windows_stream.py`.
- All capture peak windows/features/contributions: `runs/windows-streaming-diagnostics-20261118/capture-peaks.json`.
- Threshold counterfactuals, native replay, bound and unchanged hashes: `runs/windows-streaming-diagnostics-20261118/diagnostics.json`.
- Supplemental full-capture mutation inspection of all 27 test positives: `runs/windows-streaming-diagnostics-20261118/ransomware-test-cases.json` (separate analysis artifact, not emitted by the CLI).
- Verification assertions: `runs/windows-streaming-diagnostics-20261118/verification.json`.

Frozen model payload SHA-256: `99bb4a5580b12b10cae17230a3311a253f5bd5ebbec8453800e5231c2abd2191`.
