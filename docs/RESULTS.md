# Results and limitations

## Shipped native forest, experiment v2

These are saved research results dated 2026-11-18, not a claim that a new checkout has already passed its tests.

| Test outcome | Count |
|---|---:|
| Destructive campaigns detected / missed | 24 / 0 |
| Benign campaigns falsely alerted / not alerted | 2 / 30 |
| Destructive detection proportion | 24/24 (100%) |
| Benign false-alert proportion | 2/32 (6.25%) |

The manifest partitions 230 whole campaigns into 84 train, 42 tune, 48 benign calibration and 56 test campaigns. IDs/seeds are unique across roles; complete actor histories remain together. All seven operation variants occur in training; the structured-content profile is test-only. Templates and fixture grammars are shared, so this is not malware-family or broad application independence.

The exported model has 26 features, 32 trees, a 128-event horizon and cutoff `0.742904033012732`. Selection uses tune only; final cutoff is immediately above the largest benign calibration session maximum. Inference fields were frozen before test. Zero alerts on 48 calibration campaigns did not imply zero future false alerts.

Retained false positives: `test-benign-append-mixed-0` (first alert event 31; peak about 0.757898) and `test-benign-rotate-mixed-0` (event 208; peak about 0.746313). Truncate/full overwrite/partial overwrite each contribute 8/8 detections. Median onset-qualified delay is zero events, range 0–8. Zero delay means scoring **after the first damaging operation completes**, not prevention. Destructive warmup produced no early alerts.

The saved Docker/HTTP integration check processed 902 events with zero score discrepancy across two concurrent pairs. The original destructive worker alerted after one fixture was invalid; delayed overwrite after two. Genuine save states can transiently invalidate files without alerting. Validity is not an alarm rule.

Canonical payload SHA-256: `01b3497ca418991033fba338b301b5b823cf6ccedddecc81b82f9f9915a0e3cc` (distinct from file-byte digest). Manifest SHA-256: `cdb2a5524bd9422663c718cf03686f982816dec18b416c485c82ee68d6e5ef6a`. [Detailed evidence](../output/research/windows-native-training-results.md); [compact receipts](experiments/).

## Keep comparisons with their cohort

The frozen EN2025 linear baseline detects 1/27 ransomware captures and falsely alerts on 0/27 benign captures in its historical development test (AUROC 0.88066; threshold 0.8979676155). On the native v2 same-cohort test, that baseline detects 0/24 destructive campaigns with 0/32 benign false alerts. CAPE lacks required enriched measurements; native forest recall on historical CAPE cannot be inferred by imputing missing values.

Native experiment v1 detected 12/18 destructive campaigns with 0/24 benign false alerts and missed all six sparse cases. Those observations informed v2 and remain diagnostic evidence. Original XRan and Linux use other cohorts and representations. [Track history](RESEARCH.md).

## Practical limits

The lab uses cooperating workers on generated owned files. It does not observe arbitrary Windows applications, execute real malware, establish ransomware intent, stop corruption, restore data, or estimate a production false-alarm rate. Equivalent benign/destructive histories can remain indistinguishable. Detection may follow damage. Native and CAPE collectors differ; a real collector requires equivalent trustworthy measurements and independent validation.

Source/family independence and near-duplicate control have historical limits documented per report. Recapture can change event timing/order. New fits must report their own counts and preserve errors. Broader legitimate applications, independent collectors and independently sourced behaviors remain research priorities.
