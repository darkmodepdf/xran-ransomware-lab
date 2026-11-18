# XRan evaluation dashboard

A portable, read-only dashboard for actual `xran-endpoint-evaluation-v1` exports. It runs natively on Windows with Python 3.11 or later and has no third-party runtime dependencies. It does not train models, modify evidence, or load historical Linux results. Docker deployment is deferred.

From the project root:

```powershell
python demo/xran_dashboard/server.py --report runs/xran-original/evaluation.json --port 8766
```

Open http://127.0.0.1:8766/. The default report path is resolved against the project root, so the default also works when launched from a different directory. A missing report is a supported state: the page stays available, but metrics do not appear. Write completed exports atomically, then use **Reload export**. There is no background training or automatic polling.

For an already submitted Kaggle run, the separate completion worker can watch the run and prepare the report:

```powershell
.venv-raneval/Scripts/python.exe scripts/finish_xran_kaggle.py --kernel OWNER/SLUG --data-dir data/processed/xran-original --out runs/xran-original --timeout-minutes 150
Get-Content runs/xran-original/completion-status.json
```

The worker polls every 30 seconds, downloads to `kaggle-output`, requires exactly one campaign marker, runs the local evaluator in `verified-evaluation`, checks its verification receipt and artifact hashes, then atomically copies its valid report to `evaluation.json`. It never submits a new job. Use the project Python environment for evaluation and keep the authenticated Kaggle CLI on PATH. The Kaggle CLI reads the latest session for a slug: do not repush that slug while the worker watches it.

`completion-status.json` is the durable machine-readable status; `completion-worker.log` records transitions. Status, download, and evaluation command output are retained in separate `.log` files. A restarted worker uses the same original deadline and resumes the completed-download/evaluation stage; a completed run verifies saved artifacts without a network request or refit. One OS lock prevents concurrent workers in the same output directory. `--once` checks once, and still downloads/evaluates if the kernel is already complete. It is intended for manual inspection or tests, not repeated scheduling. A pending `--once` returns zero; inspect `phase` and `kernel_status` rather than treating exit zero alone as completion.

The page uses the existing historical dashboard's light surface, green accent, type, and spacing vocabulary without modifying that dashboard. Comparison metrics lead; a selected-model matrix and frozen operating point provide detail; source and quality evidence explain the limits. Native controls, visible keyboard focus, tabular numbers, text-only evidence rendering, and contained table scrolling support keyboard and mobile use.

## HTTP boundary

| Request | Behavior |
| --- | --- |
| `GET /api/xran/evaluation` | Validated, unchanged report; HTTP 503 `{code,message}` if missing, unreadable, incomplete, or invalid. |
| `GET /api/xran/metadata` | Dataset meaning, feature lengths, model allowlist, export readiness, runtime, and fixed limitations. |
| `GET /api/health` or `/health` | HTTP 200 for a running server; `evaluation_available` distinguishes export readiness. |
| Mutating requests | HTTP 405. No sample classification implementation is connected yet. |

The static server exposes only its three known assets. It binds to loopback by default, disables caching, and sends a content security policy. JSON rejects duplicate keys and nonfinite values; exports are bounded to 16 MiB. An invalid replacement never falls back to a stale report.

## Evaluation report contract

The exporter owns evidence. The dashboard does not fill metrics from paper values or from other experiments. Required fields:

- `schema`: `xran-endpoint-evaluation-v1`.
- `dataset`: object; recommended fields `name`, `platform`, `raw_rows`, `unique_groups`, `cohort_groups`, `test_groups`, `sources` (array of `{name, count, ...}`), and `data_quality`. Additional provenance/exclusion/split fields are displayed as evidence.
- `nominal_fpr_budget`: finite number in `[0,1]`, normally `0.05`.
- `models`: nonempty list of completed primary model evaluations. Each has a unique nonempty `id` (`counts`, `cnn`, `gru`), human-readable `label`, integer `seed` (primary `17`), optional `status="evaluated"`, and the fields below.
- `limitations`: optional string array; displayed alongside the dashboard's fixed dataset limitations.
- `generated_at`: recommended ISO timestamp; no creation time is invented if absent.
- `diagnostics`: optional object or array for seed stability, API-only/missingness ablations, overlap, and sensitivity results. Displayed separately from primary comparisons.

Each primary model:

- `metrics`: `accuracy`, `precision`, `recall`, `f1`, `specificity`, `fpr`, `fnr`, `balanced_accuracy`, `mcc`, `roc_auc`, `average_precision`. Values are finite numbers in `[0,1]`, except MCC in `[-1,1]`. Undefined values are `null`, rendered as **Unavailable**. Reasons may be in model-level or metrics-level `undefined_reasons` keyed by metric name.
- `confusion`: nonnegative integer `tp`, `fn`, `tn`, `fp`. Ransomware is positive. All primary models must have the same nonempty test-group count, matching `dataset.test_groups` when present.
- `calibration`: object with `{target_rate,n,allowed,alerts,actual_fpr,threshold,alarm_enabled}`. The target must equal the report budget, `n` must be positive, `allowed=floor(target_rate*n)`, `alerts<=allowed`, and `actual_fpr=alerts/n`. Threshold is finite in `[0,1]` when enabled; disabled alarms require `threshold=null` and zero alerts. `threshold` and `alarm_enabled` can also be supplied at model level and must agree.
- `source_metrics`: optional array of `{source,groups,confusion,metrics,undefined_reasons?}`. Single-class source rates may be null. Each provided `groups` must match its confusion matrix. Source groups may overlap across sources.
- Optional `class_report`, `intervals`, `provenance`, `bundle_sha256`, `runtime_sha256` are shown as model evidence. `class_report` and `intervals` may also be nested under `metrics`.

The dashboard validates presentation-critical shape and ranges. This does not replace the evaluator's checks of split independence, arithmetic, provenance hashes, paired comparisons, calibration reproduction, or frozen-backend parity. A matching test count alone does not prove cohort identity.

## Validation

```powershell
python -m unittest discover -s tests -p test_xran_dashboard.py -v
node --check demo/xran_dashboard/static/app.js
```

Test fixtures are synthetic and used only inside temporary test directories. They are never stored as an experiment report or presented as measured model results.

Verified 2026-11-17: seven HTTP integration tests passed, and JavaScript syntax checking passed. Browser inspection covered the no-export state, an explicitly labeled synthetic two-model fixture, model selection updating confusion counts, null source metrics, and replacing a valid export with malformed JSON. The latter hides the previous metrics. Layout widths were 1440 and 390 pixels with no page overflow. The desktop axe-core audit reported 47 passes, zero violations, and zero incomplete checks. Mobile reported zero violations and one incomplete contrast check for cells outside the horizontally scrolled table viewport; the same cells passed when visible on desktop. Screenshots are under `tmp/xran-dashboard-*.png`. The temporary browser and server were stopped after verification. This verifies dashboard behavior, not trained-model accuracy or inference parity.
