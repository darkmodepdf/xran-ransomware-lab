# Linux GRU file and process context

## Method

The GRU sees the existing seven successful file-operation tokens. The context variant adds a learned correction to the frozen refit logit using ten features of the current Linux task within the last 32 retained events. Features cover repeated changes to a file, changes after a read, file and directory spread, task activity, and successful write return sizes. Opaque capture-local identities preserve equality. The GRU and context reset after 256 events, and scoring covers at most 2,048 events per capture. [Feature implementation](../../src/raneval/context.py) · [Protocol](../../_bmad-output/initiative-streaming-ransomware/plan-context-gru.md)

The benign side records actual kernel calls with `strace` in a Debian Docker container on WSL2. The workloads are log rotation, backup, archive compression, bytecode builds, and SQLite updates. Each campaign reserves 32 training, 20 tuning, 44 calibration, and 44 fresh test captures, with 12 log rotations in calibration and test. The named regression contains three archived DarkSide and two Erebus recordings, all previously evaluated. Training ransomware comes from nine earlier CRIBA captures spread over AvosLocker, REvil, and RansomEXX. The restored positive operations, timestamps, and successful-operation totals match the previous projection. [strace manual](https://man7.org/linux/man-pages/man1/strace.1.html) · [CRIBA source](https://github.com/dsrhaslab/criba) · [Positive holdout audit](linux-gru-positive-holdout-audit.md)

Each frozen model receives its own threshold from the same 44 benign calibration captures, with at most two alerts under the nominal 5% target. Early detection means an alert by the 120th retained operation. A trace counts once in the alarm rate. The paired rotation comparison uses the same benign runs for both models.

## Initial contextual model

| Measure | GRU refit | GRU with context |
|---|---:|---:|
| Calibration false alarms | 1 / 44 | 0 / 44 |
| Fresh benign false alarms | 1 / 44 | 3 / 44 |
| Fresh log-rotation false alarms | 1 / 12 | 0 / 12 |
| Previously evaluated ransomware alerted by event 120 | 5 / 5 | 2 / 5 |
| DarkSide median first alert | Event 24 | No alerts |
| Erebus median first alert | Event 31 | Event 107 |

The context model removed one rotation alarm and added three alarms on other benign workloads. The rotation change represents one discordant pair. The candidate failed early-detection preservation. [Results](../../runs/linux-gru-context/benchmark.json) · [Context alerts](../../runs/linux-gru-context/gru_context-alerts.json) · [Refit alerts](../../runs/linux-gru-context/gru_refit-alerts.json)

The initial context bundle also scored a separate copy-and-truncate log rotation through the live collector pipeline. It scored 2,048 completed operations with no alert and a maximum score of 0.937 against its threshold of 0.957. [Recorded probe](../../runs/linux-gru-context/observed-benign.jsonl)

## Bounded context on a second fresh holdout

The second model caps the contextual adjustment at a 0.25 reduction in logit. The model was selected using development data and the same five named regression traces. A separate v4 campaign supplied 44 calibration and 44 holdout captures with zero overlapping capped sequences across the two campaigns or prior benchmarks. The original token GRU is included for comparison with earlier work.

| Measure | Original GRU | GRU refit | GRU with bounded context |
|---|---:|---:|---:|
| Calibration false alarms | 2 / 44 | 1 / 44 | 1 / 44 |
| Fresh benign false alarms | 3 / 44 | 0 / 44 | 0 / 44 |
| Fresh log-rotation false alarms | 3 / 12 | 0 / 12 | 0 / 12 |
| Previously evaluated ransomware alerted by event 120 | 2 / 5 | 5 / 5 | 5 / 5 |
| DarkSide median first alert | No alerts | Event 24 | Event 24 |
| Erebus median first alert | Event 108 | Event 31 | Event 31 |

The bounded GRU preserved every refit alert position in the named regression and tied the refit on the fresh holdout. Removing both file and directory IDs in a diagnostic also preserved the bounded outcomes after recalibration. This holdout therefore gives no evidence of an incremental detection benefit from file context. The contextual model remains experimental. All five model thresholds and every holdout and regression alert were recomputed from the frozen bundles. For both contextual versions, batch and streaming produced identical first-alert positions on all 49 held-out or regression traces. The bounded score difference was at most 1.50 × 10⁻⁶. [Selection receipt](../../runs/linux-gru-context-bounded/selection.json) · [Results](../../runs/linux-gru-context-bounded/benchmark.json) · [Audit](../../runs/linux-gru-context-bounded/audit.json)

The Docker [comparison tab](http://127.0.0.1:8765/#comparison) shows the second trial and the bounded model’s independent live check. It scored 2,048 completed log-rotation calls with no alert, reaching 0.9132 against its threshold of 0.9148. The detection replay was verified separately at event 26 with 358 later dummy writes blocked and all 358 protected files matching their original SHA-256. [Bounded live check](../../runs/linux-gru-context-bounded/observed-benign.jsonl)

## Limits

Authentic benign programs and ransomware issue the same Linux syscalls. A trace records their behavior. The model scores the sequence and the scope of changes. It cannot determine intent from one call, establish that bytes were encrypted, or count file damage from this benchmark. The benign set is repeated local controlled workloads, and the positive and benign recordings differ in collector and host environment. In the initial campaign, file/directory context was present on 92.0% of benign test events and 65.1% of the ransomware regression events. Indirect differences in context coverage can contribute to a model score. A shared-collector split with independent ransomware is needed for an external validation claim.
