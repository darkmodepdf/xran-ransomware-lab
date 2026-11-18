# Frozen experiment records

These compact records preserve the evidence behind the documentation. They are not raw training datasets. JSON bytes are kept unchanged by Git attributes so recorded SHA-256 values remain meaningful across Windows/Linux clones.

| Directory | Evidence |
|---|---|
| `native-v2` | Final230-campaign manifest, pre-test model freeze, collection summary, test/calibration metrics, timing, independent and actual Docker/HTTP verification |
| `native-v1` | Initial132-campaign experiment, its preserved misses, pre-test freeze and HTTP diagnostic results |
| `xran-endpoint` | Completed Kaggle campaign's protocol/selection marker and independently verified endpoint evaluation |
| `dashboard` | Verified648-event browser comparison and UI checks |
| `en2025-streaming` | Compact360-report audit metadata whose bytes match the historical model's recorded audit hash; no raw API records |

Final native-v2 test:24/24 destructive campaigns detected;2/32 benign campaigns falsely flagged. These are controlled fixtures with shared worker templates, not a production ransomware benchmark. The v1 failure analysis informed v2 development; v1 test is not an untouched holdout for v2. See [results](../RESULTS.md) and [reproduction](../REPRODUCIBILITY.md).

Compressed raw event records and machine-specific live state remain in ignored `runs/`. Consequently a clone can inspect frozen metrics and generate a fresh deterministic-seed campaign, but cannot replay absent original raw records byte-for-byte. Native repetition uses fresh owned files and the saved manifest policy; collection timing/PIDs will differ. Historical EN2025/Linux/Kaggle experiments require the documented upstream datasets or their original external run outputs.

`checksums.json` inside each native directory covers its copied evidence files. It does not cover itself. Model registry hashes are separate in [`models/manifest.json`](../../models/manifest.json).
