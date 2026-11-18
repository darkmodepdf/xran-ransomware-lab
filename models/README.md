# Model artifacts

The deployed live detector is [`demo/windows_streaming/native-model.json`](../demo/windows_streaming/native-model.json): a32-tree native behavior forest,26 features and128 events per process. Its payload hash is recorded in [`manifest.json`](manifest.json). No training dependency is needed for its inference. The historical native-v1 JSON and EN2025 linear comparator are also in that demo directory.

This directory additionally contains the three selected, project-trained **XRan endpoint classifiers** from the completed Kaggle campaign:

| Bundle | Meaning | Weight size |
|---|---|---:|
| `xran-endpoint/counts` | Count-logistic endpoint baseline | 37,285 bytes |
| `xran-endpoint/cnn` | Selected endpoint CNN | 4,538,761 bytes |
| `xran-endpoint/gru` | Selected endpoint GRU | 2,376,465 bytes |

Each includes `bundle.json`, `vocabulary.json`, `weights.pt` and the independently calibrated `operating-point.json`. [`manifest.json`](manifest.json) records exact paths, hashes, sizes, source candidate and seed. Files were copied byte-for-byte from the verified campaign. Tensor weights are the only three explicit exceptions to the repository's generated-weight ignore rule.

These endpoint models consume520 categorical feature positions (500API,10DLL,10mutex), **not native file events**. They are preserved research models and do not drive live streaming alerts. The three-model endpoint evaluation is in [`docs/experiments/xran-endpoint/evaluation.json`](../docs/experiments/xran-endpoint/evaluation.json). Do not compare its accuracy with native campaign recall as though they measured the same task.

Verify all shipped bytes with the standard library:

```powershell
uv run --locked python scripts/verify_models.py
```

To additionally instantiate and smoke-score the three endpoint models on CPU:

```powershell
uv run --locked --extra research python scripts/verify_models.py --load-endpoint
```

The latter uses safe tensor-only checkpoint loading (`weights_only=True`). Its synthetic input verifies loading/inference, not detection quality. Endpoint evaluation requires separately prepared dataset splits; see [research workflows](../docs/RESEARCH.md).

Raw datasets, every tuning candidate, optimizer/checkpoint state, stability runs and raw per-sample predictions remain outside Git. Acquisition and training code is included. Third-party source datasets retain their own terms; these bundled project-trained weights do not convey redistribution rights for those datasets.
