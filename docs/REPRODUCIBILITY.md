# Reproducibility

## Choose the dependency profile

```powershell
./setup.ps1 -Profile Demo      # dashboard + cooperating native workers
./setup.ps1 -Profile Native    # adds native forest fitting dependencies
./setup.ps1 -Profile Research  # adds historical research dependencies
```

Use the versioned [project metadata](../pyproject.toml) and [uv lockfile](../uv.lock) as the dependency authority. Do not rely on the author's existing `.venv-raneval`. The runtime uses the standard library. Native adds NumPy/SciPy/scikit-learn for fitting and ijson for CAPE projection tests; Research adds Torch and includes Native dependencies. ONNX tooling belongs to optional export. Kaggle is optional and requires your own configured account.

When uv is installed, equivalent explicit environment synchronization uses:

```powershell
uv sync --locked
uv sync --locked --extra native
uv sync --locked --extra research
```

These synchronize profiles; they do not collect datasets or run training. Refer to setup output for the environment used by helpers.

## Fresh native experiment

Run on Windows with the Native profile. The helper creates `runs/native-reproduction-<time>-<id>` and a separate model. `-Out <new-directory>` selects another fresh directory; existing output is refused:

```powershell
./helpers/reproduce-native.ps1
```

The underlying experiment-v2 command is:

```powershell
$env:PYTHONPATH = 'src'
# Use the Python selected by setup and a NEW output directory.
python scripts/train_windows_native.py all --experiment v2 --out runs/native-repeat --bundle runs/native-repeat/native-model.json
```

Use `.\.venv\Scripts\python.exe` in place of bare `python` unless the setup environment is activated. The `all` action freezes the campaign manifest, collects harmless worker records, fits/selects on development roles, calibrates on benign calibration campaigns, freezes inference and evaluates the held-out role. Do not pass the shipped model path as the output bundle. No deployment step follows automatically.

Whole campaign histories stay together. V2 uses 84 train, 42 tune, 48 calibration and 56 test campaigns. Shared templates limit independence. New timing/order may change measurements and results; compare manifests, versions, inference hashes and retained errors instead of promising byte-identical collection.

## Replay saved records

The repository bundles model/evidence receipts, not raw native streams or all generated runs. If you have a local preserved experiment directory with `manifest.json` and its compressed measured records, replay without fitting:

```powershell
python scripts/train_windows_native.py evaluate --experiment v2 --out runs/windows-native-campaigns-v2-20261118 --bundle demo/windows_streaming/native-model.json
```

This checks saved outcomes when the prior evaluation exists and writes `evaluation-replay.json`. It cannot run from compact metric receipts alone. Fresh collection uses `all` above. [Saved outcomes](RESULTS.md), [detailed evidence](../output/research/windows-native-training-results.md).

## Verification

```powershell
./test.ps1 -Suite Windows
./test.ps1 -Suite All
uv run --locked python scripts/verify_models.py
node --check demo/windows_streaming/static/app.js
docker build -f demo/windows_streaming/Dockerfile -t windows-stream-lab .
```

Windows tests cover actual worker measurements/cleanup in addition to parsing, actor isolation, models, HTTP and UI state. Full tests require Research dependencies. Linux test execution skips Windows-only native execution and does not substitute for Windows verification. CI does not download research datasets or submit Kaggle jobs. Read observed CI/local receipts before claiming a checkout is verified.

`verify_models.py` checks the shipped native bundles and selected endpoint artifact hashes against the registry. To additionally load and smoke-score all three endpoint models with Research dependencies, use `uv run --locked --extra research python scripts/verify_models.py --load-endpoint`.

The saved 2026-11-18 native report records 101 passing tests at that revision, numerical export parity, interleaving parity and a separate actual HTTP check. Later repository checks can have a different count. HTTP verification uses an isolated service with no competing agent and local credentials; do not run a second supervisor against the active demo casually.

## Historical reproduction

[README.legacy.md](../README.legacy.md) preserves prior Linux/EN2025 commands, expected input paths and Kaggle workflow. These paths often reference ignored local datasets/checkpoints. Acquire source data under its terms, use fresh output names and verify audit/hash receipts before training. Historical commands are research recipes, not requirements for starting the current demo. [Dataset provenance](DATASETS.md), [research map](RESEARCH.md).
