# Project structure

| Path | Purpose |
|---|---|
| [README.md](../README.md) | Current native quickstart and navigation |
| [README.legacy.md](../README.legacy.md) | Preserved historical root README |
| [src/raneval](../src/raneval/) | Dataset, model, feature, scoring and observer modules |
| [demo/windows_streaming](../demo/windows_streaming/) | Current service, native supervisor, static UI and frozen native/EN2025 JSON bundles |
| [demo/linux_dashboard](../demo/linux_dashboard/) | Historical Linux replay dashboard |
| [demo](../demo/) | Earlier response/replay demonstrations |
| [scripts](../scripts/) | Acquisition, audit, fitting, benchmark and explicit Kaggle tools |
| [models](../models/README.md) | Selected project-trained XRan endpoint bundles and manifest |
| [helpers](../helpers/) | Setup/lifecycle/test/reproduction implementation |
| [tests](../tests/) | Research, model, adapter, HTTP, state and real Windows-worker checks |
| [docs](./) | Current handoff guides |
| [docs/experiments](experiments/) | Compact provenance/metric receipts, without raw cohorts |
| [output/research](../output/research/) | Historical and current research reports |
| [_bmad-output](../_bmad-output/) | Preserved planning records and architecture decisions |
| [pyproject.toml](../pyproject.toml), [uv.lock](../uv.lock) | Versioned environment metadata and dependency lock |
| [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Automated verification configuration |

Local `data/`, `runs/`, temporary directories and virtual environments hold large/generated/private material. They are not prerequisites for the bundled demo. Local archive/PDF files and credential files are not publication inputs. Docker's limited build context excludes research training libraries and datasets; the runtime image serves inference/UI while workers execute on Windows.

Model JSONs contain schemas, ordered features, calibration/evaluation metadata and a canonical payload hash. Keep versioned bundles together with their reports. Retraining writes to a fresh run directory and a separate bundle; changing the deployed model is a deliberate subsequent action.
