# Contributing

Keep changes scoped to their research track and preserve frozen bundles, thresholds, prior results and error cases. Describe the concrete problem, changed behavior, validation and relevant limitations.

Use the [setup profiles and test helpers](docs/REPRODUCIBILITY.md). Run Windows tests on Windows for actual worker execution; use the Research profile for the full suite. Changes to static JavaScript should pass `node --check demo/windows_streaming/static/app.js`. Record checks actually observed rather than copying historical pass counts.

For experiments, freeze manifests and selection/calibration policy before test. Keep whole actor/campaign histories in one role, use fresh output paths, retain false alerts/misses, and distinguish generated templates from independent family/application holdouts. Do not tune the cutoff on final test. Document collector differences and unavailable measurements.

Do not commit credentials, session URLs, raw datasets/reports, archives, generated runs, virtual environments, unrelated PDFs or third-party content without verified rights. Add compact redacted provenance and metrics when needed. New workers must retain bounded owned-file access, cleanup validation, actor isolation and the separation between model evidence and independent file integrity.

See [architecture](docs/ARCHITECTURE.md), [dataset rights](docs/DATASETS.md), and [security reporting](SECURITY.md).
