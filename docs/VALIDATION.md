# Handoff verification

Verified locally on2026-11-18, Windows11/Python3.11.15. Target repository: [darkmodepdf/xran-ransomware-lab](https://github.com/darkmodepdf/xran-ransomware-lab), created as **PRIVATE** and checked before publication. GitHub Actions is the authority for subsequent hosted-run results; local results below are not claims about a hosted run.

## Clean checkout

A separate Git clone, with no ignored source datasets/runs or existing virtual environment, was tested at code revision `9cbec95e233aaf1eb3f90a273bcea4eb6875dac8`.

- `./setup.ps1 -Profile Demo`: installed the project only, no runtime third-party dependencies; doctor and model integrity passed.
- `./setup.ps1 -Profile Research`: locked installation and dependency consistency passed.
- Complete clean-clone suite: **109 tests passed** (including actual Windows workers).
- Separately, an exact Native profile passed **45 Windows tests** with Torch absent. Native includes ijson so historical projection tests do not rely on an undeclared dependency.
- All3 shipped native/comparator bundles and12 endpoint-bundle files passed integrity checks. All3 endpoint models loaded and smoke-scored on CPU using the Research profile.
- The current audit metadata snapshot matches the historical model's exact recorded audit SHA. No test requires the ignored raw dataset merely to inspect frozen provenance.

## Actual launcher lifecycle

The clean clone's `./start.ps1 -NoBrowser` built Docker and brought model and native agent online. Both allowlisted workers completed with648 actual events,1 model-flagged process,6 independently invalid fixtures, and first model alert at event4. `./stop.ps1` performed authenticated shutdown; the launcher exited0, removed its session file and cleaned its owned service. A busy-port check refused takeover of the existing lab.

The main checkout was subsequently started through the new helper. Session credentials and verification logs stay in ignored local directories; they are not release artifacts.

## Publication boundaries

The Git-index audit checks excluded directories/extensions, credential filenames, common secret patterns, known local session values, file sizes and selected-weight exceptions. Only three audited endpoint weights are allowed through the general generated-weight exclusion. Git attributes preserve exact JSON/evidence/model bytes while normalizing source text. Raw archives/reports, user PDFs, intermediate runs, virtual environments, caches, agent-vendor code and local memories remain outside Git.

The base Docker image is pinned by digest. Python dependencies are locked, and CI actions are pinned to upstream-verified commits. CI independently checks repository/model integrity, Linux and Windows Research tests, JavaScript syntax and Docker builds without downloading datasets or submitting Kaggle work.

Native model payload remains `01b3497ca418991033fba338b301b5b823cf6ccedddecc81b82f9f9915a0e3cc`. The repository preparation did not retrain it or change the cutoff.

Local detailed receipts are in ignored `runs/github-handoff/`. Avoid committing launcher logs: they intentionally contain the private session URL for the user.
