---
title: Reproducible private GitHub project handoff
type: feature
created: 2026-11-18
status: built
baseline_revision: NO_VCS
route: full
route_source: auto
risk: high
review: quick
review_source: pinned
lenses_ran: [quick]
context: []
---

<frozen-after-approval>

## Intent

Prepare the full research project professionally for a private GitHub repository under authenticated account darkmodepdf: correct dependencies, reproducible installation/run/train/test helpers, comprehensive current and historical documentation, layered ignore rules, and a verified clean initial push. The user explicitly authorizes private repository creation, committing and pushing; workflow restrictions on remote operations and repeated approval do not apply to this request.

## Boundaries & Constraints

Preserve existing models, calibrated thresholds, worker safety, dataset acquisition scripts, original XRan/Linux work and research records. Never commit credentials, raw reports/datasets, archives, virtualenvs, generated runs/cache, agent-vendor/runtime files or unrelated third-party PDFs. Keep current model bundles and compact provenance/metrics sufficient to understand results. Do not grant a redistribution license for third-party assets. Verify repository is PRIVATE before any push. Never force-push or overwrite an existing remote repository. Use xran-ransomware-lab unless collision; current query confirms no existing repository. Preserve live lab unless a controlled setup smoke requires an owned temporary service; avoid killing unrelated services/processes.

## I/O & Edge-Case Matrix

| Scenario | Input/state | Expected behavior | Error handling |
|---|---|---|---|
| Fresh clone demo | Windows11, Python3.11/3.12, Docker DesktopLinux | documented one-command bootstrap/start; stdlib-only inference/worker; bundled modelready | actionable prerequisites |
| Docker not started | Desktop installed but daemon down | helper starts official installed Desktop hidden and waits boundedly | never install software silently/change engine |
| Busy port | unrelated localhost8767 service | detect and refuse takeover | no automatickill |
| Native retraining | native extras + own fixture campaigns | fresh output directory and separate bundle; no overwriting deployed model bydefault | clear native-only requirement |
| Full research tests | research extras installed | complete unittest suite; Windows actual worker tests run locally | CI reports Linux skipped native vsWindowsfull |
| Repository | authdarkmodepdf, targetmissing | create private, verify, pushmain, verifyhead+privacy | halt only genuine auth/remote blockers |
| Secrets/artifacts | candidategitindex | validateallowed files, oversized artifacts and secret patterns before commit | no force-add ignored data |

</frozen-after-approval>

## Code Map & Ownership

- Packaging/helper implementer owns `pyproject.toml`, `uv.lock`, `requirements*.txt` ifuseful, `helpers/*.ps1`, root `setup.ps1/start.ps1/stop.ps1/test.ps1` wrappers, `compose.yaml`, `.env.example`, `.github/workflows/ci.yml`, and launcher improvements `demo/windows_streaming/launch.ps1`. Rootcoordinateslive8767; never shut down existing service without root. Runtime stdlib; native extras numpy2.4.6 scipy1.17.1 scikit-learn1.9.1; research adds torch2.15.0+cpu ijson3.6.0; export onnx1.20.1/onnxruntime1.23.2; optional Kaggle/orjson onlywhereused. Pythonobserved3.11.15. Validate freshenvironment rather than relyingon `.venv-raneval`.
- Documentation implementer owns root `README.md` (current quickstart), `README.legacy.md` (preserve old rootREADME so relative linksremainvalid), `docs/*.md`, `docs/assets/dashboard.jpg` screenshot copied from runs/windows-dashboard-redesign-20261118/comparison.jpg, NOTICE/CONTRIBUTING/SECURITY ifappropriate. Cover architecture/multiplemodels, current24/24 TP2/32FP withoutgeneralization, reproducibility, datasets/licenses, config/lifecycle, experiments/tests, troubleshooting, projectstructure and archivedLinux/XRan paths. Link helpercommands agreedbelow. No fakeclaims about originalXRanweight availability.
- Root owns `.gitignore`, `.gitattributes`, `.dockerignore`, `docs/experiments/*` compact curated manifests/metric/provenance receipts, repositoryaudit scripts/tests, Git creation/index/secretreview, final verification/CI/push. Existing source/tests/demo/output research and `_bmad-output` planningrecords remain; exclude `_bmad/` vendorframework.

## Tasks & Acceptance

- [x] Add versioned install metadata and lockfile with minimal runtime and optionalnative/research/export/Kaggle groups. Document uv sync commands and pipfallbackifvalidated. No hidden third-party import is a required stdlibruntime dependency.
- [x] Add setup/start/stop/doctor/test/reproduce helpers with explicit exitcodechecks, safe credentialgeneration/storageignored, Docker readiness, localhostbinding and bounded ownedservicecleanup; rootwrappers beginnerfriendly. Agree commands `./setup.ps1 -Profile Demo|Native|Research`, `./start.ps1`, `./stop.ps1`, `./test.ps1 -Suite Windows|All`, `./helpers/reproduce-native.ps1`.
- [x] Add CI for relevant Linux+Windows Python3.11 tests, JSsyntax andDockerbuild, dependency profiles explicit. No datasetdownloads/Kaggle submission inCI. Do not claim checks passed until observed.
- [x] Rewrite documentation and preserve history; include model manifest and compact saved experiment evidence without raw datasets or credentials.
- [x] Strengthen ignores redundantly bydirectories/extensions/secretnames, prove representative sensitivefilesignored and source/bundles/docsnotignored. Scan full stagedcontents for secrets andoversizedfiles beforecommit.
- [x] Fresh clone/clean staging environment smoke setup, import/package, real nativeworkers/tests, Dockerhealth and bundledmodelhash. Initializegitmain, meaningful initialcommit(s), createprivate GitHub repo and verifyprivacy/head afterpush. No pushuntil result is concrete andreviewed.

Acceptance: Given freshsourcecheckout, whenfollowingquickstart, then localdemo hasmodel andnativeagentonline without researchdatasets. Givennewresearchenvironment, then all testsrun with declareddeps. Giventraininghelper, then newexperimentsdonotaltershippedmodel. Given ignoreaudit, then archives/secrets/generatedfilesstayunstaged while models/source/docsaretracked. Givenremotehandoff, then darkmodepdfprivate repohead equals localcommit and no requireduncommitted work remains.

## Implementation Notes

Implemented locked profiles, helpers, bounded Docker/service lifecycle, private session ACL, CI, professional current/legacy documentation, selected trained model registry and frozen compact provenance. Authenticated darkmodepdf private repository created and verified. Fresh Native profile45Windows tests pass withTorch absent; Research109tests pass. Independent clean clone at9cbec95e233aaf1eb3f90a273bcea4eb6875dac8 passes all109 tests, actualstart648events/oneflag/6invalid/firstalert4, andauthenticatedstop exits0 withsessionremoved. Mainlab restarted throughnewhelper. Stagedsource audit passes againstlocalcredentials. GitHubprivacy/head verification is performed externally at publication; hostedCI has no fabricated checked-in successclaim. See docs/VALIDATION.md.

No initialVCS. ghCLI authenticated asdarkmodepdf; GitHubconnector cannot create repo. Repo creation/push via authenticatedCLI authorized byuser. No open questions necessary; choose professional routine defaults and documentthem. Root handles finalreview/publication after collaboratorsfinish.

## Review Triage Log

| Finding | Verdict | Resolution |
|---|---|---|
| Native suite imports undeclared ijson | medium | Move pinnedijson toNative, relock;45tests pass withoutTorch. |
| Readiness HTTP request can hang beyond loop count | medium | Add per-request2s timeout and15s overall deadline; mocked timeout/missingmodel/success checks pass. |
| Frozen evidence test reads ignored local audit | high | Ship compactmetadata snapshotmatchingmodelSHA; pointtest totrackedreceipt; cleanclone109tests pass. |

No findings deferred. Selected endpointweights are compact, hashverified project-trained models; no rawdatasets or privatecredentials were added.

## Verification

- Fresh uv environment, locked dependency profile checks and `uv pip check`.
- Helper PowerShell syntax/doctor/setup smoke and correct outputpaths; no destructivehostcleanup.
- Targeted safety/publish-ignore tests plus full unittest suite in cleanresearchenvironment; JSsyntax andDockerbuild.
- Cleancheckout demo/native smoke without data/runs; model hash unchanged.
- Stagedsecret/size/ignoreaudit, private GitHub repository verification and equal local/remote main SHA.
