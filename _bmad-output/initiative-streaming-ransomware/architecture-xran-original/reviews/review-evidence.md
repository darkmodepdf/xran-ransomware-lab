# Evidence, source and technology review

Reviewed 2026-11-17 against the current architecture, CONTRACTS and EXECUTION-PLAN; the supplied XRan paper; [source audit](../../../../output/research/xran-original-source-audit.md); [content audit](../../../../output/research/xran-original-data-audit.md); archive manifest; inspection script; and row-index evidence. This is a review of the plan, not validation of an implemented model.

**Disposition:** no remaining material evidence/source blocker in the inspected draft after the hash-contract correction below. The planned experiment is a reconstruction on the public XRan release, not exact paper reproduction, and its deployment is Windows-feature classification hosted in Linux. Actual modeling, export, scoring and UI claims remain gated on execution.

## Concrete finding, corrected during review

**[P2, resolved] Canonical full-feature hash disagreed with the acquired audit.** The initial CONTRACTS row serialized nested `[api,dll,mutex]`, while `scripts/inspect_xran_original.py` and the row index serialize the flat 520-cell list. This would prevent direct lineage joins and produce different hash-seeded splits even though equality groups remain mathematically equivalent. ISOT data row 1 demonstrated the mismatch:

- Existing audit/index: `33540ac665eed5a816c87f28b47a330c369c3b103460a552f269510b51d53382`.
- Initial nested contract: `844987748b17b9b4177391ea7e95ef64b7c1852c0f1c4884d739d4ef74c54eb4`.

Root updated CONTRACTS line 13 to flat `api+dll+mutex`, explicitly matching `full_sha256`. A subsequent local assertion recomputed the current contract from the archived CSV and matched the existing row index successfully. Carry this known row into the future adapter's regression fixtures.

## Decision traceability

| Decision | Evidence or status | Review conclusion |
|---|---|---|
| AD-1: only pinned XRan artifacts | Source repository explicitly associates four CSVs with XRan; manifest has pinned URLs, sizes, Git blob IDs and SHA-256. | Supported. Earlier EN2025/CRIBA/ebpfangel data and weights are explicitly excluded. User-provided files require lineage verification before incorporation. |
| AD-2: one complete 520-position sample | Actual shared headers are 500 API, 10 DLL and 10 mutex positions; archive has no identity, time, process or outcome columns. | Supported. Case/blanks/PRF preservation avoids inventing undocumented normalization. PAD/UNK IDs are a declared new implementation convention, not an assertion about the paper. |
| AD-3: group and quarantine before splitting | Audit records 30,171 rows, 22,469 full-vector groups, 7,702 excess duplicate rows, 24 contradictory full-vector groups containing 825 rows, and 192 entirely empty rows. | Evidence supports guarding against leakage and disclosing conflicts. One representative, quarantine policy, 60/10/10/20 ratios and seed are proposed benchmark choices; they are not recovered paper settings or proven optimal. Exclusions and multiplicity must remain visible. |
| AD-4: matched models and diagnostics | Missing original code/settings; strong source-dependent vocabulary/missingness; extensive API collisions. | Appropriately qualified. CNN/GRU capacity and tuning budgets remain assumptions to freeze and test. API-only results require the documented API-group sensitivity before interpretation. |
| AD-5: calibrate deployed arithmetic | Prior project evidence documents changed decisions when batch and streaming arithmetic differed; the current plan binds threshold/backend/preprocessing. | Sound reality-based safeguard. The 5% value is a nominal project target; the draft correctly avoids promising a deployment false-alarm guarantee. |
| AD-6: artifact ownership and execution gates | Existing recovery/deployment patterns and user Kaggle instructions; release has no explicit license file. | Plausible implementation choices, gated by smoke/resume/export checks. No executed XRan GPU or deployment result is claimed. |
| AD-7: evidence-oriented dashboard | Available endpoint feature data, missing metadata and explicit separation from historical Linux results. | Supported. Scores and perturbations are not presented as proven intent or causal mechanisms. |
| AD-8: raw-report extension | CSVs lack observation times, task identities, file outcomes and first-observed DLL/mutex times. | Supported. Prefix truncation cannot establish streaming or damage-aware performance; new verified same-cohort evidence is required. |

## Source and technology checks

- **Paper/release discrepancy is retained:** Sorel20M has 8,443 rows versus the paper's 7,703; the plan links the content audit and does not truncate to manufacture agreement. The other three published counts match. There is no MD archive; the second binary task stays unavailable. Public author association is not overstated as proof of exact original splits.
- **Platform boundary is correct:** Ubuntu/Linux hosts in the paper and Docker plan do not change the Windows 7 guest/API evidence. The draft does not claim that Windows API/DLL/mutex tokens validate Linux syscall detection.
- **Framework facts are scoped correctly:** Python 3.11.15, PyTorch 2.15.0+cpu and NumPy 2.4.6 are recorded as local observations supplied by the root's environment check, not asserted to be latest versions or Kaggle versions. Debian slim/ONNX reuse is conditional on actual new-model export parity; the plan does not claim this GRU/CNN export has run. Freeze actual serving versions and hashes when it does.
- **Kaggle limits remain unverified:** no numeric current service/session/quota limit is asserted. The configurable 10-hour budget is conditional on verified limits and retains a save/export reserve. Actual hardware, packages, FP16 stability, throughput, checkpoint restoration and durable outputs remain runtime checks. No additional current-framework promise needs a speculative version substitution.
- **Licensing is described as evidence and a project gate:** no license file/API license was found; README requests citation. The draft does not claim a particular open license or declare private cloud training unlawful. Recording the permission basis before upload/redistribution is framed as an unresolved project precaution. Raw ISOT agreement restrictions must not silently be assigned to the separate processed GitHub release, or vice versa; the source audit preserves that distinction.

## Remaining validation boundaries

This review did not train a model, execute a GPU job, export ONNX, build the new service, establish legal rights, or verify exact experimental identities. The source audit's earlier row-count disclaimer is superseded for content inspection by the later all-row data audit; it remains true that exact paper sample identity and splits are unverified. Final cohort preparation must still reconcile every row disposition, including overlap between entirely empty and contradictory groups, without double-counting exclusions.
