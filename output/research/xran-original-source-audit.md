# XRan original-source access audit

Checked 2026-11-17. Scope: only the sources used in the supplied [XRan paper](../../XRan.pdf), not substitute datasets. This audit distinguishes published processed features from upstream executable collections and raw sandbox reports. No malware payload was downloaded or executed by this audit, and no author/provider was contacted. The parent task owns local archive downloading and content validation.

## Result

A public, author-associated [XRan repository](https://github.com/sibelgulmez/XRan) provides four compressed CSV datasets: VirusShare, SOREL-20M, ISOT, and benign samples. Its README explicitly identifies these as representations described in the XRan paper and requests citation. This is a materially better acquisition route than reconstructing cohorts from the providers. It does **not** contain the paper's VX Heaven other-malware dataset (MD), raw Cuckoo reports, model code, or published split manifests in its current tree. The paper's 2024 statement that data are available on request is therefore not sufficient to describe current access to the processed release.

The public release is evidence of supplied XRan features, not proof that every experimental row, transformation, split, or result can be reproduced exactly. Row counts, schema, sample identifiers and content must be validated separately before naming a cohort equivalent to Table 2.

## Public processed release

Pinned repository commit: `2cfebbfe45d3ed47b0204096186877e5991d6324` (2024-04-22). The recursive GitHub tree was retrieved successfully and was not truncated. The four files total **4,425,383 bytes** compressed. [Pinned tree](https://github.com/sibelgulmez/XRan/tree/2cfebbfe45d3ed47b0204096186877e5991d6324).

| Paper component | Paper count | Verified archive size | Pinned download |
|---|---:|---:|---|
| RD1, VirusShare ransomware | 6,263 | 1,417,993 bytes | [VirusShare.zip](https://raw.githubusercontent.com/sibelgulmez/XRan/2cfebbfe45d3ed47b0204096186877e5991d6324/ransomware/VirusShare.zip) |
| RD2, SOREL-20M ransomware | 7,703 | 820,534 bytes | [Sorel20M.zip](https://raw.githubusercontent.com/sibelgulmez/XRan/2cfebbfe45d3ed47b0204096186877e5991d6324/ransomware/Sorel20M.zip) |
| RD3, ISOT ransomware | 668 | 84,220 bytes | [ISOT.zip](https://raw.githubusercontent.com/sibelgulmez/XRan/2cfebbfe45d3ed47b0204096186877e5991d6324/ransomware/ISOT.zip) |
| BD, multiple benign sources | 14,797 | 2,102,636 bytes | [Benign.zip](https://raw.githubusercontent.com/sibelgulmez/XRan/2cfebbfe45d3ed47b0204096186877e5991d6324/benign/Benign.zip) |
| MD, VX Heaven other malware | 6,263 | Not present | No processed MD download in this release |

The [subdirectory readme](https://github.com/sibelgulmez/XRan/blob/2cfebbfe45d3ed47b0204096186877e5991d6324/ransomware/readme) identifies the CSV delimiter as semicolon. There is no explicit license file in the verified tree, and GitHub repository metadata returns `license: null`. Record the citation request; do not invent a CC/MIT license or equate public accessibility with unrestricted redistribution permission.

### Author association and its limits

This is more than an arbitrary third-party reimplementation: the account name matches corresponding author Sibel Gulmez; the repository explicitly cites XRan; the same account hosts SOEMD, which the authors' earlier *Sequential opcode embedding-based malware detection method* paper explicitly links as its source-code repository. That earlier paper is indexed at the [Istanbul Commerce University repository](https://acikerisim.ticaret.edu.tr/bitstreams/455380dd-8fd5-47a2-a89c-51005e3cde0c/download). The [GTU staff profile](https://www.gtu.edu.tr/en/personel/98/57264126/display.aspx) lists both publications. These primary-source search records support describing the release as author-associated. Full reopening of those two institutional pages failed during this audit (403/502 respectively); no authenticated identity claim is made.

The account's separate [CuckooReportProcess repository](https://github.com/sibelgulmez/CuckooReportProcess) is **not verified as the XRan extraction implementation**. At commit `e45ed218912f78335f3226e93eb50f61bd3047f1`, its inspected source sorts sample features, extracts DLLs from static imports, and writes per-feature presence columns. Do not use that unrelated representation as proof of the chronology or semantics of the XRan release.

## Original upstream sources

These are provenance and recovery options, not replacements for the processed release.

**RD1 — VirusShare.** XRan Table 2/Section 4.1 describes 6,263 crypto-ransomware executables, with source year 2016. The [provider](https://virusshare.com/) requires login to search/download; its [access policy](https://virusshare.com/about) requires an invitation and disallows scraping or excessive automated downloading. The paper provides no hash manifest or exact collection identifier. A newly selected VirusShare collection is not established as RD1. No general open dataset license was verified.

**RD2 — SOREL-20M.** XRan describes a selected 7,703-sample subset using relatively high ransomware tags and fewer other-malware tags, without numeric selection thresholds. The [official README](https://github.com/sophos/SOREL-20M/blob/master/README.md) gives a public S3 release at `s3://sorel-20m/09-DEC-2020/`, including `processed-data/meta.db` (approximately 3.5 GB), static EMBER/PE features and disarmed malware binaries. The metadata download candidate is [meta.db](https://sorel-20m.s3.amazonaws.com/09-DEC-2020/processed-data/meta.db); it was not downloaded by this audit. These upstream static features are not XRan API/DLL/mutex traces. SOREL does not freely distribute benign binaries. The repository links distinct [Terms and Conditions](https://github.com/sophos/SOREL-20M/blob/master/Terms%20and%20Conditions%20of%20Use.pdf); their detailed legal provisions were not parsed in this audit, so no license summary is asserted.

**RD3 — ISOT.** The [official lab page](https://onlineacademiccommunity.uvic.ca/isot/2022/11/27/botnet-and-ransomware-detection-datasets/) does not offer a direct download of the full raw dataset. Access requires a supervisor-signed agreement, SSH public key, provider approval and subsequent SFTP instructions. The [public agreement template](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2023/03/isot_ransomware-dataset-agreement-template.docx) restricts use to the stated research purpose, requires attribution, and forbids passing data to other researchers without permission. This applies to obtaining the upstream lab corpus; the separately published XRan processed ISOT CSV is publicly reachable.

The [ISOT overview](https://onlineacademiccommunity.uvic.ca/isot/wp-content/uploads/sites/7295/2023/03/ISOT-ransomware-open_dataset_readme.pdf) lists **669 ransomware samples and 103 benign applications, 428 GB**, including Cuckoo reports, logs, network captures and some memory dumps. This differs from XRan's **668 ransomware reports**. Neither the difference nor the exact selected report IDs was resolved by the upstream documentation. ISOT's 103 benign programs are not XRan's 14,797-sample BD cohort.

**MD — VX Heaven.** XRan's reference explicitly names the [2010-05-18 Internet Archive snapshot](https://archive.org/download/vxheavens-2010-05-18). Its [metadata endpoint](https://archive.org/metadata/vxheavens-2010-05-18) was successfully retrieved with Python even though the web reader could not open it. The listing includes `VX_Heavens_Collection.tar.bz2` (47,880,726,923 bytes) and `viruses-2010-05-18.tar` (64,633,978,880 bytes). These are entire malware archives, not a verified 6,263-sample non-ransomware cohort or processed traces. Metadata has no license field. Payload accessibility, contents, selection and rights remain unverified; neither archive was downloaded.

**BD — Windows files and software sites.** XRan lists 2019–2020 benign executables from Windows system files, [CNET Download](https://download.cnet.com/), [Software Informer](https://software.informer.com/) and [Portable Freeware](https://www.portablefreeware.com/). Only Software Informer's current page was opened successfully in this check; CNET was unavailable to the web reader and Portable Freeware returned 403. No original version/hash manifest is given in the paper. Current software downloads would not establish identical binaries; terms vary by software. The public XRan benign CSV is the usable processed-source route.

## Consequences for the project

1. Use only the pinned XRan processed release for the currently accessible ransomware-versus-benign experiment, subject to its actual content audit. Preserve archives, source URLs and hashes. Do not silently replace missing MD with another dataset.
2. If the intended task requires ransomware-versus-other-malware, raw traces, exact splits, or timestamped damage outcomes, missing material must be obtained from the authors/providers or the claimed experiment scope reduced explicitly. The release alone does not establish access to those items.
3. XRan observes **Windows execution**. The paper reports an Ubuntu 20.04.4 host and Windows 7 sandbox guest; ISOT reports an Ubuntu 14.04 host and Windows 7 64-bit analysis guest. A Linux training/inference container can process these reports, but that does not turn Windows API/DLL/mutex evidence into Linux syscall evidence or validate a Linux endpoint detector.
4. API sequence order alone does not supply damage ground truth, wall-clock latency, per-process identity, or time of DLL/mutex observation. Determine which metadata the downloaded CSVs preserve before promising streaming or damage-aware evaluation. Training and performance claims remain unexecuted in this source audit.

## Verification boundary

Verified: supplied-paper dataset table/setup/access statement; current repository README, complete pinned file tree and sizes; current upstream provider documentation; ISOT agreement text; Internet Archive file metadata. Not verified here: archive row counts and schema (parent task's responsibility), exact published experimental splits, raw sample provenance beyond source documentation, MD cohort identity, full upstream payload access, or reproduction of paper metrics. The source release supersedes the narrower access statement in the earlier [reading notes](XRan-reading-notes.md), while their methodological caveats remain applicable.
