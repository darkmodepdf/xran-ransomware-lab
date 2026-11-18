# XRan: reading notes

Read on 2026-11-16. Source: [XRan.pdf](../../XRan.pdf), 18 pages. Page numbers below refer to PDF pages, which match the printed numbering. These notes describe the supplied paper; experiments and external references have not been independently reproduced or verified.

**Paper:** Sibel Gulmez, Arzu Gorgulu Kakisim, Ibrahim Sogukpinar, *XRan: Explainable deep learning-based ransomware detection using dynamic analysis*, Computers & Security 139 (2024), 103703. DOI: 10.1016/j.cose.2024.103703.

## Main idea

XRan learns from several views of a program's runtime behavior. It concatenates API calls, loaded DLLs, and mutexes into a fixed-length sequence, classifies that sequence with a two-layer CNN, and applies LIME and SHAP to explain predictions. The contribution is the combination of behavioral features with classification and explanations, rather than a new CNN or explanation algorithm.

The paper studies two separate binary tasks: ransomware versus benign software, and ransomware versus other malware. Figure 1 shows separately trained classifiers. It does not establish a single three-class model or specify a decision rule for reconciling contradictory outputs from the two classifiers. Ransomware family identification is future work.

## How the method works (Sections 3-4, pp. 5-8)

1. Execute a sample in Cuckoo Sandbox and collect its behavioral report. RD3 already supplies reports, so those samples were not re-executed by the authors.
2. Extract chronological sequences for API calls, DLLs, and mutexes.
3. Restrict their lengths and concatenate them as `A[500] || DLL[10] || Mutex[10]`, yielding 520 positions. The position ranges are 0-499, 500-509, and 510-519.
4. Apply the architecture shown in Figure 2: convolution + dropout, convolution + dropout, max pooling, flatten, dense, output. Training uses Adam and binary cross-entropy; the paper specifies sigmoid activation and 10 epochs.
5. Use LIME for individual predictions and SHAP for aggregate feature/position importance.

Concatenation preserves the order inside each feature sequence. It does **not** produce one globally time-interleaved trace across all three feature types. Joint classification can exploit their combination, but the paper does not directly establish which cross-feature temporal dependencies the CNN learns.

The CNN extracts local patterns and combines their evidence in later layers. A feature can support ransomware in one sample and the opposite class in another. The model score runs from 0 (benign or other malware, depending on the model) to 1 (ransomware); no probability-calibration study is reported.

The paper gives insufficient information for an exact implementation: token-to-number encoding, embeddings, padding/truncation policy, duplicate handling, aggregation across processes, unknown tokens, filter counts, kernel sizes, dropout rates, dense widths, batch size, learning rate, and random seeds are not fully specified. An implementation would need explicit assumptions or author-supplied code.

## Data and evaluation (Table 2, pp. 7-8)

| Dataset | Contents | Count | Source/year listed |
|---|---|---:|---|
| RD1 | Ransomware executables | 6,263 | VirusShare, 2016 |
| RD2 | Ransomware binaries selected using tags | 7,703 | SOREL-20M, 2020 |
| RD3 | Ransomware behavioral JSON reports, 21 families | 668 | ISOT, 2020 |
| MD | Other malware | 6,263 | VX Heaven, 2010 |
| BD | Benign programs | 14,797 | Windows files and software download sites, 2019-2020 |

The three ransomware collections contain 14,634 samples in total (arithmetic from Table 2). The fourth ransomware evaluation setting pools those three collections; it is not a fourth independent ransomware source.

The authors describe random undersampling of negative examples for individual-dataset experiments. Their example pairs 668 RD3 samples with 668 benign samples. The balancing description does not explain RD2+MD, because RD2 contains more samples than all of MD.

The paper states an 80% training / 10% validation / 10% testing split and also 10-fold cross-validation, without clearly explaining how these procedures fit together. Family-disjoint, time-disjoint, or source-held-out testing and duplicate controls are not described.

Reported hardware is an i7-9700K CPU with 64 GB RAM, Ubuntu 20.04.4, and a Windows 7 analysis guest. Sandbox analysis has a 60-minute upper limit. The authors report a weighted mean of 155.3 seconds per sample; this is analysis time, not CNN inference latency or time to prevention.

## Results and what they establish

For the pooled ransomware sources, Tables 4 and 5 report:

| Binary task | Accuracy | Recall / TPR | False-positive rate | F-score |
|---|---:|---:|---:|---:|
| Ransomware vs benign (Table 4, p. 9) | 99.0% | 99.4% | 1.0% | 99.2% |
| Ransomware vs other malware (Table 5, p. 10) | 95.6% | 94.7% | 2.3% | 96.8% |

TPR is the fraction of ransomware detected. FPR is the fraction of the negative class incorrectly labeled ransomware. The headline 99.4% is recall, not accuracy.

**Unresolved reporting conflict:** Table 6 (p. 10) reports 98.2% accuracy and 4.7% FPR for the pooled ransomware/benign setting, with the same 99.4% TPR. Table 4 reports 99.0% and 1.0%. Both rows were visually checked in the PDF. The paper does not explain the difference; neither row should silently replace the other.

The strongest direct evidence for feature combination is Table 3 (p. 9). API-only accuracy is approximately 85-88%, whereas merged sequences reach approximately 98-100%. API-only TPR is high, but FPR is also high: 24-31%. DLLs and mutexes add discrimination against benign programs in these experiments. The table tests individual feature types and the full combination, but does not isolate every pairwise combination or compare ordered traces against shuffled traces.

XRan reports 100% scores on RD2 and RD3 individual settings. Several simple baselines also reach 100% on RD2, so those results do not uniquely validate the two-layer CNN. On RD1 versus other malware, XRan has 92.7% accuracy and 10.5% FPR; the one-layer CNN and LSTM have slightly higher accuracy. On pooled ransomware versus other malware, XRan ties LSTM at the displayed precision.

Table 6 compares published numbers from different studies. Sharing a dataset provider does not establish identical samples, class balance, preprocessing, or splits. The table is contextual evidence, not a controlled rerun of every competing system.

## What the explanations show (pp. 12-16)

LIME examples include correct and incorrect predictions. They illustrate how features such as `Advapi32.dll`, memory-related APIs, registry APIs, and named mutexes support or oppose a particular prediction. The same name is not a universal ransomware indicator.

SHAP position rankings in Figures 11-12 often place DLL and mutex positions above API positions, especially on RD2. API positions are relatively more prominent for distinguishing ransomware from other malware. Early API positions dominate the displayed API rankings, with an exception in Figure 12a. Figure 13 also gives feature-name and grouped-feature explanations.

These plots explain the fitted models' associations. They do not establish that a feature causes malicious behavior, that a named library proves malicious intent, or that early calls suffice for prevention. A top-feature plot alone cannot prove that omitted positions are unnecessary. Explainer implementation, background selection, perturbations, fidelity, stability, and realistic behavioral counterfactuals are not sufficiently documented for reproduction.

## Important boundaries

- Random splits within source collections do not demonstrate generalization to unseen families, future samples, or a new deployment environment. Dataset age, provenance, labeling, and sandbox behavior could affect separability; this is a concern to investigate, not proven leakage.
- The work evaluates sample classification after dynamic analysis. It does not measure files lost before detection, real-time blocking, or protection against sandbox-aware behavior.
- The reported 1.0% pooled benign FPR (Table 4) still means approximately one false alert per hundred benign inputs under comparable conditions. Production prevalence and alert volume were not evaluated.
- The supplied PDF does not give confidence intervals or a complete reproducible model specification. Data are described as available on request (p. 17).
- Equation (1), p. 6, prints `1/(1+exp(x))`; the usual increasing logistic sigmoid is `1/(1+exp(-x))`. This is a visible formula issue, not evidence of what the authors' actual code executed.

The authors' proposed extensions are a static-analysis stage that routes uncertain samples to dynamic analysis, a hierarchy for ransomware types, and ransomware family classification (pp. 16-17).

## Working understanding

The paper supports testing multiple behavioral feature types together and using explanations to inspect both successes and failures. Its benchmark results are promising, but exact reproduction and broader deployment claims need stronger specification and evaluation. Any follow-up implementation should retain the paper's two-task distinction, label all missing design choices as assumptions, and preserve the unresolved metric conflict.
