# Selected direction: Option B, Windows behavior

Date: 2026-11-17.

User selected Option B and requires alignment with the supplied dataset's operating system.

The supplied XRan paper and released API/DLL/mutex feature rows describe Windows execution. Ubuntu mentioned in the paper is the analysis host; its sandbox guest is Windows. Local evidence: output/research/XRan-reading-notes.md and output/research/xran-original-source-audit.md. The root benign.7z is the EN2025 benign log archive, rather than the XRan Benign.zip feature release.

Select EN2025 raw Windows CAPE/API reports for the streaming track. Preserve XRan as the existing endpoint benchmark; do not merge XRan feature vectors with EN2025 event sequences or transfer its measured accuracy. CRIBA is not selected for this Windows-aligned implementation.

EN2025 source: https://zenodo.org/records/18218588 . Publisher describes benign, ransomware and other-malware logs, without executable binaries. Existing local benign/ransomware archives and extracted development reports can support the first schema audit. Counts and field coverage must be audited before training; a prior small pilot is not the full cohort.

Required data work: retain process/thread identities, parent relationships, capture-local process incarnation, timestamp semantics, API-specific success results and file-handle/path lifecycles. The existing token-only preparation is insufficient for file attribution. Include regular-file versus non-file handles, rename and handle reuse. Missing targets remain unknown. Capture labels must not be applied automatically to all child processes or all prefixes. Family/source/identity independence is not assumed.

Deployment alignment: retain the accepted live controlled-worker design but execute actual Windows operations in bounded native Windows workers. The worker library emits authenticated, versioned events after real fixture operations. A lightweight Linux Docker container can host inference, event routing, fixture-ledger views and UI. Native workers and the container need a narrowly scoped local communication channel; validate host reachability and authentication. Container loopback means the container's own network namespace, not Windows host loopback. Do not expose the service publicly.

There is no need to mount writable user folders or the Docker socket into the inference container. Native workers own a dedicated generated temporary fixture tree and provide independent content-validity/hash evidence. Distinguish initiating PID/task from any helper service's executing PID.

This hybrid is a change from the earlier all-Linux Option B recommendation, required by the user's Windows-data constraint. If all actual execution must reside inside Docker, use Windows containers and remeasure image size, memory, OS/API compatibility and collector support; the previous small Linux-image targets do not automatically apply. Do not change Docker engine mode without a concrete implementation need. Docker Linux daemon was unavailable during proposal inspection.

Train fresh streaming baseline/CNN/GRU candidates only after API-to-event compatibility and benign/malicious collection bias are measured. Native scripted workloads and CAPE-instrumented reports have different collectors; a mapping cannot erase that domain shift. A successful synthetic demo does not validate real ransomware generalization. No DLL/mutex information observed only later in a report may leak into early predictions.

First implementation milestone: audit EN2025 schemas and file attribution coverage; freeze the event contract and original-capture splits; build Windows fixture workers and per-process replay; compare identical replay/native events on the intended runtime; then train and calibrate. If EN2025 cannot support reliable file mapping for a subset, exclude that subset from attribution claims while keeping unknowns visible, or revise the source selection before training.

Status: dataset and platform selected; implementation and runtime verification remain to be performed. No malware execution is part of this design.
