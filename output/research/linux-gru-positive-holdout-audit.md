# Linux GRU ransomware holdout provenance

The benchmark uses seven normalized successful file operations ordered by syscall completion. It measures event position and elapsed time from the first eligible completion. To qualify as a fresh ransomware holdout, a recording must also be distinct from all captures previously used to develop or evaluate the models. [Benchmark preparation](../../scripts/prepare_linux_benchmark.py)

| Published source | Verified compatibility |
| --- | --- |
| [CRIBA SysTracer](https://github.com/dsrhaslab/criba) | At revision `b5e006ae9628e3a5361697adb9e6bb3086862660`, the three DarkSide and two Erebus archive members match the previous benchmark rows one for one. The archive SHA-256 digests match the old rows and the benchmark pins. All five are suitable for a regression check. |
| [ELFEN on Zenodo](https://zenodo.org/records/19617322) | The published ZIP contains 32 report JSON files under 16 family names. DarkSide and Erebus are absent. The audit read 9,694 records from `report.data.dynamic.fileops.data`. The 314 writes, 216 reads, 106 renames and 3 unlinks all have blank `ret` values. All 4,878 successful calls within the benchmark vocabulary are opens. A single timestamp field `ts` supplies no separate completion timestamp. |
| [GuardFS logs](https://github.com/Cyber-Tracer/FS-MTD-Detection/releases/tag/MA_Robert_Oles) and [capture method](https://arxiv.org/abs/2401.17917) | The raw ransomware CSVs cover DarkRadiation, Ransomware_PoC and roar. Fields are `pid,entropy,op,ext,filename,timestamp`. The capture method records information before file access, so the CSV has no success outcome or completion timestamp. |
| [Multi-Log dataset](https://www.multi-log.com/dataset/) | The publisher lists 60 ransomware instances. The public page has no family-level manifest, and the trace link led to Google sign-in during this audit. Family membership and recording compatibility remain unverified. |

The inspected sources yielded zero qualifying new ransomware recordings. The five CRIBA runs can measure changes in DarkSide and Erebus alert timing on known recordings. Fresh ransomware recall and latency remain unmeasured.

The audited ELFEN ZIP has SHA-256 `c3cfb1c4c284e14bb512e3078030d6cda3e828b45b15cf36cbcd1670e26a072e`. The audited GuardFS ZIP has SHA-256 `c3a56b1d971eab007a80a5059169fab97c55e08e42c9147e1f2e3ec1561aa558`.
