---
status: done
route: full
date: 2026-11-17
---

# GRU log-rotation follow-up

Measure whether a revised GRU reduces false alarms on fresh benign log rotation while retaining first alerts by event 120 on the five previously evaluated DarkSide and Erebus recordings. Use a separate 5% nominal per-capture benign calibration budget for each comparable model. Test independent ransomware recordings if compatible source data is available. Prior named-family recordings establish regression coverage and have already been exposed to development.

- [x] Record fresh busy Linux benign captures with more log-rotation behavior. Freeze capture roles and workload variants before model selection. Audit IDs, source hashes, timing and exact projected event-sequence overlap against the earlier comparison and within the fresh campaign.
- [x] Audit independent positive sources. Document the compatible fresh positive data gap and report named-family regression on the previously evaluated CRIBA recordings.
- [x] Use original GRU weights at a newly calibrated threshold as the matched-budget baseline. Compare it with fixed candidates using new benign training and tuning captures and the five known ransomware regression recordings. Freeze the selected readout before fresh test scoring. Calibrate on a separate benign set at 5%, and report actual calibration counts, test false alarms and named-family first alerts.
- [x] Stage the verified report in the Docker Model comparison tab. Verify the live API, browser and original replay. [Evidence](../../output/research/linux-gru-log-rotation.md)
