# Decision brief

Date: 2026-11-17. User requests research and a couple of implementation choices before construction.

Hard requirements: execute no malware; stream benign and ransomware-like activity on demand; keep process histories separate; flag suspicious actors and identify affected fixture files; run with a lightweight Docker image and interface. Existing XRan evaluation remains a separate Windows endpoint benchmark.

Questions: Which available logs preserve identity, operation results and file context? How can trace replay and live harmless execution be distinguished? How should file status be established without leaking simulation labels into inference? Which architecture best meets the lightweight constraint, and what evaluation would support its claims?

Scope: primary-source dataset and deployment research plus separately labeled local implementation inspection. No deployment, training, malware execution or automatic blocking of host activity is authorized by this proposal phase. The requested options are the decision point. Research performed sequentially; no researcher firewall is claimed.

Preferences in order: accurate file attribution; genuine concurrent controlled activity; reproducibility; small runtime; reuse of verified project components. No numeric weighted scores are invented before benchmark results exist.
