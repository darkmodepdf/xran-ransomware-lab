# Adapter review artifact regeneration

Fixed failed/pending rename invalidation, unnamed successful handle reuse, actor PID/incarnation immutability, and cleanup of partial fixture preparation/Popen failures. Added focused regression tests, including real owned-child stop behavior.

The complete 360-report audit and unchanged deterministic training/export recipe were rerun after the adapter corrections. No features, splits, optimizer settings or cutoff selection rule were tuned in response to tests.

Historical audit, model, evaluation, split, reports and 360 decompressed projection hashes are preserved in `output/research/windows-streaming-history/pre-adapter-review/`.

All 360 projections are byte-identical after decompression; all raw hashes and audit counters are unchanged. The lifecycle edge cases are covered by injected regressions but were not present in this selected development subset. Frozen model payload, split and evaluation are identical. Every weight, bias and cutoff has exactly zero delta, so identical projected histories yield identical scores and decisions. Test remains TP 1 / FN 26 / FP 0 / TN 27, AUROC 0.8806584362; cutoff 0.8979676155142287. See the adjacent JSON for exact comparison and hashes.

Only tests covering edited adapter/runtime/agent files were run: 20 targeted tests, with 19 passing initially and the oversized-body HTTP case encountering a transient Windows 10053 disconnect. That exact test passed on isolated rerun; no HTTP implementation or transport workaround was introduced. Full verification is performed by the parent agent.
