# EN2025 streaming audit

All locally extracted development reports; publisher benign/ransomware total 1,652, not this subset

Selected: 360; dispositions: {"projected": 360}

Denominators and counters:

```json
{
  "process_present_process_id": 1775,
  "process_present_parent_id": 1775,
  "process_present_first_seen": 1775,
  "calls": 5944179,
  "present_timestamp": 5944179,
  "present_thread_id": 5944179,
  "present_status": 5944179,
  "present_return": 5944179,
  "present_repeated": 5944179,
  "repeat_ambiguous_calls": 224018,
  "timestamp_ties": 5657802,
  "timestamp_regressions": 0,
  "handle_rebind_before_close": 143106,
  "file_events": 1649745,
  "outcome_success": 1538024,
  "target_directory": 284594,
  "close_unknown_handle": 369375,
  "outcome_failure": 111151,
  "target_file_candidate": 944166,
  "target_unknown": 414531,
  "io_calls": 264472,
  "io_target_known": 255660,
  "io_completed_bytes_known": 0,
  "unresolved_duplicate_handle": 19056,
  "target_nonfile": 6454,
  "duplicate_pid_entries": 0,
  "handle_name_conflicts": 172541,
  "setter_class_64": 555,
  "setter_class_14": 121103,
  "setter_class_4": 11853,
  "setter_class_74": 23,
  "setter_class_23": 88,
  "setter_class_41": 240,
  "setter_class_30": 1755,
  "setter_class_36": 7,
  "setter_class_65": 11,
  "rename_destination_unknown": 37,
  "setter_class_20": 5841,
  "setter_class_19": 5782,
  "setter_class_13": 6,
  "outcome_pending": 570,
  "setter_class_10": 26
}
```

- Capture labels are weak session labels, not per-call or child-process truth.
- Observed process-local order retained; interprocess chronology is not asserted. Repeated calls are not expanded.
- File paths are hashed evidence; regular-file status is only a candidate. No completed byte count is inferred from requested Length.
- 4,096 live handles per actor; eviction explicitly counted. Unknown duplicate handles and binary setter destinations remain unknown.

Every report disposition, raw hash, exact full API sequence hash and sample identity is in `data/processed/en2025-streaming/audit.json`. Errors are never silently dropped.

Exact identity duplicate groups: {"raw_sha256": 0, "sample_sha256": 0, "sequence_sha256": 2}

Per-class denominators:

```json
{
  "benign": {
    "selected_reports": 180,
    "projected_reports": 180,
    "counts": {
      "process_present_process_id": 277,
      "process_present_parent_id": 277,
      "process_present_first_seen": 277,
      "calls": 733773,
      "present_timestamp": 733773,
      "present_thread_id": 733773,
      "present_status": 733773,
      "present_return": 733773,
      "present_repeated": 733773,
      "repeat_ambiguous_calls": 48760,
      "timestamp_ties": 719663,
      "timestamp_regressions": 0,
      "handle_rebind_before_close": 1016,
      "file_events": 104649,
      "outcome_success": 100877,
      "target_directory": 8846,
      "close_unknown_handle": 67141,
      "outcome_failure": 3772,
      "target_file_candidate": 25367,
      "target_unknown": 69833,
      "io_calls": 6500,
      "io_target_known": 6249,
      "io_completed_bytes_known": 0,
      "unresolved_duplicate_handle": 1500,
      "target_nonfile": 603,
      "duplicate_pid_entries": 0,
      "handle_name_conflicts": 1101,
      "setter_class_64": 372,
      "setter_class_14": 780,
      "setter_class_4": 68,
      "setter_class_74": 20,
      "setter_class_23": 6,
      "setter_class_41": 15,
      "setter_class_30": 16,
      "setter_class_36": 7,
      "setter_class_65": 11,
      "rename_destination_unknown": 11,
      "setter_class_20": 29,
      "setter_class_19": 29
    }
  },
  "ransomware": {
    "selected_reports": 180,
    "projected_reports": 180,
    "counts": {
      "process_present_process_id": 1498,
      "process_present_parent_id": 1498,
      "process_present_first_seen": 1498,
      "calls": 5210406,
      "present_timestamp": 5210406,
      "present_thread_id": 5210406,
      "present_status": 5210406,
      "present_return": 5210406,
      "present_repeated": 5210406,
      "repeat_ambiguous_calls": 175258,
      "timestamp_ties": 4938139,
      "timestamp_regressions": 0,
      "file_events": 1545096,
      "outcome_failure": 107379,
      "target_unknown": 344698,
      "close_unknown_handle": 302234,
      "outcome_success": 1437147,
      "handle_rebind_before_close": 142090,
      "target_file_candidate": 918799,
      "target_directory": 275748,
      "handle_name_conflicts": 171440,
      "unresolved_duplicate_handle": 17556,
      "target_nonfile": 5851,
      "io_calls": 257972,
      "io_target_known": 249411,
      "io_completed_bytes_known": 0,
      "setter_class_23": 82,
      "setter_class_41": 225,
      "setter_class_30": 1739,
      "setter_class_14": 120323,
      "duplicate_pid_entries": 0,
      "setter_class_4": 11785,
      "setter_class_20": 5812,
      "setter_class_19": 5753,
      "setter_class_64": 183,
      "setter_class_13": 6,
      "outcome_pending": 570,
      "setter_class_10": 26,
      "rename_destination_unknown": 26,
      "setter_class_74": 3
    }
  }
}
```
