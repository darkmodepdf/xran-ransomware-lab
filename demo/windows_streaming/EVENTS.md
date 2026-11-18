# Windows normalized event contract, v1

`schema=windows-event-v1`. Each record has a capture-local `actor` including raw capture hash, process occurrence, PID and first_seen incarnation. `pid`, `parent_pid`, `incarnation`, `thread`, `timestamp` retain source identity and clock evidence. `observed_index` is the original call position; `seq` is the consecutive projected file-event position for that actor. Unrelated actors must never share history. Missing metadata stays null and is counted in the audit.

`api`, `op`, `outcome` describe the observed call. NTSTATUS pending 0x103 is pending even when CAPE status is true. Only NTSTATUS zero is completed success; Win32 boolean APIs require nonzero return. Unknown informational statuses remain unknown. `requested_bytes` is never completed damage. `completed_bytes` is null unless independently reported for a successful operation. Repeated call counts are retained without expansion.

`target` is a SHA256 of the observed or causally resolved path, used only for equality and evidence, never as a learned value. `target_kind` distinguishes unknown, directory, nonfile device, and file candidate. A pathname alone does not prove an ordinary file. Successful opens bind handles; successful closes retire them; reopening a live handle is explicitly counted. Each process occurrence has its own table. Missing duplicate-handle relationships remain unknown. Rename clears stale handle bindings when its binary destination cannot be decoded. Setter classes retain their class and do not imply successful content damage. Source paths are never opened or executed.

The projection includes only listed file/lifecycle APIs. Audit denominators count every source call, including unprojected calls, without an observation cap. The handle table has a 4,096-entry bound with explicit eviction counts. Cross-process timestamp ordering is not inferred. Exact capture identities and full API sequence identities are retained for transitive grouping before model windows. Capture class labels stay in the report manifest, outside all events and learned inputs.

Native generated-fixture events use the same operation/outcome/target contract after synchronous operations. Their independent hash/validity observations are display evidence outside features. Their collector differs from CAPE; compatible fields do not establish equivalent data distributions.
# Enriched native measurements (2026-11-18)

Native fixture workers additionally emit `byte_offset`, `file_offset_after`,
`file_size_before`, `file_size_after`, true `requested_bytes` and
`completed_bytes`. Read completion can be shorter than the request. Writes and
resizes are flushed before measuring the resulting size. Reads/writes use the
actual file position; a resize reports its pre-operation position and resulting
size without pretending its removed bytes are a completed write.

For writes/resizes, `entropy_before`, `entropy_after` and
`changed_byte_fraction` are measured from the bounded fixture contents before
and after the operation. No file contents or validity/checksum predicate enter
inference. These observations are specific to the cooperating fixture worker,
not an OS-wide Windows collector. A future real collector must obtain equivalent
measurements or explicitly declare them unavailable.

The native model uses bounded per-actor size/offset/coverage/change and ordered
transition summaries. Missing required enriched observations produce an
unavailable native score; historical CAPE events are not imputed as measured
zeros. The frozen historical model remains separately loadable. Scenario,
variant, seed, warmup, oracle, filenames and literal target hashes never enter
native model features. Target identities support equality counts only.

