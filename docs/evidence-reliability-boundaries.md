# Evidence verification and run-event reliability

The vendor workflow relies on distinguishing an observed outcome from a failed
check. The rules below keep those outcomes distinct within the domain stores.

## Scanner policy

`ShieldVerdict.scan_error` marks a detector failure. An ordinary clean allow has
`allowed=True, scan_error=False`. An optional balanced/permissive detector failure
logs an error and returns `allowed=True, scan_error=True`. A strict profile or
required Shield policy blocks detector failures, including builtin, SDK, decoded
variants, constitutional, output-policy and phishing checks. Disabled sinks and
disabled backends cannot satisfy required checks. Strict configuration also
requires the Shield package to be present; it cannot be relaxed by setting the
separate presence flag to false.

`shield_policy.scan_block` treats a returned `scan_error` as a block, matching its
exception policy; `shield_policy.scan_tool_call_block`, the screen for flow and
workflow tool steps (the same tool-call rules the agent applies), follows the same policy.
Optional installations still run without Shield.
These are control-failure semantics, not a claim that heuristic scanning detects
every unsafe input or that the external Shield SDK has been qualified live.

## Evidence and knowledge administration

`verify_lineage_file` distinguishes four outcomes. `VALID` means that an existing
file parses and its chain hashes agree; an existing empty file is explicitly
reported as empty. `MISSING` means no persisted file exists. `BROKEN` includes
invalid UTF-8, malformed JSON, non-object records and chain/hash failures.
`UNAVAILABLE` means the file could not be read. The `load_lineage` list
API is a best-effort display adapter and must not be used as verification.

`knowledge_admin` honors an explicit tenant over ambient context. The retained
`tenant=None` interface follows the active workspace. A custom configured path
outside the selected tenant workspace is rejected; operators with legacy shared
paths must move each tenant's own store into its workspace and configure that
path before administration. Do not copy a shared customer corpus into multiple
tenants. Remote knowledge-store namespaces derive from the resolved workspace
path through the store factory.

Disabled knowledge reports zero/empty results.
Configured but unavailable, missing or corrupt storage raises
`KnowledgeUnavailable`; erasure verification marks it unchecked with no observed
count. Counting and erasure do not create a missing SQLite database. A backend
that cannot enumerate collections cannot claim zero records. Knowledge CLI
residual JSON returns `clean=false`, `checked=false`, a null count and a nonzero
exit status for an unavailable check. A full erasure may continue deleting other
stores after a knowledge failure; its warning and indeterminate verification
must remain visible. Read/erase still use the configured embedder constructor,
so invalid embedder configuration can prevent administration.

## Replay and transport compatibility

`maverick_dashboard._event_stream` owns shared cursor, page and terminal rules.
Polling, both SSE routes and WebSocket recognize `done`, `completed`, `failed`,
`cancelled`, `blocked` and `error` as terminal for the current execution attempt.
A blocked run can later resume with the same durable event cursor.

Both SSE routes honor the greater of `since` and `Last-Event-ID`. Invalid cursor
values cannot advance replay and numeric cursors are bounded to the database
integer range. Streams drain terminal backlog before their final control frame.
WebSocket control frames retain the last durable event ID, with
`next_id` and `terminal` fields; they do not consume a fictitious event ID that
would skip the first event after resume. Ordinary event payloads are unchanged.

Polling responses add `has_more` and `terminal`. Consumers should continue
requesting pages while `has_more=true`, even if `status` is terminal, and stop
when `terminal=true`. The chat-goal dashboard follows this rule.
Legacy batched SSE and v1 per-event SSE retain their separate public framing.
Authentication, owner checks and the shared concurrency/lifetime caps remain at
the transport boundary. There is no universal delivery guarantee across client
disconnects; consumers resume by durable ID and deduplicate displayed events.

## Limits

These rules are not qualified against live remote vector stores, the external
Shield SDK or a reverse proxy in front of the event streams. The tests that
cover them are `test_scanner_failure_policy.py`,
`test_evidence_failure_boundaries.py` and `test_event_transport_parity.py`.
