# Complete tool results and bounded delivery

The tool registry collects at most 16 MiB of complete UTF-8 result data per
invocation. Sync and async generators use one bounded buffer instead of retaining
a list of every chunk. Plain returned strings use the same quota. This bounds
the host's retained result, not memory allocated internally by third-party code
before it yields or returns. A larger result is an explicit indeterminate
delivery outcome; it is never passed on as a successfully truncated value.

`set_chunk_listener` receives fixed byte-count progress while collection is
in flight. It receives no producer content or arguments at this stage. The agent
checks the whole result with its configured Shield policy, redacts the whole
result (including secrets split across chunks), and records terminal audit
evidence before releasing screened chunks. Listener failures do not repeat a
completed effect. A configured scanner/redactor failure withholds content. An
installation without the optional Shield still works, with existing missing
Shield behavior and mandatory secret redaction.

The model's existing context-sized head/tail preview remains bounded. A result
larger than that preview is stored as an immutable encrypted artifact, and the
preview identifies its artifact ID, byte count and expiry. `read_tool_result`
reads character slices with `offset`, `next_offset` and `has_more`. The reader is
classified low risk, goes through the existing tool allow/deny and capability
gates, and never broadens an identity's configured access. Existing
`[security]` tool ACL/risk settings and their installer configuration control its
availability. If the reader is denied by the tool ACL, the preview says so.

Artifacts are scoped to the canonical tenant, authenticated registry principal
and goal. Their ciphertext and complete plaintext digests are checked before
returning any slice. They expire after seven days. Per tenant, publication is
limited to 128 artifacts and 256 MiB, with cross-process quota locking; only
expired files may be reclaimed. Missing/corrupt/expired artifacts, wrong identity
or goal, missing keys and quota failure are explicit failures. Live results are
never evicted to make room. Storage is private under
`data_dir("tool_result_artifacts")`, sealed using the tenant KMS/DEK; deployment
backup/restore must preserve both those artifacts and their keys. No migration
of old conversation previews can reconstruct data already omitted in the past.

`code_exec` uses a trusted execution-data scope: declared tools retain all of
their screened values, within a combined 16 MiB input/script quota, instead of
injecting model previews into the script. An unavailable or indeterminate value
withholds script execution and warns that earlier declared calls may already
have run. It never constructs executable input from a partial result. This is
separate from workflow checkpoints, which continue to use the full encrypted
flow payload representation.

Collection and cleanup retain ownership until work actually exits. At most 32
sync workers and 32 async collection invocations are admitted. Cancellation
requests closure and bounds the caller's wait; resistant work remains owned and
consumes capacity until it finishes. `pending_tool_workers()` and
`pending_tool_invocations()` expose those counts. Python cannot force-kill a
thread or a cancellation-resistant coroutine: shutdown/recovery must keep their
state uncertain. Partial streams and cleanup timeouts are never automatically
retried, even if their tool name is ordinarily safe to retry. Budget, halt and
accounting stop signals continue to propagate.

Live provider behavior is not qualified.
