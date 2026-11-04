# Runtime integrity and bounded work

The behaviors below keep the configured authority boundaries. They are not
qualified against real providers or production workloads.

## Sandbox dispatch and cleanup

Tool subprocess dispatch invokes a supplied backend once with its per-call
timeout. A `TypeError` inside the backend does not trigger a second invocation.
The existing Sandbox SDK v2 requires `exec(command, timeout=...)`; conformance
checks reject incompatible argument shapes before entry-point dispatch. An
older implementation that cannot enforce this contract needs a supported
adapter from its author. Dropping the timeout or retrying after an exception is
not a compatibility mechanism. A missing `exec` on a supplied backend fails.

Docker and Podman cleanup check CLI exit status, attempt force removal even
when kill fails, and share one 15-second cleanup allowance. Successful removal
or successful enumeration proving the owned name absent confirms cleanup.
Daemon errors cannot prove removal. Diagnostics retain the generated container
name and a bounded status without reflecting raw daemon output.

Unresolved cleanup remains on the backend's `pending_cleanup` map and is
reported. A later command must reconcile it first. Warm containers whose
execution timed out are never reused. `close()` retries all retained owned
identities within one allowance. This in-memory state is not a durable
host-wide orphan registry; process loss can still require operator inspection
of the reported container name. Cleanup does not establish that a timed-out
external action is safe to repeat. Live Docker/Podman qualification remains
separate from the controlled CLI-failure tests.

## CSV shape summaries

`memory_safe_parse` uses the standard library's strict Excel CSV dialect
(comma delimiter, double-quoted fields, doubled quote escapes). It counts
logical records, including a header, and reports physical lines separately.
Blank physical records are ignored; quoted empty fields are records. Ragged
records are summarized with their minimum/maximum column counts, without
transforming or returning the original data.

The parser rejects malformed quoting, invalid UTF-8, field values over 65,536
characters, and requested byte/record bounds. Input is capped at 1,000,000
UTF-8 bytes, 100,000 logical records/items, and JSON nesting depth 64; callers
can tighten these limits. It never mutates the process-wide CSV field limit.
An independently lower interpreter field limit may also reject a field.

## Fair privacy callbacks

Callbacks still need fresh case, identity, source revision, adapter,
credential, capability, predecessor, retention, legal-hold and approval
checks before a lease is issued. A tenant/source-filter keyset cursor
advances through examined candidates instead of repeatedly selecting the
same blocked head of the queue. Progress is committed with the claim and
survives store reconstruction or worker restart. It is a scheduling hint,
never authority. Callback queue columns are checked against the protected
payload before dispatch.

Each poll examines at most `min(1000, limit * 10)` candidates. With a stable
blocked queue of N due rows and page size P, a complete pass takes at most
`ceil(N/P) + 1` empty polls from an arbitrary cursor. A successful poll advances through examined
rows. Exhaustion restarts from the head, allowing released holds to run.
Source filters have independent progress. Each tenant retains at most 256
recent filter cursors; eviction restarts a scan without deleting callbacks.
Continuously changing queues and cursor eviction can change the number of
polls needed. Empty polls create no claim/operation history.

## Claim-history schema v2

Stop old privacy callback writers before opening a v1 database with this
version. The first open validates and backfills the `created_at` projection,
adds expiry and operation-result indexes, and updates the schema version in
one transaction. An interrupted or invalid migration rolls back. Old readers
that require schema v1 will refuse v2; old writers cannot insert receipts
without the new timestamp projection. Restore a complete pre-upgrade backup
to roll back the store; do not relabel the schema version manually.

Claims validate and remove at most 128 expired receipts per poll, using the
tenant/time index. Unexpired receipts are not deserialized for cleanup.
Projection timestamps are checked against integrity-protected receipt JSON
before deletion or replay. The retention setting still determines expiry from
the original creation time. A directly requested expired idempotency key is
expired immediately even when it lies beyond the cleanup batch. Deleting a
receipt and its claim operation is atomic; the active callback lease remains
independent and cannot be reissued merely because history expired.

Receipts remain minimized to callback ID, revision, and lease-token digest.
Raw lease tokens are not added to history. The explicit integrity verifier
also checks projected claim timestamps.

## Governed document listings

The vault validates each already-selected document row directly inside one
read transaction. A list uses one document-head SELECT, retaining state
filters, ordering, limits and canonical row integrity checks. Concurrent
revocation does not splice newer records into an older selected page. A
listing is a snapshot, not permission to deliver: current authority and
one-time grant consumption continue to read and validate fresh records.
