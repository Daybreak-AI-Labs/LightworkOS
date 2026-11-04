# Attachment admission and submission recovery

Chat send/reply and REST attachment uploads share bounded multipart staging.
Uploads are read in chunks of at most 64 KiB, with smaller reads near the file
or batch limit. The server does not trust Content-Length. It validates every
selected file before creating a chat task. MIME/magic checks, portable filenames,
the existing file/goal byte limits, and a 128-file batch bound apply. Failed or
disconnected staging removes only that request's private staging directory.

A chat submission then creates a `draft` goal and a durable receipt in one world
database transaction. The receipt binds owner, tenant, submission key, content
fingerprint and the full attachment manifest. Its details use the existing
at-rest field encryption. Chat forms carry a stable `submission_key`; API clients
may supply `Idempotency-Key`. Reusing a key with different content returns 409.
Retrying the same key/content returns the same task, including after reopening
the database. Legacy clients without a key receive a fresh submission; they must
retain and reuse a key to identify a retry of task creation.

Attachment metadata admission serializes on the goal in SQLite/PostgreSQL,
checks the current aggregate quota, and deduplicates identical filename/MIME/
size/hash records. The entire metadata batch commits together. File publication
occurs only after quota admission while that transaction owns the goal lock.
Existing content-addressed files are verified and never overwritten. Optional
S3 mirroring follows successful authoritative admission.

Filesystem publication and the database cannot form one transaction. If file
publication or metadata storage fails, a chat task remains an explicit draft,
with its expected manifest and a recovery message. Files already published to
that draft's directory are retained for retry; unrelated files are never
deleted. A rejected batch does not become a runnable pending task.

Before dispatch, the service checks admitted files against their hashes,
generates available companions, and records missing/disabled companions. Missing
text is also identified in model context so the runner cannot silently treat it
as read evidence. A companion's availability is separate from its extraction
coverage; partial/unsupported source coverage remains inside the versioned
[extraction result](document-extraction.md). The caller's channel, identity,
conversation and suite restrictions are recorded before one atomic dispatch
claim changes a prepared draft to pending.

The task page identifies saved drafts and provides **Retry preparation** when
the admitted files are intact. An incomplete batch must be resubmitted with the
original key and files. Changing or deleting an admitted file keeps the task a
draft until the original is restored. Retrying an already claimed submission
does not dispatch another run. A crash after dispatch claim is an ambiguous
delivery boundary; inspect the existing task/runner state before deliberately
starting another run. The receipt is an admission and dispatch record, not an
automatic cross-system delivery retry service.

Schema version 38 adds the receipt table with an indexed unique goal reference
and cascading goal deletion. PostgreSQL applies exact tenant predicates and its
RLS policy to receipts; preflight/backfill includes the new table. Existing
attachment insertion also uses the serialized quota/dedup service.

Receipt isolation holds on PostgreSQL for a NOSUPERUSER/NOBYPASSRLS application
role. Live transcription and provider requests, S3 transfers and production
deployments are not qualified.
