# Complete flow checkpoints

Flow execution and retry use complete credential-redacted JSON values. Run-detail
API responses and the `flows/runs/*.json` display fields are previews: strings/lists
retain their existing 8,000-character/500-item display bounds, with a 32 KiB
total preview limit. A truncation marker is never an execution value in the new
checkpoint format.

Small complete checkpoints remain inline with a versioned integrity digest.
Larger/deeper values are written as immutable AES-GCM tenant envelopes under
`flows/run_payloads/<run-namespace>/<ciphertext-sha256>.bin`. The run row's
`data_state` reference selects the complete artifact. Authenticated envelope
contents bind the schema, exact tenant, run, flow and owner. Credential scanning
and secret-field redaction happen before encryption; encryption failure never
falls back to cleartext. This reuses the deployment's existing tenant KMS and
wrapped DEK, including configured external KMS policy.

Each complete checkpoint is limited to 16 MiB of JSON, 200,000 visited values
and keys, and depth 64. This admits ordinary large documents and business tables
without making payload storage unbounded. Unsupported/non-finite values and
quota/redaction failures stop persistence explicitly. Tuples normalize to JSON
arrays, matching their historical representation after restart. Budget,
principal quotas, immutable flow snapshots and approval authority remain in
force; this storage format does not authorize new execution.

A short per-run checkpoint lock covers row/artifact reads and publication.
The artifact is durably published before its row; the previous artifact remains
until the new row commits. Status-only writes reuse unchanged data. Old and
orphaned generations are reclaimed under the same lock; interrupted publication
keeps the previous checkpoint recoverable. Keep the run rows, artifacts and
tenant key material together in backups. Deleting a run reclaims its artifact.

New approval cards commit the complete data digest and record
`run_data_format = lightwork.flow-data.v1`; their public content still contains
only commitments and bounded labels. Changing a value beyond the visible
preview invalidates the approval. Existing complete legacy approvals retain
their original binding until their next pause.

Old run rows without `data_state` remain readable and upgrade on the next save
when their data is complete. Recognized old truncation markers require explicit
recovery; the discarded historical tail cannot be reconstructed from a marker.
Restore a complete backup or review original source inputs before initiating a
new run. Likewise, missing/corrupt artifacts, invalid references, wrong scope or
unavailable tenant keys raise `FlowPayloadError` before resuming any work.
Do not remove the reference or substitute the public preview to bypass that
error. Restore the matching artifact/key and retry the read. Downgrading to a
binary that does not understand this format is unsupported: it would mistake
the preview fields for complete execution input.

Authorized dashboard readers receive HTTP 409 with `flow_data_unavailable`
and recovery guidance; browser navigation renders the same guidance. An open
flow event stream emits that error and releases its slot if the complete
checkpoint becomes unavailable. These responses contain no artifact paths,
keys or execution values. Run-owner filtering happens before artifact loading,
so another owner's damaged checkpoint remains indistinguishable from a missing
run and does not break a scoped history query.

## Metadata history and recovery

`flows/run-index.sqlite3` is a private, rebuildable metadata index. Run JSON and
the selected encrypted artifact remain the authoritative checkpoint. History,
analytics, concurrency admission and due-recovery queries use indexed owner,
flow, status, update and due-time fields. History returns empty data/input fields
and `execution_data_status=not_loaded`; detail reads provide bounded previews
after loading complete execution state. Approval history requires a detail read
before presenting an actionable current binding. Metadata projections cannot be
saved as checkpoints.

Each run save/delete commits a per-run dirty intent before publishing the JSON
change, under a short cross-process index lock. A query repairs pending intents
before reading; concurrent saves cannot overwrite each other's intent. Selected
row file stamps are checked so deleted/changed canonical rows are reconciled or
produce a recovery error. First use, absent/corrupt indexes and startup recovery
rebuild from canonical rows, without opening result artifacts. A damaged result
artifact leaves its metadata visible; the detail/execute read reports recovery
requirements rather than using a preview.

Backup restore journals a `.run-index-rebuild` marker alongside restored run
files. Successful restore rebuilds before the first query; failed restore rolls
back both run files and invalidation state. For an offline manual file restore,
restart the dashboard/worker or call `maverick.flow.store.rebuild_run_index()` in
the intended tenant scope before reading or admitting work. Direct unjournaled
file additions during a running service are unsupported. The index can be
recreated; complete checkpoint data and key material cannot.

Recovery pages through due statuses with a `(resume_at, run_id)` cursor, rather
than restricting the search to the newest 1,000 records. Normal delayed jobs
remain the primary delivery path. Outbox repair uses an exact indexed queue
lookup by kind, run ID and tenant, including terminal jobs, so old deliveries do
not disappear behind a queue-history cutoff. Full payload validation, current
publication/approval checks and per-flow concurrency locking still precede work.
