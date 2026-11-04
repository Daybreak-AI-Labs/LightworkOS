# Workspace feedback and trace records

New task verdicts use the active workspace's `dashboard/goal-feedback-v2.ndjson`.
Readback also matches the currently authorized task owner. Aggregate feedback
counts are limited to the current account's records. Trace annotations, saved
views, pins and curated-run entries resolve their workspace on every request;
switching workspaces does not reuse another workspace's in-memory store.
New shared UX records use `dashboard/ux_store-v2.json`. The older
`ux_store.json` may contain records written by a different workspace through
the historical singleton. It is retained for separate custodian review and is
not automatically imported. New saved views, pins and annotations remain usable.

The older deployment-wide `goal-feedback.ndjson` does not establish which
workspace produced a row. It remains on disk but is not imported, displayed,
counted or assigned to a workspace by matching a task number or owner name.
Records custodians must review that historical file separately. Normal task
verdict controls continue to work for new, explicitly scoped records.

Task verdicts and trace annotations have their own retention. Deleting a
conversation does not claim to erase these side records; My Data identifies
them as retained exceptions. No automatic reassignment, deletion or provider
operation is performed during this migration.
