# Vendor questionnaire lookup

The `[vendor_management] enable = true` feature maintains a versioned
exact-token index. Tokens are hashed before indexing. A positive
lookup still reads the canonical vendor, verifies its current revision and
exact token association, and resolves the current assessment template. A
duplicate association is unavailable rather than selecting an arbitrary vendor.
Returned fields remain the vendor name/identity, assessment type and public
question text. The submission field bound is checked again at read time.

## Upgrading an existing register

Before exposing hosted forms, run this with the same tenant and backend
configuration as the dashboard:

```sh
maverick vendor questionnaire-index --batches 101
```

Each batch reads at most 100 canonical records and normally at most 16 MiB of
source content. One individually valid larger record can consume a batch.
The cursor is durable. Repeat the command if it reports `ready=false`.
Do not repeatedly add `--rebuild`: that explicitly starts over. A rebuild of
Postgres first clears derived entries in batches, so it can require additional
maintenance calls before source migration starts.

A public request advances at most ten source records if migration is pending.
Until the entire index is ready, GET and gated POST return HTTP 503 with
`Retry-After: 2`. They do not report a false 404 for an unvisited old record.
Warm valid lookups hydrate one canonical vendor; missing-token lookups hydrate
none. Business register capacity remains 10,000 vendors and 20 questionnaires
per vendor. Renewal and posture scans retain their existing full coverage.

## Persistence and recovery

Local deployments use a private SQLite projection under
`vendor_management/.record-lookup/`. A namespace lock precedes canonical
per-record locks. A committed dirty intent precedes every source mutation;
interrupted writes are reindexed or trigger a bounded rebuild. Canonical vendor
JSON is never rewritten merely to build the index. Atomic file replacements
invalidate the directory generation, and backup restore journals an explicit
rebuild marker with the restored records. An unreadable SQLite index requires
an explicit `--rebuild`; canonical record corruption remains an error.

Postgres projections use separate derived namespaces in the existing encrypted
`governed_records` table. They retain the same forced tenant RLS, key and schema
checks. Source CAS and index updates use one transaction and one connection;
failure rolls both back. Tenant-and-namespace advisory locks coordinate
backfill with writers. Lookup hydrates the canonical source in that same
transaction, including with a one-connection pool.

All processes writing this register must use the upgraded indexed backend.
Mixed-version writers and manual SQL or in-place JSON edits are unsupported.
Run `maverick vendor questionnaire-index --rebuild --batches 250` after such an
offline repair or database restore, and verify readiness before reopening forms.
A stale positive association is refused and schedules rebuilding; an index is
not an integrity monitor for arbitrary out-of-band database modifications.
