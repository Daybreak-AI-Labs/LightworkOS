---
name: database-migration-runbook
triggers:
  - db migration
  - zero downtime
  - expand contract
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Produces a zero-downtime database migration runbook using the expand/contract (parallel-change) pattern. Output is an ordered, reversible sequence of schema and code steps plus a backfill plan, so the application stays serving on both old and new shapes throughout. Handles the "change a live schema without a maintenance window" goal class.

# Steps

1. Establish the current state from real inputs: read the schema/migration files and target change with `read_file`, identify table size, write volume, FK/index constraints, and which app versions read or write the column(s). State the desired end shape. Mark anything unverified.
2. Run `knowledge_search` for the team's migration tooling, online-DDL conventions, prior backfill incidents, and rollback policy; cite them and note gaps (e.g. whether the engine locks on ADD COLUMN).
3. Lay out expand → migrate → contract phases. EXPAND: additive, backward-compatible DDL only (new nullable column / new table / new index built online). Then ship code that dual-writes old and new and reads old. BACKFILL: chunked, throttled, resumable, idempotent, with progress/verification queries. Then flip reads to new and verify. CONTRACT: only after all live code no longer references the old shape, drop it — as a separate, later release.
4. For every step give its forward action, its rollback, and a verification check; flag the point of no return (the drop). Report the runbook and hand off, stating assumptions, backfill duration estimate, and the DDL execution owner.

# Notes

Wrong if any single step is non-additive while old code still runs (causes errors mid-deploy), if backfill isn't chunked/idempotent (locks or can't resume), or if contract runs before every reader is upgraded. Per project policy, released migrations are immutable — editing one requires regenerating the checksum lock, so design new versions rather than mutating old. DROP/RENAME steps and the contract phase are irreversible: stage them for explicit human approval and run them in a separate release after the expand has soaked. Do not use for offline batch ETL or for changes that genuinely require a maintenance window. Cite engine-locking behavior to docs; never assume DDL is online.
