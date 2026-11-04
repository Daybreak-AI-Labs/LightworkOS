---
name: schema-migration-plan
triggers:
  - plan a schema migration
  - database migration plan for this change
  - how do we alter this schema safely
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Plans the safe evolution of a database schema for a requested change (add/rename/drop column, type change, new constraint, table split) without downtime or data loss. Handles the goal class "we need to change a live schema — sequence it so nothing breaks." Produces a migration plan: an expand/contract sequence, a backfill strategy, and a rollback for every step.

# Steps

1. Read the current schema and the change request: load the existing DDL/migration files via `read_file` and identify the live readers/writers of the affected tables. Confirm the migration governance rules via `knowledge_search` (in this codebase, released migrations are immutable — adding/editing one requires regenerating the checksum lock; new DROP/RENAME steps are gated). Note these constraints before proposing anything.
2. Decompose into expand/contract phases so deploy order is decoupled from schema order. Expand: add the new column/table/index as nullable or with a default, additive only, deployed and live before any app reads it. Never rename-in-place or drop in the same release as the code change — destructive steps come only after all readers have migrated.
3. Specify the backfill: how existing rows get the new value (batched, idempotent, resumable), with a row-count check that old and new agree before the app switches to reading the new shape. Call out lock duration and table size — flag any operation that takes a long lock on a large table and propose the online/concurrent variant.
4. Write the rollback for each step (the inverse, or "forward-only, restore from backup" where no clean inverse exists) and the cutover sequence: deploy expand -> backfill -> verify -> switch reads -> later release contracts/drops the old shape. Report the ordered steps, governance/lock notes, backfill plan, and per-step rollback. State assumptions about traffic and table size; mark unverified ones.

# Notes

The plan is wrong if it drops/renames in the same step as the read switch (breaks in-flight code on either side of deploy), backfills non-idempotently (a retry corrupts data), or omits rollback for a step. Long locks on large tables cause outages — always size the table and prefer concurrent/online operations. This DRAFTS and sequences the migration; it does NOT run DDL, backfills, or drops — those are irreversible against production and are staged for a human to review, test on a copy, and execute. Honor the immutable-migration / checksum-lock governance; never propose editing a released migration. Do not use for one-off ad-hoc data fixes (that is a data task, not a schema change).
