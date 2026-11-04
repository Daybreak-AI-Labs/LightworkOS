# PostgreSQL learning keys and migration 39

Migration 39 scopes key uniqueness to the tenant for all four `harness_*`
learning tables in the shared PostgreSQL learning store, so two tenants can
store the same model, guidance-line or corpus key without conflict.

The migration preserves existing tables, rows, values, nullable tenant identity,
and existing row-security policies. Named tenants have unique natural keys
within their own tenant. The legacy `tenant_id IS NULL` partition retains its
own unique keys. It remains separate even from an explicitly empty tenant value.
SQLite already keeps these stores in separate tenant files; its matching v39
migration is a no-op.

## Upgrade and refusal

WorldModel applies this through its versioned ladder. Standalone learning-store
initialization applies the same checked statements in its transaction, including
when no WorldModel has yet opened. A transaction-scoped advisory lock serializes
initializers. Table locks protect inspection and replacement; an active upgrade
may briefly block learning-store operations.

Before removing a legacy primary key, the migration verifies its exact natural
columns, checks for foreign-key dependencies and unexpected unique indexes, and
installs and validates separate named-tenant and NULL-tenant unique indexes.
It validates each index's relation, columns, predicate, validity, collation and
default B-tree operator class. Existing verified indexes make rerunning safe.
Any refused table or interrupted transaction rolls back all changes together.
The migration never deletes rows or cascades a constraint removal.

Unexpected constraints, missing recognized keys, foreign-key dependencies,
duplicate keys, or insufficient schema privileges require operator review.
Standalone callers receive `LearningSchemaError` with a bounded reason; readers
do not silently convert this refusal into an empty store. Inspect the affected
schema against the shipped table/index definitions and preserve a backup before
making an operator-approved repair. Do not remove constraints or rows merely to
force the upgrade through. A failed upgrade leaves the prior data and keys in
place; after repairing the actual mismatch, rerun initialization normally.

The current older learning-store callers remain compatible because they use
the same tables and columns and scope whole-map DELETE/INSERT operations by
tenant. They do not require `ON CONFLICT` against the removed global keys. This
is not a general rolling-deployment guarantee for custom callers. Existing
row-security policy and tenant-binding requirements remain in force; this
migration does not install new RLS policies or broaden access.

## Governance and qualification

Constraint removal is normally rejected for a new migration. The reviewed
exception is limited to **PostgreSQL version 39 and the full normalized SQL
SHA-256**:

`50f7c13c96f0f914267ccabc8dff7ba5e15be4cf5572c398fa3f570c39b0e9dc`

Changing the SQL, appending another DROP, moving it to a different version or
backend, or attempting to repin an existing migration still fails governance.
Released migration checksums remain unchanged.

Native local PostgreSQL tests cover every learning family across named and
unbound tenants, legacy row preservation, initialization order, concurrent
initializers, refused-schema rollback, process exit before commit, and retention
of RLS policy definitions and flags. The RLS preservation check does not qualify
every deployment's custom policy or role grants. SQLite lifecycle tests and
the general destructive-DDL rejection tests remain required.
