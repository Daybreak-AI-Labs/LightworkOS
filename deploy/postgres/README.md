# Lightwork on Postgres — managed world-model state

By default Lightwork keeps run state in SQLite under `~/.maverick/world.db`:
simple, zero-dependency, and a **single writer**. That caps a deployment at one
control-plane replica per state volume. Postgres provides managed HA, pooling,
and DB-enforced isolation for the world model, but does not yet centralize every
file-backed Lightwork control-plane store.

## When to switch

Switch to Postgres when **any** of these is true:

- you want managed backups / PITR (RDS, Cloud SQL, Azure Database);
- you run many tenants and want DB-enforced isolation (row-level security).

The dashboard/serve control plane must still run as one replica. Workflow
releases/runs, A2A durable claims, audit/learning ledgers, and tenant-local
policy files are not yet all Postgres-backed. Scale remote workers separately;
do not use Postgres as evidence that `replicaCount > 1` is safe.

Until then, SQLite is the right default — don't add a database you don't need.

## Configure

Point the world model at Postgres via config **or** env:

```toml
# ~/.maverick/config.toml
[world_model]
backend = "postgres"
dsn = "postgres://maverick:***@db.internal:5432/maverick"
```

```bash
# or environment (takes precedence; good for K8s secrets / Terraform)
export MAVERICK_WORLD_BACKEND=postgres
export MAVERICK_PG_DSN='postgres://maverick:***@db.internal:5432/maverick'
```

Install the extra that pulls the driver:

```bash
python -m pip install -e './packages/maverick-core[postgres]'   # psycopg[binary]
```

The container image (`deploy/docker/Dockerfile`) and the VPS bootstrap
(`deploy/vps/install.sh`) already install it: both use the core extras
`release-runtime,postgres,oidc,s3,evidence-analysis`. On a VPS, override the set with
`MAVERICK_CORE_EXTRAS=...` before running the installer. A pipx install done
by hand needs the extra spelled out the same way:

```bash
pipx install './packages/maverick-core[release-runtime,postgres,oidc,s3,evidence-analysis]'
```

## Tenant isolation (row-level security)

For multi-tenant deployments, enable Postgres RLS so the tenant boundary is
enforced by the database, not just the app layer:

```bash
export MAVERICK_PG_RLS=1                    # force RLS on tenant-scoped tables
export MAVERICK_STRICT_TENANT_ISOLATION=1   # exclude legacy NULL-tenant rows
```

With RLS on, every connection sets the `maverick.tenant` session GUC and the
DB refuses cross-tenant reads/writes even if application code has a bug.

## Provision (managed Postgres)

Any Postgres 14+ works. Recommended baseline for a managed instance:

- **Storage**: start at 20–50 GiB with autogrow; world state is text-heavy but
  compact.
- **HA**: multi-AZ / zone-redundant for production.
- **Backups**: automated daily + point-in-time recovery (retain ≥ 7 days).
- **Connection pooling**: front with PgBouncer (transaction pooling) when
  remote workers and the control plane share the database; each process opens
  a small pool.
- **TLS**: require `sslmode=verify-full` in the DSN for networked databases.

Create the role and database:

```sql
CREATE ROLE maverick LOGIN PASSWORD '***';
CREATE DATABASE maverick OWNER maverick;
```

Lightwork creates and migrates its own schema on first connect (the same
forward-only migration machinery as SQLite). No manual DDL is required.

## Backups & restore

- **Managed**: rely on the provider's automated backups + PITR (simplest).
- **Self-managed**: `pg_dump`/`pg_restore` on a schedule; test restores.
- Per-tenant export/erase (`maverick client export`, `maverick tenant delete
  --purge`) operate at the application layer and apply to either backend.

## Health

`/healthz` runs a deep check (DB writable, provider key present, runner alive)
and returns 503 when degraded — wire it to your load balancer and alerting.
