# Governed-record Postgres connections

The Postgres governed-record backend uses the same libpq connection policy
as the world-model backend. The original DSN, including TLS verification,
certificates, service settings and search path, is preserved. The application
connect cap defaults to ten seconds **per host**; a shorter operator timeout is
retained, subject to libpq's two-second minimum. This is not an end-to-end DNS or
multi-host deadline. Existing explicit statement and idle-transaction settings
are retained; otherwise the defaults are 30 and 60 seconds respectively.

## Optional connection reuse

```toml
[governed_records]
backend = "auto"
pool_size = 0
pool_timeout_seconds = 5
```

`pool_size = 0` keeps fresh connections. Values 1–32 enable a process-local pool
shared across governed namespaces with the exact same DSN, bounded options and
pool policy. This is separate from `[world_model] pool_size`. The installer
advanced step offers one connection as a conservative starting point. Benchmark
the real workload before increasing it: more connections are not automatically
faster. Change this policy through a controlled process restart.

Pool acquisition accepts a finite 0.1–60 second timeout. At most 64 callers wait
in one pool. Four distinct pool identities are permitted per process; reaching
that limit refuses acquisition instead of silently evicting active authority.
The normal deployment authority pin allows only one configured identity. No
credentials appear in cache keys or pool names. Install the `postgres` extra
(`python -m pip install -e './packages/maverick-core[postgres]'` from the
repository root) to use the backend and its optional pool.

Every transaction still verifies current schema, forced RLS, execution-role
privileges and the external encryption-key identity. It binds the tenant with
transaction-local `set_config`, commits or rolls back independently, and clears
the session tenant before reuse. Failed reset discards the socket. Concurrent
threads never share a transaction. There is no automatic replay of statements,
failed writes or unknown commit results: a broken operation fails and a later
explicit operation may acquire a fresh connection.

Shutdown seals new pooled admission, tracks leased connections and owns cleanup
of the pool workers. Expiry of the shared dashboard deadline leaves pending
cleanup visible. A new lifecycle cannot reopen while a lease, worker cleanup or
cleanup failure remains. Fresh-connection mode has no pool workers to close.

Private injected `connect=` adapters retain their historical autocommit-only
call signature, remain unpooled and own their transport timeout policy. This
compatibility seam is not a claim that an arbitrary third-party connector has
the native psycopg deadline behavior.

## Validation boundaries

Local acceptance includes actual encrypted PostgreSQL reads, forced-RLS checks
without application predicates, concurrent namespaces and tenants, acquisition
timeout, rollback on `BaseException`, killed-socket recovery on the next call,
and refusal after key loss, added permissive policy, disabled RLS or role drift.
Synthetic loopback timings are mechanism evidence, not production sizing, WAN
latency, TLS-server qualification or failover acceptance for a hosted service.

The live world-model tests use a dedicated disposable database per test. This
keeps test-scoped encryption keys and old rows from contaminating later scans;
it does not weaken decryption or schema checks to make the suite pass.
