# PostgreSQL client I/O deadlines

WorldModel and the governed-record transaction facility use an owned, synchronous
psycopg connection with a finite deadline for each established-connection I/O
wait. This includes query execution, commit, rollback and shared-pool reset. A
server-side statement timeout alone cannot release a client whose established
TCP connection has stopped delivering replies.

`MAVERICK_PG_IO_TIMEOUT_SECONDS` defaults to **35 seconds** and accepts finite
values from **0.1 through 3600 seconds**. An explicitly empty, malformed or
out-of-range value refuses connection admission. Zero does not disable the bound.
WorldModel captures the setting at construction. The governed-record facility
captures it with connection options on first use; shared pool identity includes
that captured value. Reconnects and replacement pool connections retain it.
Create a new backend/facility to adopt a changed setting.

This is independent of `MAVERICK_PG_CONNECT_TIMEOUT_SECONDS` (the existing libpq
per-host connection cap) and the server-side statement and idle-transaction
settings. Existing DSN, TLS, search-path and operator timeout options remain in
effect. A deliberately long query may need a larger client I/O setting as well
as its server statement allowance. The 35-second default leaves room for the
default 30-second server statement timeout and its response.

The bound applies to each psycopg readiness wait, not the total business
transaction, all pool acquisition, DNS resolution, or arbitrary application
code. Connection startup retains libpq's separate timeout behavior; it is not a
promise to interrupt a blocking operating-system resolver. Wait checks occur at
most 100 milliseconds apart, subject to operating-system scheduling. No watcher
thread mutates a connection being used by another caller.

## Failure and recovery

When an I/O deadline expires, the calling thread closes its owned connection and
raises `PostgresIOTimeout`, a `psycopg.OperationalError` with
`outcome_unknown=True`. Its fixed message contains no DSN, SQL, payload or
credentials. A control interruption also closes the owned connection without
sending another cancellation request over the failed transport. Cleanup failures
set `cleanup_incomplete=True` and retain the primary exception.

**A missing reply does not mean a missing effect.** A COMMIT can reach PostgreSQL
and succeed before its acknowledgement is lost. The connection layer never
retries a statement or transaction. Reconcile through the operation's existing
durable identifier and authority before deciding whether further action is
permitted. WorldModel reconnects only for a later call; the pool discards a broken
connection. Neither action replays the failed operation. The existing approval
finalization gate continues to require a reconciled audit receipt.

Injected transaction connectors retain their caller-owned behavior; this helper
does not patch their connection classes, and it does not globally modify
psycopg. Other database tools retain their own documented driver policy.

## Local qualification

Tests exercise an actual local PostgreSQL server through a loopback relay that
drops established-socket replies. They cover query, commit, rollback, pool reset,
and WorldModel approval reads and decisions in pooled and default modes. Lost
COMMIT tests inspect the database independently and confirm the committed effect
despite the caller's unknown outcome. Separate fault-injection tests prove that
generator and connection cleanup failures cannot replace the primary deadline
or control exception. These tests do not establish production network behavior
or performance under customer load.
