# SQL results, deadlines and transaction outcomes

The `database` SQLAlchemy tool and `sql_query` SQLite tool share a bounded
`QueryResult` representation. They fetch at most the configured row allowance
plus one sentinel row. The sentinel determines `has_more`; a result with more
rows, omitted columns, truncated cells or omitted output rows has `complete=false`.
Execution success and complete business evidence are separate fields.

The default readable preview is a string that puts `result_metadata` before the
row data. This keeps the completeness warning visible if an outer
agent preview cap shortens the output. `response_format="json"` returns the
same admitted data and metadata as a valid JSON object. The final renderer drops
whole rows to keep the 50,000-character output bound; it never slices serialized
JSON in the middle of a cell or removes the only completeness marker.

Up to 64 columns are retained with bounded names. Text cells use a UTF-8-safe
prefix, normally at most 1,024 bytes and tighter for wide rows. Binary cells use
an explicit base64 representation. Truncated cells carry their type, preview and
source size (characters for text, bytes for binary). Nulls remain null. Nested
driver-decoded JSON/arrays/custom objects are explicitly omitted instead of
stringifying an unbounded object; project the needed SQL fields explicitly.
Unknown affected-row counts are null with `affected_rows_known=false`, not a
negative number presented as a business count.

Every invocation closes its cursor and connection snapshot. A live continuation
cursor is therefore **not available**. Metadata states that limitation rather
than inventing a stable cursor over changing customer data. Narrow the predicate
and choose explicit ordering for a new query; it is a new observation, not a
guaranteed continuation of the prior snapshot. Complete cross-call snapshots or
export artifacts are outside this tool contract.

Qualified transactional psycopg 3 SELECTs use SQLAlchemy's server cursor with a
buffer of at most the row allowance plus sentinel. Other SQLAlchemy operations
retain their driver behavior; a bounded `fetchmany` does not prove every driver
avoids buffering a large response internally. A single cell can also have been
materialized by the driver before preview truncation.

## Execution ownership

`QueryExecution` owns a per-call absolute deadline, current Agent budget and
cancellation state. The default is 30 seconds, configurable up to a hard maximum
of 300 seconds:

```toml
[query_limits]
timeout_seconds = 30.0
```

Invalid values retain the bounded default. Agent remaining wall time can only
tighten the deadline. Full budget/halt checks run before execution and commit,
and a watcher checks them every 50 ms during supported driver operations. The
SQLite progress callback cheaply reads the published stop and absolute deadline
every 1,000 VM operations. Cancellation of the tool awaiter publishes a stop to
the handle inherited through the existing invocation context.

| Driver path | Supported behavior |
| --- | --- |
| stdlib SQLite, directly or through SQLAlchemy | progress handler, owned-connection interrupt, remaining busy timeout, explicit transaction ownership |
| PostgreSQL through psycopg 3 with `cancel_safe` | remaining statement timeout plus owned-connection cancellation, bounded cancellation request, server cursor for eligible transactional SELECTs |
| Other SQLAlchemy drivers, including psycopg 2 | explicit `cancellation_support="unsupported"`; cooperative checks before/after driver work and before commit, without a false claim that the driver was interrupted |

The cancellation watcher is joined before its connection lease is released.
Monitor shutdown is separate from the final completion acknowledgment; the
handle becomes finished after connection/engine cleanup. A stopped awaiter is
not an acknowledgment that the worker or remote operation ended. Unsupported
drivers can continue running until their driver call returns, and their worker
capacity remains occupied. There is no shared engine or cross-call connection
reuse; unknown transaction state is invalidated before normal pool/context
cleanup and the private engine is disposed.

Existing PostgreSQL connection timeout policy and operator connection options
remain intact. Pre-connection DNS/driver handshakes are not interruptible by the
statement handle; if they consume the query deadline, the subsequent statement
is refused. SQLite user-defined functions/native extensions can likewise remain
inside a blocking function until it returns. These are not complete wall-clock
guarantees for every driver or arbitrary extension.

## Writes and reconciliation

Current host grants, model-URL restrictions, confirmation rules, protected paths,
read-only mode and SQLite authorizers remain in force. SQLite explicitly
begins a transaction, covering DDL as well as DML. Nontransactional maintenance
such as VACUUM, and manual transaction management statements, are not admitted
inside that boundary; perform maintenance through a separately reviewed operator
path. This intentional compatibility restriction prevents a stopped tool from
claiming it rolled back autocommitted SQLite work.

A limited `RETURNING` cursor is closed before commit so SQLite can commit the
approved statement exactly once. Cancellation before commit prevents the commit
and attempts rollback. An acknowledged commit stays committed even if a stop
arrives afterward. Loss of the commit acknowledgment remains unknown even if a
later rollback call returns. Such writes require reconciliation and are never
automatically replayed. Budget, accounting, halt and cancellation exceptions
remain original control signals; ordinary driver diagnostics are rendered as
bounded type markers without DSNs, credentials or raw SQL error details.

The regression suite includes real SQLite and an owned local PostgreSQL service,
plus fault-injected commit acknowledgment cases. It does not qualify customer
databases, other SQL drivers, network partitions, production TLS or extensions.
