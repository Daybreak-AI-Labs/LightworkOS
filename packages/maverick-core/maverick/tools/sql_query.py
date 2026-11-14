"""SQL query tool — read-only by default, over a local SQLite database.

Lets the agent inspect a SQLite file with real SQL. Read-only is the
default and is enforced with a read-only connection plus a SQLite authorizer,
so a SELECT can never mutate the database even if a write slips past the
keyword guard. Set ``read_only=false`` to allow writes.

SQLite only for v1 (stdlib, no dependency, and it's the same engine the
world model uses). The DB path is confined to the sandbox workspace.
"""
from __future__ import annotations

import contextlib
import logging
import sqlite3
from pathlib import Path
from typing import Any

from ..approval_cards import ApprovalCardError
from ..query_execution import QueryDeadlineExceeded, QueryExecution
from ..query_results import QueryResult, render_effect
from ..safety import ConsentDenied, consume_operation_consent
from ..safety.secret_detector import redact
from . import Tool
from .execution_consent import execution_target, request_execution_consent
from .ffmpeg_tool import _safe_path

log = logging.getLogger(__name__)

_MAX_ROWS_CAP = 1000
_MAX_VALUE_BYTES = 1_000_000
_TOO_BIG_NOTE = (
    f" -- SQLite refused a value over this tool's {_MAX_VALUE_BYTES:,}-byte limit. SQLite "
    "does not say which: a result value, a stored value the query reads (even "
    "length() of a large text column), a bound parameter, or the statement "
    "text itself, which the same limit covers and cannot be exempted from."
)
_WRITE_KEYWORDS = frozenset({
    "insert", "update", "delete", "replace", "drop", "alter", "create",
    "truncate", "attach", "detach", "reindex", "vacuum",
})
_READ_ONLY_DENIED_ACTIONS = frozenset({
    sqlite3.SQLITE_ATTACH,
    sqlite3.SQLITE_DETACH,
    sqlite3.SQLITE_INSERT,
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    sqlite3.SQLITE_CREATE_INDEX,
    sqlite3.SQLITE_CREATE_TABLE,
    sqlite3.SQLITE_CREATE_TEMP_INDEX,
    sqlite3.SQLITE_CREATE_TEMP_TABLE,
    sqlite3.SQLITE_CREATE_TEMP_TRIGGER,
    sqlite3.SQLITE_CREATE_TEMP_VIEW,
    sqlite3.SQLITE_CREATE_TRIGGER,
    sqlite3.SQLITE_CREATE_VIEW,
    sqlite3.SQLITE_CREATE_VTABLE,
    sqlite3.SQLITE_DROP_INDEX,
    sqlite3.SQLITE_DROP_TABLE,
    sqlite3.SQLITE_DROP_TEMP_INDEX,
    sqlite3.SQLITE_DROP_TEMP_TABLE,
    sqlite3.SQLITE_DROP_TEMP_TRIGGER,
    sqlite3.SQLITE_DROP_TEMP_VIEW,
    sqlite3.SQLITE_DROP_TRIGGER,
    sqlite3.SQLITE_DROP_VIEW,
    sqlite3.SQLITE_DROP_VTABLE,
    sqlite3.SQLITE_ALTER_TABLE,
    sqlite3.SQLITE_REINDEX,
})


_SQL_QUERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "database": {
            "type": "string",
            "description": "Path to a SQLite database file (within the workspace).",
        },
        "query": {
            "type": "string",
            "description": "A single SQL statement to execute.",
        },
        "params": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Bind parameters for ? placeholders (avoids injection).",
        },
        "max_rows": {
            "type": "integer",
            "description": f"Max rows to return (1-{_MAX_ROWS_CAP}, default 100).",
        },
        "read_only": {
            "type": "boolean",
            "description": "Reject writes and open the DB read-only. Default true.",
        },
        "response_format": {"type": "string", "enum": ["text", "json"],
                            "description": "Readable preview (default) or structured bounded result."},
    },
    "required": ["database", "query"],
}


def _strip_sql_leading_noise(query: str) -> str:
    stripped = query.lstrip()
    while True:
        if stripped.startswith("("):
            stripped = stripped[1:].lstrip()
        elif stripped.startswith("--"):
            _, sep, rest = stripped.partition("\n")
            if not sep:
                return ""
            stripped = rest.lstrip()
        elif stripped.startswith("/*"):
            end = stripped.find("*/", 2)
            if end == -1:
                return ""
            stripped = stripped[end + 2:].lstrip()
        else:
            return stripped


def _looks_like_write(query: str) -> bool:
    stripped = _strip_sql_leading_noise(query)
    parts = stripped.split(None, 1)
    return bool(parts) and parts[0].lower() in _WRITE_KEYWORDS


def _read_only_authorizer(action: int, _arg1: str | None, _arg2: str | None,
                          _db_name: str | None, _trigger: str | None) -> int:
    if action in _READ_ONLY_DENIED_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


# Even in WRITE mode the tool is confined to the workspace-checked `database`
# path. ATTACH/DETACH would let a statement reach an arbitrary filesystem path
# (`ATTACH DATABASE '/etc/passwd' AS x`) and read/write outside that confinement,
# so deny them while still permitting normal DML/DDL on the main database.
_WRITE_DENIED_ACTIONS = frozenset({sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH})


def _write_authorizer(action: int, _arg1: str | None, _arg2: str | None,
                      _db_name: str | None, _trigger: str | None) -> int:
    if action in _WRITE_DENIED_ACTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _execute_sqlite_query(path, query, params, read_only, max_rows, response_format):
    conn = None
    cur = None
    execution = QueryExecution(mutation=not read_only)
    try:
        with execution:
            try:
                if read_only:
                    conn = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True,
                                           timeout=min(10, execution.remaining()))
                    conn.set_authorizer(_read_only_authorizer)
                else:
                    conn = sqlite3.connect(str(path), timeout=min(10, execution.remaining()))
                    conn.set_authorizer(_write_authorizer)
                # The query runs in the host process and rows are capped by
                # count only, so cap each string/BLOB value (and row) too.
                conn.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, _MAX_VALUE_BYTES)
                execution.bind_sqlite(conn)
                # Explicit ownership covers SQLite DDL as well as implicit DML.
                # Nontransactional maintenance is not admitted through this tool.
                conn.execute("BEGIN").close()
                execution.started()
                cur = conn.execute(query, params)
                if cur.description is None:
                    affected = cur.rowcount
                    cur.close()
                    cur = None
                    execution.commit(conn)
                    return render_effect(affected, execution.state, execution.cancellation_support,
                                         response_format=response_format, style="sqlite")
                cols = [column[0] for column in cur.description]
                rows = cur.fetchmany(max_rows + 1)
                cur.close()
                cur = None
                execution.check()
                if not read_only:
                    execution.commit(conn)
                else:
                    conn.rollback()
                    execution.state = "read_only"
                result = QueryResult.from_rows(cols, rows, row_limit=max_rows,
                                               transaction_status=execution.state,
                                               cancellation_support=execution.cancellation_support)
                execution.check()
                return result.render(style="sqlite", response_format=response_format)
            except BaseException as exc:
                if cur is not None:
                    with contextlib.suppress(Exception):
                        cur.close()
                if conn is not None:
                    execution.rollback(conn)
                message = execution.failure(exc)
                if isinstance(exc, sqlite3.DataError) and "too big" in str(exc):
                    message += _TOO_BIG_NOTE
                return message
            finally:
                execution.stop_monitor()
                if conn is not None:
                    conn.close()
    except QueryDeadlineExceeded as exc:
        # Admission can exhaust the deadline before __enter__ returns.
        # No driver exists yet; preserve the public tool error contract.
        execution.finish()
        return execution.failure(exc)


def _run_sql_query(args: dict[str, Any], sandbox) -> str:
    database = (args.get("database") or "").strip()
    query = (args.get("query") or "").strip()
    if not database:
        return "ERROR: database is required"
    if not query:
        return "ERROR: query is required"
    response_format = args.get("response_format", "text")
    if response_format not in {"text", "json"}:
        return "ERROR: response_format must be text or json"
    read_only = args.get("read_only")
    read_only = True if read_only is None else bool(read_only)
    try:
        max_rows = int(args.get("max_rows") or 100)
    except (TypeError, ValueError):
        max_rows = 100
    max_rows = max(1, min(max_rows, _MAX_ROWS_CAP))
    params = args.get("params") or []
    if not isinstance(params, list):
        return "ERROR: params must be a list"

    try:
        if sandbox is None:
            raise ValueError("a sandbox workspace is required to query a database")
        from ..sandbox.ssh import SSHBackend
        if isinstance(sandbox, SSHBackend):
            raise ValueError("host database tools cannot access an SSH workspace")
        db_path = _safe_path(sandbox, database)
        from ..paths import maverick_home
        candidate = Path(db_path).resolve()
        state = maverick_home().resolve()
        if candidate.is_relative_to(state) and not candidate.is_relative_to(state / "workspace"):
            raise ValueError("Lightwork's internal data directory cannot be queried")
    except ValueError as e:
        return f"ERROR: {e}"
    p = Path(db_path)
    if not p.is_file():
        return f"ERROR: database file not found: {database!r}"

    if read_only and _looks_like_write(query):
        return "ERROR: write statement rejected in read-only mode (set read_only=false to allow)"

    if read_only:
        return _execute_sqlite_query(p, query, params, read_only, max_rows, response_format)
    review = _write_review_items(query, params)
    if review is None:
        return ("ERROR: write statement is too long or contains material that would be "
                "hidden from the reviewer; split it or remove secrets before retrying")
    parameters = {"database": str(p.resolve()), "query": query, "params": params,
                  "max_rows": max_rows, "response_format": response_format}
    try:
        permit = request_execution_consent(
            "sql_query.write",
            target_provider=lambda: {**execution_target(sandbox), "database": str(p.resolve())},
            parameters=parameters,
            detail=f"Run one write-enabled SQL statement on {p.name}.",
            effect="The statement may change rows or schema in the selected database.",
            review_items=review,
            parameters_provider=lambda: {"database": str(p.resolve()), "query": query,
                                         "params": params, "max_rows": max_rows,
                                         "response_format": response_format},
        )
    except ConsentDenied:
        return "ERROR: database write was not approved; no statement was run"
    except ApprovalCardError:
        return "ERROR: SQL, database target, or approval authority changed; review it again"
    try:
        with consume_operation_consent(permit):
            return _execute_sqlite_query(p, query, params, read_only, max_rows, response_format)
    except ApprovalCardError:
        return "ERROR: SQL, database target, or approval authority changed; review it again"


_REVIEW_CHUNK = 450
_MAX_REVIEW_CHARS = 3800


def _write_review_items(query: str, params: Any) -> list[str] | None:
    """Show the whole write statement and its bind values to the reviewer.

    Returns None when the statement cannot be shown in full: too long for the
    approval card, or containing text the card's redaction would mask.
    """
    import json

    # The card collapses whitespace, which would hide where a `--` comment
    # ends. Line breaks are shown as a visible \n (backslashes escaped first,
    # so a literal "\n" in the SQL cannot pass for one).
    visible = query.replace("\\", "\\\\").replace("\r", " \\r ").replace("\n", " \\n ")
    shown = [("Query", " ".join(visible.split()))]
    if params:
        shown.append(("Bind values", json.dumps(params, default=str)))
    if sum(len(text) for _, text in shown) > _MAX_REVIEW_CHARS:
        return None
    items = []
    for name, text in shown:
        if redact(text)[0] != text:
            return None
        chunks = [text[i:i + _REVIEW_CHUNK] for i in range(0, len(text), _REVIEW_CHUNK)]
        for n, chunk in enumerate(chunks, start=1):
            part = f" (part {n} of {len(chunks)})" if len(chunks) > 1 else ""
            items.append(f"{name}{part}: {chunk}")
    return items


def sql_query(sandbox=None) -> Tool:
    """Factory: builds the sql_query tool."""
    return Tool(
        name="sql_query",
        description=(
            "Run a SQL query against a local SQLite database file. "
            "Read-only by default (writes are rejected and the DB is opened "
            "read-only); pass read_only=false to allow INSERT/UPDATE/etc. "
            "Use `params` for ? placeholders, `max_rows` to cap output. "
            "Returns a formatted table."
        ),
        input_schema=_SQL_QUERY_SCHEMA,
        fn=lambda args: _run_sql_query(args, sandbox),
    )


def sql_query_read(sandbox=None) -> Tool:
    """A separate read seat; caller arguments can never enable writes."""
    schema = {**_SQL_QUERY_SCHEMA, "properties": {
        key: value for key, value in _SQL_QUERY_SCHEMA["properties"].items()
        if key != "read_only"
    }, "additionalProperties": False}

    def run(args):
        if "read_only" in args and args["read_only"] is not True:
            return "ERROR: sql_query_read cannot enable writes"
        return _run_sql_query({**args, "read_only": True}, sandbox)

    return Tool(
        name="sql_query_read",
        description=("Read/query/aggregate a workspace SQLite database. Always read-only; "
                     "no writes, schema changes or attached databases. Use params for "
                     "bindings and max_rows for bounded results."),
        input_schema=schema, fn=run,
    )
