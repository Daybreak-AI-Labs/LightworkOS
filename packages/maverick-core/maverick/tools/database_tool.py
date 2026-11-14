"""Relational database tool — SQL via SQLAlchemy (any driver).

One connector for PostgreSQL, MySQL/MariaDB, SQL Server, CockroachDB, Oracle,
etc. through a SQLAlchemy connection URL. Simple read statements run directly;
non-read or ambiguous SQL (INSERT/UPDATE/DELETE/DDL, CTE, EXPLAIN) requires
confirm=true.

Auth: ``DATABASE_URL`` (a SQLAlchemy URL), e.g.
  postgresql+psycopg://user:pass@host:5432/db  # pragma: allowlist secret
  mysql+pymysql://user:pass@host/db  # pragma: allowlist secret
  mssql+pyodbc://user:pass@host/db?driver=ODBC+Driver+18+for+SQL+Server  # pragma: allowlist secret
  cockroachdb://user@host:26257/db
The matching driver (psycopg / pymysql / pyodbc / ...) must be installed.

The schema also advertises a model-facing ``url`` arg, but it is honored only
when a capability ``allow_hosts`` is granted or the operator opts in with
``MAVERICK_DATABASE_ALLOW_URL_ARG=1`` / ``[tools] database_allow_url_arg =
true`` (off by default) -- otherwise an agent could pick any reachable
database server, credentials embedded in the URL. A model-supplied
``sqlite:`` URL is refused unconditionally either way: it has no host for
``allow_hosts`` to scope, and an agent has no legitimate need to open its own
local database file (including this deployment's own world.db).
``DATABASE_URL`` is operator-set, so it bypasses the model-URL opt-in. An active
capability host grant still limits its destinations.

ops:
  - query(sql, url, limit, confirm)
"""
from __future__ import annotations

import contextlib
import fnmatch
import ipaddress
import logging
import math
import os
import re
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .._envparse import coerce_bool, is_truthy
from ..connector_attempts import CONTROL_ERRORS
from ..db_timeouts import postgres_connect_timeout
from ..query_execution import QueryExecution, sqlalchemy_driver
from ..query_results import QueryResult, render_effect
from . import Tool, as_bool
from .sql_safety import has_unconfirmed_statement_separator

log = logging.getLogger(__name__)

# Conservative upper bound on rows materialized into memory per call, matching
# the caps the sibling data tools enforce (sql_query, dynamodb, mongodb).
# Override with MAVERICK_DATABASE_MAX_ROWS for legitimate large pulls.
_DEFAULT_MAX_ROWS = 1000


def _max_rows() -> int:
    try:
        from ..env_setting import env_or_config

        cap = int(env_or_config("MAVERICK_DATABASE_MAX_ROWS", "tools", "database_max_rows")
                  or _DEFAULT_MAX_ROWS)
    except ValueError:
        cap = _DEFAULT_MAX_ROWS
    return max(1, cap)

_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["query"]},
        "sql": {"type": "string"},
        "url": {"type": "string", "description": "SQLAlchemy URL (else DATABASE_URL)."},
        "limit": {"type": "integer", "description": "max rows shown (default 50)."},
        "response_format": {"type": "string", "enum": ["text", "json"],
                            "description": "Readable preview (default) or structured bounded result."},
        "confirm": {"type": "boolean", "description": "required for non-read SQL."},
    },
    "required": ["op", "sql"],
}

# PRAGMA is not generally read-only: SQLite accepts assignments such as
# ``PRAGMA user_version = 7`` and ``PRAGMA journal_mode=WAL``. Gate every
# PRAGMA rather than maintaining an engine/version-specific safe subset.
_READ_KEYWORDS = {"select", "show", "describe", "desc", "values"}
_TOKEN_RE = re.compile(r"[a-zA-Z_]+")
_SELECT_EFFECT_RE = re.compile(
    r"\b(?:into|for\s+(?:no\s+key\s+)?update|lock\s+in\s+share\s+mode|"
    r"pg_advisory_(?:xact_)?lock|pg_try_advisory_(?:xact_)?lock|nextval|setval|"
    r"get_lock|release_lock|\w*sleep|benchmark|lo_\w+|dblink\w*|"
    r"pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_read_\w+|"
    r"pg_ls_\w+|set_config|load_file)\b",
    re.IGNORECASE,
)
# MySQL's DESC/DESCRIBE is also EXPLAIN (``DESC ANALYZE DELETE ...`` runs the
# DELETE), so only the plain "describe one table" form counts as a read.
_DESCRIBE_TABLE_RE = re.compile(
    r"^\s*desc(?:ribe)?\s+[\w.`\"\[\]]+(?:\s+[\w`\"%]+)?\s*;?\s*$",
    re.IGNORECASE,
)


def _leading_keyword(sql: str) -> str:
    """Return the first SQL keyword after leading whitespace/comments/parentheses."""
    idx = 0
    length = len(sql)
    while idx < length:
        while idx < length and sql[idx].isspace():
            idx += 1
        if idx < length and sql[idx] == "(":
            idx += 1
            continue
        if sql.startswith("--", idx):
            newline = sql.find("\n", idx + 2)
            if newline == -1:
                return ""
            idx = newline + 1
            continue
        if sql.startswith("/*", idx):
            # MySQL/MariaDB executable comments (`/*! ... */` and versioned
            # forms like `/*!80000 ... */`) are parsed and executed by the
            # server, so treating them as ordinary comments can hide writes.
            if (
                sql.startswith("/*!", idx)
                or sql[idx:idx + 4].lower() == "/*m!"
            ):
                return ""
            end = sql.find("*/", idx + 2)
            if end == -1:
                return ""
            idx = end + 2
            continue
        break
    match = _TOKEN_RE.match(sql, idx)
    return match.group(0).lower() if match else ""


def _is_read_sql(sql: str) -> bool:
    """Conservative read gate for statements that do not require confirm=true.

    CTE-prefixed and EXPLAIN-prefixed statements are intentionally not treated
    as read-only here: PostgreSQL, SQL Server, and MySQL-family databases can
    execute mutating statements behind those prefixes (for example
    ``WITH ... DELETE`` or ``EXPLAIN ANALYZE``).
    """
    keyword = _leading_keyword(sql)
    if keyword not in _READ_KEYWORDS:
        return False
    # A leading SELECT is not proof of purity. At minimum, SELECT ... INTO can
    # create tables or write OUTFILE/DUMPFILE, FOR UPDATE acquires write-class
    # locks, and several built-ins mutate sequence/advisory-lock/server state.
    # Gate those known forms. Governed connector execution treats *all* SQL as
    # consequential because a generic lexical parser cannot prove stored or
    # volatile functions side-effect-free across dialects.
    # VALUES (setval(...)) has the same effects, so every read keyword is
    # checked, not only SELECT.
    if keyword in ("desc", "describe") and not _DESCRIBE_TABLE_RE.match(sql):
        return False
    return _SELECT_EFFECT_RE.search(sql) is None


def _database_allow_url_arg_enabled() -> bool:
    """Whether a model-supplied ``url`` arg is honored at all (default off).

    ``allow_hosts`` is a real additional constraint when it is granted, but
    its ABSENCE must not mean "any URL is fine": with no capability grant
    the tool otherwise accepted an agent-chosen SQLAlchemy URL unconditionally,
    letting a prompt-injected agent point it at any reachable database server
    (credentials embedded in the URL) or, via ``sqlite:``, at the deployment's
    OWN world.db/audit tables. Off by default; enable with
    ``MAVERICK_DATABASE_ALLOW_URL_ARG=1`` or ``[tools] database_allow_url_arg
    = true`` for a deployment that deliberately wants agents picking their own
    connection string. ``DATABASE_URL`` (operator-set) is unaffected either way.
    """
    env = os.environ.get("MAVERICK_DATABASE_ALLOW_URL_ARG", "").strip()
    if env:
        return is_truthy(env)
    try:
        from ..config import load_config
        return coerce_bool((load_config() or {}).get("tools", {}).get(
            "database_allow_url_arg"))
    except Exception:  # pragma: no cover -- config never blocks the gate
        return False


def _model_supplied_url_denial(url: str, allow_hosts: tuple[str, ...]) -> str | None:
    """Extra gate applied ONLY to a url the model supplied via the ``url``
    arg -- never to the operator-configured ``DATABASE_URL`` fallback."""
    try:
        scheme = urlsplit(url).scheme.split("+", 1)[0].lower()
    except ValueError:
        scheme = ""
    if scheme == "sqlite":
        return (
            "⚠ DENIED: a model-supplied database url may not use sqlite: "
            "(local file access has no host for allow_hosts to scope, and "
            "an agent has no legitimate need to pick its own database file "
            "-- including this deployment's own world.db). Configure "
            "DATABASE_URL instead if a sqlite connection is genuinely needed."
        )
    if not allow_hosts and not _database_allow_url_arg_enabled():
        return (
            "⚠ DENIED: a model-supplied database url requires either a "
            "capability allow_hosts grant or [tools] database_allow_url_arg "
            "= true (off by default). Configure DATABASE_URL for an "
            "operator-set connection instead."
        )
    return None


def _denial(host: str) -> str:
    return (
        f"⚠ DENIED by capability policy: database URL host {host!r} is not "
        "granted by allow_hosts. The tool was not executed."
    )


def _connection_hosts(value: str) -> list[str]:
    """Split explicit host lists without letting a glob span two destinations."""
    hosts = []
    for item in value.split(","):
        item = item.strip()
        if not item or any(char in item for char in (";", "=", "\\", "\x00")):
            raise ValueError("database destination is empty or indirect")
        try:
            ipaddress.ip_address(item)
        except ValueError:
            parsed = urlsplit("//" + item)
            if (
                not parsed.hostname or parsed.username is not None
                or parsed.path or parsed.query or parsed.fragment
            ):
                raise ValueError("database destination is not a host") from None
            # Accessing port validates a supplied port without including it in
            # the hostname grant (including bracketed IPv6 destinations).
            if parsed.port is not None and parsed.port == 0:
                raise ValueError("database destination port is invalid") from None
            hosts.append(parsed.hostname)
        else:
            hosts.append(item.lower())
    return hosts


def _host_denial(url: str, allow_hosts: tuple[str, ...]) -> str | None:
    if not allow_hosts:
        return None
    try:
        split = urlsplit(url)
        params = parse_qs(split.query, keep_blank_values=True)
        # These parameters can select a different destination through an
        # opaque driver DSN, service definition, or local socket. A hostname
        # label cannot authorize that indirection under a host-scoped grant.
        indirect = {
            "dsn", "filedsn", "odbc_connect", "service", "servicefile", "unix_socket",
            "unix_sock", "read_default_file", "read_default_group",
        }.intersection(name.lower() for name in params)
        if indirect:
            return _denial("indirect destination: " + ", ".join(sorted(indirect)))
        authority = split.netloc.rsplit("@", 1)[-1]
        # SQLAlchemy interprets a pyodbc authority without a database as a
        # client-side DSN name, even when it looks like a granted hostname.
        dialect = split.scheme.lower()
        if (
            (dialect == "mssql" or dialect.endswith(("+pyodbc", "+aioodbc")))
            and (authority or "host" in params) and not split.path.lstrip("/")
            and "database" not in params
        ):
            return _denial("indirect destination: ODBC DSN")
        # The Oracle dialect similarly treats a bare authority as a local
        # TNS alias unless an explicit SID or service selects hostname mode.
        if (
            dialect.split("+", 1)[0] == "oracle"
            and not split.path.lstrip("/")
            and not any(params.get("service_name", ()))
        ):
            return _denial("indirect destination: Oracle TNS alias")
        candidates = _connection_hosts(authority) if authority else []
        # libpq's hostaddr overrides host for the actual network address;
        # SQLAlchemy also accepts repeated/comma-separated host entries.
        destination_params = {
            "host", "hostaddr", "server", "address", "addr", "failover_partner",
        }
        for name, values in params.items():
            if name.lower() in destination_params:
                for value in values:
                    candidates.extend(_connection_hosts(value))
    except ValueError:
        return _denial("<unparseable>")
    if not candidates:
        return _denial("<none>")
    for cand in candidates:
        if not any(fnmatch.fnmatch(cand, pat) for pat in allow_hosts):
            return _denial(cand)
    return None


def _postgres_connect_args(url: str) -> dict[str, int]:
    """Bound libpq handshakes; other SQLAlchemy drivers have different options."""
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {
        "postgresql", "postgresql+psycopg", "postgresql+psycopg2",
        "postgresql+psycopg2cffi", "cockroachdb", "cockroachdb+psycopg2",
    }:
        return {}
    values = parse_qs(parsed.query, keep_blank_values=True).get("connect_timeout", [None])
    if len(values) != 1:
        raise ValueError("database connect_timeout must be specified only once")
    return {"connect_timeout": postgres_connect_timeout(values[0])}


def _prepare_query_driver(conn, execution):
    raw = sqlalchemy_driver(conn)
    if execution.bind_sqlite(raw):
        # Own the transaction even for SQLite DDL. The legacy sqlite3 driver
        # does not automatically BEGIN for DDL or SELECT through SQLAlchemy.
        if not raw.in_transaction:
            conn.exec_driver_sql("BEGIN").close()
    elif execution.bind_postgres(raw):
        milliseconds = max(1, math.ceil(execution.remaining() * 1000))
        local = "LOCAL " if execution.transactional else ""
        conn.exec_driver_sql(f"SET {local}statement_timeout = {milliseconds}").close()
    elif execution.bind_mysql(raw):
        conn.exec_driver_sql(execution.mysql_timeout_statement(raw)).close()


def _query_connection(conn, sql, limit, needs_confirm, response_format, execution):
    from sqlalchemy import text

    result = None
    try:
        _prepare_query_driver(conn, execution)
        execution.started()
        if (not needs_confirm and _leading_keyword(sql) == "select" and execution.transactional
                and execution.cancellation_support == "postgres_statement_timeout_and_cancel_safe"):
            # Qualified psycopg SELECTs use a server cursor so the driver does
            # not first buffer an unbounded result before our sentinel fetch.
            conn = conn.execution_options(yield_per=limit + 1)
        result = conn.execute(text(sql))
        if result.returns_rows:
            cols = list(result.keys())
            rows = result.fetchmany(limit + 1)
            result.close()
            result = None
            execution.check()
            if needs_confirm:
                execution.commit(conn)
            else:
                conn.rollback()
                execution.state = "read_only"
            data = QueryResult.from_rows(cols, rows, row_limit=limit,
                                         transaction_status=execution.state,
                                         cancellation_support=execution.cancellation_support)
            execution.check()
            return data.render(response_format=response_format)
        affected = result.rowcount
        result.close()
        result = None
        if needs_confirm:
            execution.commit(conn)
        else:
            conn.rollback()
            execution.state = "read_only"
        execution.check()
        return render_effect(affected, execution.state, execution.cancellation_support,
                             response_format=response_format)
    except BaseException as exc:
        if result is not None:
            with contextlib.suppress(Exception):
                result.close()
        execution.rollback(conn)
        return execution.failure(exc)
    finally:
        execution.stop_monitor()  # Join cancellation before releasing this connection.
        if execution.state == "unknown":
            with contextlib.suppress(Exception):
                conn.invalidate()


def _execute_query(sql, url, limit, needs_confirm, response_format):
    from sqlalchemy import create_engine

    engine = None
    with QueryExecution(mutation=needs_confirm) as execution:
        try:
            engine = create_engine(url, connect_args=_postgres_connect_args(url))
            execution.check()
            with engine.connect() as conn:
                return _query_connection(conn, sql, limit, needs_confirm, response_format, execution)
        except BaseException as exc:
            return execution.failure(exc)
        finally:
            if engine is not None:
                # This per-call engine is never published or reused. Dispose
                # only after its owned driver/cancellation execution has ended.
                execution.stop_monitor()
                with contextlib.suppress(Exception):
                    engine.dispose()


def _op_query(sql: str, url_arg: str, limit: int, confirm: bool,
              allow_hosts: tuple[str, ...] = (), response_format: str = "text") -> str:
    if not sql:
        return "ERROR: query requires sql"
    if response_format not in {"text", "json"}:
        return "ERROR: response_format must be text or json"
    # A leading SELECT does not make a ``;``-stacked string a read: the server
    # executes every statement in one execute(), so confirm is required when a
    # statement separator could smuggle a write behind the read.
    needs_confirm = (not _is_read_sql(sql)) or has_unconfirmed_statement_separator(sql)
    if needs_confirm and not confirm:
        return "DRY RUN: non-read SQL (INSERT/UPDATE/DELETE/DDL). Re-run with confirm=true."
    url_arg = url_arg.strip()
    url = (url_arg or os.environ.get("DATABASE_URL", "")).strip()
    if not url:
        return "ERROR: database requires a SQLAlchemy URL via the url arg or DATABASE_URL."
    if url_arg:
        denial = _model_supplied_url_denial(url_arg, allow_hosts)
        if denial:
            return denial
    denial = _host_denial(url, allow_hosts)
    if denial:
        return denial
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        return ("ERROR: sqlalchemy not installed. Run: pip install sqlalchemy plus the "
                "driver (psycopg / pymysql / pyodbc / ...).")
    limit = max(1, min(limit, _max_rows()))
    return _execute_query(sql, url, limit, needs_confirm, response_format)


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        if op == "query":
            return _op_query((args.get("sql") or "").strip(),
                             (args.get("url") or "").strip(),
                             int(args.get("limit") or 50),
                             as_bool(args.get("confirm")),
                             tuple(args.get("_capability_allow_hosts") or ()),
                             args.get("response_format", "text"))
    except CONTROL_ERRORS:
        raise
    except Exception as e:  # noqa: BLE001
        return f"ERROR: database request failed ({type(e).__name__[:80]})"
    return f"ERROR: unknown op {op!r}"


def database_tool() -> Tool:
    return Tool(
        name="database",
        description=(
            "Relational DB SQL via SQLAlchemy (PostgreSQL, MySQL/MariaDB, SQL "
            "Server, CockroachDB, Oracle, ...). op: query (simple reads run; "
            "writes/DDL/CTE/EXPLAIN need confirm=true). Auth: DATABASE_URL "
            "(SQLAlchemy URL) or the url arg; the matching driver must be installed."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )
