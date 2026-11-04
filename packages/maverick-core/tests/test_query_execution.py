"""Owned SQLite/PG statement cancellation and transaction outcome qualification."""
from __future__ import annotations

import asyncio
import importlib
import json
import os
import sqlite3
import threading
import time
from contextlib import closing, nullcontext
from types import SimpleNamespace

import pytest
from maverick import query_execution
from maverick.budget import Budget, BudgetExceeded
from maverick.connector_attempts import bind_tool_budget
from maverick.query_execution import QueryExecution
from maverick.tools import ToolRegistry
from maverick.tools.database_tool import database_tool
from maverick.tools.sql_query import sql_query

database_module = importlib.import_module("maverick.tools.database_tool")
sqlite_module = importlib.import_module("maverick.tools.sql_query")
LONG_SQL = "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n + 1 FROM numbers WHERE n < 100000000) SELECT sum(n) FROM numbers"


@pytest.fixture(autouse=True)
def _approved_sql_writes(monkeypatch):
    monkeypatch.setattr(sqlite_module, "request_execution_consent", lambda *a, **kw: object())
    monkeypatch.setattr(sqlite_module, "consume_operation_consent", lambda permit: nullcontext())


@pytest.fixture(params=["sqlite", "sqlalchemy"])
def sqlite_call(request, monkeypatch, tmp_path):
    path = tmp_path / "deadline.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE items(value INTEGER)")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(path))
    if request.param == "sqlite":
        tool = sql_query(SimpleNamespace(workdir=tmp_path))
        args = {"database": str(path), "query": LONG_SQL, "read_only": True}
        module = sqlite_module
    else:
        pytest.importorskip("sqlalchemy")
        tool = database_tool()
        args = {"op": "query", "sql": LONG_SQL, "confirm": True}
        module = database_module
    return SimpleNamespace(path=path, tool=tool, args=args, module=module)


def capture_execution(monkeypatch, module):
    executions = []

    def factory(**kwargs):
        execution = QueryExecution(**kwargs)
        executions.append(execution)
        return execution

    monkeypatch.setattr(module, "QueryExecution", factory)
    return executions


def test_long_sqlite_query_stops_at_progress_deadline_and_releases_connection(sqlite_call, monkeypatch):
    # Initialize the real dialect/configuration before measuring statement
    # interruption. Admission expiry is covered independently below; a cold
    # SQLAlchemy dialect can otherwise consume the whole 50 ms deadline.
    key = "query" if sqlite_call.module is sqlite_module else "sql"
    warmup = json.loads(sqlite_call.tool.fn({**sqlite_call.args, key: "SELECT 1 AS value",
                                            "response_format": "json"}))
    assert warmup["rows"] == [[1]] and warmup["complete"]
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 0.05)
    executions = capture_execution(monkeypatch, sqlite_call.module)
    statements = []
    bind_sqlite = QueryExecution.bind_sqlite

    def observe_sqlite(self, connection):
        bound = bind_sqlite(self, connection)
        if bound:
            connection.set_trace_callback(statements.append)
        return bound

    monkeypatch.setattr(QueryExecution, "bind_sqlite", observe_sqlite)
    began = time.monotonic()
    result = sqlite_call.tool.fn(sqlite_call.args)
    assert time.monotonic() - began < 2
    assert LONG_SQL in statements
    if sqlite_call.module is sqlite_module:
        assert result.startswith("ERROR:") and "QueryDeadlineExceeded" in result
    else:
        # The generic SQL tool cannot prove that a WITH statement is read-only.
        # It can report a definite rollback or an unknown outcome, depending
        # on whether cancellation/rollback completed before the deadline.
        assert (
            result.startswith("ERROR:") and "transaction_status=rolled_back" in result
            or result.startswith("INDETERMINATE:")
            and "transaction_status=unknown" in result
        )
        assert "QueryDeadlineExceeded" in result
    assert executions[0].finished
    assert executions[0].cancellation_support == "sqlite_progress_and_interrupt"
    with closing(sqlite3.connect(sqlite_call.path, timeout=0.1)) as connection, connection:
        connection.execute("INSERT INTO items VALUES(1)")
        assert connection.execute("SELECT count(*) FROM items").fetchone()[0] == 1


@pytest.mark.parametrize("mutation", [False, True])
def test_sqlalchemy_engine_admission_deadline_prevents_connection_and_dispatch(tmp_path, monkeypatch, mutation):
    sqlalchemy = pytest.importorskip("sqlalchemy")
    path = tmp_path / "engine-admission.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE items(value INTEGER)")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + str(path))
    executions = capture_execution(monkeypatch, database_module)
    create_engine = sqlalchemy.create_engine
    connections = []
    disposals = []

    def initialize_after_deadline(*args, **kwargs):
        engine = create_engine(*args, **kwargs)
        connect, dispose = engine.connect, engine.dispose

        def observe_connect(*args, **kwargs):
            connections.append(True)
            return connect(*args, **kwargs)

        def observe_dispose(*args, **kwargs):
            disposals.append(True)
            return dispose(*args, **kwargs)

        monkeypatch.setattr(engine, "connect", observe_connect)
        monkeypatch.setattr(engine, "dispose", observe_dispose)
        # Deterministically represent initialization exhausting the absolute
        # deadline, without waiting or changing the application's clock.
        executions[0].deadline = time.monotonic() - 1
        return engine

    monkeypatch.setattr(sqlalchemy, "create_engine", initialize_after_deadline)
    result = database_tool().fn({"op": "query", "confirm": True,
                                 "sql": "INSERT INTO items VALUES (1)" if mutation else "SELECT 1"})
    assert result == ("ERROR: database query failed (QueryDeadlineExceeded); "
                      "transaction_status=not_started; no complete result was admitted")
    assert not connections and disposals == [True]
    assert executions[0].finished and executions[0].monitor_stopped
    assert executions[0].state == "not_started" and executions[0]._watcher is None
    assert executions[0].cancellation_support == "unsupported"
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT count(*) FROM items").fetchone()[0] == 0


@pytest.mark.parametrize("read_only", [True, False])
def test_sqlite_admission_deadline_returns_public_error_without_dispatch(tmp_path, monkeypatch, read_only):
    path = tmp_path / "admission.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE items(value INTEGER)")
    executions = []
    connections = []
    connect = sqlite3.connect

    def expired_execution(**kwargs):
        execution = QueryExecution(**kwargs)
        execution.deadline = time.monotonic() - 1
        executions.append(execution)
        return execution

    def observe_connect(*args, **kwargs):
        connections.append(args)
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite_module, "QueryExecution", expired_execution)
    monkeypatch.setattr(sqlite3, "connect", observe_connect)
    result = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(path), "read_only": read_only,
                             "query": "SELECT 1" if read_only else "INSERT INTO items VALUES (1)"})
    assert result == ("ERROR: database query failed (QueryDeadlineExceeded); "
                      "transaction_status=not_started; no complete result was admitted")
    assert not connections
    assert executions[0].finished and executions[0].monitor_stopped
    assert executions[0].state == "not_started" and executions[0]._watcher is None
    with closing(connect(path)) as connection:
        assert connection.execute("SELECT count(*) FROM items").fetchone()[0] == 0


@pytest.mark.parametrize("control", ["budget", "halt", "cancel"])
def test_sqlite_admission_preserves_control_stop(tmp_path, monkeypatch, control):
    from maverick.killswitch import Halted

    path = tmp_path / "admission-control.db"
    with closing(sqlite3.connect(path)):
        pass
    error = (Halted("stop", "test") if control == "halt" else
             {"budget": BudgetExceeded, "cancel": asyncio.CancelledError}[control]("stop"))
    connections = []
    connect = sqlite3.connect

    def stopped_execution(**kwargs):
        execution = QueryExecution(**kwargs)
        execution.request_cancel(error)
        return execution

    def observe_connect(*args, **kwargs):
        connections.append(args)
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite_module, "QueryExecution", stopped_execution)
    monkeypatch.setattr(sqlite3, "connect", observe_connect)
    with pytest.raises(type(error)) as raised:
        sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(path), "query": "SELECT 1"})
    assert raised.value is error
    assert not connections


def test_sqlite_async_cancellation_stops_worker_before_executor_join_returns(sqlite_call, monkeypatch):
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 30)
    executions = capture_execution(monkeypatch, sqlite_call.module)
    registry = ToolRegistry()
    registry.register(sqlite_call.tool)

    async def run():
        task = asyncio.create_task(registry.run(sqlite_call.tool.name, sqlite_call.args))
        for _ in range(200):
            if executions and executions[0].state == "running":
                break
            await asyncio.sleep(0.005)
        assert executions and executions[0].state == "running"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    began = time.monotonic()
    asyncio.run(run())  # Joins the actual driver worker in the default executor.
    assert time.monotonic() - began < 2
    assert executions[0].finished and not executions[0]._watcher.is_alive()


def test_expired_agent_budget_prevents_query_dispatch(sqlite_call):
    budget = Budget(max_wall_seconds=0.01)
    budget._started_monotonic -= 1
    with bind_tool_budget(budget), pytest.raises(BudgetExceeded):
        sqlite_call.tool.fn(sqlite_call.args)


def test_budget_expiring_during_sql_remains_a_budget_stop(sqlite_call):
    budget = Budget(max_wall_seconds=0.06)
    with bind_tool_budget(budget), pytest.raises(BudgetExceeded):
        sqlite_call.tool.fn(sqlite_call.args)


def test_halt_during_sql_reaches_full_control_watcher(sqlite_call, monkeypatch):
    from maverick import killswitch

    executions = capture_execution(monkeypatch, sqlite_call.module)
    registry = ToolRegistry()
    registry.register(sqlite_call.tool)

    async def run():
        task = asyncio.create_task(registry.run(sqlite_call.tool.name, sqlite_call.args))
        for _ in range(200):
            if executions and executions[0].state == "running":
                break
            await asyncio.sleep(0.005)
        assert executions and executions[0].state == "running"
        killswitch.halt("owned query fixture stop", source="test")
        with pytest.raises(killswitch.Halted):
            await task

    try:
        asyncio.run(run())
    finally:
        killswitch.clear()
    assert executions[0].finished


def test_sqlite_vm_progress_reuses_published_control_state(monkeypatch):
    execution = QueryExecution(mutation=False)
    checks = []
    monkeypatch.setattr(execution.invocation, "check", lambda: checks.append(True))
    for _ in range(100):
        assert execution._progress() == 0
    assert not checks
    execution.request_cancel()
    assert execution._progress() == 1
    execution.finish()


def test_cancel_before_commit_rolls_back_without_commit_call():
    calls = []
    connection = SimpleNamespace(commit=lambda: calls.append("commit"), rollback=lambda: calls.append("rollback"))
    with QueryExecution(mutation=True) as execution:
        execution.transactional = True
        execution.started()
        execution.request_cancel()
        with pytest.raises(asyncio.CancelledError):
            execution.commit(connection)
        execution.rollback(connection)
    assert calls == ["rollback"] and execution.state == "rolled_back" and execution.finished


def test_cancel_after_commit_ack_keeps_commit_state_and_never_replays():
    calls = []
    with QueryExecution(mutation=True) as execution:
        execution.transactional = True
        execution.started()

        def commit():
            calls.append("commit")
            execution.request_cancel()

        connection = SimpleNamespace(commit=commit, rollback=lambda: calls.append("rollback"))
        with pytest.raises(asyncio.CancelledError):
            execution.commit(connection)
        execution.rollback(connection)
    assert calls == ["commit"] and execution.state == "committed"


def test_lost_commit_ack_remains_unknown_even_when_later_rollback_returns():
    calls = []

    def commit():
        calls.append("commit")
        raise ConnectionError("secret connection diagnostic")

    connection = SimpleNamespace(commit=commit, rollback=lambda: calls.append("rollback"))
    with QueryExecution(mutation=True) as execution:
        execution.transactional = True
        execution.started()
        with pytest.raises(ConnectionError) as raised:
            execution.commit(connection)
        execution.rollback(connection)
        result = execution.failure(raised.value)
    assert execution.state == "unknown" and result.startswith("INDETERMINATE:")
    assert "secret" not in result and calls == ["commit", "rollback"]


def test_unsupported_driver_unknown_transaction_is_invalidated_after_execution_ends(monkeypatch):
    events = []

    class Connection:
        def execute(self, _statement):
            events.append("executed")
            raise ConnectionError("secret driver diagnostic")

        def rollback(self):
            events.append("rollback_returned")

        def invalidate(self):
            assert execution.monitor_stopped and not execution.finished
            events.append("invalidated")

    with QueryExecution(mutation=True) as execution:
        result = database_module._query_connection(Connection(), "UPDATE items SET value=2", 1, True, "text", execution)
    assert execution.cancellation_support == "unsupported"
    assert execution.state == "unknown" and result.startswith("INDETERMINATE:")
    assert events == ["executed", "rollback_returned", "invalidated"]
    assert "secret" not in result


def test_deadline_during_insert_select_rolls_back_all_sqlite_changes(tmp_path, monkeypatch):
    path = tmp_path / "write.db"
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.execute("CREATE TABLE items(value INTEGER)")
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 0.05)
    query = LONG_SQL.replace("SELECT sum(n) FROM numbers", "INSERT INTO items SELECT n FROM numbers")
    result = sql_query(SimpleNamespace(workdir=tmp_path)).fn({"database": str(path), "query": query, "read_only": False})
    assert result.startswith("ERROR:") and "rolled_back" in result
    with closing(sqlite3.connect(path)) as connection:
        assert connection.execute("SELECT count(*) FROM items").fetchone()[0] == 0


def _configure_postgres(request, monkeypatch):
    # Resolve the private fixture dynamically so failure reporting doesn't put
    # a credential-bearing DSN in pytest's displayed test parameter list.
    dsn = request.getfixturevalue("postgres_test_dsn")
    psycopg = pytest.importorskip("psycopg")
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from psycopg.conninfo import conninfo_to_dict

    params = conninfo_to_dict(dsn)
    url = sqlalchemy.engine.URL.create("postgresql+psycopg", username=params["user"],
                                       password=params.get("password"), host=params["host"],
                                       port=int(params["port"]), database=params["dbname"])
    monkeypatch.setenv("DATABASE_URL", url.render_as_string(hide_password=False))
    return psycopg, dsn


def test_native_postgres_statement_deadline_and_fresh_next_query(request, monkeypatch):
    _configure_postgres(request, monkeypatch)
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 0.15)
    executions = capture_execution(monkeypatch, database_module)
    began = time.monotonic()
    result = database_tool().fn({"op": "query", "sql": "SELECT pg_sleep(5)"})
    assert time.monotonic() - began < 2.5
    assert result.startswith("ERROR:") and executions[0].finished
    assert executions[0].cancellation_support == "postgres_statement_timeout_and_cancel_safe"
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 3)
    subsequent = json.loads(database_tool().fn({"op": "query", "sql": "SELECT 7 AS value", "response_format": "json"}))
    assert subsequent["rows"] == [[7]] and subsequent["complete"]


def test_native_postgres_cancellation_releases_actual_driver_and_owns_connection(request, monkeypatch):
    psycopg, dsn = _configure_postgres(request, monkeypatch)
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 20)
    executions = capture_execution(monkeypatch, database_module)
    registry = ToolRegistry()
    registry.register(database_tool())

    def active():
        with psycopg.connect(dsn) as connection:
            return connection.execute("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND state = 'active' AND pid <> pg_backend_pid() AND (query = 'SELECT pg_sleep(10)' OR query LIKE 'FETCH %%FROM %%')").fetchone()[0] == 1

    async def run():
        task = asyncio.create_task(registry.run("database", {"op": "query", "sql": "SELECT pg_sleep(10)"}))
        for _ in range(100):
            if await asyncio.to_thread(active):
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("owned fixture query did not reach PostgreSQL")
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    began = time.monotonic()
    asyncio.run(run())
    assert time.monotonic() - began < 3
    assert executions[0].finished and executions[0].cancel_attempted
    assert not executions[0]._watcher.is_alive()
    assert not active()


def test_finished_handle_cannot_cancel_a_future_driver():
    called = threading.Event()
    execution = QueryExecution(mutation=False)
    execution._cancel = called.set
    execution.finish()
    execution.request_cancel()
    assert not called.is_set() and not execution._stop.is_set()


def test_monitor_completion_does_not_pretend_connection_close_has_finished():
    execution = QueryExecution(mutation=False)
    execution.stop_monitor()
    assert execution.monitor_stopped and not execution.finished
    execution.finish()
    assert execution.finished


def test_native_postgres_read_uses_bounded_server_cursor(request, monkeypatch):
    psycopg, _dsn = _configure_postgres(request, monkeypatch)
    from sqlalchemy import event
    from sqlalchemy.engine import Engine

    cursors = []

    def inspect_cursor(_connection, cursor, statement, _parameters, _context, _many):
        if statement == "SELECT generate_series(1, 1000) AS value":
            cursors.append(isinstance(cursor, psycopg.ServerCursor))

    event.listen(Engine, "before_cursor_execute", inspect_cursor)
    try:
        result = json.loads(database_tool().fn({"op": "query", "sql": "SELECT generate_series(1, 1000) AS value",
                                               "limit": 1, "response_format": "json"}))
    finally:
        event.remove(Engine, "before_cursor_execute", inspect_cursor)
    assert cursors == [True]
    assert result["rows"] == [[1]] and result["fetched_rows"] == 2 and result["has_more"]


def test_psycopg2_statement_deadline_and_fresh_next_query(request, monkeypatch):
    """psycopg2 connections get the same server statement deadline and a real
    cancel request; before, a long statement ran past the query deadline."""
    dsn = request.getfixturevalue("postgres_test_dsn")
    pytest.importorskip("psycopg2")
    sqlalchemy = pytest.importorskip("sqlalchemy")
    from psycopg.conninfo import conninfo_to_dict

    params = conninfo_to_dict(dsn)
    url = sqlalchemy.engine.URL.create("postgresql+psycopg2", username=params["user"],
                                       password=params.get("password"), host=params["host"],
                                       port=int(params["port"]), database=params["dbname"])
    monkeypatch.setenv("DATABASE_URL", url.render_as_string(hide_password=False))
    # Qualify a statement deadline, not first-import/native-driver startup.
    # Warm the real dialect with its own fresh connection before the unchanged
    # 150ms budget; the measured call still opens and owns another connection.
    warm = json.loads(database_tool().fn({"op": "query", "sql": "SELECT 1 AS value",
                                          "response_format": "json"}))
    assert warm["rows"] == [[1]] and warm["complete"]
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 0.15)
    executions = capture_execution(monkeypatch, database_module)
    statements = []

    def capture_statement(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    sqlalchemy.event.listen(sqlalchemy.engine.Engine, "before_cursor_execute", capture_statement)
    began = time.monotonic()
    try:
        result = database_tool().fn({"op": "query", "sql": "SELECT pg_sleep(5)"})
    finally:
        sqlalchemy.event.remove(sqlalchemy.engine.Engine, "before_cursor_execute", capture_statement)
    assert time.monotonic() - began < 2.5
    assert "SELECT pg_sleep(5)" in statements
    assert result.startswith("ERROR:") and executions[0].finished
    assert executions[0].cancellation_support == "postgres_statement_timeout_and_cancel"
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 3)
    subsequent = json.loads(database_tool().fn({"op": "query", "sql": "SELECT 7 AS value", "response_format": "json"}))
    assert subsequent["rows"] == [[7]] and subsequent["complete"]


_SLOW_MYSQL_READ = ("SELECT COUNT(*) FROM information_schema.columns a, "
                    "information_schema.columns b, information_schema.columns c")


def _configure_mysql(monkeypatch):
    url = os.environ.get("MAVERICK_MYSQL_TEST_URL", "")
    if not url:
        pytest.skip("MAVERICK_MYSQL_TEST_URL not set (no MySQL/MariaDB test service)")
    pytest.importorskip("pymysql")
    pytest.importorskip("sqlalchemy")
    monkeypatch.setenv("DATABASE_URL", url)


def _mysql_read_is_stopped(monkeypatch):
    import sqlalchemy

    # Initialize the real dialect before measuring a statement's deadline.
    # The measured tool call still opens and owns a fresh native connection.
    warmup = json.loads(database_tool().fn({"op": "query", "sql": "SELECT 1 AS value",
                                           "response_format": "json"}))
    assert warmup["rows"] == [[1]] and warmup["complete"]
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 0.3)
    executions = capture_execution(monkeypatch, database_module)
    statements = []

    def capture_statement(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    sqlalchemy.event.listen(sqlalchemy.engine.Engine, "before_cursor_execute", capture_statement)
    began = time.monotonic()
    try:
        result = database_tool().fn({"op": "query", "sql": _SLOW_MYSQL_READ})
    finally:
        sqlalchemy.event.remove(sqlalchemy.engine.Engine, "before_cursor_execute", capture_statement)
    assert time.monotonic() - began < 5
    assert _SLOW_MYSQL_READ in statements
    assert result.startswith("ERROR:") and executions[0].finished
    assert executions[0].cancellation_support == "mysql_statement_timeout_and_kill_query"
    monkeypatch.setattr(query_execution, "query_timeout_seconds", lambda: 5)
    subsequent = json.loads(database_tool().fn({"op": "query", "sql": "SELECT 7 AS value",
                                                "response_format": "json"}))
    assert subsequent["rows"] == [[7]] and subsequent["complete"]


def test_mysql_statement_deadline_and_fresh_next_query(monkeypatch):
    """Before, a MySQL/MariaDB read ran on past the query deadline."""
    _configure_mysql(monkeypatch)
    _mysql_read_is_stopped(monkeypatch)


def test_mysql_kill_query_alone_stops_a_read(monkeypatch):
    _configure_mysql(monkeypatch)
    # No server-side limit: the cancel request alone must stop the statement.
    monkeypatch.setattr(QueryExecution, "mysql_timeout_statement",
                        lambda self, connection: "SELECT 1")
    _mysql_read_is_stopped(monkeypatch)


def test_mysql_server_limit_alone_stops_a_read(monkeypatch):
    _configure_mysql(monkeypatch)
    bind = QueryExecution.bind_mysql

    def unreachable():
        raise OSError("cancel connection refused")

    def bind_without_cancel(self, connection):
        bound = bind(self, connection)
        self._cancel = unreachable
        return bound

    # The cancel cannot connect: the server's own statement limit must hold.
    monkeypatch.setattr(QueryExecution, "bind_mysql", bind_without_cancel)
    _mysql_read_is_stopped(monkeypatch)
