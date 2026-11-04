"""Owned SQL execution deadline, driver cancellation and transaction outcome."""
from __future__ import annotations

import asyncio
import contextlib
import math
import sqlite3
import threading
import time

from .connector_attempts import CONTROL_ERRORS, current_invocation


class QueryDeadlineExceeded(TimeoutError):
    """The query's absolute admission deadline expired."""


def query_timeout_seconds() -> float:
    try:
        from .config import load_config

        raw = (load_config() or {}).get("query_limits", {}).get("timeout_seconds", 30)
        if isinstance(raw, bool):
            raise ValueError("boolean timeout")
        value = float(raw)
        if not math.isfinite(value) or value <= 0:
            raise ValueError("invalid timeout")
        return min(value, 300.0)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return 30.0


class QueryExecution:
    """A handle survives awaiter cancellation until its owned driver finishes.

    Only the worker closes the connection. Its watcher calls the cancellation
    operation of that exact connection and is joined before connection release.
    Unsupported drivers retain conservative outcome reporting, without a false
    claim that Python cancellation can interrupt their statement execution.
    """

    def __init__(self, *, mutation: bool):
        self.invocation = current_invocation()
        self.deadline = time.monotonic() + query_timeout_seconds()
        self.mutation = mutation
        self.state = "not_started"
        self.cancellation_support = "unsupported"
        self.transactional = False
        self._stop = threading.Event()
        self._done = threading.Event()
        self._wake = threading.Event()
        self._lock = threading.Lock()
        self._stop_error: BaseException | None = None
        self._cancel = None
        self._watcher = None
        self._clear_driver = None
        self._before_commit = None
        self.cancel_attempted = False
        self.cancel_acknowledged = False
        self.finished = False
        self.monitor_stopped = False

    def __enter__(self):
        self.invocation.register_cancel(self.request_cancel)
        try:
            self.check()
        except BaseException:
            self.invocation.unregister_cancel(self.request_cancel)
            raise
        return self

    def __exit__(self, *_exc):
        self.finish()

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if self.invocation.budget is not None:
            remaining = min(remaining, self.invocation.budget.remaining_wall())
        return max(0.0, remaining)

    def request_cancel(self, error=None):
        with self._lock:
            if self._done.is_set():
                return
            if self._stop_error is None:
                self._stop_error = error or asyncio.CancelledError("query invocation cancelled")
            self._stop.set()
        self._wake.set()

    def check(self):
        try:
            self.invocation.check()
            if self.remaining() <= 0:
                raise QueryDeadlineExceeded("query deadline reached")
        except BaseException as exc:
            self.request_cancel(exc)
            raise
        if self._stop.is_set():
            raise self._stop_error

    def _progress(self):
        # The watcher polls full budget/halt state every 50 ms. The hot SQLite
        # VM callback needs only the published stop and absolute deadline,
        # avoiding repeated config/filesystem/control checks every 1,000 ops.
        if self._stop.is_set():
            return 1
        if self.remaining() <= 0:
            self.request_cancel(QueryDeadlineExceeded("query deadline reached"))
            return 1
        return 0

    def _watch(self):
        while not self._done.is_set():
            try:
                self.check()
            except BaseException:
                break
            self._wake.wait(min(0.05, self.remaining()))
            self._wake.clear()
        if self._stop.is_set() and not self._done.is_set() and self._cancel is not None:
            self.cancel_attempted = True
            try:
                self._cancel()
            except Exception:
                pass  # Execution/transaction outcome remains unacknowledged.
            else:
                self.cancel_acknowledged = True

    def bind_sqlite(self, connection):
        if not isinstance(connection, sqlite3.Connection):
            return False
        self.check()
        self.cancellation_support = "sqlite_progress_and_interrupt"
        self.transactional = True
        connection.set_progress_handler(self._progress, 1000)
        def busy_timeout():
            milliseconds = max(1, math.ceil(self.remaining() * 1000))
            connection.execute(f"PRAGMA busy_timeout = {milliseconds}").close()
        busy_timeout()
        self._before_commit = busy_timeout
        self._cancel = connection.interrupt
        self._clear_driver = lambda: connection.set_progress_handler(None, 0)
        self._start_watcher()
        return True

    def bind_postgres(self, connection):
        try:
            import psycopg
        except ImportError:
            psycopg = None
        if (psycopg is not None and isinstance(connection, psycopg.Connection)
                and callable(getattr(connection, "cancel_safe", None))):
            self.check()
            self.cancellation_support = "postgres_statement_timeout_and_cancel_safe"
            self.transactional = not connection.autocommit
            self._cancel = lambda: connection.cancel_safe(timeout=2.0)
            self._start_watcher()
            return True
        return self._bind_psycopg2(connection)

    def _bind_psycopg2(self, connection):
        """psycopg2 has no ``cancel_safe``, but its ``cancel()`` is the
        thread-safe libpq cancel request, and the server-side
        ``statement_timeout`` bounds the statement either way."""
        try:
            import psycopg2.extensions
        except ImportError:
            return False
        if not isinstance(connection, psycopg2.extensions.connection):
            return False
        self.check()
        self.cancellation_support = "postgres_statement_timeout_and_cancel"
        self.transactional = not connection.autocommit
        self._cancel = connection.cancel
        self._start_watcher()
        return True

    def bind_mysql(self, connection):
        """pymysql (MySQL or MariaDB): a server-side statement limit plus a real
        cancel, which is ``KILL QUERY`` sent over a second, short-lived
        connection with the same credentials (the driver has no cancel)."""
        try:
            import pymysql.connections
        except ImportError:
            return False
        if not isinstance(connection, pymysql.connections.Connection):
            return False
        self.check()
        self.cancellation_support = "mysql_statement_timeout_and_kill_query"
        self.transactional = not connection.get_autocommit()
        thread_id = int(connection.thread_id())
        # Mirror the statement connection: SSL only when it required SSL (a
        # default pymysql connection merely prefers it, and passing its context
        # would make SSL mandatory for the cancel connection).
        ssl_required = getattr(connection, "_ssl_required", connection.ssl)

        def kill_query():
            import pymysql

            other = pymysql.connect(
                host=connection.host, port=connection.port, user=connection.user,
                password=connection.password, unix_socket=connection.unix_socket,
                ssl=connection.ctx if ssl_required else None,
                bind_address=connection.bind_address, connect_timeout=2,
                read_timeout=5, write_timeout=5)
            try:
                with other.cursor() as cursor:
                    cursor.execute(f"KILL QUERY {thread_id:d}")
            finally:
                other.close()

        self._cancel = kill_query
        self._start_watcher()
        return True

    def mysql_timeout_statement(self, connection) -> str:
        """The session statement limit for the remaining time (MariaDB takes
        seconds for any statement; MySQL takes milliseconds, for reads)."""
        milliseconds = max(1, math.ceil(self.remaining() * 1000))
        if "mariadb" in str(connection.get_server_info()).lower():
            return f"SET SESSION max_statement_time = {milliseconds / 1000:.3f}"
        return f"SET SESSION max_execution_time = {milliseconds}"

    def _start_watcher(self):
        self._watcher = threading.Thread(target=self._watch, name="lightwork-query-cancel", daemon=True)
        self._watcher.start()

    def started(self):
        self.check()
        self.state = "running"

    def commit(self, connection):
        self.check()
        if self._before_commit is not None:
            self._before_commit()
        with self._lock:
            if self._stop.is_set():
                raise self._stop_error
            self.state = "committing"
        try:
            connection.commit()
        except BaseException:
            self.state = "unknown"
            raise
        self.state = "committed"
        self.check()  # A subsequent stop cannot relabel acknowledged commit.

    def rollback(self, connection):
        if self.state == "committed":
            return
        was_unknown = self.state in {"committing", "unknown"}
        try:
            connection.rollback()
        except Exception:
            self.state = "unknown"
        else:
            self.state = ("unknown" if was_unknown or (self.mutation and not self.transactional)
                          else "rolled_back" if self.mutation else "read_only")

    def failure(self, error):
        # A driver interrupt is an implementation consequence of the stop;
        # preserve the original Budget/Halt/CancelledError at the tool boundary.
        try:
            self.check()
        except QueryDeadlineExceeded:
            error = QueryDeadlineExceeded()
        except (*CONTROL_ERRORS, asyncio.CancelledError):
            raise
        if isinstance(error, (*CONTROL_ERRORS, asyncio.CancelledError)):
            raise error
        if not isinstance(error, Exception):
            raise error
        if self.mutation and self.state in {"unknown", "committed", "running", "committing"}:
            return ("INDETERMINATE: database operation may have committed; reconcile before retrying. "
                    f"transaction_status={self.state}; failure_type={type(error).__name__[:80]}")
        return (f"ERROR: database query failed ({type(error).__name__[:80]}); "
                f"transaction_status={self.state}; no complete result was admitted")

    def stop_monitor(self):
        """Join the driver canceller before closing its connection lease."""
        self._done.set()
        self._wake.set()
        self.invocation.unregister_cancel(self.request_cancel)
        if self._watcher is not None:
            # Supported cancellation itself is bounded (SQLite interrupt or
            # psycopg cancel_safe timeout); never detach it onto a reused lease.
            self._watcher.join()
        if self._clear_driver is not None:
            with contextlib.suppress(Exception):
                self._clear_driver()
            self._clear_driver = None
        self._before_commit = None
        self.monitor_stopped = True

    def finish(self):
        """Acknowledge completion only after the caller released its driver."""
        self.stop_monitor()
        self.finished = True


def sqlalchemy_driver(connection):
    """Public SQLAlchemy pool proxy API; never introspect another connection."""
    proxy = getattr(connection, "connection", None)
    return getattr(proxy, "driver_connection", None)
