"""Bounded, opt-in shared connection leases with no statement/write replay."""
from __future__ import annotations

import atexit
import contextlib
import hashlib
import json
import math
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

from .db_timeouts import postgres_connection_kwargs


@dataclass
class _PoolEntry:
    pool: Any
    active: int = 0


_LOCK = threading.RLock()
_POOLS: dict[str, _PoolEntry] = {}
_CLOSED = False
_CLOSER: threading.Thread | None = None
_CLOSE_FAILED = False
_MAX_POOLS = 4


def validate_pool_settings(size: object, timeout: object) -> tuple[int, float]:
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= 32:
        raise ValueError("governed-record pool_size must be an integer from 0 to 32")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise ValueError("governed-record pool_timeout_seconds must be from 0.1 to 60")
    seconds = float(timeout)
    if not math.isfinite(seconds) or not .1 <= seconds <= 60:
        raise ValueError("governed-record pool_timeout_seconds must be from 0.1 to 60")
    return size, seconds


def validate_pool_min_size(min_size: object, size: int) -> int:
    """Connections kept open while idle: an integer from 0 to ``size``.

    Default 1: with ``min_size=0`` the first request after an idle period paid
    the TCP + TLS + auth connect on the request path.
    """
    if isinstance(min_size, bool) or not isinstance(min_size, int) or min_size < 0:
        raise ValueError("governed-record pool_min_size must be an integer from 0 to pool_size")
    return min(min_size, size)


def _reset_connection(connection: Any) -> None:
    """Remove any accidental session tenant binding before another lease."""
    # SET LOCAL in the authority transaction is the primary boundary. Reset the
    # session value as well; a failed reset makes psycopg_pool discard the socket.
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config('maverick.tenant', '', false)")
    connection.commit()


def _shared_pool(dsn: str, kwargs: dict, size: int, timeout: float, io_timeout: float,
                 min_size: int = 0) -> _PoolEntry:
    from psycopg_pool import ConnectionPool

    from .postgres_io import BoundedConnection

    # No plaintext credential is placed in cache keys or pool diagnostic names.
    key = hashlib.sha256(json.dumps([dsn, kwargs, size, timeout, io_timeout, min_size],
                                    sort_keys=True).encode()).hexdigest()
    with _LOCK:
        if _CLOSED:
            raise RuntimeError("Postgres connection admission is closed")
        entry = _POOLS.get(key)
        if entry is None:
            if len(_POOLS) >= _MAX_POOLS:
                raise RuntimeError("Postgres shared pool identity capacity reached")
            entry = _PoolEntry(ConnectionPool(
                dsn, min_size=min_size, max_size=size, max_waiting=64,
                timeout=timeout, reconnect_timeout=timeout,
                connection_class=BoundedConnection,
                kwargs={**kwargs, "io_timeout_seconds": io_timeout}, reset=_reset_connection,
                name="governed-" + key[:12], open=True,
            ))
            _POOLS[key] = entry
        return entry


class PostgresTransactions:
    """Each lease owns its transaction; optional pools are shared by authority.

    A caller-owned injected connector keeps its historic autocommit-only
    signature, remains unpooled and is responsible for its own transport policy.
    Production psycopg connections always use the shared bounded libpq policy.
    """

    def __init__(self, dsn: str, *, pool_size: int = 0,
                 pool_timeout_seconds: float = 5,
                 pool_min_size: int = 1,
                 connect: Callable[..., Any] | None = None) -> None:
        self._dsn = dsn
        self._size, self._timeout = validate_pool_settings(pool_size, pool_timeout_seconds)
        self._min_size = validate_pool_min_size(pool_min_size, self._size)
        if connect is not None and self._size:
            raise ValueError("injected Postgres connectors cannot join a shared pool")
        self._connect_override = connect
        self._kwargs: dict | None = None
        self._io_timeout: float | None = None
        self._options_lock = threading.Lock()

    def _connection_options(self) -> dict:
        # Compute once, retaining the exact capped options on later acquisition.
        with self._options_lock:
            if self._kwargs is None:
                from .postgres_io import postgres_io_timeout_seconds
                timeout = postgres_io_timeout_seconds()
                kwargs = postgres_connection_kwargs(self._dsn)
                self._kwargs, self._io_timeout = kwargs, timeout
        return dict(self._kwargs)

    def connect(self) -> Any:
        if self._connect_override is not None:
            return self._connect_override(self._dsn, autocommit=False)
        from .postgres_io import BoundedConnection
        kwargs = self._connection_options()
        return BoundedConnection.connect(self._dsn, io_timeout_seconds=self._io_timeout, **kwargs)

    @contextlib.contextmanager
    def _connection(self) -> Iterator[Any]:
        if not self._size:
            connection = self.connect()
            try:
                yield connection
            finally:
                with contextlib.suppress(Exception):
                    connection.close()
            return
        kwargs = self._connection_options()
        entry = _shared_pool(self._dsn, kwargs, self._size, self._timeout, self._io_timeout,
                             self._min_size)
        with _LOCK:
            if _CLOSED:
                raise RuntimeError("Postgres connection admission is closed")
            entry.active += 1
        connection = None
        primary_failure = None
        try:
            connection = entry.pool.getconn(timeout=self._timeout)
            yield connection
        except BaseException as exc:
            primary_failure = exc
            raise
        finally:
            try:
                if connection is not None:
                    try:
                        entry.pool.putconn(connection)
                    except BaseException:
                        with contextlib.suppress(BaseException):
                            connection.close()
                        if primary_failure is None:
                            raise
            finally:
                with _LOCK:
                    entry.active -= 1

    @contextlib.contextmanager
    def transaction(self) -> Iterator[Any]:
        with self._connection() as connection:
            cursor = None
            try:
                cursor = connection.cursor()
                yield cursor
                # A block that caught a database error and carried on leaves the
                # transaction aborted; COMMIT then silently becomes ROLLBACK in
                # PostgreSQL. Report it instead of returning apparent success.
                status = getattr(getattr(connection, "info", None), "transaction_status", None)
                if getattr(status, "name", None) == "INERROR":
                    raise TransactionAborted(
                        "the transaction was aborted by an earlier error; nothing was committed")
                connection.commit()
            except BaseException:
                try:
                    connection.rollback()
                except BaseException:
                    # Never return an indeterminate/broken transaction to reuse.
                    with contextlib.suppress(BaseException):
                        connection.close()
                raise
            finally:
                if cursor is not None:
                    with contextlib.suppress(Exception):
                        cursor.close()


class TransactionAborted(RuntimeError):
    """A transaction block completed after its transaction had failed."""


def close_postgres_pools(*, timeout: float = 5, wait: bool = True) -> None:
    """Seal admission immediately; own all pool cleanup under one wait budget."""
    global _CLOSED, _CLOSER, _CLOSE_FAILED
    seconds = float(timeout)
    if not math.isfinite(seconds) or seconds < 0:
        raise ValueError("Postgres shutdown timeout must be finite and nonnegative")
    with _LOCK:
        _CLOSED = True
        if _CLOSER is None and _POOLS:
            entries = tuple(_POOLS.values())

            def close_all() -> None:
                global _CLOSE_FAILED
                for entry in entries:
                    try:
                        # psycopg_pool's close delegates to Thread.join. Join
                        # workers fully in this owned thread; a finite library
                        # close can return with live workers. Only the caller's
                        # wait uses the shared shutdown deadline. A driver that
                        # refuses this timeout leaves explicit failed ownership.
                        entry.pool.close(timeout=None)
                    except BaseException:
                        with _LOCK:
                            _CLOSE_FAILED = True

            _CLOSER = threading.Thread(target=close_all, name="governed-pg-close", daemon=True)
            try:
                _CLOSER.start()
            except BaseException:
                # Keep failed ownership visible; do not report cleanup complete.
                _CLOSE_FAILED = True
                raise
        closer = _CLOSER
    if wait and seconds:
        deadline = time.monotonic() + seconds
        if closer is not None and closer.ident is not None:
            closer.join(timeout=max(0., deadline - time.monotonic()))
        while postgres_pools_pending() and time.monotonic() < deadline:
            time.sleep(min(.01, max(0., deadline - time.monotonic())))


def postgres_pools_pending() -> bool:
    with _LOCK:
        return bool(_CLOSE_FAILED or (_CLOSER and _CLOSER.is_alive())
                    or any(entry.active for entry in _POOLS.values()))


def open_postgres_pools() -> None:
    """Reopen only after a prior lifecycle has fully relinquished ownership."""
    global _CLOSED, _CLOSER
    with _LOCK:
        if not _CLOSED:
            return
        if postgres_pools_pending():
            raise RuntimeError("prior Postgres pool cleanup is still pending")
        _POOLS.clear()
        _CLOSER = None
        _CLOSED = False


atexit.register(close_postgres_pools, timeout=1)
