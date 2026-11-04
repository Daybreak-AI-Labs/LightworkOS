"""Calling-thread ownership for established psycopg socket I/O.

Imported only when opening production PostgreSQL connections. Optional psycopg
is not required to import the core transaction facility or injected connectors.
"""
from __future__ import annotations

import math
import os
import time

import psycopg
from psycopg import waiting

DEFAULT_IO_TIMEOUT_SECONDS = 35.0
POLL_INTERVAL_SECONDS = .1


class PostgresIOTimeout(psycopg.OperationalError):
    """No definitive reply was received; never infer absent effects or replay."""

    outcome_unknown = True


def postgres_io_timeout_seconds(value=None) -> float:
    if value is None:
        # A present environment value is used as given (even empty, which is
        # refused below); only an absent one falls back to the dashboard's
        # ``[world_model] io_timeout_seconds``.
        value = os.environ.get("MAVERICK_PG_IO_TIMEOUT_SECONDS")
    if value is None:
        from .db_timeouts import configured

        value = configured("MAVERICK_PG_IO_TIMEOUT_SECONDS", "io_timeout_seconds",
                           DEFAULT_IO_TIMEOUT_SECONDS)
    try:
        seconds = float(value)
    except (ValueError, TypeError, OverflowError):
        seconds = float("nan")
    if isinstance(value, bool) or not math.isfinite(seconds) or not .1 <= seconds <= 3600:
        raise ValueError("MAVERICK_PG_IO_TIMEOUT_SECONDS must be finite and from 0.1 to 3600")
    return seconds


def _deadline_generator(generator, deadline, cleanup_state=None):
    """Keep psycopg's readiness protocol and return value; check every wake."""
    def check():
        if time.monotonic() >= deadline:
            raise PostgresIOTimeout("Postgres client I/O deadline exceeded; transaction outcome is unknown")

    primary = None
    try:
        check()
        state = next(generator)
        while True:
            check()
            ready = yield state
            check()
            state = generator.send(ready)
    except StopIteration as completed:
        return completed.value
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            generator.close()
        except BaseException as error:
            if cleanup_state is not None:
                cleanup_state["failure"] = error
            if primary is None:
                error.cleanup_incomplete = True
                raise
            primary.cleanup_incomplete = True


class BoundedConnection(psycopg.Connection):
    """A deadline per owned wait, including commit, rollback and pool reset.

    No watcher thread touches libpq. The caller holding psycopg's connection
    lock closes the failed socket itself; a pool must discard that connection.
    This is not a total transaction timer or a server-side cancellation promise.
    """

    _io_timeout_seconds = DEFAULT_IO_TIMEOUT_SECONDS

    @classmethod
    def connect(_cls, conninfo="", *, io_timeout_seconds=DEFAULT_IO_TIMEOUT_SECONDS, **kwargs):
        # Validate before even a connection handshake. Do not pass our setting
        # to libpq; preserve the caller's other connection parameters verbatim.
        seconds = postgres_io_timeout_seconds(io_timeout_seconds)
        connection = super().connect(conninfo, **kwargs)
        connection._io_timeout_seconds = seconds
        return connection

    def wait(self, gen, interval=POLL_INTERVAL_SECONDS):
        deadline = time.monotonic() + self._io_timeout_seconds
        cleanup_state = {}
        owned = _deadline_generator(gen, deadline, cleanup_state)
        primary = None
        closed_on_failure = False
        poll = min(POLL_INTERVAL_SECONDS, self._io_timeout_seconds)
        if isinstance(interval, (int, float)) and math.isfinite(interval) and interval > 0:
            poll = min(poll, interval)
        try:
            # An interval of zero means indefinite waiting in some drivers.
            # Always use our positive bounded readiness interval. Bypass the
            # default KeyboardInterrupt cancel-then-wait path: that could send
            # another network request while this transport is partitioned.
            return waiting.wait(owned, self.pgconn.socket, interval=poll)
        except BaseException as error:
            primary = error
            if isinstance(error, PostgresIOTimeout) or not isinstance(error, Exception) or getattr(error, "cleanup_incomplete", False):
                _close_owned(self, error)
                closed_on_failure = True
            raise
        finally:
            try:
                owned.close()
            except BaseException as error:
                cleanup_state["failure"] = error
            cleanup_error = cleanup_state.get("failure")
            if cleanup_error is not None:
                authoritative = primary if primary is not None else cleanup_error
                authoritative.cleanup_incomplete = True
                if not closed_on_failure:
                    _close_owned(self, authoritative)
                if primary is None:
                    raise cleanup_error


def _close_owned(connection, error):
    error.outcome_unknown = True
    try:
        connection.close()
    except BaseException:
        error.cleanup_incomplete = True
