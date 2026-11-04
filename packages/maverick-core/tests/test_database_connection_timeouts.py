"""A database that accepts TCP but never speaks must not strand customer work."""
from __future__ import annotations

import socket
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

import pytest


@contextmanager
def _silent_database():
    stop = threading.Event()
    accepted = threading.Event()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(8)

        def serve():
            try:
                connection, _ = listener.accept()
            except (OSError, TimeoutError):
                return
            with connection:
                accepted.set()
                # Baseline failures still finish: close the fixture after the
                # assertion deadline instead of leaking a blocked worker.
                stop.wait(6)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1], accepted
        finally:
            stop.set()
            worker.join(9)
            assert not worker.is_alive(), "silent database fixture did not close"


@pytest.mark.parametrize("entry", ["tool", "world"])
def test_real_postgres_handshake_times_out_before_server_disconnect(monkeypatch, entry):
    psycopg = pytest.importorskip("psycopg")
    from maverick.world_model_backends import postgres

    if entry == "tool":
        pytest.importorskip("sqlalchemy")
    monkeypatch.setenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "2")
    monkeypatch.delenv("PGCONNECT_TIMEOUT", raising=False)
    monkeypatch.setattr(postgres, "_pool_size", lambda: 0)
    with _silent_database() as (port, accepted):
        started = time.monotonic()
        if entry == "tool":
            from maverick.tools.database_tool import database_tool

            monkeypatch.setenv("DATABASE_URL", f"postgresql+psycopg://fixture@127.0.0.1:{port}/fixture")
            result = database_tool().fn({"op": "query", "sql": "SELECT 1"})
            assert result.startswith("ERROR"), result
        else:
            with pytest.raises(psycopg.OperationalError):
                postgres.PostgresWorldModel(f"postgresql://fixture@127.0.0.1:{port}/fixture")
        elapsed = time.monotonic() - started
        assert accepted.is_set(), "the real driver never reached the fixture"
        assert elapsed < 5, f"unresponsive database held the call for {elapsed:.2f}s"


@pytest.mark.parametrize("raw,expected", [(None, 10), ("3", 3), ("90", 10), ("0", 10), ("-1", 10), ("bad", 10)])
@pytest.mark.parametrize("entry", ["tool", "world"])
def test_real_driver_receives_bounded_timeout_and_retains_operator_options(monkeypatch, raw, expected, entry):
    psycopg = pytest.importorskip("psycopg")
    from maverick.postgres_io import BoundedConnection
    from maverick.world_model_backends import postgres

    monkeypatch.delenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("PGCONNECT_TIMEOUT", raising=False)
    calls = []

    def connect(*args, **kwargs):
        calls.append(kwargs)
        raise psycopg.OperationalError("fixture inspected connection parameters")

    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(BoundedConnection, "connect", connect)
    query = "options=-c%20search_path%3Dcustomer%2Cpublic&application_name=customer-work"
    if raw is not None:
        query += "&connect_timeout=" + raw
    if entry == "tool":
        pytest.importorskip("sqlalchemy")
        from maverick.tools.database_tool import database_tool

        monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://fixture@127.0.0.1/fixture?" + query)
        assert database_tool().fn({"op": "query", "sql": "SELECT 1"}).startswith("ERROR")
    else:
        monkeypatch.setattr(postgres, "_pool_size", lambda: 0)
        with pytest.raises(psycopg.OperationalError):
            postgres.PostgresWorldModel("postgresql://fixture@127.0.0.1/fixture?" + query)
    assert len(calls) == 1
    assert calls[0]["connect_timeout"] == expected
    assert calls[0]["options"].startswith("-c search_path=customer,public")


def test_postgres_pool_and_reconnect_retain_the_bounded_timeout(monkeypatch):
    pytest.importorskip("psycopg")
    pool_module = pytest.importorskip("psycopg_pool")
    from maverick.postgres_io import BoundedConnection
    from maverick.world_model_backends import postgres

    monkeypatch.setenv("MAVERICK_PG_CONNECT_TIMEOUT_SECONDS", "4")
    monkeypatch.setenv("PGCONNECT_TIMEOUT", "30")
    monkeypatch.setenv("MAVERICK_PG_IO_TIMEOUT_SECONDS", ".2")
    monkeypatch.setattr(postgres, "_rls_enabled", lambda: False)
    monkeypatch.setattr(postgres.PostgresWorldModel, "_migrate", lambda _self: None)
    pools, direct = [], []

    def connect(*args, **kwargs):
        direct.append(kwargs)
        return SimpleNamespace(closed=False)

    def pool(*args, **kwargs):
        pools.append(kwargs)
        return SimpleNamespace()

    monkeypatch.setattr(BoundedConnection, "connect", connect)
    monkeypatch.setattr(pool_module, "ConnectionPool", pool)
    monkeypatch.setattr(postgres, "_pool_size", lambda: 2)
    postgres.PostgresWorldModel("postgresql://fixture@localhost/fixture")
    assert pools[0]["kwargs"]["connect_timeout"] == 4
    assert pools[0]["connection_class"] is BoundedConnection
    assert pools[0]["kwargs"]["io_timeout_seconds"] == .2
    monkeypatch.setattr(postgres, "_pool_size", lambda: 0)
    world = postgres.PostgresWorldModel("postgresql://fixture@localhost/fixture")
    monkeypatch.setenv("MAVERICK_PG_IO_TIMEOUT_SECONDS", ".4")
    world.conn.closed = True
    world._reconnect_if_broken()
    assert len(direct) == 2 and direct[0] == direct[1]
    assert direct[1]["connect_timeout"] == 4
    assert direct[1]["io_timeout_seconds"] == .2
