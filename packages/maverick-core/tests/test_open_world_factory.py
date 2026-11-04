"""open_world() backend-selection factory.

Verifies the factory returns the SQLite WorldModel by default and the
PostgresWorldModel when the postgres backend is configured, without ever
opening a real Postgres connection.
"""
from __future__ import annotations

import importlib.util

import pytest

_HAS_PSYCOPG = importlib.util.find_spec("psycopg") is not None


def test_open_world_defaults_to_sqlite(tmp_path, monkeypatch):
    """No config / env -> SQLite WorldModel, using the given path."""
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))  # no config.toml here

    from maverick.world_model import WorldModel, open_world

    db = tmp_path / "world.db"
    world = open_world(db)
    try:
        assert isinstance(world, WorldModel)
        assert world.path == db
    finally:
        world.close()


def test_open_world_selects_postgres_when_configured(monkeypatch):
    """backend=postgres -> PostgresWorldModel, via the lazily-imported
    factory, without opening SQLite or a real PG connection."""
    import maverick.world_model_backends as backends

    sentinel = object()
    monkeypatch.setattr(backends, "is_postgres_configured", lambda: True)
    monkeypatch.setattr(backends, "open_postgres_world", lambda: sentinel)

    from maverick.world_model import open_world

    # path is ignored for the postgres branch.
    assert open_world() is sentinel


def test_open_world_no_path_floors_to_client(tmp_path, monkeypatch):
    """No explicit path + a bound client -> the canonical world resolves to
    that client's isolated tenants/<client>/world.db (not the shared root), so
    serve/runner/worker/gRPC/dashboard all open the SAME per-client DB."""
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    from maverick import client
    from maverick.world_model import DEFAULT_DB, open_world, world_for_tenant

    client.reset_client_cache()
    try:
        world = open_world()
        assert tmp_path / "tenants" in world.path.parents or "acme" in str(world.path)
        assert world.path != DEFAULT_DB
        # Same cached instance the dashboard/world_for_tenant hands out.
        assert world is world_for_tenant("acme")
    finally:
        client.reset_client_cache()


def test_open_world_no_path_unbound_uses_default(tmp_path, monkeypatch):
    """No client bound -> the legacy shared DEFAULT_DB (behaviour unchanged)."""
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    import maverick.world_model as wm
    from maverick import client

    default_db = tmp_path / "world.db"
    monkeypatch.setattr(wm, "DEFAULT_DB", default_db)
    client.reset_client_cache()
    try:
        world = wm.open_world()
        assert isinstance(world, wm.WorldModel)
        assert world.path == default_db
    finally:
        client.reset_client_cache()
        world.close()


@pytest.mark.skipif(not _HAS_PSYCOPG, reason="psycopg not installed")
def test_open_world_returns_real_postgres_model(monkeypatch):
    """End-to-end branch with psycopg present: open_world() builds a real
    PostgresWorldModel. The connection + migration are mocked so no live
    database is required."""
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", "postgres://test")

    from maverick.postgres_io import BoundedConnection
    from maverick.world_model_backends import PostgresWorldModel

    monkeypatch.setattr(PostgresWorldModel, "_migrate", lambda self: None)
    connection = object()
    connect_calls = []

    def connect(dsn, **kwargs):
        connect_calls.append((dsn, kwargs))
        return connection

    monkeypatch.setattr(BoundedConnection, "connect", connect)

    from maverick.world_model import open_world

    world = open_world()
    assert isinstance(world, PostgresWorldModel)
    assert world.conn is connection
    assert len(connect_calls) == 1
    assert connect_calls[0][0] == "postgres://test"
    assert connect_calls[0][1]["autocommit"] is False
    assert connect_calls[0][1]["io_timeout_seconds"] == world._io_timeout_seconds


def test_closing_no_path_tenant_world_is_ignored(tmp_path, monkeypatch):
    """Canonical no-path callers must not poison the shared tenant cache."""
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    import maverick.world_model as wm
    from maverick import client

    client.reset_client_cache()
    wm._tenant_worlds.clear()
    try:
        world = wm.open_world()
        assert world is wm.world_for_tenant("acme")
        wm.close_world_if_owned(world)

        reused = wm.open_world()
        assert reused is world
        goal_id = reused.create_goal("still open", "tenant cache survived close")
        assert reused.get_goal(goal_id) is not None
    finally:
        client.reset_client_cache()
        wm._tenant_worlds.clear()
