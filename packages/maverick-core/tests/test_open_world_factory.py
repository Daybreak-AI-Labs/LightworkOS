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


def test_unreadable_config_after_postgres_refuses_local_fallback(tmp_path, monkeypatch):
    """DR 4: once Postgres was used, a config that cannot be read must not
    silently open a local database; the refusal names the file and line. A
    machine that only ever used the local database still opens it."""
    import maverick.world_model_backends as backends
    from maverick.world_model import WorldBackendUnreadable, WorldModel, open_world

    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    home = tmp_path / ".maverick"
    home.mkdir(exist_ok=True)
    config = home / "config.toml"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config))
    monkeypatch.setattr(backends, "open_postgres_world", lambda: "pg-world")
    import maverick.world_model as wm
    from maverick import client

    # A client bound in the environment needs no config to open its local
    # world, which is the path that used to fall back silently.
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "acme")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(wm, "_tenant_worlds", type(wm._tenant_worlds)())
    client.reset_client_cache()

    # Local-only history: a broken config still opens the local database.
    config.write_text('[budget\nmax_dollars = 1\n', encoding="utf-8")
    assert isinstance(open_world(), WorldModel)

    config.write_text('[world_model]\nbackend = "postgres"\n', encoding="utf-8")
    assert open_world() == "pg-world"
    config.write_text('[world_model]\nbackend = "postgres"\n[budget\n', encoding="utf-8")
    with pytest.raises(WorldBackendUnreadable) as refused:
        open_world()
    assert str(config) in str(refused.value) and "line 3" in str(refused.value)

    # Settings that are readable but silent about the backend do not switch
    # to the local database either, and the marker stays Postgres.
    config.write_text('[budget]\nmax_dollars = 1\n', encoding="utf-8")
    with pytest.raises(WorldBackendUnreadable) as silent:
        open_world()
    assert 'backend = "sqlite"' in str(silent.value) and "MAVERICK_WORLD_BACKEND=sqlite" in str(silent.value)
    with pytest.raises(WorldBackendUnreadable):
        open_world()

    # Unknown spellings are errors, never a fallback.
    config.write_text('[world_model]\nbackend = "postgresql"\n', encoding="utf-8")
    with pytest.raises(WorldBackendUnreadable) as unknown:
        open_world()
    assert "postgresql" in str(unknown.value) and str(config) in str(unknown.value)
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgresql")
    with pytest.raises(WorldBackendUnreadable) as typo:
        open_world()
    assert "MAVERICK_WORLD_BACKEND" in str(typo.value) and '"sqlite"' in str(typo.value)

    # A deliberate choice still works: the environment names the backend...
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "sqlite")
    assert isinstance(open_world(), WorldModel)
    # ...or readable settings choose the local database.
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND")
    config.write_text('[world_model]\nbackend = "sqlite"\n', encoding="utf-8")
    assert isinstance(open_world(), WorldModel)
    config.write_text('[budget]\nmax_dollars = 1\n', encoding="utf-8")
    assert isinstance(open_world(), WorldModel)  # the deliberate switch was recorded
    client.reset_client_cache()
    for world in wm._tenant_worlds.values():
        world.close()
