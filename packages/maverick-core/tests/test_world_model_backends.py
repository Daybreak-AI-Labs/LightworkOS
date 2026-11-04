"""Tests for world-model backend selection and the Postgres adapter
(maverick.world_model_backends).
"""
from __future__ import annotations

import importlib.util

import pytest

# ---------- Postgres world-model ----------

_HAS_PSYCOPG = importlib.util.find_spec("psycopg") is not None


class _CapturingCursor:
    def __init__(self):
        self.calls = []

    def execute(self, sql, params=()):
        self.calls.append((" ".join(sql.split()), tuple(params)))

    def fetchall(self):
        return []

    def fetchone(self):
        return (0, 0, 0, 0)


class _CursorTx:
    def __init__(self, cursor):
        self.cursor = cursor

    def __enter__(self):
        return self.cursor

    def __exit__(self, *exc):
        return False


def _postgres_model_with_cursor(cursor):
    from maverick.world_model_backends import PostgresWorldModel

    world = PostgresWorldModel.__new__(PostgresWorldModel)
    world._tx = lambda: _CursorTx(cursor)
    return world


def test_postgres_is_configured_default_false(monkeypatch):
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-for-this-test")
    from maverick.world_model_backends import is_postgres_configured
    # No env, no config -> False.
    assert is_postgres_configured() is False


def test_postgres_is_configured_via_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    from maverick.world_model_backends import is_postgres_configured
    assert is_postgres_configured() is True


def test_postgres_is_configured_via_config(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    cfg_dir = tmp_path / ".maverick"
    cfg_dir.mkdir()
    (cfg_dir / "config.toml").write_text(
        '[world_model]\nbackend = "postgres"\n'
    )
    from maverick.world_model_backends import is_postgres_configured
    assert is_postgres_configured() is True


def test_postgres_without_dep_raises_actionable():
    """If psycopg isn't installed, instantiation raises a clear error."""
    if _HAS_PSYCOPG:
        pytest.skip("psycopg IS installed; can't test the missing-dep path")
    from maverick.world_model_backends import PostgresWorldModel
    with pytest.raises(ImportError, match="packages/maverick-core\\[postgres\\]"):
        PostgresWorldModel(dsn="postgres://test")


def test_postgres_requires_dsn(monkeypatch):
    """No DSN -> actionable RuntimeError before loading connection I/O."""
    import sys

    monkeypatch.delenv("MAVERICK_PG_DSN", raising=False)
    if not _HAS_PSYCOPG:
        # Preserve the optional-driver check without requiring a real driver.
        import types
        fake = types.ModuleType("psycopg")

        def _connect(*args, **kwargs):
            raise NotImplementedError

        fake.connect = _connect
        monkeypatch.setitem(sys.modules, "psycopg", fake)

    from maverick.world_model_backends import PostgresWorldModel
    # A missing DSN must be reported without importing the socket I/O layer,
    # even when the real psycopg package happens to be installed.
    monkeypatch.setitem(sys.modules, "maverick.postgres_io", None)
    with pytest.raises(RuntimeError, match="MAVERICK_PG_DSN"):
        PostgresWorldModel(dsn=None)


def test_postgres_schema_constants_exist():
    """The migration SQL list is present and has the expected tables."""
    from maverick.world_model_backends.postgres import SCHEMA
    joined = " ".join(SCHEMA)
    for tbl in ("goals", "episodes", "goal_events", "facts"):
        assert f"CREATE TABLE IF NOT EXISTS {tbl}" in joined


def test_postgres_recall_candidates_are_tenant_scoped(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    token = set_tenant("tenant-a")
    try:
        cursor = _CapturingCursor()
        _postgres_model_with_cursor(cursor).candidate_goals(False, limit=7)
    finally:
        reset_tenant(token)

    sql, params = cursor.calls[-1]
    assert "FROM goals WHERE" in sql
    assert "tenant_id = %s" in sql
    assert "owner = %s" in sql
    assert params == ("", "tenant-a", 7)


def test_postgres_spend_reads_join_tenant_scoped_goals(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    token = set_tenant("tenant-a")
    try:
        cursor = _CapturingCursor()
        world = _postgres_model_with_cursor(cursor)
        world.total_spend()
        world.list_episodes(limit=30)
    finally:
        reset_tenant(token)

    total_sql, total_params = cursor.calls[0]
    list_sql, list_params = cursor.calls[1]
    assert "FROM episodes e JOIN goals g ON g.id = e.goal_id" in total_sql
    assert "g.tenant_id = %s" in total_sql
    assert total_params == ("tenant-a",)
    assert "FROM episodes e JOIN goals g ON g.id = e.goal_id" in list_sql
    assert "g.tenant_id = %s" in list_sql
    assert list_params == ("tenant-a", 30)


def test_postgres_goal_child_reads_join_tenant_scoped_goals(monkeypatch):
    from maverick.paths import reset_tenant, set_tenant

    monkeypatch.setenv("MAVERICK_STRICT_TENANT_ISOLATION", "1")
    token = set_tenant("tenant-a")
    try:
        cursor = _CapturingCursor()
        world = _postgres_model_with_cursor(cursor)
        world.goal_events(42)
        world.list_attachments(42)
    finally:
        reset_tenant(token)

    events_sql, events_params = cursor.calls[0]
    attachments_sql, attachments_params = cursor.calls[1]
    assert "FROM goal_events ge JOIN goals g ON g.id = ge.goal_id" in events_sql
    assert "g.tenant_id = %s" in events_sql
    assert events_params == (42, 0, "tenant-a", 200)
    assert "FROM attachments a JOIN goals g ON g.id = a.goal_id" in attachments_sql
    assert "g.tenant_id = %s" in attachments_sql
    assert attachments_params == (42, "tenant-a")
