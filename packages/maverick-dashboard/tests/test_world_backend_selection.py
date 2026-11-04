"""_shared._world() honors the configured world-model backend.

Regression for the split-brain bug: the dashboard always opened SQLite, so a
Postgres deployment had it reading a stale local world.db while the runner /
channel server / gRPC API wrote Postgres.
"""
from __future__ import annotations

import maverick_dashboard._shared as shared


def test_world_returns_postgres_when_configured(monkeypatch):
    sentinel = object()
    calls = {"open_world": 0}

    def fake_open_world(*a, **k):
        calls["open_world"] += 1
        return sentinel

    monkeypatch.setattr(
        "maverick.world_model_backends.is_postgres_configured", lambda: True
    )
    monkeypatch.setattr("maverick.world_model.open_world", fake_open_world)
    shared._world_cache.clear()

    assert shared._world() is sentinel
    # cached: a second call does NOT re-open a fresh Postgres connection
    assert shared._world() is sentinel
    assert calls["open_world"] == 1


def test_world_uses_sqlite_when_postgres_not_configured(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "maverick.world_model_backends.is_postgres_configured", lambda: False
    )
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "w.db")
    monkeypatch.setattr("maverick.paths.current_tenant_id", lambda: None)
    shared._world_cache.clear()
    from maverick.world_model import WorldModel
    assert isinstance(shared._world(), WorldModel)
