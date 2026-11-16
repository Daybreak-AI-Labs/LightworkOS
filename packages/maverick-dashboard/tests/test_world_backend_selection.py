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


def test_backend_refusal_is_a_plain_503_and_probes_still_answer(monkeypatch, tmp_path):
    """DR 4: a refusal to open the local database after Postgres is shown as a
    plain message (no paths), not a generic 500; /livez still answers."""
    from fastapi.testclient import TestClient
    from maverick.world_model import _record_world_backend
    from maverick_dashboard.app import app

    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr("maverick.world_model.DEFAULT_DB", tmp_path / "w.db")
    shared._world_cache.clear()
    _record_world_backend("postgres")
    client = TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False,
                        headers={"Origin": "http://127.0.0.1"})
    api = client.get("/api/v1/goals")
    assert api.status_code == 503
    assert api.json()["code"] == "records_database_refused"
    assert "maverick doctor" in api.json()["detail"] and str(tmp_path) not in api.text
    page = client.get("/", headers={"accept": "text/html"})
    assert page.status_code == 503 and "Postgres" in page.text
    assert client.get("/livez").status_code == 200
    health = client.get("/healthz")  # stays redacted: no reason, no paths
    assert "Postgres" not in health.text and str(tmp_path) not in health.text
    shared._world_cache.clear()
