"""The notification delivery page's data route, and the rule that no /api/v1
route is a health endpoint (/healthz, /livez and /readyz are the probes)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard.app import app

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    config.reset_config_cache()


def test_the_delivery_page_reads_its_status_from_the_delivery_status_route(client):
    status = client.get("/api/v1/notifications/delivery-status")
    assert status.status_code == 200, status.text
    assert "receipts" in status.json()
    assert status.headers["cache-control"] == "private, no-store"
    assert client.get("/api/v1/notifications/health").status_code == 404


def test_no_api_route_is_named_like_a_health_probe():
    from maverick_dashboard.app import app

    paths = [getattr(route, "path", "") for route in app.routes]
    assert {"/healthz", "/livez", "/readyz"} <= set(paths)
    assert [p for p in paths if p.startswith("/api/v1") and p.rstrip("/").endswith("/health")] == []
