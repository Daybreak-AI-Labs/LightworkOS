"""GET /metrics: the platform's own operational counters, bearer-gated."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, runtime_metrics, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    runtime_metrics.reset_for_tests()
    yield
    config.reset_config_cache()
    runtime_metrics.reset_for_tests()


def test_metrics_render_http_traffic_by_route_template():
    assert client.get("/healthz").status_code in (200, 503)
    response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "# TYPE lightwork_http_requests_total counter" in body
    # Route TEMPLATES, not raw paths, keep cardinality bounded.
    assert 'route="/healthz"' in body
    assert "lightwork_http_request_seconds_total" in body
    assert "lightwork_uptime_seconds" in body


def test_metrics_respect_the_dashboard_bearer(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "metrics-bearer-1")
    anon = TestClient(app, base_url="http://127.0.0.1")
    assert anon.get("/metrics").status_code == 401
    ok = anon.get("/metrics",
                  headers={"Authorization": "Bearer metrics-bearer-1"})
    assert ok.status_code == 200
