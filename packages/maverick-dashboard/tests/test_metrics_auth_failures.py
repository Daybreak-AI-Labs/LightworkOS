"""/metrics exposes an auth-failure counter so a bad-token / credential-stuffing
flood is alertable (it previously produced only 401s, invisible to Prometheus)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import auth_metrics
    auth_metrics.reset()
    yield
    auth_metrics.reset()


def _client() -> TestClient:
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_auth_failure_series_always_present():
    # Emitted even at zero so an alert rule has a series to watch from boot.
    text = _client().get("/metrics").text
    assert "# TYPE maverick_auth_failures_total counter" in text
    assert 'maverick_auth_failures_total{reason="none"} 0' in text


def test_bad_bearer_token_increments_counter(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "right-token")  # noqa: S105
    c = _client()
    # A wrong bearer on a gated route is rejected AND tallied.
    r = c.get("/api/v1/goals", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401
    r2 = c.get("/api/v1/goals", headers={"Authorization": "Bearer alsowrong"})
    assert r2.status_code == 401
    from maverick_dashboard import auth_metrics
    assert auth_metrics.auth_failure_counts().get("bad_token") == 2
    # The metric surfaces the tally (drop the token so /metrics is reachable).
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    text = _client().get("/metrics").text
    assert 'maverick_auth_failures_total{reason="bad_token"} 2' in text


def test_scim_bad_token_increments_counter(monkeypatch):
    monkeypatch.setenv("MAVERICK_SCIM_TOKEN", "scim-secret")  # noqa: S105
    c = _client()
    r = c.get("/scim/v2/Users", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401
    from maverick_dashboard import auth_metrics
    assert auth_metrics.auth_failure_counts().get("scim_bad_token") == 1
