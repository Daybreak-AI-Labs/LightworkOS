"""/metrics exposes per-principal spend so an SRE can see which user is
burning budget, not just the deployment-wide total."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    yield


def test_per_user_spend_gauge_for_auth_off_and_static_token_scrapes(monkeypatch):
    from maverick.quotas import UsageLedger
    UsageLedger().record("user:alice", 3.25, 100, 50)

    # Authentication off: the local operator sees who is spending.
    assert 'maverick_user_spend_dollars_today{principal="user:alice"} 3.2500' in client.get("/metrics").text

    # The static dashboard token is what a Prometheus scraper presents.
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "scrape-token")  # pragma: allowlist secret
    scraped = client.get("/metrics", headers={"Authorization": "Bearer scrape-token"})
    assert scraped.status_code == 200
    assert 'maverick_user_spend_dollars_today{principal="user:alice"} 3.2500' in scraped.text


def test_per_user_spend_gauge_only_for_a_named_installation_admin(monkeypatch):
    import maverick_dashboard.auth as auth
    from maverick.quotas import UsageLedger
    UsageLedger().record("user:alice", 3.25, 100, 50)
    UsageLedger().record("user:bob", 1.50, 10, 5)
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")

    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "operator")
    text = client.get("/metrics").text
    assert "maverick_user_spend_dollars_today" not in text
    assert "user:alice" not in text
    assert "user:bob" not in text

    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "admin")
    text = client.get("/metrics").text
    assert 'maverick_user_spend_dollars_today{principal="user:bob"} 1.5000' in text


def test_no_user_spend_gauge_when_empty():
    text = client.get("/metrics").text
    # No spend recorded -> the per-principal block is omitted (no empty noise).
    assert "maverick_user_spend_dollars_today{" not in text
