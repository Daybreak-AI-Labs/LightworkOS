"""/metrics exposes per-principal spend so an SRE can see which user is
burning budget, not just the deployment-wide total."""
from __future__ import annotations

import maverick_dashboard.app as app_mod
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


def test_installation_credential_does_not_enumerate_named_employee_spend():
    from maverick.quotas import UsageLedger
    UsageLedger().record("user:alice", 3.25, 100, 50)

    text = client.get("/metrics").text
    assert "maverick_user_spend_dollars_today" not in text
    assert "user:alice" not in text


def test_per_user_spend_gauge_hidden_from_non_admin(monkeypatch):
    from maverick.quotas import UsageLedger
    UsageLedger().record("user:alice", 3.25, 100, 50)
    UsageLedger().record("user:bob", 1.50, 10, 5)
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")

    text = client.get("/metrics").text
    assert "maverick_user_spend_dollars_today" not in text
    assert "user:alice" not in text
    assert "user:bob" not in text


def test_no_user_spend_gauge_when_empty():
    text = client.get("/metrics").text
    # No spend recorded -> the per-principal block is omitted (no empty noise).
    assert "maverick_user_spend_dollars_today{" not in text
