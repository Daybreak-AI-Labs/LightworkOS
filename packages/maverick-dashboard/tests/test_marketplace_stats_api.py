"""GET /api/v1/marketplace/stats — ratings stats over the local ledger."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    yield


def test_stats_empty():
    resp = client.get("/api/v1/marketplace/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 0 and body["average"] == 0.0


def test_stats_reflects_ledger():
    from maverick.marketplace.ratings import RatingsLedger
    led = RatingsLedger()
    led.rate("skills", "alpha", 5)
    led.rate("templates", "beta", 3)
    resp = client.get("/api/v1/marketplace/stats")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert body["distribution"]["5"] == 1
    assert body["top_rated"][0]["name"] == "alpha"
