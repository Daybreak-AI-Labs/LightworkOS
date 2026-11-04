"""Functional robustness: reject empty fact keys at the API boundary."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


@pytest.mark.parametrize("key", ["", "   "])
def test_set_fact_rejects_empty_key(monkeypatch, tmp_path, key):
    _prep(monkeypatch, tmp_path)
    r = _client().post(
        "/api/v1/facts", json={"key": key, "value": "v"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 400


def test_set_fact_accepts_valid_key(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    c = _client()
    r = c.post(
        "/api/v1/facts", json={"key": "city", "value": "Lisbon"},
        headers={"Origin": "http://127.0.0.1"},
    )
    assert r.status_code == 204
    assert c.get("/api/v1/facts").json().get("city") == "Lisbon"
