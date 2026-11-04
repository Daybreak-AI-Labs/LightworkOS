"""Savings dashboard: the client's own cost/value inputs + the money-saved
report, computed from real completed work in the world model.

Mutating /api/v1 requests carry a same-origin Origin (the CSRF contract).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_VALUE_HOURLY_RATE", raising=False)
    monkeypatch.delenv("MAVERICK_VALUE_HOURS", raising=False)
    config.reset_config_cache()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    yield
    config.reset_config_cache()
    api._world_cache.clear()


def _seed_completed_goal(cost=1.5, domain="finance_ap"):
    from maverick import world_model
    w = world_model.WorldModel(world_model.DEFAULT_DB)
    gid = w.create_goal(f"test goal {domain}", "seeded", domain=domain)
    ep = w.start_episode(gid)
    w.end_episode(ep, "seeded run", "success", cost_dollars=cost)
    return w


# ---- GET /api/v1/savings ---------------------------------------------------

def test_savings_report_zero_history_is_honest():
    resp = client.get("/api/v1/savings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["report"]["deliverables"] == 0
    assert body["report"]["saved"] == 0.0
    # Conservative defaults surface as the editable assumptions.
    assert body["assumptions"]["hourly_rate"] == 75.0
    assert body["assumptions"]["hours_per_task"] == 2.0


def test_savings_page_labels_assumptions_and_unverified_provider_prices():
    page = client.get("/savings")
    assert page.status_code == 200
    assert "Estimates based on your assumptions" in page.text
    assert "Counted, not estimated" not in page.text
    assert "not verified provider invoices" in page.text
    assert 'href="/outcome-pilots"' in page.text


def test_savings_report_uses_real_completed_work():
    _seed_completed_goal(cost=1.5, domain="finance_ap")
    resp = client.get("/api/v1/savings?days=30")
    assert resp.status_code == 200
    rep = resp.json()["report"]
    assert rep["deliverables"] == 1
    assert rep["agent_cost"] == 1.5
    # 1 deliverable x 2h x $75 = $150 human cost -> $148.50 saved.
    assert rep["human_cost"] == 150.0
    assert rep["saved"] == 148.5
    assert rep["by_department"][0]["department"] == "finance_ap"


def test_savings_days_is_clamped():
    assert client.get("/api/v1/savings?days=999999").status_code == 200
    assert client.get("/api/v1/savings?days=-5").status_code == 200


# ---- PUT /api/v1/savings/assumptions ----------------------------------------

def test_put_assumptions_persists_and_recomputes():
    _seed_completed_goal(cost=1.0, domain="legal_privacy")
    resp = client.put("/api/v1/savings/assumptions", json={
        "hourly_rate": 200.0,
        "hours_per_task": 0.5,
        "currency": "usd",
        "departments": {"legal_privacy": {"hourly_rate": 400.0}},
    })
    assert resp.status_code == 200, resp.text
    saved = resp.json()["assumptions"]
    assert saved["hourly_rate"] == 200.0
    assert saved["currency"] == "USD"
    assert saved["departments"]["legal_privacy"]["hourly_rate"] == 400.0
    # The override inherits the new global hours.
    assert saved["departments"]["legal_privacy"]["hours_per_task"] == 0.5

    rep = client.get("/api/v1/savings").json()["report"]
    # 1 deliverable x 0.5h x $400 (legal override) = $200 human cost.
    assert rep["human_cost"] == 200.0
    assert rep["saved"] == 199.0


def test_put_assumptions_null_department_clears_override():
    client.put("/api/v1/savings/assumptions", json={
        "departments": {"finance_ap": {"hourly_rate": 99.0}}})
    resp = client.put("/api/v1/savings/assumptions", json={
        "departments": {"finance_ap": None}})
    assert resp.status_code == 200
    assert "finance_ap" not in resp.json()["assumptions"]["departments"]


def test_put_assumptions_validates_input():
    assert client.put("/api/v1/savings/assumptions", json={"currency": "EUR"}).status_code == 422
    assert client.put("/api/v1/savings/assumptions",
                      json={"hourly_rate": -5}).status_code == 422
    assert client.put("/api/v1/savings/assumptions",
                      json={"currency": "12"}).status_code == 422
    assert client.put("/api/v1/savings/assumptions", json={
        "departments": {"x": {"hours_per_task": -1}}}).status_code == 422


def test_put_assumptions_requires_same_origin():
    # No Origin header on a mutating request -> the CSRF check rejects it.
    bare = TestClient(app, base_url="http://127.0.0.1")
    resp = bare.put("/api/v1/savings/assumptions", json={"hourly_rate": 10})
    assert resp.status_code in (403, 400)


# ---- /savings page -----------------------------------------------------------

def test_savings_page_renders_inputs_and_report():
    _seed_completed_goal(cost=2.0, domain="finance_ap")
    resp = client.get("/savings")
    assert resp.status_code == 200
    html = resp.text
    assert 'id="sv-assumptions"' in html
    assert "finance_ap" in html
    assert "Cost of an hour of a person's work" in html


def test_savings_page_empty_state():
    resp = client.get("/savings")
    assert resp.status_code == 200
    assert "No finished work in this period yet" in resp.text
