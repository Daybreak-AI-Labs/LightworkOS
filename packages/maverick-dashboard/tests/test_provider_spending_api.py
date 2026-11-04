"""Actual administrator spending routes; all accounting and identity are synthetic."""
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import audit, client, config, workspace_recovery, world_model
from maverick import provider_cost_cap as cap
from maverick.paths import data_dir
from maverick_dashboard import provider_spending_api as api
from maverick_dashboard.app import app


@pytest.fixture
def browser(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_CLIENT_ID", "accounting-test")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    client.reset_client_cache()
    monkeypatch.setattr(cap, "caps_from_config", lambda: {"openai": 20.0})
    monkeypatch.setattr(cap, "_shared_world", lambda: None)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(workspace_recovery, "_key", lambda: bytes(range(32)))
    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    test = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    yield test
    config.reset_config_cache()
    client.reset_client_cache()


def headers(browser):
    value = browser.get(api.BASE).json()
    return {"X-Lightwork-Spending-Context": value["context"], "X-Lightwork-Expected-Tenant": value["expected_tenant"]}


def test_routes_render_and_exact_review_settles_without_retry(browser):
    held = cap.reserve("openai", 3, request_id="api-unknown")
    cap.settle(held, None)
    page = browser.get("/provider-spending")
    assert page.status_code == 200 and "Settle money set aside for a request" in page.text
    assert 'id="spend-review-pick"' in page.text and "PAR-" not in page.text
    assert browser.get("/static/lightwork-provider-spending.js").status_code == 200
    assert browser.get("/static/lightwork-provider-spending.css").status_code == 200
    context = headers(browser)
    payload = {"provider": "openai", "period": held.period, "receipt": held.request_id,
               "actual": 2.0, "evidence": "Final receipt INV-7 independently verified"}
    assert browser.post(api.BASE + "/hold-review", json=payload).status_code == 409
    response = browser.post(api.BASE + "/hold-review", json=payload, headers=context)
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "private, no-store"
    review = response.json()
    assert browser.get(api.BASE + "/review/" + review["id"], headers=context).json()["receipt"] == held.request_id
    # The unfinished review is offered in the page's list (no typed reference).
    listed = browser.get(api.BASE + "/reviews", headers=context)
    assert listed.status_code == 200 and [r["id"] for r in listed.json()["reviews"]] == [review["id"]]
    assert browser.get(api.BASE + "/reviews").status_code == 409  # context header required
    assert browser.post(api.BASE + "/apply", json={"review": review["id"], "confirm": False}, headers=context).status_code == 409
    applied = browser.post(api.BASE + "/apply", json={"review": review["id"], "confirm": True}, headers=context)
    assert applied.status_code == 200, applied.text
    assert cap.check("openai").spent == 2 and cap.check("openai").reserved == 0
    assert browser.post(api.BASE + "/apply", json={"review": review["id"], "confirm": True}, headers=context).json()["state"] == "completed"
    assert browser.get(api.BASE + "/reviews", headers=context).json()["reviews"] == []


def test_global_admin_denial_precedes_read_write_or_export(browser, monkeypatch):
    context = headers(browser)
    def denied(*_a):
        raise HTTPException(403, "Global administrator required")
    monkeypatch.setattr(api, "require_global_permission", denied)
    for route in (api.BASE, "/provider-spending", api.BASE + "/diagnostics", api.BASE + "/reviews"):
        assert browser.get(route).status_code == 403
    assert browser.post(api.BASE + "/export", headers=context).status_code == 403
    assert browser.post(api.BASE + "/import", content=b"{}", headers=context).status_code == 403


def test_actor_change_refuses_review_and_unavailable_diagnostics_do_not_expose_failed_bytes(browser, monkeypatch):
    context = headers(browser)
    monkeypatch.setattr(api, "_authorization_principal", lambda _: "user:other-admin")
    assert browser.post(api.BASE + "/export", headers=context).status_code == 409
    cap.record("openai", 4)
    failed = data_dir("provider_spend.json")
    failed.write_text("{private malformed accounting fixture", encoding="utf-8")
    response = browser.get(api.BASE + "/diagnostics")
    assert response.status_code == 200 and response.json()["available"] is False
    assert "private malformed" not in response.text
    assert failed.read_text(encoding="utf-8") == "{private malformed accounting fixture"


def test_non_ascii_spending_context_header_is_refused_as_changed_not_a_server_error(browser):
    stale = {"X-Lightwork-Spending-Context": "contéxt".encode()}
    assert browser.get(api.BASE, headers=stale).status_code == 409
    assert browser.post(api.BASE + "/export", headers=stale).status_code == 409


def test_import_requires_actual_isolation_and_rejects_oversize_before_staging(browser, monkeypatch):
    context = headers(browser)
    assert browser.post(api.BASE + "/import", content=b"{}", headers=context).status_code == 409
    monkeypatch.setattr(api.spending, "MAX_UPLOAD", 4)
    assert browser.post(api.BASE + "/import", content=b"12345", headers=context).status_code == 413


def test_prior_period_reservations_remain_accessible_and_invalid_period_is_rejected(browser):
    old = 1735689600  # UTC 2025-01-01, an earlier real period.
    held = cap.reserve("openai", 3, now=old, request_id="old-hold")
    cap.settle(held, None)
    response = browser.get(api.BASE, params={"period": held.period})
    assert response.status_code == 200
    row = response.json()["providers"][0]
    assert row["holds"][0]["id"] == "old-hold" and row["reserved"] == 3
    assert browser.get(api.BASE, params={"period": "2026-99-99"}).status_code == 409
    assert browser.get(api.BASE, params={"period": "../invalid"}).status_code == 422
