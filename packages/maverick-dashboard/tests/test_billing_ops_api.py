"""Billing page: plan contents and Stripe billing status, preview and send."""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
BASE = "/api/v1/admin/billing-ops"
_BANNED = re.compile(r"\b(tenant|principal|payload|json|toml|webhook|sdk|entitlements?)\b|/api/v1|MAVERICK_",
                     re.IGNORECASE)


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT", "MAVERICK_CLIENT_ID", "MAVERICK_STRIPE_ENABLE",
                 "MAVERICK_STRIPE_SECRET_KEY", "MAVERICK_STRIPE_BILL_METERED"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    from maverick.tenant.registry import create_tenant
    create_tenant("acme", plan="pro", display_name="Acme")
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash_app._world_cache.clear()
    audit_writer._defaults.clear()


def _as(monkeypatch, role: str, who: str = "user:someone"):
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _audit_verbs(monkeypatch):
    from maverick.audit import writer
    seen: list[dict] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(payload)
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def test_billing_controls_need_an_installation_administrator(client, monkeypatch):
    _as(monkeypatch, "operator")
    assert client.get(BASE + "/plan", params={"workspace": "acme"}).status_code == 403
    assert client.get(BASE + "/stripe").status_code == 403
    assert client.get(BASE + "/stripe/preview", params={"workspace": "acme"}).status_code == 403
    assert client.post(BASE + "/stripe/sync", json={"workspace": "acme", "confirm": True,
        "review_id": "0" * 48, "sha256": "0" * 64}).status_code == 403


def test_plan_contents_come_from_the_plan_in_plain_words(client):
    data = client.get(BASE + "/plan", params={"workspace": "acme"}).json()
    assert data["plan"] == "Pro" and "Chat apps" in data["features"]
    assert data["daily_limit"] == "$100 a day" and data["tasks_at_once"] == "5"
    assert client.get(BASE + "/plan", params={"workspace": "ghost"}).status_code == 404


def test_stripe_status_preview_and_a_confirmed_send(client, monkeypatch):
    status = client.get(BASE + "/stripe").json()
    assert status["ready"] is False and "turned off" in status["summary"]
    assert not _BANNED.search(status["summary"])
    preview = client.get(BASE + "/stripe/preview", params={"workspace": "acme"}).json()
    assert preview["can_sync"] is False and "only a preview" in preview["summary"]
    bad = client.get(BASE + "/stripe/preview", params={"workspace": "acme", "since": "2026-02-01",
                                                       "until": "2026-01-01"})
    assert bad.status_code == 422
    body = {"workspace": "acme", "review_id": preview["review_id"], "sha256": preview["sha256"]}
    assert client.post(BASE + "/stripe/sync", json=body).status_code == 409
    off = client.post(BASE + "/stripe/sync", json={**body, "confirm": True})
    assert off.status_code == 409 and "retained stage receipt" in off.json()["detail"]
    retained = client.get(BASE + "/stripe/receipt", params={"workspace": "acme"}).json()["current"]
    assert retained["state"] == "prepared" and retained["dispatches"] == []

    from maverick import billing_stripe
    calls = []

    class FakeStripe:
        def create_customer(self, **kwargs):
            calls.append(("customer", kwargs))
            # The native durable intent is present before any provider call.
            from maverick_dashboard import billing_sync_reviews as reviews
            row = reviews.STORE.get(reviews._key("acme"))
            assert row["stages"]["customer"]["state"] == "pending"
            assert row["dispatches"][-1]["state"] == "pending"
            return {"id": "cus_123"}

        def list_subscriptions(self, customer_id):
            assert customer_id == "cus_123"
            return []

        def create_subscription(self, **kwargs):
            calls.append(("subscription", kwargs))
            return {"id": "sub_123", "status": "active"}

    provider = FakeStripe()
    monkeypatch.setattr(billing_stripe, "_client", lambda existing=None: existing if existing is not None else provider)
    monkeypatch.setattr(billing_stripe, "require_enabled", lambda: None)
    monkeypatch.setattr(billing_stripe, "enabled", lambda: True)
    monkeypatch.setattr(billing_stripe, "get_billing_stripe", lambda: {"prices": {"pro": "price_test"}, "currency": "usd"})
    fields = {"workspace": "acme", "since": "2026-01-01", "until": "2026-01-31"}
    response = client.get(BASE + "/stripe/preview", params=fields)
    assert response.status_code == 200, response.text
    preview = response.json()
    body = {**fields, "confirm": True, "review_id": preview["review_id"], "sha256": preview["sha256"]}
    assert client.post(BASE + "/stripe/sync", json={**body, "until": "2026-01-30"}).status_code == 409
    assert calls == []
    response = client.post(BASE + "/stripe/sync", json=body)
    assert response.status_code == 200, response.text
    sent = response.json()
    assert sent["state"] == "complete"
    assert sent["stages"]["customer"]["result"]["customer"] == "cus_123"
    assert sent["stages"]["subscription"]["state"] == "confirmed"
    assert [name for name, _ in calls] == ["customer", "subscription"]
    assert all(arguments["idempotency_key"] for _, arguments in calls)
    assert client.post(BASE + "/stripe/sync", json=body).json()["state"] == "complete"
    assert len(calls) == 2


def test_billing_page_shows_the_new_panels_to_administrators(client):
    page = client.get("/billing")
    assert page.status_code == 200
    for marker in ('id="plan-form"', 'id="stripe-form"', "/static/lightwork-billing-ops.js", "Preview the charge"):
        assert marker in page.text
    main = page.text.split('id="plan-contents"', 1)[1].split("<script", 1)[0]
    text = _html.unescape(re.sub(r"<[^>]+>", " ", main))
    assert not _BANNED.search(text)
    assert client.get("/static/lightwork-billing-ops.js").status_code == 200


def test_stripe_status_shows_where_stripe_sends_payment_notices(client, monkeypatch):
    facts = {row["label"]: row["value"] for row in client.get(BASE + "/stripe").json()["facts"]}
    assert facts["Payment notices from Stripe accepted"] == "No"
    assert facts["Address for Stripe payment notices"] == "http://127.0.0.1/webhook/stripe"
    monkeypatch.setenv("MAVERICK_STRIPE_WEBHOOK_SECRET", "whsec_synthetic123")  # pragma: allowlist secret
    facts = {row["label"]: row["value"] for row in client.get(BASE + "/stripe").json()["facts"]}
    assert facts["Payment notices from Stripe accepted"] == "Yes"
