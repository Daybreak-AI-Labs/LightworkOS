"""POST /webhook/stripe: Stripe payment notices, signed or refused.

The route authenticates with Stripe's own signature (``Stripe-Signature``,
checked by ``maverick.billing_stripe.verify_webhook`` against the Stripe
message signing secret), refuses everything while no secret is set, caps the
body size, ignores a repeated event, and records every accepted event in the
activity record before ``handle_event`` applies it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

SECRET = "whsec_synthetictestsecret123"  # pragma: allowlist secret
PATH = "/webhook/stripe"


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick_dashboard import app as dash_app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY",
                 "MAVERICK_STRIPE_WEBHOOK_SECRET"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    dash_app._issue_webhook_seen.clear()

    from maverick import billing_stripe
    handled: list[dict] = []
    monkeypatch.setattr(billing_stripe, "handle_event",
                        lambda event: handled.append(event) or {"handled": True,
                                                                "tenant": "acme",
                                                                "action": "downgrade",
                                                                "billing_status": "past_due",
                                                                "type": event["type"]})
    import maverick.audit as audit
    rows: list[dict] = []
    monkeypatch.setattr(audit, "audit_event",
                        lambda kind, **payload: rows.append({"kind": kind, **payload}) or True)
    yield TestClient(dash_app.app, base_url="http://127.0.0.1"), handled, rows
    config.reset_config_cache()


def _event(event_id="evt_1"):
    return json.dumps({"id": event_id, "type": "invoice.payment_failed",
                       "data": {"object": {"customer": "cus_1", "metadata": {}}}}).encode()


def _signed(body: bytes, secret: str = SECRET, ts: int | None = None) -> dict:
    ts = int(time.time()) if ts is None else ts
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return {"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"}


def test_refused_while_no_secret_is_set(env):
    http, handled, _rows = env
    body = _event()
    r = http.post(PATH, content=body, headers=_signed(body))
    assert r.status_code == 503 and "signing secret" in r.json()["detail"]
    assert handled == []


def test_unsigned_and_badly_signed_events_are_refused(env, monkeypatch):
    http, handled, rows = env
    monkeypatch.setenv("MAVERICK_STRIPE_WEBHOOK_SECRET", SECRET)
    body = _event()
    assert http.post(PATH, content=body).status_code == 400
    assert http.post(PATH, content=body,
                     headers=_signed(body, "whsec_someoneelse123")).status_code == 400  # pragma: allowlist secret
    stale = _signed(body, ts=int(time.time()) - 3600)
    assert http.post(PATH, content=body, headers=stale).status_code == 400
    odd = {"Stripe-Signature": f"t={int(time.time())},v1=éé".encode("latin-1")}
    assert http.post(PATH, content=body, headers=odd).status_code == 400
    assert handled == [] and rows == []


def test_a_signed_event_is_recorded_and_applied_once(env, monkeypatch):
    http, handled, rows = env
    monkeypatch.setenv("MAVERICK_STRIPE_WEBHOOK_SECRET", SECRET)
    body = _event("evt_once")
    r = http.post(PATH, content=body, headers=_signed(body))
    assert r.status_code == 200, r.text
    assert [e["id"] for e in handled] == ["evt_once"]
    recorded = [row for row in rows if row.get("action") == "stripe_payment_notice"]
    assert len(recorded) == 1
    assert recorded[0]["event_id"] == "evt_once"
    assert recorded[0]["event_type"] == "invoice.payment_failed"
    assert SECRET not in repr(rows) and "cus_1" not in repr(rows)
    # Stripe resends the same event: acknowledged, not applied again.
    again = http.post(PATH, content=body, headers=_signed(body))
    assert again.status_code == 200 and again.json().get("duplicate") is True
    assert len(handled) == 1


def test_oversized_body_is_refused(env, monkeypatch):
    http, handled, _rows = env
    monkeypatch.setenv("MAVERICK_STRIPE_WEBHOOK_SECRET", SECRET)
    body = b"{" + b" " * (300 * 1024) + b"}"
    r = http.post(PATH, content=body, headers=_signed(body))
    assert r.status_code == 413
    assert handled == []
