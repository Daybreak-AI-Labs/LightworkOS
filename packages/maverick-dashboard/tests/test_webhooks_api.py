"""Settings > Webhooks: subscriptions, deliveries, test events, retry, and the
deadline-alert endpoints and record-page section.

Mutating /api/v1 requests carry a same-origin Origin (the CSRF contract).
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

OK = (200, 4, "ok", "")
DOWN = (500, 9, "boom", "HTTP 500")


@pytest.fixture(autouse=True)
def _fresh_world(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick.tools import _ssrf
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_ENTERPRISE", "MAVERICK_WEBHOOK_SECRET"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    import maverick_dashboard.api as api
    api._world_cache.clear()
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", lambda host: "93.184.216.34")
    yield


@pytest.fixture
def transport(monkeypatch):
    from maverick import webhooks
    calls: list[tuple] = []
    results = [OK]

    def fake(url, body, headers, timeout):
        calls.append((url, body, headers))
        return results[0]
    monkeypatch.setattr(webhooks, "_post_result", fake)
    monkeypatch.setattr(webhooks, "_submit", lambda executor, fn, *a: fn(*a) or True)
    fake.calls = calls
    fake.results = results
    return fake


def _create(**overrides):
    body = {"url": "https://hooks.example.com/lightwork", "events": ["dsar.*"], "secret": "s3", "description": "CRM"}  # pragma: allowlist secret
    body.update(overrides)
    r = client.post("/api/v1/webhooks/subscriptions", json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_page_renders_and_settings_links_to_it():
    page = client.get("/settings/webhooks/manage")
    assert page.status_code == 200
    assert "Add a subscription" in page.text and "dsar.opened" in page.text and "Retry" in page.text
    assert "/settings/webhooks/manage" in client.get("/settings").text


def test_subscription_crud_never_echoes_the_secret():
    sub = _create()
    assert sub["secret_set"] is True and "secret" not in sub
    listed = client.get("/api/v1/webhooks/subscriptions").json()
    assert [s["id"] for s in listed["subscriptions"]] == [sub["id"]]
    assert "s3" not in client.get("/api/v1/webhooks/subscriptions").text.replace('"s3"', "")
    assert listed["max_attempts"] == 5 and listed["retry_schedule_seconds"] == [60, 300, 900, 2400]
    r = client.patch(f"/api/v1/webhooks/subscriptions/{sub['id']}", json={"enabled": False, "events": "incident.*"})
    assert r.status_code == 200 and r.json()["enabled"] is False and r.json()["events"] == ["incident.*"]
    assert client.patch("/api/v1/webhooks/subscriptions/whs_nope", json={"enabled": True}).status_code == 404
    assert client.get(f"/api/v1/webhooks/subscriptions/{sub['id']}").status_code == 200


def test_bad_addresses_and_events_are_refused(monkeypatch):
    from maverick.tools import _ssrf

    def blocked(host):
        raise _ssrf.BlockedHost("private")
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", blocked)
    r = client.post("/api/v1/webhooks/subscriptions", json={"url": "https://10.1.1.1/x"})
    assert r.status_code == 400 and "not allowed" in r.json()["detail"]
    monkeypatch.setattr(_ssrf, "resolve_pinned_ip", lambda host: "93.184.216.34")
    r = client.post("/api/v1/webhooks/subscriptions", json={"url": "https://ok.example.com/x", "events": ["nope"]})
    assert r.status_code == 400 and "unknown event" in r.json()["detail"]
    assert client.get("/api/v1/webhooks/subscriptions").json()["subscriptions"] == []


def test_send_test_event_then_retry_now(transport):
    sub = _create()
    transport.results[0] = DOWN
    r = client.post(f"/api/v1/webhooks/subscriptions/{sub['id']}/test")
    assert r.status_code == 200
    delivery = r.json()["delivery"]
    assert delivery["status"] == "pending" and delivery["attempts"] == 1 and delivery["last_status_code"] == 500
    assert delivery["last_response"] == "boom" and delivery["next_attempt_at"] > delivery["created_at"]
    url, body, headers = transport.calls[0]
    assert url == sub["url"] and headers["X-Maverick-Event"] == "webhook.test"
    assert headers["X-Maverick-Signature"].startswith("sha256=")
    rows = client.get("/api/v1/webhooks/deliveries", params={"status": "pending"}).json()["deliveries"]
    assert [d["id"] for d in rows] == [delivery["id"]] and "body" not in rows[0]
    transport.results[0] = OK
    r = client.post(f"/api/v1/webhooks/deliveries/{delivery['id']}/retry")
    assert r.status_code == 200 and r.json()["delivery"]["status"] == "delivered"
    assert client.get(f"/api/v1/webhooks/deliveries/{delivery['id']}").json()["attempt_log"][-1]["status_code"] == 200
    assert client.get("/api/v1/webhooks/deliveries", params={"status": "weird"}).status_code == 400
    assert client.post("/api/v1/webhooks/deliveries/whd_nope/retry").status_code == 404


def test_opening_a_request_delivers_a_filtered_event(transport):
    _create(events=["dsar.*"])
    _create(url="https://other.example.com/h", events=["incident.*"])
    from maverick import privacy_ops
    record = privacy_ops.open_dsar("a@b.com", "erasure", opened_by="t")
    rows = client.get("/api/v1/webhooks/deliveries").json()["deliveries"]
    assert [(d["event_type"], d["url"], d["status"]) for d in rows] == [
        ("dsar.opened", "https://hooks.example.com/lightwork", "delivered")]
    import json
    envelope = json.loads(transport.calls[0][1])
    assert envelope["record"]["id"] == record["id"] and envelope["link"] == f"/privacy/dsar/{record['id']}"


def test_events_catalog_is_served():
    r = client.get("/api/v1/webhooks/events")
    assert r.status_code == 200
    types = {e["type"] for e in r.json()["events"]}
    assert {"dsar.opened", "incident.closed", "approval.expired", "policy.published"} <= types


def test_deadline_alerts_endpoints_and_record_page(monkeypatch):
    from maverick import deadline_alerts, privacy_ops
    record = privacy_ops.open_dsar("a@b.com", "access", opened_by="t")
    page = client.get(f"/privacy/dsar/{record['id']}")
    assert page.status_code == 200 and "No alerts have been sent" in page.text
    # Make the request overdue and run one cycle now.
    monkeypatch.setattr(privacy_ops, "list_dsars", lambda: [{**record, "due_at": 1.0}])
    sent = []
    monkeypatch.setattr(deadline_alerts, "deliver", lambda title, body, **kw: sent.append(body) or 1)
    r = client.post("/api/v1/deadline-alerts/run")
    assert r.status_code == 200 and r.json()["sent"] == 1 and r.json()["alerts"][0]["state"] == "overdue"
    assert sent and "Overdue" not in sent[0] and "was due" in sent[0]
    r = client.get("/api/v1/deadline-alerts", params={"record_type": "dsar", "record_id": record["id"]})
    assert r.status_code == 200 and r.json()["alerts"][0]["state"] == "overdue"
    assert r.json()["settings"]["enabled"] is True and r.json()["last_cycle"]["sent"] == 1
    assert client.get("/api/v1/deadline-alerts", params={"record_type": "dsar"}).status_code == 400
    assert client.get("/api/v1/deadline-alerts").json()["alerts"][0]["record_id"] == record["id"]
    page = client.get(f"/privacy/dsar/{record['id']}")
    assert "was due" in page.text and "the privacy owner" in page.text


def test_an_unconfirmed_deadline_alert_says_so_and_is_not_replayed(monkeypatch):
    from maverick import deadline_alerts, privacy_ops
    record = privacy_ops.open_dsar("c@d.com", "access", opened_by="t")
    monkeypatch.setattr(privacy_ops, "list_dsars", lambda: [{**record, "due_at": 1.0}])
    monkeypatch.setattr(deadline_alerts, "deliver",
                        lambda title, body, **kw: deadline_alerts.Delivery(0, uncertain=True))
    r = client.post("/api/v1/deadline-alerts/run")
    assert r.status_code == 200 and r.json()["sent"] == 0 and r.json()["unconfirmed"] == 1
    page = client.get(f"/privacy/dsar/{record['id']}")
    assert "Not confirmed. Check the channel before sending it again." in page.text
    assert client.post("/api/v1/deadline-alerts/run").json()["already_sent"] == 1
