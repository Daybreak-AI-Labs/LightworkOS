"""The standalone DSAR Concierge end to end over HTTP: intake → verify →
fulfill/handoff → close, and the ops surface
(/health, /value.json) the partner fleet console polls."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

HERE = Path(__file__).resolve().parent

# The demo agents share module NAMES (backend, capabilities, ...) by
# design -- each directory is a self-contained deployable. In one pytest
# process that collides in sys.modules, so every loader purges the shared
# names before executing its app.
_SHARED_MODULES = ("backend", "capabilities", "mailsink",
                   "value_ledger", "dsar_engine", "serve_standalone")


def _purge_shared_modules():
    for _m in _SHARED_MODULES:
        sys.modules.pop(_m, None)



@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DSAR_STANDALONE", "1")
    monkeypatch.setenv("DSAR_DATA_DIR", str(tmp_path / "store"))
    monkeypatch.setenv("DSAR_OPERATOR_TOKEN", "test-operator-token")
    sys.path.insert(0, str(HERE))
    _purge_shared_modules()
    try:
        spec = importlib.util.spec_from_file_location(
            "dsar_concierge_app", HERE / "app.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.INBOX.clear()
        # No SMTP listener in tests; backend inserts into INBOX directly.
        yield TestClient(module.app), module, {
            "auth": ("operator", "test-operator-token"),
            "headers": {"Origin": module.BASE_URL}}
    finally:
        sys.path.remove(str(HERE))


def _mail_link(module, needle="/verify/"):
    for m in module.INBOX:
        for line in m.body.splitlines():
            if needle in line:
                return line.strip()
    return ""


def test_full_access_flow(client):
    tc, module, operator = client
    r = tc.post("/request", data={"subject_id": "jordan@example.test",
                                  "kind": "access", "note": "everything"})
    assert r.status_code == 200 and "opened" in r.text
    link = _mail_link(module)
    assert link, "verification email not delivered"
    token = link.rsplit("/", 1)[-1]
    assert "Identity confirmed" in tc.get(f"/verify/{token}").text
    rid = next(iter(module.engine.list_requests()))["id"]
    r = tc.post(f"/case/{rid}/fulfill",
                data={"extracts": "CRM: name, email\nBilling: 3 invoices"},
                follow_redirects=True, **operator)
    assert r.status_code == 200
    pkg = tc.get(f"/case/{rid}/package.json", **operator)
    assert pkg.status_code == 200
    assert set(pkg.json()["data"]) == {"CRM", "Billing"}
    # The subject got the cover note.
    assert any("is ready" in m.subject for m in module.INBOX)
    v = tc.get("/value.json").json()
    assert v["agent"] == "dsar-concierge" and v["cases"] == 1
    assert v["dollars"] > 0
    assert tc.get("/health").json()["ok"] is True


def test_webhook_detector_and_erasure_handoff(client):
    tc, module, operator = client
    r = tc.post("/webhook/message", json={
        "text": "Under Article 17 please delete my data.",
        "sender": "sam@example.test"})
    assert r.status_code == 201
    rid = r.json()["id"]
    assert r.json()["kind"] == "erasure"
    # Nonsense never opens a case.
    assert tc.post("/webhook/message",
                   json={"text": "lovely weather"}).status_code == 422
    token = _mail_link(module).rsplit("/", 1)[-1]
    tc.get(f"/verify/{token}")
    r = tc.post(f"/case/{rid}/erasure", data={"systems": "CRM\nBilling"},
                follow_redirects=True, **operator)
    assert "deliberately" in r.text or "non-destructive" in r.text
    rec = module.engine.get(rid)
    assert rec["status"] == "awaiting_erasure"
    tc.post(f"/case/{rid}/close", data={"reason": "confirmed"},
            follow_redirects=True, **operator)
    assert module.engine.get(rid)["status"] == "closed"


def test_operator_console_rejects_unauthenticated_clients(client):
    tc, module, operator = client
    opened = tc.post("/request", data={
        "subject_id": "privacy@example.test", "kind": "access"})
    assert opened.status_code == 200
    rid = next(iter(module.engine.list_requests()))["id"]
    for path in ("/", f"/case/{rid}", f"/case/{rid}/package.json"):
        response = tc.get(path)
        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Basic")
    for path in (f"/case/{rid}/fulfill", f"/case/{rid}/erasure",
                 f"/case/{rid}/close"):
        assert tc.post(path, data={}).status_code == 401
    assert tc.get("/", **operator).status_code == 200


def test_cross_origin_cannot_change_operator_cases(client):
    tc, module, operator = client
    tc.post("/request", data={"subject_id": "privacy@example.test", "kind": "access"})
    rid = next(iter(module.engine.list_requests()))["id"]
    for suffix in ("fulfill", "erasure", "close"):
        response = tc.post(f"/case/{rid}/{suffix}", auth=operator["auth"],
                           headers={"Origin": "https://attacker.example"}, data={})
        assert response.status_code == 403
    assert module.engine.get(rid)["status"] != "closed"
    assert tc.post(f"/case/{rid}/close", auth=operator["auth"], data={}).status_code == 403
    for origin in ("null", "http://[", module.BASE_URL + "/path", "https://127.0.0.1:8891", "http://127.0.0.1:8892"):
        response = tc.post(f"/case/{rid}/close", auth=operator["auth"], data={},
                           headers={"Origin": origin, "Referer": module.BASE_URL + "/case"})
        assert response.status_code == 403
    response = tc.post(f"/case/{rid}/close", auth=operator["auth"], data={},
                       headers={"Origin": module.BASE_URL, "Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403
    response = tc.post(f"/case/{rid}/close", auth=operator["auth"], data={}, follow_redirects=False,
                       headers={"Referer": module.BASE_URL + "/case", "Host": "attacker.example"})
    assert response.status_code == 303


@pytest.mark.parametrize("auth", [
    ("opérateur", "test-operator-token"),
    ("operator", "jeton-é"),
])
def test_operator_console_rejects_non_ascii_credentials(client, auth):
    # Basic credentials decode as UTF-8, so accents arrive as text: they are
    # wrong credentials (401), not a server error.
    tc, _module, operator = client
    response = tc.get("/", auth=auth)
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Basic")
    assert tc.get("/", **operator).status_code == 200


def test_platform_intake_requires_an_allowed_email_domain(client, monkeypatch):
    tc, module, _operator = client
    monkeypatch.setattr(module, "STANDALONE", False)
    monkeypatch.delenv("DSAR_EMAIL_ALLOWED_DOMAINS", raising=False)
    response = tc.post("/request", data={"subject_id": "victim@example.test", "kind": "access"})
    assert "not enabled" in response.text
    assert not module.engine.list_requests()
    monkeypatch.setenv("DSAR_EMAIL_ALLOWED_DOMAINS", "allowed.test")
    response = tc.post("/webhook/message", json={"text": "access request", "sender": "victim@example.test"})
    assert response.status_code == 422
    assert not module.engine.list_requests()
    assert tc.post("/webhook/message", json={"text": "access request", "sender": "bad\r\n@example.test"}).status_code == 422


def test_public_intake_limits_repeated_requests(client):
    tc, module, _operator = client
    module._intake_attempts.clear()
    for _ in range(30):
        tc.post("/webhook/message", json={"text": "not a request"})
    assert tc.post("/webhook/message", json={"text": "not a request"}).status_code == 429


def test_intake_suppresses_repeated_email_to_same_recipient(client):
    tc, module, _operator = client
    first = tc.post("/request", data={"subject_id": "victim@example.test", "kind": "access"})
    second = tc.post("/webhook/message", json={"text": "access request", "sender": "VICTIM@example.test"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert len(module.INBOX) == 1
    assert len(module.engine.list_requests()) == 1


def test_invalid_intake_does_not_reserve_email_quota(client):
    tc, module, _operator = client
    assert tc.post("/webhook/message", json={"text": "weather", "sender": "victim@example.test"}).status_code == 422
    tc.post("/request", data={"subject_id": "victim@example.test", "kind": "invalid"})
    assert tc.post("/request", data={"subject_id": "victim@example.test", "kind": "access"}).status_code == 200
    assert len(module.INBOX) == 1
