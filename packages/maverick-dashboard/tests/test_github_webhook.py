"""GitHub App webhook route (/webhook/github) — issue→PR receiver wiring."""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _labeled_issue(label="maverick"):
    return {
        "action": "labeled",
        "repository": {"full_name": "acme/widgets"},
        "issue": {"number": 7, "title": "Fix the bug", "body": "details"},
        "label": {"name": label},
        "sender": {"login": "alice"},
    }


@pytest.fixture(autouse=True)
def _secret(monkeypatch):
    monkeypatch.setenv("MAVERICK_GH_APP_WEBHOOK_SECRET", "shh")  # pragma: allowlist secret
    from maverick_dashboard import app as app_mod

    app_mod._issue_webhook_seen.clear()
    app_mod._goal_times.clear()
    app_mod._goal_times_global.clear()


def test_rejects_bad_signature():
    body = json.dumps(_labeled_issue()).encode()
    r = _client().post("/webhook/github", content=body,
                       headers={"X-GitHub-Event": "issues",
                                "X-Hub-Signature-256": "sha256=deadbeef"})
    assert r.status_code == 401


def test_trigger_reports_unavailable_without_scheduling(monkeypatch):
    ran = {}

    async def _fake_process(payload, **kw):
        ran["issue"] = payload.issue_number

    monkeypatch.setattr("maverick.github_app.process_issue", _fake_process)
    body = json.dumps(_labeled_issue()).encode()
    r = _client().post("/webhook/github", content=body,
                       headers={"X-GitHub-Event": "issues",
                                "X-GitHub-Delivery": "delivery-1",
                                "X-Hub-Signature-256": _sig(body, "shh")})
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"]
    assert not ran


def test_ignores_non_trigger_label():
    body = json.dumps(_labeled_issue(label="wontfix")).encode()
    r = _client().post("/webhook/github", content=body,
                       headers={"X-GitHub-Event": "issues",
                                "X-GitHub-Delivery": "delivery-ignored",
                                "X-Hub-Signature-256": _sig(body, "shh")})
    assert r.status_code == 200
    assert r.json()["status"] == "ignored"


def test_route_is_auth_exempt():
    # The webhook authenticates by HMAC, so it must bypass the bearer gate.
    from maverick_dashboard.app import _AUTH_EXEMPT
    assert "/webhook/github" in _AUTH_EXEMPT


def test_rejects_missing_delivery_id(monkeypatch):
    ran = []

    async def _fake_process(payload, **kw):
        ran.append(payload.issue_number)

    monkeypatch.setattr("maverick.github_app.process_issue", _fake_process)
    body = json.dumps(_labeled_issue()).encode()
    r = _client().post("/webhook/github", content=body,
                       headers={"X-GitHub-Event": "issues",
                                "X-Hub-Signature-256": _sig(body, "shh")})
    assert r.status_code == 403
    assert r.json()["detail"] == "missing delivery id"
    assert ran == []


def test_disabled_retries_remain_unavailable(monkeypatch):
    ran = []

    async def _fake_process(payload, **kw):
        ran.append(payload.issue_number)

    monkeypatch.setattr("maverick.github_app.process_issue", _fake_process)
    body = json.dumps(_labeled_issue()).encode()
    headers = {"X-GitHub-Event": "issues",
               "X-GitHub-Delivery": "delivery-1",
               "X-Hub-Signature-256": _sig(body, "shh")}
    first = _client().post("/webhook/github", content=body, headers=headers)
    assert first.status_code == 503
    replay = _client().post("/webhook/github", content=body,
                            headers={**headers, "X-GitHub-Delivery": "delivery-2"})
    assert replay.status_code == 503
    assert "unavailable" in replay.json()["detail"]
    assert ran == []


def test_disabled_github_webhook_does_not_consume_goal_quota(monkeypatch):
    ran = []

    async def _fake_process(payload, **kw):
        ran.append(payload.issue_number)

    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "100")
    monkeypatch.setattr("maverick.github_app.process_issue", _fake_process)

    body1 = json.dumps(_labeled_issue()).encode()
    first = _client().post("/webhook/github", content=body1,
                           headers={"X-GitHub-Event": "issues",
                                    "X-GitHub-Delivery": "delivery-1",
                                    "X-Hub-Signature-256": _sig(body1, "shh")})
    assert first.status_code == 503

    payload2 = _labeled_issue()
    payload2["issue"] = {**payload2["issue"], "number": 8, "title": "Fix another bug"}
    body2 = json.dumps(payload2).encode()
    second = _client().post("/webhook/github", content=body2,
                            headers={"X-GitHub-Event": "issues",
                                     "X-GitHub-Delivery": "delivery-2",
                                     "X-Hub-Signature-256": _sig(body2, "shh")})
    assert second.status_code == 503
    assert ran == []
