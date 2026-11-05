"""A web request that sends data waits on the Approvals page like other steps.

http_fetch sends anything but a plain GET/HEAD only after a person approves
that exact request. In dashboard mode the request is parked on the Approvals
page with the website, method, address, headers and body (credentials hidden);
approving it there sends it once, rejecting it sends nothing.
"""
from __future__ import annotations

import json
import re
import threading
import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}
SECRET = "sk-live-" + "Q7" * 20  # pragma: allowlist secret


class _Resp:
    status_code = 200
    reason_phrase = "OK"
    encoding = "utf-8"
    url = "https://api.example.test/v1/items"
    headers = {"content-type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def iter_bytes(self, chunk_size=None):
        yield b'{"saved": true}'


@pytest.fixture
def sent(monkeypatch, tmp_path):
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "30")
    monkeypatch.setenv("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS", "0")
    monkeypatch.setenv("MAVERICK_FETCH_ALLOW_PRIVATE", "1")  # offline: no DNS
    monkeypatch.setenv("MAVERICK_FETCH_NO_SCAN", "1")
    calls: list[dict] = []

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def stream(self, method, url, headers=None, content=None):
            calls.append({"method": method, "url": url, "body": content})
            return _Resp()

    import maverick.tools._ssrf as ssrf

    monkeypatch.setattr(ssrf, "safe_client", lambda url, **kw: _Client())
    return calls


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN)


def _start_post():
    from maverick.tools.http_fetch import http_fetch

    result: dict[str, str] = {}
    args = {
        "url": "https://api.example.test/v1/items",
        "method": "POST",
        "headers": {"Content-Type": "application/json",
                    "Authorization": f"Bearer {SECRET}"},
        "body": json.dumps({"name": "quarterly numbers"}),
        "render": "raw",
    }
    thread = threading.Thread(target=lambda: result.update(out=http_fetch().fn(args)))
    thread.start()
    return thread, result


def _wait_for_pending(tmp_path):
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    try:
        for _ in range(200):
            pending = world.pending_approvals()
            if pending:
                return pending[0]
            time.sleep(0.05)
    finally:
        world.close()
    raise AssertionError("the request never reached the Approvals page")


def test_post_waits_on_the_approvals_page_and_runs_once_approved(sent, tmp_path):
    thread, result = _start_post()
    row = _wait_for_pending(tmp_path)
    client = _client()

    page = client.get("/approvals")
    assert page.status_code == 200
    text = page.text
    assert f'data-id="{row.id}"' in text
    assert "Send a POST request to api.example.test" in text
    assert "https://api.example.test" in text
    assert "quarterly numbers" in text
    assert "[REDACTED:sensitive field]" in text
    assert SECRET not in text
    assert "Can&#39;t be undone" in text or "Can't be undone" in text
    assert sent == []  # nothing leaves before the decision

    binding = re.search(
        rf'data-id="{row.id}" data-action="approve" data-binding="([0-9a-f]{{64}})"', text,
    ).group(1)
    approved = client.post(
        f"/api/v1/approvals/{row.id}/approve",
        json={"acknowledged": True, "confirmation": "approve"},
        headers={"X-Lightwork-Approval-Binding": binding},
    )
    assert approved.status_code == 204
    thread.join(timeout=30)

    assert "HTTP 200 OK" in result["out"]
    assert len(sent) == 1
    assert sent[0]["method"] == "POST"
    assert sent[0]["body"] == json.dumps({"name": "quarterly numbers"})


def test_rejecting_on_the_approvals_page_sends_nothing(sent, tmp_path):
    thread, result = _start_post()
    row = _wait_for_pending(tmp_path)

    denied = _client().post(f"/api/v1/approvals/{row.id}/deny", json={})
    assert denied.status_code in (200, 204)
    thread.join(timeout=30)

    assert "not approved" in result["out"]
    assert sent == []
