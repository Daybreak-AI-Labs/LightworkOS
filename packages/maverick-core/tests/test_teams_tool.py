"""Microsoft Teams tool."""
from __future__ import annotations

from maverick.tools.teams_tool import _build_card, teams_tool


def test_build_card_plain():
    card = _build_card("hello world")
    assert card["@type"] == "MessageCard"
    assert card["text"] == "hello world"
    assert "title" not in card


def test_build_card_with_title():
    card = _build_card("body", "My Title")
    assert card["title"] == "My Title"
    assert card["summary"] == "My Title"


def test_send_posts_card(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 200
        text = "1"

    class _FakeClient:
        """Stands in for the pinned _ssrf.safe_client context manager."""

        def __init__(self, url, **kw):
            captured["pinned_url"] = url

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None):
            captured["url"] = url
            captured["json"] = json
            return _Resp()

    import maverick.tools._ssrf as ssrf
    monkeypatch.setattr(ssrf, "safe_client", lambda url, **kw: _FakeClient(url, **kw))
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://outlook.office.com/webhook/abc")
    out = teams_tool().fn({"text": "deploy done", "title": "CI"})
    assert out == "posted to Teams"
    assert captured["json"]["text"] == "deploy done"
    assert captured["json"]["title"] == "CI"
    # The POST went through the pinned client, not a raw httpx call.
    assert captured["pinned_url"] == "https://outlook.office.com/webhook/abc"


def test_send_requires_webhook(monkeypatch):
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    out = teams_tool().fn({"text": "hi"})
    assert out.startswith("ERROR") and "webhook" in out


def test_send_rejects_non_https(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "http://outlook.office.com/x")
    out = teams_tool().fn({"text": "hi"})
    assert out.startswith("ERROR") and "https" in out


def test_send_rejects_private_host(monkeypatch):
    # A loopback/private webhook is rejected by the pinned client (BlockedHost).
    monkeypatch.delenv("MAVERICK_FETCH_ALLOW_PRIVATE", raising=False)
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://127.0.0.1/webhook")
    out = teams_tool().fn({"text": "hi"})
    assert out.startswith("ERROR")


def test_send_requires_text():
    assert teams_tool().fn({"text": ""}).startswith("ERROR")


def test_send_refuses_caller_selected_webhook(monkeypatch):
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://x.office.com/configured")
    out = teams_tool().fn({"text": "hi", "webhook": "https://x.office.com/other"})
    assert "operator-configured" in out
