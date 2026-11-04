"""Tests for the slack_bot tool (maverick.tools.slack_bot)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Slack bot tool ----------

def test_slack_bot_requires_op():
    from maverick.tools.slack_bot import slack_bot
    assert "op is required" in slack_bot().fn({})


def test_slack_bot_missing_token(monkeypatch):
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.slack_bot import slack_bot
    out = slack_bot().fn({"op": "post", "channel": "#x", "text": "hi"})
    assert "SLACK_BOT_TOKEN" in out


def test_slack_bot_post_calls_api(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    resp = MagicMock()
    resp.json = MagicMock(return_value={
        "ok": True, "channel": "C12345", "ts": "1234.5678",
    })

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.slack_bot import slack_bot
    out = slack_bot().fn({"op": "post", "channel": "C12345", "text": "hello"})
    assert "posted to C12345" in out
    # Verify auth header was set.
    headers = fake_httpx.post.call_args.kwargs["headers"]
    assert headers["Authorization"].startswith("Bearer xoxb-test")


def test_slack_bot_post_validates_args():
    from maverick.tools.slack_bot import slack_bot
    out = slack_bot().fn({"op": "post"})
    assert "post requires channel and text" in out


def test_slack_bot_history_renders(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    resp = MagicMock()
    resp.json = MagicMock(return_value={"ok": True, "messages": [
        {"ts": "1.0", "user": "U1", "text": "hi"},
        {"ts": "2.0", "user": "U2", "text": "yo"},
    ]})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.slack_bot import slack_bot
    out = slack_bot().fn({"op": "history", "channel": "C1"})
    assert "U1" in out and "hi" in out


def test_slack_bot_history_follows_cursor(monkeypatch):
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")

    def _resp(msgs, has_more, cursor):
        r = MagicMock()
        body = {"ok": True, "messages": msgs, "has_more": has_more}
        if cursor:
            body["response_metadata"] = {"next_cursor": cursor}
        r.json = MagicMock(return_value=body)
        return r

    get = MagicMock(side_effect=[
        _resp([{"ts": "1.0", "user": "U1", "text": "page-one"}], True, "cur-2"),
        _resp([{"ts": "2.0", "user": "U2", "text": "page-two"}], False, ""),
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = get
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.slack_bot import slack_bot
    out = slack_bot().fn({"op": "history", "channel": "C1", "limit": 100})
    assert "page-one" in out and "page-two" in out
    assert get.call_count == 2
    assert get.call_args_list[1].kwargs["params"]["cursor"] == "cur-2"
