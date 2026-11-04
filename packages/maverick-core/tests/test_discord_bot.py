"""Tests for the discord_bot tool (maverick.tools.discord_bot)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Discord bot tool ----------

def test_discord_bot_requires_op():
    from maverick.tools.discord_bot import discord_bot
    assert "op is required" in discord_bot().fn({})


def test_discord_bot_missing_token(monkeypatch):
    monkeypatch.delenv("DISCORD_BOT_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.discord_bot import discord_bot
    out = discord_bot().fn({"op": "post", "channel_id": "123456789012345678", "content": "hi"})
    assert "DISCORD_BOT_TOKEN" in out


def test_discord_bot_post_calls_api(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "bot_xx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"id": "msg_42"})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.discord_bot import discord_bot
    out = discord_bot().fn({"op": "post", "channel_id": "123456789012345678", "content": "hi"})
    assert "posted to 123456789012345678" in out and "msg_42" in out


def test_discord_bot_history_renders(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "bot_xx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=[
        {"id": "1", "author": {"username": "alice"}, "content": "hello"},
        {"id": "2", "author": {"username": "bob"}, "content": "yo"},
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.discord_bot import discord_bot
    out = discord_bot().fn({"op": "history", "channel_id": "123456789012345678", "limit": 10})
    assert "alice: hello" in out and "bob: yo" in out


def test_discord_bot_react_validates(monkeypatch):
    fake_httpx = types.ModuleType("httpx")
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.discord_bot import discord_bot
    out = discord_bot().fn({"op": "react", "channel_id": "123456789012345678"})
    assert "channel_id, message_id, emoji" in out


def test_discord_bot_rejects_non_snowflake_ids(monkeypatch):
    monkeypatch.setenv("DISCORD_BOT_TOKEN", "bot_xx")
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.discord_bot import discord_bot
    out = discord_bot().fn({"op": "lookup_channel", "channel_id": "123/../roles"})
    assert "snowflake" in out
    fake_httpx.get.assert_not_called()
