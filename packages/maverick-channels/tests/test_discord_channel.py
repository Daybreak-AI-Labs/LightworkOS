"""Discord channel adapter: message dispatch, author authorization and reply hygiene."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from maverick_channels import discord as dmod


class _Author:
    def __init__(self, id_):
        self.id = id_


class _Chan:
    def __init__(self):
        self.id = 555
        self.sent: list[str] = []
        self.mentions: list = []

    async def send(self, chunk, allowed_mentions=None):
        self.sent.append(chunk)
        self.mentions.append(allowed_mentions)
        return SimpleNamespace(id=len(self.sent))


class _Msg:
    def __init__(self, author_id, text, chan):
        self.author = _Author(author_id)
        self.content = text
        self.channel = chan
        self.id = 777


def _adapter(handler):
    channel = dmod.DiscordChannel.__new__(dmod.DiscordChannel)
    channel.handler = handler
    channel.allowed_user_ids = {"123"}
    channel._client = SimpleNamespace(user=SimpleNamespace(id=456))
    return channel


def test_discord_invokes_agent_via_passed_dispatch_text():
    chan = _Chan()
    seen = []

    async def fake_dispatch(m):
        seen.append(m.text)
        return "world"

    asyncio.run(dmod._handle_discord_message(
        _Msg("123", "hello", chan), bot_user=SimpleNamespace(id=456),
        channel=_adapter(fake_dispatch)))

    assert seen == ["hello"]      # the agent WAS invoked (no AttributeError)
    assert chan.sent == ["world"]  # reply delivered


def test_discord_gates_unauthorized_author():
    chan = _Chan()
    called = []

    async def fake_dispatch(m):
        called.append(1)
        return "x"

    asyncio.run(dmod._handle_discord_message(
        _Msg("999", "hi", chan), bot_user=SimpleNamespace(id=456),
        channel=_adapter(fake_dispatch)))

    assert called == [] and chan.sent == []


def test_discord_empty_reply_is_not_sent():
    # An empty reply (action-only goal, or a Reply whose text dispatch dropped)
    # must not be sent: split_for_discord("") -> [""] and channel.send("") is a
    # Discord 400 "Cannot send an empty message" that escapes on_message.
    chan = _Chan()

    async def empty(m):
        return ""

    asyncio.run(dmod._handle_discord_message(
        _Msg("123", "hi", chan), bot_user=SimpleNamespace(id=456),
        channel=_adapter(empty)))

    assert chan.sent == []  # nothing sent, no empty-message API error


def test_discord_suppresses_mention_amplification(monkeypatch):
    # Agent output containing @everyone must NOT ping the guild: every send
    # pins an AllowedMentions that suppresses mentions. We stub _no_mentions to
    # a sentinel so the assertion holds whether or not discord.py is installed.
    chan = _Chan()
    monkeypatch.setattr(dmod, "_no_mentions", lambda: "SUPPRESSED")

    async def echo(m):
        return "@everyone free nitro"

    asyncio.run(dmod._handle_discord_message(
        _Msg("123", "hi", chan), bot_user=SimpleNamespace(id=456),
        channel=_adapter(echo)))

    assert chan.sent == ["@everyone free nitro"]   # text still delivered
    assert chan.mentions == ["SUPPRESSED"]          # ...with mentions suppressed


def test_discord_handler_error_does_not_leak_internals():
    chan = _Chan()

    async def boom(m):
        raise RuntimeError("secret internal detail")

    asyncio.run(dmod._handle_discord_message(
        _Msg("123", "hi", chan), bot_user=SimpleNamespace(id=456),
        channel=_adapter(boom)))

    assert chan.sent == ["⚠ An internal error occurred."]
    assert "secret internal detail" not in chan.sent[0]
