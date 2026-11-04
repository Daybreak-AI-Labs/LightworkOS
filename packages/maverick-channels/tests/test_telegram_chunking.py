"""Telegram outbound length handling.

The Bot API hard-rejects text messages over 4096 chars with a 400 "message is
too long", which raised out of the handler (no error handler registered on the
Application) -- the run completed and was billed, but the user got NOTHING.
Long replies must be chunked on line boundaries instead, in `_on_message`,
`send()` and `send_threaded()`.

The SDK is fully mocked (no ``telegram`` install / network needed): the
adapter only gates construction on the module's ``_HAVE_TELEGRAM`` flag, and
these paths never touch the real ``Application``.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import maverick_channels.telegram as tg
import pytest
from maverick_channels.telegram import TELEGRAM_LIMIT


@pytest.fixture()
def make_channel(monkeypatch):
    monkeypatch.setattr(tg, "_HAVE_TELEGRAM", True)

    def _make(handler=None):
        return tg.TelegramChannel(
            handler=handler or (lambda m: ""), token="x:y",
            allowed_user_ids={"111"},
        )
    return _make


def _update():
    return SimpleNamespace(
        message=SimpleNamespace(text="hi", message_id=7,
            reply_text=AsyncMock(return_value=SimpleNamespace(message_id=8))),
        effective_user=SimpleNamespace(id=111),
        effective_chat=SimpleNamespace(id=111, type="private"),
    )


def test_long_reply_is_chunked_not_lost(make_channel):
    long_reply = "\n".join(f"line {i}: " + "x" * 90 for i in range(120))
    assert len(long_reply) > TELEGRAM_LIMIT

    async def handler(msg):
        return long_reply

    ch = make_channel(handler)
    upd = _update()
    asyncio.run(ch._on_message(upd, None))

    sent = [c.args[0] for c in upd.message.reply_text.await_args_list]
    assert len(sent) > 1                                   # actually chunked
    assert all(len(s) <= TELEGRAM_LIMIT for s in sent)     # every piece sendable
    assert "".join(sent) == long_reply                     # nothing dropped


def test_short_reply_single_send_unchanged(make_channel):
    async def handler(msg):
        return "short answer"

    ch = make_channel(handler)
    upd = _update()
    asyncio.run(ch._on_message(upd, None))
    upd.message.reply_text.assert_awaited_once_with("short answer")


def test_proactive_send_chunked(make_channel):
    ch = make_channel()
    bot = SimpleNamespace(send_message=AsyncMock())
    ch._app = SimpleNamespace(bot=bot)

    text = "a" * (TELEGRAM_LIMIT + 10)
    asyncio.run(ch.send("111", text))

    calls = bot.send_message.await_args_list
    assert len(calls) == 2
    assert all(c.kwargs["chat_id"] == 111 for c in calls)
    assert all(len(c.kwargs["text"]) <= TELEGRAM_LIMIT for c in calls)
    assert "".join(c.kwargs["text"] for c in calls) == text


def test_send_threaded_chunks_keep_thread_anchor(make_channel):
    ch = make_channel()
    bot = SimpleNamespace(send_message=AsyncMock())
    ch._app = SimpleNamespace(bot=bot)

    text = "b" * (TELEGRAM_LIMIT + 1)
    asyncio.run(ch.send_threaded("111", text, reply_to="42"))

    calls = bot.send_message.await_args_list
    assert len(calls) == 2
    assert all(c.kwargs["reply_to_message_id"] == 42 for c in calls)
    assert "".join(c.kwargs["text"] for c in calls) == text
