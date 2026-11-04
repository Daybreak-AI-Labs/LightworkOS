"""Channel reply threading: IncomingMessage.message_id + Channel.send_threaded
(base fallback, Slack thread_ts, Telegram reply_to_message_id)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from maverick_channels.base import Channel, IncomingMessage


def test_incoming_message_id_defaults_none():
    m = IncomingMessage(user_id="u", text="hi")
    assert m.message_id is None


def test_base_send_threaded_falls_back_to_send():
    sent = []

    class Plain(Channel):
        name = "plain"

        def __init__(self):
            super().__init__(handler=None)

        async def start(self):  # pragma: no cover
            pass

        async def send(self, user_id, text):
            sent.append((user_id, text))

        async def stop(self):  # pragma: no cover
            pass

    asyncio.run(Plain().send_threaded("u1", "hello", reply_to="m-9"))
    assert sent == [("u1", "hello")]  # thread ref ignored, no crash


def _slack_channel(monkeypatch, thread_replies):
    import maverick_channels.slack as slack_mod
    monkeypatch.setattr(slack_mod, "_HAVE_SLACK", True)
    monkeypatch.setattr(slack_mod, "AsyncWebClient", MagicMock())
    monkeypatch.setattr(slack_mod, "SocketModeClient", MagicMock())
    ch = slack_mod.SlackChannel(
        handler=AsyncMock(return_value="the answer"),
        app_token="xapp-1", bot_token="xoxb-1",
        allowed_user_ids=["U123"], thread_replies=thread_replies,
    )
    ch._web = MagicMock()
    ch._web.chat_postMessage = AsyncMock(return_value={"ok": True, "ts": "reply-1"})
    ch._account_id = "T1:B1"
    ch._team_id = "T1"
    return ch


def test_slack_send_threaded_passes_thread_ts(monkeypatch):
    ch = _slack_channel(monkeypatch, thread_replies=True)
    asyncio.run(ch.send_threaded("C1", "hi", reply_to="171.001"))
    kw = ch._web.chat_postMessage.call_args.kwargs
    assert kw["thread_ts"] == "171.001" and kw["channel"] == "C1"


def test_slack_send_threaded_without_ref_is_plain(monkeypatch):
    ch = _slack_channel(monkeypatch, thread_replies=True)
    asyncio.run(ch.send_threaded("C1", "hi"))
    assert "thread_ts" not in ch._web.chat_postMessage.call_args.kwargs


def test_slack_inbound_reply_threads_when_enabled(monkeypatch):
    import maverick_channels.slack as slack_mod
    ch = _slack_channel(monkeypatch, thread_replies=True)
    client = MagicMock()
    client.send_socket_mode_response = AsyncMock()
    req = MagicMock()
    req.type = "events_api"
    req.envelope_id = "e1"
    req.payload = {"team_id": "T1", "event": {"type": "message", "user": "U123",
                             "channel": "C9", "text": "do it", "ts": "171.5"}}
    monkeypatch.setattr(slack_mod, "SocketModeResponse", MagicMock())
    asyncio.run(ch._on_request(client, req))
    kw = ch._web.chat_postMessage.call_args.kwargs
    assert kw["thread_ts"] == "171.5"


def test_slack_inbound_unthreaded_by_default(monkeypatch):
    import maverick_channels.slack as slack_mod
    monkeypatch.delenv("SLACK_THREAD_REPLIES", raising=False)
    ch = _slack_channel(monkeypatch, thread_replies=None)
    assert ch.thread_replies is False
    client = MagicMock()
    client.send_socket_mode_response = AsyncMock()
    req = MagicMock()
    req.type = "events_api"
    req.envelope_id = "e1"
    req.payload = {"team_id": "T1", "event": {"type": "message", "user": "U123",
                             "channel": "C9", "text": "do it", "ts": "171.5"}}
    monkeypatch.setattr(slack_mod, "SocketModeResponse", MagicMock())
    asyncio.run(ch._on_request(client, req))
    assert "thread_ts" not in ch._web.chat_postMessage.call_args.kwargs


def test_telegram_send_threaded(monkeypatch):
    import maverick_channels.telegram as tg_mod
    ch = tg_mod.TelegramChannel.__new__(tg_mod.TelegramChannel)
    ch._app = MagicMock()
    ch._app.bot.send_message = AsyncMock()
    asyncio.run(ch.send_threaded("42", "pong", reply_to="777"))
    kw = ch._app.bot.send_message.call_args.kwargs
    assert kw["reply_to_message_id"] == 777 and kw["chat_id"] == 42
    # Bogus thread id degrades to a plain send.
    asyncio.run(ch.send_threaded("42", "pong", reply_to="not-an-id"))
    assert "reply_to_message_id" not in ch._app.bot.send_message.call_args.kwargs
