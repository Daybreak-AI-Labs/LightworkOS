"""Real durable stores and adapter calls; provider transports are local fakes."""
from __future__ import annotations

import asyncio
import sqlite3
from contextlib import asynccontextmanager
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, MagicMock

import pytest
from maverick_channels import discord, imessage, matrix, slack, telegram
from maverick_channels.base import IncomingMessage
from maverick_channels.delivery import DeliveryJournal, DeliveryNotSent, DeliveryUnknown


@pytest.fixture(autouse=True)
def local_store(monkeypatch):
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORD_BACKEND", "local")


def _slack(monkeypatch, handler):
    monkeypatch.setattr(slack, "_HAVE_SLACK", True)
    monkeypatch.setattr(slack, "AsyncWebClient", MagicMock())
    monkeypatch.setattr(slack, "SocketModeClient", MagicMock())
    monkeypatch.setattr(slack, "SocketModeResponse", lambda **kw: NS(**kw))
    channel = slack.SlackChannel(handler, app_token="app-test", bot_token="bot-test",
                                 allowed_user_ids={"human"}, thread_replies=True)
    channel._account_id, channel._team_id = "team:bot", "team"
    channel._web.chat_postMessage = AsyncMock(return_value={"ok": True, "ts": "reply-id"})
    client = NS(send_socket_mode_response=AsyncMock())
    request = NS(type="events_api", envelope_id="envelope", payload={"team_id": "team", "event": {
        "type": "message", "user": "human", "channel": "room", "ts": "100.1", "text": "question",
    }})
    return channel, client, request


def _telegram(monkeypatch, handler):
    monkeypatch.setattr(telegram, "_HAVE_TELEGRAM", True)
    channel = telegram.TelegramChannel(handler, token="123:secret", allowed_user_ids={"7"})
    update = NS(message=NS(text="question", message_id=5,
        reply_text=AsyncMock(return_value=NS(message_id=6))),
        effective_user=NS(id=7), effective_chat=NS(id=-77, type="group"))
    return channel, update


def _discord(handler):
    channel = discord.DiscordChannel.__new__(discord.DiscordChannel)
    channel.handler, channel.allowed_user_ids = handler, {"7"}
    channel._client = NS(user=NS(id=123))
    room = NS(id=77, send=AsyncMock(return_value=NS(id=456)))
    message = NS(id=111, author=NS(id=7), channel=room, content="question")
    return channel, message


def _matrix(handler):
    channel = matrix.MatrixChannel.__new__(matrix.MatrixChannel)
    channel.handler, channel.allowed_user_ids = handler, {"@human:hs"}
    channel.user_id, channel.homeserver, channel._start_ts_ms = "@bot:hs", "https://hs", None
    channel._client = NS(room_send=AsyncMock(return_value=NS(event_id="$reply")))
    return channel, NS(room_id="!room"), NS(sender="@human:hs", body="question",
                                        event_id="$input", server_timestamp=1)


def _imessage(monkeypatch, tmp_path, handler):
    db = tmp_path / "chat.db"
    monkeypatch.setattr(imessage, "CHAT_DB", db)
    with sqlite3.connect(db) as conn:
        conn.executescript("CREATE TABLE IF NOT EXISTS handle(id TEXT);"
            "CREATE TABLE IF NOT EXISTS message(handle_id INTEGER,text TEXT,guid TEXT,is_from_me INTEGER);")
    channel = imessage.iMessageChannel.__new__(imessage.iMessageChannel)
    channel.handler, channel.allowed_user_ids = handler, {"+1555"}
    channel._last_rowid, channel._stop, channel.poll_interval = None, False, 0
    channel.send = AsyncMock(return_value="local-accepted")
    return channel


@pytest.mark.parametrize("adapter", ["slack", "telegram", "discord", "matrix", "imessage"])
def test_redelivery_and_concurrency_execute_once(monkeypatch, tmp_path, adapter):
    handler = AsyncMock(return_value="answer")
    if adapter == "slack":
        channel, client, req = _slack(monkeypatch, handler)
        def invoke():
            return channel._on_request(client, req)
        send = channel._web.chat_postMessage
    elif adapter == "telegram":
        channel, update = _telegram(monkeypatch, handler)
        def invoke():
            return channel._on_message(update, None)
        send = update.message.reply_text
    elif adapter == "discord":
        channel, msg = _discord(handler)
        def invoke():
            return discord._handle_discord_message(msg, bot_user=channel._client.user, channel=channel)
        send = msg.channel.send
    elif adapter == "matrix":
        channel, room, event = _matrix(handler)
        def invoke():
            return channel._on_message(room, event)
        send = channel._client.room_send
    else:
        channel = _imessage(monkeypatch, tmp_path, handler)
        def invoke():
            return channel._receive("+1555", "question", 1, "guid-1")
        send = channel.send

    async def run():
        await asyncio.gather(*(invoke() for _ in range(4)))
        await invoke()
    asyncio.run(run())
    assert handler.await_count == 1
    assert send.await_count == 1
    assert DeliveryJournal().store.list()[0]["delivery"] == "delivered"


def test_slack_admits_before_ack_then_downloads_and_recovers_after_ack_crash(monkeypatch):
    handler = AsyncMock(return_value="answer")
    channel, client, req = _slack(monkeypatch, handler)
    req.payload["event"]["files"] = [{"id": "F1", "name": "example.txt", "mimetype": "text/plain"}]
    order = []
    async def ack(response):
        assert DeliveryJournal().store.list()[0]["execution"] == "received"
        order.append("ack")
    async def download(event):
        order.append("download")
        return [{"filename": "example.txt", "mime": "text/plain", "data": b"important"}]
    client.send_socket_mode_response.side_effect = ack
    channel._download_files = download
    original = channel.process_message
    channel.process_message = AsyncMock(side_effect=asyncio.CancelledError)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(channel._on_request(client, req))
    assert order == ["ack"] and not handler.called
    channel.process_message = original
    account = channel._account_id
    asyncio.run(channel.recover_messages(account=account,
        authorize=lambda msg: channel._authorized(msg, account),
        prepare=channel._prepare, send=channel._send_saved))
    assert order == ["ack", "download"] and handler.await_count == 1
    assert handler.call_args.args[0].attachments[0]["data"] == b"important"
    assert channel._web.chat_postMessage.call_args.kwargs["thread_ts"] == "100.1"


def test_queued_slack_question_uses_saved_receipt_and_sends_once(monkeypatch):
    from maverick import server as server_mod

    async def handler(msg):
        msg._channel_question_watch = {
            "goal_id": 4, "conversation_id": 8, "tenant": None,
            "owner": "user:slack:human", "execution_principal": "user:slack:human",
        }
        return "Task queued"

    channel, client, request = _slack(monkeypatch, handler)
    asyncio.run(channel._on_request(client, request))
    row = DeliveryJournal().store.list()[0]
    assert row["question_watch"]["goal_id"] == 4
    assert row["delivery"] == "delivered"
    seen = []

    def question(watch, msg, account_sha256):
        seen.append((watch["goal_id"], msg.principal_id, account_sha256))
        return "Question #9 for task #4: Which customer?\nReply here with your answer.", False

    monkeypatch.setattr(server_mod, "queued_channel_question", question)
    kwargs = {"account": channel._account_id,
              "authorize": lambda msg: channel._authorized(msg, channel._account_id),
              "send": channel._send_saved, "prepare": channel._prepare}
    asyncio.run(channel.recover_messages(**kwargs))
    assert len(seen) == 1 and seen[0][0:2] == (4, "human")
    assert channel._web.chat_postMessage.await_count == 2
    assert "Question #9" in channel._web.chat_postMessage.call_args.kwargs["text"]
    assert channel._web.chat_postMessage.call_args.kwargs["thread_ts"] == "100.1"
    assert DeliveryJournal().get(row["id"])["question_watch"] is None
    asyncio.run(channel.recover_messages(**kwargs))
    assert channel._web.chat_postMessage.await_count == 2


def test_queued_telegram_question_uses_original_chat_and_reply_anchor(monkeypatch):
    from maverick import server as server_mod

    async def handler(msg):
        msg._channel_question_watch = {
            "goal_id": 4, "conversation_id": 8, "tenant": None,
            "owner": "user:telegram:7", "execution_principal": "user:telegram:7",
        }
        return "Task queued"

    channel, update = _telegram(monkeypatch, handler)
    channel._app = NS(bot=NS(send_message=AsyncMock(return_value=NS(message_id=9))))
    asyncio.run(channel._on_message(update, None))
    monkeypatch.setattr(server_mod, "queued_channel_question",
                        lambda *a: ("Question #9 for task #4: Which customer?", False))
    account = channel._account()
    kwargs = {"account": account,
              "authorize": lambda msg: channel._authorized(msg, account, None),
              "send": channel._send_saved, "prepare": channel._prepare_saved}
    asyncio.run(channel.recover_messages(**kwargs))
    call = channel._app.bot.send_message.call_args.kwargs
    assert call["chat_id"] == -77
    assert call["reply_to_message_id"] == 5
    assert "Which customer?" in call["text"]
    assert DeliveryJournal().store.list()[0]["question_watch"] is None


def test_uncertain_queued_question_send_is_held_without_duplicate(monkeypatch):
    from maverick import server as server_mod

    async def handler(msg):
        msg._channel_question_watch = {
            "goal_id": 4, "conversation_id": 8, "tenant": None,
            "owner": "user:slack:human", "execution_principal": "user:slack:human",
        }
        return "Task queued"

    channel, client, request = _slack(monkeypatch, handler)
    asyncio.run(channel._on_request(client, request))
    monkeypatch.setattr(server_mod, "queued_channel_question",
                        lambda *a: ("Question #9 for task #4: Which customer?", False))
    channel._web.chat_postMessage.side_effect = TimeoutError("uncertain acceptance")
    kwargs = {"account": channel._account_id,
              "authorize": lambda msg: channel._authorized(msg, channel._account_id),
              "send": channel._send_saved, "prepare": channel._prepare}
    asyncio.run(channel.recover_messages(**kwargs))
    row = DeliveryJournal().store.list()[0]
    assert row["question_watch"] is not None
    assert row["delivery"] == "delivered"  # queued ack remains confirmed
    assert any(key.startswith("question:") and chunk["state"] == "delivery_unknown"
               for key, chunk in row["chunks"].items())
    asyncio.run(channel.recover_messages(**kwargs))
    assert channel._web.chat_postMessage.await_count == 2


def test_preupgrade_slack_receipt_authority_is_legacy_only(monkeypatch):
    from maverick import oidc

    channel, _, _ = _slack(monkeypatch, AsyncMock(return_value="answer"))
    old_message = IncomingMessage(user_id="room", sender_id="human", channel="slack", text="question")
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: False)
    assert channel._authorized(old_message, channel._account_id)
    assert not channel._authorized(old_message, "another installation")
    channel.allowed_user_ids.clear()
    assert not channel._authorized(old_message, channel._account_id)
    channel.allowed_user_ids.add("human")
    monkeypatch.setattr(oidc, "oidc_enabled", lambda: True)
    assert not channel._authorized(old_message, channel._account_id)


def test_slack_failed_admission_is_not_acked_or_executed(monkeypatch):
    handler = AsyncMock(return_value="answer")
    channel, client, req = _slack(monkeypatch, handler)
    channel.admit_message = AsyncMock(side_effect=OSError("disk full"))
    with pytest.raises(OSError):
        asyncio.run(channel._on_request(client, req))
    assert not client.send_socket_mode_response.called and not handler.called


def test_slack_wrong_workspace_and_revoked_sender_cannot_execute(monkeypatch):
    handler = AsyncMock(return_value="answer")
    channel, client, req = _slack(monkeypatch, handler)
    req.payload["team_id"] = "another-team"
    with pytest.raises(PermissionError):
        asyncio.run(channel._on_request(client, req))
    req.payload["team_id"] = "team"
    async def revoke(response):
        channel.allowed_user_ids.clear()
    client.send_socket_mode_response.side_effect = revoke
    with pytest.raises(PermissionError):
        asyncio.run(channel._on_request(client, req))
    assert not handler.called and not channel._web.chat_postMessage.called


def test_telegram_saved_chunks_resume_without_replaying_prefix_or_agent(monkeypatch):
    handler = AsyncMock(return_value="x" * (telegram.TELEGRAM_LIMIT + 2))
    channel, update = _telegram(monkeypatch, handler)
    calls = []
    async def send(text):
        calls.append(text)
        if len(calls) == 2:
            raise DeliveryNotSent("rejected before acceptance")
        return NS(message_id=len(calls))
    update.message.reply_text.side_effect = send
    async def run():
        first = await channel._on_message(update, None)
        assert first["delivery"] == "retryable"
        # Restarted SDK object uses durable route and same stable bot id.
        recovered, _ = _telegram(monkeypatch, handler)
        recovered._app = NS(bot=NS(send_message=AsyncMock(side_effect=lambda **kw: NS(message_id=99))))
        results = await recovered.recover_messages(account=recovered._account(),
            authorize=lambda msg: recovered._authorized(msg, recovered._account(), None),
            send=recovered._send_saved, prepare=recovered._prepare_saved)
        assert results[0]["delivery"] == "delivered"
        kwargs = recovered._app.bot.send_message.call_args.kwargs
        assert kwargs == {"text": "xx", "chat_id": -77, "reply_to_message_id": 5}
    asyncio.run(run())
    assert len(calls) == 2 and handler.await_count == 1


def test_telegram_ambiguous_send_is_held_and_account_rotation_preserves_identity(monkeypatch):
    handler = AsyncMock(return_value="answer")
    channel, update = _telegram(monkeypatch, handler)
    update.message.reply_text.side_effect = TimeoutError()
    async def run():
        assert (await channel._on_message(update, None))["delivery"] == "delivery_unknown"
        channel.token = "123:new-secret"
        await channel._on_message(update, None)
    asyncio.run(run())
    assert handler.await_count == update.message.reply_text.await_count == 1


def test_discord_partial_reply_keeps_mentions_disabled_and_current_auth(monkeypatch):
    monkeypatch.setattr(discord, "_no_mentions", lambda: "none")
    handler = AsyncMock(return_value="x" * 2001)
    channel, msg = _discord(handler)
    calls = []
    async def send(text, **kwargs):
        calls.append((text, kwargs))
        channel.allowed_user_ids.clear()
        return NS(id=5)
    msg.channel.send.side_effect = send
    result = asyncio.run(discord._handle_discord_message(msg, bot_user=channel._client.user, channel=channel))
    assert len(calls) == 1 and calls[0][1] == {"allowed_mentions": "none"}
    assert result["delivery"] == "delivery_unknown"


def test_matrix_timeout_redelivery_uses_same_provider_transaction_and_no_agent_replay():
    handler = AsyncMock(return_value="answer")
    channel, room, event = _matrix(handler)
    channel._client.room_send.side_effect = [TimeoutError(), NS(event_id="$reply")]
    async def run():
        assert (await channel._on_message(room, event))["delivery"] == "delivery_unknown"
        assert (await channel._on_message(room, event))["delivery"] == "delivered"
    asyncio.run(run())
    calls = channel._client.room_send.call_args_list
    assert calls[0].kwargs["tx_id"] == calls[1].kwargs["tx_id"]
    assert handler.await_count == 1


def test_matrix_error_response_is_not_delivery_and_backlog_self_guards_remain():
    handler = AsyncMock(return_value="answer")
    channel, room, event = _matrix(handler)
    channel._client.room_send.return_value = NS(status_code="M_FORBIDDEN")
    assert asyncio.run(channel._on_message(room, event))["delivery"] == "retryable"
    event.event_id = "$old"
    channel._start_ts_ms = 2
    asyncio.run(channel._on_message(room, event))
    channel._start_ts_ms = None
    event.sender = channel.user_id
    asyncio.run(channel._on_message(room, event))
    assert handler.await_count == 1


def test_imessage_restart_cursor_and_saved_inbox_recovery(monkeypatch, tmp_path):
    handler = AsyncMock(return_value="answer")
    channel = _imessage(monkeypatch, tmp_path, handler)
    assert channel._checkpoint() == 0
    with sqlite3.connect(imessage.CHAT_DB) as conn:
        conn.execute("INSERT INTO handle VALUES ('+1555')")
        conn.execute("INSERT INTO message VALUES (1, 'question', 'guid-1', 0)")
    assert channel._fetch_new() == [("+1555", "question", 1, "guid-1")]
    channel.process_message = AsyncMock(side_effect=asyncio.CancelledError)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(channel._receive("+1555", "question", 1, "guid-1"))
    restart = _imessage(monkeypatch, tmp_path, handler)
    restart._last_rowid = restart._checkpoint()
    assert restart._last_rowid == 1 and restart._fetch_new() == []
    asyncio.run(restart.recover_messages(account=restart._account(),
        authorize=lambda msg: restart._authorized(msg, restart._account()), send=restart._send_saved))
    assert handler.await_count == restart.send.await_count == 1


def test_imessage_failed_admission_cannot_advance_checkpoint(monkeypatch, tmp_path):
    channel = _imessage(monkeypatch, tmp_path, AsyncMock())
    assert channel._checkpoint() == 0
    channel.admit_message = AsyncMock(side_effect=OSError())
    with pytest.raises(OSError):
        asyncio.run(channel._receive("+1555", "question", 1, "guid-1"))
    assert channel._checkpoint() == 0


def test_imessage_process_acceptance_is_explicit_and_argv_literal(monkeypatch, tmp_path):
    channel = _imessage(monkeypatch, tmp_path, AsyncMock())
    del channel.send
    run = MagicMock(return_value=NS(returncode=0))
    monkeypatch.setattr(imessage.subprocess, "run", run)
    text = '"; tell application "Finder" to delete every file'
    assert asyncio.run(channel.send("+1555", text)) == "osascript-accepted"
    assert run.call_args.args[0] == ["osascript", "-", text, "+1555"]
    assert run.call_args.kwargs["input"] == imessage._SEND_SCRIPT
    run.return_value.returncode = 1
    with pytest.raises(DeliveryUnknown):
        asyncio.run(channel.send("+1555", "answer"))
    run.side_effect = FileNotFoundError()
    with pytest.raises(DeliveryNotSent):
        asyncio.run(channel.send("+1555", "answer"))


def test_matrix_recovery_rechecks_account_binding():
    handler = AsyncMock(return_value="answer")
    channel, room, event = _matrix(handler)
    msg = IncomingMessage(user_id=room.room_id, text=event.body, channel="matrix",
                          sender_id=event.sender, message_id=event.event_id)
    account = channel._account()
    asyncio.run(channel.admit_message(msg, external_id=event.event_id, account=account, authorize=lambda: True))
    channel.homeserver = "https://other"
    outcomes = asyncio.run(channel.recover_messages(account=account,
        authorize=lambda msg: channel._authorized(msg, account), send=channel._send_saved, idempotent=True))
    assert outcomes == [] and not handler.called


def test_slack_chunk_receipts_skip_confirmed_prefix_on_rejection(monkeypatch):
    handler = AsyncMock(return_value="x" * 4001)
    channel, client, request = _slack(monkeypatch, handler)
    channel._web.chat_postMessage.side_effect = [
        {"ok": True, "ts": "first"}, {"ok": False, "error": "ratelimited"},
        {"ok": True, "ts": "second"},
    ]
    async def run():
        assert (await channel._on_request(client, request))["delivery"] == "retryable"
        assert (await channel._on_request(client, request))["delivery"] == "delivered"
    asyncio.run(run())
    calls = channel._web.chat_postMessage.call_args_list
    assert [len(call.kwargs["text"]) for call in calls] == [4000, 1, 1]
    assert all(call.kwargs["thread_ts"] == "100.1" for call in calls)
    assert handler.await_count == 1


@pytest.mark.parametrize("response", [{"ok": True}, {"ok": False, "error": "fatal_error"}])
def test_slack_incomplete_or_uncertain_ack_is_held(monkeypatch, response):
    handler = AsyncMock(return_value="answer")
    channel, client, request = _slack(monkeypatch, handler)
    channel._web.chat_postMessage.return_value = response
    async def run():
        assert (await channel._on_request(client, request))["delivery"] == "delivery_unknown"
        await channel._on_request(client, request)
    asyncio.run(run())
    assert handler.await_count == channel._web.chat_postMessage.await_count == 1


@pytest.mark.parametrize("adapter", ["slack", "matrix", "discord", "telegram"])
def test_transport_lifetime_owns_and_drains_recovery(monkeypatch, adapter):
    state = []
    entered = asyncio.Event()
    @asynccontextmanager
    async def recovery_worker(**kwargs):
        state.append("recovery-entered")
        entered.set()
        try:
            yield
        finally:
            state.append("recovery-exited")
    handler = AsyncMock(return_value="")
    async def run():
        if adapter == "slack":
            channel, _, _ = _slack(monkeypatch, handler)
            channel._web.auth_test = AsyncMock(return_value={"team_id": "team", "user_id": "bot"})
            channel._sm.connect = AsyncMock()
            channel._stop_event.set()
        elif adapter == "matrix":
            channel, _, _ = _matrix(handler)
            channel._client.sync_forever = AsyncMock()
        elif adapter == "discord":
            channel, _ = _discord(handler)
            channel.token = "test"
            channel._client.wait_until_ready = AsyncMock()
            async def start(token):
                await entered.wait()
            channel._client.start = start
        else:
            channel, _ = _telegram(monkeypatch, handler)
            channel._app = NS(updater=NS(stop=AsyncMock()), stop=AsyncMock(), shutdown=AsyncMock())
        channel.recovery_worker = recovery_worker
        if adapter == "telegram":
            channel._recovery_task = asyncio.create_task(channel._recover())
            await entered.wait()
            await channel.stop()
            assert channel._recovery_task is None
        else:
            await channel.start()
        assert state == ["recovery-entered", "recovery-exited"]
    asyncio.run(asyncio.wait_for(run(), timeout=5))


def test_imessage_poll_materializes_one_bounded_batch(monkeypatch, tmp_path):
    channel = _imessage(monkeypatch, tmp_path, AsyncMock())
    with sqlite3.connect(imessage.CHAT_DB) as conn:
        conn.execute("INSERT INTO handle VALUES ('+1555')")
        conn.executemany("INSERT INTO message VALUES (1, 'question', ?, 0)",
                         [(f"guid-{index}",) for index in range(507)])
    batch = channel._fetch_new()
    assert len(batch) == 256 and batch[-1][2] == 256
    channel._last_rowid = batch[-1][2]
    assert len(channel._fetch_new()) == 251


def test_a_slack_thread_reply_is_admitted_only_where_the_bot_was_asked(monkeypatch):
    # Every allowlisted thread reply in any room the bot is in was stored, with
    # its files, filling the intake with conversations not meant for Lightwork.
    from maverick_channels.delivery import _record_id

    handled = []

    async def handler(msg):
        handled.append(msg.text)
        return "noted"

    channel, client, _request = _slack(monkeypatch, handler)
    attachment = {"id": "F1", "name": "notes.pdf", "url_private": "https://files.slack.com/F1"}

    def event(ts, **fields):
        return NS(type="events_api", envelope_id="env-" + ts, payload={"team_id": "team", "event": {
            "type": "message", "user": "human", "channel": "room", "channel_type": "channel",
            "ts": ts, "text": "chatting", **fields}})

    journal = DeliveryJournal()
    asyncio.run(channel._on_request(client, event("300.2", thread_ts="300.1", files=[attachment])))
    assert journal.get(_record_id("slack", "team:bot", "room:300.2")) is None and handled == []
    asyncio.run(channel._on_request(client, event("400.1", type="app_mention", text="prepare the report")))
    asyncio.run(channel._on_request(client, event("400.2", thread_ts="400.1", files=[attachment])))
    row = journal.get(_record_id("slack", "team:bot", "room:400.2"))
    assert row is not None and row["message"]["question_reply_only"] is True
    assert row["route"]["files"] == [] and row["message"]["text"] == "chatting"


def test_a_live_telegram_reply_uploads_its_saved_files(monkeypatch):
    # The live path sent only the text; the saved output files (and the
    # rendered page the text says is attached) went out only on recovery,
    # which never runs once the reply is marked delivered.
    import hashlib

    from maverick_channels.base import Reply

    data = b"quarterly totals\n"
    async def handler(msg):
        msg._channel_reply_material = {"source": None, "files": [{
            "filename": "report.txt", "mime": "text/plain", "data": data,
            "sha256": hashlib.sha256(data).hexdigest(), "source": {"kind": "artifact"}}]}
        return Reply("Your report is attached.", attachments=["report.txt"])

    channel, update = _telegram(monkeypatch, handler)
    channel._app = NS(bot=NS(send_document=AsyncMock(return_value=NS(message_id=10))))
    row = asyncio.run(channel._on_message(update, None))
    update.message.reply_text.assert_awaited()
    sent = channel._app.bot.send_document.call_args.kwargs
    assert sent["chat_id"] == -77 and sent["filename"] == "report.txt" and sent["reply_to_message_id"] == 5
    assert row["delivery"] == "delivered" and row["chunks"]["file-0"]["state"] == "delivered"
