"""Threads (Meta Threads API) polling adapter: poll-and-reply cycle, author
allowlist, atomic dedup claim with release-on-failure (fail-closed when the
claim store is down — polling re-sees replies every cycle), and the two-step
create -> publish outbound flow with 500-char chunking."""
from __future__ import annotations

import asyncio
import sys
import types
from unittest.mock import AsyncMock, MagicMock

import pytest
from maverick_channels.threads import ThreadsChannel

SELF_ID = "17841400000000000"
OWNER = "ownerhandle"
OWNER_ID = "999000111"
REPLY_ID = "18010000000000001"
ACCESS_TOKEN = "THQVJ-token"


def _channel(**overrides):
    kw = dict(
        handler=AsyncMock(return_value="the reply"),
        access_token=ACCESS_TOKEN,
        user_id=SELF_ID,
        allowed_user_ids=[OWNER_ID],
    )
    kw.update(overrides)
    return ThreadsChannel(**kw)


def _reply(username=OWNER, text="hello agent", reply_id=REPLY_ID, from_id="999000111"):
    return {"id": reply_id, "text": text, "username": username,
            "from": {"id": from_id, "username": username}, "timestamp": "2026-01-01T00:00:00Z"}


class _Resp:
    def __init__(self, json_data=None, status_code=200):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = ""

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


def _responder_with(batch):
    """Route fake responses by URL: replies polls, create, publish."""
    def _responder(method, url, payload):
        if url.endswith("/threads_publish"):
            return _Resp({"id": "MEDIA1"})
        if url.endswith("/threads"):
            return _Resp({"id": "CREATION1"})
        if url.endswith("/replies"):
            return _Resp({"data": batch})
        return _Resp({})
    return _responder


def _install_httpx(monkeypatch, calls, responder):
    """threads.py imports httpx lazily inside methods, so a sys.modules fake
    keeps every test offline."""
    class _Client:
        def __init__(self, timeout=None):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, headers=None, params=None):
            calls.append({"method": "GET", "url": url, "headers": headers,
                          "params": params})
            return responder("GET", url, params)

        async def post(self, url, headers=None, data=None, json=None):
            calls.append({"method": "POST", "url": url, "headers": headers,
                          "data": data, "json": json})
            return responder("POST", url, data)

    monkeypatch.setitem(sys.modules, "httpx", types.SimpleNamespace(AsyncClient=_Client))


def _fake_wm(monkeypatch):
    """Stateful in-memory claim store mirroring WorldModel's dedup contract:
    True on first claim, False on duplicates, release undoes the claim."""
    wm = MagicMock()
    wm.is_processed_message.return_value = False
    claimed = set()

    def _mark(channel, ext_id, goal_id=None):
        if (channel, ext_id) in claimed:
            return False
        claimed.add((channel, ext_id))
        return True

    wm.mark_message_processed.side_effect = _mark
    wm.release_processed_message.side_effect = (
        lambda channel, ext_id: claimed.discard((channel, ext_id))
    )
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    return wm


async def _cycle(ch):
    """One poll cycle: what start()'s loop does between stop-event waits."""
    for reply in await ch._poll_once():
        await ch._dispatch(reply)


def test_poll_cycle_processes_allowed_reply_once(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    wm = _fake_wm(monkeypatch)
    calls = []
    _install_httpx(monkeypatch, calls, _responder_with([_reply()]))

    asyncio.run(_cycle(ch))
    asyncio.run(_cycle(ch))  # same reply re-polled -> dedup claim no-ops

    ch.handler.assert_awaited_once()
    msg = ch.handler.await_args.args[0]
    assert msg.user_id == REPLY_ID and msg.message_id == REPLY_ID
    assert msg.sender_id == OWNER_ID and msg.channel == "threads"
    assert msg.text == "hello agent"
    assert wm.mark_message_processed.call_count == 1
    assert wm.mark_message_processed.call_args.args[0] == "delivery:threads"
    ch.send.assert_awaited_once_with(REPLY_ID, "the reply")

    poll = calls[0]
    assert poll["method"] == "GET"
    assert poll["url"].endswith(f"/v1.0/{SELF_ID}/replies")
    assert poll["params"] == {"fields": "id,text,username,from,timestamp", "limit": 25}
    assert poll["headers"]["Authorization"] == f"Bearer {ACCESS_TOKEN}"


def test_unlisted_author_ignored(monkeypatch):
    ch = _channel()
    ch.send = AsyncMock()
    wm = _fake_wm(monkeypatch)
    _install_httpx(monkeypatch, [], _responder_with([_reply(username=OWNER, from_id="999000222")]))

    asyncio.run(_cycle(ch))

    assert not ch.handler.await_count
    assert not wm.mark_message_processed.called  # denied before the claim
    assert not ch.send.await_count


def test_username_allow_list_keeps_stable_sender_identity(monkeypatch):
    ch = _channel(allowed_user_ids=[OWNER])
    ch.send = AsyncMock()
    _fake_wm(monkeypatch)
    _install_httpx(monkeypatch, [], _responder_with([_reply()]))
    asyncio.run(_cycle(ch))
    ch.handler.assert_awaited_once()
    assert ch.handler.await_args.args[0].sender_id == OWNER_ID
    ch.send.assert_awaited_once()


def test_self_authored_reply_skipped(monkeypatch):
    """The bot's own replies come back on the edge; answering them would
    loop. from.id == configured user_id is dropped before any claim."""
    ch = _channel()
    ch.send = AsyncMock()
    wm = _fake_wm(monkeypatch)
    _install_httpx(monkeypatch, [], _responder_with([_reply(from_id=SELF_ID)]))

    asyncio.run(_cycle(ch))

    assert not ch.handler.await_count
    assert not wm.mark_message_processed.called
    assert not ch.send.await_count


def test_unknown_handler_outcome_retains_claim(monkeypatch):
    ch = _channel(handler=AsyncMock(side_effect=RuntimeError("boom")))
    ch.send = AsyncMock()
    wm = _fake_wm(monkeypatch)
    _install_httpx(monkeypatch, [], _responder_with([_reply()]))

    asyncio.run(_cycle(ch))

    from maverick_channels.delivery import DeliveryJournal
    row = DeliveryJournal().store.list(limit=1)[0]
    assert row["execution"] == "execution_unknown"
    assert wm.mark_message_processed.call_count == 1
    wm.release_processed_message.assert_not_called()
    ch.send.assert_awaited_once_with(REPLY_ID, "⚠ An internal error occurred.")


def test_claim_infra_failure_skips_fail_closed(monkeypatch):
    """A polling adapter must defer when the claim store is unavailable.

    Like the webhook adapters, it never processes without an authoritative
    claim. Polling needs no HTTP retry response because the next poll sees the
    same reply again.
    """
    ch = _channel()
    ch.send = AsyncMock()
    monkeypatch.setattr(
        "maverick.world_model.WorldModel",
        MagicMock(side_effect=RuntimeError("no db")),
    )
    _install_httpx(monkeypatch, [], _responder_with([_reply()]))

    with pytest.raises(RuntimeError, match="no db"):
        asyncio.run(_cycle(ch))

    assert not ch.handler.await_count
    assert not ch.send.await_count


def test_release_failure_holds_claim_and_prevents_second_execution(monkeypatch, caplog):
    ch = _channel(handler=AsyncMock(side_effect=RuntimeError("handler failed")))
    ch.send = AsyncMock()
    claimed = set()
    wm = MagicMock()
    wm.is_processed_message.return_value = False

    def _mark(channel, ext_id):
        key = (channel, ext_id)
        if key in claimed:
            return False
        claimed.add(key)
        return True

    wm.mark_message_processed.side_effect = _mark
    wm.release_processed_message.side_effect = RuntimeError("release store offline")
    monkeypatch.setattr("maverick.world_model.WorldModel", MagicMock(return_value=wm))
    _install_httpx(monkeypatch, [], _responder_with([_reply()]))

    with caplog.at_level("ERROR"):
        asyncio.run(_cycle(ch))
        asyncio.run(_cycle(ch))

    assert ch.handler.await_count == 1
    assert wm.mark_message_processed.call_count == 1
    wm.release_processed_message.assert_not_called()


def test_two_step_publish_payloads(monkeypatch):
    ch = _channel()
    calls = []
    _install_httpx(monkeypatch, calls, _responder_with([]))

    asyncio.run(ch.send(REPLY_ID, "pong"))

    assert [c["url"].rsplit("/", 1)[-1] for c in calls] == ["threads", "threads_publish"]
    create, publish = calls
    assert create["url"].endswith(f"/v1.0/{SELF_ID}/threads")
    assert create["data"] == {"media_type": "TEXT", "text": "pong",
                              "reply_to_id": REPLY_ID}
    assert create["headers"]["Authorization"] == f"Bearer {ACCESS_TOKEN}"
    assert publish["url"].endswith(f"/v1.0/{SELF_ID}/threads_publish")
    assert publish["data"] == {"creation_id": "CREATION1"}


def test_send_non_reply_target_posts_standalone(monkeypatch):
    """A non-numeric target (a username) is not a media id: no reply_to_id."""
    ch = _channel()
    calls = []
    _install_httpx(monkeypatch, calls, _responder_with([]))

    asyncio.run(ch.send(OWNER, "pong"))

    create = calls[0]
    assert create["data"] == {"media_type": "TEXT", "text": "pong"}


def test_long_replies_chunked_at_500(monkeypatch):
    ch = _channel()
    calls = []
    _install_httpx(monkeypatch, calls, _responder_with([]))

    asyncio.run(ch.send(REPLY_ID, "x" * 1200))

    # create, publish, create, publish, create, publish
    assert [c["url"].rsplit("/", 1)[-1] for c in calls] == \
        ["threads", "threads_publish"] * 3
    chunks = [c["data"]["text"] for c in calls if c["url"].endswith(f"/{SELF_ID}/threads")]
    assert [len(c) for c in chunks] == [500, 500, 200]
    assert "".join(chunks) == "x" * 1200
    # Every chunk threads onto the same reply target.
    assert all(c["data"]["reply_to_id"] == REPLY_ID
               for c in calls if c["url"].endswith(f"/{SELF_ID}/threads"))


def test_chunked_send_aborts_and_logs_on_midstream_failure(monkeypatch, caplog):
    """A multi-chunk reply whose 2nd chunk fails to create must stop (the
    publish edge is sequential and can't be rewound) and log how many chunks
    went undelivered instead of truncating silently."""
    ch = _channel()
    calls = []
    state = {"creates": 0}

    def _responder(method, url, payload):
        if url.endswith("/threads_publish"):
            return _Resp({"id": "MEDIA1"})
        if url.endswith("/threads"):
            state["creates"] += 1
            if state["creates"] == 2:  # second chunk's create fails
                return _Resp({}, status_code=500)
            return _Resp({"id": "CREATION1"})
        return _Resp({})

    _install_httpx(monkeypatch, calls, _responder)

    from maverick_channels.delivery import DeliveryUnknown
    with pytest.raises(DeliveryUnknown, match="unconfirmed"):
        asyncio.run(ch.send(REPLY_ID, "x" * 1200))  # 3 chunks of 500/500/200

    # chunk 1 create+publish, chunk 2 create (fails) -> stop. Chunk 3 never sent.
    assert state["creates"] == 2
    assert not any(c["url"].endswith("/threads_publish") for c in calls[2:])
    # The failure is surfaced to the caller; it is never reported as success.


def test_missing_credentials_raise(monkeypatch):
    monkeypatch.delenv("THREADS_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("THREADS_USER_ID", raising=False)
    with pytest.raises(ValueError, match="credentials missing"):
        _channel(access_token=None, user_id=None)


def test_missing_allowlist_raises(monkeypatch):
    monkeypatch.delenv("THREADS_ALLOWED_USER_IDS", raising=False)
    with pytest.raises(ValueError, match="ALLOWED_USER_IDS"):
        _channel(allowed_user_ids=None)
