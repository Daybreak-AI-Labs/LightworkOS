"""Real local journal/checkpoint acceptance, fake provider HTTP only."""
from __future__ import annotations

import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from maverick_channels import polling
from maverick_channels.bluesky import BlueskyChannel
from maverick_channels.delivery import DeliveryJournal
from maverick_channels.mastodon import MastodonChannel
from maverick_channels.polling import PollCheckpoint
from maverick_channels.threads import ThreadsChannel


class Response:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status
    def json(self):
        return self.payload
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"fixture HTTP {self.status_code}")


def transport(monkeypatch, get, post=None):
    class Client:
        def __init__(self, **kwargs):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def get(self, url, *, params, **kwargs):
            return get(params)
        async def post(self, url, **kwargs):
            return post(url, kwargs) if post else Response({"id": "saved", "uri": "at://saved"})
    monkeypatch.setitem(sys.modules, "httpx", SimpleNamespace(AsyncClient=Client))


def mastodon(handler=None):
    channel = MastodonChannel(handler or AsyncMock(return_value="answer"), instance="fixture.invalid",
                              access_token="fixture", allowed_user_ids={"owner"})
    channel._last_seen_id = "0"
    return channel


def mastodon_item(index):
    return {"id": str(index), "account": {"acct": "owner"},
            "status": {"id": str(index), "content": str(index), "visibility": "private"}}


def test_mastodon_burst_restart_drains_all_before_watermark(monkeypatch):
    monkeypatch.setattr(polling, "MAX_PAGES", 1)
    # This checks durable 65-item pagination, not the separate poll deadline.
    # Real journal writes can exceed 15 seconds under parallel CI load.
    monkeypatch.setattr(polling, "POLL_DEADLINE_SECONDS", 90.0)
    calls, handler = [], AsyncMock(return_value="answer")
    def get(params):
        calls.append(params)
        top = int(params.get("max_id", "66")) - 1
        return Response([mastodon_item(index) for index in range(top, max(top - 30, 0), -1)])
    transport(monkeypatch, get)
    async def run():
        for index in range(3):
            channel = mastodon(handler)
            for item in await channel._poll_once():
                await channel._dispatch(item)
            assert channel._last_seen_id == ("65" if index == 2 else "0")
        assert DeliveryJournal().store.count() == 65
    asyncio.run(run())
    assert handler.await_count == 65
    assert [call.get("max_id") for call in calls] == [None, "36", "6"]


def test_mastodon_failure_after_page_admission_keeps_cursor_and_recovers(monkeypatch):
    failure, handler = [True], AsyncMock(return_value="answer")
    def get(params):
        if params.get("max_id") and failure[0]:
            return Response({}, 429)
        top = int(params.get("max_id", "33")) - 1
        return Response([mastodon_item(index) for index in range(top, max(top - 30, 0), -1)])
    transport(monkeypatch, get)
    async def run():
        channel = mastodon(handler)
        with pytest.raises(RuntimeError, match="429"):
            await channel._poll_once()
        checkpoint = PollCheckpoint(channel.name, channel._account())
        state = checkpoint.store.get(checkpoint.record_id)
        assert state["cursor"] == "3" and state["watermark"] == "0"
        assert DeliveryJournal().store.count() == 30 and handler.await_count == 0
        failure[0] = False
        await mastodon(handler)._poll_once()
        async def send_saved(msg, reply, route):
            return await channel._post_reply(route["status"], route["account"], reply.text)
        for _ in range(3):
            await channel.recover_messages(account=channel._account(), authorize=lambda msg: True, send=send_saved)
        assert handler.await_count == 32
    asyncio.run(run())


def test_mastodon_seed_failure_and_changed_order_never_backfill(monkeypatch):
    transport(monkeypatch, lambda params: Response({}, 429))
    channel = mastodon()
    channel._last_seen_id = None
    with pytest.raises(RuntimeError):
        asyncio.run(channel._poll_once())
    assert DeliveryJournal().store.count() == 0
    transport(monkeypatch, lambda params: Response([mastodon_item(1), mastodon_item(2)]))
    channel._last_seen_id = "0"
    with pytest.raises(ValueError, match="ordering"):
        asyncio.run(channel._poll_once())
    assert DeliveryJournal().store.count() == 0


def bluesky(handler=None):
    channel = BlueskyChannel(handler or AsyncMock(return_value="answer"), handle="fixture", password="fixture",
                             allowed_user_ids={"did:owner"})
    channel._session = {"did": "did:self", "accessJwt": "fixture"}
    channel._last_seen_indexed_at = "2026-01-01T00:00:00Z"
    return channel


def bluesky_item(identity, timestamp="2026-01-01T00:00:02Z"):
    return {"uri": "at://" + identity, "cid": identity, "reason": "mention", "indexedAt": timestamp,
            "author": {"did": "did:owner"}, "record": {"text": identity}}


def test_bluesky_opaque_pages_late_index_and_restart_floor(monkeypatch):
    monkeypatch.setattr(polling, "MAX_PAGES", 1)
    pages = {None: {"notifications": [bluesky_item("z")], "cursor": "opaque-A"},
             "opaque-A": {"notifications": [bluesky_item("old", "2025-01-01T00:00:00Z")], "cursor": "opaque-B"},
             "opaque-B": {"notifications": [bluesky_item("a", "2026-01-01T00:00:01Z")]}}
    transport(monkeypatch, lambda params: Response(pages[params.get("cursor")]))
    handler = AsyncMock(return_value="answer")
    async def run():
        for _ in range(3):
            channel = bluesky(handler)
            channel._last_seen_indexed_at = None if DeliveryJournal().store.count() else channel._last_seen_indexed_at
            for item in await channel._poll_once():
                await channel._dispatch(item)
            assert channel._last_seen_indexed_at == "2026-01-01T00:00:00Z"
        assert {call.args[0].message_id for call in handler.await_args_list} == {"at://z", "at://a"}
        for _ in range(3):
            for item in await channel._poll_once():
                await channel._dispatch(item)
        assert handler.await_count == 2
    asyncio.run(run())


def threads(handler=None):
    return ThreadsChannel(handler or AsyncMock(return_value="answer"), user_id="100", access_token="fixture",
                          allowed_user_ids={"200"})


def thread_item(identity, timestamp="2026-01-02T00:00:00Z"):
    return {"id": identity, "text": identity, "username": "owner", "from": {"id": "200"}, "timestamp": timestamp}


def test_threads_startup_scope_then_burst_uses_opaque_continuation(monkeypatch):
    monkeypatch.setattr(polling, "MAX_PAGES", 1)
    phase, requests = ["startup"], []
    def get(params):
        requests.append(params.get("after"))
        if phase[0] == "startup":
            return Response({"data": [thread_item("900", "2026-01-01T00:00:00Z")],
                             "paging": {"next": "untrusted-unused-url", "cursors": {"after": "history"}}})
        if not params.get("after"):
            return Response({"data": [thread_item("2")], "paging": {"next": "unused", "cursors": {"after": "opaque"}}})
        return Response({"data": [thread_item("1"), thread_item("901", "2025-01-01T00:00:00Z")]})
    transport(monkeypatch, get)
    handler = AsyncMock(return_value="answer")
    async def run():
        channel = threads(handler)
        for item in await channel._poll_once():
            await channel._dispatch(item)
        assert requests == [None]  # No startup historical page was requested.
        phase[0] = "burst"
        for _ in range(2):
            channel = threads(handler)
            for item in await channel._poll_once():
                await channel._dispatch(item)
        assert {call.args[0].message_id for call in handler.await_args_list} == {"900", "2", "1"}
    asyncio.run(run())
    assert requests == [None, None, "opaque"]


def test_threads_retries_publish_with_saved_container_and_one_execution(monkeypatch):
    calls, failure = [], [True]
    def post(url, payload):
        calls.append((url, payload["data"]))
        if url.endswith("/threads"):
            return Response({"id": "container"})
        if failure[0]:
            failure[0] = False
            return Response({}, 429)
        return Response({"id": "published"})
    transport(monkeypatch, lambda params: Response({}), post)
    channel = threads()
    async def run():
        first = await channel._dispatch(thread_item("1"))
        assert first["delivery"] == "retryable"
        second = await channel._dispatch(thread_item("1"))
        assert second["delivery"] == "delivered"
        channel.handler.assert_awaited_once()
    asyncio.run(run())
    assert [url.rsplit("/", 1)[-1] for url, _ in calls] == ["threads", "threads_publish", "threads_publish"]
    assert calls[-1][1] == {"creation_id": "container"}


@pytest.mark.parametrize("adapter", ["threads", "bluesky"])
def test_social_cursor_cycle_visible_and_execution_remains_once(monkeypatch, adapter):
    channel = threads() if adapter == "threads" else bluesky()
    calls = []
    item = thread_item("1") if adapter == "threads" else bluesky_item("one")
    def get(params):
        calls.append(params)
        if adapter == "threads":
            return Response({"data": [item], "paging": {"next": "unused", "cursors": {"after": "cycle"}}})
        return Response({"notifications": [item], "cursor": "cycle"})
    transport(monkeypatch, get)
    async def run():
        if adapter == "threads":
            for event in await channel._poll_once():
                await channel._dispatch(event)
        for event in await channel._poll_once():
            await channel._dispatch(event)
        assert channel.poll_status == "incomplete_cursor_cycle"
        channel.handler.assert_awaited_once()
    asyncio.run(run())
    assert len(calls) == (3 if adapter == "threads" else 2)


def test_threads_refuses_unknown_history_boundary_before_following_pages(monkeypatch):
    item = thread_item("1")
    item.pop("timestamp")
    calls = []
    def get(params):
        calls.append(params)
        return Response({"data": [item], "paging": {"next": "unused", "cursors": {"after": "history"}}})
    transport(monkeypatch, get)
    channel = threads()
    with pytest.raises(ValueError, match="timestamps"):
        asyncio.run(channel._poll_once())
    assert len(calls) == 1 and channel.handler.await_count == 0 and DeliveryJournal().store.count() == 0


@pytest.mark.parametrize("factory", [mastodon, bluesky, threads])
def test_poll_transport_survives_recovery_store_failure_and_stops(factory, monkeypatch):
    channel = factory()
    if channel.name == "mastodon":
        monkeypatch.setattr(channel, "_seed_cursor", AsyncMock())
    async def poll():
        channel._stop_event.set()
        return []
    monkeypatch.setattr(channel, "_poll_once", poll)
    monkeypatch.setattr(channel, "recover_messages", AsyncMock(side_effect=OSError("fixture store unavailable")))
    asyncio.run(channel.start())
    channel.recover_messages.assert_awaited_once()
    assert channel._running is False


@pytest.mark.parametrize("factory, method", [(mastodon, "_seed_cursor"), (bluesky, "_ensure_session")])
def test_initialization_failure_leaves_transport_stopped(factory, method, monkeypatch):
    channel = factory()
    monkeypatch.setattr(channel, method, AsyncMock(side_effect=OSError("fixture unavailable")))
    with pytest.raises(OSError):
        asyncio.run(channel.start())
    assert channel._running is False
