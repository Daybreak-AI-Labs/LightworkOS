"""Bluesky / AT Protocol channel adapter tests.

Mirrors test_voice_channel.py / test_channel_authz.py: skips cleanly when
the optional httpx dep is missing, and otherwise monkeypatches
``httpx.AsyncClient`` to assert (a) construction is fail-closed without an
allowlist, (b) the allowlist denies non-members before the handler runs,
(c) the inbound cursor advances past seen notifications, and (d) the
reply/send paths shape the AT Proto createRecord payload correctly.

No network is touched: the fake client records every request and returns
canned JSON.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _have_deps() -> bool:
    try:
        import httpx  # noqa: F401
        return True
    except ImportError:
        return False


async def _noop(_):
    return ""


class _FakeResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = ""

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


class _FakeClient:
    """Records every request; replies from a queued per-URL response map.

    ``calls`` is shared across instances so a test can inspect what the
    channel sent across the (per-request) AsyncClient lifecycles.
    """

    def __init__(self, calls, responder):
        self._calls = calls
        self._responder = responder

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, *, json=None, headers=None, data=None, **kw):
        self._calls.append({"method": "POST", "url": url, "json": json,
                            "headers": headers, "data": data})
        return self._responder("POST", url, json)

    async def get(self, url, *, headers=None, params=None, **kw):
        self._calls.append({"method": "GET", "url": url, "headers": headers,
                            "params": params})
        return self._responder("GET", url, None)


def _install_fake_httpx(monkeypatch, calls, responder):
    import httpx

    def _factory(*a, **kw):
        return _FakeClient(calls, responder)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)


# --- construction is fail-closed -------------------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_requires_allowlist():
    from maverick_channels.bluesky import BlueskyChannel
    with pytest.raises(ValueError, match="BLUESKY_ALLOWED_USER_IDS"):
        BlueskyChannel(handler=_noop, handle="me.bsky.social",
                       password="app-pw", allowed_user_ids=set())


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_stores_allowlist_and_denies_non_member():
    from maverick_channels.base import is_allowed
    from maverick_channels.bluesky import BlueskyChannel
    chan = BlueskyChannel(handler=_noop, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    assert is_allowed("did:plc:owner", chan.allowed_user_ids) is True
    assert is_allowed("did:plc:stranger", chan.allowed_user_ids) is False


# --- allowlist gate on the dispatch path -----------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_dispatch_denies_unauthorized_author(monkeypatch):
    """An author not on the allowlist must never reach the handler nor
    trigger an outbound reply."""
    from maverick_channels.bluesky import BlueskyChannel

    seen = []

    async def _handler(msg):
        seen.append(msg.user_id)
        return "should not be sent"

    calls = []
    _install_fake_httpx(monkeypatch, calls, lambda *a: _FakeResponse())

    chan = BlueskyChannel(handler=_handler, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    chan._session = {"accessJwt": "tok", "did": "did:plc:me"}

    notif = {
        "reason": "mention",
        "uri": "at://post/1", "cid": "cid1",
        "author": {"did": "did:plc:stranger", "handle": "stranger.bsky"},
        "record": {"text": "hello"},
    }
    asyncio.run(chan._dispatch(notif))

    assert seen == []
    # No createRecord (reply) call happened.
    assert not any("createRecord" in c["url"] for c in calls)


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_dispatch_allows_member_and_shapes_reply(monkeypatch):
    """An allowlisted author reaches the handler, and the reply is posted
    as an in-thread createRecord with the right shape."""
    from maverick_channels.bluesky import BlueskyChannel

    seen = []

    async def _handler(msg):
        seen.append((msg.user_id, msg.text))
        return "hi there"

    calls = []
    _install_fake_httpx(monkeypatch, calls, lambda *a: _FakeResponse())

    chan = BlueskyChannel(handler=_handler, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    chan._session = {"accessJwt": "tok", "did": "did:plc:me"}

    notif = {
        "reason": "mention",
        "uri": "at://post/abc", "cid": "cidabc",
        "author": {"did": "did:plc:owner", "handle": "owner.bsky"},
        "record": {"text": "are you there?"},
    }
    asyncio.run(chan._dispatch(notif))

    assert seen == [("did:plc:owner", "are you there?")]

    posts = [c for c in calls if c["method"] == "POST"
             and "createRecord" in c["url"]]
    assert len(posts) == 1
    body = posts[0]["json"]
    assert body["repo"] == "did:plc:me"
    assert body["collection"] == "app.bsky.feed.post"
    record = body["record"]
    assert record["text"] == "hi there"
    # Reply threads back to the parent notification's uri/cid.
    assert record["reply"]["parent"] == {"uri": "at://post/abc", "cid": "cidabc"}
    assert record["reply"]["root"] == {"uri": "at://post/abc", "cid": "cidabc"}
    # Authorization header carried the session token.
    assert posts[0]["headers"]["Authorization"] == "Bearer tok"


# --- inbound cursor advancement --------------------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_parse_indexed_at_handles_mixed_precision():
    # AT-proto indexedAt arrives at varying fractional precision; the floor is
    # seeded at 6-digit microseconds. Parsing must make the boundary second equal
    # regardless of the fractional form (a raw string compare ranked "...:05Z"
    # ABOVE "...:05.000000Z" because 'Z' > '.').
    from maverick_channels.bluesky import _parse_indexed_at

    no_frac = _parse_indexed_at("2026-01-01T00:00:05Z")
    micros = _parse_indexed_at("2026-01-01T00:00:05.000000Z")
    millis = _parse_indexed_at("2026-01-01T00:00:05.123Z")
    nanos = _parse_indexed_at("2026-01-01T00:00:05.123456789Z")
    assert no_frac == micros               # boundary second equal across forms
    assert millis < nanos                  # .123000 < .123456 after clamp
    assert no_frac < millis                # ordering preserved
    assert _parse_indexed_at("") is None
    assert _parse_indexed_at("not-a-timestamp") is None


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_poll_skips_boundary_second_at_mixed_precision(monkeypatch):
    """A notification stamped at exactly the startup second but in the
    no-fractional 'Z' form must be treated as pre-startup (skipped), not
    delivered. A raw string compare ranked '...:05Z' ABOVE the microsecond-seeded
    floor '...:05.000000Z' and backfilled it -- duplicate replies + LLM spend."""
    from maverick_channels.bluesky import BlueskyChannel

    notifications = {"notifications": [
        {"reason": "mention", "indexedAt": "2026-01-01T00:00:05Z",
         "author": {"did": "did:plc:owner"}, "record": {"text": "pre-startup"},
         "uri": "at://boundary", "cid": "c1"},
    ]}

    def _responder(method, url, body):
        if "listNotifications" in url:
            return _FakeResponse(json_data=notifications)
        return _FakeResponse()

    calls = []
    _install_fake_httpx(monkeypatch, calls, _responder)

    chan = BlueskyChannel(handler=_noop, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    chan._session = {"accessJwt": "tok", "did": "did:plc:me"}
    # Floor seeded at the same second with microsecond precision, as start() does.
    chan._last_seen_indexed_at = "2026-01-01T00:00:05.000000Z"

    new = asyncio.run(chan._poll_once())
    assert new == []  # boundary-second notification correctly treated as pre-history


def test_bluesky_poll_filters_and_advances_cursor(monkeypatch):
    """_poll_once returns only new mention/reply notifications and moves the
    cursor to the newest indexedAt; a second poll over the same data yields
    nothing."""
    from maverick_channels.bluesky import BlueskyChannel

    notifications = {
        "notifications": [
            {"reason": "like", "indexedAt": "2026-01-01T00:00:09Z",
             "author": {"did": "did:plc:x"}, "record": {}},
            {"reason": "mention", "indexedAt": "2026-01-01T00:00:05Z",
             "author": {"did": "did:plc:owner"}, "record": {"text": "a"},
             "uri": "at://1", "cid": "c1"},
            {"reason": "reply", "indexedAt": "2026-01-01T00:00:08Z",
             "author": {"did": "did:plc:owner"}, "record": {"text": "b"},
             "uri": "at://2", "cid": "c2"},
        ]
    }

    def _responder(method, url, body):
        if "listNotifications" in url:
            return _FakeResponse(json_data=notifications)
        return _FakeResponse()

    calls = []
    _install_fake_httpx(monkeypatch, calls, _responder)

    chan = BlueskyChannel(handler=_noop, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    chan._session = {"accessJwt": "tok", "did": "did:plc:me"}

    chan._last_seen_indexed_at = "2026-01-01T00:00:00Z"
    new = asyncio.run(chan._poll_once())
    # The like is filtered out; the two mention/reply events come through.
    reasons = sorted(n["reason"] for n in new)
    assert reasons == ["mention", "reply"]
    # Dedup is by uri now (not a strict timestamp watermark): both uris recorded.
    assert chan._seen_uris == {"at://1", "at://2"}

    # Second poll over identical data: both uris already seen -> empty.
    again = asyncio.run(chan._poll_once())
    assert again == []


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_poll_delivers_out_of_order_notification(monkeypatch):
    """A genuinely-new notification indexed BEFORE the newest one (AT-proto
    indexedAt is not monotonic) must still be delivered -- a strict high-water-
    mark on indexedAt must not silently drop it."""
    from maverick_channels.bluesky import BlueskyChannel

    state = {"notifs": [
        {"reason": "mention", "indexedAt": "2026-01-01T00:00:08Z",
         "author": {"did": "did:plc:owner"}, "record": {"text": "first"},
         "uri": "at://newest", "cid": "c1"},
    ]}

    def _responder(method, url, body):
        if "listNotifications" in url:
            return _FakeResponse(json_data={"notifications": state["notifs"]})
        return _FakeResponse()

    calls = []
    _install_fake_httpx(monkeypatch, calls, _responder)
    chan = BlueskyChannel(handler=_noop, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    chan._session = {"accessJwt": "tok", "did": "did:plc:me"}

    chan._last_seen_indexed_at = "2026-01-01T00:00:00Z"
    first = asyncio.run(chan._poll_once())
    assert [n["uri"] for n in first] == ["at://newest"]

    # Next poll: a NEW mention indexed a second EARLIER (late server indexing),
    # alongside the already-seen one. The earlier-but-new uri must come through.
    state["notifs"] = [
        {"reason": "mention", "indexedAt": "2026-01-01T00:00:08Z",
         "author": {"did": "did:plc:owner"}, "record": {"text": "first"},
         "uri": "at://newest", "cid": "c1"},
        {"reason": "mention", "indexedAt": "2026-01-01T00:00:06Z",
         "author": {"did": "did:plc:owner"}, "record": {"text": "late"},
         "uri": "at://late", "cid": "c2"},
    ]
    second = asyncio.run(chan._poll_once())
    assert [n["uri"] for n in second] == ["at://late"]  # delivered, not dropped


# --- send path payload shaping ---------------------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_bluesky_send_shapes_top_level_post(monkeypatch):
    from maverick_channels.bluesky import BlueskyChannel

    calls = []
    _install_fake_httpx(monkeypatch, calls, lambda *a: _FakeResponse())

    chan = BlueskyChannel(handler=_noop, handle="me.bsky.social",
                          password="app-pw", allowed_user_ids={"did:plc:owner"})
    chan._session = {"accessJwt": "tok", "did": "did:plc:me"}

    asyncio.run(chan.send("owner.bsky", "ping"))

    posts = [c for c in calls if c["method"] == "POST"
             and "createRecord" in c["url"]]
    assert len(posts) == 1
    body = posts[0]["json"]
    assert body["repo"] == "did:plc:me"
    assert body["collection"] == "app.bsky.feed.post"
    # Stand-alone send mentions the user and is NOT a threaded reply.
    assert body["record"]["text"] == "@owner.bsky: ping"
    assert "reply" not in body["record"]
    assert posts[0]["headers"]["Authorization"] == "Bearer tok"


# ---------- Bluesky channel ----------

@pytest.mark.asyncio
async def test_bluesky_start_requires_credentials():
    from maverick_channels.bluesky import BlueskyChannel

    async def handler(msg):
        return ""

    ch = BlueskyChannel(handler=handler, handle="", password="", allowed_user_ids={"did:plc:ok"})
    with pytest.raises(RuntimeError, match="BLUESKY_HANDLE"):
        await ch.start()


@pytest.mark.asyncio
async def test_bluesky_session_created_and_cached():
    from maverick_channels.bluesky import BlueskyChannel

    fake_resp = MagicMock()
    fake_resp.json = MagicMock(return_value={
        "accessJwt": "tok-123",
        "did": "did:plc:abc",
        "handle": "user.bsky.social",
    })
    fake_resp.raise_for_status = MagicMock()

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.post = AsyncMock(return_value=fake_resp)

    with patch("httpx.AsyncClient", return_value=fake_client):

        async def handler(msg):
            return ""

        ch = BlueskyChannel(
            handler=handler, handle="me.bsky.social", password="app-pass",
            allowed_user_ids={"did:plc:ok"},
        )
        sess = await ch._ensure_session()
        assert sess["accessJwt"] == "tok-123"
        # Second call hits the cache, no extra POST.
        sess2 = await ch._ensure_session()
        assert sess2["accessJwt"] == "tok-123"
        assert fake_client.post.call_count == 1
