"""Mastodon channel adapter tests.

Mirrors test_voice_channel.py / test_channel_authz.py: skips cleanly when
the optional httpx dep is missing, and otherwise monkeypatches
``httpx.AsyncClient`` to assert (a) construction is fail-closed without an
allowlist, (b) the allowlist denies non-members before the handler runs,
(c) the inbound ``since_id`` cursor advances past seen notifications, and
(d) the reply/send paths shape the Mastodon status form payload correctly.

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
        self._json = json_data if json_data is not None else []
        self.text = ""

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


class _FakeClient:
    def __init__(self, calls, responder):
        self._calls = calls
        self._responder = responder

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, *, headers=None, data=None, json=None, **kw):
        self._calls.append({"method": "POST", "url": url, "headers": headers,
                            "data": data, "json": json})
        return self._responder("POST", url, data)

    async def get(self, url, *, headers=None, params=None, **kw):
        self._calls.append({"method": "GET", "url": url, "headers": headers,
                            "params": params})
        return self._responder("GET", url, params)


def _install_fake_httpx(monkeypatch, calls, responder):
    import httpx

    def _factory(*a, **kw):
        return _FakeClient(calls, responder)

    monkeypatch.setattr(httpx, "AsyncClient", _factory)


# --- construction is fail-closed -------------------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_requires_allowlist():
    from maverick_channels.mastodon import MastodonChannel
    with pytest.raises(ValueError, match="MASTODON_ALLOWED_USER_IDS"):
        MastodonChannel(handler=_noop, instance="mastodon.social",
                        access_token="tok", allowed_user_ids=set())


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_stores_allowlist_and_denies_non_member():
    from maverick_channels.base import is_allowed
    from maverick_channels.mastodon import MastodonChannel
    chan = MastodonChannel(handler=_noop, instance="mastodon.social",
                           access_token="tok", allowed_user_ids={"owner@host"})
    assert is_allowed("owner@host", chan.allowed_user_ids) is True
    assert is_allowed("stranger@host", chan.allowed_user_ids) is False


# --- allowlist gate on the dispatch path -----------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_dispatch_denies_unauthorized_account(monkeypatch):
    from maverick_channels.mastodon import MastodonChannel

    seen = []

    async def _handler(msg):
        seen.append(msg.user_id)
        return "should not be sent"

    calls = []
    _install_fake_httpx(monkeypatch, calls, lambda *a: _FakeResponse())

    chan = MastodonChannel(handler=_handler, instance="mastodon.social",
                           access_token="tok", allowed_user_ids={"owner@host"})

    notif = {
        "account": {"acct": "stranger@host", "username": "stranger"},
        "status": {"id": "99", "content": "<p>hi</p>", "visibility": "public"},
    }
    asyncio.run(chan._dispatch(notif))

    assert seen == []
    assert not any("/api/v1/statuses" in c["url"] for c in calls)


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_dispatch_allows_member_and_shapes_reply(monkeypatch):
    """Allowlisted account reaches the handler (with HTML stripped), and the
    reply posts as an in_reply_to status mentioning the account."""
    from maverick_channels.mastodon import MastodonChannel

    seen = []

    async def _handler(msg):
        seen.append((msg.user_id, msg.text))
        return "hi there"

    calls = []
    _install_fake_httpx(monkeypatch, calls, lambda *a: _FakeResponse())

    chan = MastodonChannel(handler=_handler, instance="mastodon.social",
                           access_token="tok", allowed_user_ids={"owner@host"})

    notif = {
        "id": "notification-42",
        "account": {"acct": "owner@host", "username": "owner"},
        "status": {"id": "42", "content": "<p>are you &amp; there?</p>",
                   "visibility": "unlisted"},
    }
    asyncio.run(chan._dispatch(notif))

    # HTML stripped and entity decoded on the inbound text.
    assert seen == [("owner@host", "are you & there?")]

    posts = [c for c in calls if c["method"] == "POST"
             and c["url"].endswith("/api/v1/statuses")]
    assert len(posts) == 1
    form = posts[0]["data"]
    assert form["status"] == "@owner@host hi there"
    assert form["in_reply_to_id"] == "42"
    # Reply inherits the parent status visibility.
    assert form["visibility"] == "unlisted"
    assert posts[0]["headers"]["Authorization"] == "Bearer tok"


# --- inbound cursor advancement --------------------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_poll_advances_since_id_cursor(monkeypatch):
    """_poll_once requests mention notifications and advances since_id to the
    max id seen; the next poll carries that since_id as a request param."""
    from maverick_channels.mastodon import MastodonChannel

    batch = [
        {"id": "100", "account": {"acct": "owner@host"},
         "status": {"id": "100", "content": "<p>a</p>"}},
        {"id": "103", "account": {"acct": "owner@host"},
         "status": {"id": "103", "content": "<p>b</p>"}},
        {"id": "101", "account": {"acct": "owner@host"},
         "status": {"id": "101", "content": "<p>c</p>"}},
    ]

    def _responder(method, url, params):
        if url.endswith("/api/v1/notifications"):
            return _FakeResponse(json_data=sorted(batch, key=lambda item: int(item["id"]), reverse=True))
        return _FakeResponse()

    calls = []
    _install_fake_httpx(monkeypatch, calls, _responder)

    chan = MastodonChannel(handler=_noop, instance="mastodon.social",
                           access_token="tok", allowed_user_ids={"owner@host"})

    chan._last_seen_id = "0"  # Already initialized; startup no-backfill is tested separately.
    first = asyncio.run(chan._poll_once())
    assert len(first) == 3
    # Cursor is the numeric max, committed after all page receipts exist.
    assert chan._last_seen_id == "103"
    assert calls[0]["params"]["since_id"] == "0"
    # The request targeted mention notifications.
    assert calls[0]["params"]["types[]"] == "mention"

    # Second poll now carries since_id from the advanced cursor.
    calls.clear()
    asyncio.run(chan._poll_once())
    assert calls[0]["params"]["since_id"] == "103"


# --- send path payload shaping ---------------------------------------------

@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_send_shapes_direct_status(monkeypatch):
    from maverick_channels.mastodon import MastodonChannel

    calls = []
    _install_fake_httpx(monkeypatch, calls, lambda *a: _FakeResponse())

    chan = MastodonChannel(handler=_noop, instance="mastodon.social",
                           access_token="tok", allowed_user_ids={"owner@host"})

    asyncio.run(chan.send("owner@host", "ping"))

    posts = [c for c in calls if c["method"] == "POST"
             and c["url"].endswith("/api/v1/statuses")]
    assert len(posts) == 1
    form = posts[0]["data"]
    assert form["status"] == "@owner@host ping"
    assert form["visibility"] == "direct"
    assert posts[0]["headers"]["Authorization"] == "Bearer tok"


@pytest.mark.skipif(not _have_deps(), reason="httpx not installed")
def test_mastodon_cursor_uses_numeric_not_lexicographic_max(monkeypatch):
    """Regression: the since_id cursor used a string max(), so across an
    id digit-length boundary "9999999" sorted after "10000001" and the
    cursor moved backwards, re-delivering notifications. It must advance
    to the numeric max."""
    from maverick_channels.mastodon import MastodonChannel

    batch = [
        {"id": "9999999", "account": {"acct": "owner@host"},
         "status": {"id": "9999999", "content": "<p>old</p>"}},
        {"id": "10000001", "account": {"acct": "owner@host"},
         "status": {"id": "10000001", "content": "<p>new</p>"}},
    ]

    def _responder(method, url, params):
        if url.endswith("/api/v1/notifications"):
            return _FakeResponse(json_data=sorted(batch, key=lambda item: int(item["id"]), reverse=True))
        return _FakeResponse()

    calls = []
    _install_fake_httpx(monkeypatch, calls, _responder)
    chan = MastodonChannel(handler=_noop, instance="mastodon.social",
                           access_token="tok", allowed_user_ids={"owner@host"})
    chan._last_seen_id = "0"
    asyncio.run(chan._poll_once())
    # Numeric max is 10000001; a lexicographic max would wrongly pick 9999999.
    assert chan._last_seen_id == "10000001"


# ---------- Mastodon channel ----------

@pytest.mark.asyncio
async def test_mastodon_requires_token():
    from maverick_channels.mastodon import MastodonChannel

    async def handler(msg):
        return ""

    ch = MastodonChannel(handler=handler, access_token="", allowed_user_ids={"ok@example"})
    with pytest.raises(RuntimeError, match="MASTODON_ACCESS_TOKEN"):
        await ch._poll_once()


def test_mastodon_strip_html():
    from maverick_channels.mastodon import _strip_html
    html = "<p>Hello <a href='x'>world</a>!</p>"
    assert _strip_html(html) == "Hello world!"


@pytest.mark.asyncio
async def test_mastodon_poll_uses_since_id():
    from maverick_channels.mastodon import MastodonChannel

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json = MagicMock(return_value=[
        {"id": "100", "status": {"content": "<p>hi</p>", "id": "200"},
         "account": {"acct": "user@example"}},
    ])
    captured = {}

    async def fake_get(url, headers=None, params=None):
        captured["params"] = params
        return fake_resp

    fake_client = MagicMock()
    fake_client.__aenter__ = AsyncMock(return_value=fake_client)
    fake_client.__aexit__ = AsyncMock(return_value=False)
    fake_client.get = AsyncMock(side_effect=fake_get)

    with patch("httpx.AsyncClient", return_value=fake_client):
        async def handler(msg):
            return ""

        ch = MastodonChannel(
            handler=handler, access_token="tok",
            instance="mastodon.test",
            allowed_user_ids={"user@example"},
        )
        # Start from an explicitly admitted empty checkpoint. A fresh account
        # seeds from the newest historical notification to avoid replaying it.
        ch._last_seen_id = "0"
        first = await ch._poll_once()
        assert len(first) == 1
        assert captured["params"]["since_id"] == "0"

        second_resp = MagicMock()
        second_resp.status_code = 200
        second_resp.raise_for_status = MagicMock()
        second_resp.json = MagicMock(return_value=[])
        async def fake_get2(url, headers=None, params=None):
            captured["params"] = params
            return second_resp
        fake_client.get = AsyncMock(side_effect=fake_get2)
        await ch._poll_once()
        # Second call: since_id = "100".
        assert captured["params"].get("since_id") == "100"
