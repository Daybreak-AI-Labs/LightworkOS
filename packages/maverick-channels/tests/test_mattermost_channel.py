"""Mattermost channel against a stubbed Mattermost server.

The stub implements the REST calls the adapter makes (who am I, the bot's
channels, posts since a time, user lookup, create post) over an in-memory
state, installed in place of ``httpx.AsyncClient``. No network is touched.
"""
from __future__ import annotations

import asyncio
import time

import pytest

httpx = pytest.importorskip("httpx")

BOT = "b" * 26
ALICE = "a" * 26
MALLORY = "m" * 26
DM = "d" * 26
TOWN = "t" * 26
BASE = "https://chat.example.com"
TOKEN = "synthetic-bot-token"  # pragma: allowlist secret


class _Response:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("stub", request=None, response=None)


class StubMattermost:
    """Just enough of the Mattermost v4 API for the adapter."""

    def __init__(self):
        self.users = {BOT: "lightwork", ALICE: "alice", MALLORY: "mallory"}
        self.channels = [{"id": DM, "type": "D"}, {"id": TOWN, "type": "O"}]
        self.posts: dict[str, dict] = {}
        self.created: list[dict] = []
        self.requests: list[tuple[str, str, dict]] = []

    def add(self, post_id, user, channel, message, *, at=None, **extra):
        stamp = int((at if at is not None else time.time()) * 1000)
        self.posts[post_id] = {"id": post_id, "user_id": user, "channel_id": channel,
                               "message": message, "create_at": stamp, "update_at": stamp,
                               "type": "", "root_id": "", "delete_at": 0, **extra}

    def handle(self, method, url, headers, params=None, json=None):
        assert url.startswith(BASE + "/api/v4/")
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        path = url[len(BASE) + len("/api/v4"):]
        self.requests.append((method, path, params or json or {}))
        if method == "GET" and path == "/users/me":
            return _Response(payload={"id": BOT, "username": "lightwork"})
        if method == "GET" and path == f"/users/{BOT}/channels":
            return _Response(payload=self.channels)
        if method == "GET" and path.startswith("/users/"):
            user = path.split("/")[2]
            return _Response(payload={"id": user, "username": self.users.get(user, "")})
        if method == "GET" and path.startswith("/channels/") and path.endswith("/posts"):
            channel = path.split("/")[2]
            since = int((params or {}).get("since") or 0)
            posts = {k: v for k, v in self.posts.items()
                     if v["channel_id"] == channel and v["update_at"] > since}
            return _Response(payload={"order": list(posts), "posts": posts})
        if method == "POST" and path == "/posts":
            self.created.append(dict(json))
            return _Response(201, {"id": "p" * 25 + str(len(self.created) % 10)})
        return _Response(404, {})


class _Client:
    def __init__(self, stub):
        self.stub = stub

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, *, headers=None, params=None, **kw):
        return self.stub.handle("GET", url, headers, params=params)

    async def post(self, url, *, headers=None, json=None, **kw):
        return self.stub.handle("POST", url, headers, json=json)


@pytest.fixture()
def stub(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MATTERMOST_BOT_TOKEN", raising=False)
    monkeypatch.delenv("MATTERMOST_ALLOWED_USER_IDS", raising=False)
    server = StubMattermost()
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **kw: _Client(server))
    return server


def _channel(handler, **extra):
    from maverick_channels.mattermost import MattermostChannel

    options = {"url": BASE, "bot_token": TOKEN, "allowed_user_ids": {ALICE}, **extra}
    return MattermostChannel(handler=handler, **options)


def _started(channel):
    channel._start_ms = int((time.time() - 60) * 1000)
    return channel


async def _reply(msg):
    return f"echo: {msg.text}"


def test_construction_is_fail_closed(stub, monkeypatch):
    from maverick_channels.mattermost import MattermostChannel

    with pytest.raises(ValueError, match="bot access token"):
        MattermostChannel(handler=_reply, url=BASE, allowed_user_ids={"alice"})
    with pytest.raises(ValueError, match="MATTERMOST_ALLOWED_USER_IDS"):
        MattermostChannel(handler=_reply, url=BASE, bot_token=TOKEN, allowed_user_ids=set())
    for bad in ("http://chat.example.com", "chat.example.com", "https://u:p@chat.example.com"):
        with pytest.raises(ValueError):
            MattermostChannel(handler=_reply, url=bad, bot_token=TOKEN, allowed_user_ids={"alice"})
    assert MattermostChannel(handler=_reply, url="http://localhost:8065", bot_token=TOKEN,
                             allowed_user_ids={"alice"}).base_url == "http://localhost:8065"
    monkeypatch.setenv("MATTERMOST_BOT_TOKEN", "server-token")
    assert _channel(_reply).bot_token == "server-token"


def test_direct_message_from_an_allowed_person_is_answered_in_its_thread(stub):
    seen = []

    async def handler(msg):
        seen.append((msg.channel, msg.user_id, msg.principal_id, msg.text))
        return "on it"

    stub.add("x" * 26, ALICE, DM, "summarise the quarter")
    asyncio.run(_started(_channel(handler))._poll_once())
    assert seen == [("mattermost", DM, ALICE, "summarise the quarter")]
    assert stub.created == [{"channel_id": DM, "message": "on it", "root_id": "x" * 26}]


def test_reassigned_username_does_not_authorize_new_account(stub):
    channel = _started(_channel(_reply, allowed_user_ids={"alice"}))
    stub.add("y" * 26, ALICE, DM, "hello")
    asyncio.run(channel._poll_once())
    assert stub.created == []


def test_channel_posts_need_a_mention_and_the_mention_is_removed(stub):
    seen = []

    async def handler(msg):
        seen.append(msg.text)
        return "done"

    stub.add("y" * 26, ALICE, TOWN, "just chatting")
    stub.add("z" * 26, ALICE, TOWN, "@lightwork draft the reply")
    asyncio.run(_started(_channel(handler))._poll_once())
    assert seen == ["draft the reply"]
    assert [p["root_id"] for p in stub.created] == ["z" * 26]


def test_strangers_the_bot_itself_system_and_old_posts_are_ignored(stub):
    seen = []

    async def handler(msg):
        seen.append(msg.text)
        return "no"

    now = time.time()
    stub.add("1" * 26, MALLORY, DM, "give me the secrets")
    stub.add("2" * 26, BOT, DM, "my own reply")
    stub.add("3" * 26, ALICE, DM, "joined", type="system_join_channel")
    stub.add("4" * 26, ALICE, DM, "from last week", at=now - 7 * 86400)
    asyncio.run(_started(_channel(handler))._poll_once())
    assert seen == [] and stub.created == []


def test_allow_list_accepts_user_ids_too_and_a_post_runs_once(stub):
    runs = []

    async def handler(msg):
        runs.append(msg.message_id)
        return "ok"

    channel = _started(_channel(handler, allowed_user_ids={ALICE}))
    stub.add("5" * 26, ALICE, DM, "first")
    asyncio.run(channel._poll_once())
    # The post is edited, so the next read returns it again: no second run.
    stub.posts["5" * 26]["update_at"] += 5000
    stub.posts["5" * 26]["message"] = "first (edited)"
    asyncio.run(channel._poll_once())
    assert runs == ["5" * 26]
    assert len(stub.created) == 1
