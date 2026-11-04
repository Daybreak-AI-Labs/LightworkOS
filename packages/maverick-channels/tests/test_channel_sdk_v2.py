"""Channel SDK v2: structured Reply + str shim + dispatch."""
from __future__ import annotations

import asyncio

import pytest
from maverick_channels.base import Channel, IncomingMessage, Reply, as_reply


def test_as_reply_shims_str():
    from maverick import deprecations

    # Other channel tests can exercise this process-wide warn-once path first.
    # Reset the registry so this test verifies and consumes its own warning
    # deterministically regardless of suite order.
    deprecations.reset_warned()
    with pytest.warns(DeprecationWarning, match="bare str"):
        r = as_reply("hello")
    assert isinstance(r, Reply)
    assert r.text == "hello" and r.attachments == [] and r.thread_ref is None


def test_as_reply_passthrough_and_none():
    r = Reply(text="t", attachments=["/a.png"], thread_ref="ts1")
    assert as_reply(r) is r
    assert as_reply(None).text == ""


class _Chan(Channel):
    name = "fake"

    def __init__(self, handler):
        super().__init__(handler)
        self.sent: list = []

    async def start(self):  # pragma: no cover - not exercised
        pass

    async def stop(self):  # pragma: no cover - not exercised
        pass

    async def send(self, user_id, text):
        self.sent.append((user_id, text))


def _msg():
    return IncomingMessage(user_id="u1", text="hi", channel="fake")


def test_dispatch_normalizes_str_handler():
    async def handler(msg):
        return "plain reply"

    ch = _Chan(handler)
    reply = asyncio.run(ch.dispatch(_msg()))
    assert isinstance(reply, Reply) and reply.text == "plain reply"


def test_dispatch_passes_structured_reply():
    async def handler(msg):
        return Reply(text="rich", attachments=["/tmp/x.html"], thread_ref="t9")

    ch = _Chan(handler)
    reply = asyncio.run(ch.dispatch(_msg()))
    assert reply.attachments == ["/tmp/x.html"] and reply.thread_ref == "t9"


def test_dispatch_text_returns_text_and_drops_attachments(caplog):
    async def handler(msg):
        return Reply(text="rich", attachments=["/tmp/x.html"])

    ch = _Chan(handler)
    import logging
    with caplog.at_level(logging.DEBUG, logger="maverick_channels.base"):
        text = asyncio.run(ch.dispatch_text(_msg()))
    assert text == "rich"
    assert any("dropping 1 attachment" in r.message for r in caplog.records)


def test_v2_handler_works_through_a_migrated_adapter():
    """The in-tree adapters route via dispatch_text, so a Reply-returning
    handler flows end-to-end without the adapter knowing about v2."""
    from maverick_channels.irc import IRCChannel  # a real in-tree adapter

    async def handler(msg):
        return Reply(text=f"echo:{msg.text}")

    ch = IRCChannel.__new__(IRCChannel)
    Channel.__init__(ch, handler)
    out = asyncio.run(ch.dispatch_text(_msg()))
    assert out == "echo:hi"


def test_exports():
    import maverick_channels as mc
    assert mc.Reply is Reply and mc.as_reply is as_reply
