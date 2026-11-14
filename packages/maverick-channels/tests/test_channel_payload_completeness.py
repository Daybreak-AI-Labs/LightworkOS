"""Attachments and Matrix reply chunks preserve complete provider payloads."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from aiohttp.base_protocol import BaseProtocol
from maverick_channels import matrix, slack
from maverick_channels.delivery import DeliveryNotSent


@pytest.mark.parametrize("declared,blocks,expected", [
    (8, [b"first", b"end"], b"firstend"),
    (9, [b"first", b"end"], None),
    (7, [b"first", b"end"], None),
    (None, [b"first", b"end"], None),
    (True, [b"first", b"end"], None),
    ("eight", [b"first", b"end"], None),
    (100 * 1024 * 1024 + 1, [b"first", b"end"], None),
])
def test_slack_download_waits_for_eof_and_checks_advertised_size(monkeypatch, declared, blocks, expected):
    async def run():
        protocol = BaseProtocol(asyncio.get_running_loop())
        protocol.connection_made(MagicMock(spec=asyncio.Transport))
        stream = aiohttp.StreamReader(protocol, 65536)
        stream.feed_data(blocks[0])
        loop = asyncio.get_running_loop()
        def finish():
            stream.feed_data(blocks[1])
            stream.feed_eof()
        loop.call_soon(finish)

        class Response:
            content = stream
            def raise_for_status(self):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass

        class Session:
            def __init__(self, **kwargs):
                pass
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                pass
            def get(self, url):
                return Response()

        monkeypatch.setattr(aiohttp, "ClientSession", Session)
        channel = slack.SlackChannel.__new__(slack.SlackChannel)
        channel.bot_token = "synthetic"
        result = await channel._download_files({"files": [{
            "url_private_download": "https://files.slack.com/fixture",
            "size": declared, "name": "evidence.txt", "mimetype": "text/plain",
        }]})
        assert [item["data"] for item in result] == ([] if expected is None else [expected])
    asyncio.run(run())


def test_matrix_chunk_retry_preserves_every_character_and_transaction(monkeypatch):
    from maverick_channels.base import IncomingMessage, Reply
    from maverick_channels.delivery import DeliveryJournal

    monkeypatch.setenv("MAVERICK_GOVERNED_RECORD_BACKEND", "local")
    text = ("\U0001f600\x01" * 11000) + "last"
    handler = AsyncMock(return_value=Reply(text))
    channel = matrix.MatrixChannel.__new__(matrix.MatrixChannel)
    channel.handler = handler
    calls = []
    async def post(**payload):
        calls.append(payload)
        assert len(json.dumps(payload["content"]).encode("utf-8")) < 60 * 1024
        if len(calls) == 2:
            raise TimeoutError("acceptance uncertain")
        return SimpleNamespace(event_id=f"$event-{len(calls)}")
    channel._client = SimpleNamespace(room_send=post)
    msg = IncomingMessage(user_id="!room:example.test", text="question", channel="matrix", message_id="$input")
    journal = DeliveryJournal()
    async def send(reply):
        return await channel.send(msg.user_id, reply.text)
    async def run():
        kwargs = dict(external_id="$input", account="matrix-fixture", authorize=lambda: True,
                      send=send, journal=journal, idempotent=True)
        assert (await channel.process_message(msg, **kwargs))["delivery"] == "delivery_unknown"
        assert (await channel.process_message(msg, **kwargs))["delivery"] == "delivered"
    asyncio.run(run())
    handler.assert_awaited_once()
    assert calls[1] == calls[2]
    assert len({call["tx_id"] for call in calls}) == len(calls) - 1
    assert "".join(call["content"]["body"] for index, call in enumerate(calls) if index != 1) == text
    row = journal.store.list()[0]
    assert set(row["chunks"]) == {"reply", *(f"text-{i}" for i in range(len(calls) - 1))}


def test_matrix_too_large_is_definitively_not_sent():
    channel = matrix.MatrixChannel.__new__(matrix.MatrixChannel)
    channel._client = SimpleNamespace(room_send=AsyncMock(return_value=SimpleNamespace(status_code="M_TOO_LARGE")))
    with pytest.raises(DeliveryNotSent, match="Matrix rejected"):
        asyncio.run(channel.send("!room:example.test", "reply"))
