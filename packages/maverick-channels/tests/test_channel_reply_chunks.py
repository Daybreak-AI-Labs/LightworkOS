"""Long social replies retain every character and confirmed chunk on retry."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from maverick import world_model
from maverick_channels.base import IncomingMessage, Reply
from maverick_channels.bluesky import BlueskyChannel
from maverick_channels.delivery import DeliveryJournal
from maverick_channels.mastodon import MastodonChannel
from maverick_channels.mattermost import _MAX_POST_CHARS, MattermostChannel


@pytest.mark.parametrize("provider", ["mastodon", "bluesky", "mattermost"])
def test_long_reply_retries_only_rejected_chunk(provider, monkeypatch, tmp_path):
    import httpx

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    calls = []

    class Client:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def post(self, url, *, json=None, data=None, **kwargs):
            payload = json if json is not None else data
            calls.append(payload)
            return httpx.Response(400 if len(calls) == 2 else 200,
                                  json={"id": f"post-{len(calls)}", "uri": f"at://post/{len(calls)}"})

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    handler = AsyncMock()
    if provider == "mastodon":
        channel = MastodonChannel(handler, instance="example.test", access_token="fixture", allowed_user_ids={"owner"})
        limit, prefix = 480, "@owner "
        async def send(reply):
            return await channel._post_reply({"id": "parent", "visibility": "private"}, {"acct": "owner"}, reply.text)
    elif provider == "bluesky":
        channel = BlueskyChannel(handler, handle="example.test", password="fixture", allowed_user_ids={"owner"})
        channel._session = {"did": "did:self", "accessJwt": "fixture"}
        limit, prefix = 300, ""
        async def send(reply):
            return await channel._reply({"uri": "at://parent", "cid": "parent-cid"}, reply.text)
    else:
        channel = MattermostChannel(handler, url="https://example.test", bot_token="fixture", allowed_user_ids={"owner"})
        limit, prefix = _MAX_POST_CHARS, ""
        async def send(reply):
            return await channel._post("room", reply.text, "parent")
    text = "a" * (limit * 2) + "tail"
    handler.return_value = Reply(text)
    message = IncomingMessage(user_id="owner", text="question", channel=provider, message_id="event")
    journal = DeliveryJournal()

    async def run():
        args = dict(external_id="event", account="account", authorize=lambda: True, send=send, journal=journal)
        first = await channel.process_message(message, **args)
        assert first["delivery"] == "retryable"
        second = await channel.process_message(message, **args)
        assert second["delivery"] == "delivered"

    asyncio.run(run())
    handler.assert_awaited_once()
    assert len(calls) == 4
    successful = [payload for index, payload in enumerate(calls) if index != 1]
    chunks = [payload["record"]["text"] if provider == "bluesky" else payload["status" if provider == "mastodon" else "message"]
              for payload in successful]
    assert all(len(chunk) <= limit for chunk in chunks)
    assert "".join(chunk.removeprefix(prefix) for chunk in chunks) == text
    if provider == "mastodon":
        assert all(payload["visibility"] == "private" and payload["in_reply_to_id"] == "parent" for payload in calls)
    elif provider == "bluesky":
        assert all(payload["record"]["reply"]["parent"] == {"uri": "at://parent", "cid": "parent-cid"} for payload in calls)
    else:
        assert all(payload["root_id"] == "parent" and payload["channel_id"] == "room" for payload in calls)


@pytest.mark.parametrize("provider", ["sms", "whatsapp"])
def test_twilio_long_reply_is_chunked_and_retries_only_rejected_chunk(provider, monkeypatch, tmp_path):
    from maverick_channels import sms, whatsapp

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    module, cls = (sms, sms.SMSChannel) if provider == "sms" else (whatsapp, whatsapp.WhatsAppChannel)
    calls = []

    class Rejected(Exception):
        status = 400

    class Messages:
        def create(self, *, body, from_, to):
            calls.append(body)
            if len(calls) == 2:
                raise Rejected("body too long")
            return type("Message", (), {"sid": f"SM{len(calls)}"})()

    handler = AsyncMock()
    channel = cls.__new__(cls)
    channel.handler = handler
    channel.from_number = "+15550000000"
    channel._twilio = type("Client", (), {"messages": Messages()})()
    limit = module.TWILIO_BODY_LIMIT
    text = "a" * (limit * 2) + "tail"
    handler.return_value = Reply(text)
    message = IncomingMessage(user_id="+15551111111", text="question", channel=provider, message_id="SMevent")
    journal = DeliveryJournal()

    async def send(reply):
        return await channel.send(message.user_id, reply.text)

    async def run():
        args = dict(external_id="SMevent", account="account", authorize=lambda: True, send=send, journal=journal)
        first = await channel.process_message(message, **args)
        assert first["delivery"] == "retryable"
        second = await channel.process_message(message, **args)
        assert second["delivery"] == "delivered"

    asyncio.run(run())
    handler.assert_awaited_once()
    assert len(calls) == 4
    successful = [body for index, body in enumerate(calls) if index != 1]
    assert all(len(body) <= limit for body in successful)
    assert "".join(successful) == text


@pytest.mark.parametrize("provider", ["sms", "whatsapp"])
def test_twilio_reply_saved_as_one_rejected_body_still_finishes(provider, monkeypatch, tmp_path):
    """A long reply saved under the old single ``text-0`` key (rejected by
    Twilio) is sent in chunks on the next pass instead of being refused as a
    changed chunk; chunks are counted in UTF-16 units."""
    from maverick_channels import sms, whatsapp
    from maverick_channels.delivery import DeliveryNotSent, send_chunk

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    cls = sms.SMSChannel if provider == "sms" else whatsapp.WhatsAppChannel
    bodies = []

    class Messages:
        def create(self, *, body, from_, to):
            bodies.append(body)
            return type("Message", (), {"sid": f"SM{len(bodies)}"})()

    handler = AsyncMock()
    channel = cls.__new__(cls)
    channel.handler, channel.from_number = handler, "+15550000000"
    channel._twilio = type("Client", (), {"messages": Messages()})()
    text = "\U0001F600" * 1000 + "a" * 700  # 1,700 characters, 2,700 UTF-16 units
    handler.return_value = Reply(text)
    message = IncomingMessage(user_id="+15551111111", text="question", channel=provider, message_id="SMold")
    journal = DeliveryJournal()

    async def old_style(reply):
        async def rejected():
            raise DeliveryNotSent("Provider rejected the message")
        return await send_chunk("text-0", reply.text, rejected)

    async def send(reply):
        return await channel.send(message.user_id, reply.text)

    async def run():
        args = dict(external_id="SMold", account="account", authorize=lambda: True, journal=journal)
        assert (await channel.process_message(message, send=old_style, **args))["delivery"] == "retryable"
        assert (await channel.process_message(message, send=send, **args))["delivery"] == "delivered"

    asyncio.run(run())
    assert "".join(bodies) == text
    assert all(len(body.encode("utf-16-le")) // 2 <= 1600 for body in bodies)
