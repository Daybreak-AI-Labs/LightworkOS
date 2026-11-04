"""Local ASGI/callback acceptance with real durable channel authority."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import httpx
import pytest
from maverick_channels.delivery import DeliveryJournal
from maverick_channels.voice import VoiceChannel


async def until(predicate):
    async def wait():
        while not await predicate():
            await asyncio.sleep(0.005)
    await asyncio.wait_for(wait(), timeout=5)


def voice_event(**fields):
    return {"message": {"type": fields.get("type", "tool-calls"),
            "call": {"id": "call1", "assistantId": "fixture-assistant", "customer": {"number": "+12025550111"}},
            "toolCallList": [{"id": fields.get("id", "event1"), "name": "lightwork_request",
                              "parameters": {"request": fields.get("request", "question")}}]}}


def test_voice_parallel_callbacks_return_saved_result_with_one_execution():
    async def run():
        entered, release = asyncio.Event(), asyncio.Event()
        async def handler(message):
            entered.set()
            await release.wait()
            return "saved response"
        handler_mock = AsyncMock(side_effect=handler)
        channel = VoiceChannel(handler_mock, api_key="fixture", webhook_token="fixture", assistant_id="fixture-assistant",  # pragma: allowlist secret -- test fixture values
                               allowed_callers={"+12025550111"})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=channel._app), base_url="http://fixture",
                                     headers={"Authorization": "Bearer fixture"}) as client:
            first = asyncio.create_task(client.post("/webhook/voice", json=voice_event()))
            await asyncio.wait_for(entered.wait(), timeout=5)
            duplicates = await asyncio.gather(*(client.post("/webhook/voice", json=voice_event()) for _ in range(3)))
            assert all(response.status_code == 200 and "still processing" in response.json()["results"][0]["result"]
                       for response in duplicates)
            release.set()
            saved = {"results": [{"name": "lightwork_request", "toolCallId": "event1", "result": "saved response"}]}
            assert (await first).json() == saved
            assert (await client.post("/webhook/voice", json=voice_event())).json() == saved
            handler_mock.assert_awaited_once()
            channel.allowed_callers = {"+12025550112"}
            response = await client.post("/webhook/voice", json=voice_event())
            assert "saved response" not in response.text
        row = DeliveryJournal().store.list(limit=1)[0]
        assert row["execution"] == "completed" and row["delivery"] == "delivery_unknown"
    asyncio.run(run())


def test_voice_partial_missing_identity_and_changed_replay_do_not_execute():
    async def run():
        handler = AsyncMock(return_value="answer")
        channel = VoiceChannel(handler, api_key="fixture", webhook_token="fixture", assistant_id="fixture-assistant",  # pragma: allowlist secret -- test fixture values
                               allowed_callers={"+12025550111"})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=channel._app), base_url="http://fixture",
                                     headers={"Authorization": "Bearer fixture"}) as client:
            assert (await client.post("/webhook/voice", json=voice_event(type="transcript"))).json() == {}
            assert (await client.post("/webhook/voice", json=voice_event(id=None))).status_code == 400
            handler.assert_not_awaited()
            assert (await client.post("/webhook/voice", json=voice_event())).status_code == 200
            assert (await client.post("/webhook/voice", json=voice_event(request="changed"))).status_code == 409
            handler.assert_awaited_once()
    asyncio.run(run())


def test_vapi_tool_calls_in_the_documented_nested_shape_are_accepted():
    # Vapi's custom-tools reference sends {id, type, function: {name, arguments}}
    # (and toolWithToolCallList[].toolCall.function); only the flat
    # {name, parameters} shape was read, so such calls were all refused.
    from maverick_channels.voice import parse_request

    call = {"id": "call1", "assistantId": "assistant-1", "customer": {"number": "+12025550111"}}
    function = {"name": "lightwork_request", "arguments": {"request": "What is due today?"}}
    for arguments in (function["arguments"], '{"request": "What is due today?"}'):
        nested = {"id": "tool-1", "type": "function", "function": {**function, "arguments": arguments}}
        message = {"type": "tool-calls", "call": call, "toolCallList": [nested],
                   "toolWithToolCallList": [{"type": "function", "server": {"url": "https://x.example"},
                                             "function": {"name": "lightwork_request", "parameters": {}},
                                             "toolCall": nested}]}
        parsed = parse_request({"message": message}, provider="vapi", assistant_id="assistant-1",
                               callers={"+12025550111"})
        assert parsed[2] == [("tool-1", "What is due today?")]
    only_wrapped = {"type": "tool-calls", "call": call, "toolWithToolCallList": [
        {"type": "function", "function": {"name": "lightwork_request"}, "toolCall": nested}]}
    assert parse_request({"message": only_wrapped}, provider="vapi", assistant_id="assistant-1",
                         callers={"+12025550111"})[2] == [("tool-1", "What is due today?")]
    other = {"id": "tool-2", "type": "function", "function": {"name": "transfer_call", "arguments": {}}}
    with pytest.raises(ValueError, match="not supported"):
        parse_request({"message": {"type": "tool-calls", "call": call, "toolCallList": [other]}},
                      provider="vapi", assistant_id="assistant-1", callers={"+12025550111"})
