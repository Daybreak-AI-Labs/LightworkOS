"""Request-level regressions; fake clients only, no credentials or API calls."""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from maverick.providers import openai_provider
from maverick.providers.openai_provider import OpenAIClient


def _tool(name):
    return {"name": name, "description": name, "input_schema": {"type": "object"}}


@pytest.fixture(autouse=True)
def _no_remembered_rejections(monkeypatch):
    monkeypatch.setattr(OpenAIClient, "_TOOL_REASONING_REJECTED", set())


@pytest.mark.parametrize("model", ["o3", "gpt-5", "gpt-5.1", "gpt-5.2"])
def test_tools_preserve_requested_reasoning_until_provider_rejects_it(model):
    client = OpenAIClient.__new__(OpenAIClient)
    request = client._build_kwargs("system", [], [_tool("read")], 500, model, 1_000)
    assert request["reasoning_effort"] == "low"


@pytest.mark.parametrize("model", ["gpt-5.4", "gpt-5.4-mini", "gpt-5.5", "gpt-5.6-terra", "gpt-6-astra"])
@pytest.mark.parametrize("thinking_budget", [None, 1_000])
def test_from_gpt_5_4_tool_calls_ask_for_no_reasoning_up_front(model, thinking_budget):
    # OpenAI: "Starting with GPT-5.4, Chat Completions does not support tool
    # calling with reasoning_effort values other than none." Live, every tool
    # turn on gpt-5.4-mini was rejected first and resent, and each rejected
    # attempt was kept as an unknown charge that blocks a provider spending cap.
    client = OpenAIClient.__new__(OpenAIClient)
    request = client._build_kwargs("system", [], [_tool("read")], 500, model, thinking_budget)
    assert request["reasoning_effort"] == "none"
    # Without tools the requested reasoning is unchanged.
    plain = client._build_kwargs("system", [], None, 500, model, 1_000)
    assert plain.get("reasoning_effort") == ("low" if model.startswith("gpt-5") else None)


def test_cap_keeps_registration_priority_before_cache_sort(monkeypatch):
    monkeypatch.setattr(openai_provider, "_OPENAI_MAX_TOOLS", 128)
    tools = [_tool("z_core")] + [_tool(f"extension_{i:03d}") for i in range(129)]
    client = OpenAIClient.__new__(OpenAIClient)
    request = client._build_kwargs("long stable prefix " * 400, [], tools, 500, "gpt-5.1")
    names = [item["function"]["name"] for item in request["tools"]]
    assert len(names) == 128
    assert set(names) == {tool["name"] for tool in tools[:128]}
    assert names == sorted(names)
    assert tools[0]["name"] == "z_core"  # Caller-owned registry is untouched.


def test_cap_keeps_explicitly_required_tool(monkeypatch):
    monkeypatch.setattr(openai_provider, "_OPENAI_MAX_TOOLS", 128)
    tools = [_tool(f"tool_{i:03d}") for i in range(129)]
    client = OpenAIClient.__new__(OpenAIClient)
    request = client._build_kwargs(
        "system", [], tools, 500, "gpt-5.1",
        tool_choice={"type": "tool", "name": "tool_128", "disable_parallel_tool_use": True},
    )
    names = [item["function"]["name"] for item in request["tools"]]
    assert len(names) == 128 and "tool_128" in names and "tool_000" in names
    assert request["tool_choice"] == {"type": "function", "function": {"name": "tool_128"}}
    assert request["parallel_tool_calls"] is False


def _bad_request(message):
    sdk = pytest.importorskip("openai")
    response = httpx.Response(400, request=httpx.Request("POST", "https://example.invalid/chat"))
    body = {"message": message}
    # Match the SDK's error envelope, including its escaped repr of the body.
    return sdk.BadRequestError(f"Error code: 400 - { {'error': body} }", response=response, body=body)


_REJECTION = (
    'Function tools with reasoning_effort are not supported for model "fixture" in Chat Completions; '
    "use /v1/responses or set reasoning_effort to 'none'."
)


def _fake_client(errors):
    calls = []
    result = object()

    def create(**kwargs):
        calls.append(kwargs)
        if errors:
            raise errors.pop(0)
        return result

    async def create_async(**kwargs):
        return create(**kwargs)

    client = OpenAIClient.__new__(OpenAIClient)
    client._sync = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    client._async = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create_async)))
    client._from_response = lambda response, *args, **kwargs: response
    return client, calls, result


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("thinking_budget", [None, 1_000])
async def test_explicit_provider_rejection_retries_once_with_tools(asynchronous, thinking_budget):
    client, calls, expected = _fake_client([_bad_request(_REJECTION)])
    kwargs = {"tools": [_tool("read")], "model": "gpt-5.1", "thinking_budget": thinking_budget}
    if asynchronous:
        result = await client.complete_async("system", [], **kwargs)
    else:
        result = client.complete("system", [], **kwargs)
    assert result is expected and len(calls) == 2
    assert calls[0].get("reasoning_effort") == ("low" if thinking_budget else None)
    assert calls[1] == {**calls[0], "reasoning_effort": "none"}


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_second_compatibility_error_propagates_without_retry_loop(asynchronous):
    first, second = _bad_request(_REJECTION), _bad_request(_REJECTION)
    client, calls, _result = _fake_client([first, second])
    with pytest.raises(type(second)) as raised:
        if asynchronous:
            await client.complete_async("system", [], tools=[_tool("read")], model="gpt-5.1")
        else:
            client.complete("system", [], tools=[_tool("read")], model="gpt-5.1")
    assert raised.value is second and len(calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_unrelated_request_error_is_not_rewritten(asynchronous):
    error = _bad_request("Invalid function schema")
    client, calls, _result = _fake_client([error])
    with pytest.raises(type(error)) as raised:
        if asynchronous:
            await client.complete_async("system", [], tools=[_tool("read")], model="o3", thinking_budget=1_000)
        else:
            client.complete("system", [], tools=[_tool("read")], model="o3", thinking_budget=1_000)
    assert raised.value is error and len(calls) == 1
    assert calls[0]["reasoning_effort"] == "low"


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_a_model_that_rejected_tool_reasoning_is_not_asked_again(asynchronous):
    client, calls, expected = _fake_client([_bad_request(_REJECTION)])
    kwargs = {"tools": [_tool("read")], "model": "gpt-5.1", "thinking_budget": 1_000}
    for _ in range(2):
        if asynchronous:
            assert await client.complete_async("system", [], **kwargs) is expected
        else:
            assert client.complete("system", [], **kwargs) is expected
    assert [call["reasoning_effort"] for call in calls] == ["low", "none", "none"]
    # Another model still keeps its requested reasoning.
    other = client._build_kwargs("system", [], [_tool("read")], 500, "o3", 1_000)
    assert other["reasoning_effort"] == "low"
