"""Tool_choice, per-tool strict, and disable_parallel_tool_use reach
the providers.

The Provider protocol, LLM.complete, AnthropicClient._build_request and
OpenAIClient._build_kwargs accepted none of them, so the kernel could not
force a structured tool call, guarantee schema-valid arguments, or serialise
tool calls. They are threaded in Anthropic vocabulary and translated per
provider; a forced choice is clamped to ``auto`` (plus an instruction) where
the API rejects it -- Fable/Mythos 5.1 and manual extended thinking.
"""
from __future__ import annotations

import pytest
from maverick.providers.anthropic_provider import AnthropicClient
from maverick.providers.base import normalize_tool_choice
from maverick.providers.openai_provider import OpenAIClient
from maverick.tools import Tool

TOOLS = [{"name": "get_weather", "description": "d", "input_schema": {"type": "object"}}]


def _anthropic_request(**overrides):
    client = AnthropicClient.__new__(AnthropicClient)
    args = dict(
        system="sys",
        messages=[{"role": "user", "content": "hi"}],
        tools=TOOLS,
        max_tokens=100,
        thinking_budget=None,
        model="claude-opus-4-8",
    )
    args.update(overrides)
    return client._build_request(**args)


# ---- vocabulary ----

def test_normalize_tool_choice_validates_and_copies():
    assert normalize_tool_choice(None) is None
    assert normalize_tool_choice({}) is None
    assert normalize_tool_choice({"type": "any"}) == {"type": "any"}
    assert normalize_tool_choice({"type": "tool", "name": "x", "extra": 1}) == {"type": "tool", "name": "x"}
    assert normalize_tool_choice({"type": "auto", "disable_parallel_tool_use": True}) == {
        "type": "auto", "disable_parallel_tool_use": True}
    with pytest.raises(ValueError):
        normalize_tool_choice({"type": "required"})
    with pytest.raises(ValueError):
        normalize_tool_choice({"type": "tool"})


def test_tool_strict_flag_is_emitted_only_when_set():
    plain = Tool(name="a", description="d", input_schema={"type": "object"}, fn=lambda a: "")
    strict = Tool(name="b", description="d", input_schema={"type": "object"}, fn=lambda a: "", strict=True)
    assert "strict" not in plain.to_anthropic()          # catalog (and cache key) unchanged
    assert strict.to_anthropic()["strict"] is True


# ---- Anthropic translator ----

def test_anthropic_forced_tool_choice_passes_through_where_supported():
    kw = _anthropic_request(tool_choice={"type": "tool", "name": "get_weather",
                                         "disable_parallel_tool_use": True})
    assert kw["tool_choice"] == {"type": "tool", "name": "get_weather",
                                 "disable_parallel_tool_use": True}
    assert kw["messages"][-1]["content"] == "hi"         # no instruction needed


def test_anthropic_omits_tool_choice_without_tools_or_when_unset():
    assert "tool_choice" not in _anthropic_request()
    assert "tool_choice" not in _anthropic_request(tools=None, tool_choice={"type": "any"})


def test_anthropic_clamps_forced_choice_on_fable_5_1_with_an_instruction():
    kw = _anthropic_request(model="claude-fable-5-1",
                            tool_choice={"type": "tool", "name": "get_weather",
                                         "disable_parallel_tool_use": True})
    assert kw["tool_choice"] == {"type": "auto", "disable_parallel_tool_use": True}
    last = kw["messages"][-1]
    assert last["role"] == "user"
    assert last["content"][0] == {"type": "text", "text": "hi"}
    assert last["content"][-1]["text"] == "Respond by calling the `get_weather` tool."
    # ``auto``/``none`` are fine on Fable 5.1 and untouched.
    assert _anthropic_request(model="claude-fable-5-1", tool_choice={"type": "none"})["tool_choice"] == {"type": "none"}


def test_anthropic_clamps_forced_choice_under_manual_thinking():
    # Sonnet 4.6 with an explicit budget sends thinking.type == "enabled",
    # where any/tool are rejected by the API.
    kw = _anthropic_request(model="claude-sonnet-4-6", thinking_budget=2048,
                            tool_choice={"type": "any"})
    assert kw["thinking"]["type"] == "enabled"
    assert kw["tool_choice"] == {"type": "auto"}
    assert kw["messages"][-1]["content"][-1]["text"] == "Respond by calling one of the available tools."
    # Adaptive thinking (Opus 4.8) supports forced tool use: no clamp.
    kw = _anthropic_request(model="claude-opus-4-8", thinking_budget=2048, tool_choice={"type": "any"})
    assert kw["thinking"]["type"] == "adaptive"
    assert kw["tool_choice"] == {"type": "any"}


def test_anthropic_instruction_does_not_mutate_the_callers_history():
    messages = [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]
    _anthropic_request(model="claude-fable-5-1", messages=messages, tool_choice={"type": "any"})
    assert messages == [{"role": "user", "content": [{"type": "text", "text": "hi"}]}]


# ---- OpenAI translator ----

def _openai_kwargs(**overrides):
    client = OpenAIClient.__new__(OpenAIClient)
    args = dict(system="sys", messages=[{"role": "user", "content": "hi"}],
                tools=TOOLS, max_tokens=100, model="gpt-5.4")
    args.update(overrides)
    return client._build_kwargs(**args)


@pytest.mark.parametrize(
    ("choice", "expected"),
    [
        ({"type": "auto"}, "auto"),
        ({"type": "any"}, "required"),
        ({"type": "none"}, "none"),
        ({"type": "tool", "name": "get_weather"}, {"type": "function", "function": {"name": "get_weather"}}),
    ],
)
def test_openai_tool_choice_mapping(choice, expected):
    kw = _openai_kwargs(tool_choice=choice)
    assert kw["tool_choice"] == expected
    assert "parallel_tool_calls" not in kw


def test_openai_disable_parallel_and_strict_tools():
    kw = _openai_kwargs(
        tools=[{**TOOLS[0], "strict": True}],
        tool_choice={"type": "any", "disable_parallel_tool_use": True},
    )
    assert kw["parallel_tool_calls"] is False
    assert kw["tools"][0]["function"]["strict"] is True
    assert "strict" not in _openai_kwargs()["tools"][0]["function"]
    assert "tool_choice" not in _openai_kwargs()


# ---- LLM dispatcher ----

class _Recording:
    DEFAULT_MODEL = "m"

    def __init__(self):
        self.kwargs = None

    async def complete_async(self, system, messages, tools=None, budget=None,
                             max_tokens=4096, thinking_budget=None, model=None,
                             tool_choice=None, **extra):
        from maverick.llm import LLMResponse
        self.kwargs = {"tool_choice": tool_choice, **extra}
        return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")


class _Legacy:
    DEFAULT_MODEL = "m"

    def __init__(self):
        self.called = False

    async def complete_async(self, system, messages, tools=None, budget=None,
                             max_tokens=4096, thinking_budget=None, model=None):
        from maverick.llm import LLMResponse
        self.called = True
        return LLMResponse(text="ok", thinking=None, tool_calls=[], stop_reason="end_turn")


def test_llm_threads_tool_choice_and_drops_it_for_clients_without_the_parameter():
    from maverick.llm import _add_tool_choice

    kw: dict = {}
    recording = _Recording()
    _add_tool_choice(kw, {"type": "tool", "name": "get_weather"}, recording, "complete_async", TOOLS)
    assert kw == {"tool_choice": {"type": "tool", "name": "get_weather"}}
    kw = {}
    _add_tool_choice(kw, {"type": "any"}, _Legacy(), "complete_async", TOOLS)
    assert kw == {}                                   # no parameter -> dropped, not a TypeError
    kw = {}
    _add_tool_choice(kw, {"type": "any"}, recording, "complete_async", None)
    assert kw == {}                                   # no tools -> nothing to choose from
    with pytest.raises(ValueError):
        _add_tool_choice({}, {"type": "bogus"}, recording, "complete_async", TOOLS)


@pytest.mark.asyncio
async def test_llm_complete_async_accepts_tool_choice(monkeypatch):
    from maverick.llm import LLM

    llm = LLM(model="anthropic:claude-opus-4-8")
    recording = _Recording()
    monkeypatch.setattr(llm, "_get_client", lambda provider: recording)
    monkeypatch.setattr("maverick.llm._run_preflight", lambda *a, **k: None, raising=False)
    resp = await llm.complete_async(
        system="s", messages=[{"role": "user", "content": "hi"}], tools=TOOLS,
        tool_choice={"type": "any", "disable_parallel_tool_use": True},
    )
    assert resp.text == "ok"
    assert recording.kwargs["tool_choice"] == {"type": "any", "disable_parallel_tool_use": True}
