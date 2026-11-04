"""OpenAI provider format-translation tests.

No API calls. Pure unit tests on ``_to_openai_messages``, ``_to_openai_tools``,
``_from_response``, ``_extract_tool_result_text``, ``_wants_max_completion``.
"""
from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest
from maverick.providers.openai_provider import (
    OpenAIClient,
    _extract_tool_result_text,
)
from maverick.providers.openrouter_provider import OpenRouterClient


class TestExtractToolResultText:
    def test_string(self):
        assert _extract_tool_result_text("hello") == "hello"

    def test_list_of_text_blocks(self):
        blocks = [
            {"type": "text", "text": "first"},
            {"type": "text", "text": "second"},
        ]
        assert _extract_tool_result_text(blocks) == "first\nsecond"

    def test_none(self):
        assert _extract_tool_result_text(None) == ""

    def test_int_coerced(self):
        assert _extract_tool_result_text(42) == "42"


class TestToOpenAIMessages:
    def test_plain_user_and_assistant(self):
        out = OpenAIClient._to_openai_messages(
            "sys",
            [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": "hello"},
            ],
        )
        assert out == [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "hi"},
            {"role": "assistant", "content": "hello"},
        ]

    def test_tool_use_round_trip(self):
        msgs = [
            {"role": "user", "content": "what time is it?"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "let me check"},
                {"type": "tool_use", "id": "t1", "name": "clock",
                 "input": {"tz": "UTC"}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "10:00"},
            ]},
        ]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        assert out[0]["role"] == "system"
        assert out[1]["role"] == "user"
        assert out[2]["role"] == "assistant"
        assert out[2]["content"] == "let me check"
        assert "tool_calls" in out[2]
        tc = out[2]["tool_calls"][0]
        assert tc["id"] == "t1"
        assert tc["function"]["name"] == "clock"
        assert json.loads(tc["function"]["arguments"]) == {"tz": "UTC"}
        assert out[3] == {"role": "tool", "tool_call_id": "t1", "content": "10:00"}

    def test_thinking_blocks_dropped(self):
        msgs = [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": "internal"},
            {"type": "text", "text": "the answer is 42"},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        # System + assistant, thinking gone, text preserved.
        assert len(out) == 2
        assert out[1]["content"] == "the answer is 42"
        assert "tool_calls" not in out[1]

    def test_empty_assistant_turn_skipped(self):
        # Pure-thinking assistant turn would otherwise emit content=None which
        # OpenAI rejects -- the translator drops it entirely.
        msgs = [{"role": "assistant", "content": [
            {"type": "thinking", "thinking": "internal only"},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        assert len(out) == 1  # only the system message

    def test_assistant_with_only_tool_calls(self):
        msgs = [{"role": "assistant", "content": [
            {"type": "tool_use", "id": "x", "name": "f", "input": {}},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        # Empty content + tool_calls is valid; content must be "" not None.
        assert out[1]["content"] == ""
        assert out[1]["tool_calls"][0]["function"]["name"] == "f"

    def test_tool_result_list_content(self):
        msgs = [{"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1",
             "content": [{"type": "text", "text": "line 1"},
                         {"type": "text", "text": "line 2"}]},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        assert out[1] == {"role": "tool", "tool_call_id": "t1", "content": "line 1\nline 2"}

    def test_image_block_becomes_image_url_part_not_stringified_text(self):
        # An image block used to str()-stringify into the joined text
        # body -- the base64 payload landed in the prompt as literal text
        # (a Python dict repr), not an actual image the model could see.
        msgs = [{"role": "user", "content": [
            {"type": "text", "text": "what is this?"},
            {"type": "image", "source": {
                "type": "base64", "media_type": "image/png", "data": "QUJD",
            }},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        user_msg = out[1]
        assert user_msg["role"] == "user"
        assert isinstance(user_msg["content"], list)
        parts = {p["type"] for p in user_msg["content"]}
        assert parts == {"text", "image_url"}
        text_part = next(p for p in user_msg["content"] if p["type"] == "text")
        image_part = next(p for p in user_msg["content"] if p["type"] == "image_url")
        assert "QUJD" not in text_part["text"], "base64 payload leaked into the text part"
        assert image_part["image_url"]["url"] == "data:image/png;base64,QUJD"

    def test_image_url_source_passed_through_verbatim(self):
        msgs = [{"role": "user", "content": [
            {"type": "image", "source": {
                "type": "url", "url": "https://example.test/cat.png",
            }},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        image_part = out[1]["content"][0]
        assert image_part == {
            "type": "image_url",
            "image_url": {"url": "https://example.test/cat.png"},
        }

    def test_text_only_turn_still_collapses_to_a_plain_string(self):
        # No image in the turn -> keep the pre-existing plain-string shape
        # (not a single-element content-part list) so nothing downstream
        # that expects a string for a text-only turn breaks.
        msgs = [{"role": "user", "content": [
            {"type": "text", "text": "hello"},
        ]}]
        out = OpenAIClient._to_openai_messages("sys", msgs)
        assert out[1] == {"role": "user", "content": "hello"}

    def test_document_block_raises_instead_of_stringifying(self):
        # OpenAI-family providers have no equivalent to Anthropic's
        # inline document content type -- reject loudly rather than
        # silently stringifying a base64 PDF into the prompt text.
        msgs = [{"role": "user", "content": [
            {"type": "document", "source": {
                "type": "base64", "media_type": "application/pdf", "data": "JVBERi0x",
            }},
        ]}]
        with pytest.raises(RuntimeError, match="document"):
            OpenAIClient._to_openai_messages("sys", msgs)


class TestToOpenAITools:
    def test_basic(self):
        out = OpenAIClient._to_openai_tools([{
            "name": "calc",
            "description": "do math",
            "input_schema": {"type": "object", "properties": {"x": {"type": "number"}}},
        }])
        assert out == [{
            "type": "function",
            "function": {
                "name": "calc",
                "description": "do math",
                "parameters": {"type": "object", "properties": {"x": {"type": "number"}}},
            },
        }]

    def test_empty_returns_none(self):
        assert OpenAIClient._to_openai_tools(None) is None
        assert OpenAIClient._to_openai_tools([]) is None


class TestWantsMaxCompletion:
    def test_gpt_4o(self):
        assert OpenAIClient._wants_max_completion("gpt-4o")
        assert OpenAIClient._wants_max_completion("gpt-4o-mini")

    def test_o_series(self):
        assert OpenAIClient._wants_max_completion("o1")
        assert OpenAIClient._wants_max_completion("o3-mini")

    def test_gpt_5(self):
        assert OpenAIClient._wants_max_completion("gpt-5")

    def test_later_generations(self):
        """gpt-6 and later reject max_tokens with a 400 (seen in production
        on gpt-6.1-sol); the generation number decides, not a release list."""
        for name in ("gpt-6-astra", "gpt-6.1-sol", "gpt-6-luna", "gpt-5.6-luna", "gpt-7"):
            assert OpenAIClient._wants_max_completion(name), name

    def test_older_generations_keep_max_tokens(self):
        for name in ("gpt-4", "gpt-4-turbo", "gpt-3.5-turbo"):
            assert not OpenAIClient._wants_max_completion(name), name

    def test_legacy(self):
        assert not OpenAIClient._wants_max_completion("gpt-3.5-turbo")
        assert not OpenAIClient._wants_max_completion("text-davinci-003")


class TestFromResponse:
    def test_finish_reason_mapped(self):
        resp = SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(content="hi", tool_calls=None),
                finish_reason="tool_calls",
            )],
            usage=None,
        )
        out = OpenAIClient._from_response(resp, budget=None)
        # tool_calls -> tool_use (Anthropic vocab)
        assert out.stop_reason == "tool_use"

    def test_finish_reason_length_mapped(self):
        resp = SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(content="truncated", tool_calls=None),
                finish_reason="length",
            )],
            usage=None,
        )
        out = OpenAIClient._from_response(resp, budget=None)
        assert out.stop_reason == "max_tokens"

    def test_invalid_arguments_default_to_empty(self):
        # If the model returns malformed JSON for tool args, don't crash.
        tc = SimpleNamespace(
            id="x",
            function=SimpleNamespace(name="f", arguments="not-valid-json"),
        )
        resp = SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(content="", tool_calls=[tc]),
                finish_reason="tool_calls",
            )],
            usage=None,
        )
        out = OpenAIClient._from_response(resp, budget=None)
        assert out.tool_calls[0].input == {}


class TestProviderApiKeyIsolation:
    def test_openrouter_does_not_fallback_to_openai_env(self, monkeypatch):
        captures = []

        class FakeClient:
            def __init__(
                self, api_key=None, base_url=None, timeout=None, max_retries=None,
            ):
                captures.append((api_key, base_url))

        class FakeModule:
            OpenAI = FakeClient
            AsyncOpenAI = FakeClient

        monkeypatch.setitem(sys.modules, "openai", FakeModule())
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)

        # With no OpenRouter key, the client must NOT silently fall back to
        # OPENAI_API_KEY (which would ship the user's OpenAI key to
        # openrouter.ai). It now fails closed with RuntimeError rather than
        # constructing a leaky client.
        with pytest.raises(RuntimeError, match="requires a non-empty API key"):
            OpenRouterClient()
        assert captures == []

    def test_openrouter_prefers_openrouter_env(self, monkeypatch):
        captures = []

        class FakeClient:
            def __init__(
                self, api_key=None, base_url=None, timeout=None, max_retries=None,
            ):
                captures.append((api_key, base_url))

        class FakeModule:
            OpenAI = FakeClient
            AsyncOpenAI = FakeClient

        monkeypatch.setitem(sys.modules, "openai", FakeModule())
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        monkeypatch.setenv("OPENROUTER_API_KEY", "sk-openrouter")

        OpenRouterClient()

        assert captures[0][0] == "sk-openrouter"
        assert captures[1][0] == "sk-openrouter"


def test_tool_result_never_follows_a_user_message():
    # Regression: a `tool` message must immediately follow the assistant
    # tool_calls -- a `user` message between them is an OpenAI 400. Anthropic
    # allows text before/between tool_result blocks; the translator must
    # reorder so all tool messages come first, then trailing text.
    from maverick.providers.openai_provider import OpenAIClient
    msgs = [
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "c1", "name": "x", "input": {}},
            {"type": "tool_use", "id": "c2", "name": "y", "input": {}},
        ]},
        {"role": "user", "content": [
            {"type": "text", "text": "before"},
            {"type": "tool_result", "tool_use_id": "c1", "content": "r1"},
            {"type": "text", "text": "between"},
            {"type": "tool_result", "tool_use_id": "c2", "content": "r2"},
        ]},
    ]
    out = OpenAIClient._to_openai_messages("sys", msgs)
    roles = [m["role"] for m in out]
    assert not any(roles[i] == "tool" and roles[i - 1] == "user"
                   for i in range(1, len(roles))), roles
    tool_ids = [m["tool_call_id"] for m in out if m["role"] == "tool"]
    assert tool_ids == ["c1", "c2"]  # order preserved -> each matches its call
    # supplementary text survives as a trailing user message
    assert [m["content"] for m in out if m["role"] == "user"] == ["before\nbetween"]
