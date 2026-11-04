"""Conversation records preserve provider evidence and adapter behavior."""
from __future__ import annotations

import copy
import json

import pytest
from maverick.llm import LLMResponse, ToolCall
from maverick.providers.conversation import ContentPart, ConversationMessage, PartKind
from maverick.providers.openai_provider import OpenAIClient


def test_anthropic_round_trip_preserves_interleaved_signed_content_and_extensions():
    original = {
        "role": "assistant",
        "content": [
            {"type": "thinking", "thinking": "first", "signature": "signature-one"},
            {"type": "text", "text": "before"},
            {"type": "redacted_thinking", "data": "opaque-signed-data"},
            {"type": "tool_use", "id": "call-1", "name": "lookup", "input": {"x": 1}},
            {"type": "thinking", "thinking": "second", "signature": "signature-two"},
            {"type": "future_provider_block", "content": {"nested": [1, 2]}},
        ],
        "provider_extension": {"trace": "example"},
    }
    snapshot = copy.deepcopy(original)
    record = ConversationMessage.from_anthropic(original)
    original["content"][0]["signature"] = "changed later"
    assert [part.kind for part in record.content] == [
        PartKind.REASONING, PartKind.TEXT, PartKind.REDACTED_REASONING,
        PartKind.TOOL_CALL, PartKind.REASONING, PartKind.UNKNOWN,
    ]
    assert record.to_anthropic() == snapshot
    emitted = record.to_anthropic()
    emitted["content"][0]["signature"] = "changed on emission"
    exposed = record.content
    exposed[0].payload["signature"] = "changed through public part"
    exposed[-1].payload["content"]["nested"].append(3)
    record.extensions["provider_extension"]["trace"] = "changed through public extension"
    assert record.to_anthropic() == snapshot


@pytest.mark.parametrize("message", [
    {}, {"role": "user"}, {"content": None},
    {"role": "user", "content": ("non-list content",)},
    {"role": "user", "content": [{"type": ["unexpected"]}, "literal", None]},
])
def test_round_trip_keeps_missing_and_unknown_values(message):
    assert ConversationMessage.from_anthropic(message).to_anthropic() == message


def test_openai_adapter_keeps_tools_before_text_and_image():
    messages = [{"role": "user", "content": [
        {"type": "text", "text": "What is this?"},
        {"type": "tool_result", "tool_use_id": "call-1", "content": "found"},
        {"type": "image", "source": {"type": "url", "url": "https://example.test/image.png"}},
    ]}]
    result = OpenAIClient._to_openai_messages("system", messages)
    assert result[1] == {"role": "tool", "tool_call_id": "call-1", "content": "found"}
    assert result[2]["content"] == [
        {"type": "text", "text": "What is this?"},
        {"type": "image_url", "image_url": {"url": "https://example.test/image.png"}},
    ]
    typed = ConversationMessage.from_anthropic(messages[0])
    assert OpenAIClient._to_openai_messages("system", [typed]) == result


def test_openai_adapter_preserves_tool_call_arguments_and_omits_reasoning():
    message = {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "private", "signature": "signed"},
        {"type": "tool_use", "id": "call-1", "name": "lookup", "input": {"x": [1, 2]}},
    ]}
    result = OpenAIClient._to_openai_messages("system", [message])[1]
    assert result["content"] == ""
    assert json.loads(result["tool_calls"][0]["function"]["arguments"]) == {"x": [1, 2]}
    assert "signed" not in json.dumps(result)


def test_openai_adapter_still_rejects_inline_documents():
    message = {"role": "user", "content": [{"type": "document", "source": {}}]}
    with pytest.raises(RuntimeError, match="do not accept inline document"):
        OpenAIClient._to_openai_messages("system", [message])


def test_direct_anthropic_request_accepts_canonical_history_without_mutating_it(monkeypatch):
    from maverick.providers.anthropic_provider import AnthropicClient

    monkeypatch.setenv("MAVERICK_CACHE_MESSAGES", "0")
    original = {"role": "assistant", "content": [
        {"type": "thinking", "thinking": "private", "signature": "sig"},
        {"type": "text", "text": "ready"},
    ]}
    record = ConversationMessage.from_anthropic(original)
    client = AnthropicClient.__new__(AnthropicClient)
    kwargs = client._build_request("system", [record], None, 100, None, "claude-sonnet-4-6")
    assert kwargs["messages"] == [original]
    kwargs["messages"][0]["content"][0]["signature"] = "changed"
    assert record.to_anthropic() == original


def test_codex_prompt_accepts_canonical_history_with_legacy_parity():
    from maverick.providers.codex_cli_provider import CodexCLIClient

    source = {"role": "user", "content": [{"type": "text", "text": "hello"}]}
    typed = ConversationMessage.from_anthropic(source)
    assert CodexCLIClient._compose_prompt("system", [typed], None) == (
        CodexCLIClient._compose_prompt("system", [source], None)
    )


def test_unknown_part_retains_original_payload():
    part = ContentPart.from_anthropic({"type": "vendor", "value": [1, 2]})
    assert part.kind is PartKind.UNKNOWN
    assert part.to_anthropic() == {"type": "vendor", "value": [1, 2]}


def test_non_mapping_content_is_copied_on_access():
    source = {"role": {"name": "user"}, "content": [["opaque"]]}
    record = ConversationMessage.from_anthropic(source)
    record.role["name"] = "changed"
    record.content[0].append("changed")
    assert record.to_anthropic() == source


def test_response_to_conversation_preserves_interleaved_signed_blocks():
    blocks = [
        {"type": "thinking", "thinking": "first", "signature": "sig-1"},
        {"type": "tool_use", "id": "one", "name": "lookup", "input": {}},
        {"type": "thinking", "thinking": "second", "signature": "sig-2"},
    ]
    response = LLMResponse(text="", thinking=None, tool_calls=[ToolCall("one", "lookup", {})],
                           stop_reason="tool_use", content_blocks=blocks)
    record = response.as_conversation_message()
    assert record.to_anthropic() == {"role": "assistant", "content": blocks}
    blocks[0]["signature"] = "changed"
    assert record.to_anthropic()["content"][0]["signature"] == "sig-1"


def test_response_final_with_suppressed_calls_does_not_replay_signed_or_tool_blocks():
    response = LLMResponse(text="FINAL: done", thinking="private", thinking_signature="sig",
                           tool_calls=[ToolCall("one", "lookup", {})], stop_reason="tool_use")
    message = response.as_conversation_message(final_dropped_tools=True).to_anthropic()
    assert message == {"role": "assistant", "content": [{"type": "text", "text": "FINAL: done"}]}
