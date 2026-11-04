"""Tests for the OpenAI provider."""
from __future__ import annotations


class TestReasoningContentPreserved:
    def test_openai_response_reasoning_content_to_thinking(self):
        from maverick.providers.openai_provider import OpenAIClient

        class _Msg:
            content = "the answer"
            reasoning_content = "step-by-step CoT"
            tool_calls = None

        class _Choice:
            message = _Msg()
            finish_reason = "stop"

        class _Resp:
            choices = [_Choice()]
            usage = None

        out = OpenAIClient._from_response(_Resp(), None, model="deepseek-reasoner")
        assert out.thinking == "step-by-step CoT"
        assert out.text == "the answer"
