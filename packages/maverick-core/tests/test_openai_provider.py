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


def test_usage_is_metered_under_the_admitted_model_not_the_wire_id(monkeypatch):
    # Ollama's promoted adapter rewrites the wire model in _build_kwargs; the
    # facade admits the base id, so metering under the wire id was refused
    # after the paid call ran.
    from types import SimpleNamespace

    from maverick.budget import Budget
    from maverick.providers.ollama_provider import OllamaClient

    monkeypatch.setattr("maverick.adapter_rung.effective_wire_model",
                        lambda provider, model: "llama3-lw-abc123")
    client = OllamaClient()
    sent = {}

    def create(**kwargs):
        sent.update(kwargs)
        msg = SimpleNamespace(content="ok", tool_calls=None, reasoning_content=None)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=msg, finish_reason="stop")],
            usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2),
        )

    client._sync = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    metered = []
    monkeypatch.setattr(Budget, "record_tokens",
                        lambda self, i, o, **kw: metered.append(kw["model"]))
    client.complete("sys", [{"role": "user", "content": "hi"}],
                    budget=Budget(max_dollars=1.0), model="some-base")
    assert sent["model"] == "llama3-lw-abc123"
    assert metered == ["ollama:some-base"]


def test_openai_org_and_project_ids_are_not_sent_to_other_vendors(monkeypatch):
    from maverick.providers.deepseek_provider import DeepSeekClient

    ids = {"OPENAI_ORG_ID": "org-secret-123", "OPENAI_PROJECT_ID": "proj-9"}
    for name, value in ids.items():
        monkeypatch.setenv(name, value)
    for client in (DeepSeekClient(api_key="dk-test", environment=dict(ids)),
                   DeepSeekClient(api_key="dk-test")):  # pragma: allowlist secret
        for sdk in (client._sync, client._async):
            assert sdk.organization is None and sdk.project is None
            assert not isinstance(sdk.default_headers["OpenAI-Organization"], str)
            assert not isinstance(sdk.default_headers["OpenAI-Project"], str)
