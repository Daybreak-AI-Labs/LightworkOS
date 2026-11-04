"""OTel GenAI semantic-convention attributes for LLM spans.

Lightwork already had opt-in OTel/Prometheus, but the LLM spans used ad-hoc
attribute names and a generic span name that no OTel-aware backend
understands without custom mapping. observability.gen_ai_attributes() /
gen_ai_span_name() emit the standard gen_ai.* names so traces are legible to
Grafana / Honeycomb / Arize Phoenix out of the box, and LLM.complete /
complete_async name their span via the convention.
"""
from __future__ import annotations

import inspect

from maverick import llm as llm_mod
from maverick import observability as obs


def test_span_name_is_operation_space_model():
    assert obs.gen_ai_span_name("chat", "claude-opus-4-8") == "chat claude-opus-4-8"


def test_request_attributes_use_genai_semconv_keys():
    a = obs.gen_ai_attributes("anthropic", "claude-opus-4-8", max_tokens=4096)
    assert a["gen_ai.operation.name"] == "chat"
    assert a["gen_ai.system"] == "anthropic"
    assert a["gen_ai.request.model"] == "claude-opus-4-8"
    assert a["gen_ai.request.max_tokens"] == 4096
    # response/usage fields omitted when unknown (built in a second pass).
    assert "gen_ai.usage.input_tokens" not in a


def test_usage_attributes_included_when_provided():
    a = obs.gen_ai_attributes(
        "openai", "gpt-5.5", operation="chat",
        response_model="gpt-5.5", input_tokens=1200, output_tokens=340,
    )
    assert a["gen_ai.response.model"] == "gpt-5.5"
    assert a["gen_ai.usage.input_tokens"] == 1200
    assert a["gen_ai.usage.output_tokens"] == 340


def test_exports():
    assert "gen_ai_attributes" in obs.__all__
    assert "gen_ai_span_name" in obs.__all__
    assert "safe_agent_telemetry_label" in obs.__all__


def test_llm_complete_paths_use_genai_span_helpers():
    """Both the sync and async LLM entry points must name their OTel span via
    the GenAI convention (gen_ai_span_name) and attach gen_ai_attributes --
    not the old generic 'llm.complete' span. Source-level guard so it can't
    silently regress to ad-hoc attribute names."""
    src = inspect.getsource(llm_mod.LLM.complete)
    src += inspect.getsource(llm_mod.LLM.complete_async)
    assert "gen_ai_span_name(" in src
    assert "gen_ai_attributes(" in src
    # the old generic span name must be gone from both paths
    assert '"llm.complete"' not in src


def test_full_request_and_response_attribute_set():
    a = obs.gen_ai_attributes(
        "openai", "gpt-5.5",
        max_tokens=4096, temperature=0.7, top_p=0.95,
        frequency_penalty=0.1, presence_penalty=0.2,
        response_model="gpt-5.5-2026", response_id="resp_abc",
        finish_reasons=["stop"], input_tokens=10, output_tokens=20,
    )
    # request params
    assert a["gen_ai.request.temperature"] == 0.7
    assert a["gen_ai.request.top_p"] == 0.95
    assert a["gen_ai.request.frequency_penalty"] == 0.1
    assert a["gen_ai.request.presence_penalty"] == 0.2
    # response
    assert a["gen_ai.response.id"] == "resp_abc"
    assert a["gen_ai.response.finish_reasons"] == ["stop"]
    # usage
    assert a["gen_ai.usage.input_tokens"] == 10


def test_optional_attributes_omitted_when_unset():
    a = obs.gen_ai_attributes("anthropic", "claude-opus-4-8")
    for k in ("gen_ai.request.temperature", "gen_ai.request.top_p",
              "gen_ai.response.id", "gen_ai.response.finish_reasons"):
        assert k not in a


def test_agent_attributes_use_genai_semconv_keys():
    a = obs.gen_ai_agent_attributes("coder", agent_id="coder-1",
                                    description="writes code")
    assert a["gen_ai.operation.name"] == "invoke_agent"
    assert a["gen_ai.agent.name"] == "coder"
    assert a["gen_ai.agent.id"] == "coder-1"
    assert a["gen_ai.agent.description"] == "writes code"
    # optional fields omitted when unknown
    b = obs.gen_ai_agent_attributes("coder")
    assert "gen_ai.agent.id" not in b and "gen_ai.agent.description" not in b


def test_agent_attributes_redact_model_controlled_role_text():
    secret_role = "researcher SECRET_TOKEN_FROM_WORKSPACE=sk_live_12345"  # pragma: allowlist secret
    secret_id = f"{secret_role}-1-abcdef"

    attrs = obs.gen_ai_agent_attributes(secret_role, agent_id=secret_id)

    assert "SECRET_TOKEN" not in attrs["gen_ai.agent.name"]
    assert "sk_live" not in attrs["gen_ai.agent.name"]
    assert "SECRET_TOKEN" not in attrs["gen_ai.agent.id"]
    assert "sk_live" not in attrs["gen_ai.agent.id"]
    assert attrs["gen_ai.agent.name"].startswith("redacted-agent-")
    assert attrs["gen_ai.agent.id"].startswith("redacted-agent-")


def test_agent_run_redacts_role_from_invoke_agent_span(monkeypatch):
    import maverick.agent as agent_mod

    spans: list = []

    class _Span:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_trace_span(name, *, attributes=None):
        spans.append((name, attributes or {}))
        return _Span()

    monkeypatch.setattr(obs, "trace_span", _fake_trace_span)

    async def _inner(self):
        # Agent.run's contract is a structured AgentResult.
        return agent_mod.AgentResult(final="ok", role=self.role, name=self.name)

    monkeypatch.setattr(agent_mod.Agent, "_run_inner", _inner)
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    agent.role = "researcher SECRET_TOKEN_FROM_WORKSPACE=sk_live_12345"
    agent.name = f"{agent.role}-1-abcdef"

    import asyncio
    assert asyncio.run(agent_mod.Agent.run(agent)).final == "ok"
    span_name, attrs = spans[0]
    assert "SECRET_TOKEN" not in span_name
    assert "sk_live" not in span_name
    assert "SECRET_TOKEN" not in attrs["gen_ai.agent.name"]
    assert "sk_live" not in attrs["gen_ai.agent.id"]


def test_agent_run_opens_invoke_agent_span(monkeypatch):
    """Agent.run wraps the loop in an invoke_agent span (semconv leg 3)."""
    import maverick.agent as agent_mod

    spans: list = []

    class _Span:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_trace_span(name, *, attributes=None):
        spans.append((name, attributes or {}))
        return _Span()

    monkeypatch.setattr(obs, "trace_span", _fake_trace_span)

    async def _inner(self):
        # Agent.run's contract is a structured AgentResult.
        return agent_mod.AgentResult(final="ok", role=self.role, name=self.name)

    monkeypatch.setattr(agent_mod.Agent, "_run_inner", _inner)
    agent = agent_mod.Agent.__new__(agent_mod.Agent)
    agent.role = "coder"
    agent.name = "coder-1"

    import asyncio
    assert asyncio.run(agent_mod.Agent.run(agent)).final == "ok"
    assert spans and spans[0][0] == "invoke_agent coder"
    assert spans[0][1]["gen_ai.agent.name"] == "coder"
    assert spans[0][1]["gen_ai.agent.id"] == "coder-1"


def test_error_type_attribute_set_on_failed_span(monkeypatch):
    """trace_span stamps semconv error.type when the body raises."""
    class _Span:
        def __init__(self):
            self.attrs = {}

        def set_attribute(self, k, v):
            self.attrs[k] = v

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    span = _Span()

    class _Tracer:
        # The SDK's record_exception / set_status_on_exception keywords are accepted.
        def start_as_current_span(self, name, **_kwargs):
            return span

    monkeypatch.setattr(obs, "_initialized", True)
    monkeypatch.setattr(obs, "_tracer", _Tracer())
    monkeypatch.setattr(obs, "_sentry", None)

    import pytest
    with pytest.raises(ValueError):
        with obs.trace_span("chat m"):
            raise ValueError("boom")
    assert span.attrs.get("error.type") == "ValueError"
