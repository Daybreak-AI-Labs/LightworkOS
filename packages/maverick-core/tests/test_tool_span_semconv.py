"""The tool-execution span carries OTel GenAI-semconv attributes.

``ToolRegistry.run`` opens a ``tool.run`` span. Wiring it through
``observability.gen_ai_tool_attributes`` means the span follows the
``execute_tool`` convention (``gen_ai.tool.name`` / ``gen_ai.operation.name``)
so any OTel-aware backend understands it without custom mapping. The legacy
``tool.name`` attribute is kept additively, and with otel off behaviour is
unchanged.

Hermetic: no network, no live collector. The span-emitting test uses an
in-memory exporter and skips gracefully when opentelemetry isn't importable,
like the repo's other otel-dependent tests.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest
from maverick import observability as obs
from maverick.tools import Tool, ToolRegistry


@pytest.fixture(autouse=True)
def _reset_obs_state(monkeypatch):
    """Each test starts from a clean, otel-off module state."""
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    monkeypatch.setattr(obs, "_initialized", False, raising=False)
    monkeypatch.setattr(obs, "_tracer", None, raising=False)
    monkeypatch.setattr(obs, "_metrics", {}, raising=False)


def _echo_registry() -> ToolRegistry:
    reg = ToolRegistry()
    reg.register(
        Tool(
            name="echo",
            description="echo back",
            input_schema={"type": "object", "properties": {}},
            fn=lambda args: "ok",
        )
    )
    return reg


# ---------- source-level guard (no otel required) ----------

def test_run_wires_gen_ai_tool_attributes():
    """ToolRegistry.run must build the span attributes via the GenAI helper,
    not an ad-hoc dict alone. Source guard so it can't silently regress."""
    src = inspect.getsource(ToolRegistry.run)
    assert "gen_ai_tool_attributes" in src


def test_run_still_works_with_otel_off():
    """Default path (otel off): the tool runs and the span is a no-op."""
    reg = _echo_registry()
    assert obs._tracer is None
    assert asyncio.run(reg.run("echo", {})) == "ok"
    # no-op span never created a tracer
    assert obs._tracer is None


# ---------- attributes actually land on the emitted span (otel required) ----

def test_span_has_genai_semconv_attributes(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    # Inject a real tracer directly so trace_span emits spans without taking
    # observability's OTLP-exporter path (and without touching global state).
    monkeypatch.setattr(obs, "_initialized", True, raising=False)
    monkeypatch.setattr(obs, "_tracer", provider.get_tracer("test"), raising=False)

    reg = _echo_registry()
    assert asyncio.run(reg.run("echo", {})) == "ok"

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "tool.run"
    attrs = dict(span.attributes)
    # GenAI semconv attributes from gen_ai_tool_attributes(...)
    assert attrs["gen_ai.operation.name"] == "execute_tool"
    assert attrs["gen_ai.tool.name"] == "echo"
    assert attrs["gen_ai.tool.type"] == "function"
    # legacy attribute kept additively
    assert attrs["tool.name"] == "echo"
