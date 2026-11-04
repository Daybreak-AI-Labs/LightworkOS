"""Tests for metrics and tracing (maverick.observability)."""
from __future__ import annotations

import asyncio
import sys
import types


def _boom(args):
    raise RuntimeError("kaboom")


# --- ToolRegistry must emit the tool_calls metric ---

def test_tool_registry_emits_tool_metric(monkeypatch):
    import maverick.observability as obs
    from maverick.tools import Tool, ToolRegistry

    calls: list = []
    monkeypatch.setattr(
        obs, "record_metric",
        lambda name, *a, **k: calls.append((name, k.get("labels"))),
    )
    reg = ToolRegistry()
    reg.register(Tool(name="echo", description="e",
                      input_schema={"type": "object", "properties": {}},
                      fn=lambda args: "ok"))
    reg.register(Tool(name="boom", description="b",
                      input_schema={"type": "object", "properties": {}},
                      fn=_boom))
    asyncio.run(reg.run("echo", {}))
    asyncio.run(reg.run("boom", {}))
    assert ("tool_calls", {"tool": "echo", "status": "succeeded"}) in calls
    assert ("tool_calls", {"tool": "boom", "status": "error"}) in calls


# ---------- observability: record_metric label handling ----------

def test_record_metric_unlabeled_gauge_no_crash(monkeypatch):
    import maverick.observability as obs

    calls = {"set": None}

    class _Gauge:
        def inc(self, _v):
            raise AssertionError("gauge must not use inc() for absolute values")

        def set(self, v):
            calls["set"] = v

        def labels(self, **kw):
            raise AssertionError("must not call .labels() with no labels")

    monkeypatch.setattr(obs, "_metrics", {"budget_dollars": _Gauge()})
    monkeypatch.setattr(obs, "_initialize", lambda: None)
    obs.record_metric("budget_dollars", 1.23)  # no labels
    assert calls["set"] == 1.23


def test_record_metric_labeled_counter(monkeypatch):
    import maverick.observability as obs

    seen = {"labels": None, "inc": None}

    class _Child:
        def inc(self, v):
            seen["inc"] = v

    class _Counter:
        def labels(self, **kw):
            seen["labels"] = kw
            return _Child()

    monkeypatch.setattr(obs, "_metrics", {"llm_calls": _Counter()})
    monkeypatch.setattr(obs, "_initialize", lambda: None)
    obs.record_metric("llm_calls", 1.0,
                      labels={"provider": "anthropic", "model": "m"})
    assert seen["labels"] == {"provider": "anthropic", "model": "m"}
    assert seen["inc"] == 1.0


def test_record_metric_bounds_dynamic_label_series(monkeypatch):
    import maverick.observability as obs

    seen = []

    class _Child:
        @staticmethod
        def inc(_value):
            return None

    class _Counter:
        @staticmethod
        def labels(**labels):
            seen.append(labels)
            return _Child()

    monkeypatch.setattr(obs, "_metrics", {"llm_calls": _Counter()})
    monkeypatch.setattr(obs, "_initialize", lambda: None)
    monkeypatch.setattr(obs, "_MAX_LABEL_SERIES_PER_METRIC", 3)
    obs._metric_label_series.clear()
    try:
        for model in ("one", "two", "three", "four"):
            obs.record_metric(
                "llm_calls",
                labels={"provider": "custom", "model": model},
            )
    finally:
        obs._metric_label_series.clear()

    assert seen[:2] == [
        {"provider": "custom", "model": "one"},
        {"provider": "custom", "model": "two"},
    ]
    assert seen[2:] == [
        {"provider": obs._OVERFLOW_LABEL, "model": obs._OVERFLOW_LABEL},
        {"provider": obs._OVERFLOW_LABEL, "model": obs._OVERFLOW_LABEL},
    ]


def test_record_metric_hashes_control_character_labels(monkeypatch):
    import maverick.observability as obs

    captured = {}

    class _Child:
        @staticmethod
        def inc(_value):
            return None

    class _Counter:
        @staticmethod
        def labels(**labels):
            captured.update(labels)
            return _Child()

    monkeypatch.setattr(obs, "_metrics", {"tool_calls": _Counter()})
    monkeypatch.setattr(obs, "_initialize", lambda: None)
    obs._metric_label_series.clear()
    try:
        obs.record_metric(
            "tool_calls",
            labels={"tool": "unsafe\nlabel", "status": "ok"},
        )
    finally:
        obs._metric_label_series.clear()

    assert captured["tool"].startswith("redacted-")
    assert "\n" not in captured["tool"]
    assert captured["status"] == "ok"


def test_provider_latency_collector_reads_ms_snapshot_fields(monkeypatch):
    import maverick.observability as obs
    from maverick import provider_health

    captured = []

    class _Family:
        def __init__(self, name, _help, labels=None):
            self.name = name
            self.labels = labels or []
            self.metrics = []

        def add_metric(self, labels, value):
            self.metrics.append((labels, value))

    fake_client = types.ModuleType("prometheus_client")
    fake_client.REGISTRY = types.SimpleNamespace(
        register=lambda collector: captured.append(collector)
    )
    fake_core = types.ModuleType("prometheus_client.core")
    fake_core.GaugeMetricFamily = _Family
    monkeypatch.setitem(sys.modules, "prometheus_client", fake_client)
    monkeypatch.setitem(sys.modules, "prometheus_client.core", fake_core)
    monkeypatch.setattr(
        provider_health,
        "get",
        lambda: types.SimpleNamespace(
            snapshot=lambda: [{
                "provider": "anthropic",
                "model": "model",
                "error_rate": 0.25,
                "p50_ms": 75.0,
                "p95_ms": 100.0,
            }]
        ),
    )

    obs._register_computed_collector()
    families = {family.name: family for family in captured[0].collect()}

    assert families["maverick_provider_latency_ms"].metrics == [
        (["anthropic", "model", "0.5"], 75.0),
        (["anthropic", "model", "0.95"], 100.0),
    ]


def test_prometheus_exporter_defaults_to_loopback_bind(monkeypatch):
    import importlib
    import sys
    import types

    monkeypatch.setenv("MAVERICK_PROMETHEUS_PORT", "9999")
    monkeypatch.delenv("MAVERICK_PROMETHEUS_ADDR", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)

    calls = {}

    def _start_http_server(port, *args, **kwargs):
        calls["port"] = port
        calls["args"] = args
        calls["kwargs"] = kwargs

    fake_prom = types.SimpleNamespace(
        Counter=lambda *a, **k: object(),
        Gauge=lambda *a, **k: object(),
        Histogram=lambda *a, **k: object(),
        start_http_server=_start_http_server,
    )
    monkeypatch.setitem(sys.modules, "prometheus_client", fake_prom)

    import maverick.observability as obs
    obs = importlib.reload(obs)
    monkeypatch.setattr(obs, "_initialized", False)
    monkeypatch.setattr(obs, "_metrics", {})
    obs._initialize()

    assert calls["port"] == 9999
    assert calls["kwargs"].get("addr") == "127.0.0.1"


# ---------- observability ----------

def test_observability_no_op_when_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    monkeypatch.delenv("MAVERICK_PROMETHEUS_PORT", raising=False)
    from maverick.observability import is_enabled, record_metric, trace_span
    assert not is_enabled()
    # trace_span and record_metric should be no-ops, not raise.
    with trace_span("test", attributes={"x": 1}) as span:
        assert span is None
    record_metric("nonexistent", 1.0, labels={"a": "b"})  # no-op


def test_observability_is_enabled_flag(monkeypatch):
    monkeypatch.setenv("MAVERICK_PROMETHEUS_PORT", "9999")
    from maverick.observability import is_enabled
    assert is_enabled()


# ---------- OTEL span wiring ----------

def test_tool_dispatch_opens_span(monkeypatch):
    """ToolRegistry.run wraps the call in a trace_span context."""
    import asyncio

    from maverick.tools import Tool, ToolRegistry

    seen = {"name": None, "attrs": None}

    class _FakeCtx:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_trace_span(name, attributes=None):
        seen["name"] = name
        seen["attrs"] = attributes
        return _FakeCtx()

    import maverick.observability as obs
    monkeypatch.setattr(obs, "trace_span", _fake_trace_span)

    reg = ToolRegistry()
    reg.register(Tool(
        name="echo", description="echo",
        input_schema={"type": "object", "properties": {}},
        fn=lambda args: "ok",
    ))
    out = asyncio.run(reg.run("echo", {}))
    assert out == "ok"
    assert seen["name"] == "tool.run"
    # The span carries the back-compat tool.name plus the GenAI-semconv tool
    # attributes (gen_ai.operation.name/tool.name/tool.type) merged in.
    assert seen["attrs"]["tool.name"] == "echo"
    assert seen["attrs"]["gen_ai.operation.name"] == "execute_tool"
    assert seen["attrs"]["gen_ai.tool.name"] == "echo"


def test_llm_complete_opens_span(monkeypatch):
    from maverick.llm import LLM

    seen = {"calls": []}

    class _FakeCtx:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_trace_span(name, attributes=None):
        seen["calls"].append((name, attributes))
        return _FakeCtx()

    import maverick.observability as obs
    monkeypatch.setattr(obs, "trace_span", _fake_trace_span)

    class _FakeResp:
        text = "ok"
        thinking = None
        tool_calls = []
        stop_reason = "end_turn"
        cache_creation_tokens = 0
        cache_read_tokens = 0
        raw = None
        thinking_blocks = []
        thinking_signature = None

    class _FakeClient:
        def complete(self, **kwargs):
            return _FakeResp()

    llm = LLM(model="anthropic:claude-haiku-4-5-20251001", api_key="dummy")
    monkeypatch.setattr(llm, "_get_client", lambda provider: _FakeClient())

    llm.complete(system="s", messages=[{"role": "user", "content": "hi"}])
    assert seen["calls"]
    name, attrs = seen["calls"][0]
    # The LLM span now follows the OTel GenAI semantic conventions: span name
    # "<operation> <model>" plus gen_ai.* attributes. The legacy llm.provider
    # attribute is kept alongside for back-compat. (Assert on the convention
    # shape, not the exact model-id spelling, so the test doesn't couple to
    # how the id is normalized.)
    assert name.startswith("chat claude-haiku-4-5")
    assert attrs and attrs.get("gen_ai.system") == "anthropic"
    assert attrs.get("gen_ai.request.model") == name.split(" ", 1)[1]
    assert attrs.get("llm.provider") == "anthropic"
