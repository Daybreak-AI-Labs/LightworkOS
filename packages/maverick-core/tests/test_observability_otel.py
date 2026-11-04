"""OTLP endpoint/headers config + OTel GenAI semconv for tool spans.

Extends the existing opt-in OTel layer (test_genai_semconv.py covers the LLM
helpers). Here we assert:

  - ``MAVERICK_OTEL_HEADERS`` is parsed from the env into the exporter, and the
    no-header default path is unchanged;
  - enabling stays opt-in / no-op by default (otel off);
  - tool spans get the standard ``execute_tool`` gen_ai.* attributes.

Hermetic: no network, no live collector. Tests that need a real tracer skip
gracefully when opentelemetry isn't importable, like the repo's other
otel-dependent tests.
"""
from __future__ import annotations

import asyncio
import contextlib
import importlib
import sys
import types

import pytest
from maverick import observability as obs


@pytest.fixture(autouse=True)
def _reset_obs_state(monkeypatch):
    """Each test starts from a clean, otel-off module state."""
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_ENDPOINT", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_HEADERS", raising=False)
    monkeypatch.delenv("MAVERICK_OTEL_METRICS", raising=False)
    monkeypatch.delenv("MAVERICK_PROMETHEUS_PORT", raising=False)
    monkeypatch.setattr(obs, "_initialized", False, raising=False)
    monkeypatch.setattr(obs, "_tracer", None, raising=False)
    monkeypatch.setattr(obs, "_metrics", {}, raising=False)
    monkeypatch.setattr(obs, "_otel_instruments", {}, raising=False)


# ---------- MAVERICK_OTEL_HEADERS parsing ----------

def test_headers_unset_is_empty(monkeypatch):
    assert obs._otlp_headers() == {}


def test_headers_blank_is_empty(monkeypatch):
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "   ")
    assert obs._otlp_headers() == {}


def test_headers_parsed_from_env(monkeypatch):
    monkeypatch.setenv(
        "MAVERICK_OTEL_HEADERS", "x-honeycomb-team=abc123, dd-api-key=xyz"
    )
    assert obs._otlp_headers() == {
        "x-honeycomb-team": "abc123",
        "dd-api-key": "xyz",
    }


def test_headers_skip_malformed_pairs(monkeypatch):
    # A bare token with no '=' is skipped, not crashed on.
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "garbage,authorization=Bearer t")
    assert obs._otlp_headers() == {"authorization": "Bearer t"}


# ---------- opt-in / no-op by default ----------

def test_disabled_by_default(monkeypatch):
    assert obs._otel_enabled() is False
    assert obs.is_enabled() is False


def test_trace_span_is_noop_when_disabled(monkeypatch):
    # No tracer is created, span yields None, attributes don't raise.
    with obs.trace_span("chat test-model", attributes={"gen_ai.system": "x"}) as s:
        assert s is None
    assert obs._tracer is None


def test_headers_not_read_when_disabled(monkeypatch):
    # Setting headers without the exporter flag must not enable anything.
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "authorization=Bearer t")
    obs._initialize()
    assert obs._tracer is None
    assert obs.is_enabled() is False


# ---------- headers reach the exporter (otel required) ----------

def test_headers_passed_to_exporter_when_enabled(monkeypatch):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    from opentelemetry.exporter.otlp.proto.http import trace_exporter as te

    captured: dict[str, object] = {}

    class _SpyExporter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export(self, spans):  # pragma: no cover - never called in test
            return None

        def shutdown(self):  # pragma: no cover
            return None

    monkeypatch.setattr(te, "OTLPSpanExporter", _SpyExporter)
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    monkeypatch.setenv("MAVERICK_OTEL_ENDPOINT", "https://collector.example/v1/traces")
    monkeypatch.setenv("MAVERICK_OTEL_HEADERS", "x-api-key=secret")

    obs._initialize()

    assert captured.get("endpoint") == "https://collector.example/v1/traces"
    assert captured.get("headers") == {"x-api-key": "secret"}
    assert obs._tracer is not None


def test_no_headers_kwarg_omitted_when_unset(monkeypatch):
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")
    from opentelemetry.exporter.otlp.proto.http import trace_exporter as te

    captured: dict[str, object] = {}

    class _SpyExporter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export(self, spans):  # pragma: no cover
            return None

        def shutdown(self):  # pragma: no cover
            return None

    monkeypatch.setattr(te, "OTLPSpanExporter", _SpyExporter)
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")

    obs._initialize()

    # default path: no headers kwarg, so the exporter keeps its own default.
    assert "headers" not in captured


# ---------- tool span gen_ai.* attributes ----------

def test_tool_attributes_minimal():
    a = obs.gen_ai_tool_attributes("read_file")
    assert a["gen_ai.operation.name"] == "execute_tool"
    assert a["gen_ai.tool.name"] == "read_file"
    assert a["gen_ai.tool.type"] == "function"
    # optional fields omitted when unknown
    assert "gen_ai.tool.call.id" not in a
    assert "gen_ai.tool.description" not in a


def test_tool_attributes_full():
    a = obs.gen_ai_tool_attributes(
        "bash", call_id="call_42", description="run a shell command",
        tool_type="function",
    )
    assert a["gen_ai.tool.name"] == "bash"
    assert a["gen_ai.tool.call.id"] == "call_42"
    assert a["gen_ai.tool.description"] == "run a shell command"


def test_tool_helper_exported():
    assert "gen_ai_tool_attributes" in obs.__all__


# ---------- import-safe without otel ----------

def test_module_imports_without_otel(monkeypatch):
    # Re-importing the module must never require opentelemetry at import time.
    mod = importlib.reload(obs)
    assert hasattr(mod, "trace_span")
    assert hasattr(mod, "gen_ai_tool_attributes")


# ---------- OTLP metrics (MAVERICK_OTEL_METRICS) ----------

class _FakeInstrument:
    """Counter stand-in: ``add`` records the way the OTel counter does."""

    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.points = []

    def add(self, amount, attributes=None, context=None):
        self.points.append((amount, dict(attributes or {})))


class _FakeHistogram(_FakeInstrument):
    """Histogram stand-in: ``record`` is the histogram's entry point."""

    def record(self, amount, attributes=None, context=None):
        self.points.append((amount, dict(attributes or {})))


@pytest.fixture
def fake_otlp_metrics(monkeypatch):
    """Stand-ins for the OTLP metric exporter and the metrics SDK.

    The venvs do not install opentelemetry-sdk, so these modules are injected
    and the real SDK path is covered by the importorskip tests below.
    """
    built: dict = {}

    class _Meter:
        def create_counter(self, name, unit="", description=""):
            instrument = _FakeInstrument(name, description)
            built[name] = instrument
            return instrument

        def create_histogram(self, name, unit="", description="", **_kwargs):
            instrument = _FakeHistogram(name, description)
            built[name] = instrument
            return instrument

    class _MeterProvider:
        def __init__(self, resource=None, metric_readers=()):
            built["readers"] = list(metric_readers)

        def get_meter(self, name, *_args, **_kwargs):
            built["meter"] = name
            return _Meter()

    class _Exporter:
        def __init__(self, **kwargs):
            built["exporter_kwargs"] = kwargs

    exporter_mod = types.ModuleType("opentelemetry.exporter.otlp.proto.http.metric_exporter")
    exporter_mod.OTLPMetricExporter = _Exporter
    sdk_mod = types.ModuleType("opentelemetry.sdk.metrics")
    sdk_mod.MeterProvider = _MeterProvider
    export_mod = types.ModuleType("opentelemetry.sdk.metrics.export")
    export_mod.PeriodicExportingMetricReader = lambda exporter, **_kw: ("reader", exporter)
    for name, module in (
        ("opentelemetry.exporter.otlp.proto.http.metric_exporter", exporter_mod),
        ("opentelemetry.sdk.metrics", sdk_mod),
        ("opentelemetry.sdk.metrics.export", export_mod),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    return built


def test_metric_names_and_kinds_are_pinned():
    """Dashboards and alerts key on these names; OTel mirrors them exactly."""
    assert [(kind, name, labels) for kind, _key, name, _doc, labels in obs._METRIC_SPECS] == [
        ("counter", "maverick_llm_calls_total", ("provider", "model")),
        ("histogram", "maverick_llm_latency_seconds", ("provider", "model")),
        ("counter", "maverick_llm_tokens_total", ("provider", "model", "direction")),
        ("counter", "maverick_llm_cache_tokens_total", ("provider", "model", "kind")),
        ("counter", "maverick_tool_calls_total", ("tool", "status")),
        ("counter", "maverick_budget_dollars_spent", ()),
        ("counter", "maverick_tool_latency_budget_exceeded_total", ("tool",)),
    ]
    keys = [key for _kind, key, _name, _doc, _labels in obs._METRIC_SPECS]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize(
    ("setting", "expected"),
    [(None, False), ("", False), ("0", False), ("false", False), ("off", False),
     ("1", True), ("true", True), ("Yes", True), ("on", True)],
)
def test_otlp_metrics_knob_is_on_only_for_a_true_value(monkeypatch, setting, expected):
    # [observability] otlp_metrics = false reaches the module as "0", which a
    # plain bool() would read as on.
    monkeypatch.setattr(obs, "_setting", lambda env_name, key: setting)
    assert obs._otlp_metrics_enabled() is expected


@pytest.mark.parametrize(
    ("traces", "metrics"),
    [
        ("http://localhost:4318/v1/traces", "http://localhost:4318/v1/metrics"),
        ("https://collector.example/base/v1/traces", "https://collector.example/base/v1/metrics"),
        # No derivable metrics path: stay off rather than post to a guessed URL.
        ("https://collector.example/custom", None),
        ("https://collector.example/v1/traces/", None),
    ],
)
def test_metrics_url_replaces_only_the_signal_path(traces, metrics):
    assert obs._otlp_metrics_endpoint(traces) == metrics


def test_metrics_exporter_uses_the_span_endpoint_and_headers(fake_otlp_metrics):
    obs._initialize_otlp_metrics(
        "https://collector.example/v1/traces", {"x-api-key": "secret"}, None)
    assert fake_otlp_metrics["exporter_kwargs"] == {
        "endpoint": "https://collector.example/v1/metrics",
        "headers": {"x-api-key": "secret"},
    }


def test_metrics_exporter_omits_headers_kwarg_when_unset(fake_otlp_metrics):
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    assert fake_otlp_metrics["exporter_kwargs"] == {
        "endpoint": "http://localhost:4318/v1/metrics"}


def test_every_recorded_metric_gets_an_instrument_of_the_same_name_and_kind(
        fake_otlp_metrics):
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    assert set(obs._otel_instruments) == {key for _kind, key, *_ in obs._METRIC_SPECS}
    for kind, key, name, doc, _labels in obs._METRIC_SPECS:
        recorded_kind, instrument = obs._otel_instruments[key]
        assert recorded_kind == kind
        assert instrument.name == name
        assert instrument.description == doc
        assert isinstance(instrument, _FakeHistogram) == (kind == "histogram")


def test_record_metric_mirrors_to_otel_with_the_same_labels(fake_otlp_metrics, monkeypatch):
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    monkeypatch.setattr(obs, "_metrics", {})  # Prometheus off: OTel alone records
    obs.record_metric("tool_calls", labels={"tool": "search", "status": "ok"})
    obs.record_metric("llm_latency", 0.25, labels={"provider": "anthropic", "model": "m"})
    obs.record_metric("budget_dollars", 0.5)
    assert obs._otel_instruments["tool_calls"][1].points == [
        (1.0, {"tool": "search", "status": "ok"})]
    assert obs._otel_instruments["llm_latency"][1].points == [
        (0.25, {"provider": "anthropic", "model": "m"})]
    assert obs._otel_instruments["budget_dollars"][1].points == [(0.5, {})]


def test_otel_points_carry_the_redacted_label_not_the_raw_value(fake_otlp_metrics, monkeypatch):
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    monkeypatch.setattr(obs, "_metrics", {})
    raw = "model-controlled-" + "x" * 200
    obs.record_metric("tool_calls", labels={"tool": raw, "status": "ok"})
    (_value, attributes), = obs._otel_instruments["tool_calls"][1].points
    assert attributes["tool"] == obs._safe_metric_label(raw)
    assert raw not in attributes.values()


def test_otel_series_obey_the_same_cardinality_budget(fake_otlp_metrics, monkeypatch):
    monkeypatch.setattr(obs, "_MAX_LABEL_SERIES_PER_METRIC", 3)
    monkeypatch.setattr(obs, "_metric_label_series", {})
    monkeypatch.setattr(obs, "_metrics", {})
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    for tool in ("a", "b", "c", "d"):
        obs.record_metric("tool_calls", labels={"tool": tool, "status": "ok"})
    attributes = [attrs for _value, attrs in obs._otel_instruments["tool_calls"][1].points]
    assert attributes[:2] == [{"tool": "a", "status": "ok"}, {"tool": "b", "status": "ok"}]
    assert attributes[2:] == [{"tool": "__other__", "status": "__other__"}] * 2


def test_prometheus_and_otel_receive_the_same_labels(fake_otlp_metrics, monkeypatch):
    seen = []

    class _Child:
        def inc(self, amount=1.0):
            seen.append(("prometheus", amount))

    class _PrometheusCounter:
        def labels(self, **labels):
            seen.append(("labels", labels))
            return _Child()

    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    monkeypatch.setattr(obs, "_metrics", {"tool_calls": _PrometheusCounter()})
    obs.record_metric("tool_calls", labels={"tool": "search", "status": "ok"})
    assert seen == [("labels", {"tool": "search", "status": "ok"}), ("prometheus", 1.0)]
    (_value, attributes), = obs._otel_instruments["tool_calls"][1].points
    assert attributes == {"tool": "search", "status": "ok"}


def test_metrics_knob_without_the_exporter_stays_off_and_says_why(monkeypatch, caplog):
    monkeypatch.setenv("MAVERICK_OTEL_METRICS", "1")
    obs._initialize()
    assert obs._otel_instruments == {}
    assert "MAVERICK_OTEL_METRICS" in caplog.text


def test_metrics_knob_off_loads_no_metrics_sdk(monkeypatch, caplog):
    """The default path never imports the OTel metrics SDK."""
    pytest.importorskip("opentelemetry.sdk.trace")
    for name in ("opentelemetry.sdk.metrics",
                 "opentelemetry.exporter.otlp.proto.http.metric_exporter"):
        monkeypatch.setitem(sys.modules, name, None)  # any import now raises ImportError
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    monkeypatch.setenv("MAVERICK_OTEL_ENDPOINT", "http://127.0.0.1:9/v1/traces")
    obs._initialize()
    assert obs._tracer is not None
    assert obs._otel_instruments == {}
    assert "OTLP metrics" not in caplog.text


def test_real_sdk_metrics_carry_the_prometheus_names(monkeypatch):
    """Real SDK path: the in-memory reader sees the same names and labels."""
    pytest.importorskip("opentelemetry.sdk.metrics")
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.metric_exporter")
    from opentelemetry.sdk.metrics import export as metric_export

    readers = []

    def _reader(exporter, **_kwargs):
        reader = metric_export.InMemoryMetricReader()
        readers.append(reader)
        return reader

    monkeypatch.setattr(metric_export, "PeriodicExportingMetricReader", _reader)
    obs._initialize_otlp_metrics("http://localhost:4318/v1/traces", {}, None)
    monkeypatch.setattr(obs, "_metrics", {})
    obs.record_metric("tool_calls", labels={"tool": "search", "status": "ok"})
    obs.record_metric("llm_latency", 0.25, labels={"provider": "anthropic", "model": "m"})

    data = readers[0].get_metrics_data()
    metrics = {
        metric.name: metric
        for resource in data.resource_metrics
        for scope in resource.scope_metrics
        for metric in scope.metrics
    }
    calls = metrics["maverick_tool_calls_total"].data.data_points
    assert [(dict(p.attributes), p.value) for p in calls] == [
        ({"tool": "search", "status": "ok"}, 1)]
    latency = metrics["maverick_llm_latency_seconds"].data.data_points
    assert [dict(p.attributes) for p in latency] == [{"provider": "anthropic", "model": "m"}]


# ---------- HTTP request spans (http_request_span / mark_span_failed) ----------

def test_otlp_tracing_enabled_follows_the_exporter_knob(monkeypatch):
    assert obs.otlp_tracing_enabled() is False
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    assert obs.otlp_tracing_enabled() is True


def test_request_span_is_none_when_span_export_is_off(monkeypatch):
    monkeypatch.setattr(obs, "_initialized", True)
    with obs.http_request_span("GET") as span:
        assert span is None


def test_request_span_is_a_server_span_and_never_a_sentry_transaction(monkeypatch):
    opened = []

    class _Span:
        pass

    class _Tracer:
        @contextlib.contextmanager
        def start_as_current_span(self, name, kind=None, **_kwargs):
            opened.append((name, kind))
            yield _Span()

    def _sentry_must_not_open(*_args, **_kwargs):
        raise AssertionError("request spans are OTLP-only; Sentry is not called")

    monkeypatch.setattr(obs, "_initialized", True)
    monkeypatch.setattr(obs, "_tracer", _Tracer())
    monkeypatch.setattr(obs, "_trace_api", types.SimpleNamespace(
        SpanKind=types.SimpleNamespace(SERVER="SERVER")))
    monkeypatch.setattr(obs, "_sentry", types.SimpleNamespace(
        start_transaction=_sentry_must_not_open, start_span=_sentry_must_not_open,
        get_current_scope=_sentry_must_not_open))
    with obs.http_request_span("GET") as span:
        assert isinstance(span, _Span)
    assert opened == [("HTTP GET", "SERVER")]


def test_mark_span_failed_sets_the_error_status(monkeypatch):
    statuses = []

    class _Span:
        def set_status(self, status):
            statuses.append(status)

    monkeypatch.setattr(obs, "_trace_api", types.SimpleNamespace(
        StatusCode=types.SimpleNamespace(ERROR="ERROR")))
    obs.mark_span_failed(_Span())
    assert statuses == ["ERROR"]


# ---------- failed spans name the exception type, never its message ----------

class _SDKSpan:
    """What the span keeps: attributes, events and the status."""

    def __init__(self):
        self.attributes = {}
        self.events = []
        self.status = None

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def set_status(self, status, description=None):
        self.status = (status, description)


class _SDKTracer:
    """Stand-in for the SDK tracer, with its default exception handling.

    Unless a caller turns them off, ``start_as_current_span`` records the exception
    message as an event and sets an ERROR status carrying the message, as the SDK does.
    """

    def __init__(self):
        self.spans = []
        self.options = []

    @contextlib.contextmanager
    def start_as_current_span(self, name, record_exception=True,
                              set_status_on_exception=True, **_kwargs):
        span = _SDKSpan()
        self.spans.append((name, span))
        self.options.append((record_exception, set_status_on_exception))
        try:
            yield span
        except BaseException as error:
            if record_exception:
                span.events.append(("exception", str(error)))
            if set_status_on_exception:
                span.status = ("ERROR", str(error))
            raise


@pytest.fixture
def sdk_tracer(monkeypatch):
    tracer = _SDKTracer()
    monkeypatch.setattr(obs, "_initialized", True)
    monkeypatch.setattr(obs, "_tracer", tracer)
    monkeypatch.setattr(obs, "_trace_api", types.SimpleNamespace(
        StatusCode=types.SimpleNamespace(ERROR="ERROR")))
    monkeypatch.setattr(obs, "_sentry", None)
    return tracer


def test_failed_span_records_no_message_and_names_only_the_type(sdk_tracer):
    secret = "sk-live-do-not-export"  # pragma: allowlist secret
    with pytest.raises(RuntimeError):
        with obs.trace_span("tool.run", attributes={"tool.name": "fetch"}):
            raise RuntimeError(f"upstream rejected {secret}")
    ((name, span),) = sdk_tracer.spans
    assert name == "tool.run"
    assert span.events == []
    assert span.status == ("ERROR", "RuntimeError")
    assert span.attributes["error.type"] == "RuntimeError"
    assert secret not in repr((span.events, span.status, span.attributes))


def test_every_trace_span_opens_with_sdk_exception_recording_off(sdk_tracer):
    # Tool, provider and agent spans all come through trace_span().
    with obs.trace_span("provider.call"):
        pass
    with pytest.raises(ValueError):
        with obs.trace_span("agent.turn"):
            raise ValueError("boom")
    assert sdk_tracer.options == [(False, False), (False, False)]


def test_successful_span_gets_no_error_status(sdk_tracer):
    with obs.trace_span("agent.turn") as span:
        assert span is not None
    ((_, span),) = sdk_tracer.spans
    assert span.status is None
    assert "error.type" not in span.attributes


@pytest.mark.parametrize("error", [asyncio.CancelledError("stop"), GeneratorExit()])
def test_cancelled_span_is_not_marked_as_an_error(sdk_tracer, error):
    # As the SDK does, only an Exception makes a span an error; a cancellation or a
    # GeneratorExit propagates unchanged and leaves the status unset.
    with pytest.raises(type(error)):
        with obs.trace_span("tool.run"):
            raise error
    ((_, span),) = sdk_tracer.spans
    assert span.status is None


def test_real_sdk_failed_span_exports_type_and_no_message(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace as trace_api
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(obs, "_initialized", True)
    monkeypatch.setattr(obs, "_sentry", None)
    monkeypatch.setattr(obs, "_tracer", provider.get_tracer("test"))
    monkeypatch.setattr(obs, "_trace_api", trace_api)
    with pytest.raises(ValueError):
        with obs.trace_span("tool.run"):
            raise ValueError("token sk-live-do-not-export")
    (span,) = exporter.get_finished_spans()
    assert list(span.events) == []
    assert span.status.status_code == trace_api.StatusCode.ERROR
    assert span.status.description == "ValueError"
    assert "sk-live-do-not-export" not in repr(span.attributes)


# ---------- on/off settings: the same reading from the environment and from config ----------

_OFF_VALUES = [False, "false", "0", "off", "no", ""]
_ON_VALUES = [True, "1", "true", "yes", "on"]


@pytest.fixture
def no_config(monkeypatch):
    """No configuration file and no DSN in the environment; each test sets one switch."""
    import maverick.config as config_mod

    monkeypatch.setattr(config_mod, "load_config", dict)
    monkeypatch.delenv("MAVERICK_SENTRY_DSN", raising=False)
    return config_mod


def _config_switch(monkeypatch, config_mod, key, value):
    monkeypatch.setattr(config_mod, "load_config", lambda: {"observability": {key: value}})


@pytest.mark.parametrize("value", _OFF_VALUES)
def test_off_spellings_are_off_and_blank_or_off(value):
    assert obs.switch_is_on(value) is False
    assert obs.setting_is_blank_or_off(value) is True


@pytest.mark.parametrize("value", _ON_VALUES + ["  ON  ", "otlp"])
def test_on_spellings_are_on_and_not_blank(value):
    assert obs.switch_is_on(value, extra_on=frozenset({"otlp"})) is True
    assert obs.setting_is_blank_or_off(value) is False


@pytest.mark.parametrize("value", ["console", "otlp/http"])
def test_unlisted_text_is_off(value):
    # Only the documented exporter value (and the on-words) turn a switch on.
    assert obs.switch_is_on(value, extra_on=frozenset({"otlp"})) is False


# (env var, [observability] key, reader, values that turn it on)
_SWITCHES = [
    ("MAVERICK_OTEL_METRICS", "otlp_metrics", "_otlp_metrics_enabled", _ON_VALUES),
    ("MAVERICK_OTEL_EXPORTER", "otel_exporter", "_otel_enabled", ["otlp", "OTLP", True, "1"]),
]
_SWITCH_OFF = [(env, key, fn, value) for env, key, fn, _on in _SWITCHES for value in _OFF_VALUES]
_SWITCH_ON = [(env, key, fn, value) for env, key, fn, on in _SWITCHES for value in on]


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_OFF)
def test_switch_is_off_from_config(no_config, monkeypatch, env, key, fn, value):
    _config_switch(monkeypatch, no_config, key, value)
    assert getattr(obs, fn)() is False


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_ON)
def test_switch_is_on_from_config(no_config, monkeypatch, env, key, fn, value):
    _config_switch(monkeypatch, no_config, key, value)
    assert getattr(obs, fn)() is True


@pytest.mark.parametrize(("env", "key", "fn"), [(e, k, f) for e, k, f, _on in _SWITCHES])
@pytest.mark.parametrize("value", ["false", "0", "off", "no"])
def test_switch_is_off_from_env(no_config, monkeypatch, env, key, fn, value):
    # A blank env var is unset and falls through to config, so it is not listed here.
    monkeypatch.setenv(env, value)
    assert getattr(obs, fn)() is False


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_ON)
def test_switch_is_on_from_env(no_config, monkeypatch, env, key, fn, value):
    monkeypatch.setenv(env, str(value))
    assert getattr(obs, fn)() is True


@pytest.mark.parametrize(("env", "key", "fn", "value"), _SWITCH_ON)
def test_env_switch_wins_over_config_both_ways(no_config, monkeypatch, env, key, fn, value):
    _config_switch(monkeypatch, no_config, key, value)
    monkeypatch.setenv(env, "false")
    assert getattr(obs, fn)() is False
    _config_switch(monkeypatch, no_config, key, False)
    monkeypatch.setenv(env, str(value))
    assert getattr(obs, fn)() is True


@pytest.mark.parametrize("value", _OFF_VALUES)
def test_prometheus_port_off_values_do_not_publish(no_config, monkeypatch, value):
    # A config false arrives as "0": without this, the exporter would bind a random port.
    _config_switch(monkeypatch, no_config, "prometheus_port", value)
    assert obs._prometheus_enabled() is False


@pytest.mark.parametrize("value", [9100, "9100"])
def test_prometheus_port_on_from_config(no_config, monkeypatch, value):
    _config_switch(monkeypatch, no_config, "prometheus_port", value)
    assert obs._prometheus_enabled() is True


@pytest.mark.parametrize("value", ["0", "off", "false", "no"])
def test_prometheus_port_off_from_env(no_config, monkeypatch, value):
    monkeypatch.setenv("MAVERICK_PROMETHEUS_PORT", value)
    assert obs._prometheus_enabled() is False


def _fake_prometheus(monkeypatch):
    started = []
    fake = types.ModuleType("prometheus_client")

    class _Metric:
        def __init__(self, *_args, **_kwargs):
            pass

    fake.Counter = _Metric
    fake.Histogram = _Metric
    fake.start_http_server = lambda port, addr=None: started.append(port)
    monkeypatch.setitem(sys.modules, "prometheus_client", fake)
    return started


def test_false_prometheus_port_never_starts_the_server(no_config, monkeypatch):
    started = _fake_prometheus(monkeypatch)
    _config_switch(monkeypatch, no_config, "prometheus_port", False)
    obs._initialize()
    assert started == []


def test_numeric_prometheus_port_starts_the_server(no_config, monkeypatch):
    # Positive control for the test above: a real port does start the server.
    started = _fake_prometheus(monkeypatch)
    _config_switch(monkeypatch, no_config, "prometheus_port", 9100)
    obs._initialize()
    assert started == [9100]


@pytest.mark.parametrize("value", [False, "false", "0", "off", "no", ""])
def test_sentry_dsn_off_values_mean_no_sentry(no_config, monkeypatch, value):
    _config_switch(monkeypatch, no_config, "sentry_dsn", value)
    assert obs._sentry_dsn() == ""
    assert obs._sentry_enabled() is False


@pytest.mark.parametrize("value", ["false", "0", "off", "no"])
def test_sentry_dsn_off_words_from_env_mean_no_sentry(no_config, monkeypatch, value):
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", value)
    assert obs._sentry_dsn() == ""


def test_sentry_dsn_from_config_and_env_are_read(no_config, monkeypatch):
    dsn = "https://k@o0.ingest.sentry.io/1"
    _config_switch(monkeypatch, no_config, "sentry_dsn", dsn)
    assert obs._sentry_dsn() == dsn
    monkeypatch.setenv("MAVERICK_SENTRY_DSN", "  " + dsn + "  ")
    assert obs._sentry_dsn() == dsn
