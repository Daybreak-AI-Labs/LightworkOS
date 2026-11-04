"""Opt-in OpenTelemetry + Prometheus exporters.

Off by default. Knobs:

  - ``MAVERICK_OTEL_EXPORTER=otlp``      enables OTLP span export
  - ``MAVERICK_OTEL_ENDPOINT=https://...``  override default collector URL
  - ``MAVERICK_OTEL_HEADERS=k1=v1,k2=v2`` per-request headers on the OTLP
    exporter (e.g. ``x-honeycomb-team=...`` / ``dd-api-key=...`` so traces
    reach a managed backend like Honeycomb / Datadog / Grafana Cloud)
  - ``MAVERICK_OTEL_METRICS=1``          also export the measurements below over
    OTLP, to the same collector (needs the OTLP exporter; the metrics URL is the
    span endpoint with ``/v1/traces`` replaced by ``/v1/metrics``)
  - ``MAVERICK_PROMETHEUS_PORT=9100``    expose /metrics on this port
  - ``MAVERICK_PROMETHEUS_ADDR=127.0.0.1`` bind address for /metrics

When neither is set, this module is a pure-Python no-op: ``trace_span()``
returns a context-manager that does nothing, ``record_metric()`` is a
no-op.

When enabled, it wraps:
  - Agent kernel turns (one span per LLM call)
  - Tool invocations (one span per tool call, attributes = tool name +
    result-size + ms)
  - Provider dispatches (provider + model + tokens + cost in attributes)
  - Dashboard HTTP requests: one server span each, named by route template
    (``maverick_dashboard.request_spans``; never the raw path or query)

Deps are heavyweight + optional. Install with:
    python -m pip install -e './packages/maverick-core[observability]'

Failures during span/metric export are logged and swallowed.
"""
from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import re
import threading
from collections.abc import Iterator, Mapping
from typing import Any

from .config_contracts import TEXT_SETTINGS

log = logging.getLogger(__name__)


_initialized = False
_init_lock = threading.Lock()
_tracer: Any = None
# opentelemetry.trace itself (SpanKind, StatusCode), set together with _tracer.
_trace_api: Any = None
_sentry: Any = None
_metrics: dict[str, Any] = {}
# name -> (kind, OTLP instrument) for the metrics in _METRIC_SPECS (MAVERICK_OTEL_METRICS).
_otel_instruments: dict[str, tuple[str, Any]] = {}
_metric_series_lock = threading.Lock()
_metric_label_series: dict[str, set[tuple[tuple[str, str], ...]]] = {}
_MAX_LABEL_SERIES_PER_METRIC = 128
_OVERFLOW_LABEL = "__other__"

# Every metric record_metric() records. The Prometheus registry and, when
# MAVERICK_OTEL_METRICS is on, the OTLP meter are both built from this table, so
# a metric has the same name, kind and label names on both. Rows are
# (kind, key, metric name, description, label names). Dashboards and alerts key
# on the names, so renaming one is a breaking change.
_METRIC_SPECS: tuple[tuple[str, str, str, str, tuple[str, ...]], ...] = (
    ("counter", "llm_calls", "maverick_llm_calls_total", "Total LLM API calls",
     ("provider", "model")),
    ("histogram", "llm_latency", "maverick_llm_latency_seconds", "LLM call latency",
     ("provider", "model")),
    ("counter", "llm_tokens", "maverick_llm_tokens_total", "Total tokens billed",
     ("provider", "model", "direction")),
    # Prompt-cache effectiveness: input tokens served from cache (~0.1x cost),
    # written to cache (~1.25-2x), and processed fresh (full price). Hit rate =
    # cache_read / (cache_read + input). A value stuck near zero across a run flags
    # a silent cache invalidator (a date/UUID in the system prompt, an unstable
    # tool order) -- the cheapest regression to catch and the dearest to miss.
    ("counter", "llm_cache_tokens", "maverick_llm_cache_tokens_total",
     "Prompt-cache input tokens", ("provider", "model", "kind")),
    ("counter", "tool_calls", "maverick_tool_calls_total", "Tool invocations",
     ("tool", "status")),
    # Lifetime total -> a Counter (monotonic, accumulates via inc()). A Gauge fed
    # `.set(budget.dollars)` from the per-goal Budget accumulator would let a second
    # goal starting fresh at $0 stomp the running total back down. Callers inc() by
    # each call's delta, which sums to a true cross-goal lifetime spend.
    ("counter", "budget_dollars", "maverick_budget_dollars_spent",
     "Total dollars spent (lifetime)", ()),
    # latency_budget.note_elapsed has always called record_metric with this name,
    # but it was never registered -- and record_metric returns silently for an
    # unknown metric, so every breach was recorded into nothing. The one signal that
    # says a tool blew its latency budget was dropped at the last step.
    ("counter", "tool_latency_budget_exceeded", "maverick_tool_latency_budget_exceeded_total",
     "Tool calls that exceeded [tools] latency_budget_ms", ("tool",)),
)

_SAFE_TELEMETRY_LABEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,63}$")


def safe_agent_telemetry_label(value: object, *, fallback: str = "redacted-agent") -> str:
    """Return a bounded, non-secret label safe for telemetry metadata.

    Spawned-agent roles can be model-controlled.  Keep ordinary role/id labels
    unchanged for readable traces, but never export arbitrary prompt text,
    whitespace, or long values to Sentry/OTel span names or GenAI attributes.
    """
    if isinstance(value, str) and _SAFE_TELEMETRY_LABEL_RE.fullmatch(value):
        return value
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:12]
    return f"{fallback}-{digest}"


def _safe_metric_label(value: object) -> str:
    """Bound hostile/dynamic metric label text without exposing raw payloads."""
    text = str(value)
    if (
        len(text) <= 128
        and all(char >= " " and char not in {"\x7f", "\r", "\n"} for char in text)
    ):
        return text
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    return f"redacted-{digest}"


def _bounded_metric_labels(
    metric_name: str,
    labels: dict[str, str],
) -> dict[str, str]:
    """Return safe labels under a fixed per-metric series-cardinality budget.

    ``prometheus_client`` retains every distinct label tuple for the process
    lifetime. Model IDs and generated tool names are configurable, so passing
    them through without a budget turns telemetry into an unbounded-memory
    input surface. Reserve one series for overflow and aggregate every later
    unseen tuple there.
    """
    safe = {str(key): _safe_metric_label(value) for key, value in labels.items()}
    signature = tuple(sorted(safe.items()))
    with _metric_series_lock:
        seen = _metric_label_series.setdefault(metric_name, set())
        if signature in seen:
            return safe
        if len(seen) < max(0, _MAX_LABEL_SERIES_PER_METRIC - 1):
            seen.add(signature)
            return safe
        overflow = dict.fromkeys(safe, _OVERFLOW_LABEL)
        seen.add(tuple(sorted(overflow.items())))
        return overflow


def _setting(env_name: str, key: str) -> str | None:
    """The environment variable, else ``[observability] key`` (read at start)."""
    from .env_setting import env_or_config

    return env_or_config(env_name, "observability", key)


# The text an on/off setting reads as off. The environment and [observability] both
# arrive as text, and a TOML ``false`` arrives as "0", so each spelling is listed.
_OFF_TEXT = frozenset({"", "0", "false", "off", "no"})
_ON_TEXT = frozenset({"1", "true", "yes", "on"})


def _text(value: object) -> str:
    return "" if value is None else str(value).strip().lower()


def switch_is_on(value: object, *, extra_on: frozenset[str] = frozenset()) -> bool:
    """True when an on/off setting's value turns it on.

    ``1``, ``true``, ``yes`` and ``on`` (any case) turn it on, and so do the setting's own
    documented values in ``extra_on``. Everything else is off: ``false``, ``0``, ``off``,
    ``no``, blank, and text this list does not name. ``value`` is the text or the raw
    TOML value.
    """
    text = _text(value)
    return text in _ON_TEXT or text in extra_on


def setting_is_blank_or_off(value: object) -> bool:
    """True when a setting that is on by being set (a DSN, a port) is blank or switched off."""
    return _text(value) in _OFF_TEXT


def _otel_enabled() -> bool:
    """``MAVERICK_OTEL_EXPORTER`` / ``[observability] otel_exporter``: on for ``otlp``."""
    return switch_is_on(_setting("MAVERICK_OTEL_EXPORTER", "otel_exporter"),
                        extra_on=frozenset({"otlp"}))


def _sentry_dsn() -> str:
    """Sentry DSN from env or [observability] sentry_dsn (empty = off, and so is ``false``)."""
    dsn = os.environ.get("MAVERICK_SENTRY_DSN", "").strip()
    if not dsn:
        try:
            from .config import load_config
            dsn = str((load_config() or {}).get("observability", {}).get("sentry_dsn") or "").strip()
        except Exception:  # pragma: no cover -- config never blocks init
            return ""
    return "" if setting_is_blank_or_off(dsn) else dsn


def _sentry_enabled() -> bool:
    return bool(_sentry_dsn())


def _prometheus_enabled() -> bool:
    """``MAVERICK_PROMETHEUS_PORT`` / ``[observability] prometheus_port``: a port turns it on.

    A config ``false`` reaches here as ``"0"``, which would otherwise bind a random port.
    """
    return not setting_is_blank_or_off(_setting("MAVERICK_PROMETHEUS_PORT", "prometheus_port"))


def _otlp_headers() -> dict[str, str]:
    """Parse ``MAVERICK_OTEL_HEADERS`` into a header dict for the exporter.

    Format mirrors the OTel-standard ``OTEL_EXPORTER_OTLP_HEADERS``:
    comma-separated ``key=value`` pairs (``x-honeycomb-team=abc,dd-api-key=xyz``).
    Returns ``{}`` when unset/blank so the default (no headers) is unchanged.
    Malformed pairs (no ``=``) are skipped rather than crashing init.
    """
    raw = (_setting("MAVERICK_OTEL_HEADERS", "otel_headers") or "").strip()
    if not raw:
        return {}
    headers: dict[str, str] = {}
    for pair in raw.split(","):
        key, sep, value = pair.partition("=")
        key = key.strip()
        if sep and key:
            headers[key] = value.strip()
    return headers


def _otlp_metrics_enabled() -> bool:
    """``MAVERICK_OTEL_METRICS`` / ``[observability] otlp_metrics``: on for a true value only.

    A config ``false`` reaches here as ``"0"``, which a plain ``bool()`` would read as on.
    """
    return switch_is_on(_setting("MAVERICK_OTEL_METRICS", "otlp_metrics"))


def _otlp_metrics_endpoint(traces_endpoint: str) -> str | None:
    """The OTLP/HTTP metrics URL for the span endpoint, or ``None`` if there is none.

    The HTTP exporter posts to an explicit endpoint verbatim, so the signal path
    must be right: ``.../v1/traces`` becomes ``.../v1/metrics``, the path the
    exporter uses by default. Any other span endpoint has no derivable metrics
    path, so metrics stay off rather than post to a guessed URL.
    """
    suffix = "/v1/traces"
    if traces_endpoint.endswith(suffix):
        return traces_endpoint[: -len(suffix)] + "/v1/metrics"
    return None


def _initialize_otlp_metrics(endpoint: str, headers: dict[str, str], resource: Any) -> None:
    """Create one OTLP instrument per ``_METRIC_SPECS`` row, on a meter of its own.

    The meter provider is not made global (the traces provider is), and it uses the
    span exporter's headers. The imports stay here, so with the knob off the metrics
    SDK is never loaded. A failure logs and leaves metrics off; traces and
    Prometheus are unaffected.
    """
    metrics_endpoint = _otlp_metrics_endpoint(endpoint)
    if metrics_endpoint is None:
        log.warning(
            "observability: OTLP metrics need an endpoint ending in /v1/traces (got %s); "
            "metrics stay off", endpoint,
        )
        return
    try:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    except ImportError:
        log.warning(
            "observability: OTLP metrics need opentelemetry-sdk and the OTLP HTTP exporter. "
            "Install with: python -m pip install -e './packages/maverick-core[observability]'"
        )
        return
    try:
        # Same rule as the span exporter: pass headers only when set.
        exporter = (
            OTLPMetricExporter(endpoint=metrics_endpoint, headers=headers)
            if headers
            else OTLPMetricExporter(endpoint=metrics_endpoint)
        )
        provider = MeterProvider(
            resource=resource,
            metric_readers=[PeriodicExportingMetricReader(exporter)],
        )
        meter = provider.get_meter("maverick")
        for kind, key, name, doc, _labels in _METRIC_SPECS:
            if kind == "histogram":
                instrument = meter.create_histogram(name, description=doc)
            else:
                instrument = meter.create_counter(name, description=doc)
            _otel_instruments[key] = (kind, instrument)
    except Exception as e:
        log.warning("observability: OTLP metrics exporter init failed: %s", e)
        return
    log.info("observability: OTLP metrics -> %s", metrics_endpoint)


def _initialize() -> None:
    """Idempotent setup. Imports happen here so the module is cheap to
    import when observability is off."""
    global _initialized, _tracer, _sentry, _trace_api
    with _init_lock:
        if _initialized:
            return
        _initialized = True

        if _sentry_enabled():
            # Sentry performance tab: init with tracing on so trace_span()
            # also opens Sentry spans (transactions at the root). Sample rate
            # via MAVERICK_SENTRY_TRACES_SAMPLE_RATE (default 0.1).
            try:
                import sentry_sdk
                try:
                    rate = float(_setting("MAVERICK_SENTRY_TRACES_SAMPLE_RATE",
                                          "sentry_traces_sample_rate") or "0.1")
                except ValueError:
                    rate = 0.1
                sentry_sdk.init(
                    dsn=_sentry_dsn(),
                    traces_sample_rate=max(0.0, min(1.0, rate)),
                    # The runtime handles prompts/results; never attach local
                    # variables or request bodies to events.
                    include_local_variables=False,
                    send_default_pii=False,
                )
                _sentry = sentry_sdk
                log.info("observability: Sentry performance tracing on")
            except ImportError:
                log.warning(
                    "observability: MAVERICK_SENTRY_DSN set but sentry-sdk is "
                    "not installed. python -m pip install -e './packages/maverick-core[sentry]'")

        if _otel_enabled():
            try:
                from opentelemetry import trace
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
                from opentelemetry.sdk.resources import Resource
                from opentelemetry.sdk.trace import TracerProvider
                from opentelemetry.sdk.trace.export import BatchSpanProcessor
            except ImportError:
                log.warning(
                    "observability: opentelemetry not installed. "
                    "Install with: python -m pip install -e './packages/maverick-core[observability]'"
                )
                return
            endpoint = _setting(
                "MAVERICK_OTEL_ENDPOINT", "otel_endpoint"
            ) or TEXT_SETTINGS["observability.otel_endpoint"].runtime_default
            headers = _otlp_headers()
            resource = Resource.create({"service.name": "maverick"})
            provider = TracerProvider(resource=resource)
            try:
                # Pass headers only when set so the no-header default path is
                # byte-for-byte unchanged for collectors that don't need auth.
                exporter = (
                    OTLPSpanExporter(endpoint=endpoint, headers=headers)
                    if headers
                    else OTLPSpanExporter(endpoint=endpoint)
                )
                provider.add_span_processor(BatchSpanProcessor(exporter))
            except Exception as e:
                log.warning("observability: OTLP exporter init failed: %s", e)
                return
            trace.set_tracer_provider(provider)
            _tracer = trace.get_tracer("maverick")
            _trace_api = trace
            log.info(
                "observability: OTLP traces -> %s (%d header(s))",
                endpoint, len(headers),
            )
            if _otlp_metrics_enabled():
                _initialize_otlp_metrics(endpoint, headers, resource)
        elif _otlp_metrics_enabled():
            log.warning(
                "observability: MAVERICK_OTEL_METRICS is set but MAVERICK_OTEL_EXPORTER "
                "is not otlp; OTLP metrics stay off",
            )

        if _prometheus_enabled():
            try:
                from prometheus_client import Counter, Histogram, start_http_server
            except ImportError:
                log.warning(
                    "observability: prometheus_client not installed. "
                    "Install with: python -m pip install -e './packages/maverick-core[observability]'"
                )
                return
            port_str = _setting("MAVERICK_PROMETHEUS_PORT", "prometheus_port") or "9100"
            addr = _setting("MAVERICK_PROMETHEUS_ADDR", "prometheus_addr") or "127.0.0.1"
            try:
                port = int(port_str)
                start_http_server(port, addr=addr)
            except (OSError, ValueError) as e:
                log.warning("observability: Prometheus exporter failed: %s", e)
                return
            with _metric_series_lock:
                _metric_label_series.clear()
            for kind, key, name, doc, labels in _METRIC_SPECS:
                metric_type = Histogram if kind == "histogram" else Counter
                _metrics[key] = metric_type(name, doc, list(labels))
            _register_computed_collector()
            log.info("observability: Prometheus /metrics on %s:%d", addr, port)


def _register_computed_collector(registry=None) -> None:
    """Export the profiles this process already computes but never published.

    ``tool_latency`` keeps per-tool p50/p95/p99 in a ring buffer and
    ``provider_health`` keeps per-provider error rates; both were readable only
    by calling ``report()`` / ``snapshot()`` in-process. An operator scraping
    /metrics could not see the two numbers they would actually alert on -- so
    the platform computed per-tool p99 and per-provider error rate and exported
    neither.

    A scrape-time collector rather than Counters, because these are derived
    snapshots of a bounded window, not monotonic totals: pushing them into a
    Counter would misreport a ring buffer that forgets as a value that only
    grows. Registration is best-effort and never breaks startup.
    """
    try:
        from prometheus_client import REGISTRY
        from prometheus_client.core import GaugeMetricFamily
    except ImportError:  # pragma: no cover -- optional extra
        return

    class _ComputedProfiles:
        def collect(self):
            lat = GaugeMetricFamily(
                "maverick_tool_latency_ms",
                "Per-tool latency percentiles over the in-process window",
                labels=["tool", "quantile"])
            calls = GaugeMetricFamily(
                "maverick_tool_latency_samples",
                "Samples in the per-tool latency window", labels=["tool"])
            try:
                from . import tool_latency

                for row in tool_latency.report():
                    tool = _safe_metric_label(row.get("tool", "?"))
                    for q, key in (("0.5", "p50_ms"), ("0.95", "p95_ms"),
                                   ("0.99", "p99_ms"), ("max", "max_ms")):
                        lat.add_metric([tool, q], float(row.get(key) or 0.0))
                    calls.add_metric([tool], float(row.get("count") or 0))
            except Exception:  # pragma: no cover -- a scrape must not raise
                log.debug("observability: tool_latency collect failed", exc_info=True)
            yield lat
            yield calls

            err = GaugeMetricFamily(
                "maverick_provider_error_rate",
                "Provider error rate over the in-process window",
                labels=["provider", "model"])
            plat = GaugeMetricFamily(
                "maverick_provider_latency_ms",
                "Provider latency percentiles over the in-process window",
                labels=["provider", "model", "quantile"])
            try:
                from . import provider_health

                for row in provider_health.get().snapshot():
                    p = _safe_metric_label(row.get("provider", "?"))
                    m = _safe_metric_label(row.get("model", "?"))
                    err.add_metric([p, m], float(row.get("error_rate") or 0.0))
                    for q, key in (("0.5", "p50_ms"), ("0.95", "p95_ms")):
                        v = row.get(key)
                        if v is not None:
                            plat.add_metric([p, m, q], float(v))
            except Exception:  # pragma: no cover
                log.debug("observability: provider_health collect failed", exc_info=True)
            yield err
            yield plat

            breaches = GaugeMetricFamily(
                "maverick_tool_latency_budget_breaches",
                "Recorded latency-budget breaches in this process")
            try:
                from . import latency_budget

                breaches.add_metric([], float(len(latency_budget.breaches())))
            except Exception:  # pragma: no cover
                log.debug("observability: latency_budget collect failed", exc_info=True)
            yield breaches

    try:
        target = REGISTRY if registry is None else registry
        target.register(_ComputedProfiles())
    except Exception:  # pragma: no cover -- duplicate registration on re-init
        log.debug("observability: computed collector already registered",
                  exc_info=True)


@contextlib.contextmanager
def trace_span(
    name: str,
    *,
    attributes: dict[str, Any] | None = None,
) -> Iterator[Any]:
    """Context manager that opens a span (no-op when off).

    With Sentry configured, the same call also opens a Sentry span — a
    transaction when there is no active one (episodes), a child span inside
    one (tools) — so the existing instrumentation points feed Sentry's
    performance tab with zero new call sites.
    """
    _initialize()
    with contextlib.ExitStack() as stack:
        if _sentry is not None:
            try:
                if _sentry.get_current_scope().transaction is None:
                    sspan = stack.enter_context(
                        _sentry.start_transaction(name=name, op="maverick"))
                else:
                    sspan = stack.enter_context(_sentry.start_span(op=name))
                for k, v in (attributes or {}).items():
                    try:
                        sspan.set_data(k, v)
                    except Exception:
                        pass
            except Exception:  # pragma: no cover -- sentry must never break a run
                pass
        if _tracer is None:
            yield None
            return
        with _tracer.start_as_current_span(
            name,
            # The SDK would record the exception's message and stack on the span. That
            # text can carry a token, so this span records neither (as http_request_span
            # does); the failure is marked with the exception type alone, below.
            record_exception=False, set_status_on_exception=False,
        ) as span:
            if attributes:
                for k, v in attributes.items():
                    try:
                        span.set_attribute(k, v)
                    except Exception:
                        pass
            try:
                yield span
            except BaseException as e:
                # OTel semconv: failed operations carry ``error.type`` (the
                # exception class). The ERROR status names the type only, and, as
                # in the SDK, only an Exception is an error (not a cancellation).
                error_type = type(e).__qualname__
                try:
                    span.set_attribute("error.type", error_type)
                    if isinstance(e, Exception):
                        span.set_status(_trace_api.StatusCode.ERROR, error_type)
                except Exception:
                    pass
                raise


@contextlib.contextmanager
def http_request_span(method: str, *, carrier: Mapping[str, str] | None = None) -> Iterator[Any]:
    """The OTLP server span for one dashboard HTTP request; ``None`` when span export is off.

    The span is made current, so the spans a request starts (agent, tool,
    provider) nest under it. Unlike trace_span() it never opens a Sentry
    transaction: request spans are OTLP-only, so Sentry's performance quota is
    not spent on every page. ``carrier`` is the caller's W3C trace context; when it
    names a trace, the span joins that trace as a remote child.
    """
    _initialize()
    if _tracer is None:
        yield None
        return
    with _tracer.start_as_current_span(
        f"HTTP {method}", context=_inbound_context(carrier),
        kind=_trace_api.SpanKind.SERVER,
        # The SDK would record an unhandled error's message and stack on the span.
        # That text can carry a path value (a share token) or a secret, so the
        # request span records neither; mark_span_failed sets the status instead.
        record_exception=False, set_status_on_exception=False,
    ) as span:
        yield span


def _inbound_context(carrier: Mapping[str, str] | None) -> Any:
    """The context the caller's ``traceparent`` names, or ``None`` to start a new trace.

    Only ``traceparent`` and ``tracestate`` are passed on, whatever the carrier holds,
    and no value is recorded: the propagator reads them and nothing else.
    """
    if not carrier or "traceparent" not in carrier:
        return None
    try:
        from opentelemetry import propagate

        selected = {key: carrier[key] for key in ("traceparent", "tracestate") if key in carrier}
        state = selected.get("tracestate")
        if state is not None and len(state.encode("utf-8")) > 512:
            # W3C Trace Context caps tracestate at 512 bytes. Ignore the
            # oversized vendor state while preserving the parent trace.
            del selected["tracestate"]
        return propagate.extract(selected)
    except Exception:  # pragma: no cover -- a malformed header never breaks a request
        log.debug("inbound trace context not read", exc_info=True)
        return None


def mark_span_failed(span: Any) -> None:
    """Set the OTel status to ERROR on ``span``: a 5xx answer (exceptions set it themselves)."""
    try:
        span.set_status(_trace_api.StatusCode.ERROR)
    except Exception:  # pragma: no cover -- a span never breaks a request
        log.debug("span status not set", exc_info=True)


def record_metric(
    name: str,
    value: float = 1.0,
    *,
    labels: dict[str, str] | None = None,
) -> None:
    """Bump a known counter / observe a histogram / set a gauge.

    The Prometheus metric and, with ``MAVERICK_OTEL_METRICS`` on, the OTLP
    instrument of the same name both record the value under the same bounded
    labels.
    """
    _initialize()
    metric = _metrics.get(name)
    instrument = _otel_instruments.get(name)
    if metric is None and instrument is None:
        return
    labels = labels or {}
    try:
        labels = _bounded_metric_labels(name, labels) if labels else {}
    except Exception:  # pragma: no cover -- never crash on metric export
        log.debug("metric %s labels failed", name, exc_info=True)
        return
    if metric is not None:
        try:
            # Resolve the label child once. Calling metric.labels() with the
            # wrong (or empty) label set raises in prometheus_client, so only
            # scope when labels are actually provided.
            scoped = metric.labels(**labels) if labels else metric
            # Histograms expose observe(); gauges expose set() *and* inc();
            # counters expose inc(). Prefer set() before inc() so gauges are
            # updated as absolute values rather than accumulated.
            if hasattr(scoped, "observe"):
                scoped.observe(value)
            elif hasattr(scoped, "set"):
                scoped.set(value)
            elif hasattr(scoped, "inc"):
                scoped.inc(value)
        except Exception:  # pragma: no cover -- never crash on metric export
            log.debug("metric %s failed", name, exc_info=True)
    if instrument is not None:
        _record_otlp_metric(name, instrument, value, labels)


def _record_otlp_metric(
    name: str,
    instrument: tuple[str, Any],
    value: float,
    labels: dict[str, str],
) -> None:
    """Record on an OTLP instrument: a histogram observes, a counter adds."""
    kind, otel = instrument
    try:
        if kind == "histogram":
            otel.record(value, attributes=labels or None)
        else:
            otel.add(value, attributes=labels or None)
    except Exception:  # pragma: no cover -- never crash on metric export
        log.debug("OTLP metric %s failed", name, exc_info=True)


def otlp_tracing_enabled() -> bool:
    """True when OTLP span export is on (``MAVERICK_OTEL_EXPORTER=otlp``)."""
    return _otel_enabled()


def is_enabled() -> bool:
    """True if either OTEL or Prometheus is configured."""
    return _otel_enabled() or _prometheus_enabled() or _sentry_enabled()


# --- OpenTelemetry GenAI semantic conventions (gen_ai.*) -------------------
# These attribute names are the cross-vendor standard for LLM/agent
# telemetry (OTel semconv). Emitting them means traces Lightwork produces are
# legible to any OTel-aware backend (Grafana, Honeycomb, Arize Phoenix, ...)
# without custom attribute mapping -- the convention that became the
# observability standard for agents in 2026.

def gen_ai_span_name(operation: str, model: str) -> str:
    """OTel GenAI convention: a span is named ``"<operation> <model>"``."""
    return f"{operation} {model}"


def gen_ai_attributes(
    system: str,
    request_model: str,
    *,
    operation: str = "chat",
    max_tokens: int | None = None,
    temperature: float | None = None,
    top_p: float | None = None,
    frequency_penalty: float | None = None,
    presence_penalty: float | None = None,
    response_model: str | None = None,
    response_id: str | None = None,
    finish_reasons: list[str] | None = None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> dict[str, Any]:
    """Build an OTel GenAI-semconv attribute dict for an LLM span.

    ``system`` is the provider slug (anthropic/openai/gemini/...). Covers the
    full GenAI request + response attribute set; only the fields that are known
    are included, so request-time and response-time attributes can be built in
    two passes (the response side filled once the call returns).
    """
    attrs: dict[str, Any] = {
        "gen_ai.operation.name": operation,
        "gen_ai.system": system,
        "gen_ai.request.model": request_model,
    }
    # -- request parameters (gen_ai.request.*) --
    if max_tokens is not None:
        attrs["gen_ai.request.max_tokens"] = max_tokens
    if temperature is not None:
        attrs["gen_ai.request.temperature"] = temperature
    if top_p is not None:
        attrs["gen_ai.request.top_p"] = top_p
    if frequency_penalty is not None:
        attrs["gen_ai.request.frequency_penalty"] = frequency_penalty
    if presence_penalty is not None:
        attrs["gen_ai.request.presence_penalty"] = presence_penalty
    # -- response (gen_ai.response.*) --
    if response_model is not None:
        attrs["gen_ai.response.model"] = response_model
    if response_id is not None:
        attrs["gen_ai.response.id"] = response_id
    if finish_reasons is not None:
        attrs["gen_ai.response.finish_reasons"] = list(finish_reasons)
    # -- usage (gen_ai.usage.*) --
    if input_tokens is not None:
        attrs["gen_ai.usage.input_tokens"] = input_tokens
    if output_tokens is not None:
        attrs["gen_ai.usage.output_tokens"] = output_tokens
    return attrs


def gen_ai_agent_attributes(
    name: str,
    *,
    agent_id: str | None = None,
    description: str | None = None,
    operation: str = "invoke_agent",
) -> dict[str, Any]:
    """Build an OTel GenAI-semconv attribute dict for an agent span.

    The convention models running an agent as the ``invoke_agent`` operation
    with ``gen_ai.agent.name`` / ``gen_ai.agent.id`` /
    ``gen_ai.agent.description`` — the third leg (alongside LLM and tool
    spans) of the GenAI semconv an agent runtime is expected to emit.
    """
    attrs: dict[str, Any] = {
        "gen_ai.operation.name": operation,
        "gen_ai.agent.name": safe_agent_telemetry_label(name),
    }
    if agent_id is not None:
        attrs["gen_ai.agent.id"] = safe_agent_telemetry_label(agent_id)
    if description is not None:
        attrs["gen_ai.agent.description"] = description
    return attrs


def gen_ai_tool_attributes(
    tool_name: str,
    *,
    call_id: str | None = None,
    description: str | None = None,
    tool_type: str = "function",
) -> dict[str, Any]:
    """Build an OTel GenAI-semconv attribute dict for a tool-execution span.

    The convention models a tool call as the ``execute_tool`` operation with
    ``gen_ai.tool.name`` / ``gen_ai.tool.call.id`` / ``gen_ai.tool.type``, the
    counterpart to :func:`gen_ai_attributes` for LLM spans. Optional fields are
    omitted when unknown so a caller that only knows the tool name still emits a
    valid span.
    """
    attrs: dict[str, Any] = {
        "gen_ai.operation.name": "execute_tool",
        "gen_ai.tool.name": tool_name,
        "gen_ai.tool.type": tool_type,
    }
    if call_id is not None:
        attrs["gen_ai.tool.call.id"] = call_id
    if description is not None:
        attrs["gen_ai.tool.description"] = description
    return attrs


__all__ = [
    "trace_span", "record_metric", "is_enabled",
    "http_request_span", "mark_span_failed", "otlp_tracing_enabled",
    "switch_is_on", "setting_is_blank_or_off",
    "gen_ai_span_name", "gen_ai_attributes", "gen_ai_tool_attributes",
    "gen_ai_agent_attributes",
    "safe_agent_telemetry_label",
]
