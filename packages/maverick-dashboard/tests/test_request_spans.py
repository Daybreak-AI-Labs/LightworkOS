"""Each dashboard HTTP request is one OTel server span, named for its route template.

The span carries the route template (never the raw path or query), the method,
and the status; a 5xx or an unhandled error marks it failed. With OTLP tracing
off the middleware is not installed at all.

The fake-tracer tests need no OpenTelemetry install. The real-SDK test
importorskips it, like the repo's other OTel tests.
"""
from __future__ import annotations

import contextlib
import inspect
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from maverick import observability
from maverick_dashboard import request_spans
from maverick_dashboard.request_spans import RequestSpanMiddleware

# Stand-ins for opentelemetry.trace's enums, as the middleware reads them.
_TRACE_API = SimpleNamespace(
    SpanKind=SimpleNamespace(SERVER="SERVER"),
    StatusCode=SimpleNamespace(ERROR="ERROR"),
)


class _Span:
    def __init__(self, name, kind):
        self.name = name
        self.kind = kind
        self.attributes = {}
        self.events = []
        self.status = None

    def update_name(self, name):
        self.name = name

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def set_status(self, status):
        self.status = status


class _Tracer:
    def __init__(self):
        self.spans = []

    @contextlib.contextmanager
    def start_as_current_span(
        self, name, kind=None, record_exception=True, set_status_on_exception=True,
        **_kwargs,
    ):
        span = _Span(name, kind)
        self.spans.append(span)
        try:
            yield span
        except BaseException as error:
            # What the SDK does for an exception, unless the span is told not to.
            if record_exception:
                span.events.append(("exception", str(error)))
            if set_status_on_exception:
                span.status = "ERROR"
            raise


@pytest.fixture(autouse=True)
def _otlp_tracing_on(monkeypatch):
    """Tracing is on for these tests; no real exporter is ever started."""
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    monkeypatch.setattr(observability, "_initialized", True)
    monkeypatch.setattr(observability, "_tracer", None)
    monkeypatch.setattr(observability, "_trace_api", _TRACE_API)
    monkeypatch.setattr(observability, "_sentry", None)


@pytest.fixture
def tracer(monkeypatch):
    fake = _Tracer()
    monkeypatch.setattr(observability, "_tracer", fake)
    return fake


def _app(**fastapi_options: Any) -> FastAPI:
    app = _add_routes(FastAPI(**fastapi_options))
    assert request_spans.install(app) is True
    return app


def _add_routes(app: FastAPI) -> FastAPI:
    @app.get("/goals/{goal_id}")
    def goal(goal_id: str):
        return {"goal": goal_id}

    @app.get("/unavailable")
    def unavailable():
        return JSONResponse({"detail": "down"}, status_code=503)

    @app.get("/crash")
    def crash():
        raise RuntimeError("internal detail that must not reach a span")

    @app.get("/share/{token}")
    def share(token: str):
        raise KeyError(f"no share for token {token}")

    @app.get("/work")
    def work():
        with observability.trace_span("tool search"):
            return {"ok": True}

    @app.websocket("/ws")
    async def echo(websocket: WebSocket):
        await websocket.accept()
        await websocket.send_text(await websocket.receive_text())
        await websocket.close()

    return app


def _client(app: FastAPI | None = None) -> TestClient:
    # The dashboard builds its app with these options; see app.py.
    app = app or _app(**request_spans.fastapi_telemetry_kwargs())
    return TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False)


def _sdk_provider():
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter, provider


def test_span_is_named_for_the_route_template_and_carries_no_identifiers(tracer):
    response = _client().get(
        "/goals/42?token=s3cret",
        headers={"Cookie": "session=abc", "X-Tenant": "tenant-7"},
    )
    assert response.status_code == 200
    (span,) = tracer.spans
    assert span.name == "HTTP GET /goals/{goal_id}"
    assert span.kind == "SERVER"
    assert span.attributes == {
        "http.request.method": "GET",
        "http.route": "/goals/{goal_id}",
        "http.response.status_code": 200,
    }
    assert span.status is None


def test_a_server_error_answer_marks_the_span_failed(tracer):
    _client().get("/unavailable")
    (span,) = tracer.spans
    assert span.name == "HTTP GET /unavailable"
    assert span.attributes["http.response.status_code"] == 503
    assert span.status == "ERROR"


def test_an_unhandled_error_is_a_500_span_marked_failed(tracer):
    response = _client().get("/crash")
    assert response.status_code == 500
    (span,) = tracer.spans
    assert span.name == "HTTP GET /crash"
    assert span.attributes == {
        "http.request.method": "GET",
        "http.route": "/crash",
        "http.response.status_code": 500,
    }
    assert span.status == "ERROR"
    assert span.events == []  # the exception's text is not recorded on the span


def test_an_unhandled_error_records_no_exception_text_on_the_real_span(monkeypatch):
    """The SDK records an exception's message and stack on a span by default. A path
    value (a share token) can be in that message, so the request span must not record it."""
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace

    exporter, provider = _sdk_provider()
    monkeypatch.setattr(observability, "_tracer", provider.get_tracer("maverick"))
    monkeypatch.setattr(observability, "_trace_api", trace)

    response = _client().get("/share/tok_SECRETTOKEN123?x=1")
    assert response.status_code == 500
    (span,) = exporter.get_finished_spans()
    assert span.name == "HTTP GET /share/{token}"
    assert span.status.status_code == trace.StatusCode.ERROR
    assert len(span.events) == 0
    exported = repr((span.name, dict(span.attributes), span.events))
    assert "tok_SECRETTOKEN123" not in exported
    assert "no share for token" not in exported


def test_an_unmatched_request_is_named_by_method_alone(tracer):
    response = _client().get("/nowhere/secret-id-99")
    assert response.status_code == 404
    (span,) = tracer.spans
    assert span.name == "HTTP GET"
    assert span.attributes == {
        "http.request.method": "GET",
        "http.response.status_code": 404,
    }
    assert "secret-id-99" not in span.name


def test_an_invented_method_is_bounded_to_other(tracer):
    _client().request("PURGE", "/goals/42")
    (span,) = tracer.spans
    assert span.name == "HTTP _OTHER /goals/{goal_id}"
    assert span.attributes["http.request.method"] == "_OTHER"


def test_websockets_pass_through_without_a_span(tracer):
    with _client().websocket_connect("ws://127.0.0.1" + "/ws") as websocket:
        websocket.send_text("ping")
        assert websocket.receive_text() == "ping"
    assert tracer.spans == []


def test_no_span_and_no_error_when_the_tracer_is_unavailable(monkeypatch):
    monkeypatch.setattr(observability, "_tracer", None)
    response = _client().get("/goals/42")
    assert response.status_code == 200
    assert response.json() == {"goal": "42"}


def test_tracing_off_installs_nothing(monkeypatch):
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    app = FastAPI()
    assert request_spans.install(app) is False
    assert RequestSpanMiddleware not in [entry.cls for entry in app.user_middleware]


def test_tracing_on_installs_the_middleware_once(monkeypatch):
    app = FastAPI()
    assert request_spans.install(app) is True
    classes = [entry.cls for entry in app.user_middleware]
    assert classes.count(RequestSpanMiddleware) == 1


def test_the_dashboard_app_decides_at_startup():
    source = (Path(request_spans.__file__).parent / "app.py").read_text(encoding="utf-8")
    assert "request_spans.install(app)" in source


def test_real_sdk_span_and_its_children(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace

    exporter, provider = _sdk_provider()
    monkeypatch.setattr(observability, "_tracer", provider.get_tracer("maverick"))
    monkeypatch.setattr(observability, "_trace_api", trace)

    client = _client()
    client.get("/goals/42?x=1")
    client.get("/unavailable")
    client.get("/work")

    spans = {span.name: span for span in exporter.get_finished_spans()}
    goal = spans["HTTP GET /goals/{goal_id}"]
    assert goal.kind == trace.SpanKind.SERVER
    assert dict(goal.attributes) == {
        "http.request.method": "GET",
        "http.route": "/goals/{goal_id}",
        "http.response.status_code": 200,
    }
    assert goal.status.status_code == trace.StatusCode.UNSET
    assert spans["HTTP GET /unavailable"].status.status_code == trace.StatusCode.ERROR
    # The request span is the current span while the handler runs.
    work = spans["HTTP GET /work"]
    tool = spans["tool search"]
    assert tool.parent.span_id == work.context.span_id


def test_the_fastapi_telemetry_option_is_set_only_with_otlp_tracing_on(monkeypatch):
    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    assert request_spans.fastapi_telemetry_kwargs() == {}
    monkeypatch.setenv("MAVERICK_OTEL_EXPORTER", "otlp")
    if "telemetry" not in inspect.signature(FastAPI).parameters:
        pytest.skip("this FastAPI has no native tracing option")
    assert request_spans.fastapi_telemetry_kwargs() == {"telemetry": {"tracing": False}}


def test_with_tracing_off_fastapi_keeps_its_own_span_as_a_plain_app_does(monkeypatch):
    """Off is the default. A global tracer provider set elsewhere still gets FastAPI's own
    server span, as a plain FastAPI app does, and no Maverick span is added."""
    pytest.importorskip("fastapi.telemetry")
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace

    monkeypatch.delenv("MAVERICK_OTEL_EXPORTER", raising=False)
    exporter, provider = _sdk_provider()
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)

    app = _add_routes(FastAPI(**request_spans.fastapi_telemetry_kwargs()))
    assert request_spans.install(app) is False
    _client(app).get("/goals/42")
    names = [span.name for span in exporter.get_finished_spans()]
    assert "GET /goals/{goal_id}" in names
    assert not any(name.startswith("HTTP ") for name in names)


def test_the_request_span_joins_the_callers_trace(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace

    exporter, provider = _sdk_provider()
    monkeypatch.setattr(observability, "_tracer", provider.get_tracer("maverick"))
    monkeypatch.setattr(observability, "_trace_api", trace)
    trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    parent_id = "00f067aa0ba902b7"

    _client().get(
        "/goals/42",
        headers={"traceparent": f"00-{trace_id}-{parent_id}-01",
                 "Cookie": "session=cookie-secret"},
    )
    (span,) = exporter.get_finished_spans()
    assert format(span.context.trace_id, "032x") == trace_id
    assert format(span.parent.span_id, "016x") == parent_id
    assert span.parent.is_remote
    assert "cookie-secret" not in repr((span.name, dict(span.attributes), span.events))


def test_a_request_without_trace_headers_starts_a_new_trace(monkeypatch):
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace

    exporter, provider = _sdk_provider()
    monkeypatch.setattr(observability, "_tracer", provider.get_tracer("maverick"))
    monkeypatch.setattr(observability, "_trace_api", trace)

    _client().get("/goals/42")
    (span,) = exporter.get_finished_spans()
    assert span.parent is None


def test_only_the_trace_context_headers_are_read():
    scope = {"headers": [
        (b"traceparent", b"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        (b"tracestate", b"vendor=opaque"),
        (b"cookie", b"session=secret"),
        (b"authorization", b"Bearer secret"),
        (b"x-tenant", b"tenant-7"),
    ]}
    assert request_spans._trace_carrier(scope) == {
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "tracestate": "vendor=opaque",
    }
    assert request_spans._trace_carrier({}) == {}


def test_fastapi_own_server_span_is_switched_off_so_no_raw_url_is_exported(monkeypatch):
    """FastAPI 0.143+ opens its own server span once a provider is set; it records the
    raw url.path and url.query. The dashboard's options switch it off."""
    pytest.importorskip("fastapi.telemetry")
    pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry import trace

    exporter, provider = _sdk_provider()
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: provider)
    monkeypatch.setattr(observability, "_tracer", provider.get_tracer("maverick"))
    monkeypatch.setattr(observability, "_trace_api", trace)

    # Negative control: FastAPI's own options leave its span on, raw query and all.
    _client(_app()).get("/goals/42?tab=private")
    assert any(
        span.name == "GET /goals/{goal_id}" and "tab=private" in str(dict(span.attributes))
        for span in exporter.get_finished_spans()
    )

    exporter.clear()
    _client().get("/goals/42?tab=private")
    names = [span.name for span in exporter.get_finished_spans()]
    assert "HTTP GET /goals/{goal_id}" in names
    assert "GET /goals/{goal_id}" not in names
    exported = repr([dict(span.attributes) for span in exporter.get_finished_spans()])
    assert "tab=private" not in exported and "/goals/42" not in exported


def test_inbound_trace_discards_oversized_tracestate(monkeypatch):
    propagate = pytest.importorskip("opentelemetry.propagate")
    seen = []
    monkeypatch.setattr(propagate, "extract", lambda carrier: seen.append(carrier))
    parent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    observability._inbound_context({"traceparent": parent, "tracestate": "x" * 513})
    assert seen[-1] == {"traceparent": parent}
    observability._inbound_context({"traceparent": parent, "tracestate": "a" * 512})
    assert seen[-1]["tracestate"] == "a" * 512
    observability._inbound_context({"traceparent": parent, "tracestate": "é" * 257})
    assert "tracestate" not in seen[-1]
