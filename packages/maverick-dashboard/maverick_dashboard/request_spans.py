"""One OpenTelemetry server span per dashboard HTTP request (opt-in).

Installed only when OTLP tracing is on (``MAVERICK_OTEL_EXPORTER=otlp``). That is
decided once, while the app is built: with tracing off the middleware is not in
the stack, so a request pays nothing for it.

The span is named ``HTTP <METHOD> <route template>``, for example
``HTTP GET /goals/{goal_id}``. The template is the route the router matched, so
ids and query strings never reach the span name or its attributes. An unmatched
request is named ``HTTP <METHOD>`` with no ``http.route``. Attributes are
``http.request.method``, ``http.route`` and ``http.response.status_code``; a 5xx,
or an unhandled error, marks the span failed. The W3C ``traceparent`` and
``tracestate`` headers are read so the span joins the caller's trace. No other
header, cookie or identity is read, and no header value is recorded.
"""
from __future__ import annotations

import inspect
import logging
from typing import Any

from fastapi import FastAPI
from maverick import observability

log = logging.getLogger(__name__)

# Methods a span name may carry. Any other method is "_OTHER" (OTel semconv), so a
# client cannot make span names unbounded by inventing methods.
_METHODS = frozenset({
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT",
})


def fastapi_telemetry_kwargs() -> dict[str, Any]:
    """``FastAPI(**kwargs)`` options that switch FastAPI's own per-request tracing off.

    Only with OTLP tracing on. FastAPI 0.143 and later open a server span for every
    request once a global tracer provider is set, and that span records the raw
    ``url.path`` and ``url.query``, which can carry tokens (``/share/<token>``). With
    tracing on, the request span above is the dashboard's server span instead, named
    by route template. With tracing off nothing changes, so a global provider set
    elsewhere still gets FastAPI's spans. Older FastAPI has no native tracing and no
    such option, so it gets nothing extra.
    """
    if not observability.otlp_tracing_enabled():
        return {}
    if "telemetry" in inspect.signature(FastAPI).parameters:
        return {"telemetry": {"tracing": False}}
    return {}


def install(app: Any) -> bool:
    """Add the request-span middleware when OTLP tracing is on; True when it was added.

    Call it once, while the app is built, before the first request.
    """
    if not observability.otlp_tracing_enabled():
        return False
    app.add_middleware(RequestSpanMiddleware)
    return True


# The only request headers read: the W3C trace context, to join the caller's trace.
_TRACE_CONTEXT_HEADERS = (b"traceparent", b"tracestate")


class RequestSpanMiddleware:
    """Pure ASGI: one server span around each HTTP request, named once its route is known."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method = _method(scope)
        with observability.http_request_span(method, carrier=_trace_carrier(scope)) as span:
            if span is None:
                await self.app(scope, receive, send)
                return
            status: list[int] = []

            async def send_and_note_status(message: Any) -> None:
                if message["type"] == "http.response.start" and not status:
                    status.append(int(message["status"]))
                await send(message)

            try:
                await self.app(scope, receive, send_and_note_status)
            except Exception:
                # An unhandled error becomes a 500 in the server layer outside this one.
                if not status:
                    status.append(500)
                raise
            finally:
                _describe(span, scope, method, status[0] if status else None)


def _trace_carrier(scope: Any) -> dict[str, str]:
    """The caller's ``traceparent`` / ``tracestate`` headers, and no other header."""
    carrier: dict[str, str] = {}
    for name, value in scope.get("headers") or ():
        if name.lower() in _TRACE_CONTEXT_HEADERS:
            carrier[name.decode("latin-1").lower()] = value.decode("latin-1")
    return carrier


def _method(scope: Any) -> str:
    method = str(scope.get("method") or "").upper()
    return method if method in _METHODS else "_OTHER"


def _describe(span: Any, scope: Any, method: str, status: int | None) -> None:
    """Name the span for its route template and record the outcome; never the raw path."""
    try:
        # The router stores the matched route on the scope, as http_metrics reads it.
        template = getattr(scope.get("route"), "path", None)
        if isinstance(template, str) and template:
            span.update_name(f"HTTP {method} {template}")
            span.set_attribute("http.route", template)
        else:
            span.update_name(f"HTTP {method}")
        span.set_attribute("http.request.method", method)
        if status is not None:
            span.set_attribute("http.response.status_code", status)
            if status >= 500:
                observability.mark_span_failed(span)
    except Exception:  # pragma: no cover -- a span never breaks a request
        log.debug("request span not described", exc_info=True)
