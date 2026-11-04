"""Consecutive function middlewares run as one layer, with the same results."""
from __future__ import annotations

import contextvars
import inspect
from itertools import pairwise

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.testclient import TestClient
from maverick_dashboard import app as dash_app
from maverick_dashboard.middleware_chain import merge_function_middleware
from starlette.middleware.base import BaseHTTPMiddleware

_SET_INSIDE = contextvars.ContextVar("test_set_inside", default="unset")


def _app(merged: bool, seen: list):
    app = FastAPI()

    @app.get("/plain")
    def plain():
        return PlainTextResponse(f"plain {_SET_INSIDE.get()}")

    @app.post("/echo")
    async def echo(request: Request):
        return PlainTextResponse((await request.body()).decode())

    @app.get("/boom")
    def boom():
        raise RuntimeError("endpoint failed")

    @app.get("/stream")
    def stream():
        return StreamingResponse(iter([b"one,", b"two"]), media_type="text/plain")

    @app.middleware("http")
    async def innermost_sets_context(request, call_next):
        seen.append("innermost")
        _SET_INSIDE.set("leaked")  # never reset: must not reach an outer function
        return await call_next(request)

    @app.middleware("http")
    async def bounds_the_body(request, call_next):
        seen.append("bounds")
        if request.method != "POST":
            return await call_next(request)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
        if len(body) > 8:
            return JSONResponse({"detail": "too large"}, status_code=413)
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        request._body = bytes(body)
        request._receive = replay
        return await call_next(request)

    @app.middleware("http")
    async def blocks(request, call_next):
        seen.append("blocks")
        if request.url.path == "/blocked":
            return JSONResponse({"detail": "signed out"}, status_code=401)
        return await call_next(request)

    @app.middleware("http")
    async def outermost_observes(request, call_next):
        seen.append("outermost")
        try:
            response = await call_next(request)
        except RuntimeError:
            response = JSONResponse({"detail": "caught"}, status_code=500)
        response.headers["x-context-after"] = _SET_INSIDE.get()
        return response

    if merged:
        assert merge_function_middleware(app) == 3
        assert sum(m.cls is BaseHTTPMiddleware for m in app.user_middleware) == 1
    return app


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", "/plain", None),
    ("POST", "/echo", b"12345"),
    ("POST", "/echo", b"123456789"),
    ("GET", "/blocked", None),
    ("GET", "/boom", None),
    ("GET", "/stream", None),
    ("GET", "/missing", None),
])
def test_merged_and_separate_layers_answer_alike(method, path, body):
    results = []
    for merged in (False, True):
        seen = []
        client = TestClient(_app(merged, seen), base_url="http://127.0.0.1", raise_server_exceptions=False)
        response = client.request(method, path, content=body)
        results.append((response.status_code, response.text, response.headers.get("x-context-after"),
                        response.headers.get("content-type"), seen))
    assert results[0] == results[1]
    assert results[1][2] == "unset", "an inner function's context never reaches an outer one"


def test_the_dashboard_runs_its_consecutive_function_middlewares_as_one_layer():
    layers = dash_app.app.user_middleware
    kinds = [m.cls is BaseHTTPMiddleware for m in layers]
    assert not any(a and b for a, b in pairwise(kinds)), "no two function layers in a row"
    chained = [m.kwargs["dispatch"] for m in layers if m.cls is BaseHTTPMiddleware
               and hasattr(m.kwargs["dispatch"], "chained")]
    assert len(chained) == 1
    functions = chained[0].chained
    assert len(functions) == 13
    # A function registered later wraps the earlier ones: the chain runs them
    # outermost first, in the reverse of their order in app.py.
    lines = [inspect.getsourcelines(fn)[1] for fn in functions]
    assert lines == sorted(lines, reverse=True)
    names = [fn.__name__ for fn in functions]
    assert names.index("bearer_auth") < names.index("http_metrics")
    assert names[0] == "tenant_pinning" and names[-1] == "persist_theme"
