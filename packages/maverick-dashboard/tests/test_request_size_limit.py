"""Every dashboard request is size-capped before any parser reads it."""
from __future__ import annotations

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick_dashboard import request_size
from maverick_dashboard.request_size import RequestSizeLimitMiddleware


def _app(limit: int) -> TestClient:
    app = FastAPI()

    @app.post("/upload")
    async def upload(request: Request):
        form = await request.form()
        return {"files": len(form)}

    @app.post("/raw")
    async def raw(request: Request):
        return {"bytes": len(await request.body())}

    app.add_middleware(RequestSizeLimitMiddleware, limit=limit)
    return TestClient(app, base_url="http://127.0.0.1")


def test_small_uploads_pass_and_oversize_uploads_are_refused_plainly():
    client = _app(1024)
    ok = client.post("/upload", files={"f": ("a.txt", b"x" * 100)})
    assert ok.status_code == 200 and ok.json() == {"files": 1}
    big = client.post("/upload", files={"f": ("a.txt", b"x" * 5000)})
    assert big.status_code == 413
    assert big.json()["detail"].startswith("That upload is too large.")


def test_a_streamed_body_without_a_length_is_stopped_at_the_cap():
    client = _app(1024)

    def chunks():
        for _ in range(10):
            yield b"y" * 400

    response = client.post("/raw", content=chunks())
    assert response.status_code == 413


def test_the_cap_comes_from_settings(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_REQUEST_MB", "2")
    assert request_size.max_request_bytes() == 2 * 1024 * 1024
    for bad in ("0", "-5", "nan", "lots"):
        monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_REQUEST_MB", bad)
        assert request_size.max_request_bytes() == request_size.DEFAULT_MAX_REQUEST_MB * 1024 * 1024


@pytest.mark.parametrize("header", ["-1", "not-a-number"])
def test_an_unreadable_length_is_refused(header):
    client = _app(1024)
    response = client.post("/raw", content=b"abc", headers={"content-length": header})
    assert response.status_code == 400


def test_the_dashboard_uses_the_cap(monkeypatch):
    from maverick_dashboard.app import app
    assert any(m.cls is RequestSizeLimitMiddleware for m in app.user_middleware)
