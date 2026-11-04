"""GET /api/v1/voice/captions — live-caption SSE over an injected source."""
from __future__ import annotations

import json

import maverick_dashboard.auth as auth
import pytest
from fastapi.testclient import TestClient
from maverick.live_captions import Segment, register_source, unregister_source
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture
def scripted_source():
    """Register a deterministic transcript source as 'default'; always clean up."""
    async def _gen():
        yield Segment("the quick", final=False, ts=1.0)
        yield Segment("the quick brown fox", ts=2.0)
        yield Segment("jumps over", ts=3.0)

    register_source("default", lambda: _gen())
    yield
    unregister_source("default")


def _frames(body: str) -> list[dict]:
    return [json.loads(line[len("data: "):])
            for line in body.splitlines()
            if line.startswith("data: ") and line != "data: {}"]


def _enable_oidc_principal_map(monkeypatch):
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _as(user: str) -> dict:
    return {"Authorization": f"Bearer {user}"}


def test_captions_404_when_no_source_registered():
    r = client.get("/api/v1/voice/captions")
    assert r.status_code == 404
    assert "no caption source registered" in r.json()["detail"]


def test_captions_stream_rolls_up_segments(scripted_source):
    r = client.get("/api/v1/voice/captions")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    frames = _frames(r.text)
    assert [f["caption"] for f in frames] == [
        "the quick",
        "the quick brown fox",
        "the quick brown fox jumps over",
    ]
    assert [f["final"] for f in frames] == [False, True, True]
    assert frames[-1]["ts"] == 3.0
    assert "event: end" in r.text


def test_captions_max_chars_trims_window(scripted_source):
    r = client.get("/api/v1/voice/captions", params={"max_chars": 16})
    last = _frames(r.text)[-1]["caption"]
    assert len(last) <= 16
    assert last.endswith("jumps over")


def test_captions_named_source_and_unknown_source():
    async def _gen():
        yield Segment("hi from mic2")

    register_source("mic2", lambda: _gen())
    try:
        ok = client.get("/api/v1/voice/captions", params={"source": "mic2"})
        assert _frames(ok.text)[0]["caption"] == "hi from mic2"
        assert client.get(
            "/api/v1/voice/captions", params={"source": "mic9"},
        ).status_code == 404
    finally:
        unregister_source("mic2")


def test_captions_off_again_after_unregister(scripted_source):
    unregister_source("default")
    assert client.get("/api/v1/voice/captions").status_code == 404
    # Re-register so the fixture's cleanup unregister stays a no-op-safe call.
    async def _gen():
        yield Segment("x")
    register_source("default", lambda: _gen())


def test_captions_authenticated_non_admin_cannot_stream_global_source(
    scripted_source, monkeypatch,
):
    _enable_oidc_principal_map(monkeypatch)

    r = client.get("/api/v1/voice/captions", headers=_as("alice"))

    assert r.status_code == 404
    assert r.json()["detail"] == "no such caption source"


def test_captions_503_when_sse_capacity_full(scripted_source, monkeypatch):
    """The caption stream shares the SSE concurrency cap: when the semaphore is
    already fully held it returns 503 instead of opening an unbounded stream."""
    import asyncio

    import maverick_dashboard.api as api

    # A zero-permit semaphore is already locked() -> every SSE slot in use ->
    # the route must 503 before opening (acquiring) a new stream. The shared
    # cap now lives in _shared, so override the accessor the route calls.
    monkeypatch.setattr(api, "_get_sse_semaphore", lambda: asyncio.Semaphore(0))

    r = client.get("/api/v1/voice/captions")
    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "5"


def test_captions_dashboard_admin_can_stream_global_source(scripted_source, monkeypatch):
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:root")

    r = client.get("/api/v1/voice/captions", headers=_as("root"))

    assert r.status_code == 200
    assert _frames(r.text)[0]["caption"] == "the quick"
