"""Exposed-deployment hardening: dashboard resource limits.

Covers:
  * SSE goal-event stream concurrency cap (503 past the limit).
  * Per-client goal rate limiting (one client's flood doesn't 429 another).
  * A2A JSON-RPC body-size cap (oversized body rejected with 413).
  * /healthz minimal payload when ANY auth mechanism is configured
    (static token, OIDC, or reverse-proxy SSO).
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _setup(monkeypatch, tmp_path):
    from maverick import world_model
    db = tmp_path / "world.db"
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()
    return world_model.WorldModel(db)


# ---------- task 1: SSE concurrent-connection cap ----------

def test_sse_stream_returns_503_when_cap_exhausted(monkeypatch, tmp_path):
    w = _setup(monkeypatch, tmp_path)
    gid = w.create_goal("g", "d")
    w.set_goal_status(gid, "done")

    from maverick_dashboard import app as dash_app

    # Simulate the cap being fully consumed by other live streams: the route
    # checks ``sem.locked()`` and returns 503 before ever acquiring, so a stub
    # reporting "locked" is enough (and avoids touching a real event loop).
    class _FullSem:
        def locked(self):
            return True

    monkeypatch.setattr(dash_app, "_get_sse_semaphore", lambda: _FullSem())

    r = _client().get(f"/api/goal/{gid}/events/stream")
    assert r.status_code == 503
    assert r.headers.get("Retry-After") == "5"


def test_sse_stream_serves_when_capacity_available(monkeypatch, tmp_path):
    w = _setup(monkeypatch, tmp_path)
    gid = w.create_goal("g", "d")
    w.append_event(gid, "planner", "plan", "hi")
    w.set_goal_status(gid, "done")

    from maverick_dashboard import app as dash_app
    # Fresh, fully-available semaphore.
    monkeypatch.setattr(dash_app, "_get_sse_semaphore", lambda: asyncio.Semaphore(4))

    r = _client().get(f"/api/goal/{gid}/events/stream")
    assert r.status_code == 200
    assert "event: terminal" in r.text


# ---------- task 2: per-client goal rate limiting ----------

def _reset_rl():
    from maverick_dashboard import app as dash_app
    dash_app._goal_times.clear()
    dash_app._goal_times_global.clear()


def test_rate_limit_is_per_client(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    _reset_rl()
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "2")
    # Keep the global ceiling well above the per-client cap so it doesn't fire.
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "100")

    from fastapi import HTTPException
    from maverick_dashboard import app as dash_app

    class _Req:
        def __init__(self, host):
            self.client = type("C", (), {"host": host})()

    a = _Req("1.1.1.1")
    b = _Req("2.2.2.2")

    # Client A exhausts its own window (cap 2).
    dash_app.check_goal_rate_limit(a)
    dash_app.check_goal_rate_limit(a)
    with pytest.raises(HTTPException) as exc:
        dash_app.check_goal_rate_limit(a)
    assert exc.value.status_code == 429

    # Client B is unaffected by A's flood.
    dash_app.check_goal_rate_limit(b)
    dash_app.check_goal_rate_limit(b)


def test_rate_limit_global_ceiling(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    _reset_rl()
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "5")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "3")

    from fastapi import HTTPException
    from maverick_dashboard import app as dash_app

    class _Req:
        def __init__(self, host):
            self.client = type("C", (), {"host": host})()

    # Three distinct clients, each under their own cap, still trip the global
    # ceiling of 3.
    dash_app.check_goal_rate_limit(_Req("1.1.1.1"))
    dash_app.check_goal_rate_limit(_Req("2.2.2.2"))
    dash_app.check_goal_rate_limit(_Req("3.3.3.3"))
    with pytest.raises(HTTPException) as exc:
        dash_app.check_goal_rate_limit(_Req("4.4.4.4"))
    assert exc.value.status_code == 429


# ---------- task 3: A2A JSON-RPC body-size cap ----------

def test_a2a_oversized_body_rejected(monkeypatch):
    pytest.importorskip("fastapi")
    import maverick.a2a as a2a
    from fastapi import FastAPI

    monkeypatch.setenv("MAVERICK_A2A_ENABLED", "1")
    monkeypatch.setenv("MAVERICK_A2A_ALLOW_UNAUTHENTICATED", "1")
    monkeypatch.delenv("MAVERICK_A2A_TOKEN", raising=False)

    app = FastAPI()
    a2a.mount(app)
    client = TestClient(app, base_url="http://127.0.0.1")

    # >256 KiB body must be rejected before parsing/auth.
    big = "x" * (300 * 1024)
    rpc = {"jsonrpc": "2.0", "id": 1, "method": "message/send",
           "params": {"pad": big}}
    r = client.post("/a2a/v1", json=rpc)
    assert r.status_code == 413
    assert r.json()["error"]["message"] == "request body too large"

    # A small body still works.
    small = {"jsonrpc": "2.0", "id": 2, "method": "tasks/get",
             "params": {"id": "nope"}}
    r = client.post("/a2a/v1", json=small)
    assert r.status_code == 200


def test_finance_body_cap_rejects_declared_length_before_parsing(monkeypatch):
    from maverick_dashboard import app as dash_app

    path = "/api/v1/finance-operations/anomalies/scan"
    monkeypatch.setitem(dash_app._FINANCE_LARGE_BODY_LIMITS, path, 64)
    response = _client().post(
        path,
        content=b"{}",
        headers={
            "Content-Type": "application/json",
            "Content-Length": "65",
            "Origin": "http://127.0.0.1",
        },
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "finance operations request body too large"}


def test_finance_body_cap_streams_chunked_body_without_content_length(monkeypatch):
    from maverick_dashboard import app as dash_app

    path = "/api/v1/finance-operations/anomalies/scan"
    monkeypatch.setitem(dash_app._FINANCE_LARGE_BODY_LIMITS, path, 64)

    def chunks():
        yield b"{" + (b"x" * 39)
        yield b"x" * 40 + b"}"

    response = _client().post(
        path,
        content=chunks(),
        headers={
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
            "Origin": "http://127.0.0.1",
        },
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "finance operations request body too large"}


@pytest.mark.parametrize(
    ("path", "limit_name", "detail"),
    (
        (
            "/api/v1/public/consent/rights-requests",
            "_MAX_PUBLIC_CONSENT_BODY_BYTES",
            "public consent request body too large",
        ),
        (
            "/api/v1/external/third-party-collaboration/portal_ref_1234567890/draft",
            "_MAX_THIRD_PARTY_COLLABORATION_BODY_BYTES",
            "third-party collaboration request body too large",
        ),
    ),
)
def test_public_governance_body_cap_stops_lengthless_stream_before_authority(
    monkeypatch,
    path,
    limit_name,
    detail,
):
    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(dash_app, limit_name, 64)
    resolver_calls: list[str] = []
    monkeypatch.setattr(
        dash_app.app.state,
        "third_party_collaboration_portal_resolver",
        lambda *_args, **_kwargs: resolver_calls.append("called"),
        raising=False,
    )
    consent_origin_calls: list[str] = []
    if path.startswith("/api/v1/public/consent/"):
        monkeypatch.setattr(
            dash_app.app.state,
            "public_consent_error_origin_resolver",
            lambda request: consent_origin_calls.append(request.url.path)
            or "https://consent.example",
            raising=False,
        )

    def chunks():
        yield b"{" + (b"x" * 39)
        yield b"x" * 40 + b"}"

    response = _client().request(
        "PUT" if path.endswith("/draft") else "POST",
        path,
        content=chunks(),
        headers={
            "Content-Type": "application/json",
            "Transfer-Encoding": "chunked",
            "Authorization": "ThirdPartyInvitation tpc1." + ("A" * 43),
            "Origin": "https://consent.example",
        },
    )
    assert response.status_code == 413
    assert response.json() == {"detail": detail}
    assert resolver_calls == []
    if path.startswith("/api/v1/public/consent/"):
        assert response.headers["access-control-allow-origin"] == (
            "https://consent.example"
        )
        assert response.headers["cache-control"] == "no-store, private"
        assert consent_origin_calls == [path]
    else:
        assert "access-control-allow-origin" not in response.headers


def test_evidence_files_skip_the_json_cap_and_meet_authentication_first(monkeypatch):
    """A supplier's evidence file is larger than the portal's JSON cap by design.

    It is not buffered by the JSON cap: the route authenticates the invitation
    before reading anything and then streams only up to that invitation's own
    file limit (see test_third_party_collaboration_evidence.py).
    """

    from maverick_dashboard import app as dash_app

    monkeypatch.setattr(dash_app, "_MAX_THIRD_PARTY_COLLABORATION_BODY_BYTES", 64)
    resolver_calls: list[str] = []
    monkeypatch.setattr(
        dash_app.app.state,
        "third_party_collaboration_portal_resolver",
        lambda *_args, **_kwargs: resolver_calls.append("called"),
        raising=False,
    )
    portal = "portal_ref_1234567890"
    response = _client().post(
        f"/api/v1/external/third-party-collaboration/{portal}/evidence",
        content=b"%PDF-" + b"x" * 500,
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "invitation unavailable"}
    assert resolver_calls == []

# ---------- task 4: /healthz minimal payload under a token ----------

def test_healthz_minimal_payload_when_token_set(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")

    r = _client().get("/healthz")
    assert r.status_code == 200
    body = r.json()
    # Only the status leaks; no llm_key / in-flight gauge / db path.
    assert body == {"status": "ok"}
    assert "checks" not in body


def test_healthz_redacts_payload_without_token(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")

    r = _client().get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body == {"status": "ok"}


# ---------- redaction gates on ANY auth mechanism, not just token -----------

def test_healthz_redacts_under_oidc_without_token(monkeypatch, tmp_path):
    # An OIDC-only deployment runs with MAVERICK_DASHBOARD_TOKEN UNSET. The
    # auth-exempt /healthz payload must still redact -- gating on the token
    # alone left the full checks block (llm_key, in-flight gauge, posture)
    # readable by any unauthenticated network peer.
    _setup(monkeypatch, tmp_path)  # delenvs the token
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)

    r = _client().get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert "checks" not in r.json()


def test_readyz_redacts_under_oidc_without_token(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)

    body = _client().get("/readyz").json()
    assert set(body) == {"status"}       # posture detail suppressed
    assert "checks" not in body


def test_healthz_hides_db_path_under_oidc_on_db_failure(monkeypatch, tmp_path):
    # The un-redacted DB-failure branch appends str(e), which carries the
    # absolute world.db path/DSN. Under OIDC (no token) that must collapse to
    # the exception type only -- here, to no checks block at all.
    _setup(monkeypatch, tmp_path)
    monkeypatch.setattr("maverick.oidc.oidc_enabled", lambda: True)

    class _Broken:
        def ping(self):
            raise RuntimeError("/abs/secret/home/world.db is locked")

    from maverick_dashboard import app as dash_app
    monkeypatch.setattr(dash_app, "_world", lambda: _Broken())
    r = _client().get("/healthz")
    assert r.status_code == 503
    assert r.json() == {"status": "degraded"}
    assert "secret" not in r.text        # no DB path leaks


def test_healthz_redacts_under_proxy_sso_without_token(monkeypatch, tmp_path):
    # A reverse-proxy-SSO deployment also runs token-less.
    _setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    monkeypatch.setattr("maverick.proxy_auth.proxy_auth_enabled", lambda: True)

    r = _client().get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}
    assert "checks" not in r.json()


def test_rate_limit_dict_does_not_grow_unbounded(monkeypatch, tmp_path):
    # A stream of distinct one-shot rate-limit keys (many principals / direct
    # client IPs) must not grow _goal_times without bound: the per-call sweep
    # prunes every key whose window has fully expired, not just already-empty ones.
    _setup(monkeypatch, tmp_path)
    _reset_rl()
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "100")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "100000")
    from maverick_dashboard import app as dash_app

    clock = [1000.0]
    monkeypatch.setattr(dash_app.time, "monotonic", lambda: clock[0])

    for i in range(50):
        dash_app.check_goal_rate_limit(source=f"client-{i}")
    assert len(dash_app._goal_times) == 50

    # Advance past the 60s window so every prior entry is stale, then one more
    # distinct call: the sweep prunes the 50 now-empty keys.
    clock[0] = 1100.0
    dash_app.check_goal_rate_limit(source="client-new")
    assert len(dash_app._goal_times) == 1  # only the live key remains
