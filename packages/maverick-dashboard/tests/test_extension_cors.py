"""Browser-extension CORS gate (extensions/browser <-> the local dashboard).

The allowance is opt-in (`[dashboard] allow_extension` / env) and fail-closed:
until the operator turns it on and configures a dashboard token, no CORS header
is emitted, preflights are not answered, and extension-origin POSTs are blocked
by the cross-site gate. Scoped to extension origins only — web origins never get
a CORS header.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

EXT_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop"
PREFLIGHT_HEADERS = {
    "Origin": EXT_ORIGIN,
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "authorization,content-type",
}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", raising=False)
    # Point config at a non-existent file so a developer's real
    # ~/.maverick/config.toml can't flip the gate under the tests.
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "absent.toml"))
    yield


def _patch_runner(monkeypatch):
    """Stop goal creation from actually calling a provider."""
    import maverick.runner as runner_mod
    calls = []
    monkeypatch.setattr(
        runner_mod, "run_goal_in_thread",
        lambda goal_id, *a, **kw: calls.append(goal_id),
    )
    return calls


# ---------- fail-closed default ----------

def test_gate_off_no_cors_header_on_get():
    resp = _client().get("/livez", headers={"Origin": EXT_ORIGIN})
    assert "access-control-allow-origin" not in resp.headers


def test_gate_off_preflight_not_answered():
    resp = _client().options("/api/v1/goals", headers=PREFLIGHT_HEADERS)
    assert "access-control-allow-origin" not in resp.headers
    assert resp.status_code != 204


def test_gate_off_extension_post_blocked(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    _patch_runner(monkeypatch)
    resp = _client().post(
        "/api/v1/goals", json={"title": "hi"}, headers={"Origin": EXT_ORIGIN},
    )
    assert resp.status_code == 403
    assert "cross-site" in resp.json()["detail"]


# ---------- opt-in via env ----------

def test_gate_on_preflight_answered(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    resp = _client().options("/api/v1/goals", headers=PREFLIGHT_HEADERS)
    assert resp.status_code == 204
    assert resp.headers["access-control-allow-origin"] == EXT_ORIGIN
    assert "authorization" in resp.headers["access-control-allow-headers"].lower()
    assert "POST" in resp.headers["access-control-allow-methods"]


def test_idempotency_header_is_limited_to_goal_admission_and_receipt_read(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    headers = {**PREFLIGHT_HEADERS, "Access-Control-Request-Headers": "authorization,idempotency-key"}
    for path in ("/api/v1/goals", "/api/v1/goal-submissions/receipt"):
        response = _client().options(path, headers=headers)
        assert response.status_code == 204
        assert "idempotency-key" in response.headers["access-control-allow-headers"].lower()
    other = _client().options("/api/v1/connections", headers=headers)
    assert "idempotency-key" not in other.headers["access-control-allow-headers"].lower()
    foreign = _client().options("/api/v1/goals", headers={**headers, "Origin": "https://foreign.example"})
    assert "access-control-allow-origin" not in foreign.headers


def test_gate_on_extension_post_creates_goal(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    calls = _patch_runner(monkeypatch)
    resp = _client().post(
        "/api/v1/goals", json={"title": "from the popup"},
        headers={"Origin": EXT_ORIGIN, "Authorization": "Bearer sekret"},
    )
    assert resp.status_code == 201
    assert resp.headers["access-control-allow-origin"] == EXT_ORIGIN
    assert calls == [resp.json()["id"]]


def test_gate_on_events_poll_gets_cors_header(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    from maverick_dashboard._shared import _world
    goal_id = _world().create_goal("t", "d")
    resp = _client().get(
        f"/api/v1/goals/{goal_id}/events",
        headers={"Origin": EXT_ORIGIN, "Authorization": "Bearer sekret"},
    )
    assert resp.status_code == 200
    assert resp.headers["access-control-allow-origin"] == EXT_ORIGIN


def test_gate_on_web_origin_never_allowed(monkeypatch):
    """Scoped to extension origins: an https origin gets neither CORS nor CSRF pass."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")
    _patch_runner(monkeypatch)
    resp = _client().post(
        "/api/v1/goals", json={"title": "hi"},
        headers={"Origin": "https://evil.example"},
    )
    assert resp.status_code == 401
    assert "access-control-allow-origin" not in resp.headers


def test_gate_on_firefox_origin_accepted(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    moz = "moz-extension://12345678-90ab-cdef-1234-567890abcdef"
    resp = _client().options(
        "/api/v1/goals", headers={**PREFLIGHT_HEADERS, "Origin": moz},
    )
    assert resp.status_code == 204
    assert resp.headers["access-control-allow-origin"] == moz


# ---------- opt-in via config file ----------

def test_gate_on_via_config_file(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    cfg = tmp_path / "config.toml"
    cfg.write_text("[dashboard]\nallow_extension = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    resp = _client().options("/api/v1/goals", headers=PREFLIGHT_HEADERS)
    assert resp.status_code == 204
    assert resp.headers["access-control-allow-origin"] == EXT_ORIGIN


def test_config_false_stays_closed(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text("[dashboard]\nallow_extension = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    resp = _client().options("/api/v1/goals", headers=PREFLIGHT_HEADERS)
    assert "access-control-allow-origin" not in resp.headers


def test_gate_on_without_token_stays_closed(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    resp = _client().options("/api/v1/goals", headers=PREFLIGHT_HEADERS)
    assert "access-control-allow-origin" not in resp.headers
    assert resp.status_code != 204


def test_gate_on_without_token_extension_get_not_readable(monkeypatch):
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    resp = _client().get("/api/v1/goals", headers={"Origin": EXT_ORIGIN})
    assert resp.status_code == 200
    assert "access-control-allow-origin" not in resp.headers


# ---------- token mode ----------

def test_token_mode_still_requires_bearer(monkeypatch):
    """The gate grants CORS, never auth: token mode still 401s without it."""
    monkeypatch.setenv("MAVERICK_DASHBOARD_ALLOW_EXTENSION", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "sekret")
    client = _client()
    resp = client.get("/api/v1/goals", headers={"Origin": EXT_ORIGIN})
    assert resp.status_code == 401
    # ... but the popup can READ the 401 (CORS header present on errors too).
    assert resp.headers["access-control-allow-origin"] == EXT_ORIGIN
    ok = client.get(
        "/api/v1/goals",
        headers={"Origin": EXT_ORIGIN, "Authorization": "Bearer sekret"},
    )
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == EXT_ORIGIN
