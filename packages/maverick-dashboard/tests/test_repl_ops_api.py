"""The task page's code sandbox (``maverick repl exec|transcript|close``).

These run the REAL governed session kernel and the local sandbox backend, so a
step genuinely executes through ``sandbox.exec`` with its receipts."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture
def policy(monkeypatch):
    from maverick import config
    live = {"enable": True, "max_seconds": 60.0, "max_output_chars": 8000,
            "max_state_bytes": 262_144, "max_statements": 200}
    monkeypatch.setattr(config, "get_repl", lambda: dict(live))
    return live


@pytest.fixture
def client(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import app as dash_app
    from maverick_dashboard import repl_ops_api

    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_SUPPRESS_SANDBOX_WARNING", "1")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_CONFIG", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT", "MAVERICK_REPL"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    dash_app._world_cache.clear()
    repl_ops_api._open.clear()
    try:
        yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers=ORIGIN)
    finally:
        repl_ops_api.close_all_sessions(timeout=5)
        config.reset_config_cache()
        audit_writer._default = None
        audit_writer._defaults.clear()
        dash_app._world_cache.clear()


def _as(monkeypatch, role: str, who: str) -> None:
    from maverick_dashboard import auth, rbac
    rbac.set_role(who, role)
    monkeypatch.setattr(auth, "caller_principal", lambda request: who)


def _goal(owner: str = "") -> int:
    from maverick_dashboard._shared import _world
    return _world().create_goal("Tidy the sales sheet", "", owner=owner)


def _audit(monkeypatch) -> list[str]:
    from maverick.audit import writer
    seen: list[str] = []
    real = writer.audit_event

    def spy(kind, **payload):
        seen.append(payload.get("verb") or str(kind))
        return real(kind, **payload)
    monkeypatch.setattr(writer, "audit_event", spy)
    import maverick.audit as audit_pkg
    monkeypatch.setattr(audit_pkg, "audit_event", spy)
    return seen


def test_turned_off_says_so_and_refuses(client):
    gid = _goal()
    assert client.get(f"/api/v1/goals/{gid}/code").json() == {"enabled": False, "sessions": []}
    r = client.post(f"/api/v1/goals/{gid}/code/sessions", json={})
    assert r.status_code == 409 and "turned off" in r.json()["detail"]


def test_open_run_log_and_close_through_the_governed_kernel(client, policy, monkeypatch):
    gid = _goal()
    seen = _audit(monkeypatch)
    sid = client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).json()["id"]
    first = client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/run", json={"code": "x = 21"}).json()
    assert first["ok"] is True
    second = client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/run", json={"code": "print(x * 2)"}).json()
    assert second["ok"] is True and second["output"].strip() == "42"
    failed = client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/run", json={"code": "1 / 0"}).json()
    assert failed["ok"] is False and "ZeroDivisionError" in failed["problems"]
    listing = client.get(f"/api/v1/goals/{gid}/code").json()
    assert listing["enabled"] is True and listing["sessions"][0] == {
        "id": sid, "open": True, "steps": 3, "started": listing["sessions"][0]["started"]}
    log = client.get(f"/api/v1/goals/{gid}/code/sessions/{sid}/log").json()
    assert [s["ok"] for s in log["steps"]] == [True, True, False] and log["steps"][1]["code"] == "print(x * 2)"
    assert client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/close", json={}).json() == {"closed": True}
    assert client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/run", json={"code": "x"}).status_code == 404
    assert client.get(f"/api/v1/goals/{gid}/code/sessions/{sid}/log").json()["closed"] is True  # the log stays
    assert "code_session_open" in seen and "code_session_close" in seen
    assert any("repl" in v.lower() for v in seen)  # the kernel's own per-step record


def test_sessions_belong_to_one_person_and_one_task(client, policy, monkeypatch):
    gid = _goal("user:ada")
    other_task = _goal("user:ada")
    _as(monkeypatch, "admin", "user:ada")
    sid = client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).json()["id"]
    assert client.post(f"/api/v1/goals/{other_task}/code/sessions/{sid}/run", json={"code": "1"}).status_code == 404
    _as(monkeypatch, "admin", "user:bea")
    assert client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/run", json={"code": "1"}).status_code == 404
    assert client.get(f"/api/v1/goals/{gid}/code/sessions/{sid}/log").status_code == 404
    assert client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/close", json={}).status_code == 404
    _as(monkeypatch, "operator", "user:cy")  # cannot even see Ada's task
    assert client.get(f"/api/v1/goals/{gid}/code").status_code == 404
    _as(monkeypatch, "viewer", "user:ada")
    assert client.get(f"/api/v1/goals/{gid}/code").status_code == 403


def test_code_on_this_computer_is_for_installation_administrators(client, policy, monkeypatch):
    gid = _goal("user:op")
    _as(monkeypatch, "operator", "user:op")
    from maverick import governed_repl
    monkeypatch.setattr(governed_repl, "runs_on_host", lambda: True)
    state = client.get(f"/api/v1/goals/{gid}/code").json()
    assert state["allowed"] is False and state["on_this_computer"] is True
    assert client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).status_code == 403
    monkeypatch.setattr(governed_repl, "runs_on_host", lambda: False)
    assert client.get(f"/api/v1/goals/{gid}/code").json()["allowed"] is True


def test_limits_bound_code_sessions_and_the_task_budget(client, policy, monkeypatch):
    from maverick import budget
    from maverick_dashboard import repl_ops_api
    gid = _goal()
    too_long = "x = 1\n" * 4000
    sid = client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).json()["id"]
    assert client.post(f"/api/v1/goals/{gid}/code/sessions/{sid}/run", json={"code": too_long}).status_code == 422
    client.post(f"/api/v1/goals/{gid}/code/sessions", json={})
    r = client.post(f"/api/v1/goals/{gid}/code/sessions", json={})
    assert r.status_code == 409 and "Close one first" in r.json()["detail"]
    # The task's own limits: here one tool call per session.
    monkeypatch.setattr(budget, "resolve_budget_caps", lambda **k: {"max_tool_calls": 1})
    repl_ops_api._open.clear()
    capped = client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).json()["id"]
    assert client.post(f"/api/v1/goals/{gid}/code/sessions/{capped}/run", json={"code": "1"}).json()["ok"] is True
    r = client.post(f"/api/v1/goals/{gid}/code/sessions/{capped}/run", json={"code": "2"})
    assert r.status_code == 409 and "limits" in r.json()["detail"]


def test_idle_sessions_close_and_shutdown_closes_the_rest(client, policy):
    from maverick import governed_repl
    from maverick_dashboard import repl_ops_api
    gid = _goal()
    idle = client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).json()["id"]
    repl_ops_api._open[idle].last_used = time.time() - repl_ops_api.IDLE_SECONDS - 1
    busy = client.post(f"/api/v1/goals/{gid}/code/sessions", json={}).json()["id"]
    assert idle not in repl_ops_api._open and governed_repl.session_info(idle)["closed"] is True
    repl_ops_api.close_all_sessions(timeout=0, wait=False)  # the signal phase does no work
    assert busy in repl_ops_api._open
    repl_ops_api.close_all_sessions(timeout=5)
    assert repl_ops_api._open == {} and governed_repl.session_info(busy)["closed"] is True
