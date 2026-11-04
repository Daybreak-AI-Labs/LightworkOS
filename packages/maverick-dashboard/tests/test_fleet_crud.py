"""Create / remove a fleet from the operator console (no CLI needed).

POST /api/v1/fleets creates-or-replaces a roster owned by the caller;
DELETE /api/v1/fleets/{name} removes it. Owner-scoped; same-origin POST/DELETE
(the CSRF contract). Mirrors ``maverick fleet create`` / ``fleet rm``.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _as(monkeypatch, principal, *, admin=False):
    import maverick_dashboard.api as api
    monkeypatch.setattr(api, "caller_principal", lambda request: principal)
    monkeypatch.setattr(api, "is_dashboard_admin", lambda p: admin)


def test_create_fleet(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/fleets", json={
        "name": "acme",
        "agents": [
            {"name": "researcher", "role": "analyst", "description": "digs"},
            {"name": "coder", "role": "engineer"},
            {"name": "", "role": "ignored"},  # blank -> dropped
        ],
    })
    assert r.status_code == 201, r.text
    from maverick.fleet import load_fleet
    f = load_fleet("acme")
    assert f is not None
    assert f.owner == ""  # auth-off
    assert [a.name for a in f.agents] == ["researcher", "coder"]  # blank dropped
    assert f.agents[0].role == "analyst"


def test_create_rejects_bad_fleet_name(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/fleets", json={"name": "../evil", "agents": []})
    assert r.status_code == 400


def test_create_rejects_bad_agent_name(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/fleets",
                       json={"name": "ok", "agents": [{"name": "../evil", "role": "x"}]})
    assert r.status_code == 400


def test_create_rejects_missing_agent_role(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post(
        "/api/v1/fleets",
        json={"name": "ok", "agents": [{"name": "worker", "role": "   "}]},
    )
    assert r.status_code == 400


def test_create_rejects_unknown_configured_role(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"roles": {"analyst": {"allow_tools": ["read_file"]}}},
    )
    r = _client().post(
        "/api/v1/fleets",
        json={"name": "ok", "agents": [{"name": "worker", "role": "ghost"}]},
    )
    assert r.status_code == 400


def test_create_owned_by_caller(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _as(monkeypatch, "user:dana")
    r = _client().post("/api/v1/fleets", json={"name": "dteam", "agents": []})
    assert r.status_code == 201
    from maverick.fleet import load_fleet
    assert load_fleet("dteam").owner == "user:dana"


def test_fleet_run_schedules_against_caller_not_agent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _as(monkeypatch, "user:alice")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake")

    import maverick.runner as runner_mod
    from maverick.fleet import Fleet, FleetAgent, save_fleet

    calls = []

    def fake_run(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(runner_mod, "run_goal_in_thread", fake_run)
    save_fleet(Fleet(
        name="acme",
        owner="user:alice",
        agents=(FleetAgent(name="coder", role="engineer"),),
    ))

    r = _client().post(
        "/api/v1/fleets/acme/run",
        json={"agent": "coder", "prompt": "ship it"},
    )

    assert r.status_code == 201, r.text
    assert r.json()["principal"] == "agent:acme.coder"
    assert len(calls) == 1
    assert calls[0][1]["user_id"] == "agent:acme.coder"
    assert calls[0][1]["concurrency_principal"] == "user:alice"


def test_create_clobber_other_owner_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.fleet import Fleet, load_fleet, save_fleet
    save_fleet(Fleet(name="acme", owner="user:dana"))
    _as(monkeypatch, "user:eve")
    r = _client().post("/api/v1/fleets", json={"name": "acme", "agents": []})
    assert r.status_code == 404
    assert load_fleet("acme").owner == "user:dana"  # untouched


def test_delete_fleet(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.fleet import Fleet, load_fleet, save_fleet
    save_fleet(Fleet(name="acme", owner=""))
    assert _client().delete("/api/v1/fleets/acme").status_code == 204
    assert load_fleet("acme") is None


def test_delete_missing_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    assert _client().delete("/api/v1/fleets/ghost").status_code == 404


def test_delete_cross_owner_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.fleet import Fleet, load_fleet, save_fleet
    save_fleet(Fleet(name="acme", owner="user:dana"))
    _as(monkeypatch, "user:eve")
    assert _client().delete("/api/v1/fleets/acme").status_code == 404
    assert load_fleet("acme") is not None  # not removed


def test_page_has_create_form_and_remove(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.fleet import Fleet, save_fleet
    save_fleet(Fleet(name="acme", owner=""))
    text = _client().get("/fleets").text
    assert 'id="fleet-create-form"' in text
    assert 'fleet-remove-btn"' in text
