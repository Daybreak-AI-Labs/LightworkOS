"""Decisions on the Approvals page, its API and the Copilot share one answer
path and one authorization rule (maverick_dashboard.decision_requests_api)."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import decision_requests as dr
from maverick.world_model import WorldModel
from maverick_dashboard import api
from maverick_dashboard import app as dashboard
from maverick_dashboard import decision_requests_api as native

_REQUEST = {
    "question": "May this workspace send the weekly summary to customers?",
    "options": [{"label": "Hold it", "effect": "Nothing is sent this week."},
                {"label": "Send it", "effect": "Customers get the summary today."}],
    "recommended": 1, "why": "The summary has not been reviewed.", "area": "external_messages",
}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    from maverick import config

    config.reset_config_cache()
    who = {"principal": "user:alice", "admin": False}
    monkeypatch.setattr(native, "require_permission", lambda *a, **k: None)
    monkeypatch.setattr(native, "caller_principal", lambda _r: who["principal"])
    monkeypatch.setattr(native, "has_permission", lambda _r, perm, **k: perm != "admin" or who["admin"])
    monkeypatch.setattr("maverick.outcome_pilot_start_gate.require_work_item_admission", lambda *a: None)
    started = []
    monkeypatch.setattr(native, "resume", lambda bg, world, goal_id: started.append(goal_id) or True)
    with WorldModel(tmp_path / "world.db") as world:
        monkeypatch.setattr(native, "_world", lambda: world)
        monkeypatch.setattr(api, "_world", lambda: world)
        goal = world.create_goal("Send the weekly summary", "", owner="user:alice")
        world.set_goal_status(goal, "blocked")
        decision = dr.request(world, goal, **dr.validate(_REQUEST))
        client = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
        yield client, world, goal, decision, who, started
    config.reset_config_cache()


def test_the_queue_lists_the_decision_and_an_answer_resumes_the_run(env):
    client, world, goal, decision, _who, started = env

    listed = client.get("/api/v1/decisions").json()["decisions"]
    assert [(d["id"], d["can_answer"], d["recommended"]) for d in listed] == [(decision.id, True, 1)]
    response = client.post(f"/api/v1/decisions/{decision.id}/answer", json={"option": 2, "note": "Approved by sales."})

    assert response.status_code == 200, response.text
    assert response.json()["message"] == "You chose “Send it”. The run continues with your choice."
    assert dr.get(world, decision.id).chosen == 2 and world.get_goal(goal).status == "pending"
    assert started == [goal]


def test_copilot_answers_under_the_same_authorization_as_the_queue(env, monkeypatch):
    from maverick_dashboard import product_operations_decisions as copilot

    client, world, goal, decision, who, started = env
    selection = {"kind": "decision", "id": decision.id}
    who["principal"] = "user:mallory"
    page = client.post(f"/api/v1/decisions/{decision.id}/answer", json={"option": 1})
    assert page.status_code == 404
    with pytest.raises(HTTPException) as refused:
        copilot.prepare(_request(), selection, {"option": 1, "note": ""})
    assert refused.value.status_code == page.status_code

    who["principal"] = "user:alice"
    monkeypatch.setattr("maverick_dashboard.app._require_same_origin", lambda _r: None)
    preview = copilot.prepare(_request(), selection, {"option": 1, "note": ""})
    result = copilot.execute(_request(), selection, {"option": 1, "note": ""}, preview.native, "op-1")
    assert result.status == "confirmed" and dr.get(world, decision.id).chosen == 1
    assert dr.get(world, decision.id).decided_by == "user:alice"


def _request():
    from starlette.requests import Request

    return Request({"type": "http", "method": "POST", "headers": [], "path": "/", "query_string": b""})
