"""Resuming from the app preserves authorization and deployment spending caps."""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


@pytest.fixture
def resume_env(monkeypatch, tmp_path):
    from maverick import world_model
    from maverick_dashboard import api
    from maverick_dashboard.app import app

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = world_model.WorldModel(world_model.DEFAULT_DB)
    monkeypatch.setattr(api, "_world", lambda: world)
    from maverick_dashboard import _shared
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr(api, "configured_goal_ceiling_dollars", lambda: 2.0)
    calls = []

    async def run(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr("maverick.runner.run_goal_in_background_async", run)
    goal_id = world.create_goal("Review a draft", "")
    world.set_goal_status(goal_id, "blocked", result="Budget exhausted")
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world, goal_id, calls
    world.close()


@pytest.mark.parametrize("payload", [None, {}, {"max_dollars": None}])
def test_legacy_resume_keeps_runner_defaults(resume_env, payload):
    client, world, goal_id, calls = resume_env
    response = client.post(f"/api/v1/goals/{goal_id}/resume", **({"json": payload} if payload is not None else {}))
    assert response.status_code == 204, response.text
    assert world.get_goal(goal_id).status == "pending"
    assert len(calls) == 1 and "max_dollars" not in calls[0][1]


def test_resume_sends_per_attempt_limit_and_execution_identity(resume_env, monkeypatch):
    from maverick_dashboard import api

    client, _, goal_id, calls = resume_env
    monkeypatch.setattr(api, "execution_user_id_from_request", lambda request: "alice")
    monkeypatch.setattr(api, "caller_suites", lambda request: frozenset({"privacy"}))
    response = client.post(f"/api/v1/goals/{goal_id}/resume", json={"max_dollars": 1.25})
    assert response.status_code == 204, response.text
    assert calls == [((goal_id,), {"max_dollars": 1.25, "user_id": "alice", "channel": "api", "allowed_suites": frozenset({"privacy"})})]


@pytest.mark.parametrize("value, status", [(0, 422), (-1, 422), ("NaN", 422), ("Infinity", 422), (2.01, 400)])
def test_invalid_or_excessive_limit_cannot_change_goal_or_start_work(resume_env, value, status):
    client, world, goal_id, calls = resume_env
    response = client.post(f"/api/v1/goals/{goal_id}/resume", json={"max_dollars": value})
    assert response.status_code == status, response.text
    assert world.get_goal(goal_id).status == "blocked"
    assert world.get_goal(goal_id).result == "Budget exhausted"
    assert not calls


def test_ceiling_is_the_deployment_spend_cap_not_the_fallback(resume_env, monkeypatch):
    """The Settings page's spend cap is the ceiling; the $2 default is only the
    fallback for a deployment that configured nothing."""
    from maverick import runner, runtime_overrides
    from maverick_dashboard import api

    client, world, goal_id, calls = resume_env
    monkeypatch.setattr(api, "configured_goal_ceiling_dollars", runner.configured_goal_ceiling_dollars)
    runtime_overrides.set_budget(25000.01)
    over = client.post(f"/api/v1/goals/{goal_id}/resume", json={"max_dollars": 25000.02})
    assert over.status_code == 400
    assert "$25,000.01" in over.json()["detail"]["field_errors"]["max_dollars"]
    assert world.get_goal(goal_id).status == "blocked" and not calls

    response = client.post(f"/api/v1/goals/{goal_id}/resume", json={"max_dollars": 24000})
    assert response.status_code == 204, response.text
    assert world.get_goal(goal_id).status == "pending"
    assert calls and calls[0][1]["max_dollars"] == 24000


def test_budget_control_does_not_bypass_goal_ownership(resume_env, monkeypatch):
    from maverick_dashboard import api

    client, world, goal_id, calls = resume_env

    def deny(request, goal):
        raise HTTPException(status_code=404, detail="no such goal")

    monkeypatch.setattr(api, "assert_goal_access", deny)
    response = client.post(f"/api/v1/goals/{goal_id}/resume", json={"max_dollars": 1})
    assert response.status_code == 404
    assert world.get_goal(goal_id).status == "blocked"
    assert not calls


def _review(client, goal_id, operation="a" * 32):
    state = client.get(f"/api/v1/goals/{goal_id}/resume-review").json()
    return {"operation_id": operation, "expected_context": state["context"], "expected_updated_at": state["expected_updated_at"],
            "expected_owner": state["expected_owner"], "max_dollars": 1.0}


def test_reviewed_restart_exact_retry_recovers_without_second_dispatch(resume_env):
    client, world, goal_id, calls = resume_env
    body = _review(client, goal_id)
    first = client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body)
    assert first.status_code == 200, first.text
    assert first.json()["admitted"] and first.json()["execution"] == "unconfirmed"
    lookup = client.get(f"/api/v1/goals/{goal_id}/resume-receipt/{body['operation_id']}")
    assert lookup.status_code == 200 and lookup.json()["received"]
    assert lookup.json()["context"] == body["expected_context"]
    world.set_goal_status(goal_id, "failed", result="Later attempt stopped")
    repeated = client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body)
    assert repeated.status_code == 200 and repeated.json()["replayed"]
    assert len(calls) == 1 and world.get_goal(goal_id).status == "failed"
    assert client.post(f"/api/v1/goals/{goal_id}/resume-receipt", json=body).json()["replayed"]


def test_missing_specialist_action_blocks_restart_until_setup_check_passes(resume_env, monkeypatch):
    from maverick import domain_edit

    client, world, goal_id, calls = resume_env
    world.set_goal_domain(goal_id, "legal_research")
    world.set_goal_status(goal_id, "blocked", result=(
        "domain 'legal_research' agent build failed: Domain 'legal_research' "
        "cannot deploy: required workflow tools unavailable: web_search. No model work has started."))
    review = client.get(f"/api/v1/goals/{goal_id}/resume-review")
    assert review.status_code == 200
    assert "needs setup" in review.json()["blocked"]
    body = _review(client, goal_id)
    refused = client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body)
    assert refused.status_code == 409
    assert world.get_goal(goal_id).status == "blocked" and not calls

    monkeypatch.setattr(domain_edit, "workflow_readiness", lambda profile: {"state": "action_ready"})
    ready = client.get(f"/api/v1/goals/{goal_id}/resume-review")
    assert ready.status_code == 200, ready.text
    assert ready.json()["blocked"] == ""
    admitted = client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body)
    assert admitted.status_code == 200, admitted.text
    assert len(calls) == 1


def test_reviewed_restart_stale_version_and_changed_reference_refuse(resume_env):
    client, world, goal_id, calls = resume_env
    body = _review(client, goal_id)
    world.set_goal_status(goal_id, "failed")
    assert client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body).status_code == 409
    assert not calls
    body = _review(client, goal_id)
    assert client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body).status_code == 200
    body["max_dollars"] = 0.5
    assert client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body).status_code == 409
    assert len(calls) == 1


def test_reviewed_restart_refuses_while_cancelled_runner_still_finishes(resume_env):
    from maverick.task_execution_guard import lease
    client, world, goal_id, calls = resume_env
    world.set_goal_status(goal_id, "cancelled")
    body = _review(client, goal_id)
    with lease(world, goal_id):
        response = client.post(f"/api/v1/goals/{goal_id}/resume-reviewed", json=body)
    assert response.status_code == 409 and not calls
    assert world.get_goal(goal_id).status == "cancelled"


def test_copilot_restart_uses_same_admission_receipt(resume_env, monkeypatch):
    from maverick_dashboard import app
    from maverick_dashboard import product_operations_resume as actions
    from starlette.requests import Request
    client, world, goal_id, calls = resume_env
    monkeypatch.setattr(app, "_world", lambda: world)
    request = Request({"type": "http", "method": "POST", "scheme": "http", "path": "/", "headers": []})
    selection, args = {"kind": "goal", "id": goal_id}, {"max_dollars": 1.0}
    reviewed = actions.prepare(request, selection, args)
    first = actions.execute(request, selection, args, reviewed.native, "b" * 32)
    assert first.status == "queued" and len(first.background.tasks) == 1
    replay = actions.recover(request, selection, args, reviewed.native, "b" * 32)
    assert replay.status == "replayed" and replay.background is None
    assert len(world.query("SELECT * FROM goal_mutation_receipts WHERE kind='resume'")) == 1
