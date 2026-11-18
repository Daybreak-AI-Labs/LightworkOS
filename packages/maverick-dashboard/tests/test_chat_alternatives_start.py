"""Try again / Edit and resend / Branch from here must start, or say why not.

Live goals 40-42 (Try again, Edit and resend, Branch from here) stayed
"pending" with no events for 43-50 minutes. The runner refused them at start
("The task owner no longer has workspace execution permission"), logged the
error and left the task queued forever. These tests run the real flow for a
named workspace member and pin that a refused start is settled with a plain
reason instead of hanging.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal

ORIGIN = {"Origin": "http://127.0.0.1"}
RUNS: dict[int, tuple] = {}


@pytest.fixture
def env(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import app as dash
    from maverick_dashboard import auth

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_TENANT", "MAVERICK_DASHBOARD_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:org-admin")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "1000")
    config.reset_config_cache()
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **_: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token}))
    dash._world_cache.clear()
    from maverick.tenant import registry
    from maverick_dashboard import rbac, workspace_tenants

    registry.create_tenant("demo", display_name="Demo")
    rbac.set_tenant_role("demo", "user:member", "operator", actor="test")
    for who in ("org-admin", "member"):
        workspace_tenants.set_selection("user:" + who, "demo")

    # Stop at the model boundary: the orchestrator answers without an AI call.
    def finish(llm, world, budget, goal_id, **_):
        RUNS[goal_id] = (budget.max_dollars, budget.max_wall_seconds)
        world.set_goal_status(goal_id, "done", result="A short answer.")
    RUNS.clear()
    monkeypatch.setattr("maverick.orchestrator.run_goal_sync", finish)
    yield TestClient(dash.app, base_url="http://127.0.0.1", headers=ORIGIN)
    config.reset_config_cache()
    dash._world_cache.clear()


def _headers(who):
    return {"Authorization": "Bearer " + who, "X-Lightwork-Expected-Tenant": "demo"}


def _world():
    from maverick.paths import tenant_scope
    from maverick_dashboard import app as dash

    with tenant_scope(tenant="demo"):
        return dash._world()


def _first_task(client, who):
    sent = client.post("/chat/send", data={"title": "Write a short welcome note", "composer_mode": "message"},
                       headers=_headers(who), follow_redirects=False)
    assert sent.status_code == 303, sent.text
    goal_id = int(sent.headers["location"].rsplit("/", 1)[1])
    page = client.get(f"/chat/goal/{goal_id}", headers=_headers(who))
    assert page.status_code == 200
    return goal_id, re.search(r'data-context="([a-f0-9]{64})"', page.text).group(1)


def _alternative(client, who, goal_id, context, action="retry", **limits):
    source = client.get(f"/api/v1/chat/message-actions/{goal_id}/source", params={"action": action, "context": context},
                        headers=_headers(who))
    assert source.status_code == 200, source.text
    body = source.json()
    reviewed = client.post("/api/v1/chat/message-actions/review", headers=_headers(who), json={
        "context": context, "goal": goal_id, "action": action, "source": body["source"],
        "message": body["message"] or "Try a shorter note", "answer_only": True, **limits})
    assert reviewed.status_code == 200, reviewed.text
    applied = client.post("/api/v1/chat/message-actions/apply", headers=_headers(who),
                          json={"token": reviewed.json()["token"], "confirmed": True})
    assert applied.status_code == 200, applied.text
    return applied.json()["goal"], reviewed.json()


@pytest.mark.parametrize("action", ["retry", "edit", "branch"])
def test_a_named_member_s_alternative_starts_and_finishes(env, action):
    goal_id, context = _first_task(env, "member")
    assert _world().get_goal(goal_id).status == "done"
    new_id, _ = _alternative(env, "member", goal_id, context, action)
    assert _world().get_goal(new_id).status == "done"


@pytest.mark.parametrize("action", ["retry", "edit", "branch"])
def test_a_refused_alternative_is_settled_with_the_reason_not_left_queued(env, action, monkeypatch):
    from maverick import conversation_inbox
    from maverick.stop_reasons import stop_payload

    goal_id, context = _first_task(env, "member")
    assert _world().get_goal(goal_id).status == "done"

    def refused(goal):  # the start-time authority check refuses the owner
        raise PermissionError("The task owner no longer has workspace execution permission")
    monkeypatch.setattr(conversation_inbox, "current_authority", refused)
    new_id, _ = _alternative(env, "member", goal_id, context, action)
    goal = _world().get_goal(new_id)
    assert goal.status == "blocked"
    stop = stop_payload(goal.status, goal.result)
    assert stop["kind"] == "workspace_access"
    assert "member of this workspace" in stop["message"] and "No AI work" in stop["message"]
    assert "workspace administrator" in stop["action"]
    page = env.get(f"/chat/goal/{new_id}", headers=_headers("member")).text
    assert "member of this workspace" in page


@pytest.mark.parametrize("action", ["retry", "edit", "branch"])
def test_an_alternative_runs_under_the_limits_the_person_chose(env, action):
    """The main composer has per-task limits; so do the three alternative flows.
    They can only lower the reviewed limits, and the run's Budget enforces them."""
    goal_id, context = _first_task(env, "member")
    default_dollars, default_seconds = RUNS[goal_id]
    new_id, reviewed = _alternative(env, "member", goal_id, context, action,
                                    max_dollars="0.25", max_minutes="2")
    assert reviewed["caps"]["max_dollars"] == 0.25 and reviewed["caps"]["max_wall_seconds"] == 120
    assert RUNS[new_id] == (0.25, 120)
    assert default_dollars > 0.25 and default_seconds > 120


def test_an_alternative_cannot_raise_the_workspace_limit(env):
    goal_id, context = _first_task(env, "member")
    source = env.get(f"/api/v1/chat/message-actions/{goal_id}/source", params={"action": "retry", "context": context},
                     headers=_headers("member")).json()
    refused = env.post("/api/v1/chat/message-actions/review", headers=_headers("member"), json={
        "context": context, "goal": goal_id, "action": "retry", "source": source["source"],
        "message": source["message"], "answer_only": True, "max_dollars": "100000"})
    assert refused.status_code == 400
    assert "lower the workspace" in refused.text
