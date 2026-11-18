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

import maverick.orchestrator as _orchestrator
import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal

ORIGIN = {"Origin": "http://127.0.0.1"}
# The live roster entry's shape: an Auth0 subject for a Google sign-in.
ADMIN_SUB = "google-oauth2|104857600123456789"
ADMIN = "user:" + ADMIN_SUB
RUNS: dict[int, tuple] = {}
_REAL_RUN = _orchestrator.run_goal_sync  # the fixture below stubs it; the file tests restore it


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
    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:someone-else," + ADMIN)
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
    for who in (ADMIN_SUB, "member"):
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


@pytest.mark.parametrize("action", ["retry", "edit", "branch"])
def test_an_installation_administrator_s_alternative_starts_like_new_work(env, action):
    """Live goal 40: a roster administrator (Google sign-in through Auth0, no
    named membership in a workspace that has members) starts new work, but the
    runner refused Try again / Edit / Branch at start with "The task owner no
    longer has workspace execution permission". The start-time recheck must
    resolve the role exactly as the request that admitted the work did."""
    from maverick_dashboard import rbac

    assert rbac.get_tenant_role("demo", ADMIN) is None  # no named membership
    goal_id, context = _first_task(env, ADMIN_SUB)
    first = _world().get_goal(goal_id)
    assert first.status == "done"
    assert first.owner == ADMIN  # stored exactly as the roster entry
    new_id, _ = _alternative(env, ADMIN_SUB, goal_id, context, action)
    goal = _world().get_goal(new_id)
    assert goal.owner == ADMIN
    assert goal.status == "done", goal.result


def _change_before_start(monkeypatch, change):
    """Change the owner's standing after the review was applied and before the
    runner's start-time check: only that check can refuse the work."""
    import maverick.runner as runner

    real = runner.run_goal_in_background_async

    def start(*args, **kwargs):
        change()
        return real(*args, **kwargs)
    monkeypatch.setattr(runner, "run_goal_in_background_async", start)


def _refused_at_start(client, who, goal_id, context, caplog, reason):
    with caplog.at_level("WARNING", logger="maverick.runner"):
        new_id, _ = _alternative(client, who, goal_id, context, "retry")
    goal = _world().get_goal(new_id)
    assert goal.status == "blocked"
    assert new_id not in RUNS  # no model work started
    assert f"goal #{new_id} not started: {reason}" in caplog.text
    return goal


def test_an_administrator_removed_from_the_roster_is_refused_at_start(env, monkeypatch, caplog):
    """Without the roster entry the owner is a non-admin non-member."""
    goal_id, context = _first_task(env, ADMIN_SUB)
    _change_before_start(monkeypatch, lambda: monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "user:someone-else"))
    goal = _refused_at_start(env, ADMIN_SUB, goal_id, context, caplog,
                             "The task owner no longer has workspace execution permission")
    assert goal.result == "start_refused:workspace_access"


def test_a_deactivated_administrator_is_refused_at_start(env, monkeypatch, caplog):
    from maverick_dashboard import subject_directory

    goal_id, context = _first_task(env, ADMIN_SUB)
    _change_before_start(monkeypatch, lambda: subject_directory.retire([ADMIN_SUB]))
    goal = _refused_at_start(env, ADMIN_SUB, goal_id, context, caplog, "The task owner is no longer active")
    assert goal.result == "start_refused:access"


def test_a_demoted_member_is_refused_at_start(env, monkeypatch, caplog):
    from maverick_dashboard import rbac

    goal_id, context = _first_task(env, "member")
    _change_before_start(monkeypatch, lambda: rbac.set_tenant_role("demo", "user:member", "viewer", actor="test"))
    goal = _refused_at_start(env, "member", goal_id, context, caplog,
                             "The task owner no longer has workspace execution permission")
    assert goal.result == "start_refused:workspace_access"


def test_a_non_admin_non_member_cannot_start_work_in_the_workspace(env):
    from maverick_dashboard import workspace_tenants

    workspace_tenants.set_selection("user:outsider", "demo")
    sent = env.post("/chat/send", data={"title": "Write a short welcome note", "composer_mode": "message"},
                    headers=_headers("outsider"), follow_redirects=False)
    assert sent.status_code == 403, (sent.status_code, sent.text[:300])
    assert not RUNS


# ---- the copied files reach the new attempt's model -------------------------
#
# Live goal #50 read QA-note.txt and answered "HERON". Try again (#51, answer
# only) listed "Files available to this new attempt: QA-note.txt" and showed
# "Attachments (1)", but answered "Unknown": the file never reached the model.
# These run the real orchestrator to the model boundary with a scripted model
# that records every prompt it is given.

NOTE = b"The code word is HERON.\n"
QUESTION = "Using only the attached note, what is the code word? Answer in one word."
PROMPTS: list[dict] = []


class _ScriptedModel:
    """Reads the note with its tools when it has them; answers from what it saw.
    A branch copies the earlier answer, so only the note's own text counts."""

    async def complete_async(self, **kwargs):
        import json

        from maverick.llm import LLMResponse, ToolCall

        PROMPTS.append(kwargs)
        seen = json.dumps(kwargs.get("messages"), default=str)
        if "The code word is HERON" in seen:  # the note itself, not an earlier answer
            return LLMResponse("FINAL: HERON", None, [], "end_turn")
        names = {tool.get("name") for tool in kwargs.get("tools") or []}
        listed = re.search(r"(\d+)  QA-note\.txt", seen)
        if listed and "read_attachment" in names:
            return LLMResponse("", None, [ToolCall("r1", "read_attachment", {"id": int(listed.group(1))})], "tool_use")
        if "list_attachments" in names and "list_attachments" not in seen:
            return LLMResponse("", None, [ToolCall("l1", "list_attachments", {})], "tool_use")
        return LLMResponse("FINAL: Unknown", None, [], "end_turn")


@pytest.fixture
def scripted(env, monkeypatch):
    import maverick.orchestrator as orchestrator
    from maverick.llm import LLM

    PROMPTS.clear()
    monkeypatch.setattr(orchestrator, "run_goal_sync", _REAL_RUN)
    monkeypatch.setattr(LLM, "_get_client", lambda self, provider: _ScriptedModel())
    return env


def _task_with_note(client, who="member"):
    sent = client.post("/chat/send", data={"title": QUESTION, "composer_mode": "message"},
                       files={"files": ("QA-note.txt", NOTE, "text/plain")},
                       headers=_headers(who), follow_redirects=False)
    assert sent.status_code == 303, sent.text
    goal_id = int(sent.headers["location"].rsplit("/", 1)[1])
    page = client.get(f"/chat/goal/{goal_id}", headers=_headers(who))
    return goal_id, re.search(r'data-context="([a-f0-9]{64})"', page.text).group(1)


@pytest.mark.parametrize("answer_only", [True, False], ids=["answer-only", "actions-allowed"])
@pytest.mark.parametrize("action", ["retry", "edit", "branch"])
def test_the_new_attempt_reads_the_copied_file(scripted, action, answer_only):
    goal_id, context = _task_with_note(scripted)
    first = _world().get_goal(goal_id)
    assert first.status == "done" and "HERON" in (first.result or ""), first.result
    PROMPTS.clear()
    new_id, reviewed = _alternative(scripted, "member", goal_id, context, action, answer_only=answer_only)
    assert reviewed["answer_only"] is answer_only
    assert [row["name"] for row in reviewed["files"]] == ["QA-note.txt"]
    assert [a.filename for a in _world().list_attachments(new_id)] == ["QA-note.txt"]
    assert PROMPTS, "the new attempt never reached the model"
    goal = _world().get_goal(new_id)
    assert "HERON" in (goal.result or ""), goal.result
