"""Decision requests: a run asks a person to choose, pauses, and continues
with the chosen option as a structured record (maverick.decision_requests)."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import decision_requests as dr
from maverick.budget import Budget
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel

_REQUEST = {
    "question": "May this workspace keep chat logs for two years?",
    "options": [
        {"label": "Keep 90 days", "effect": "Logs older than 90 days are erased."},
        {"label": "Keep two years", "effect": "Logs stay for two years, then are erased."},
    ],
    "recommended": 1,
    "why": "The current policy says 90 days.",
    "area": "data_erasure_retention",
}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    from maverick import config

    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _world(tmp_path: Path) -> WorldModel:
    return WorldModel(path=tmp_path / "world.db")


def _paused_goal(world, *, owner="alice", area="data_erasure_retention"):
    gid = world.create_goal("tidy the retention settings", "", owner=owner)
    world.set_goal_status(gid, "blocked")
    decision = dr.request(world, gid, **{**dr.validate({**_REQUEST, "area": area})})
    return gid, decision


async def _run(world, gid, fake_llm, tmp_path, budget=None):
    return await run_goal(llm=fake_llm, world=world, budget=budget or Budget(max_dollars=1.0),
                          goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1)


@pytest.mark.asyncio
async def test_a_run_that_asks_pauses_without_spending_even_headless(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    # Headless runs assume past ask_user; a decision is never auto-answered.
    monkeypatch.setenv("MAVERICK_AUTONOMOUS", "1")
    fake_llm.scripted = [make_llm_response(
        text="A person must decide this.",
        tool_calls=[ToolCall(id="t1", name="request_decision", input=_REQUEST)])]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")
    budget = Budget(max_dollars=1.0)

    out = await _run(world, gid, fake_llm, tmp_path, budget)

    goal = world.get_goal(gid)
    assert goal.status == "blocked"
    assert goal.result == f"Waiting for a person to decide: {_REQUEST['question']}"
    assert "Paused" in out and "maverick decisions answer" in out
    [waiting] = dr.open_for_goal(world, gid)
    assert (waiting.recommended, waiting.area, waiting.requested_by) == (1, "data_erasure_retention", "alice")
    # run_goal returned instead of waiting: one model call, the episode is
    # closed, and no process holds the budget while a person decides.
    assert len(fake_llm.calls) == 1
    assert all(e.ended_at is not None for e in world.list_episodes())
    from maverick.runner import inflight_goals

    assert inflight_goals() == 0


@pytest.mark.asyncio
async def test_an_answer_resumes_the_run_with_the_chosen_option(
        tmp_path, fake_llm, make_llm_response):
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)

    outcome = dr.answer(world, decision.id, 2, actor="alice", is_admin=False,
                        note="Legal agreed.")

    assert outcome["resume"] is True and world.get_goal(gid).status == "pending"
    fake_llm.scripted = [
        make_llm_response(text="FINAL: kept for two years"),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    await _run(world, gid, fake_llm, tmp_path)
    first = str(fake_llm.calls[0].get("messages", ""))
    assert '"outcome": "chosen"' in first and '"option": 2' in first
    assert '"label": "Keep two years"' in first and '"note": "Legal agreed."' in first
    assert world.get_goal(gid).status == "done"


def test_a_person_without_authority_is_refused(tmp_path):
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)

    with pytest.raises(dr.DecisionRefused) as refused:
        dr.answer(world, decision.id, 1, actor="mallory", is_admin=False)

    assert refused.value.reason == "not_permitted"
    assert dr.get(world, decision.id).status == "open"
    assert world.get_goal(gid).status == "blocked"


def test_the_starter_answers_an_admin_area_only_as_the_approval_rule_allows(
        tmp_path, monkeypatch):
    # Same rule as a high-risk approval (separate_approver, default when_available).
    world = _world(tmp_path)
    _gid, decision = _paused_goal(world, area="governance")
    assert decision.admin_required
    with pytest.raises(dr.DecisionRefused) as not_admin:
        dr.answer(world, decision.id, 1, actor="bob", is_admin=False)
    assert not_admin.value.reason == "admin_required"

    # Two people: another administrator exists, so the starter may not answer.
    monkeypatch.setattr(dr, "_other_admin_available", lambda requester: True)
    with pytest.raises(dr.DecisionRefused) as refused:
        dr.answer(world, decision.id, 1, actor="alice", is_admin=True)
    assert refused.value.reason == "self_answer"
    # Only one administrator: the starter is the only person who can answer.
    monkeypatch.setattr(dr, "_other_admin_available", lambda requester: False)
    assert dr.answer(world, decision.id, 1, actor="alice", is_admin=True)["decision"].chosen == 1


def test_a_single_person_install_can_answer_its_own_admin_decision(tmp_path):
    world = _world(tmp_path)
    _gid, decision = _paused_goal(world, owner="", area="governance")
    outcome = dr.answer(world, decision.id, 2, actor="", is_admin=True)
    assert outcome["decision"].chosen == 2 and outcome["resume"]


def test_expiry_stops_the_run_without_choosing(tmp_path, monkeypatch):
    import maverick.audit as audit

    written = []
    monkeypatch.setattr(audit, "record", lambda kind, **kw: written.append((kind, kw)) or True)
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)

    assert dr.expire_due(world, now=decision.expires_at + 1) == [decision.id]

    expired = dr.get(world, decision.id)
    assert (expired.status, expired.chosen) == ("expired", None)
    goal = world.get_goal(gid)
    assert goal.status == "failed" and "No option was chosen" in goal.result
    assert ("decision_expired", "system:decision-expiry") in [(k, kw["agent"]) for k, kw in written]
    assert '"outcome": "expired"' in dr.brief_block(world, gid)
    with pytest.raises(dr.DecisionRefused) as late:
        dr.answer(world, decision.id, 1, actor="alice", is_admin=False)
    assert late.value.reason == "expired"


@pytest.mark.asyncio
async def test_an_unsaved_request_stops_the_run_before_it_continues(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    from maverick.attachment_submissions import SubmissionStore

    def broken(self, lock, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(SubmissionStore, "transaction", broken)
    fake_llm.scripted = [
        make_llm_response(text="Asking.", tool_calls=[
            ToolCall(id="t1", name="request_decision", input=_REQUEST)]),
        make_llm_response(text="FINAL: I decided myself"),
    ]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")

    out = await _run(world, gid, fake_llm, tmp_path)

    assert out == dr.STOP_MESSAGE
    assert len(fake_llm.calls) == 1
    goal = world.get_goal(gid)
    assert goal.status == "blocked" and goal.result == dr.STOP_MESSAGE


def test_postgres_keeps_a_decision_inside_its_named_workspace(postgres_test_dsn, monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setattr("maverick.outcome_pilot_start_gate.require_work_item_admission",
                        lambda *a: None)
    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        with tenant_scope(tenant="tenant-a"):
            gid = world.create_goal("tidy the retention settings", "", owner="alice")
            world.set_goal_status(gid, "blocked")
            decision = dr.request(world, gid, **dr.validate(_REQUEST))
        with tenant_scope(tenant="tenant-b"):
            assert dr.get(world, decision.id) is None and dr.list_open(world) == []
            with pytest.raises(dr.DecisionRefused) as hidden:
                dr.answer(world, decision.id, 1, actor="alice", is_admin=True)
            assert hidden.value.reason == "not_found"
        with tenant_scope(tenant="tenant-a"):
            assert [d.id for d in dr.list_open(world)] == [decision.id]
            outcome = dr.answer(world, decision.id, 2, actor="alice", is_admin=False)
            assert outcome["resume"] and world.get_goal(gid).status == "pending"
            assert '"option": 2' in dr.brief_block(world, gid)


def test_the_slack_card_answers_under_the_same_owner_rule(tmp_path, monkeypatch):
    from maverick import slack_interactive as slack

    started = []
    monkeypatch.setattr(dr, "dispatch_resume", lambda _world, goal_id: started.append(goal_id))
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)
    buttons = slack.decision_blocks(decision.public())[-1]["elements"]
    assert [b["value"] for b in buttons] == [f"{decision.id}:1", f"{decision.id}:2"]
    people = {"U1": "alice", "U2": "mallory", "U3": "alice"}
    roles = {"alice": True, "mallory": True}

    def authority(_channel):
        def check(principal, _decision_id):
            if not roles.get(principal):
                raise PermissionError("Your Lightwork account can't answer decisions.")
        return check
    monkeypatch.setattr("maverick_dashboard.approval_decisions.decision_authority_for", authority)
    blocks = slack.decision_blocks(decision.public())
    assert any(b.get("text", {}).get("text") == decision.question for b in blocks)

    def press(user, button):
        return slack.handle_block_action({"type": "block_actions", "user": {"id": user},
                                          "actions": [button]}, world=world, principal_for=people.get)

    assert "Only the person who started this run" in press("U2", buttons[0])["text"]
    roles["alice"] = False  # the owner lost the operator role
    assert "can't answer decisions" in press("U1", buttons[0])["text"]
    roles["alice"] = True
    assert dr.get(world, decision.id).status == "open"
    done = press("U1", buttons[1])
    assert done["replace_original"] and "Keep two years" in done["text"]
    assert dr.get(world, decision.id).chosen == 2 and started == [gid]

    # An administrator-only decision has no buttons; a forged press is refused.
    _gid2, admin_only = _paused_goal(world, area="governance")
    assert slack.decision_blocks(admin_only.public())[-1]["type"] == "context"
    forged = {"action_id": "lightwork_decide_1", "value": f"{admin_only.id}:1"}
    assert "workspace administrator" in press("U1", forged)["text"]


# --- the pause holds for the whole run ---------------------------------------

def _spawn(task="look into the retention policy"):
    return ToolCall(id="s1", name="spawn_subagent", input={"role": "researcher", "task": task})


_FINISH = ["FINAL: done", '{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
           "FINAL: (no skill)"]


@pytest.mark.asyncio
async def test_nothing_else_in_the_turn_runs_once_a_decision_is_filed(
        tmp_path, fake_llm, make_llm_response):
    target = tmp_path / "written.txt"
    fake_llm.scripted = [make_llm_response(text="Writing and asking.", tool_calls=[
        ToolCall(id="w1", name="write_file", input={"path": str(target), "content": "acted"}),
        ToolCall(id="t1", name="request_decision", input=_REQUEST),
        ToolCall(id="w2", name="write_file", input={"path": str(target), "content": "acted"})])]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")

    await _run(world, gid, fake_llm, tmp_path)

    assert not target.exists()
    assert world.get_goal(gid).status == "blocked" and dr.open_for_goal(world, gid)


@pytest.mark.asyncio
async def test_a_parallel_batch_does_not_run_while_the_run_waits(tmp_path, fake_llm, make_llm_response,
                                                                 monkeypatch):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.swarm import SwarmContext

    monkeypatch.setenv("MAVERICK_PARALLEL_TOOLS", "1")
    monkeypatch.setenv("MAVERICK_REHEARSAL", "0")
    world = _world(tmp_path)
    gid = world.create_goal("tidy", "", owner="alice")
    ctx = SwarmContext(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
                       blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=gid, max_depth=2, use_skills=False)
    dr.mark_run(ctx.world, gid, dr.WAITING)  # a sibling agent filed a decision
    ran = []

    async def run_tool(self, name, args):
        ran.append(name)
        return "ok"
    monkeypatch.setattr(Agent, "_run_tool", run_tool)
    fake_llm.scripted = [make_llm_response(text="Reading.", tool_calls=[
        ToolCall(id="r1", name="read_file", input={"path": "a"}),
        ToolCall(id="r2", name="list_dir", input={"path": "."})])]

    result = await Agent(ctx=ctx, role="researcher", brief="read").run()

    assert result.blocked_on_user is True and ran == []


@pytest.mark.asyncio
async def test_a_subagents_decision_pauses_the_root_run(tmp_path, fake_llm, make_llm_response):
    fake_llm.scripted = [
        make_llm_response(text="Delegating.", tool_calls=[_spawn()]),
        make_llm_response(text="A person must decide.", tool_calls=[
            ToolCall(id="c1", name="request_decision", input=_REQUEST)]),
        *[make_llm_response(text=t) for t in _FINISH],
    ]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")

    out = await _run(world, gid, fake_llm, tmp_path)

    assert "Paused" in out and world.get_goal(gid).status == "blocked"
    assert len(fake_llm.calls) == 2 and dr.open_for_goal(world, gid)


@pytest.mark.asyncio
async def test_a_subagents_unsaved_request_stops_the_root_run(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    from maverick.attachment_submissions import SubmissionStore

    def broken(self, lock, **_kw):
        raise OSError("disk full")
    monkeypatch.setattr(SubmissionStore, "transaction", broken)
    fake_llm.scripted = [
        make_llm_response(text="Delegating.", tool_calls=[_spawn()]),
        make_llm_response(text="Asking.", tool_calls=[
            ToolCall(id="c1", name="request_decision", input=_REQUEST)]),
        *[make_llm_response(text=t) for t in _FINISH],
    ]
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")

    out = await _run(world, gid, fake_llm, tmp_path)

    assert out == dr.STOP_MESSAGE and world.get_goal(gid).status == "blocked"
    assert len(fake_llm.calls) == 2


@pytest.mark.asyncio
async def test_a_run_never_finishes_while_a_sub_goal_decision_is_open(
        tmp_path, fake_llm, make_llm_response):
    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")
    child = world.create_goal("check one policy", "", parent_id=gid, owner="alice")
    dr.request(world, child, **dr.validate(_REQUEST))
    fake_llm.scripted = [make_llm_response(text=t) for t in _FINISH]

    out = await _run(world, gid, fake_llm, tmp_path)

    assert world.get_goal(gid).status == "blocked" and "Paused" in out
    assert not fake_llm.calls  # the run did not even start


# --- no restart path skips an open decision --------------------------------------

def test_resume_and_clarification_answers_wait_for_open_decisions(tmp_path, monkeypatch):
    from maverick.attachment_submissions import SubmissionConflict
    from maverick.chat_threads import ChatThreads
    from maverick.conversational_supervisor import Supervisor

    world = _world(tmp_path)
    gid, decision = _paused_goal(world, area="governance")
    question = world.ask("Which folder?", goal_id=gid)

    with pytest.raises(SubmissionConflict) as refused:
        ChatThreads(world).resume(gid)
    assert decision.question in str(refused.value) and "administrator" in str(refused.value)
    restart = ChatThreads(world).answer(gid, question, "The shared one", require_admission=lambda: None)
    assert restart.admitted is False and world.get_goal(gid).status == "blocked"
    goal = world.get_goal(gid)
    assert "Nothing changed" in Supervisor(world)._apply("resume", goal)
    assert world.get_goal(gid).status == "blocked"


def test_cli_resume_refuses_a_waiting_run_with_exit_two(tmp_path):
    import maverick.cli as cli
    from click.testing import CliRunner
    from maverick.world_model import open_world

    db = tmp_path / "world.db"
    world = open_world(db)
    gid, _decision = _paused_goal(world)
    result = CliRunner().invoke(cli.main, ["--db", str(db), "resume", str(gid)])
    assert result.exit_code == 2 and "waiting for 1 decision" in result.output


# --- expiry, restarts and refusals ---------------------------------------------

def test_a_past_due_decision_expires_without_anyone_looking(tmp_path, monkeypatch):
    from maverick.world_model import open_world

    world = open_world()
    gid, decision = _paused_goal(world)

    assert dr.sweep_once(now=decision.expires_at + 1) == 1
    assert dr.get(world, decision.id).status == "expired"
    assert world.get_goal(gid).status == "failed"


def test_a_run_bound_to_its_own_key_is_named_as_needing_its_owner(tmp_path):
    world = _world(tmp_path)
    gid = world.create_goal("tidy", "", owner="alice", execution_principal="agent:nightly")
    world.set_goal_status(gid, "blocked")
    decision = dr.request(world, gid, **dr.validate(_REQUEST))

    outcome = dr.answer(world, decision.id, 1, actor="alice", is_admin=False)

    assert outcome["resume"] is False and outcome["next"] == "manual"
    assert "cannot restart it" in dr.next_text(outcome)


def test_a_flow_step_cannot_stop_to_ask(tmp_path):
    from maverick.tools.request_decision import request_decision

    world = _world(tmp_path)
    gid = world.create_goal("flow step", "", owner="alice")
    token = dr.IN_FLOW_STEP.set(True)
    try:
        out = request_decision(world, gid).fn(_REQUEST)
    finally:
        dr.IN_FLOW_STEP.reset(token)
    assert out == dr.FLOW_REFUSAL and not dr.open_for_goal(world, gid)


def test_a_refused_audit_write_leaves_the_answer_unsaved_with_a_plain_503(tmp_path, monkeypatch):
    import maverick.audit as audit
    from maverick.audit.errors import AuditRefused

    world = _world(tmp_path)
    _gid, decision = _paused_goal(world)

    def refuse(kind, **_kw):
        raise AuditRefused("signed chain required")
    monkeypatch.setattr(audit, "record", refuse)
    with pytest.raises(dr.DecisionRefused) as refused:
        dr.answer(world, decision.id, 1, actor="alice", is_admin=False)
    assert refused.value.status_code == 503 and "audit log" in refused.value.message
    assert dr.get(world, decision.id).status == "open"


def test_an_unknown_admin_area_keeps_the_default(tmp_path, monkeypatch):
    from maverick import config

    (tmp_path / "home").mkdir(exist_ok=True)
    (tmp_path / "home" / "config.toml").write_text(
        '[approval]\ndecision_admin_areas = ["govrnance"]\n', encoding="utf-8")
    config.reset_config_cache()
    assert dr.admin_areas() == ["governance"]


def test_postgres_never_shows_a_no_workspace_decision_inside_a_named_workspace(postgres_test_dsn):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        legacy_goal = world.create_goal("legacy task", "", owner="alice")
        legacy = dr.request(world, legacy_goal, **dr.validate(_REQUEST))
        with tenant_scope(tenant="tenant-a"):
            assert dr.list_open(world) == [] and dr.get(world, legacy.id) is None
        assert [d.id for d in dr.list_open(world)] == [legacy.id]
