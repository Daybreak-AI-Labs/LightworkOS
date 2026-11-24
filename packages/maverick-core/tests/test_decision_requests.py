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


@pytest.mark.asyncio
async def test_an_answer_that_lands_before_the_pause_continues_the_run(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    import threading

    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")
    published, answered, outcomes, started = threading.Event(), threading.Event(), [], []

    def person():  # answers on its own thread once the decision is published
        published.wait(10)
        decision = dr.list_open(world)[0]
        outcomes.append(dr.answer(world, decision.id, 2, actor="alice", is_admin=False))
        answered.set()

    def announce(world, decision):  # the run is still active: it has not paused yet
        published.set()
        assert answered.wait(10)
    threading.Thread(target=person).start()
    monkeypatch.setattr(dr, "_announce", announce)
    monkeypatch.setattr(dr, "dispatch_resume", lambda world, goal_id: started.append(goal_id))
    fake_llm.scripted = [make_llm_response(text="A person must decide.", tool_calls=[
        ToolCall(id="t1", name="request_decision", input=_REQUEST)])]

    await _run(world, gid, fake_llm, tmp_path)

    assert outcomes[0]["resume"] is False                    # it answered a run still active
    assert world.get_goal(gid).status == "pending" and started == [gid]
    fake_llm.scripted = [make_llm_response(text=t) for t in _FINISH]
    await _run(world, gid, fake_llm, tmp_path)
    assert '"option": 2' in str(fake_llm.calls[1].get("messages", ""))
    assert world.get_goal(gid).status == "done"


@pytest.mark.asyncio
async def test_an_answer_while_the_run_still_holds_its_lease_continues_it_once(
        tmp_path, fake_llm, make_llm_response, monkeypatch):
    import threading

    from maverick import orchestrator

    world = _world(tmp_path)
    gid = world.create_goal("tidy the retention settings", "", owner="alice")
    answered, outcomes, started = threading.Event(), [], []
    settle = orchestrator._settle_decision_result

    def person():
        outcomes.append(dr.answer(world, dr.list_open(world)[0].id, 2, actor="alice",
                                  is_admin=False))
        answered.set()

    def settled(**kwargs):  # blocked, but the run has not released its lease yet
        out = settle(**kwargs)
        threading.Thread(target=person).start()
        assert answered.wait(10)
        return out
    monkeypatch.setattr(orchestrator, "_settle_decision_result", settled)
    monkeypatch.setattr(dr, "dispatch_resume", lambda world, goal_id: started.append(goal_id))
    fake_llm.scripted = [make_llm_response(text="A person must decide.", tool_calls=[
        ToolCall(id="t1", name="request_decision", input=_REQUEST)])]

    await _run(world, gid, fake_llm, tmp_path)

    assert outcomes[0]["resume"] is False and outcomes[0]["next"] == "finishing"
    assert "once it has stopped" in dr.next_text(outcomes[0])
    assert world.get_goal(gid).status == "pending" and started == [gid]   # started once
    assert dr.continue_answered(world, gid) is False and started == [gid]  # the claim is taken


def _left_pending(world, monkeypatch, *, age=3600.0):
    """A run its answer moved to pending, then the process stopped before the
    run started: its last change and its restart marker are ``age`` old."""
    monkeypatch.setattr("maverick.outcome_pilot_start_gate.require_work_item_admission",
                        lambda *a: None)
    gid, decision = _paused_goal(world)
    assert dr.answer(world, decision.id, 1, actor="alice", is_admin=False)["resume"] is True
    with world._writing() as conn:
        conn.execute("UPDATE goals SET updated_at = updated_at - ? WHERE id = ?", (age, gid))
        conn.execute("UPDATE decision_requests SET resume_dispatched_at = resume_dispatched_at - ? "
                     "WHERE goal_id = ?", (age, gid))
    return gid


def test_a_run_left_pending_after_its_answer_is_recovered_once(tmp_path, monkeypatch):
    from maverick import runner

    started = []
    monkeypatch.setattr(dr, "dispatch_resume", lambda world, goal_id: started.append(goal_id))
    world = _world(tmp_path)
    fresh = _left_pending(world, monkeypatch, age=0.0)
    assert dr.recover_all_stranded(world) == 0                  # its restart is recent
    world.set_goal_status(fresh, "done")
    gid = _left_pending(world, monkeypatch)
    with runner._submitted_here(gid):                           # still queued for a slot here
        assert dr.recover_all_stranded(world) == 0
    assert dr.recover_all_stranded(world) == 1 and started == [gid]
    assert world.get_goal(gid).status == "pending"
    assert dr.recover_all_stranded(world) == 0 and started == [gid]   # its new marker holds it


def test_resume_and_the_cli_take_back_a_run_left_pending_once(tmp_path, monkeypatch):
    import maverick.cli as cli
    from click.testing import CliRunner
    from maverick import goal_resume
    from maverick.chat_threads import ChatThreads
    from maverick.goal_mutations import GoalMutationConflict
    from maverick.world_model import open_world

    db = tmp_path / "world.db"
    world = open_world(db)
    gid = _left_pending(world, monkeypatch)
    updated = world.get_goal(gid).updated_at
    reserve = dict(actor="alice", expected_updated_at=updated, expected_owner="alice",
                   max_dollars=None, require_authority=lambda: None, require_admission=lambda: None)
    result = goal_resume.reserve(world, gid, operation_id="a" * 32, **reserve)
    assert result["admitted"] and world.get_goal(gid).status == "pending"
    with pytest.raises(GoalMutationConflict):                   # the same review never twice
        goal_resume.reserve(world, gid, operation_id="b" * 32, **reserve)
    with pytest.raises(Exception, match="already running"):     # its marker is now recent
        ChatThreads(world).resume(gid)
    world.set_goal_status(gid, "done")
    gid = _left_pending(world, monkeypatch)
    ChatThreads(world).resume(gid)
    assert world.get_goal(gid).status == "pending"
    world.set_goal_status(gid, "done")
    gid = _left_pending(world, monkeypatch)
    ran = []
    import contextlib

    monkeypatch.setattr(cli, "_require_llm_key", lambda: None)
    monkeypatch.setattr(cli, "_cli_sandbox", lambda k, backend=None: contextlib.nullcontext())
    monkeypatch.setattr(cli, "_kernel", lambda: type("K", (), {
        "LLM": lambda self, model=None: None,
        "run_goal_sync": lambda self, *a, **k: ran.append(a[3]) or "done"})())
    out = CliRunner().invoke(cli.main, ["--db", str(db), "resume", str(gid)])
    assert ran == [gid], out.output
    out = CliRunner().invoke(cli.main, ["--db", str(db), "resume", str(gid)])
    assert out.exit_code == 2 and "already starting again" in out.output and ran == [gid]


def test_start_up_recovers_a_workspace_run_left_pending(tmp_path, monkeypatch):
    from maverick.paths import _tenant_segment, tenant_scope

    started = []
    monkeypatch.setattr(dr, "dispatch_resume",
                        lambda world, goal_id: started.append((current(), goal_id)))
    from maverick.paths import current_tenant_id as current
    store = tmp_path / "home" / "tenants" / _tenant_segment("team-a") / "world.db"
    store.parent.mkdir(parents=True)
    with tenant_scope(tenant="team-a"), WorldModel(path=store) as team:
        gid = _left_pending(team, monkeypatch)
    assert dr.recover_everywhere(_world(tmp_path)) == 1 and started == [("team-a", gid)]


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
            # The owner filter runs in the query, before the limit.
            other = world.create_goal("someone else's run", "", owner="bob")
            world.set_goal_status(other, "blocked")
            dr.request(world, other, **dr.validate(_REQUEST))
            assert [d.id for d in dr.list_open(world, limit=1)] == [decision.id]
            assert [d.requested_by for d in dr.list_open(world, limit=1, requested_by="bob")] \
                == ["bob"]
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
async def test_a_choice_left_to_the_agent_neither_pauses_the_run_nor_skips_the_turn(
        tmp_path, fake_llm, make_llm_response):
    # Live: "which output format?" filed as area "other" got "yours to make",
    # yet the run was marked blocked with nothing for a person to answer, and
    # the page said "The run stopped before finishing. Try again."
    target = tmp_path / "written.txt"
    style = {**_REQUEST, "question": "PDF only, or PDF and Word?", "area": "other"}
    fake_llm.scripted = [
        make_llm_response(text="Writing and checking the format.", tool_calls=[
            ToolCall(id="w1", name="write_file", input={"path": str(target), "content": "acted"}),
            ToolCall(id="t1", name="request_decision", input=style)]),
        *[make_llm_response(text=t) for t in _FINISH],
    ]
    world = _world(tmp_path)
    gid = world.create_goal("make a printable checklist", "", owner="alice")

    await _run(world, gid, fake_llm, tmp_path)

    assert target.read_text() == "acted"
    assert world.get_goal(gid).status == "done" and dr.for_goal(world, gid) == []


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


@pytest.mark.parametrize("principal, origin, says", [
    ("key:nightly-report", None, "Only whoever started this run can start it again."),
    # A fleet agent a person started from the dashboard: not "another system".
    ("agent:fleet.reviewer", None, "Only whoever started this run can start it again."),
    ("federation:peer-1", "federation", "no person can restart it"),
    ("a2a", None, "no person can restart it"),
])
def test_a_run_bound_to_its_own_key_says_who_restarts_it(tmp_path, principal, origin, says):
    world = _world(tmp_path)
    gid = world.create_goal("tidy", "", owner="alice", execution_principal=principal)
    if origin:
        world.record_goal_origin(gid, origin, "peer-1")
    world.set_goal_status(gid, "blocked")
    decision = dr.request(world, gid, **dr.validate(_REQUEST))
    assert says in dr.restart_note(world.get_goal(gid), world)  # shown before anyone answers

    outcome = dr.answer(world, decision.id, 1, actor="alice", is_admin=False)

    assert outcome["resume"] is False and outcome["next"] == "manual"
    assert says in dr.next_text(outcome)
    goal = world.get_goal(gid)
    assert "Waiting for a person" not in goal.result
    assert "was saved" in goal.result and says in goal.result


def test_a_flow_step_that_needs_a_decision_stops_the_flow_on_its_error_route():
    from maverick.flow import Flow, FlowNode
    from maverick.flow.runner import STATUS_COMPLETED, STATUS_FAILED, run_flow

    calls = []

    def agent(node, brief, data):
        calls.append(node.id)
        if node.id == "a":
            raise dr.FlowDecisionNeeded("This step needs a person to decide: Keep logs?")
        return ("handled", 1.0)

    def flow(on_error):
        nodes = [FlowNode(id="a", kind="agent", brief="tidy", retries=3, next="c", on_error=on_error),
                 FlowNode(id="b", kind="agent", brief="report", output="reported"),
                 FlowNode(id="c", kind="agent", brief="go on", output="went_on")]
        return Flow(id="f", name="f", start="a", nodes={n.id: n for n in nodes})

    stopped = run_flow(flow(None), agent_fn=agent, action_fn=lambda *a: ("", None))
    assert stopped.status == STATUS_FAILED and stopped.cursor == "a" and calls == ["a"]
    assert "Keep logs?" in (stopped.error or "")
    calls.clear()
    routed = run_flow(flow("b"), agent_fn=agent, action_fn=lambda *a: ("", None))
    assert routed.status == STATUS_COMPLETED and calls == ["a", "b"] and "went_on" not in routed.data


def test_a_flow_steps_goal_that_asks_raises_instead_of_succeeding(tmp_path, monkeypatch):
    from maverick import runner
    from maverick.flow.execution import default_agent_runner
    from maverick.tools.request_decision import request_decision

    world = _world(tmp_path)

    def run_goal_in_thread(gid, **_kw):
        out = request_decision(world, gid).fn(_REQUEST)
        assert out == dr.FLOW_REFUSAL
        world.set_goal_status(gid, "done", result="FINAL: a person must choose")
        return "done"
    monkeypatch.setattr(runner, "run_goal_in_thread", run_goal_in_thread)

    with pytest.raises(dr.FlowDecisionNeeded) as needed:
        default_agent_runner(world, owner="alice")("tidy the logs", {})
    assert _REQUEST["question"] in str(needed.value)
    goals = [world.get_goal(i) for i in range(1, 3)]
    assert [g.status for g in goals if g] == ["failed"] and not dr.list_open(world)


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


def test_a_decision_closes_when_its_run_ends(tmp_path):
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)
    world.set_goal_status(gid, "cancelled")

    with pytest.raises(dr.DecisionRefused) as ended:
        dr.answer(world, decision.id, 1, actor="alice", is_admin=False)

    assert ended.value.reason == "ended" and "has ended" in ended.value.message
    assert dr.get(world, decision.id).status == "closed" and dr.list_open(world) == []
    assert world.get_goal(gid).status == "cancelled"


def test_the_sweep_reaches_a_workspace_missing_from_the_registry(tmp_path):
    from maverick.paths import maverick_home

    store = maverick_home() / "tenants" / "api%3Aalice" / "world.db"
    store.parent.mkdir(parents=True, mode=0o700)
    store.parent.parent.chmod(0o700)
    maverick_home().chmod(0o700)
    world = WorldModel(path=store)
    gid, decision = _paused_goal(world)

    assert dr.sweep_once(now=decision.expires_at + 1) >= 1
    assert dr.get(world, decision.id).status == "expired"
    assert world.get_goal(gid).status == "failed"


def test_postgres_sweep_expires_a_decision_in_an_unregistered_workspace(postgres_test_dsn,
                                                                       monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.world_model_backends.postgres import PostgresWorldModel

    monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
    with PostgresWorldModel(dsn=postgres_test_dsn) as world:
        with tenant_scope(tenant="api:alice"):
            gid = world.create_goal("per-user task", "", owner="alice")
            world.set_goal_status(gid, "blocked")
            decision = dr.request(world, gid, **dr.validate(_REQUEST))

        assert dr.sweep_once(now=decision.expires_at + 1) == 1

        with tenant_scope(tenant="api:alice"):
            assert dr.get(world, decision.id).status == "expired"
            assert world.get_goal(gid).status == "failed"


@pytest.mark.asyncio
async def test_best_of_n_reports_a_pause_instead_of_a_finished_patch(tmp_path, monkeypatch):
    from maverick.orchestrator import run_goal_best_of_n

    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    monkeypatch.setenv("MAVERICK_BON_LADDER", "model_a:0.3,model_b:0.7")
    world = _world(tmp_path)
    gid = world.create_goal("fix the bug", "", owner="alice")
    attempts = []

    async def paused_attempt(llm, world_, budget, goal_id, **kwargs):
        attempts.append(goal_id)
        dr.request(world_, goal_id, **dr.validate(_REQUEST))
        world_.set_goal_status(goal_id, "blocked", result="Waiting")
        return "Paused: Waiting for a person to decide\\n--- a/x.py\\n+++ b/x.py\\n@@ -1 +1 @@\\n-x\\n+y\\n"
    monkeypatch.setattr("maverick.orchestrator.run_goal", paused_attempt)

    out = await run_goal_best_of_n(llm=None, world=world, budget=Budget(max_dollars=4.0, max_wall_seconds=120.0),
                                   goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), n=2)

    assert out.startswith("Paused") and "DONE" not in out and attempts == [gid]
    assert world.get_goal(gid).status == "blocked"


def test_an_unreadable_decision_store_refuses_a_restart(tmp_path, monkeypatch):
    world = _world(tmp_path)
    gid = world.create_goal("tidy", "", owner="alice")

    def broken(*_a, **_kw):
        raise OSError("database unavailable")
    monkeypatch.setattr(dr, "open_for_tree", broken)

    assert "could not check" in dr.resume_refusal(world, gid)


def test_the_answer_says_when_a_restart_repeats_finished_steps(monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "0")
    assert "may run again" in dr.next_text({"next": "resumed"})
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    assert "may run again" not in dr.next_text({"next": "resumed"})


def _workspace_world(name):
    from maverick.paths import tenant_scope
    from maverick.world_model import open_world

    with tenant_scope(tenant=name):
        world = open_world()
        gid, decision = _paused_goal(world)
    return world, gid, decision


def test_the_sqlite_sweep_audits_each_expiry_in_its_own_workspace(tmp_path, monkeypatch):
    import maverick.audit as audit
    from maverick.paths import current_tenant_id

    world, _gid, decision = _workspace_world("ws1")
    written = []
    monkeypatch.setattr(audit, "record",
                        lambda kind, **kw: written.append((kind, current_tenant_id())) or True)

    dr.sweep_once(now=decision.expires_at + 1)

    assert ("decision_expired", "ws1") in written
    assert dr.get(world, decision.id).status == "expired"


def test_the_sqlite_sweep_visits_only_workspaces_with_open_decisions(tmp_path, monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.world_model import open_world

    world, _gid, decision = _workspace_world("ws1")
    with tenant_scope(tenant="ws2"):
        open_world().create_goal("nothing to decide", "")
    assert dr.indexed_workspaces() == ["ws1"]
    dr.sweep_once(now=decision.expires_at - 10)  # the catch-up scan of every workspace
    visited = []
    real = dr._sweep_one
    monkeypatch.setattr(dr, "_sweep_one",
                        lambda w, now: visited.append(Path(w.path).parent.name) or real(w, now))

    dr.sweep_once(now=decision.expires_at + 1)

    assert "ws2" not in visited and "ws1" in visited
    assert dr.indexed_workspaces() == []  # nothing left open in ws1


def test_postgres_sweep_under_forced_rls_reaches_known_workspaces(postgres_test_dsn, monkeypatch,
                                                                  caplog):
    import logging
    import secrets

    from maverick.paths import tenant_scope
    from maverick.tenant.registry import create_tenant
    from maverick.world_model_backends import postgres as pg
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    role, password = "mvk_dec_" + secrets.token_hex(6), secrets.token_hex(24)  # pragma: allowlist secret -- random throwaway role
    create_tenant("tenant-a")
    with PostgresWorldModel(dsn=postgres_test_dsn) as admin:
        decisions = {}
        for workspace in ("tenant-a", "slack:U1"):
            with tenant_scope(tenant=workspace):
                gid = admin.create_goal("waiting task", "", owner="alice")
                admin.set_goal_status(gid, "blocked")
                decisions[workspace] = dr.request(admin, gid, **dr.validate(_REQUEST))
        with admin._tx() as cur:
            cur.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(password)))
            cur.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
            cur.execute(sql.SQL("GRANT ALL ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(role)))
            cur.execute(sql.SQL("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(role)))
        admin._apply_rls()
        try:
            monkeypatch.setenv("MAVERICK_PG_RLS", "1")
            monkeypatch.setenv("MAVERICK_WORLD_BACKEND", "postgres")
            monkeypatch.setenv("MAVERICK_PG_DSN", make_conninfo(postgres_test_dsn, user=role, password=password))
            monkeypatch.setattr(pg, "_UNREBOUND_BACKENDS", set(), raising=False)
            due = max(d.expires_at for d in decisions.values()) + 1
            with caplog.at_level(logging.WARNING, logger="maverick.decision_requests"):
                assert dr.sweep_once(now=due) == 2
            assert "row-level security" in caplog.text
            for workspace, decision in decisions.items():
                with tenant_scope(tenant=workspace):
                    assert dr.get(admin, decision.id).status == "expired"
        finally:
            with admin._tx() as cur:
                cur.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
                cur.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


# -- goals below a code change's step (maverick.codebase.features) --

def _below_a_step(world, *, step_status: str) -> tuple[int, int]:
    """A never-run goal an agent made below a code change's step."""
    from maverick.codebase import features

    step = world.create_goal("[pricing] Discount", "", owner="alice")
    world.record_goal_origin(step, features.ORIGIN_KIND, "change-1")
    world.set_goal_status(step, step_status)
    return step, world.create_goal("look closer", "", parent_id=step, owner="alice")


def test_a_goal_below_a_running_step_whose_change_is_gone_never_starts(tmp_path):
    world = _world(tmp_path)
    _step, child = _below_a_step(world, step_status="active")
    assert dr.resume_refusal(world, child) == dr.FEATURE_RESTARTS


def test_a_goal_below_a_paused_step_never_starts_while_its_change_is_built(tmp_path):
    from maverick.codebase import features

    world = _world(tmp_path)
    paused, _ = _below_a_step(world, step_status="blocked")
    # A repair step below the paused one is running.
    repair = world.create_goal("[pricing] Repair", "", parent_id=paused, owner="alice")
    world.record_goal_origin(repair, features.ORIGIN_KIND, "change-1")
    world.set_goal_status(repair, "active")
    child = world.create_goal("look closer", "", parent_id=repair, owner="alice")
    assert dr.resume_refusal(world, child) == dr.FEATURE_RESTARTS


def test_an_early_answer_never_continues_a_code_change_step(tmp_path, monkeypatch):
    from maverick.codebase import features

    monkeypatch.setattr("maverick.outcome_pilot_start_gate.require_work_item_admission",
                        lambda *a: None)
    started = []
    monkeypatch.setattr(dr, "dispatch_resume", lambda world, goal_id: started.append(goal_id))
    world = _world(tmp_path)
    gid, decision = _paused_goal(world)
    world.record_goal_origin(gid, features.ORIGIN_KIND, "change-1")
    with world._writing() as conn:   # answered before the step paused
        conn.execute("UPDATE decision_requests SET status = 'answered', chosen = 1 WHERE id = ?",
                     (decision.id,))
    assert dr.continue_answered(world, gid) is False
    assert started == [] and world.get_goal(gid).status == "blocked"


def test_a_goal_below_a_live_step_starts_only_inside_its_code_change(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    world = _world(tmp_path)
    step, child = _below_a_step(world, step_status="active")
    token = dr.FEATURE_LOOP.set(frozenset({step}))
    try:
        assert dr.resume_refusal(world, child) == ""             # the change's own loop
    finally:
        dr.FEATURE_LOOP.reset(token)
    assert dr.resume_refusal(world, child) == dr.FEATURE_RESTARTS    # anywhere else
    monkeypatch.setattr("maverick.cli.open_world", lambda *a, **k: world, raising=False)
    out = CliRunner().invoke(main, ["resume", "--goal-id", str(child)])
    assert out.exit_code == 2 and "step of a code change" in out.output, out.output


def test_the_rules_leave_choices_about_the_deliverable_to_the_agent():
    # Seen live: asked for a 3,000-word history, the agent stopped to ask how
    # the history should be presented, reading "What people see" as the reader.
    from maverick import decision_requests

    assert decision_requests.AREAS["user_facing"] == "What people see in Lightwork, including the Copilot"
    text = decision_requests.rules_text()
    assert "What people see in Lightwork, including the Copilot" in text
    assert ("format, length, structure or wording of the work you deliver, about which tool or method to use "
            "and about whether to use files already in the workspace, are yours") in text


def test_a_resume_after_a_decision_keeps_the_limits_the_person_set(tmp_path, monkeypatch):
    # Seen live: a task started with a 1-minute limit was answered on its
    # decision card, and the resumed run went on for 3.5 minutes under the
    # workspace defaults instead.
    import threading

    from maverick import decision_requests as dr
    from maverick import runner
    from maverick.attachment_submissions import SubmissionStore

    world = WorldModel(tmp_path / "w.db")
    receipt = SubmissionStore(world).create(
        token="t1", fingerprint="a" * 64, owner="user:alice", title="History",
        description="Write it", manifest=[],
        submission_detail={"task_limits": {"max_dollars": 2.0, "max_wall_seconds": 60.0}})
    plain = SubmissionStore(world).create(
        token="t2", fingerprint="b" * 64, owner="user:alice", title="Other",
        description="No limits", manifest=[])
    started, done = [], threading.Event()

    def fake_run(goal_id, **kwargs):
        started.append((goal_id, kwargs))
        done.set()

    monkeypatch.setattr(runner, "run_goal_in_background", fake_run)
    for goal_id in (receipt["goal_id"], plain["goal_id"]):
        done.clear()
        assert dr.dispatch_resume(world, goal_id) is True
        assert done.wait(5)
    (first, limited), (second, unlimited) = started
    assert first == receipt["goal_id"] and second == plain["goal_id"]
    assert limited["max_dollars"] == 2.0 and limited["max_wall_seconds"] == 60.0
    assert "max_wall_seconds" not in unlimited and "max_dollars" not in unlimited
    world.close()


def test_an_option_label_does_not_repeat_the_recommended_marker():
    # Seen live: "Academic-style report (recommended) (recommended)" on the card.
    from maverick import decision_requests as dr

    checked = dr.validate({
        "question": "How should the history be presented?", "area": "other", "recommended": 1,
        "why": "It fits the request.",
        "options": [{"label": "Academic-style report (Recommended)", "effect": "Headings and endnotes."},
                    {"label": "Magazine-style narrative", "effect": "A flowing feature."}]})
    assert [o["label"] for o in checked["options"]] == ["Academic-style report", "Magazine-style narrative"]


def test_a_choice_outside_the_chosen_areas_is_the_agents_own(tmp_path):
    # Live: runs stopped to ask people to pick an invoice style ("Minimal",
    # "Standard", "Detailed"), whether to add a table file, and which tool to
    # convert with, each filed as area "other".
    from maverick.tools.request_decision import request_decision

    world = _world(tmp_path)
    gid = world.create_goal("make an invoice", "", owner="alice")
    style = {**_REQUEST, "question": "Which invoice style?", "area": "other",
             "options": [{"label": "Minimal", "effect": "Just the essentials."},
                         {"label": "Standard", "effect": "Adds payment terms."}], "recommended": 2}
    out = request_decision(world, gid).fn(style)
    assert "yours to make" in out and '"Standard" (Adds payment terms.)' in out and "does not wait" in out
    assert dr.for_goal(world, gid) == [] and dr.run_state(world, gid) is None
    # A chosen area still waits for a person.
    assert request_decision(world, gid).fn(_REQUEST).startswith("WAITING for decision")


def test_an_operator_can_make_runs_ask_about_every_choice(tmp_path, monkeypatch):
    from maverick import config
    from maverick.tools.request_decision import request_decision

    cfg = tmp_path / "config.toml"
    cfg.write_text("[approval]\nask_outside_areas = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    world = _world(tmp_path)
    gid = world.create_goal("make an invoice", "", owner="alice")
    out = request_decision(world, gid).fn({**_REQUEST, "area": "other"})
    assert out.startswith("WAITING for decision") and len(dr.for_goal(world, gid)) == 1


def test_the_rules_keep_a_plans_assumptions_with_the_agent():
    # Live: a business-plan task filed "which sales ramp should the budget
    # use?" under "Spending and budgets" and waited for a person.
    text = dr.rules_text()
    assert "Spending money or changing spending limits" in text
    assert "not the content of the work you deliver" in text and "budget, plan, forecast" in text
