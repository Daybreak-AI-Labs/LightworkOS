"""Owner cancellation and certified pre-dispatch flow holds use real boundaries."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from maverick import config, world_model
from maverick.agent import Agent
from maverick.budget import Budget, BudgetExceeded
from maverick.flow import Flow, FlowNode, execution, store
from maverick.orchestrator import run_goal
from maverick.run_outcome import GoalAdmissionRefused, GoalCancelled, owned_task, task_stop
from maverick.sandbox import LocalBackend
from maverick.verifier import VerifierVerdict


@pytest.fixture
def stop_world(tmp_path, monkeypatch):
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "stop-world.db")
    policy = tmp_path / "stop-config.toml"
    policy.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(policy))
    monkeypatch.setenv("MAVERICK_SELF_LEARNING", "0")
    monkeypatch.setenv("MAVERICK_DURABLE", "0")
    config.reset_config_cache()
    world = world_model.open_world()
    yield world, policy
    world.close()
    config.reset_config_cache()


def _guard_agent(world, goal_id, budget):
    agent = object.__new__(Agent)
    agent.ctx = SimpleNamespace(world=world, goal_id=goal_id, budget=budget)
    agent._HALT_POLL_SECONDS = 0.005
    return agent


@pytest.mark.asyncio
@pytest.mark.parametrize("wall", [None, 30])
@pytest.mark.parametrize("phase", ["mid-generation", "mid-tool-execution"])
async def test_http_cancel_interrupts_owned_await(stop_world, monkeypatch, wall, phase):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from maverick_dashboard import api

    world, _ = stop_world
    gid = world.create_goal("cancel pending work", "")
    world.set_goal_status(gid, "active")
    agent = _guard_agent(world, gid, Budget(max_wall_seconds=wall))
    started, cleaned = asyncio.Event(), asyncio.Event()

    async def pending():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned.set()

    # Real HTTP serialization and the actual route handler; authentication
    # and learning are isolated because this case tests execution ownership.
    monkeypatch.setattr(api, "_world", lambda: world)
    monkeypatch.setattr(api, "require_permission", lambda *_: None)
    monkeypatch.setattr(api, "assert_goal_access", lambda *_: None)
    monkeypatch.setattr(api, "_ground_outcome", lambda *_a, **_k: None)
    app = FastAPI()
    app.add_api_route("/goals/{goal_id}/cancel", api.cancel_goal, methods=["POST"], status_code=204)
    task = owned_task(agent._await_wall_clock_guarded(pending, in_flight_note=phase))
    try:
        await asyncio.wait_for(started.wait(), 1)
        with TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            response = await asyncio.to_thread(client.post, f"/goals/{gid}/cancel")
        assert response.status_code == 204
        with pytest.raises(asyncio.CancelledError) as caught:
            await asyncio.wait_for(task, 1)
        stopped = task_stop(task, caught.value)  # the task's own stop, on 3.10 too
        assert isinstance(stopped, GoalCancelled)
        assert cleaned.is_set()
        assert world.get_goal(gid).status == "cancelled"
        assert bool(getattr(stopped, "tool_execution_unknown", False)) == (phase == "mid-tool-execution")
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_cancelled_goal_does_not_create_another_coroutine(stop_world):
    world, _ = stop_world
    gid = world.create_goal("already cancelled", "")
    world.set_goal_status(gid, "cancelled")
    agent = _guard_agent(world, gid, Budget())
    calls = []

    def make_work():
        calls.append(True)
        raise AssertionError("work must not start")

    with pytest.raises(GoalCancelled):
        await agent._await_wall_clock_guarded(make_work, in_flight_note="mid-generation")
    assert calls == []


@pytest.mark.asyncio
async def test_cancellation_retains_owned_task_until_its_cleanup_finishes(stop_world):
    world, _ = stop_world
    gid = world.create_goal("slow cancellation cleanup", "")
    agent = _guard_agent(world, gid, Budget())
    started, draining, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def pending():
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            draining.set()
            await release.wait()
            return "effect may already have committed"

    task = owned_task(agent._await_wall_clock_guarded(pending, in_flight_note="mid-tool-execution"))
    try:
        await asyncio.wait_for(started.wait(), 1)
        world.set_goal_status(gid, "cancelled")
        await asyncio.wait_for(draining.wait(), 1)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError) as caught:
            await asyncio.wait_for(task, 1)
        stopped = task_stop(task, caught.value)
        assert isinstance(stopped, GoalCancelled)
        assert stopped.tool_execution_unknown is True
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_budget_stop_keeps_the_owned_task_unknown_effect_marker(stop_world):
    # The guard owns its coroutine as a separate task. Python 3.10 re-raises a
    # cancelled task as a fresh CancelledError, so the marker must be recovered.
    world, _ = stop_world
    gid = world.create_goal("budget stop mid tool", "")
    agent = _guard_agent(world, gid, Budget(max_wall_seconds=0.05))

    async def pending():
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError as exc:
            exc.tool_execution_unknown = True
            raise

    with pytest.raises(BudgetExceeded) as stopped:
        await agent._await_wall_clock_guarded(pending, in_flight_note="mid-tool-execution")
    assert stopped.value.tool_execution_unknown is True


@pytest.mark.asyncio
async def test_owned_task_goal_cancellation_keeps_its_type_and_marker(stop_world):
    world, _ = stop_world
    gid = world.create_goal("nested owner stop", "")
    agent = _guard_agent(world, gid, Budget())

    async def nested():
        cancelled = GoalCancelled("stopped inside the owned call")
        cancelled.tool_execution_unknown = True
        raise cancelled

    with pytest.raises(GoalCancelled) as stopped:
        await agent._await_wall_clock_guarded(nested, in_flight_note="mid-generation")
    assert stopped.value.tool_execution_unknown is True


@pytest.mark.asyncio
async def test_goal_cancellation_retains_unknown_effect_in_durable_status(
    stop_world, monkeypatch, fake_llm, tmp_path,
):
    world, _ = stop_world
    gid = world.create_goal("cancel tool", "")
    started = asyncio.Event()

    async def brief(**_):
        return "offline brief", ""

    async def execute(self):
        self._HALT_POLL_SECONDS = 0.005

        async def pending():
            started.set()
            await asyncio.Event().wait()

        await self._await_wall_clock_guarded(pending, in_flight_note="mid-tool-execution")
        raise AssertionError("cancelled work cannot succeed")

    monkeypatch.setattr("maverick.orchestrator._build_orchestrator_brief", brief)
    monkeypatch.setattr("maverick.orchestrator.load_mcp_specs_from_config", list)
    monkeypatch.setattr(Agent, "_run_traced", execute)
    task = asyncio.create_task(run_goal(fake_llm, world, Budget(), gid,
                                        sandbox=LocalBackend(workdir=tmp_path)))
    try:
        await asyncio.wait_for(started.wait(), 5)
        world.set_goal_status(gid, "cancelled")
        result = await asyncio.wait_for(task, 2)
        goal = world.get_goal(gid)
        assert goal.status == "cancelled"
        assert "may have committed" in result and "may have committed" in goal.result
        episode, = world.list_episodes(goal_id=gid)
        assert episode.outcome == "interrupted" and episode.ended_at is not None
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


def _flow():
    return Flow(id="stop-boundary", name="Stop boundary", start="kept", nodes={
        "kept": FlowNode(id="kept", kind="action", tool="web_search", output="kept", next="agent"),
        "agent": FlowNode(id="agent", kind="agent", brief="Return a simple answer.", output="answer"),
    })


def test_real_flow_admission_retains_progress_and_resumes_after_policy_change(
    stop_world, monkeypatch, fake_llm, make_llm_response,
):
    world, policy = stop_world
    policy.write_text("[budget]\nmax_wall_seconds = 0.0\n", encoding="utf-8")
    config.reset_config_cache()
    constructed, effects = [], []

    def factory():
        constructed.append(True)
        return fake_llm

    async def brief(**_):
        return "Return a simple answer using FINAL.", ""

    async def verify(*_a, **_kw):
        return VerifierVerdict(confidence=1.0, accepts=True, critique="", issues=[])

    def action(*_):
        effects.append("performed once")
        return "kept result", 1.0

    monkeypatch.setattr("maverick.llm.LLM", factory)
    monkeypatch.setattr("maverick.orchestrator._build_orchestrator_brief", brief)
    monkeypatch.setattr("maverick.orchestrator.load_mcp_specs_from_config", list)
    monkeypatch.setattr("maverick.verifier.verify_final", verify)
    fake_llm.scripted.append(make_llm_response(text="FINAL: completed customer work"))
    flow = _flow()
    first = execution.execute(flow, agent_runner=execution.default_agent_runner(world), action_runner=action)
    assert first.status == "budget_limited" and first.cursor == "agent"
    assert first.continuation and first.data["kept"] == "kept result"
    assert constructed == [] and fake_llm.calls == []
    assert store.load_run(first.run_id).status == "budget_limited"
    assert "agent" not in first.nodes  # no guessed business-failure learning signal
    policy.write_text("[budget]\nmax_wall_seconds = 30.0\n", encoding="utf-8")
    config.reset_config_cache()
    second = execution.execute(flow, agent_runner=execution.default_agent_runner(world), action_runner=action,
                               resume_run_id=first.run_id, from_failure=True)
    assert second.status == "completed"
    assert "completed customer work" in second.data["answer"]
    assert effects == ["performed once"] and fake_llm.calls


def test_budget_stop_after_execution_begins_stays_indeterminate(stop_world, monkeypatch, fake_llm, tmp_path):
    world, _ = stop_world
    effect = tmp_path / "effect.txt"

    async def brief(**_):
        return "offline brief", ""

    async def execute(self):
        effect.write_text("one committed effect", encoding="utf-8")
        self.ctx.budget.max_wall_seconds = 0
        self.ctx.budget.check()

    monkeypatch.setattr("maverick.llm.LLM", lambda: fake_llm)
    monkeypatch.setattr("maverick.orchestrator._build_orchestrator_brief", brief)
    monkeypatch.setattr("maverick.orchestrator.load_mcp_specs_from_config", list)
    monkeypatch.setattr(Agent, "run", execute)
    first = execution.execute(_flow(), agent_runner=execution.default_agent_runner(world),
                              action_runner=lambda *_: ("kept", 1.0))
    assert effect.read_text(encoding="utf-8") == "one committed effect"
    assert first.cost_dollars == 0 and first.status == "indeterminate"
    assert first.continuation == {}
    with pytest.raises(execution.FlowNotResumable):
        execution.execute(_flow(), agent_runner=execution.default_agent_runner(world),
                          action_runner=lambda *_: ("kept", 1.0), resume_run_id=first.run_id, from_failure=True)


@pytest.mark.parametrize("result", ["blocked", GoalAdmissionRefused(999, stop_kind="budget", detail="blocked")])
def test_flow_does_not_trust_display_text_or_another_goals_stop(stop_world, monkeypatch, result):
    from maverick import runner

    world, _ = stop_world

    def dispatch(gid, **kwargs):
        world.set_goal_status(gid, "blocked", result="budget-looking display text")
        kwargs["usage_observer"](0)
        return result

    monkeypatch.setattr(runner, "run_goal_in_thread", dispatch)
    first = execution.execute(_flow(), agent_runner=execution.default_agent_runner(world),
                              action_runner=lambda *_: ("kept", 1.0))
    assert first.status == "indeterminate" and first.continuation == {}


@pytest.mark.parametrize("status", ["cancelled", "done"])
@pytest.mark.parametrize("race", [False, True])
def test_allowance_refusal_cannot_overwrite_terminal_goal(stop_world, monkeypatch, status, race):
    from maverick import runner

    world, _ = stop_world
    gid = world.create_goal("terminal admission race")
    budget = Budget(max_wall_seconds=0)

    def finish():
        world.set_goal_status(gid, status, result="authoritative terminal result")
        if status == "done":
            world.record_signoff(gid, "approved")

    if race:
        write = world.block_goal_admission

        def raced_write(*args, **kwargs):
            finish()
            return write(*args, **kwargs)

        monkeypatch.setattr(world, "block_goal_admission", raced_write)
    else:
        finish()
    result = runner._allowance_admission(world, gid, budget)
    assert result == status and not isinstance(result, GoalAdmissionRefused)
    assert world.get_goal(gid).result == "authoritative terminal result"
    assert bool(world.signoff_for(gid)) == (status == "done")


@pytest.mark.parametrize("status", ["pending", "active", "running", "blocked"])
def test_sqlite_admission_refusal_changes_only_eligible_goal(stop_world, status):
    world, _ = stop_world
    gid = world.create_goal("allowance admission")
    world.set_goal_status(gid, "done", result="old result")
    world.record_signoff(gid, "approved")
    # Simulate a legacy row whose stale sign-off survived its earlier transition.
    with world._writing() as conn:
        conn.execute("UPDATE goals SET status=? WHERE id=?", (status, gid))
    before = world.get_goal(gid)
    assert world.block_goal_admission(gid, result="allowance refused") is True
    after = world.get_goal(gid)
    assert after.status == "blocked" and after.result == "allowance refused"
    assert after.updated_at > before.updated_at
    assert world._read_one("SELECT completed_at FROM goals WHERE id=?", (gid,))["completed_at"] is None
    assert world.signoff_for(gid) is None
    assert world.block_goal_admission(gid + 1, result="missing") is False


def test_unreadable_handoff_record_stops_cleanly_like_a_real_hold(stop_world, monkeypatch):
    from maverick import human_conversation_handoffs
    from maverick.goal_mutations import GoalMutationConflict

    world, _ = stop_world
    gid = world.create_goal("poll the stop checks", "")
    world.set_goal_status(gid, "active")
    agent = _guard_agent(world, gid, Budget())

    def unreadable(*_a, **_k):
        raise PermissionError("invalid audit outbox")
    monkeypatch.setattr(human_conversation_handoffs, "require_ai_open", unreadable)
    # A hold that cannot be read may be a human's: the run stops through the
    # normal stop path (no exception out of the poll loop), as for a real hold.
    assert Agent._goal_cancelled(agent) is True

    def held(*_a, **_k):
        raise GoalMutationConflict("A human handoff holds this conversation.")
    monkeypatch.setattr(human_conversation_handoffs, "require_ai_open", held)
    world.set_goal_status(gid, "active")
    assert Agent._goal_cancelled(agent) is True


def test_the_cancel_check_reads_only_the_status(stop_world, monkeypatch):
    world, _ = stop_world
    gid = world.create_goal("poll the stop checks", "")
    world.set_goal_status(gid, "active")
    agent = _guard_agent(world, gid, Budget())
    monkeypatch.setattr(world, "get_goal", lambda *_a: pytest.fail("the whole goal was read"))
    assert Agent._goal_cancelled(agent) is False
    world.set_goal_status(gid, "cancelled")
    assert Agent._goal_cancelled(agent) is True
