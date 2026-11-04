"""Regression coverage for one authoritative run budget and terminal lifecycle."""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from maverick.agent import Agent, AgentResult
from maverick.blackboard import Blackboard
from maverick.budget import Budget, BudgetExceeded
from maverick.checkpoint import Checkpointer
from maverick.orchestrator import run_goal
from maverick.quotas import UsageLedger
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


@pytest.fixture
def run_state(tmp_path, fake_llm, monkeypatch):
    monkeypatch.setenv("MAVERICK_DURABLE", "1")
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    monkeypatch.setenv("MAVERICK_SELF_LEARNING", "0")
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("vendor assessment", "review evidence")
    budget = Budget(max_dollars=1.0)
    ctx = SwarmContext(
        llm=fake_llm, world=world, budget=budget, blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path), goal_id=gid, max_depth=1,
        use_skills=False,
    )
    return ctx


def test_resume_preserves_authoritative_budget_and_current_caps(run_state):
    ctx = run_state
    original = ctx.budget
    original._tenant_reservation_id = "current-reservation"
    original.record_tokens(10, 3, model="fake:test")
    original.max_tool_calls = 2
    previous = Budget(max_dollars=100, max_tool_calls=999)
    previous.record_tokens(100, 40, model="fake:test")
    Checkpointer(ctx.world).save(
        goal_id=ctx.goal_id, agent_id="researcher-0", step_seq=4,
        messages=[{"role": "user", "content": "prior evidence"}], budget=previous,
    )
    agent = Agent(ctx=ctx, role="researcher", brief="assess", depth=0)
    agent._resume_from_checkpoint([], ctx.blackboard, 0)
    assert ctx.budget is original
    assert original.max_dollars == 1.0
    assert original.max_tool_calls == 2
    assert original._tenant_reservation_id == "current-reservation"
    assert original.input_tokens == 110
    assert original.output_tokens == 43


def test_resume_over_current_limit_blocks_before_model(run_state):
    ctx = run_state
    previous = Budget(max_dollars=100)
    previous.dollars = 2
    Checkpointer(ctx.world).save(
        goal_id=ctx.goal_id, agent_id="researcher-0", step_seq=4,
        messages=[{"role": "user", "content": "prior evidence"}], budget=previous,
    )
    agent = Agent(ctx=ctx, role="researcher", brief="assess", depth=0)
    with pytest.raises(BudgetExceeded):
        agent._resume_from_checkpoint([], ctx.blackboard, 0)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_stage", ["agent", "brief", "hooks", "mcp"])
@pytest.mark.parametrize("cancel", [False, True])
async def test_exception_and_cancel_close_every_started_episode(
    run_state, monkeypatch, failure_stage, cancel,
):
    ctx = run_state
    error = asyncio.CancelledError if cancel else RuntimeError

    async def fail(*args, **kwargs):
        ctx.budget.record_tokens(120, 40, model="fake:test")
        raise error("interrupted")

    if failure_stage == "agent":
        monkeypatch.setattr(Agent, "run", fail)
    elif failure_stage == "brief":
        monkeypatch.setattr("maverick.orchestrator._build_orchestrator_brief", fail)
    elif failure_stage == "hooks":
        monkeypatch.setattr("maverick.hooks.ensure_loaded", fail)
    else:
        monkeypatch.setattr("maverick.orchestrator.load_mcp_specs_from_config", lambda: [object()])
        monkeypatch.setattr("maverick.orchestrator.start_mcp_clients", fail)
    with pytest.raises(error):
        await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    # An unexpected error marks the goal failed (2182ba8e); a cancel stays cancelled.
    assert ctx.world.get_goal(ctx.goal_id).status == ("cancelled" if cancel else "failed")
    episode, = ctx.world.list_episodes(goal_id=ctx.goal_id)
    assert episode.ended_at is not None
    assert episode.outcome == ("interrupted" if cancel else "failure")
    assert episode.cost_dollars == ctx.budget.dollars
    assert UsageLedger().usage("user:local")["in_tokens"] == 120


@pytest.mark.asyncio
async def test_final_refusal_closes_episode_without_persisting_rejected_text(run_state, monkeypatch):
    ctx = run_state
    shield = SimpleNamespace(
        scan_input=lambda text: SimpleNamespace(allowed=True),
        scan_output=lambda text: SimpleNamespace(allowed=False, reasons=["policy"]),
    )
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: shield)

    async def answer(self):
        self.ctx.budget.record_tokens(120, 40, model="fake:test")
        return AgentResult(role=self.role, name=self.name, final="withheld answer")

    monkeypatch.setattr(Agent, "run", answer)
    out = await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert "Output blocked by Shield" in out
    goal = ctx.world.get_goal(ctx.goal_id)
    assert goal.status == "blocked"
    assert "withheld answer" not in goal.result
    episode, = ctx.world.list_episodes(goal_id=ctx.goal_id)
    assert episode.ended_at is not None
    assert episode.outcome == "blocked"
    assert episode.input_tokens == 120


@pytest.mark.asyncio
async def test_paid_finalize_is_included_in_episode_and_quota(run_state, monkeypatch):
    ctx = run_state
    monkeypatch.setenv("MAVERICK_AUTO_DISTILL", "1")
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)

    async def answer(self):
        self.ctx.budget.record_tokens(120, 40, model="fake:test")
        return AgentResult(role=self.role, name=self.name, final="assessment ready")

    def distill(*args, budget, **kwargs):
        budget.record_tokens(50, 20, model="fake:test")
        return None

    monkeypatch.setattr(Agent, "run", answer)
    monkeypatch.setattr("maverick.orchestrator.distill", distill)
    await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    episode, = ctx.world.list_episodes(goal_id=ctx.goal_id)
    assert episode.input_tokens == 170
    assert episode.output_tokens == 60
    assert UsageLedger().usage("user:local")["in_tokens"] == 170


@pytest.mark.asyncio
async def test_private_goal_skips_opted_in_shared_skill_distillation(run_state, monkeypatch):
    from maverick import audit

    ctx = run_state
    ctx.goal_id = ctx.world.create_goal("private payroll plan", owner="user:alice")
    monkeypatch.setenv("MAVERICK_AUTO_DISTILL", "1")
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)

    async def answer(self):
        return AgentResult(role=self.role, name=self.name, final="assessment ready")

    def forbidden_distill(*args, **kwargs):
        pytest.fail("private goal must not reach the tenant-wide distiller")

    skipped = []
    original_audit = audit.audit_event

    def capture_audit(kind, **payload):
        if kind == audit.EventKind.SKILL_DISTILL_SKIPPED:
            skipped.append(payload)
        return original_audit(kind, **payload)

    monkeypatch.setattr(Agent, "run", answer)
    monkeypatch.setattr("maverick.orchestrator.distill", forbidden_distill)
    monkeypatch.setattr(audit, "audit_event", capture_audit)
    result = await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert "skill distill" not in result
    assert ctx.world.get_goal(ctx.goal_id).status == "done"
    assert skipped == [{"agent": "skill_distillation", "goal_id": ctx.goal_id,
                        "reason": "private_source"}]


@pytest.mark.asyncio
async def test_resume_counts_history_once_and_settles_only_new_usage(run_state, monkeypatch):
    ctx = run_state
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)
    attempts = 0
    seen_budgets = []

    async def execute(self):
        nonlocal attempts
        attempts += 1
        seen_budgets.append(self.ctx.budget)
        self._resume_from_checkpoint([], self.ctx.blackboard, self.ctx.episode_id)
        self.ctx.budget.record_tokens(120, 40, model="fake:test")
        if attempts == 1:
            Checkpointer(self.ctx.world).save(
                goal_id=self.ctx.goal_id, episode_id=self.ctx.episode_id,
                agent_id=self.checkpoint_id, step_seq=1,
                messages=[{"role": "user", "content": "reviewed evidence"}],
                budget=self.ctx.budget,
            )
            # Usage after the last committed message must survive too.
            self.ctx.budget.record_tokens(10, 5, model="fake:test")
            raise RuntimeError("provider interrupted")
        return AgentResult(role=self.role, name=self.name, final="assessment ready")

    monkeypatch.setattr(Agent, "run", execute)
    with pytest.raises(RuntimeError, match="provider interrupted"):
        await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert UsageLedger().usage("user:local")["in_tokens"] == 130
    resumed = Budget(max_dollars=2)
    resumed._tenant_reservation_id = "new-reservation"
    await run_goal(ctx.llm, ctx.world, resumed, ctx.goal_id, sandbox=ctx.sandbox, resume=True)
    assert seen_budgets == [ctx.budget, resumed]
    assert resumed.input_tokens == 250
    assert resumed.output_tokens == 85
    assert resumed._tenant_reservation_id == "new-reservation"
    assert UsageLedger().usage("user:local")["in_tokens"] == 250
    assert UsageLedger().usage("user:local")["out_tokens"] == 85
    episode, = ctx.world.list_episodes(goal_id=ctx.goal_id)
    assert episode.input_tokens == 250
    assert episode.outcome == "success"
    assert Checkpointer(ctx.world).latest_episode_id(ctx.goal_id, "orchestrator-0") is None


@pytest.mark.asyncio
async def test_lost_checkpoint_ack_does_not_charge_history_twice(run_state, monkeypatch):
    ctx = run_state
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)
    attempts = 0

    async def execute(self):
        nonlocal attempts
        attempts += 1
        self._resume_from_checkpoint([], self.ctx.blackboard, self.ctx.episode_id)
        self.ctx.budget.record_tokens(120, 40, model="fake:test")
        if attempts == 1:
            Checkpointer(self.ctx.world).save(
                goal_id=self.ctx.goal_id, episode_id=self.ctx.episode_id,
                agent_id=self.checkpoint_id, step_seq=1,
                messages=[{"role": "user", "content": "reviewed evidence"}],
                budget=self.ctx.budget,
            )
            self.ctx.budget.record_tokens(10, 5, model="fake:test")
            raise RuntimeError("provider interrupted")
        return AgentResult(role=self.role, name=self.name, final="assessment ready")

    def lose_ack(*args, **kwargs):
        raise OSError("process stopped after ledger commit")

    monkeypatch.setattr(Agent, "run", execute)
    original_ack = Checkpointer.record_settlement
    monkeypatch.setattr(Checkpointer, "record_settlement", lose_ack)
    with pytest.raises(RuntimeError, match="provider interrupted"):
        await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert UsageLedger().usage("user:local")["in_tokens"] == 130
    monkeypatch.setattr(Checkpointer, "record_settlement", original_ack)
    resumed = Budget(max_dollars=2)
    await run_goal(ctx.llm, ctx.world, resumed, ctx.goal_id, sandbox=ctx.sandbox, resume=True)
    assert resumed.input_tokens == 250
    assert UsageLedger().usage("user:local")["in_tokens"] == 250
    assert UsageLedger().usage("user:local")["out_tokens"] == 85


@pytest.mark.asyncio
async def test_spent_episode_without_checkpoint_requires_new_episode(run_state, monkeypatch):
    ctx = run_state
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)
    attempts = []

    async def execute(self):
        attempts.append(True)
        self.ctx.budget.record_tokens(120, 40, model="fake:test")
        if len(attempts) == 1:
            raise RuntimeError("interrupted before first checkpoint")
        return AgentResult(role=self.role, name=self.name, final="assessment ready")

    monkeypatch.setattr(Agent, "run", execute)
    with pytest.raises(RuntimeError, match="before first checkpoint"):
        await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    episode, = ctx.world.list_episodes(goal_id=ctx.goal_id)
    with pytest.raises(ValueError, match="no resumable checkpoint"):
        await run_goal(ctx.llm, ctx.world, Budget(max_dollars=2), ctx.goal_id,
                       sandbox=ctx.sandbox, resume_episode_id=episode.id)
    assert len(attempts) == 1
    assert UsageLedger().usage("user:local")["in_tokens"] == 120
    assert ctx.world.list_episodes(goal_id=ctx.goal_id)[0].input_tokens == 120
    await run_goal(ctx.llm, ctx.world, Budget(max_dollars=2), ctx.goal_id, sandbox=ctx.sandbox)
    assert len(attempts) == 2
    assert UsageLedger().usage("user:local")["in_tokens"] == 240


@pytest.mark.asyncio
@pytest.mark.parametrize("agent_key", ["orchestrator-0", "compliance-reviewer-0"])
async def test_resume_limit_checked_before_paid_brief(run_state, monkeypatch, agent_key):
    ctx = run_state
    episode_id = ctx.world.start_episode(ctx.goal_id)
    previous = Budget(max_dollars=100)
    previous.dollars = 2
    Checkpointer(ctx.world).save(
        goal_id=ctx.goal_id, episode_id=episode_id, agent_id=agent_key,
        step_seq=3, messages=[{"role": "user", "content": "prior"}], budget=previous,
    )
    calls = []

    async def brief(**kwargs):
        calls.append("paid brief")
        return "brief", ""

    monkeypatch.setattr("maverick.orchestrator._build_orchestrator_brief", brief)
    out = await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox, resume=True)
    assert "spending or time limit" in out
    assert not calls
    assert ctx.budget.dollars == 2
    assert ctx.budget.max_dollars == 1
    assert ctx.world.get_goal(ctx.goal_id).status == "blocked"


@pytest.mark.asyncio
async def test_resume_cannot_close_another_goals_episode(run_state):
    ctx = run_state
    other_goal = ctx.world.create_goal("other owner work", "")
    other_episode = ctx.world.start_episode(other_goal)
    with pytest.raises(ValueError, match="does not belong"):
        await run_goal(
            ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox,
            resume_episode_id=other_episode,
        )
    other, = ctx.world.list_episodes(goal_id=other_goal)
    assert other.ended_at is None


@pytest.mark.parametrize("field,value", [("dollars", float("nan")), ("tool_calls", -1), ("input_tokens", 1.5)])
def test_invalid_checkpoint_counters_do_not_mutate_live_budget(run_state, field, value):
    from maverick.checkpoint import restore_budget, snapshot_budget

    original = run_state.budget
    snapshot = snapshot_budget(Budget())
    snapshot[field] = value
    with pytest.raises(ValueError, match="invalid checkpoint"):
        restore_budget(snapshot, into=original)
    assert original.input_tokens == 0
    assert original.dollars == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("required", [True, False])
async def test_shield_unavailable_follows_current_policy(run_state, monkeypatch, required):
    ctx = run_state
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1" if required else "0")
    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: None)
    calls = []

    async def answer(self):
        calls.append("model")
        return AgentResult(role=self.role, name=self.name, final="assessment ready")

    monkeypatch.setattr(Agent, "run", answer)
    out = await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert ctx.world.get_goal(ctx.goal_id).status == ("blocked" if required else "done")
    assert bool(calls) is not required
    assert ("required safety shield unavailable" in out) is required


@pytest.mark.asyncio
@pytest.mark.parametrize("final", [True, False])
async def test_dashboard_cancellation_wins_over_returned_result(run_state, monkeypatch, final):
    ctx = run_state

    async def answer(self):
        self.ctx.world.set_goal_status(self.ctx.goal_id, "cancelled", result="cancelled by owner")
        return AgentResult(
            role=self.role, name=self.name,
            final="late answer" if final else None,
            error=None if final else "cancelled",
        )

    monkeypatch.setattr(Agent, "run", answer)
    out = await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert "cancelled" in out
    assert ctx.world.get_goal(ctx.goal_id).status == "cancelled"
    episode, = ctx.world.list_episodes(goal_id=ctx.goal_id)
    assert episode.outcome == "interrupted"


@pytest.mark.parametrize("corruption", ["json", "shape", "storage"])
def test_requested_checkpoint_cannot_become_a_fresh_run_on_read_error(run_state, monkeypatch, corruption):
    ctx = run_state
    cp = Checkpointer(ctx.world)
    cp.save(
        goal_id=ctx.goal_id, agent_id="researcher-0", step_seq=3,
        messages=[{"role": "user", "content": "prior"}], budget=Budget(),
    )
    if corruption == "storage":
        def unavailable(*args):
            raise OSError("storage disconnected")
        monkeypatch.setattr(ctx.world, "_read_one", unavailable)
    else:
        with ctx.world._writing() as conn:
            conn.execute(
                "UPDATE checkpoints SET messages = ?",
                ("{" if corruption == "json" else '"not messages"',),
            )
    agent = Agent(ctx=ctx, role="researcher", brief="assess", depth=0)
    with pytest.raises(ValueError, match="checkpoint"):
        agent._resume_from_checkpoint([], ctx.blackboard, 0)


def test_failed_quota_write_preserves_unsettled_checkpoint_usage(run_state, monkeypatch):
    from maverick.orchestrator import _QuotaUsageSettlement

    ctx = run_state
    cp = Checkpointer(ctx.world)
    cp.save(
        goal_id=ctx.goal_id, agent_id="orchestrator-0", step_seq=1,
        messages=[{"role": "user", "content": "prior"}], budget=ctx.budget,
    )
    ctx.budget.record_tokens(100, 50, model="fake:test")
    monkeypatch.setattr("maverick.quotas.record_usage", lambda *args, **kwargs: False)
    settlement = _QuotaUsageSettlement(principal="user:local", budget=ctx.budget, domain=None)
    settlement.world, settlement.episode_id = ctx.world, 0
    settlement.goal = ctx.world.get_goal(ctx.goal_id)
    settlement.record()
    saved = cp.latest(ctx.goal_id, "orchestrator-0")
    assert saved.budget["input_tokens"] == 100
    assert saved.budget.get("_settled", {}) == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("raised", [True, False])
async def test_required_final_scanner_failure_blocks_and_closes(run_state, monkeypatch, raised):
    ctx = run_state
    monkeypatch.setenv("MAVERICK_REQUIRE_SHIELD", "1")

    def scan(text):
        if raised:
            raise RuntimeError("scanner offline")
        return SimpleNamespace(allowed=True, scan_error=True)

    monkeypatch.setattr("maverick.orchestrator._build_shield", lambda: SimpleNamespace(
        scan_input=lambda text: SimpleNamespace(allowed=True), scan_output=scan,
    ))

    async def answer(self):
        return AgentResult(role=self.role, name=self.name, final="unverified text")

    monkeypatch.setattr(Agent, "run", answer)
    out = await run_goal(ctx.llm, ctx.world, ctx.budget, ctx.goal_id, sandbox=ctx.sandbox)
    assert "required safety scan unavailable" in out
    assert ctx.world.get_goal(ctx.goal_id).status == "blocked"
    assert ctx.world.list_episodes(goal_id=ctx.goal_id)[0].ended_at is not None
