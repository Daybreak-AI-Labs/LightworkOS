"""run_goal wiring for per-principal usage quotas (cost governance).

Proves the two integration points added to ``orchestrator.run_goal``:

  1. With quotas enforced and the principal already over its daily cap, the
     run is refused BEFORE the agent loop -- the goal is marked ``blocked`` and
     the LLM is never called (no spend on a principal that's out of budget).
  2. With quotas off (the default), the run proceeds normally and the finished
     run's spend is recorded to the principal's daily ledger.

Hermetic, mirroring tests/test_orchestrator.py (FakeLLM + tmp world db +
LocalBackend) and tests/test_quotas.py (real UsageLedger under the per-test
isolated ``~/.maverick``, env-driven enforcement). No network.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick.budget import Budget
from maverick.orchestrator import run_goal
from maverick.quotas import record_usage
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


@pytest.fixture(autouse=True)
def _clear_quota_env(monkeypatch):
    """Start each test with no quota config leaking in from the environment.

    These tests deliberately meter the synthetic ``fake:test`` model.  It has
    no vendor rate-card evidence, so opt this test-only gateway into the
    product's explicit estimate-only compatibility mode.  Production billing
    remains strict by default and is covered by the pricing-provider suite.
    """
    for env in (
        "MAVERICK_QUOTA_ENFORCE",
        "MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY",
        "MAVERICK_QUOTA_MAX_TOKENS_PER_DAY",
        "MAVERICK_TENANT",
    ):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")


def _final_script(make_llm_response):
    """The orchestrator FINAL turn, its verifier accept, and the distiller's
    terminal turn -- enough for a clean run_goal completion."""
    return [
        make_llm_response(text="FINAL: the answer is 42"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]


@pytest.mark.asyncio
async def test_over_quota_refuses_without_calling_llm(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    # Enforce a tiny daily dollar cap and pre-load this principal over it via
    # the real ledger, exactly as a prior run would have.
    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    monkeypatch.setenv("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY", "5")
    record_usage("user:local", 10.0, 0, 0)  # 10 >= 5 -> over quota

    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")
    budget = Budget(max_dollars=1.0)

    out = await run_goal(
        llm=fake_llm,
        world=world,
        budget=budget,
        goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    # The run was refused with the human-readable reason; the LLM never ran.
    assert "quota" in out
    assert fake_llm.calls == []
    goal = world.get_goal(gid)
    assert goal.status == "blocked"
    assert "quota" in (goal.result or "")
    # No episode work was spent on a refused run.
    assert world.list_episodes() == []


@pytest.mark.asyncio
async def test_over_quota_refusal_honours_user_id_principal(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    # The refusal keys on f"user:{user_id or 'local'}" -- a DIFFERENT user_id
    # whose principal is under cap must run, even when 'user:local' is over.
    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    monkeypatch.setenv("MAVERICK_QUOTA_MAX_DOLLARS_PER_DAY", "5")
    record_usage("user:alice", 10.0, 0, 0)  # alice is over

    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")

    out = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
        user_id="bob",  # bob -> "user:bob", under cap -> runs
    )

    assert "DONE." in out
    assert world.get_goal(gid).status == "done"
    assert len(fake_llm.calls) >= 1


@pytest.mark.asyncio
async def test_quotas_off_run_proceeds_and_records_usage(
    tmp_path: Path, fake_llm, make_llm_response, monkeypatch,
):
    # Default-off: nothing configured. Even a principal far over any imaginable
    # cap runs to completion, and the finished run's spend is recorded.
    record_usage("user:local", 1000.0, 0, 0)  # huge prior spend, but enforcement off

    # Spy on record_usage so the assertion holds regardless of FakeLLM's $0
    # cost: orchestrator does ``from . import quotas; quotas.record_usage(...)``,
    # so patch the function on the module it resolves.
    import maverick.quotas as q
    recorded: list[tuple] = []
    real_record_usage = q.record_usage
    monkeypatch.setattr(
        q, "record_usage",
        lambda *a, **k: (recorded.append((a, k)), real_record_usage(*a, **k))[1],
    )

    fake_llm.scripted = _final_script(make_llm_response)
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")
    budget = Budget(max_dollars=1.0)

    out = await run_goal(
        llm=fake_llm,
        world=world,
        budget=budget,
        goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "DONE." in out
    assert world.get_goal(gid).status == "done"
    # record_usage fired exactly once on completion, with this run's principal
    # and final budget totals.
    assert len(recorded) == 1
    (args, _kwargs) = recorded[0]
    assert args[0] == "user:local"
    assert args[1:] == (budget.dollars, budget.input_tokens, budget.output_tokens)


@pytest.mark.asyncio
async def test_budget_exceeded_run_records_usage_before_return(
    tmp_path: Path, fake_llm, monkeypatch,
):
    # BudgetExceeded can be raised after a provider response has already added
    # tokens/dollars to the Budget. That spend must advance the daily ledger so
    # a second run is refused by the quota gate instead of spending again.
    from maverick.agent import Agent
    from maverick.quotas import UsageLedger, over_quota

    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    monkeypatch.setenv("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY", "100")

    calls = 0

    async def spend_then_exceed(self):
        nonlocal calls
        calls += 1
        self.ctx.budget.record_tokens(200, 50, model="fake:test")

    monkeypatch.setattr(Agent, "run", spend_then_exceed)

    world = WorldModel(path=tmp_path / "world.db")
    gid1 = world.create_goal("exhaust budget", "trivial")
    out1 = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_input_tokens=100, max_dollars=1.0),
        goal_id=gid1,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "hit your spending or time limit" in out1
    assert world.get_goal(gid1).status == "blocked"
    usage = UsageLedger().usage("user:local")
    assert usage["in_tokens"] == 200
    assert usage["out_tokens"] == 50
    assert over_quota("user:local") is not None

    gid2 = world.create_goal("try again", "trivial")
    out2 = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid2,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "quota" in out2
    assert world.get_goal(gid2).status == "blocked"
    assert calls == 1


@pytest.mark.asyncio
async def test_agent_error_run_records_usage_before_return(
    tmp_path: Path, fake_llm, monkeypatch,
):
    # Agent errors/max-steps can occur after paid LLM activity. Charge that
    # spend before returning the friendly error so the next run sees the cap.
    from maverick.agent import Agent, AgentResult
    from maverick.quotas import UsageLedger, over_quota

    monkeypatch.setenv("MAVERICK_QUOTA_ENFORCE", "1")
    monkeypatch.setenv("MAVERICK_QUOTA_MAX_TOKENS_PER_DAY", "100")

    calls = 0

    async def spend_then_error(self):
        nonlocal calls
        calls += 1
        self.ctx.budget.record_tokens(60, 50, model="fake:test")
        return AgentResult(error="max_steps exceeded", role=self.role, name=self.name)

    monkeypatch.setattr(Agent, "run", spend_then_error)

    world = WorldModel(path=tmp_path / "world.db")
    gid1 = world.create_goal("fail after spend", "trivial")
    out1 = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid1,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "couldn't finish" in out1
    assert world.get_goal(gid1).status == "blocked"
    usage = UsageLedger().usage("user:local")
    assert usage["in_tokens"] == 60
    assert usage["out_tokens"] == 50
    assert over_quota("user:local") is not None

    gid2 = world.create_goal("try again", "trivial")
    out2 = await run_goal(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        goal_id=gid2,
        sandbox=LocalBackend(workdir=tmp_path),
        max_depth=1,
    )

    assert "quota" in out2
    assert world.get_goal(gid2).status == "blocked"
    assert calls == 1
