"""STOP signals must propagate, not be swallowed.

`BudgetExceeded` (budget cap) and `killswitch.Halted` (the killswitch) are
control-flow signals, not normal failures. Two fan-out sites must not fold
them into ordinary outcomes:

  - `spawn_swarm` gathers children with `return_exceptions=True` and folds each
    result into a tool-result string; a budget/halt must not become "ERROR:
    tool raised ...", which would let the parent keep spending.
  - best-of-N (`run_goal_best_of_n`) must not score a halted attempt zero and
    continue: a cap hit during attempt 0 must not spawn attempts 1..N.

Both re-raise these signals (matching agent.py's gather handler).
"""
from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_spawn_swarm_reraises_budget_exceeded(tmp_path, monkeypatch):
    import maverick.tools.spawn as spawn_mod
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget, BudgetExceeded
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    class _FakeLLM:
        async def complete_async(self, **_kw):
            from maverick.llm import LLMResponse
            return LLMResponse(text="FINAL: done", thinking=None,
                               tool_calls=[], stop_reason="end_turn")

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("stop-signal-test", "")
    ctx = SwarmContext(
        llm=_FakeLLM(), world=world, budget=Budget(),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=2,
    )
    parent = Agent(ctx=ctx, role="orchestrator", brief="x", depth=0)
    tool = spawn_mod.spawn_swarm_tool(parent)

    # A child whose work trips the budget cap: its run() raises BudgetExceeded.
    async def _boom(self):
        raise BudgetExceeded("cap hit in child")

    monkeypatch.setattr(Agent, "run", _boom)

    # The STOP signal must propagate out of the tool, not be folded into the
    # returned tool-result string.
    with pytest.raises(BudgetExceeded):
        await tool.fn({"agents": [{"role": "researcher", "task": "t"}]})


@pytest.mark.asyncio
async def test_spawn_swarm_reraises_halted(tmp_path, monkeypatch):
    import maverick.tools.spawn as spawn_mod
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.killswitch import Halted
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    class _FakeLLM:
        async def complete_async(self, **_kw):
            from maverick.llm import LLMResponse
            return LLMResponse(text="FINAL: done", thinking=None,
                               tool_calls=[], stop_reason="end_turn")

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("halt-test", "")
    ctx = SwarmContext(
        llm=_FakeLLM(), world=world, budget=Budget(),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=2,
    )
    parent = Agent(ctx=ctx, role="orchestrator", brief="x", depth=0)
    tool = spawn_mod.spawn_swarm_tool(parent)

    async def _halt(self):
        raise Halted("killswitch engaged", "test")

    monkeypatch.setattr(Agent, "run", _halt)

    with pytest.raises(Halted):
        await tool.fn({"agents": [{"role": "researcher", "task": "t"}]})


@pytest.mark.asyncio
async def test_best_of_n_reraises_budget_exceeded(tmp_path, monkeypatch):
    import maverick.orchestrator as orch
    from maverick.budget import Budget, BudgetExceeded
    from maverick.world_model import WorldModel

    # Force coding-mode best-of-N on so we exercise the candidate loop rather
    # than the n<=1 single-shot fallback.
    class _Cfg:
        enabled = True

    monkeypatch.setattr(orch, "model_for_role", lambda _role: "test-model")
    monkeypatch.setattr(
        "maverick.coding_mode.from_env", lambda: _Cfg(), raising=False,
    )

    # The first attempt trips the budget cap: run_goal raises BudgetExceeded.
    async def _run_goal_boom(*_a, **_kw):
        raise BudgetExceeded("cap hit during attempt 0")

    monkeypatch.setattr(orch, "run_goal", _run_goal_boom)

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("bon-test", "")

    # Must propagate the STOP signal instead of scoring the candidate zero and
    # spawning the remaining attempts.
    with pytest.raises(BudgetExceeded):
        await orch.run_goal_best_of_n(
            llm=None, world=world, budget=Budget(max_dollars=1.0),
            goal_id=gid, n=4,
        )
