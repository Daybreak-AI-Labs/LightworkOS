"""Tests for sub-agent spawning (maverick.tools.spawn): the swarm fan-out cap
and sealed-child hook output.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.domain import enabled_domains
from maverick.quarantine import QuarantineRegistry
from maverick.tools.spawn import spawn_specialist_tool


def _fake_parent(depth=0):
    ctx = SimpleNamespace(
        budget=Budget(max_dollars=10.0), blackboard=Blackboard(), max_depth=3,
        goal_id=1, quarantine=None,
        try_reserve_spawns=lambda n: True, release_spawns=lambda n: None,
    )
    return SimpleNamespace(depth=depth, name="orchestrator", role="orchestrator",
                           ctx=ctx, max_steps=17, capability=None)


@pytest.mark.asyncio
async def test_sealed_mid_run_child_final_not_leaked_into_subagent_stop_hook(monkeypatch):
    # The leak path is a child sealed DURING run: the spawn-time check passes
    # (not yet sealed), the child runs and is compromised, then the post-run
    # check withholds it -- but the SUBAGENT_STOP hook fired in between with the
    # raw final. So the withhold check runs before the emit.
    dom = sorted(enabled_domains())[0]
    quarantine = QuarantineRegistry()
    parent = _fake_parent()
    parent.ctx.quarantine = quarantine

    def fake_agent_from_profile(profile, ctx, task, *, parent=None, depth=0, principal=None):
        name = f"agent:{profile.name}-{depth}"

        async def _run():
            quarantine.seal(name, "compromised mid-run")  # sealed AFTER spawn check
            return SimpleNamespace(final="SHOULD NOT LEAK", blocked_on_user=False, error=None)
        return SimpleNamespace(role=profile.name, name=name,
                               domain=profile.compartment, max_steps=None, run=_run)

    captured = {}

    async def _capture_hook(event, **kwargs):
        captured["final"] = (kwargs.get("extra") or {}).get("final")

    monkeypatch.setattr("maverick.domain.agent_from_profile", fake_agent_from_profile)
    monkeypatch.setattr("maverick.hooks.emit", _capture_hook)

    out = await spawn_specialist_tool(parent).fn({"domain": dom, "task": "do it"})
    assert "SHOULD NOT LEAK" not in out
    # The hook payload must NOT carry the sealed child's raw final either.
    assert captured.get("final") is not None
    assert "SHOULD NOT LEAK" not in captured["final"]
    assert "withheld" in captured["final"]


class TestSwarmFanoutCap:
    @pytest.mark.asyncio
    async def test_fanout_capped_at_max(self, tmp_path, monkeypatch):
        """A spawn_swarm with 50 agents gets trimmed to MAX_SWARM_FANOUT."""
        import maverick.tools.spawn as spawn_mod
        monkeypatch.setattr(spawn_mod, "MAX_SWARM_FANOUT", 3)

        from maverick.agent import Agent
        from maverick.blackboard import Blackboard
        from maverick.budget import Budget
        from maverick.sandbox import LocalBackend
        from maverick.swarm import SwarmContext
        from maverick.world_model import WorldModel

        class _FakeLLM:
            calls = 0

            async def complete_async(self, **_kw):
                self.calls += 1
                from maverick.llm import LLMResponse
                return LLMResponse(text="FINAL: done", thinking=None,
                                   tool_calls=[], stop_reason="end_turn")

        world = WorldModel(tmp_path / "w.db")
        gid = world.create_goal("fanout-test", "")
        ctx = SwarmContext(
            llm=_FakeLLM(), world=world, budget=Budget(),
            blackboard=Blackboard(),
            sandbox=LocalBackend(workdir=tmp_path),
            goal_id=gid, max_depth=2,
        )
        parent = Agent(ctx=ctx, role="orchestrator", brief="x", depth=0)
        tool = spawn_mod.spawn_swarm_tool(parent)

        # Request 10; only 3 should actually run.
        out = await tool.fn({
            "agents": [
                {"role": "researcher", "task": f"t{i}"} for i in range(10)
            ],
        })
        # The 3 children each return FINAL after one LLM call.
        assert ctx.llm.calls == 3
        # Blackboard should have an error post noting the cap fired.
        errs = ctx.blackboard.by_kind("error")
        assert any("fan-out capped" in e.content for e in errs)
        # The blackboard post alone isn't enough -- it's only ever
        # rendered into the orchestrator's FIRST user turn (agent.py's
        # `bb.render(40)`), so it never reaches the model again. The TOOL
        # RESULT itself (re-sent on every later turn) must say the same 7
        # requested agents never ran, or the caller synthesizes an answer
        # believing all 10 sub-tasks completed.
        assert "NOTE" in out
        assert "7 of 10" in out
        assert "t3" in out  # first dropped task's preview

    @pytest.mark.asyncio
    async def test_fanout_not_capped_has_no_drop_notice(self, tmp_path, monkeypatch):
        """When the request fits under the cap, no drop notice is added."""
        import maverick.tools.spawn as spawn_mod
        monkeypatch.setattr(spawn_mod, "MAX_SWARM_FANOUT", 3)

        from maverick.agent import Agent
        from maverick.blackboard import Blackboard
        from maverick.budget import Budget
        from maverick.sandbox import LocalBackend
        from maverick.swarm import SwarmContext
        from maverick.world_model import WorldModel

        class _FakeLLM:
            calls = 0

            async def complete_async(self, **_kw):
                self.calls += 1
                from maverick.llm import LLMResponse
                return LLMResponse(text="FINAL: done", thinking=None,
                                   tool_calls=[], stop_reason="end_turn")

        world = WorldModel(tmp_path / "w.db")
        gid = world.create_goal("fanout-test-2", "")
        ctx = SwarmContext(
            llm=_FakeLLM(), world=world, budget=Budget(),
            blackboard=Blackboard(),
            sandbox=LocalBackend(workdir=tmp_path),
            goal_id=gid, max_depth=2,
        )
        parent = Agent(ctx=ctx, role="orchestrator", brief="x", depth=0)
        tool = spawn_mod.spawn_swarm_tool(parent)

        out = await tool.fn({
            "agents": [
                {"role": "researcher", "task": f"t{i}"} for i in range(3)
            ],
        })
        assert ctx.llm.calls == 3
        assert "NOTE" not in out
        errs = ctx.blackboard.by_kind("error")
        assert not any("fan-out capped" in e.content for e in errs)


@pytest.mark.asyncio
async def test_sealed_swarm_child_final_not_leaked_into_subagent_stop_hook(tmp_path, monkeypatch):
    import maverick.tools.spawn as spawn_mod
    from maverick.agent import Agent
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    quarantine = QuarantineRegistry()

    async def _run(self):
        quarantine.seal(self.name, "compromised mid-run")
        return SimpleNamespace(final="SHOULD NOT LEAK", blocked_on_user=False, error=None)

    finals = []

    async def _capture_hook(event, **kwargs):
        finals.append((kwargs.get("extra") or {}).get("final"))

    monkeypatch.setattr(Agent, "run", _run)
    monkeypatch.setattr("maverick.hooks.emit", _capture_hook)
    world = WorldModel(tmp_path / "w.db")
    ctx = SwarmContext(llm=None, world=world, budget=Budget(), blackboard=Blackboard(),
                       sandbox=LocalBackend(workdir=tmp_path),
                       goal_id=world.create_goal("seal", ""), max_depth=2)
    ctx.quarantine = quarantine
    parent = Agent(ctx=ctx, role="orchestrator", brief="x", depth=0)
    out = await spawn_mod.spawn_swarm_tool(parent).fn(
        {"agents": [{"role": "researcher", "task": "t"}]})
    assert "SHOULD NOT LEAK" not in out
    assert finals and all("SHOULD NOT LEAK" not in f and "withheld" in f for f in finals)
