"""The PRM selection path is wired into the agent loop: build_from_env()
chooses the backend, and steps are scored to the blackboard as kind="prm"
when a non-Null PRM is configured. NullPRM (the default) is a no-op."""
from pathlib import Path

import pytest
from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.world_model import WorldModel


@pytest.fixture
def ctx(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("test goal", "")
    return SwarmContext(
        llm=fake_llm,
        world=world,
        budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id,
        max_depth=2,
        use_skills=False,
    )


def test_default_prm_is_null_and_disabled(ctx, monkeypatch):
    monkeypatch.delenv("MAVERICK_PRM", raising=False)
    agent = Agent(ctx=ctx, role="researcher", brief="x")
    assert type(agent._prm).__name__ == "NullPRM"
    assert agent._prm_enabled is False


def test_heuristic_prm_selected_from_env(ctx, monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM", "heuristic")
    agent = Agent(ctx=ctx, role="researcher", brief="x")
    assert type(agent._prm).__name__ == "HeuristicPRM"
    assert agent._prm_enabled is True


def test_score_step_noop_when_null(ctx, monkeypatch):
    monkeypatch.delenv("MAVERICK_PRM", raising=False)
    agent = Agent(ctx=ctx, role="researcher", brief="x")
    agent._score_step(step_index=0, tool_name="shell", tool_succeeded=True)
    prm_posts = [e for e in ctx.blackboard.render(50).splitlines() if "prm" in e.lower()]
    assert prm_posts == []  # NullPRM emits nothing


def test_score_step_posts_for_heuristic(ctx, monkeypatch):
    monkeypatch.setenv("MAVERICK_PRM", "heuristic")
    agent = Agent(ctx=ctx, role="researcher", brief="x")
    agent._score_step(step_index=1, tool_name="shell", tool_succeeded=True)
    agent._score_step(step_index=2, is_final=True)
    rendered = ctx.blackboard.render(50)
    assert "promise=" in rendered
    assert "progress=" in rendered
    # is_final with no error -> strong positive promise (HeuristicPRM=1.0)
    assert "promise=1.00" in rendered


def test_score_step_never_raises(ctx, monkeypatch):
    """A broken PRM is observability noise, not a loop-killer."""
    monkeypatch.setenv("MAVERICK_PRM", "heuristic")
    agent = Agent(ctx=ctx, role="researcher", brief="x")

    class _Boom:
        def score(self, ctx):
            raise RuntimeError("prm down")
    agent._prm = _Boom()
    # Should swallow the error, not propagate.
    agent._score_step(step_index=0, tool_name="shell", tool_succeeded=True)
