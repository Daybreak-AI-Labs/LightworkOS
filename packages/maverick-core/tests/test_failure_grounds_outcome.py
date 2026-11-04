"""A run that genuinely fails is real negative ground truth. When [consequence]
is on, the orchestrator's failure exit grounds a 0.0 outcome for the run's
episode -- the most common negative signal, previously invisible to learning.
Budget caps are excluded (a cap is not the agent's failure)."""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import consequence
from maverick.budget import Budget
from maverick.llm import LLMResponse
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    consequence.reset_shared()


@pytest.mark.asyncio
async def test_failed_run_grounds_negative_outcome(monkeypatch, tmp_path: Path, fake_llm):
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")
    _isolate(monkeypatch, tmp_path)
    # Empty response, no tools -> AgentResult(error=...) -> the failure exit.
    fake_llm.scripted = [
        LLMResponse(text="", thinking=None, stop_reason="end_turn", tool_calls=[]),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Summarize the quarterly report", "10-K filing")

    out = await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    assert "Stopped" in out
    eps = world.list_episodes(goal_id=gid, limit=1)
    assert eps, "the run should have an episode"
    assert consequence.resolve(gid, eps[0].id) == 0.0   # organic failure grounded


@pytest.mark.asyncio
async def test_failed_run_not_grounded_when_consequence_off(monkeypatch, tmp_path: Path, fake_llm):
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "0")
    _isolate(monkeypatch, tmp_path)
    fake_llm.scripted = [
        LLMResponse(text="", thinking=None, stop_reason="end_turn", tool_calls=[]),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("Summarize the quarterly report", "10-K filing")
    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
        sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )
    eps = world.list_episodes(goal_id=gid, limit=1)
    # Explicit opt-out keeps the kernel stateless: no grounded outcome.
    assert not eps or consequence.resolve(gid, eps[0].id) is None
