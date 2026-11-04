from __future__ import annotations

import asyncio

from maverick.agent import Agent
from maverick.blackboard import Blackboard
from maverick.budget import Budget
from maverick.domain import enabled_domains, suite_for
from maverick.sandbox import LocalBackend
from maverick.swarm import SwarmContext
from maverick.tools.spawn import list_specialists_tool, spawn_specialist_tool
from maverick.world_model import WorldModel


def _ctx(tmp_path, allowed_suites=frozenset({"finance"})):
    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    return SwarmContext(
        llm=None,
        world=world,
        budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(),
        sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id,
        max_depth=1,
        use_skills=False,
        allowed_suites=allowed_suites,
    )


def _domain_for_suite(suite: str) -> str:
    for name in sorted(enabled_domains()):
        if suite_for(name) == suite:
            return name
    raise AssertionError(f"no enabled domain for suite {suite!r}")


def test_list_specialists_honors_run_suite_grant(tmp_path):
    parent = Agent(ctx=_ctx(tmp_path), role="orchestrator", brief="g", depth=0)
    tool = list_specialists_tool(parent)

    listing = asyncio.run(tool.fn({}))

    assert "- finance:" in listing
    assert "- legal:" not in listing


def test_spawn_specialist_blocks_domain_outside_run_suite_grant(tmp_path):
    parent = Agent(ctx=_ctx(tmp_path), role="orchestrator", brief="g", depth=0)
    tool = spawn_specialist_tool(parent)
    legal_domain = _domain_for_suite("legal")

    result = asyncio.run(tool.fn({"domain": legal_domain, "task": "review contract"}))

    assert "outside your department grant" in result
    assert parent.ctx._spawns_used == 0
