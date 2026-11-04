"""A halted Lightwork must refuse new goals with a clear message + the right
next step (`maverick unhalt`), not create a goal and trip the killswitch
mid-run (which produced a confusing generic 'ran into an error' with bad
'resume' advice -- resuming while halted just halts again).
"""
from __future__ import annotations

from pathlib import Path

import pytest
from maverick import killswitch
from maverick.budget import Budget
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


@pytest.mark.asyncio
async def test_run_goal_refuses_upfront_when_halted(tmp_path: Path, fake_llm):
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("blocked by halt", "")

    killswitch.halt("test halt")
    try:
        out = await run_goal(
            fake_llm, world, Budget(max_dollars=1.0), gid,
            sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
        )
    finally:
        killswitch.clear()

    assert "halted" in out.lower()
    assert "maverick unhalt" in out
    assert "ran into an error" not in out
    assert world.get_goal(gid).status == "blocked"
    # Refused before the agent ran -- the LLM was never called.
    assert fake_llm.calls == []
