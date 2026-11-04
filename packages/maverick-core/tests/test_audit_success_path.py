"""Success-path audit: a completed run records GOAL_START/GOAL_END (and tool
calls record TOOL_CALL/TOOL_RESULT) on the audit chain -- not just the denial
events. Regression guard for the "tamper-evident log only captured denials" gap.
"""
from __future__ import annotations

import pytest
from maverick.budget import Budget
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.world_model import WorldModel


@pytest.fixture
def _audit_home(monkeypatch, tmp_path):
    # Point the default audit log at a temp home and drop the cached singleton so
    # record() rebuilds it against tmp instead of the real ~/.maverick.
    monkeypatch.setattr("maverick.paths.maverick_home", lambda: tmp_path / "home")
    monkeypatch.setattr("maverick.audit.writer._default", None, raising=False)
    return tmp_path


@pytest.mark.asyncio
async def test_run_goal_emits_goal_start_and_end(
    _audit_home, tmp_path, fake_llm, make_llm_response,
):
    fake_llm.scripted = [
        make_llm_response(text="FINAL: the answer is 42"),
        make_llm_response(
            text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}',
        ),
        make_llm_response(text="FINAL: (no skill)"),
    ]
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal("compute the answer", "trivial")

    await run_goal(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1,
    )

    from maverick.audit.reader import iter_events

    events = [e for e in iter_events(all_days=True) if e.get("goal_id") == gid]
    kinds = {e["kind"] for e in events}
    assert "goal_start" in kinds
    assert "goal_end" in kinds
    end = next(e for e in events if e["kind"] == "goal_end")
    assert end["status"] == "succeeded"
