"""The audit goal-id ContextVar lets goal-less record() calls correlate to a run.

The agent kernel records tool/shield events with an explicit goal_id, but the
consent gate and per-action approval gate emit events from deeper in the stack
without one. The run loop binds a ContextVar so those still attribute to the run.
"""
from __future__ import annotations

import pytest
from maverick.audit import (
    EventKind,
    goal_context,
    iter_events,
    record,
    reset_goal_context,
    set_goal_context,
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick.audit import writer as audit_writer
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(audit_writer, "_default", None)
    audit_writer._defaults.clear()
    yield


def _events():
    return list(iter_events(all_days=True))


def test_record_without_goal_falls_back_to_context():
    with goal_context(42):
        record(EventKind.CONSENT_PROMPT, action="browser.click", risk="high")
    evs = [e for e in _events() if e.get("kind") == "consent_prompt"]
    assert evs and evs[0]["goal_id"] == 42


def test_explicit_goal_id_wins_over_context():
    with goal_context(42):
        record(EventKind.TOOL_CALL, goal_id=7, name="browser")
    evs = [e for e in _events() if e.get("kind") == "tool_call"]
    assert evs and evs[0]["goal_id"] == 7


def test_no_context_leaves_goal_none():
    record(EventKind.TOOL_CALL, name="browser")
    evs = [e for e in _events() if e.get("kind") == "tool_call"]
    assert evs and evs[0]["goal_id"] is None


def test_context_resets_after_block():
    token = set_goal_context(99)
    reset_goal_context(token)
    record(EventKind.HALT)
    evs = [e for e in _events() if e.get("kind") == "halt"]
    assert evs and evs[0]["goal_id"] is None


def test_run_goal_sync_binds_context(monkeypatch):
    # The orchestrator wrapper must bind the goal context around the run, so an
    # event recorded without goal_id inside run_goal attributes to the goal.
    import maverick.orchestrator as orch

    async def fake_run_goal(llm, world, budget, goal_id, **kw):
        record(EventKind.CONSENT_RESULT, action="x", decision="approve")
        return "done"

    monkeypatch.setattr(orch, "run_goal", fake_run_goal)
    assert orch.run_goal_sync(None, None, None, 123) == "done"
    evs = [e for e in _events() if e.get("kind") == "consent_result"]
    assert evs and evs[0]["goal_id"] == 123
