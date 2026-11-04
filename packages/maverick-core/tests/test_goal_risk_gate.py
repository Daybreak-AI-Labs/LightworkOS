"""The goal-risk check at task start: off by default, and when an
administrator turns it on, a person decides before a flagged task starts."""
from __future__ import annotations

import threading
import time

import pytest
from maverick.budget import Budget


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    # The approval queue is the default world, as the dashboard reads it.
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_GOAL_RISK_FLOOR", "MAVERICK_GOAL_RISK_REQUIRE_HUMAN",
                 "MAVERICK_CONSENT_MODE", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "5")


def _script(make_llm_response):
    return [
        make_llm_response(text="FINAL: done"),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)"),
    ]


async def _run(tmp_path, fake_llm, title):
    from maverick.orchestrator import run_goal
    from maverick.sandbox import LocalBackend
    from maverick.world_model import WorldModel
    world = WorldModel(path=tmp_path / "world.db")
    gid = world.create_goal(title, "")
    out = await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
                         goal_id=gid, sandbox=LocalBackend(workdir=tmp_path), max_depth=1)
    return out, world, gid


def _audit(monkeypatch):
    import maverick.audit as audit
    rows = []
    real = audit.audit_event

    def capture(kind, **kw):
        rows.append((str(kind), kw))
        return real(kind, **kw)

    monkeypatch.setattr(audit, "audit_event", capture)
    return rows


def _decide_when_parked(world_path, status, stop):
    """Act as the person on the Approvals page."""
    from maverick.world_model import WorldModel

    def watch():
        world = WorldModel(path=world_path)
        while not stop.is_set():
            pending = world.pending_approvals()
            if pending:
                world.decide_approval(pending[0].id, status, decided_by="user:approver")
                return
            time.sleep(0.05)

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return thread


@pytest.mark.asyncio
async def test_off_by_default_a_high_risk_task_runs_and_its_tier_is_recorded(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    rows = _audit(monkeypatch)
    fake_llm.scripted = _script(make_llm_response)
    out, world, gid = await _run(tmp_path, fake_llm, "Deploy the new pricing page to production")
    assert world.get_goal(gid).status == "done"
    assert world.list_approvals() == []
    start = [kw for kind, kw in rows if kind.endswith("goal_start")]
    assert start and start[0]["risk_tier"] == "high"
    assert start[0]["risk_signals"] == ["infra_destruction", "irreversible"]


@pytest.mark.parametrize("vote,started", [("approved", True), ("denied", False)])
@pytest.mark.asyncio
async def test_when_turned_on_a_person_decides_before_a_flagged_task_starts(
    tmp_path, fake_llm, make_llm_response, monkeypatch, vote, started,
):
    monkeypatch.setenv("MAVERICK_GOAL_RISK_REQUIRE_HUMAN", "high")
    stop = threading.Event()
    thread = _decide_when_parked(tmp_path / "world.db", vote, stop)
    fake_llm.scripted = _script(make_llm_response)
    try:
        out, world, gid = await _run(tmp_path, fake_llm, "Deploy the new pricing page to production")
    finally:
        stop.set()
        thread.join(2)
    approvals = world.list_approvals()
    assert len(approvals) == 1 and approvals[0].action == "start_task"
    goal = world.get_goal(gid)
    if started:
        assert goal.status == "done"
    else:
        assert goal.status == "blocked" and fake_llm.calls == []
        assert out.startswith("A person decided not to start this task")


@pytest.mark.asyncio
async def test_no_decision_in_time_means_no_start_and_the_request_is_withdrawn(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_GOAL_RISK_REQUIRE_HUMAN", "high")
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "0.3")
    fake_llm.scripted = _script(make_llm_response)
    out, world, gid = await _run(tmp_path, fake_llm, "Rotate the API keys in production")
    assert world.get_goal(gid).status == "blocked" and fake_llm.calls == []
    assert "No one approved it in time" in out and "handles passwords or keys" in out
    # The deployment's automatic consent mode never answers for a person.
    [approval] = world.list_approvals()
    assert approval.status == "denied" and approval.decided_by == "system:no-decision"
    assert world.pending_approvals() == []


@pytest.mark.asyncio
async def test_a_low_risk_task_never_waits(tmp_path, fake_llm, make_llm_response, monkeypatch):
    monkeypatch.setenv("MAVERICK_GOAL_RISK_REQUIRE_HUMAN", "high")
    fake_llm.scripted = _script(make_llm_response)
    out, world, gid = await _run(tmp_path, fake_llm, "Summarize last week's standup notes")
    assert world.get_goal(gid).status == "done" and world.list_approvals() == []
