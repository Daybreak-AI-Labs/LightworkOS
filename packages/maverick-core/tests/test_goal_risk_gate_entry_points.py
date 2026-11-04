"""The start-of-task risk hold must apply to the product's own entry
points, not only to ``run_goal(resume=False)`` from the terminal.

Every dashboard chat, REST, schedule, flow and queue-worker start goes through
``runner.run_goal_in_thread``, which always asks the orchestrator to ``resume``
(so a crashed run can pick its checkpoint back up). Reading that flag as "a
person already let this task through" would skip the gate for all of them, so
the gate trusts durable evidence instead: a task is "resumed" only when a run
of it is already on record.
"""
from __future__ import annotations

import threading
import time

import pytest

_RISKY = "Wire the vendor payment of $50,000 and delete the production database permanently"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in ("MAVERICK_GOAL_RISK_FLOOR", "MAVERICK_GOAL_RISK_REQUIRE_HUMAN",
                 "MAVERICK_CONSENT_MODE", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "false")
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "0.3")
    monkeypatch.setenv("MAVERICK_GOAL_RISK_REQUIRE_HUMAN", "medium")


def _script(make_llm_response):
    return [
        make_llm_response(text="FINAL: done"),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)"),
    ]


def _world(tmp_path):
    from maverick.world_model import WorldModel
    return WorldModel(path=tmp_path / "world.db")


def _start_like_the_dashboard(tmp_path, fake_llm, monkeypatch, goal_id):
    """What a dashboard/REST/worker start does: the shared thread runner."""
    from maverick import llm as llm_mod
    from maverick import runner
    from maverick import sandbox as sandbox_mod
    from maverick.sandbox import LocalBackend

    monkeypatch.setattr(llm_mod, "LLM", lambda: fake_llm)
    monkeypatch.setattr(sandbox_mod, "build_sandbox", lambda: LocalBackend(workdir=tmp_path))
    return runner.run_goal_in_thread(goal_id, max_depth=1)


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


def test_a_flagged_task_started_by_the_shared_runner_waits_for_a_person(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    fake_llm.scripted = _script(make_llm_response)
    world = _world(tmp_path)
    goal_id = world.create_goal(_RISKY, "")

    status = _start_like_the_dashboard(tmp_path, fake_llm, monkeypatch, goal_id)

    goal = _world(tmp_path).get_goal(goal_id)
    assert status == "blocked"
    assert goal.status == "blocked"
    assert "waits for a person to approve it" in (goal.result or "")
    assert fake_llm.calls == [], "the task started without anyone approving it"
    [approval] = _world(tmp_path).list_approvals()
    assert approval.action == "start_task"


def test_an_approval_lets_the_runner_start_the_task(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "5")
    fake_llm.scripted = _script(make_llm_response)
    goal_id = _world(tmp_path).create_goal(_RISKY, "")
    stop = threading.Event()
    thread = _decide_when_parked(tmp_path / "world.db", "approved", stop)
    try:
        status = _start_like_the_dashboard(tmp_path, fake_llm, monkeypatch, goal_id)
    finally:
        stop.set()
        thread.join(2)

    assert status == "done"
    [approval] = _world(tmp_path).list_approvals()
    assert approval.action == "start_task" and approval.status == "approved"


def test_a_task_that_already_ran_is_not_asked_about_again_on_resume(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    # A run of it is on record: a person (or the administrator's setting) let it
    # through once, so a crash-retry or an answered question just carries on.
    fake_llm.scripted = _script(make_llm_response)
    world = _world(tmp_path)
    goal_id = world.create_goal(_RISKY, "")
    world.start_episode(goal_id)

    status = _start_like_the_dashboard(tmp_path, fake_llm, monkeypatch, goal_id)

    assert status == "done"
    assert _world(tmp_path).list_approvals() == []


@pytest.mark.asyncio
async def test_resume_of_a_task_that_was_held_and_never_started_asks_again(
    tmp_path, fake_llm, make_llm_response, monkeypatch,
):
    # `maverick resume` on a task the gate refused must not be a way around it.
    from maverick.budget import Budget
    from maverick.orchestrator import run_goal
    from maverick.sandbox import LocalBackend

    fake_llm.scripted = _script(make_llm_response)
    world = _world(tmp_path)
    goal_id = world.create_goal(_RISKY, "")

    out = await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
                         goal_id=goal_id, sandbox=LocalBackend(workdir=tmp_path),
                         max_depth=1, resume=True)

    assert "waits for a person to approve it" in out
    assert fake_llm.calls == []
    assert world.get_goal(goal_id).status == "blocked"
