"""An agent proposes a schedule; a person reviews and creates it."""
from __future__ import annotations

import pytest
from maverick import schedule_proposals as sp
from maverick.budget import Budget
from maverick.llm import ToolCall
from maverick.orchestrator import run_goal
from maverick.sandbox import LocalBackend
from maverick.tools.propose_schedule import propose_schedule
from maverick.world_model import WorldModel

_ASK = {"text": "Review overdue invoices and draft reminder emails.", "cron": "0 9 * * 1",
        "title": "Monday invoice review"}


def test_a_proposal_is_checked_recorded_and_described(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("remind me every Monday", "")
    out = propose_schedule(world, gid).fn(_ASK)
    assert out.startswith("PROPOSED: 'Monday invoice review', every Monday at 09:00 (UTC).")
    assert "Nothing runs yet" in out
    assert sp.for_goal(world, gid) == [{**_ASK, "zone": ""}]
    propose_schedule(world, gid).fn(_ASK)  # the same proposal twice is listed once
    assert len(sp.for_goal(world, gid)) == 1
    assert sp.for_goal(world, world.create_goal("other", "")) == []


@pytest.mark.parametrize("args, says", [
    ({"text": "", "cron": "0 9 * * 1"}, "'text'"),
    ({"text": "x", "cron": "every monday"}, "five-part timetable"),
    ({"text": "x", "cron": "0 9 * * 1", "zone": "Mars/Olympus"}, "time zone"),
])
def test_a_bad_proposal_says_what_to_fix_and_records_nothing(tmp_path, args, says):
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("g", "")
    out = propose_schedule(world, gid).fn(args)
    assert out.startswith("ERROR") and says in out and sp.for_goal(world, gid) == []
    assert propose_schedule(world, None).fn(_ASK).startswith("ERROR")


def test_timetables_are_described_in_plain_words():
    assert sp.describe("30 7 * * *", "America/Chicago") == "every day at 07:30 (America/Chicago)"
    assert sp.describe("0 9 * * 1-5") == "every weekday at 09:00 (UTC)"
    assert sp.describe("0 9 * * 1,3") == "every Monday, Wednesday at 09:00 (UTC)"
    assert sp.describe("0 8 1 * *") == "on day 1 of every month at 08:00 (UTC)"
    assert sp.describe("*/15 * * * *") == "on the timetable */15 * * * * (UTC)"


@pytest.mark.asyncio
async def test_a_run_asked_for_recurring_work_proposes_it_and_finishes(tmp_path, fake_llm, make_llm_response):
    # Live: "Every Monday at 9am, remind me to review overdue invoices" ended
    # "blocked on user input": the agent had no way to set up recurring work.
    fake_llm.scripted = [
        make_llm_response(text="Proposing it.", tool_calls=[ToolCall(id="p1", name="propose_schedule", input=_ASK)]),
        make_llm_response(text="FINAL: I proposed a schedule every Monday at 09:00 (UTC); review and create it "
                               "from this task."),
        make_llm_response(text='{"confidence": 0.95, "accepts": true, "critique": "ok", "issues": []}'),
        make_llm_response(text="FINAL: (no skill)")]
    world = WorldModel(tmp_path / "world.db")
    gid = world.create_goal("Every Monday at 9am, remind me to review overdue invoices", "", owner="alice")

    await run_goal(llm=fake_llm, world=world, budget=Budget(max_dollars=1.0), goal_id=gid,
                   sandbox=LocalBackend(workdir=tmp_path), max_depth=1)

    assert world.get_goal(gid).status == "done"
    assert sp.for_goal(world, gid)[0]["cron"] == "0 9 * * 1"


def test_a_scheduled_run_does_its_work_instead_of_proposing_another_schedule(tmp_path):
    # Live: the proposal's work read "Every Monday at 9am, remind me ...", so
    # each Monday run would have proposed the schedule again.
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("Every Monday at 9am, review overdue invoices", "")
    world.record_goal_origin(gid, "schedule", "abc123")
    out = propose_schedule(world, gid).fn(_ASK)
    assert out.startswith("ERROR") and "already a run of a schedule" in out and sp.for_goal(world, gid) == []
    assert "not the timetable" in propose_schedule(world, gid).description


def test_with_schedules_turned_off_the_agent_is_told_to_say_so(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "get_features", lambda: {"scheduling": False})
    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("every Monday", "")
    out = propose_schedule(world, gid).fn(_ASK)
    assert out.startswith("ERROR") and "Settings" in out and sp.for_goal(world, gid) == []
