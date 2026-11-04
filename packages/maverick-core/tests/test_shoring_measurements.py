"""Recorded completion and exact approval attribution against a real SQLite store."""
from __future__ import annotations

import pytest
from maverick import shoring, world_model
from maverick.logging_config import reset_goal_context, set_goal_context


@pytest.fixture
def world(tmp_path):
    with world_model.WorldModel(tmp_path / "work.db") as store:
        yield store


def _function():
    return shoring.Function("ap", "Accounts payable", department="finance_ap", slas=[
        shoring.SLATarget("Turnaround", "max_turnaround_hours", 2),
    ])


def test_completion_time_survives_edits_and_resets_for_reruns(world, monkeypatch):
    clock = [1_800_000_000.0]
    monkeypatch.setattr(world_model.time, "time", lambda: clock[0])
    goal = world.create_goal("Process invoice", domain="finance_ap")
    clock[0] += 3600
    world.set_goal_status(goal, "done", "Paid")
    clock[0] += 3600
    world.set_goal_status(goal, "done", "Paid; verified receipt")
    result = shoring.function_status(_function(), world, now=clock[0])
    assert result["max_turnaround_hours"] == 1
    assert result["slas"][0]["status"] == "met"
    world.set_goal_status(goal, "active")
    assert world.shoring_measurements("finance_ap", since=0, until=clock[0] + 1)["max_turnaround_hours"] is None
    clock[0] += 3 * 3600
    world.set_goal_status(goal, "done")
    result = shoring.function_status(_function(), world, now=clock[0] + 1)
    assert result["max_turnaround_hours"] == 5
    assert result["slas"][0]["status"] == "breached"


def test_measurements_include_all_goals_and_exclude_other_departments_and_windows(world):
    now = 1_800_000_000.0
    # Seed a large operating record in one transaction; no mock query layer.
    with world._writing() as connection:
        connection.executemany(
            "INSERT INTO goals(title, status, domain, created_at, updated_at, completed_at) "
            "VALUES('fixture', 'done', ?, ?, ?, ?)",
            [("finance_ap", now - 7200, now - 3600, now - 3600)] * 2101
            + [("support", now - 7200, now - 3600, now - 3600)] * 50
            + [("finance_ap", now - 300000, now - 200000, now - 200000)],
        )
    result = shoring.function_status(_function(), world, window_days=1, now=now)
    assert result["delivered"] == 2101
    assert result["measurement_complete"] and result["turnaround_measurement_complete"]
    assert result["max_turnaround_hours"] == 1


def test_legacy_completion_does_not_fabricate_turnaround(world, monkeypatch):
    now = 1_800_000_000.0
    with world._writing() as connection:
        goal = connection.execute(
            "INSERT INTO goals(title, status, domain, created_at, updated_at) "
            "VALUES('legacy', 'done', 'finance_ap', ?, ?)", (now - 1000, now),
        ).lastrowid
    monkeypatch.setattr(world_model.time, "time", lambda: now + 3600)
    world.set_goal_status(goal, "done", result="Corrected deliverable")
    result = shoring.function_status(_function(), world, now=now + 3601)
    assert result["delivered"] == 1
    assert result["legacy_completion_count"] == 1
    assert not result["turnaround_measurement_complete"]
    assert result["slas"][0]["status"] == "no_data"


def test_approval_department_comes_from_goal_context_not_free_text(world):
    goal = world.create_goal("Invoice", domain="finance_ap")
    tokens = set_goal_context(goal_id=goal)
    try:
        approval = world.create_approval("payment", scope="support", detail="marketing finance")
    finally:
        reset_goal_context(tokens)
    unassigned = world.create_approval("finance_ap", provenance="finance_ap", scope="finance_ap")
    record = world.get_approval(approval)
    assert record.department == "finance_ap" and record.goal_id == goal
    result = shoring.function_status(_function(), world)
    assert [row["id"] for row in result["exceptions"]] == [approval]
    assert result["unassigned_exception_count"] == 1
    assert world.get_approval(unassigned).department == ""
