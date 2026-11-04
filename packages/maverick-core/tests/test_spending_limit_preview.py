"""Preview a spending limit against the last 30 days before saving it."""
from __future__ import annotations

import calendar

import pytest
from maverick import spending_limits
from maverick.spending_limit_preview import preview
from maverick.spending_limits import SpendingLimitError
from maverick.world_model import WorldModel

DAY = 86400


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    return WorldModel(tmp_path / "world.db")


NOW = float(calendar.timegm((2026, 10, 20, 12, 0, 0)))  # midday UTC, mid-month


def _task(world, owner, cost, ended_at):
    gid = world.create_goal("Report", owner=owner)
    eid = world.start_episode(gid)
    world.end_episode(eid, "Done", "success", cost_dollars=cost)
    with world._writing() as conn:
        conn.execute("UPDATE episodes SET started_at = ?, ended_at = ? WHERE id = ?",
                     (ended_at - 60, ended_at, eid))


def test_history_query_reads_owner_end_and_cost_oldest_first(world):
    _task(world, "user:a", 2.0, NOW - 2 * DAY)
    _task(world, "user:b", 3.0, NOW - DAY)
    _task(world, "user:a", 9.0, NOW - 40 * DAY)  # outside the window
    assert world.episode_costs_since(NOW - 30 * DAY) == [
        ("user:a", NOW - 2 * DAY, 2.0), ("user:b", NOW - DAY, 3.0)]


def test_daily_limit_counts_tasks_and_people_that_would_have_stopped(world):
    for owner in ("user:a", "user:b"):
        _task(world, owner, 4.0, NOW - 3 * DAY)
        _task(world, owner, 4.0, NOW - 3 * DAY + 60)   # same day: $8 for each person
    _task(world, "user:c", 4.0, NOW - 2 * DAY)
    result = preview("default", "5", "day", world=world, now=NOW)
    assert (result["considered"], result["tasks"], result["people"]) == (5, 2, 2)
    # The workspace adds everyone up: $16 on one day, $4 on another.
    result = preview("workspace", "10", "day", world=world, now=NOW)
    assert (result["tasks"], result["people"]) == (2, 2)
    # A looser limit stops nothing.
    assert preview("workspace", "100", "month", world=world, now=NOW)["tasks"] == 0


def test_per_task_limit_and_one_person(world):
    _task(world, "user:a", 6.0, NOW - DAY)
    _task(world, "user:a", 1.0, NOW - DAY)
    _task(world, "user:b", 9.0, NOW - DAY)
    result = preview("person", "5", "task", principal="user:a", world=world, now=NOW)
    assert (result["considered"], result["tasks"], result["people"]) == (2, 1, 1)


def test_everyone_limit_skips_people_with_their_own_limit(world):
    spending_limits.set_user_limit("user:a", "100", "month", actor="user:admin")
    _task(world, "user:a", 50.0, NOW - DAY)
    _task(world, "user:b", 50.0, NOW - DAY)
    result = preview("default", "10", "month", world=world, now=NOW)
    assert (result["considered"], result["tasks"]) == (1, 1)


def test_preview_saves_and_enforces_nothing(world):
    _task(world, "user:a", 50.0, NOW - DAY)
    before = spending_limits.load()
    preview("workspace", "1", "day", world=world, now=NOW)
    assert spending_limits.load() == before
    assert not spending_limits._path().exists()


def test_preview_validates_like_saving(world):
    with pytest.raises(SpendingLimitError):
        preview("workspace", "0", "day", world=world, now=NOW)
    with pytest.raises(SpendingLimitError):
        preview("workspace", "5", "task", world=world, now=NOW)  # a workspace limit is per day or month
    with pytest.raises(ValueError):
        preview("everything", "5", "day", world=world, now=NOW)
