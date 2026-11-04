"""Typical cost before starting a task: recorded history, never a prediction."""
from __future__ import annotations

import pytest
from maverick import config, typical_cost
from maverick.world_model import WorldModel


@pytest.fixture
def world(tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    config.reset_config_cache()
    yield WorldModel(tmp_path / "world.db")
    config.reset_config_cache()


def _task(world, cost, *, domain="", principal="", runs=1):
    gid = world.create_goal("Report", owner="user:a", execution_principal=principal)
    if domain:
        world.set_goal_domain(gid, domain)
    for _ in range(runs):
        eid = world.start_episode(gid)
        world.end_episode(eid, "Done", "success", cost_dollars=cost / runs)
    return gid


def test_history_is_per_specialist_and_sums_each_tasks_runs(world):
    _task(world, 1.0, domain="finance_close", runs=2)
    _task(world, 3.0, domain="finance_close")
    _task(world, 50.0, domain="hr_onboarding")
    world.start_episode(world.create_goal("Running", owner="user:a"))  # unfinished
    assert sorted(world.task_costs_for(domain="finance_close")) == pytest.approx([1.0, 3.0])
    assert world.task_costs_for(domain="") == []


def test_history_for_an_agent_uses_its_principal(world):
    _task(world, 2.0, principal="agent:team.writer")
    _task(world, 9.0, principal="agent:team.other")
    assert world.task_costs_for(execution_principal="agent:team.writer") == [2.0]


def test_a_range_needs_the_minimum_number_of_runs(world):
    for cost in (0.2, 0.4, 0.6, 0.8, 1.0):
        _task(world, cost, domain="finance_close")
    few = typical_cost.typical_cost(world, specialist="finance_close", minimum=6)
    assert few["enough"] is False and few["runs"] == 5 and few["median"] is None
    enough = typical_cost.typical_cost(world, specialist="finance_close", minimum=5)
    assert enough["enough"] is True
    assert enough["low"] == pytest.approx(0.4)
    assert enough["median"] == pytest.approx(0.6)
    assert enough["high"] == pytest.approx(0.8)


def test_the_minimum_defaults_to_ten_and_follows_the_setting(world, tmp_path):
    assert typical_cost.min_runs() == 10
    (tmp_path / "config.toml").write_text("[spending_limits]\ntypical_cost_min_runs = 25\n")
    config.reset_config_cache()
    assert typical_cost.min_runs() == 25
    (tmp_path / "config.toml").write_text("[spending_limits]\ntypical_cost_min_runs = 1\n")
    config.reset_config_cache()
    assert typical_cost.min_runs() == 10  # out of range keeps the default


@pytest.mark.parametrize("value", [1, 1001, "lots", True, 2.5, None])
def test_bad_minimums_are_refused(value):
    with pytest.raises(ValueError):
        typical_cost.validate_min_runs(value)


def test_an_unreadable_store_gives_no_range():
    class Broken:
        def task_costs_for(self, **_):
            raise RuntimeError("down")

    result = typical_cost.typical_cost(Broken(), specialist="x", minimum=2)
    assert result == {"runs": 0, "min_runs": 2, "enough": False, "low": None,
                      "median": None, "high": None}
