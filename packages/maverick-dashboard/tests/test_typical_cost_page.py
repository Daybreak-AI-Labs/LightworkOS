"""Before starting a task, people see what past runs usually cost.

From recorded task costs in this workspace only, as the middle half and the
median, and only after the minimum number of finished tasks; never a guess.
"""
from __future__ import annotations

import html as _html
import re

import pytest
from fastapi.testclient import TestClient

SPECIALIST = "aero_avionics"


def _visible(page: str) -> str:
    page = re.sub(r"<(script|style)\b.*?</\1>", " ", page, flags=re.DOTALL)
    return _html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)))


@pytest.fixture
def env(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mvhome"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    from maverick_dashboard import app as dash_app

    dash_app._world_cache.clear()
    world = WorldModel(tmp_path / "world.db")
    yield TestClient(dash_app.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world, tmp_path
    world.close()
    config.reset_config_cache()


def _tasks(world, costs, *, domain=SPECIALIST, principal=""):
    for cost in costs:
        gid = world.create_goal("Report", owner="", execution_principal=principal)
        if domain:
            world.set_goal_domain(gid, domain)
        eid = world.start_episode(gid)
        world.end_episode(eid, "Done", "success", cost_dollars=cost)


def test_the_specialist_page_says_not_enough_runs_below_the_minimum(env):
    client, world, _ = env
    _tasks(world, [0.5] * 3)
    words = _visible(client.get(f"/agents?name={SPECIALIST}").text)
    assert "Not enough past tasks to estimate yet: 3 of the 10 finished tasks needed." in words


def test_the_specialist_page_shows_the_range_from_enough_runs(env):
    client, world, _ = env
    _tasks(world, [0.2, 0.4, 0.6, 0.8, 1.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    _tasks(world, [90.0] * 10, domain="aero_cmmc")  # another specialist's history
    words = _visible(client.get(f"/agents?name={SPECIALIST}").text)
    assert ("Past tasks usually cost $0.40 to $0.80, $0.60 in the middle "
            "(based on 10 finished tasks in this workspace). "
            "This is past spending, not a prediction.") in words


def test_the_minimum_follows_the_setting(env):
    client, world, tmp_path = env
    from maverick import config

    (tmp_path / "config.toml").write_text("[spending_limits]\ntypical_cost_min_runs = 3\n")
    config.reset_config_cache()
    _tasks(world, [1.0, 2.0, 3.0])
    words = _visible(client.get(f"/agents?name={SPECIALIST}").text)
    assert "Past tasks usually cost $1.50 to $2.50, $2.00 in the middle (based on 3" in words


def test_the_team_task_form_shows_each_agents_past_runs(env):
    client, world, _ = env
    from maverick.fleet import Fleet, FleetAgent, save_fleet

    save_fleet(Fleet(name="acme", owner="", agents=(
        FleetAgent("writer", "researcher"), FleetAgent("avionics", "researcher", domain=SPECIALIST))))
    _tasks(world, [1.0] * 10)
    _tasks(world, [0.3], domain="", principal="agent:acme.writer")
    page = client.get("/fleets").text
    assert ('data-typical="Past tasks usually cost $1.00 to $1.00, $1.00 in the middle '
            '(based on 10 finished tasks in this workspace).') in page
    assert 'data-typical="Not enough past tasks to estimate yet: 1 of the 10' in page
    assert "Choose an agent or specialist to see what its past tasks usually cost." in page
