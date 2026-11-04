"""The cost line beside Start on every task launch.

Before, what tasks usually cost was behind "Check budget before starting".
Now the chat composer says, under the Start button, what this person's own
past tasks cost: a range from recorded costs, or how many more finished
tasks it needs. History only, never a prediction.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

ANA = "user:ana@corp.com"


@pytest.fixture
def env(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("[spending_limits]\ntypical_cost_min_runs = 2\n", encoding="utf-8")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = WorldModel(tmp_path / "world.db")
    from maverick_dashboard import api, auth, rbac
    rbac.set_role(ANA, "operator")
    api._world_cache.clear()
    monkeypatch.setattr(auth, "caller_principal", lambda request: ANA)
    from maverick_dashboard import app as app_module
    from maverick_dashboard.app import app

    # The chat page reads the signed-in person through its own import.
    monkeypatch.setattr(app_module, "caller_principal", lambda request: ANA)
    yield TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}), world
    world.close()
    api._world_cache.clear()
    config.reset_config_cache()


def _finished(world, owner, dollars):
    goal = world.create_goal("Done task", owner=owner)
    episode = world.start_episode(goal)
    world.end_episode(episode, "done", "ok", cost_dollars=dollars)


def test_start_shows_what_your_past_tasks_cost(env):
    client, world = env
    page = client.get("/chat").text
    assert 'id="composer-typical-cost"' in page and 'aria-describedby="composer-typical-cost"' in page
    assert "No cost range yet: 0 of the 2 finished tasks needed" in page
    for dollars in (0.40, 0.60, 0.80):
        _finished(world, ANA, dollars)
    _finished(world, "user:ben@corp.com", 90.0)  # someone else's tasks never count
    page = client.get("/chat").text
    assert "Your past tasks usually cost $0.50 to $0.70, $0.60 in the middle (from your last 3 finished tasks)." in page
    assert "This is past spending, not a prediction." in page
