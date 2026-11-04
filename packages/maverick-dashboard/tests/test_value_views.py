"""Overview, Spend and Savings tell each role the truth about whose work they
count. A read-only role sees whole-workspace totals and never task content;
nobody is told to start work they cannot start; an estimate shows its
assumptions."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    from maverick_dashboard import auth, rbac

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_ADMINS"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    api_mod._world_cache.clear()
    app_mod._world_cache.clear()
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)

    def _verify(token, **_kw):
        return VerifiedPrincipal(sub=token, issuer="https://issuer.example",
                                 audience="maverick", claims={"sub": token})

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)
    rbac.set_role("user:audrey", "auditor")
    rbac.set_role("user:vic", "viewer")
    rbac.set_role("user:alice", "operator")
    yield
    config.reset_config_cache()
    api_mod._world_cache.clear()
    app_mod._world_cache.clear()


def _as(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user}", "Origin": "http://127.0.0.1"}


def _finished(owner: str, title: str, cost: float) -> int:
    from maverick_dashboard.app import _world

    world = _world()
    goal = world.create_goal(title, "d", owner=owner)
    episode = world.start_episode(goal)
    world.end_episode(episode, "done", "success", cost_dollars=cost,
                      input_tokens=10, output_tokens=5)
    world.set_goal_status(goal, "done", result="Private result")
    return goal


def test_a_read_only_role_sees_workspace_totals_but_no_task_content():
    _finished("user:alice", "Alice private vendor review", 1.0)
    _finished("user:bob", "Bob private payroll check", 2.0)
    overview = client.get("/api/v1/dashboards/overview", headers=_as("audrey")).json()
    assert overview["scope"] == "workspace"
    assert overview["totals"]["total"] == 2 and overview["recent"] == []
    spend = client.get("/api/v1/dashboards/spend", headers=_as("audrey")).json()
    assert spend["scope"] == "workspace"
    assert spend["totals"]["dollars"] == pytest.approx(3.0)
    assert spend["per_run"] == [] and spend["top_goals"] == []
    savings = client.get("/api/v1/savings", headers=_as("vic")).json()
    assert savings["scope"] == "workspace" and savings["report"]["deliverables"] == 2
    board = client.get("/api/v1/dashboards/savings", headers=_as("vic")).json()
    assert board["scope"] == "workspace" and board["report"]["deliverables"] == 2
    for page in ("/overview", "/spend", "/savings"):
        html = client.get(page, headers=_as("audrey")).text
        assert "private vendor review" not in html and "private payroll" not in html, page
    assert "2 tasks on record in this workspace" in client.get("/overview", headers=_as("audrey")).text
    # Someone who runs tasks still counts only their own work.
    mine = client.get("/api/v1/dashboards/overview", headers=_as("alice")).json()
    assert mine["scope"] == "own" and mine["totals"]["total"] == 1
    assert [row["title"] for row in mine["recent"]] == ["Alice private vendor review"]


def test_read_only_roles_are_not_told_to_start_work_they_cannot_start():
    for user in ("audrey", "vic"):
        overview = client.get("/overview", headers=_as(user)).text
        assert "Start your first task" not in overview and 'action="/chat/send"' not in overview
        assert "No tasks have run in this workspace yet" in overview
        assert 'href="/chat">Start a task' not in client.get("/savings", headers=_as(user)).text
        assert ">Start a task<" not in client.get("/spend", headers=_as(user)).text
    assert "Start your first task" in client.get("/overview", headers=_as("alice")).text


def test_the_savings_estimate_shows_its_assumptions(tmp_path):
    from maverick import config

    _finished("user:alice", "Archive drafts", 0.06)
    html = client.get("/savings", headers=_as("alice")).text
    assert "times what Lightwork cost" not in html      # no bare cost multiple
    assert "starting numbers" in html                  # defaults are not yet the customer's
    assert 'href="#sv-assumptions"' in html            # where to change them
    (tmp_path / "config.toml").write_text("[value]\nhourly_rate = 60.0\nhours_per_task = 0.5\n",
                                          encoding="utf-8")
    config.reset_config_cache()
    html = client.get("/savings", headers=_as("alice")).text
    assert "starting numbers" not in html
