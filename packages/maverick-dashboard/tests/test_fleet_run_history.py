"""Per-agent fleet run history on the operator console (/fleets).

Hermetic, like ``test_fleets_console.py``: OIDC off, HOME + MAVERICK_HOME
isolated to a tmp_path (so fleets + their run index land in the temp dir), and
the WorldModel points at a fresh DB so goal lookups resolve there.
"""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _save_fleet(name="acme", owner=""):
    from maverick.fleet import Fleet, FleetAgent, save_fleet
    fleet = Fleet(
        name=name,
        owner=owner,
        agents=(
            FleetAgent("researcher", "researcher", "digs through sources"),
            FleetAgent("coder", "coder"),
        ),
    )
    return save_fleet(fleet)


def test_recorded_run_shows_up_with_goal_title_and_status(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    from maverick.fleet import record_run
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("Summarize the Q3 board deck")
    w.set_goal_status(gid, "done")
    record_run("acme", "researcher", gid)

    r = _client().get("/fleets")
    assert r.status_code == 200
    text = r.text
    assert "recent tasks" in text.lower()
    # The agent, a link to the task, its title, and status all render.
    assert "Researcher" in text
    assert f'href="/chat/goal/{gid}"' in text
    assert "Summarize the Q3 board deck" in text
    assert "Done" in text


def test_empty_state_when_no_runs(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    r = _client().get("/fleets")
    assert r.status_code == 200
    assert "No tasks yet" in r.text


def test_runs_are_newest_first_and_capped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    from maverick.fleet import record_run
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    # Record more than the per-fleet cap (12) so we exercise the trim.
    gids = []
    for i in range(15):
        gid = w.create_goal(f"task number {i}")
        record_run("acme", "coder", gid)
        gids.append(gid)

    text = _client().get("/fleets").text
    # Newest goal renders; the oldest (trimmed past the 12-cap) does not.
    # Assert on the unique goal titles -- a bare ``#<id>`` substring collides
    # with the page's CSS hex colours for tiny ids.
    assert "task number 14" in text
    assert "task number 0" not in text
    # Newest-first: the most recent goal appears before an older one.
    assert text.index("task number 14") < text.index("task number 13")


def test_missing_goal_renders_fail_soft(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_fleet()
    from maverick.fleet import record_run
    # A run that points at a goal id that does not exist in the world.
    record_run("acme", "coder", 999999)
    r = _client().get("/fleets")
    assert r.status_code == 200
    text = r.text
    assert 'href="/chat/goal/999999"' not in text
    assert "No tasks yet" in text


def test_authenticated_run_history_hides_other_owner_stale_index(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick_dashboard.app as dashboard_app
    from maverick.fleet import Fleet, record_run, remove_fleet, save_fleet
    from maverick.world_model import WorldModel

    w = WorldModel(tmp_path / "world.db")
    alice_gid = w.create_goal("Alice private board deck", owner="user:alice")
    save_fleet(Fleet(name="acme", owner="user:alice"))
    record_run("acme", "researcher", alice_gid)
    remove_fleet("acme")

    # Simulate an old orphaned run index left by a prior build, then reuse the
    # same fleet name under a different authenticated owner.
    record_run("acme", "researcher", alice_gid)
    eve_gid = w.create_goal("Eve onboarding task", owner="user:eve")
    record_run("acme", "coder", eve_gid)
    save_fleet(Fleet(name="acme", owner="user:eve"))
    monkeypatch.setattr(dashboard_app, "goal_owner_filter", lambda request: "user:eve")

    r = _client().get("/fleets")
    assert r.status_code == 200
    text = r.text
    assert "Eve onboarding task" in text
    assert "Alice private board deck" not in text
    assert f">#{alice_gid}</td>" not in text
