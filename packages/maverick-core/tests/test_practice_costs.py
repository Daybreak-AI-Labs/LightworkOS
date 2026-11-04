"""Practice AI calls cost real provider money: every cost view shows them on
their own labelled line, apart from real totals, limits and quotas."""
from __future__ import annotations

import time

import pytest


@pytest.fixture
def home(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def practice_run(dollars, *, owner="pat", outcome="done"):
    from maverick import practice
    from maverick.world_model import open_world

    with practice.scope():
        world = open_world()
        goal = world.create_goal("Practice: chase the PO", owner=owner)
        episode = world.start_episode(goal)
        world.end_episode(episode, "ok", outcome, cost_dollars=dollars, input_tokens=100, output_tokens=20)
    return goal


def test_nothing_practised_reads_as_no_line_and_creates_nothing(home):
    from maverick import practice, practice_costs

    assert practice_costs.summary(owner="pat") is None
    with practice.scope():
        from maverick.world_model import default_db_path
        assert not default_db_path().exists()


def test_practice_runs_are_totalled_apart_from_real_spend(home):
    from maverick import practice_costs
    from maverick.world_model import open_world

    practice_run(0.30)
    practice_run(0.12)
    practice_run(0.05, owner="sam")
    assert open_world().total_spend(owner="pat")["dollars"] == 0  # the real record never sees practice
    line = practice_costs.summary(owner="pat")
    assert line["dollars"] == pytest.approx(0.42) and line["runs"] == 2 and line["today"] == pytest.approx(0.42)
    assert line["text"] == "Practice: $0.42 today (not counted against limits)"
    assert practice_costs.summary(owner=None)["dollars"] == pytest.approx(0.47)
    assert practice_costs.summary(owner="pat", since=time.time() + 60) is None
    assert practice_costs.label(line, "this month") == "Practice: $0.42 this month (not counted against limits)"


def test_a_practice_view_never_shows_practice_twice(home):
    from maverick import practice, practice_costs

    practice_run(0.30)
    with practice.scope():
        assert practice_costs.summary(owner="pat") is None


def test_practice_spend_still_does_not_count_against_limits(home):
    from maverick import practice, quotas, spending_limits

    spending_limits.set_user_limit("pat", 0.50, "day", actor="admin")
    practice_run(0.42)
    with practice.scope():
        quotas.record_usage("pat", 0.42)

    class Run:
        dollars, _reserved, _organization_principal = 0.0, 0.0, "pat"

    spending_limits.admit(Run(), 0.45)  # live: the $0.42 practised is not counted
    assert spending_limits.recorded_spend("day", "pat") == 0.0
