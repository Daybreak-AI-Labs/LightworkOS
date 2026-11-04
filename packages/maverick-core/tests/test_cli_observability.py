"""Consumer-facing CLI UX and observability.

  1. Live spend is visible mid-run: a still-open episode whose running totals
     were mirrored (before end_episode) shows non-zero spend via `runs` /
     `budget` / the read path.
  2. The model-404 hint points at `maverick config` (where [models] live),
     not `maverick doctor` (which only validates the API key).
  3. Library log lines don't bleed onto the terminal by default; they surface
     when MAVERICK_DEBUG is set.
"""
from __future__ import annotations

import logging
from pathlib import Path

from click.testing import CliRunner
from maverick.cli import _configure_cli_logging, _humanize_run_error, main
from maverick.world_model import WorldModel

# ---------- task 1: live mid-run spend ----------

def test_update_episode_spend_mirrors_running_totals(tmp_path: Path):
    wm = WorldModel(tmp_path / "world.db")
    goal_id = wm.create_goal("long run", "")
    ep = wm.start_episode(goal_id)

    # Before any mirror, the live episode reads $0.00 / 0 tools.
    [live] = wm.list_episodes(goal_id=goal_id)
    assert live.cost_dollars == 0 and live.tool_calls == 0
    assert live.ended_at is None  # still running

    # Mid-run mirror writes accruing spend.
    wm.update_episode_spend(
        ep, cost_dollars=0.42, input_tokens=1000, output_tokens=200, tool_calls=3,
    )
    [live] = wm.list_episodes(goal_id=goal_id)
    assert live.cost_dollars == 0.42
    assert live.input_tokens == 1000
    assert live.tool_calls == 3
    assert live.ended_at is None  # mirror must NOT end the episode
    wm.close()


def test_runs_command_shows_mid_run_spend(tmp_path: Path):
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    goal_id = wm.create_goal("live goal", "")
    ep = wm.start_episode(goal_id)
    wm.update_episode_spend(ep, cost_dollars=1.23, tool_calls=5)
    wm.close()

    result = CliRunner().invoke(main, ["--db", str(db), "runs"])
    assert result.exit_code == 0
    assert "running" in result.output
    assert "$1.2300" in result.output
    assert "tools=5" in result.output


def test_budget_command_shows_mid_run_spend(tmp_path: Path):
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    goal_id = wm.create_goal("live goal", "")
    ep = wm.start_episode(goal_id)
    wm.update_episode_spend(ep, cost_dollars=0.77, tool_calls=2)
    wm.close()

    result = CliRunner().invoke(main, ["--db", str(db), "budget"])
    assert result.exit_code == 0
    # The live (not-yet-ended) episode shows in the per-run history as running.
    assert "running" in result.output
    assert "$0.7700" in result.output


def test_mirror_does_not_count_toward_total_spend(tmp_path: Path):
    # total_spend sums only ENDED episodes, so the live mirror must not inflate
    # lifetime totals (it's a read-side observability mirror, not a spend path).
    wm = WorldModel(tmp_path / "world.db")
    goal_id = wm.create_goal("g", "")
    ep = wm.start_episode(goal_id)
    wm.update_episode_spend(ep, cost_dollars=9.99, tool_calls=9)
    assert wm.total_spend()["dollars"] == 0
    wm.close()


def test_end_episode_overrides_mirror(tmp_path: Path):
    wm = WorldModel(tmp_path / "world.db")
    goal_id = wm.create_goal("g", "")
    ep = wm.start_episode(goal_id)
    wm.update_episode_spend(ep, cost_dollars=0.10, tool_calls=1)
    wm.end_episode(ep, "done", "success", cost_dollars=0.55, tool_calls=4)
    [e] = wm.list_episodes(goal_id=goal_id)
    assert e.cost_dollars == 0.55 and e.tool_calls == 4
    assert e.ended_at is not None
    # A late mirror after the episode ended must NOT clobber final totals.
    wm.update_episode_spend(ep, cost_dollars=0.0, tool_calls=0)
    [e] = wm.list_episodes(goal_id=goal_id)
    assert e.cost_dollars == 0.55 and e.tool_calls == 4
    wm.close()


# ---------- task 3: model-404 hint points at config, not doctor ----------

def test_model_404_hint_points_at_config_not_doctor():
    class NotFoundError(Exception):
        pass

    msg = _humanize_run_error(
        NotFoundError("Error code: 404 - model: claude-opus-9-9 not found")
    )
    assert "config" in msg
    assert "doctor" not in msg
    assert "404" in msg


def test_model_404_by_message_text():
    msg = _humanize_run_error(ValueError("model not found"))
    assert "maverick config" in msg
    assert "doctor" not in msg


# ---------- task 4: library logs don't bleed onto the terminal ----------

def _reset_logging():
    import maverick.logging_config as lc
    lc._configured = False
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)


def test_library_warning_suppressed_by_default(monkeypatch, capsys):
    monkeypatch.delenv("MAVERICK_DEBUG", raising=False)
    monkeypatch.delenv("MAVERICK_LOG_LEVEL", raising=False)
    _reset_logging()
    # Call the entrypoint's logging setup directly so the handler binds to the
    # real sys.stderr that capsys intercepts (CliRunner swaps the stream).
    _configure_cli_logging()
    logging.getLogger("some.library").warning("ignoring unreadable config.toml")
    err = capsys.readouterr().err
    assert "ignoring unreadable config.toml" not in err
    _reset_logging()


def test_library_warning_surfaced_with_debug(monkeypatch, capsys):
    monkeypatch.setenv("MAVERICK_DEBUG", "1")
    monkeypatch.delenv("MAVERICK_LOG_LEVEL", raising=False)
    _reset_logging()
    _configure_cli_logging()
    logging.getLogger("some.library").warning("ignoring unreadable config.toml")
    err = capsys.readouterr().err
    assert "ignoring unreadable config.toml" in err
    _reset_logging()


def test_sandbox_security_warning_surfaced_by_default(monkeypatch, capsys):
    monkeypatch.delenv("MAVERICK_DEBUG", raising=False)
    monkeypatch.delenv("MAVERICK_LOG_LEVEL", raising=False)
    _reset_logging()
    _configure_cli_logging()
    logging.getLogger("maverick.sandbox").warning(
        "sandbox backend is 'local': model-generated shell runs directly on this host"
    )
    err = capsys.readouterr().err
    assert "model-generated shell runs directly on this host" in err
    _reset_logging()


def test_shield_security_warning_surfaced_by_default(monkeypatch, capsys):
    monkeypatch.delenv("MAVERICK_DEBUG", raising=False)
    monkeypatch.delenv("MAVERICK_LOG_LEVEL", raising=False)
    _reset_logging()
    _configure_cli_logging()
    logging.getLogger("maverick.orchestrator").warning(
        "maverick-shield not installed; tool-call scans disabled"
    )
    err = capsys.readouterr().err
    assert "maverick-shield not installed" in err
    _reset_logging()
