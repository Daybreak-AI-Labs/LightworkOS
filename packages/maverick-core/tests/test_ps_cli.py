"""`maverick ps`: the unified process table -- recent goals + scheduled jobs.

A read-only view across the two execution surfaces (world-model goals and the
cron/job queue) so an operator sees everything the runtime is doing or about to
do in one place.
"""
from __future__ import annotations

import json

from click.testing import CliRunner


def test_ps_registered():
    from maverick.cli import main
    assert "ps" in main.commands


def test_ps_empty(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    from maverick.cli import main
    res = CliRunner().invoke(main, ["--db", str(tmp_path / "world.db"), "ps"])
    assert res.exit_code == 0, res.output
    assert "no goals or scheduled jobs" in res.output


def test_ps_lists_goal_and_job(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    from maverick.world_model import open_world
    db = tmp_path / "world.db"
    w = open_world(db)
    w.create_goal("Summarize emails", "do it")
    w.close()
    from maverick.job_queue import JobQueue
    JobQueue(db_path=tmp_path / "jobs.db").enqueue(
        "start_goal", {"text": "nightly", "__cron__": "0 9 * * *"}, run_at=1000.0)

    from maverick.cli import main
    res = CliRunner().invoke(main, ["--db", str(db), "ps"])
    assert res.exit_code == 0, res.output
    assert "goal" in res.output and "Summarize emails" in res.output
    assert "job" in res.output and "start_goal" in res.output
    assert "0 9 * * *" in res.output  # the cron schedule is surfaced


def test_ps_json(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    from maverick.world_model import open_world
    db = tmp_path / "world.db"
    w = open_world(db)
    w.create_goal("G1", "x")
    w.close()

    from maverick.cli import main
    res = CliRunner().invoke(main, ["--db", str(db), "ps", "--json"])
    assert res.exit_code == 0, res.output
    rows = json.loads(res.output)
    assert any(r["type"] == "goal" and r["what"] == "G1" for r in rows)


def test_ps_text_strips_terminal_control_sequences(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    from maverick.world_model import open_world
    db = tmp_path / "world.db"
    w = open_world(db)
    w.create_goal("Goal\x1b[2JTitle\x1b]52;c;SGVsbG8=\x07", "x")
    w.close()

    from maverick.job_queue import JobQueue
    JobQueue(db_path=tmp_path / "jobs.db").enqueue(
        "job\x1b]8;;https://evil.example/\x07kind",
        {"__cron__": "* * * * *\x1b[31m"},
        run_at=1000.0,
    )

    from maverick.cli import main
    res = CliRunner().invoke(main, ["--db", str(db), "ps"])
    assert res.exit_code == 0, res.output
    assert "\x1b" not in res.output
    assert "\x07" not in res.output
    assert "GoalTitle" in res.output
    assert "jobkind" in res.output


def test_ps_json_preserves_raw_values(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.job_queue.DEFAULT_DB", tmp_path / "jobs.db")
    from maverick.world_model import open_world
    db = tmp_path / "world.db"
    w = open_world(db)
    title = "Goal\x1b[2JTitle"
    w.create_goal(title, "x")
    w.close()

    from maverick.cli import main
    res = CliRunner().invoke(main, ["--db", str(db), "ps", "--json"])
    assert res.exit_code == 0, res.output
    rows = json.loads(res.output)
    assert any(r["type"] == "goal" and r["what"] == title for r in rows)
