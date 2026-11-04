"""`maverick resume --goal-id <bad>` must exit non-zero, not silently succeed.

An explicit, non-existent --goal-id printed run_goal's "no such goal: N" and
exited 0 (a script couldn't tell it failed; export exits 2 for the same case).
"""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from maverick.cli import main
from maverick.world_model import WorldModel


def test_resume_nonexistent_goal_exits_nonzero(tmp_path: Path):
    db = tmp_path / "world.db"
    result = CliRunner(env={"OPENAI_API_KEY": "sk-x"}).invoke(
        main, ["--db", str(db), "resume", "--goal-id", "99999"]
    )
    assert result.exit_code == 2
    assert "no such goal" in result.output


def test_resume_no_goal_is_graceful(tmp_path: Path):
    db = tmp_path / "world.db"
    result = CliRunner(env={"OPENAI_API_KEY": "sk-x"}).invoke(
        main, ["--db", str(db), "resume"]
    )
    # Nothing to resume is not an error.
    assert result.exit_code == 0
    assert "no active or blocked goal" in result.output


def test_resume_accepts_positional_goal_id(tmp_path: Path):
    # The budget-halt / error messages suggest `maverick resume <id>`
    # (positional). Resume previously took only --goal-id, so the suggested
    # command failed with "Got unexpected extra argument". The positional must
    # reach the same not-found validation (exit 2), not a usage error.
    db = tmp_path / "world.db"
    result = CliRunner(env={"OPENAI_API_KEY": "sk-x"}).invoke(
        main, ["--db", str(db), "resume", "99999"]
    )
    assert result.exit_code == 2, result.output
    assert "no such goal" in result.output
    assert "unexpected extra argument" not in result.output.lower()


def test_resume_requires_provider_only_after_finding_work(tmp_path: Path):
    db = tmp_path / "world.db"
    world = WorldModel(db)
    goal_id = world.create_goal("resume me")
    world.set_goal_status(goal_id, "blocked")
    world.close()

    result = CliRunner(env={
        "ANTHROPIC_API_KEY": None,
        "OPENAI_API_KEY": None,
    }).invoke(main, ["--db", str(db), "resume"])

    assert result.exit_code == 2
    assert "can't reach an LLM" in result.output
