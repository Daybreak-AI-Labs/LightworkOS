"""Run health score."""
from __future__ import annotations

from maverick.health_score import compute_health, render


def test_clean_success_scores_high():
    h = compute_health(success=True)
    assert h.score == 100
    assert h.grade == "A"


def test_failure_starts_low():
    h = compute_health(success=False)
    assert h.score == 40
    assert h.grade == "F"


def test_tool_errors_and_retries_penalise():
    h = compute_health(success=True, tool_errors=2, tool_retries=3)
    # 100 - (2*8 + 3*3) = 100 - 25 = 75
    assert h.score == 75
    assert h.grade == "C"


def test_tool_penalty_is_capped():
    h = compute_health(success=True, tool_errors=100)
    assert h.score == 50  # 100 - 50 (cap)


def test_efficiency_penalty_on_overshoot():
    # used 2x expected -> overshoot 1.0 -> 15-point penalty
    h = compute_health(success=True, in_tok=1000, out_tok=1000,
                       expected_tokens=1000)
    assert h.score == 85


def test_under_budget_not_penalised():
    h = compute_health(success=True, in_tok=100, out_tok=100,
                       expected_tokens=1000)
    assert h.score == 100


def test_score_never_negative():
    h = compute_health(success=False, tool_errors=100, in_tok=10_000,
                       out_tok=0, expected_tokens=10)
    assert h.score == 0
    assert render(h) == "Run health: 0/100 (F)"


def test_diag_health_cli_reads_the_shared_kernel_score(tmp_path, monkeypatch):
    """``maverick diag health`` and the task page read one kernel function."""
    from click.testing import CliRunner
    from maverick import world_model
    from maverick.cli import main
    from maverick.health_score import goal_health

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    world = world_model.open_world()
    gid = world.create_goal("report", "")
    ep = world.start_episode(gid)
    world.end_episode(ep, "done", "success", input_tokens=10, output_tokens=5)
    world.set_goal_status(gid, "done")
    _goal, health = goal_health(world, gid)
    world_model.close_world_if_owned(world)
    result = CliRunner().invoke(main, ["diag", "health", str(gid)])
    assert result.exit_code == 0, result.output
    assert result.output == f"goal #{gid} (done):\n{render(health)}\n"
    missing = CliRunner().invoke(main, ["diag", "health", "999999"])
    assert missing.exit_code == 2 and "no such goal 999999" in missing.output
