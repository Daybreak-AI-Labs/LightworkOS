"""Cost retrospective: aggregation, failed-work + concentration, CLI."""
from __future__ import annotations

from click.testing import CliRunner
from maverick.cli import main
from maverick.cost import retrospective as cr
from maverick.world_model import WorldModel


def _seed(path, goals):
    """goals: list of (title, [(cost, outcome), ...])."""
    wm = WorldModel(path)
    for title, eps in goals:
        gid = wm.create_goal(title, "")
        for cost, outcome in eps:
            ep = wm.start_episode(gid)
            wm.end_episode(ep, summary="s", outcome=outcome, cost_dollars=cost)
    wm.close()


def test_totals_and_top_goals(tmp_path):
    _seed(tmp_path / "w.db", [
        ("cheap", [(0.10, "succeeded")]),
        ("expensive", [(5.0, "succeeded"), (1.0, "succeeded")]),
        ("free", [(0.0, "succeeded")]),
    ])
    rep = cr.retrospective(WorldModel(tmp_path / "w.db"))
    assert rep["total_spend"] == 6.10
    assert rep["priced_goals"] == 2          # the free goal is excluded
    assert rep["top_goals"][0]["title"] == "expensive"
    assert rep["top_goals"][0]["cost"] == 6.0


def test_failed_spend_is_attributed(tmp_path):
    _seed(tmp_path / "w.db", [
        ("ok", [(2.0, "succeeded")]),
        ("bad", [(3.0, "failed")]),
    ])
    rep = cr.retrospective(WorldModel(tmp_path / "w.db"))
    assert rep["failed_spend"] == 3.0
    assert rep["failed_share"] == 0.6
    assert any("failed" in o.lower() for o in rep["observations"])


def test_top_goal_dominance_observed(tmp_path):
    _seed(tmp_path / "w.db", [
        ("whale", [(10.0, "succeeded")]),
        ("a", [(0.5, "succeeded")]),
        ("b", [(0.5, "succeeded")]),
    ])
    rep = cr.retrospective(WorldModel(tmp_path / "w.db"))
    assert any("all spend" in o for o in rep["observations"])


def test_concentration_pure():
    # all spend in one of ten goals -> costliest 10% (=1 goal) holds it all
    costs = [10.0] + [0.0] * 9
    assert cr._concentration(costs) == 1.0
    # perfectly even -> top 10% holds ~10%
    assert cr._concentration([1.0] * 10) == 0.1


def test_empty_world(tmp_path):
    _seed(tmp_path / "w.db", [])
    rep = cr.retrospective(WorldModel(tmp_path / "w.db"))
    assert rep["total_spend"] == 0.0 and rep["priced_goals"] == 0
    assert "no priced goals" in rep["observations"][0]


def test_cli_cost_retro(tmp_path):
    db = tmp_path / "world.db"
    _seed(db, [("g", [(1.0, "succeeded")]), ("bad", [(2.0, "failed")])])
    res = CliRunner().invoke(main, ["--db", str(db), "cost-retro"])
    assert res.exit_code == 0
    assert "Cost retrospective" in res.output
    assert "Observations" in res.output


def test_cli_cost_retro_strips_terminal_control_from_titles(tmp_path):
    db = tmp_path / "world.db"
    malicious_title = "normal\x1b]52;c;SGVsbG8=\x07SPOOF\nNEXTLINE\x1b[2K"
    _seed(db, [(malicious_title, [(1.0, "succeeded")])])

    res = CliRunner().invoke(main, ["--db", str(db), "cost-retro"])

    assert res.exit_code == 0
    assert "\x1b" not in res.output
    assert "\x07" not in res.output
    assert "normalSPOOFNEXTLINE" in res.output


def test_cli_cost_retro_json(tmp_path):
    db = tmp_path / "world.db"
    _seed(db, [("g", [(1.0, "succeeded")])])
    res = CliRunner().invoke(main, ["--db", str(db), "cost-retro", "--json"])
    assert res.exit_code == 0
    import json
    assert json.loads(res.output)["total_spend"] == 1.0


class _GoalByGoal:
    """A world without the batch reader: the pre-change per-goal reads."""

    def __init__(self, world):
        self._world = world

    def list_goals(self, **kwargs):
        return self._world.list_goals(**kwargs)

    def list_episodes(self, **kwargs):
        return self._world.list_episodes(**kwargs)


def test_goal_rows_match_goal_by_goal_reads(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    goals = [world.create_goal(f"task {i}", owner="user:alice") for i in range(5)]
    with world._writing() as conn:
        for index in range(120):
            conn.execute(
                "INSERT INTO episodes(goal_id, started_at, cost_dollars, outcome) VALUES (?, ?, ?, ?)",
                (goals[index % 5], 3_000.0 + index, 0.0 if index % 4 == 0 else 0.03 * (index % 6),
                 "failed" if index % 7 == 0 else "succeeded"),
            )
    for limit in (2000, 10):
        assert cr._goal_rows(world, limit=limit) == cr._goal_rows(_GoalByGoal(world), limit=limit)
    assert cr.retrospective(world) == cr.retrospective(_GoalByGoal(world))
    assert len(cr._goal_rows(world, limit=10)) == 5
