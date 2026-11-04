"""DuckDB analytics over the world model: load, canned queries, read-only guard."""

from __future__ import annotations

import pytest
from click.testing import CliRunner
from maverick.cli import main
from maverick.world_model import WorldModel

duckdb = pytest.importorskip("duckdb")
from maverick.duckdb_analytics import WorldAnalytics  # noqa: E402


def _seed(path, goals):
    """goals: list of (title, status, [(cost, outcome, ended_at), ...])."""
    wm = WorldModel(path)
    for title, status, eps in goals:
        gid = wm.create_goal(title, "")
        if status:
            wm.set_goal_status(gid, status)
        for cost, outcome, _ended in eps:
            ep = wm.start_episode(gid)
            wm.end_episode(ep, summary="s", outcome=outcome, cost_dollars=cost)
    wm.close()
    return WorldModel(path)


def test_cost_percentiles(tmp_path):
    w = _seed(
        tmp_path / "w.db",
        [(f"g{i}", "done", [(float(i) * 0.5, "success", 1.0)]) for i in range(1, 11)],
    )
    wa = WorldAnalytics(w)
    pct = wa.cost_percentiles()
    assert pct["n"] == 10
    assert pct["max_cost"] == pytest.approx(5.0)
    assert 0 < pct["p50"] <= pct["p90"] <= pct["p99"] <= pct["max_cost"]
    wa.close()


def test_top_goals(tmp_path):
    w = _seed(
        tmp_path / "w.db",
        [
            ("cheap", "done", [(0.1, "success", 1.0)]),
            ("whale", "done", [(5.0, "success", 1.0), (1.0, "success", 1.0)]),
            ("free", "done", [(0.0, "success", 1.0)]),
        ],
    )
    wa = WorldAnalytics(w)
    rows = wa.top_goals(5)
    assert rows[0]["title"] == "whale" and rows[0]["total_cost"] == pytest.approx(6.0)
    assert rows[0]["ep_count"] == 2
    assert all(r["title"] != "free" for r in rows)  # zero-cost excluded
    wa.close()


def test_daily_cost(tmp_path):
    w = _seed(tmp_path / "w.db", [("g", "done", [(1.0, "success", 1.0)])])
    wa = WorldAnalytics(w)
    days = wa.daily_cost()
    # end_episode stamps ended_at = now, so there's one day bucket at today.
    assert len(days) == 1 and days[0]["spend"] == pytest.approx(1.0)
    import re

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", days[0]["bucket"])
    wa.close()


def test_adhoc_query(tmp_path):
    w = _seed(tmp_path / "w.db", [("a", "done", [(2.0, "success", 1.0)])])
    wa = WorldAnalytics(w)
    rows = wa.query("SELECT count(*) AS n FROM episodes")
    assert rows == [{"n": 1}]
    wa.close()


def test_query_rejects_writes(tmp_path):
    w = _seed(tmp_path / "w.db", [("a", "done", [(1.0, "success", 1.0)])])
    wa = WorldAnalytics(w)
    for bad in (
        "DELETE FROM episodes",
        "DROP TABLE goals",
        "UPDATE goals SET title='x'",
        "INSERT INTO goals VALUES (1,'x','y')",
    ):
        with pytest.raises(ValueError, match="only SELECT"):
            wa.query(bad)
    wa.close()


def test_query_applies_row_limit(tmp_path):
    w = _seed(tmp_path / "w.db", [(str(i), "done", [(1.0, "success", 1.0)]) for i in range(3)])
    wa = WorldAnalytics(w, query_limit=2)
    rows = wa.query("SELECT id FROM goals ORDER BY id")
    assert len(rows) == 2
    wa.close()


def test_query_rejects_multiple_statements(tmp_path):
    w = _seed(tmp_path / "w.db", [("a", "done", [(1.0, "success", 1.0)])])
    wa = WorldAnalytics(w)
    with pytest.raises((ValueError, duckdb.ParserException)):
        wa.query("SELECT 1; SELECT * FROM goals")
    wa.close()


def test_query_cannot_break_out_of_the_single_select(tmp_path):
    # Closing the wrapper's parenthesis smuggles further statements past the
    # SELECT/WITH prefix check: writes and settings changes, and a last
    # statement that swallows the row limit's placeholder.
    w = _seed(tmp_path / "w.db", [("a", "done", [(1.0, "success", 1.0)])])
    wa = WorldAnalytics(w, query_limit=5)
    for bad in (
        "SELECT 1) AS x; DROP TABLE goals; SELECT * FROM (SELECT 1",
        "SELECT 1) AS x; SET threads = 64; SELECT * FROM (SELECT 1",
        "SELECT 1) AS x; SELECT ?::INT AS lim, range AS r FROM range(50) --",
    ):
        with pytest.raises((ValueError, duckdb.Error)):
            wa.query(bad)
    assert wa.query("SELECT count(*) AS n FROM goals") == [{"n": 1}]
    wa.close()


def test_query_disables_external_file_access(tmp_path):
    w = _seed(tmp_path / "w.db", [("a", "done", [(1.0, "success", 1.0)])])
    secret = tmp_path / "secret.csv"
    secret.write_text("s\nleak\n")
    wa = WorldAnalytics(w)
    with pytest.raises(
        duckdb.PermissionException, match="file system operations are disabled|Cannot access file"
    ):
        wa.query(f"SELECT * FROM read_csv('{secret}', header=true)")
    wa.close()


def test_empty_world(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    wa = WorldAnalytics(w)
    assert wa.cost_percentiles().get("n") == 0
    assert wa.top_goals() == []
    wa.close()


def test_cli_analytics(tmp_path):
    db = tmp_path / "world.db"
    _seed(db, [("g", "done", [(1.5, "success", 1.0)])]).close()
    res = CliRunner().invoke(main, ["--db", str(db), "analytics"])
    assert res.exit_code == 0
    assert "cost percentiles" in res.output.lower()
    assert "Costliest goals" in res.output


def test_cli_analytics_sql(tmp_path):
    db = tmp_path / "world.db"
    _seed(db, [("g", "done", [(1.0, "success", 1.0)])]).close()
    res = CliRunner().invoke(
        main, ["--db", str(db), "analytics", "--sql", "SELECT count(*) n FROM goals"]
    )
    assert res.exit_code == 0
    import json

    assert json.loads(res.output) == [{"n": 1}]


class _GoalByGoal:
    """A world without the batch reader: the pre-change per-goal reads."""

    def __init__(self, world):
        self._world = world

    def list_goals(self, **kwargs):
        return self._world.list_goals(**kwargs)

    def list_episodes(self, **kwargs):
        return self._world.list_episodes(**kwargs)


def test_loaded_episode_rows_match_goal_by_goal_reads(tmp_path):
    world = WorldModel(tmp_path / "w.db")
    goals = [world.create_goal(f"task {i}", owner="user:alice") for i in range(4)]
    with world._writing() as conn:
        for index in range(150):
            conn.execute(
                "INSERT INTO episodes(goal_id, started_at, ended_at, cost_dollars, input_tokens, "
                "output_tokens, outcome) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (goals[index % 4], 4_000.0 + index, 4_000.5 + index, 0.01 * (index % 5), index, 2,
                 "failed" if index % 6 == 0 else "done"),
            )
    query = ("SELECT goal_id, cost, in_tok, out_tok, outcome, ended_at FROM episodes "
             "ORDER BY goal_id, ended_at")
    for limit in (100000, 10):
        batched = WorldAnalytics(world, limit=limit).query(query)
        by_goal = WorldAnalytics(_GoalByGoal(world), limit=limit).query(query)
        assert batched == by_goal
    assert len(WorldAnalytics(world, limit=10).query(query)) == 40
