"""Cost forecasting for `maverick start --dry-cost`."""
from __future__ import annotations

from click.testing import CliRunner
from maverick.cli import main
from maverick.cost.forecast import CostForecast, forecast, gather_samples, render


def test_no_history_returns_none_basis():
    fc = forecast([], "do a thing")
    assert fc.n_samples == 0 and fc.basis == "none" and fc.estimate_dollars == 0.0


def test_zero_cost_samples_ignored():
    fc = forecast([("a run", 0.0), ("another", 0)], "a run")
    assert fc.basis == "none"


def test_similar_runs_weighted():
    samples = [
        ("research AI agent frameworks", 2.0),
        ("research AI agent tooling", 2.4),
        ("cook a pasta dinner", 0.5),
    ]
    fc = forecast(samples, "research AI agent benchmarks")
    assert fc.basis == "similar"
    # estimate is dominated by the two similar research runs (~2.0-2.4), not pasta
    assert 1.8 <= fc.estimate_dollars <= 2.5
    assert fc.low_dollars == 2.0 and fc.high_dollars == 2.4


def test_recent_average_when_nothing_similar():
    samples = [("alpha task", 1.0), ("beta task", 3.0)]
    fc = forecast(samples, "zzz totally unrelated qqq")
    assert fc.basis == "recent"
    assert fc.estimate_dollars == 2.0  # mean of 1.0 and 3.0
    assert fc.n_samples == 2


def test_gather_samples_joins_titles_and_filters_zero():
    class _Ep:
        def __init__(self, goal_id, cost):
            self.goal_id, self.cost_dollars = goal_id, cost

    class _Goal:
        def __init__(self, title):
            self.title = title

    class _World:
        _goals = {1: _Goal("research agents"), 2: _Goal("free run")}

        def list_episodes(self, limit=200):
            return [_Ep(1, 1.5), _Ep(2, 0.0), _Ep(1, 2.5)]

        def get_goal(self, gid):
            return self._goals.get(gid)

    samples = gather_samples(_World())
    assert samples == [("research agents", 1.5), ("research agents", 2.5)]


def test_render_messages():
    assert "can't forecast" in render(CostForecast(0, 0, 0, 0, "none"))
    msg = render(CostForecast(1.2345, 0.5, 2.0, 3, "similar"))
    assert "$1.2345" in msg and "3 similar" in msg


def test_cli_dry_cost_no_history(tmp_path, monkeypatch):
    # No LLM key set, empty db -> --dry-cost still works (no key required) and
    # reports no history, without creating a goal or running the swarm.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    db = tmp_path / "world.db"
    r = CliRunner().invoke(main, ["--db", str(db), "start", "hello world", "--dry-cost"])
    assert r.exit_code == 0, r.output
    assert "No priced run history" in r.output
