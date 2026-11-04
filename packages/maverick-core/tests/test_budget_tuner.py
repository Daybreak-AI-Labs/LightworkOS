"""Self-tuning budgets: percentile/recommend math + world integration + CLI."""
from __future__ import annotations

from click.testing import CliRunner
from maverick import budget_tuner as bt
from maverick.cli import main
from maverick.world_model import WorldModel

# ---- pure math ----

def test_percentile_basic():
    vals = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    assert bt.percentile(vals, 0) == 1.0
    assert bt.percentile(vals, 100) == 10.0
    assert bt.percentile(vals, 50) == 5.5  # interpolated median


def test_percentile_edge_cases():
    assert bt.percentile([], 90) == 0.0
    assert bt.percentile([3.0], 90) == 3.0


def test_recommend_sizes_to_percentile_plus_margin():
    costs = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    # p90 ~ 0.91; * 1.25 margin ~ 1.14
    rec = bt.recommend(costs, pct=90, margin=1.25, floor=0.5)
    assert 1.0 < rec < 1.3


def test_recommend_floor_applies_with_small_costs():
    assert bt.recommend([0.01, 0.02, 0.03], floor=0.5) == 0.5


def test_recommend_no_data_returns_floor():
    assert bt.recommend([], floor=0.75) == 0.75


def test_recommend_ceiling_caps():
    assert bt.recommend([100, 200, 300], ceiling=5.0) == 5.0


def test_recommend_ignores_negative_costs():
    # a negative/garbage cost is clamped to 0, not allowed to drag the cap down
    rec = bt.recommend([-5, 1.0, 1.0, 1.0], pct=50, floor=0.1)
    assert rec > 0


# ---- world integration ----

def _seed(path, costs_by_goal):
    wm = WorldModel(path)
    for title, costs in costs_by_goal.items():
        gid = wm.create_goal(title, "")
        for c in costs:
            ep = wm.start_episode(gid)
            wm.end_episode(ep, summary="s", outcome="succeeded", cost_dollars=c)
    wm.close()
    return wm


def test_goal_costs_sums_episodes(tmp_path):
    _seed(tmp_path / "w.db", {"g1": [0.5, 0.5], "g2": [1.0], "free": [0.0]})
    wm = WorldModel(tmp_path / "w.db")
    costs = bt.goal_costs(wm)
    # g1 -> 1.0, g2 -> 1.0; the zero-cost goal is excluded
    assert sorted(costs.values()) == [1.0, 1.0]
    assert len(costs) == 2


def test_recommend_for_world_default_class(tmp_path):
    seeds = {f"g{i}": [0.2 * (i + 1)] for i in range(8)}  # 8 priced goals
    _seed(tmp_path / "w.db", seeds)
    wm = WorldModel(tmp_path / "w.db")
    recs = bt.recommend_for_world(wm, min_samples=5)
    assert "default" in recs
    assert recs["default"]["samples"] == 8
    assert recs["default"]["recommended_max_dollars"] > 0


def test_recommend_for_world_respects_min_samples(tmp_path):
    _seed(tmp_path / "w.db", {"a": [0.1], "b": [0.2]})  # only 2 priced goals
    wm = WorldModel(tmp_path / "w.db")
    assert bt.recommend_for_world(wm, min_samples=5) == {}


def test_recommend_for_world_per_class(tmp_path):
    # classify by a token in the title -> two classes
    seeds = {f"cheap-{i}": [0.1] for i in range(5)}
    seeds.update({f"pricey-{i}": [2.0] for i in range(5)})
    _seed(tmp_path / "w.db", seeds)
    wm = WorldModel(tmp_path / "w.db")
    recs = bt.recommend_for_world(
        wm, classify=lambda g: g.title.split("-")[0], min_samples=5)
    assert set(recs) == {"cheap", "pricey"}
    assert recs["pricey"]["recommended_max_dollars"] > \
        recs["cheap"]["recommended_max_dollars"]


# ---- CLI ----

def test_cli_budget_tune_reports(tmp_path):
    db = tmp_path / "world.db"
    _seed(db, {f"g{i}": [0.3] for i in range(6)})
    res = CliRunner().invoke(main, ["--db", str(db), "budget-tune", "--min-samples", "5"])
    assert res.exit_code == 0
    assert "Recommended max_dollars" in res.output


def test_cli_budget_tune_insufficient_data(tmp_path):
    db = tmp_path / "world.db"
    _seed(db, {"only": [0.3]})
    res = CliRunner().invoke(main, ["--db", str(db), "budget-tune"])
    assert res.exit_code == 0
    assert "not enough priced goals" in res.output


class _GoalByGoal:
    """A world without the batch reader: the pre-change per-goal reads."""

    def __init__(self, world):
        self._world = world

    def list_goals(self, **kwargs):
        return self._world.list_goals(**kwargs)

    def list_episodes(self, **kwargs):
        return self._world.list_episodes(**kwargs)


def test_goal_costs_and_newest_runs_match_goal_by_goal_reads(tmp_path):
    # One batched episode read per goal set must return, for each goal, the
    # same newest runs list_episodes(goal_id=...) returns, and the same spend.
    from maverick.budget_tuner import goal_costs
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "w.db")
    goals = [world.create_goal(f"task {i}", owner="user:alice") for i in range(3)]
    with world._writing() as conn:
        for index in range(130):
            conn.execute(
                "INSERT INTO episodes(goal_id, started_at, cost_dollars, input_tokens, "
                "output_tokens) VALUES (?, ?, ?, ?, ?)",
                (goals[index % 3], 1_000.0 + index, 0.0 if index % 5 == 0 else 0.02 * (index % 9), index, 1),
            )
    batch = world.episodes_by_goal(goals, per_goal=50)
    for gid in goals:
        assert batch[gid] == world.list_episodes(goal_id=gid, limit=50)
    assert world.episodes_by_goal([], per_goal=50) == {}
    assert goal_costs(world) == goal_costs(_GoalByGoal(world))
    assert goal_costs(world, limit=20) == goal_costs(_GoalByGoal(world), limit=20)
    assert len(goal_costs(world)) == 3


def test_episodes_by_goal_keeps_the_runs_list_episodes_keeps_at_a_tied_cut_off(tmp_path):
    # Runs that share a start time straddle the per-goal cut-off here. The batch
    # must keep the same runs list_episodes(goal_id=..., limit=...) keeps.
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "w.db")
    goals = [world.create_goal(f"tied {i}", owner="user:alice") for i in range(2)]
    with world._writing() as conn:
        for index in range(90):
            conn.execute(
                "INSERT INTO episodes(goal_id, started_at, cost_dollars) VALUES (?, ?, ?)",
                (goals[index % 2], 5_000.0 + index // 15, 0.01),
            )
    for per_goal in (7, 0, -1):   # 0 and negative limits read as list_episodes reads them
        batch = world.episodes_by_goal(goals, per_goal=per_goal)
        for gid in goals:
            assert [e.id for e in batch[gid]] == [e.id for e in world.list_episodes(goal_id=gid, limit=per_goal)]
