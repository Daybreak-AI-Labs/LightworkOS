"""Cost split by tag."""
from __future__ import annotations

from maverick.cost.by_tag import gather, render, split_by_tag
from maverick.world_model import EpisodeSpend


class _FakeWorld:
    def __init__(self, episodes):
        self._eps = episodes

    def list_episodes(self, *, limit=500):
        return self._eps[:limit]


def test_gather_reads_real_episode_token_fields():
    # Regression: gather() read in_tokens/out_tokens, but EpisodeSpend exposes
    # input_tokens/output_tokens -- so every real episode reported 0 tokens in
    # the chargeback export. It must read the real fields.
    ep = EpisodeSpend(
        id=1, goal_id=7, started_at=0.0, ended_at=1.0, outcome="done",
        cost_dollars=2.5, input_tokens=1200, output_tokens=340, tool_calls=3,
    )
    ep.tag = "acme"
    rows = gather(_FakeWorld([ep]))
    assert rows == [{"tag": "acme", "cost": 2.5, "in_tok": 1200, "out_tok": 340}]


def test_private_tag_field_is_not_read_from_the_episode():
    # GET /cost/by-tag passes tag_field from the query string; "__dict__"
    # returned the episode row's repr as its tag.
    ep = EpisodeSpend(
        id=1, goal_id=7, started_at=0.0, ended_at=1.0, outcome="done",
        cost_dollars=2.5, input_tokens=1, output_tokens=1, tool_calls=0,
    )
    rows = gather(_FakeWorld([ep]), tag_field="__dict__")
    assert rows[0]["tag"] == ""


def test_split_groups_and_sorts_by_cost():
    rows = [
        {"tag": "acme", "cost": 1.0, "in_tok": 100, "out_tok": 50},
        {"tag": "beta", "cost": 3.0, "in_tok": 200, "out_tok": 80},
        {"tag": "acme", "cost": 0.5, "in_tok": 10, "out_tok": 5},
    ]
    out = split_by_tag(rows)
    assert [b["tag"] for b in out] == ["beta", "acme"]  # cost desc
    acme = next(b for b in out if b["tag"] == "acme")
    assert acme["cost"] == 1.5
    assert acme["in_tok"] == 110
    assert acme["runs"] == 2


def test_missing_tag_goes_to_untagged():
    out = split_by_tag([{"cost": 2.0}, {"tag": "  ", "cost": 1.0}])
    assert len(out) == 1
    assert out[0]["tag"] == "(untagged)"
    assert out[0]["cost"] == 3.0


def test_non_numeric_cost_counts_as_zero():
    out = split_by_tag([{"tag": "x", "cost": "oops"}])
    assert out[0]["cost"] == 0.0
    assert out[0]["runs"] == 1


class _Ep:
    def __init__(self, cost, gid=None, tag=None, in_t=0, out_t=0):
        self.cost_dollars = cost
        self.goal_id = gid
        self.in_tokens = in_t
        self.out_tokens = out_t
        if tag is not None:
            self.tag = tag


class _Goal:
    def __init__(self, metadata=None, tags=None):
        self.metadata = metadata or {}
        self.tags = tags or []


class _World:
    def __init__(self, eps, goals):
        self._eps = eps
        self._goals = goals

    def list_episodes(self, limit=500):
        return self._eps

    def get_goal(self, gid):
        return self._goals.get(gid)


def test_gather_reads_tag_from_episode_then_goal():
    eps = [
        _Ep(1.0, tag="direct"),
        _Ep(2.0, gid=7),       # tag from goal metadata
        _Ep(0.0, tag="free"),  # zero cost dropped
    ]
    world = _World(eps, {7: _Goal(metadata={"tag": "from-goal"})})
    rows = gather(world)
    tags = sorted(r["tag"] for r in rows)
    assert tags == ["direct", "from-goal"]
    assert render(split_by_tag(rows)).startswith("tag")


def test_owner_episodes_in_one_query_match_the_per_goal_reads(tmp_path, monkeypatch):
    # One owner-scoped query must return the rows the per-goal reads returned
    # (newest goal first, newest run first, 500 raw rows), and tagging must not
    # decrypt goal rows: the shipped Goal carries no tags to read.
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "w.db")
    alice = [world.create_goal(f"alice {i}", owner="user:alice") for i in range(3)]
    bob = world.create_goal("bob", owner="user:bob")
    with world._writing() as conn:
        for index in range(600):
            goal = bob if index % 10 == 0 else alice[index % 3]
            conn.execute(
                "INSERT INTO episodes(goal_id, started_at, cost_dollars, input_tokens, "
                "output_tokens) VALUES (?, ?, ?, ?, ?)",
                (goal, 1_000.0 + index, 0.0 if index % 4 == 0 else 0.01 * (index % 7 + 1),
                 index, index % 9),
            )
    goal_ids = [g.id for g in world.list_goals(owner="user:alice", limit=10_000, order="desc")]
    reference = split_by_tag(gather(world, limit=500, goal_ids=goal_ids))
    scoped = world.episodes_for_owner_goals("user:alice", limit=500)
    assert len(scoped) == 500
    assert [(e.goal_id, e.started_at) for e in scoped] == sorted(
        [(e.goal_id, e.started_at) for e in scoped], key=lambda t: (-t[0], -t[1]))
    assert split_by_tag(gather(world, episodes=scoped)) == reference
    assert reference and all(b["runs"] > 0 for b in reference)

    reads = []
    real_get_goal = WorldModel.get_goal
    monkeypatch.setattr(WorldModel, "get_goal",
                        lambda self, goal_id: reads.append(goal_id) or real_get_goal(self, goal_id))
    gather(world, episodes=scoped)
    assert reads == []

