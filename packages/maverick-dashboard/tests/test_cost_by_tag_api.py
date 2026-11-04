"""The cost-attribution API buckets episode spend by tag."""
from __future__ import annotations

import types

from fastapi.testclient import TestClient
from maverick_dashboard import app as app_mod
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


class _Ep:
    def __init__(self, goal_id, cost, tag=None, in_tok=10, out_tok=5):
        self.goal_id = goal_id
        self.cost_dollars = cost
        self.in_tokens = in_tok
        self.out_tokens = out_tok
        if tag is not None:
            self.tag = tag


class _FakeWorld:
    def __init__(self):
        self._eps = [
            _Ep(1, 0.50, tag="team-a"),
            _Ep(1, 0.25, tag="team-a"),
            _Ep(2, 0.40, tag="team-b"),
            _Ep(3, 0.10),  # untagged
        ]

    def list_goals(self, *, owner, limit, order):
        assert owner == "" and limit == 10_000 and order == "desc"
        return [self.get_goal(gid) for gid in (1, 2, 3)]

    def list_episodes(self, limit=500, goal_id=None):
        assert goal_id in (1, 2, 3)  # never read another employee's episodes
        return [ep for ep in self._eps if ep.goal_id == goal_id][:limit]

    def get_goal(self, gid):
        return types.SimpleNamespace(id=gid, owner="", metadata=None, tags=None)


def test_cost_by_tag_buckets(monkeypatch):
    monkeypatch.setattr(app_mod, "_world", lambda: _FakeWorld())
    r = client.get("/api/v1/cost/by-tag")
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["tag_field"] == "tag"
    buckets = {b["tag"]: b for b in data["buckets"]}
    assert buckets["team-a"]["cost"] == 0.75 and buckets["team-a"]["runs"] == 2
    assert buckets["team-b"]["cost"] == 0.40
    assert "(untagged)" in buckets
    # Sorted by spend: team-a first.
    assert data["buckets"][0]["tag"] == "team-a"


def test_cost_by_tag_limit_clamped(monkeypatch):
    seen = {}

    class _W(_FakeWorld):
        def list_episodes(self, limit=500, goal_id=None):
            seen["limit"] = limit
            return []

    monkeypatch.setattr(app_mod, "_world", lambda: _W())
    assert client.get("/api/v1/cost/by-tag?limit=999999").status_code == 200
    assert seen["limit"] == 10_000


def test_cost_by_tag_scopes_authenticated_owner(monkeypatch):
    class _OwnedWorld:
        def __init__(self):
            self.calls = []
            self._eps = {
                1: [_Ep(1, 1.25, tag="alice")],
                2: [_Ep(2, 9.50, tag="bob")],
            }

        def list_goals(self, owner=None, limit=None, order="asc"):
            assert owner == "user:alice"
            return [types.SimpleNamespace(id=1, owner="user:alice")]

        def list_episodes(self, limit=500, goal_id=None):
            self.calls.append((limit, goal_id))
            if goal_id is None:
                return [ep for eps in self._eps.values() for ep in eps]
            return self._eps.get(goal_id, [])[:limit]

        def get_goal(self, gid):
            return types.SimpleNamespace(id=gid, owner="user:alice" if gid == 1 else "user:bob", metadata=None, tags=None)

    world = _OwnedWorld()
    monkeypatch.setattr(app_mod, "_world", lambda: world)
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")

    r = client.get("/api/v1/cost/by-tag")

    assert r.status_code == 200, r.text
    buckets = {b["tag"]: b for b in r.json()["buckets"]}
    assert buckets == {
        "alice": {
            "tag": "alice",
            "cost": 1.25,
            "in_tok": 10,
            "out_tok": 5,
            "runs": 1,
        }
    }

    by_goal = client.get("/api/v1/cost/by-tag?tag_field=goal_id")
    assert by_goal.status_code == 200, by_goal.text
    assert {b["tag"] for b in by_goal.json()["buckets"]} == {"1"}
    assert world.calls == [(500, 1), (500, 1)]


def test_cost_by_tag_owner_scope_matches_the_per_goal_path(tmp_path, monkeypatch):
    from maverick.cost.by_tag import gather, split_by_tag
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "w.db")
    alice = world.create_goal("alice run", owner="user:alice")
    bob = world.create_goal("bob run", owner="user:bob")
    with world._writing() as conn:
        for goal, started, cost in ((alice, 1.0, 0.5), (alice, 2.0, 0.25), (bob, 3.0, 9.0)):
            conn.execute(
                "INSERT INTO episodes(goal_id, started_at, cost_dollars, input_tokens, "
                "output_tokens) VALUES (?, ?, ?, ?, ?)",
                (goal, started, cost, 10, 5),
            )
    monkeypatch.setattr(app_mod, "_world", lambda: world)
    monkeypatch.setattr(app_mod, "goal_owner_filter", lambda request: "user:alice")

    body = client.get("/api/v1/cost/by-tag").json()
    ids = [g.id for g in world.list_goals(owner="user:alice", limit=10_000, order="desc")]
    assert body["buckets"] == split_by_tag(gather(world, limit=500, goal_ids=ids))
    assert body["buckets"] == [
        {"tag": "(untagged)", "cost": 0.75, "in_tok": 20, "out_tok": 10, "runs": 2}
    ]

