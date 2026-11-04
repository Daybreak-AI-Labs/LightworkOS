"""search_goals: text search across runs, owner-scoped, encryption-aware."""
from __future__ import annotations

from maverick.world_model import WorldModel


def test_search_matches_title_and_description(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g1 = w.create_goal("Deploy the billing service", "rollout to prod")
    g2 = w.create_goal("Write quarterly report", "finance summary")
    w.create_goal("unrelated chore", "")

    assert [g.id for g in w.search_goals("billing")] == [g1]
    assert g2 in [g.id for g in w.search_goals("finance")]
    # encrypted-at-rest fields are still searchable (decrypt-then-filter)
    assert [g.id for g in w.search_goals("BILLING")] == [g1]  # case-insensitive


def test_search_owner_scoped(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    g1 = w.create_goal("Deploy billing service", "x", owner="alice")
    w.create_goal("Deploy billing service", "y", owner="bob")

    assert [g.id for g in w.search_goals("billing", owner="alice")] == [g1]
    assert "bob" in {g.owner for g in w.search_goals("billing", owner="bob")}
    assert len(w.search_goals("billing")) == 2  # owner=None -> all


def test_search_empty_query_and_limit(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    for i in range(5):
        w.create_goal(f"alpha task {i}", "")
    assert w.search_goals("") == []
    assert len(w.search_goals("alpha", limit=2)) == 2
    assert "no" not in w.search_goals("definitely-absent-token") and \
        w.search_goals("definitely-absent-token") == []
