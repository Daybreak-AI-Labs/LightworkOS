"""WorldModel spend reads can scope to one principal's runs (owner=) by joining
episodes to the owning goal — backing the dashboard /spend cross-user fix."""
from __future__ import annotations

from maverick.world_model import WorldModel


def _run(w: WorldModel, owner: str, cost: float) -> None:
    gid = w.create_goal("g", "d", owner=owner)
    eid = w.start_episode(gid)
    w.end_episode(eid, "done", "success", cost_dollars=cost,
                  input_tokens=10, output_tokens=5)


def test_total_spend_owner_scope(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    _run(w, "user:alice", 1.0)
    _run(w, "user:alice", 2.0)
    _run(w, "user:bob", 7.0)

    assert w.total_spend()["dollars"] == 10.0                 # admin / all
    assert w.total_spend(owner="user:alice")["dollars"] == 3.0
    assert w.total_spend(owner="user:bob")["dollars"] == 7.0
    assert w.total_spend(owner="user:nobody")["runs"] == 0
    w.close()


def test_list_episodes_owner_scope(tmp_path):
    w = WorldModel(tmp_path / "world.db")
    _run(w, "user:alice", 1.0)
    _run(w, "user:bob", 7.0)

    alice = w.list_episodes(owner="user:alice")
    assert len(alice) == 1 and alice[0].cost_dollars == 1.0
    assert len(w.list_episodes()) == 2  # unfiltered admin view
    w.close()
