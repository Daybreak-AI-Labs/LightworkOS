"""Watch glance: tiny fixed payload from world + spend ledger."""
from __future__ import annotations

import json

from maverick.glance import build_glance
from maverick.world_model import WorldModel


def test_glance_shape_and_counts(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    w = WorldModel(tmp_path / "world.db")
    a = w.create_goal("active goal", "")
    w.set_goal_status(a, "active")
    d = w.create_goal("done goal", "")
    w.set_goal_status(d, "done", result="all wrapped up")
    f = w.create_goal("failed goal", "")
    w.set_goal_status(f, "failed", result="boom")
    g = build_glance(w)
    assert set(g) == {"active", "done_today", "failed_today", "spend_today",
                      "last_result", "as_of"}
    assert g["active"] == 1
    assert g["done_today"] == 1 and g["failed_today"] == 1
    assert g["last_result"] in ("all wrapped up", "boom")
    json.dumps(g)
    w.close()


def test_glance_bounded_last_result(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    w = WorldModel(tmp_path / "world.db")
    gid = w.create_goal("g", "")
    w.set_goal_status(gid, "done", result="x" * 500)
    assert len(build_glance(w)["last_result"]) == 60
    w.close()


def test_glance_includes_spend(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    from maverick.quotas import UsageLedger
    UsageLedger().record("user:a", 1.25, 1, 1)
    UsageLedger().record("user:b", 0.75, 1, 1)
    w = WorldModel(tmp_path / "world.db")
    assert build_glance(w)["spend_today"] == 2.0
    w.close()


def test_glance_scopes_goals_and_spend_by_owner(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    from maverick.quotas import UsageLedger

    UsageLedger().record("user:alice", 1.25, 1, 1)
    UsageLedger().record("user:bob", 9.75, 1, 1)
    w = WorldModel(tmp_path / "world.db")
    alice = w.create_goal("alice done", "", owner="user:alice")
    w.set_goal_status(alice, "done", result="ALICE_ONLY_RESULT")
    bob = w.create_goal("bob done", "", owner="user:bob")
    w.set_goal_status(bob, "done", result="BOB_SECRET_RESULT")

    g = build_glance(w, owner="user:alice")

    assert g["done_today"] == 1
    assert g["spend_today"] == 1.25
    assert g["last_result"] == "ALICE_ONLY_RESULT"
    w.close()


def test_glance_empty_world(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    w = WorldModel(tmp_path / "world.db")
    g = build_glance(w)
    assert g["active"] == 0 and g["last_result"] == ""
    w.close()


class _FullScan:
    """The pre-change read: every goal decrypted through list_goals."""

    def __init__(self, world):
        self._world = world

    def list_goals(self, **kwargs):
        return self._world.list_goals(**kwargs)

    def get_goal(self, goal_id):
        return self._world.get_goal(goal_id)


def test_glance_counts_match_a_full_scan_and_decrypt_one_goal(tmp_path, monkeypatch):
    import time

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    w = WorldModel(tmp_path / "world.db")
    for title, owner, status, result in (
        ("alpha", "user:alice", "active", None),
        ("beta", "user:alice", "pending", None),
        ("gamma", "user:alice", "done", "gamma wrapped"),
        ("delta", "user:alice", "failed", "delta broke"),
        ("epsilon", "user:bob", "done", "bob's result"),
    ):
        gid = w.create_goal(title, "", owner=owner)
        w.set_goal_status(gid, status, result=result)
    now = time.time()
    expected = {
        owner: build_glance(_FullScan(w), now=now, owner=owner)
        for owner in (None, "user:alice")
    }
    assert build_glance(w, now=now) == expected[None]
    assert build_glance(w, now=now, owner="user:alice") == expected["user:alice"]
    assert expected[None]["active"] == 2 and expected[None]["done_today"] == 2

    def no_full_decrypt(self, **kwargs):
        raise AssertionError("glance must not decrypt every goal")

    reads = []
    real_get_goal = WorldModel.get_goal
    monkeypatch.setattr(WorldModel, "list_goals", no_full_decrypt)
    monkeypatch.setattr(WorldModel, "get_goal",
                        lambda self, goal_id: reads.append(goal_id) or real_get_goal(self, goal_id))
    build_glance(w, now=now)
    assert len(reads) == 1
    w.close()

