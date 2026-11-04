"""Forward ledger: goals due soon, with their open questions."""
from __future__ import annotations

from maverick.forward_ledger import upcoming
from maverick.world_model import WorldModel


class _ScanWorld:
    """The pre-change read: every goal decrypted through list_goals, then filtered."""

    def __init__(self, world):
        self._world = world

    def list_goals(self, **kwargs):
        return self._world.list_goals(**kwargs)

    def open_questions(self, goal_id):
        return self._world.open_questions(goal_id)


def test_upcoming_matches_a_full_scan_and_decodes_only_due_goals(tmp_path, monkeypatch):
    now = 1_800_000_000.0
    w = WorldModel(tmp_path / "w.db")
    specs = [
        ("due soon", "alice", "active", now + 3600),
        ("overdue", "alice", "pending", now - 86400),
        ("later", "alice", "active", now + 90 * 86400),
        ("no deadline", "alice", "pending", None),
        ("finished", "alice", "done", now + 3600),
        ("bob's due", "bob", "pending", now + 60),
    ]
    for title, owner, status, deadline in specs:
        gid = w.create_goal(title, "", owner=f"user:{owner}")
        w.set_goal_status(gid, status)
        if deadline is not None:
            with w._writing() as conn:
                conn.execute("UPDATE goals SET deadline = ? WHERE id = ?", (deadline, gid))
    for owner in (None, "user:alice"):
        expected = upcoming(_ScanWorld(w), now=now, owner=owner)
        got = upcoming(w, now=now, owner=owner)
        assert [(o.goal.id, o.goal.title, o.deadline, o.open_questions) for o in got] == [
            (o.goal.id, o.goal.title, o.deadline, o.open_questions) for o in expected]
    titles = [o.goal.title for o in upcoming(w, now=now, owner="user:alice")]
    assert titles == ["overdue", "due soon"]

    def no_full_decrypt(self, **kwargs):
        raise AssertionError("upcoming must not decrypt every goal")

    monkeypatch.setattr(WorldModel, "list_goals", no_full_decrypt)
    assert [o.goal.title for o in upcoming(w, now=now, owner="user:alice")] == titles
    w.close()
