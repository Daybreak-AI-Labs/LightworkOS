"""Multi-turn conversation state per channel user.

The same (channel, user_id) pair must map to the same conversation row
on every inbound message so the orchestrator can prepend prior turns
to the brief. Forward-only migrations must add the new tables without
disturbing existing data.
"""
from __future__ import annotations

import time

from maverick.world_model import SCHEMA_VERSION, WorldModel


def test_get_or_create_is_idempotent(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    c1 = wm.get_or_create_conversation("telegram", "user-42")
    c2 = wm.get_or_create_conversation("telegram", "user-42")
    assert c1.id == c2.id
    # last_seen advances on every touch.
    assert c2.last_seen >= c1.last_seen


def test_different_users_get_different_conversations(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    a = wm.get_or_create_conversation("telegram", "alice")
    b = wm.get_or_create_conversation("telegram", "bob")
    # Same channel != same conversation.
    assert a.id != b.id


def test_same_user_different_channels_separate_conversations(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    a = wm.get_or_create_conversation("telegram", "alice")
    b = wm.get_or_create_conversation("imessage", "alice")
    assert a.id != b.id


def test_append_and_recent_turns_chronological(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    c = wm.get_or_create_conversation("telegram", "alice")
    wm.append_turn(c.id, "user", "first")
    wm.append_turn(c.id, "assistant", "second")
    wm.append_turn(c.id, "user", "third")

    turns = wm.recent_turns(c.id, limit=10)
    assert [t.content for t in turns] == ["first", "second", "third"]
    # recent_turns returns chronological asc.
    assert turns[0].id < turns[-1].id


def test_recent_turns_limit_keeps_newest(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    c = wm.get_or_create_conversation("cli", "local")
    for i in range(5):
        wm.append_turn(c.id, "user", f"turn-{i}")
    # Asking for 2 returns the last 2 in chronological order.
    turns = wm.recent_turns(c.id, limit=2)
    assert [t.content for t in turns] == ["turn-3", "turn-4"]


def test_append_turn_rejects_unknown_role(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    c = wm.get_or_create_conversation("cli", "local")
    import pytest
    with pytest.raises(ValueError, match="role must be"):
        wm.append_turn(c.id, "system", "nope")


def test_list_and_prune(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    fresh = wm.get_or_create_conversation("telegram", "fresh-user")
    stale = wm.get_or_create_conversation("telegram", "stale-user")
    wm.append_turn(stale.id, "user", "old message")
    # Backdate the stale row.
    wm.conn.execute(
        "UPDATE conversations SET last_seen = ? WHERE id = ?",
        (time.time() - 100 * 24 * 3600, stale.id),
    )
    wm.conn.commit()

    convs = wm.list_conversations()
    assert {c.id for c in convs} == {fresh.id, stale.id}

    removed = wm.prune_conversations(idle_for_seconds=30 * 24 * 3600)
    assert removed == 1
    convs = wm.list_conversations()
    assert {c.id for c in convs} == {fresh.id}
    # The stale conversation's turns are gone too.
    assert wm.recent_turns(stale.id) == []


def test_conversations_and_turns_tables_present(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    assert wm.schema_version == SCHEMA_VERSION
    assert wm.schema_version >= 4
    tables = {
        r[0] for r in wm.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "conversations" in tables
    assert "turns" in tables
