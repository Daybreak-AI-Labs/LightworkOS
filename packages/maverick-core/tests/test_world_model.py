"""Tests for the world model (maverick.world_model): file permissions, processed
messages, orphan reclaim and connection lifecycle.
"""
from __future__ import annotations

import os
import stat

import pytest

# --- world.db must not be world/group readable ---

def test_world_db_permissions_locked(tmp_path):
    from maverick.world_model import WorldModel
    p = tmp_path / "w.db"
    wm = WorldModel(p)
    wm.close()
    mode = stat.S_IMODE(os.stat(p).st_mode)
    if os.name != "nt":  # POSIX mode bits aren't meaningful on NTFS
        assert mode & 0o077 == 0  # no group/other access


class TestWorldDBPerms:
    @pytest.mark.skipif(os.name != "posix", reason="POSIX perms")
    def test_db_file_created_0600(self, tmp_path):
        from maverick.world_model import open_world
        db = tmp_path / "world.db"
        w = open_world(db)
        try:
            mode = stat.S_IMODE(db.stat().st_mode)
            assert mode == 0o600, oct(mode)
        finally:
            w.close()


# ---------- channel idempotency ----------

def test_processed_messages_idempotent(tmp_path):
    """Twilio resend of the same MessageSid must not double-process."""
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "w.db")
    gid = wm.create_goal("g", "")

    first = wm.mark_message_processed("sms", "SM123", goal_id=gid)
    second = wm.mark_message_processed("sms", "SM123", goal_id=gid)
    third = wm.mark_message_processed("sms", "SM456", goal_id=gid)

    assert first is True
    assert second is False  # duplicate rejected
    assert third is True
    assert wm.lookup_processed_message("sms", "SM123") == gid
    assert wm.lookup_processed_message("sms", "missing") is None


def test_release_processed_message_allows_reclaim(tmp_path):
    """Channels claim the dedup row BEFORE running the goal (so a racing Twilio
    retry no-ops instead of double-spending). A failed run must release the
    claim so the retry can re-process -- not be deduped against a run that
    never completed."""
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "w.db")

    assert wm.mark_message_processed("sms", "SM-x") is True   # claim wins
    assert wm.mark_message_processed("sms", "SM-x") is False  # racing retry no-ops
    wm.release_processed_message("sms", "SM-x")               # the run failed
    assert wm.is_processed_message("sms", "SM-x") is False    # claim released
    assert wm.mark_message_processed("sms", "SM-x") is True   # retry can re-claim
    # Releasing a SID that was never claimed is a harmless no-op.
    wm.release_processed_message("sms", "never-seen")


# ---------- orphan reclaim ----------

def test_reclaim_orphan_goals(tmp_path):
    """Goals in 'active'/'pending' get reset to 'blocked' on startup.

    The default is max_age_seconds=60 so live goals in a sibling
    process aren't yanked out from under it. The test simulates a real
    crashed run by passing max_age_seconds=0 explicitly.
    """
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "w.db")
    a = wm.create_goal("a", "")
    b = wm.create_goal("b", "")
    c = wm.create_goal("c", "")
    wm.set_goal_status(a, "active")
    wm.set_goal_status(b, "done", result="ok")
    # c stays 'pending' (default)

    reclaimed = wm.reclaim_orphan_goals(max_age_seconds=0)
    assert reclaimed == 2  # a (active) + c (pending)

    assert wm.get_goal(a).status == "blocked"
    assert wm.get_goal(b).status == "done"  # untouched
    assert wm.get_goal(c).status == "blocked"


def test_reclaim_includes_goal_exactly_at_cutoff(tmp_path, monkeypatch):
    import maverick.world_model as world_model

    monkeypatch.setattr(world_model.time, "time", lambda: 1_000.0)
    wm = world_model.WorldModel(tmp_path / "equal-cutoff.db")
    goal_id = wm.create_goal("equal-cutoff", "")
    wm.set_goal_status(goal_id, "active")

    assert wm.reclaim_orphan_goals(max_age_seconds=0) == 1
    assert wm.get_goal(goal_id).status == "blocked"


def test_reclaim_orphan_goals_skips_recent(tmp_path):
    """Default max_age_seconds=60 protects goals from a sibling process."""
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "w.db")
    gid = wm.create_goal("live-in-sibling", "")
    wm.set_goal_status(gid, "active")

    # A startup hook with the default (60s) must NOT reclaim a goal
    # whose updated_at is current.
    reclaimed = wm.reclaim_orphan_goals()
    assert reclaimed == 0
    assert wm.get_goal(gid).status == "active"


# ---------- foreign keys enforced ----------

def test_foreign_keys_on(tmp_path):
    """PRAGMA foreign_keys=ON so REFERENCES clauses actually do something."""
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "w.db")
    row = wm.conn.execute("PRAGMA foreign_keys").fetchone()
    assert row[0] == 1


# ---------- Schema-version race on concurrent fresh-DB startup ----------

def test_schema_version_init_handles_concurrent_inserts(tmp_path, monkeypatch):
    """Two WorldModel constructions on the same fresh DB don't crash
    on the schema_version PRIMARY KEY collision."""
    from maverick.world_model import WorldModel

    db = tmp_path / "race.db"
    # First connection initializes.
    wm1 = WorldModel(db)
    # Second connection on the same DB must not raise IntegrityError
    # under the now-correct INSERT-OR-IGNORE check-then-insert path.
    wm2 = WorldModel(db)
    assert wm1.schema_version == wm2.schema_version


# ---------- is_processed_message distinguishes "seen" from "goal_id null" ----------

def test_is_processed_message_handles_null_goal_id(tmp_path):
    """SMS/WhatsApp commit with goal_id=None; is_processed_message
    must still return True for those rows."""
    from maverick.world_model import WorldModel

    wm = WorldModel(tmp_path / "w.db")
    wm.mark_message_processed("sms", "SMxyz", goal_id=None)

    # lookup returns 0 (sentinel for "row exists but goal_id is null")
    # vs None for "no row at all".
    assert wm.lookup_processed_message("sms", "SMxyz") == 0
    assert wm.lookup_processed_message("sms", "missing") is None
    # is_processed_message gives the unambiguous "have we seen this".
    assert wm.is_processed_message("sms", "SMxyz") is True
    assert wm.is_processed_message("sms", "missing") is False


# ---------- prune_processed_messages ----------

def test_prune_processed_messages(tmp_path):
    """Twilio dedup rows accumulate forever without explicit pruning."""
    import time as _time

    from maverick.world_model import WorldModel

    wm = WorldModel(tmp_path / "w.db")
    wm.mark_message_processed("sms", "SM1")
    wm.mark_message_processed("sms", "SM2")
    # Backdate SM1 to 60 days ago.
    wm.conn.execute(
        "UPDATE processed_messages SET seen_at = ? WHERE external_id = 'SM1'",
        (_time.time() - 60 * 24 * 3600,),
    )
    wm.conn.commit()
    removed = wm.prune_processed_messages(older_than_seconds=30 * 24 * 3600)
    assert removed == 1
    assert wm.is_processed_message("sms", "SM1") is False
    assert wm.is_processed_message("sms", "SM2") is True


# ---- WorldModel.close() ----

class TestWorldModelClose:
    def test_close_closes_connection(self, tmp_path):
        from maverick.world_model import WorldModel
        wm = WorldModel(tmp_path / "w.db")
        wm.close()
        # After close, queries raise sqlite3.ProgrammingError.
        import sqlite3
        with pytest.raises(sqlite3.ProgrammingError):
            wm.conn.execute("SELECT 1")

    def test_context_manager_closes(self, tmp_path):
        from maverick.world_model import WorldModel
        with WorldModel(tmp_path / "w.db") as wm:
            wm.create_goal("x", "")
        import sqlite3
        with pytest.raises(sqlite3.ProgrammingError):
            wm.conn.execute("SELECT 1")


def test_an_interrupted_write_is_rolled_back_not_left_for_the_next_write(tmp_path):
    from maverick.world_model import WorldModel

    wm = WorldModel(tmp_path / "w.db")
    try:
        with pytest.raises(KeyboardInterrupt):
            with wm._writing() as conn:
                conn.execute("INSERT INTO episodes(goal_id, started_at) VALUES (NULL, 1.0)")
                raise KeyboardInterrupt
        assert not wm.conn.in_transaction
        assert wm.conn.execute("SELECT COUNT(*) FROM episodes").fetchone()[0] == 0
    finally:
        wm.close()
