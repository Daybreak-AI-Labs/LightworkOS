"""Collaborative supervision: approval claiming + decider attribution
(world-model semantics, SQLite backend)."""
from __future__ import annotations

import pytest
from maverick.world_model import open_world


def _world(tmp_path):
    return open_world(tmp_path / "world.db")


def _park(w):
    return w.create_approval("wire_transfer", risk="high", scope="acct-1",
                             detail="$5k to vendor")


def test_claim_release_lifecycle(tmp_path):
    w = _world(tmp_path)
    aid = _park(w)
    assert w.claim_approval(aid, "alice") is True
    a = w.get_approval(aid)
    assert a.claimed_by == "alice" and a.claimed_at is not None
    # Someone else can't steal the claim...
    assert w.claim_approval(aid, "bob") is False
    # ...but alice re-claiming her own is a no-op refresh.
    assert w.claim_approval(aid, "alice") is True
    # Only the holder releases.
    assert w.release_approval(aid, "bob") is False
    assert w.release_approval(aid, "alice") is True
    assert w.get_approval(aid).claimed_by is None
    # Now bob can claim.
    assert w.claim_approval(aid, "bob") is True


def test_decided_by_attribution(tmp_path):
    w = _world(tmp_path)
    aid = _park(w)
    assert w.decide_approval(aid, "approved", decided_by="alice") is True
    a = w.get_approval(aid)
    assert a.status == "approved" and a.decided_by == "alice"
    # Legacy unattributed call still works on a fresh row.
    aid2 = _park(w)
    assert w.decide_approval(aid2, "denied") is True
    assert w.get_approval(aid2).decided_by is None


def test_decided_rows_unclaimable(tmp_path):
    w = _world(tmp_path)
    aid = _park(w)
    w.decide_approval(aid, "denied", decided_by="alice")
    assert w.claim_approval(aid, "bob") is False


def test_claim_validation(tmp_path):
    w = _world(tmp_path)
    aid = _park(w)
    with pytest.raises(ValueError):
        w.claim_approval(aid, "  ")
    with pytest.raises(ValueError):
        w.release_approval(aid, "")
    assert w.claim_approval(99999, "alice") is False


def test_pending_listing_carries_claims(tmp_path):
    w = _world(tmp_path)
    aid = _park(w)
    w.claim_approval(aid, "alice")
    pending = {a.id: a for a in w.pending_approvals()}
    assert pending[aid].claimed_by == "alice"


def test_migration_on_existing_v12_db(tmp_path):
    """A pre-claiming DB upgrades in place: v13 columns appear, rows intact."""
    import sqlite3

    import maverick.world_model as wm
    db = tmp_path / "old.db"
    w = open_world(db)
    aid = _park(w)
    w.close() if hasattr(w, "close") else None
    # Simulate a v12 database: drop the v13 columns + reset user_version.
    conn = sqlite3.connect(db)
    for col in ("claimed_by", "claimed_at", "decided_by"):
        conn.execute(f"ALTER TABLE approvals DROP COLUMN {col}")
    # The runner tracks its own schema_version TABLE (not PRAGMA user_version).
    conn.execute("UPDATE schema_version SET version = 12")
    conn.commit()
    conn.close()
    w2 = wm.WorldModel(db)  # reopen -> migration 13 runs
    assert w2.claim_approval(aid, "alice") is True
    assert w2.get_approval(aid).claimed_by == "alice"
