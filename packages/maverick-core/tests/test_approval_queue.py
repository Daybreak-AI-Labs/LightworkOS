"""Approval queue: world-model persistence + consent dashboard mode."""
from __future__ import annotations

import threading

from maverick.world_model import SCHEMA_VERSION, WorldModel


def test_schema_has_approvals_table(tmp_path):
    wm = WorldModel(path=tmp_path / "world.db")
    assert wm.schema_version == SCHEMA_VERSION
    # The approvals table exists and is queryable.
    assert wm.pending_approvals() == []


def test_create_and_decide_approval(tmp_path):
    wm = WorldModel(path=tmp_path / "world.db")
    aid = wm.create_approval("rm-rf", risk="high", scope="/tmp/build", detail="wipe build dir")
    row = wm.get_approval(aid)
    assert row is not None
    assert row.status == "pending"
    assert row.action == "rm-rf"
    assert row.risk == "high"
    assert row.scope == "/tmp/build"
    assert row.provenance is None
    assert [a.id for a in wm.pending_approvals()] == [aid]

    # Approve transitions state; the row leaves the pending queue.
    assert wm.decide_approval(aid, "approved") is True
    assert wm.get_approval(aid).status == "approved"
    assert wm.get_approval(aid).decided_at is not None
    assert wm.pending_approvals() == []

    # Deciding again is a no-op (already decided).
    assert wm.decide_approval(aid, "denied") is False
    assert wm.get_approval(aid).status == "approved"



def test_create_approval_preserves_trusted_provenance(tmp_path):
    wm = WorldModel(path=tmp_path / "world.db")
    aid = wm.create_approval(
        "shell", risk="high", detail="operator review", provenance="governance"
    )

    row = wm.get_approval(aid)
    assert row is not None
    assert row.provenance == "governance"
    assert wm.pending_approvals()[0].provenance == "governance"

def test_decide_unknown_approval_returns_false(tmp_path):
    wm = WorldModel(path=tmp_path / "world.db")
    assert wm.decide_approval(9999, "approved") is False


def test_consent_dashboard_mode_blocks_until_decided(tmp_path, monkeypatch):
    """In dashboard mode require_consent parks a pending approval and
    polls until the dashboard flips it -> the decision reflects that."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    # Speed up the poll loop's deadline; the decider runs well within it.
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "10")

    db = tmp_path / ".maverick" / "world.db"
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)

    from maverick.safety.consent import require_consent

    # A background thread approves the (only) pending approval shortly after.
    def _approver():
        wm = WorldModel(path=db)
        for _ in range(100):
            pending = wm.pending_approvals()
            if pending:
                wm.decide_approval(
                    pending[0].id, "approved", decided_by="user:operator"
                )
                return
            import time as _t
            _t.sleep(0.05)

    t = threading.Thread(target=_approver)
    t.start()
    d = require_consent("mass-dm", risk="high", scope="channel:#general")
    t.join(timeout=10)

    assert d.granted is True
    assert d.source == "dashboard"
    assert d.actor == "user:operator"


def test_consent_dashboard_mode_denied(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONSENT_MODE", "dashboard")
    monkeypatch.setenv("MAVERICK_CONSENT_DASHBOARD_TIMEOUT", "10")
    db = tmp_path / ".maverick" / "world.db"
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", db)

    from maverick.safety.consent import ConsentDenied, require_consent

    def _denier():
        wm = WorldModel(path=db)
        for _ in range(100):
            pending = wm.pending_approvals()
            if pending:
                wm.decide_approval(pending[0].id, "denied")
                return
            import time as _t
            _t.sleep(0.05)

    t = threading.Thread(target=_denier)
    t.start()
    try:
        require_consent("force-push", risk="high", raise_on_deny=True)
        raise AssertionError("expected ConsentDenied")
    except ConsentDenied as e:
        assert e.action == "force-push"
    finally:
        t.join(timeout=10)
