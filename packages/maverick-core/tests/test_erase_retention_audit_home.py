"""Erase and retention must act on the audit dir the writer actually uses.

The writer resolves ``data_dir("audit")`` at call time (home- and
tenant-aware). If ``scrub_user``/``delete_user`` (erase) and
``purge_audit_files``/``enforce`` (retention) defaulted ``audit_dir`` to a
module-import-time ``~/.maverick/audit``, then whenever ``MAVERICK_HOME`` or an
active tenant moved the real audit files elsewhere, erase would report success
while scrubbing nothing (an Art. 17 gap) and retention would report "no audit
dir". These pin that both resolve the writer's dir.
"""
from __future__ import annotations

from maverick.audit import erase, retention
from maverick.audit.writer import AuditLog
from maverick.paths import data_dir


def _seed(n_alice: int = 3) -> None:
    """Write a real signed audit chain at the active scope's audit dir."""
    log = AuditLog(data_dir("audit"), sign=True)
    from maverick.audit.events import AuditEvent
    for i in range(n_alice):
        log.record(AuditEvent(ts=1.0 + i, kind="tool_call", agent="a", goal_id=1,
                              payload={"channel": "telegram", "user_id": "alice999",
                                       "input_summary": f"hi {i}"}))
    log.record(AuditEvent(ts=9.0, kind="tool_call", agent="a", goal_id=1,
                          payload={"channel": "telegram", "user_id": "bob123",
                                   "input_summary": "hey"}))


def test_erase_scrubs_under_maverick_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _seed()
    audit_dir = data_dir("audit")
    assert "alice999" in "\n".join(p.read_text() for p in audit_dir.glob("*.ndjson"))

    # No explicit audit_dir: must resolve the SAME home-aware dir, not the
    # frozen ~/.maverick/audit (which would scrub 0 and "succeed").
    matched, scanned = erase.scrub_user("telegram", "alice999")
    after = "\n".join(p.read_text() for p in audit_dir.glob("*.ndjson"))
    assert matched == 3, (matched, scanned)
    assert "alice999" not in after          # subject genuinely scrubbed
    assert "bob123" in after                # other subjects untouched


def test_erase_scrubs_under_active_tenant(tmp_path, monkeypatch):
    # The insidious case: no MAVERICK_HOME, but an active tenant scopes the
    # audit dir to tenants/<t>/audit -- the frozen default never saw it.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    _seed()
    tenant_audit = data_dir("audit")
    assert "tenants" in str(tenant_audit) and "acme" in str(tenant_audit)

    deleted, _ = erase.delete_user("telegram", "alice999")
    after = "\n".join(p.read_text() for p in tenant_audit.glob("*.ndjson"))
    assert deleted == 3
    assert "alice999" not in after and "bob123" in after


def test_retention_finds_audit_dir_under_maverick_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _seed()
    # No explicit audit_dir: must see the home-aware dir, not report "no audit
    # dir". today's file is recent, so a 1-day window keeps it (kept >= 1).
    rep = retention.purge_audit_files(days=1, dry_run=True)
    assert rep.get("reason") != "no audit dir"
    assert rep.get("kept", 0) >= 1

    # enforce() passes its (None) audit_dir through to purge_audit_files.
    full = retention.enforce(config={"audit_days": 1}, dry_run=True)
    assert full.get("audit", {}).get("reason") != "no audit dir"
