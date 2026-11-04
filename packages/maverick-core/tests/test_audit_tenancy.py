"""Data plane: the audit log is tenant-isolated via ``maverick.paths``.

Completes the cross-session-memory increment by routing the audit dir AND the
signing-key dir through the tenant-aware ``data_dir`` helper. With no tenant the
paths stay EXACTLY the legacy ``~/.maverick/audit/...`` (single-tenant
unchanged); with a tenant active each tenant gets its own, self-consistent
Ed25519/Merkle chain under ``~/.maverick/tenants/<t>/audit/...``.

The on-disk format and chain semantics are unchanged -- only *where* the
directory is resolved. These tests reuse the existing ``verify_chain`` API.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from maverick.audit.events import AuditEvent, EventKind
from maverick.audit.writer import AuditLog, default_audit_log, record, record_global
from maverick.paths import reset_tenant, set_tenant


def _reset_default_logs(monkeypatch):
    import maverick.audit.writer as writer

    monkeypatch.setattr(writer, "_default", None)
    monkeypatch.setattr(writer, "_defaults", {})


def _event(title: str) -> AuditEvent:
    # A fixed UTC timestamp keeps the day-file name stable across the test run.
    return AuditEvent(
        ts=1_000_000.0,
        kind=EventKind.GOAL_START,
        agent="system",
        goal_id=1,
        payload={"title": title, "description": None},
    )


def _today_file(audit_dir):
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return audit_dir / f"{day}.ndjson"


# --- no tenant: paths stay EXACTLY the legacy location ----------------------

def test_audit_dir_no_tenant_is_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    log = AuditLog()
    assert log.audit_dir == tmp_path / ".maverick" / "audit"
    assert "tenants" not in log.audit_dir.parts


def test_default_audit_log_no_tenant_is_legacy(monkeypatch, tmp_path):
    # The module singleton also resolves the legacy dir when no tenant is set.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _reset_default_logs(monkeypatch)
    assert default_audit_log().audit_dir == tmp_path / ".maverick" / "audit"


def test_key_dir_no_tenant_is_legacy(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit import signing

    assert signing._key_dir() == tmp_path / ".maverick" / "audit" / "keys"


# --- a tenant gets its own audit dir + key dir -----------------------------

def test_audit_dir_follows_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.audit import signing

    tok = set_tenant("acme")
    try:
        assert AuditLog().audit_dir == (
            tmp_path / ".maverick" / "tenants" / "acme" / "audit"
        )
        assert signing._key_dir() == (
            tmp_path / ".maverick" / "tenants" / "acme" / "audit" / "keys"
        )
    finally:
        reset_tenant(tok)


def test_records_land_under_tenant_dir(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    tok = set_tenant("acme")
    try:
        log = AuditLog()
        assert log.record(_event("acme goal"))
    finally:
        reset_tenant(tok)

    tenant_file = _today_file(tmp_path / ".maverick" / "tenants" / "acme" / "audit")
    assert tenant_file.exists()
    assert "acme goal" in tenant_file.read_text()
    # Nothing leaked into the legacy single-tenant location.
    assert not _today_file(tmp_path / ".maverick" / "audit").exists()


def test_global_control_record_bypasses_active_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _reset_default_logs(monkeypatch)
    token = set_tenant("acme")
    try:
        assert record_global(
            EventKind.LEARNING_CONTROL_CHANGED,
            control="self_modify",
            enabled=True,
            acknowledged=True,
        )
    finally:
        reset_tenant(token)
    global_file = _today_file(tmp_path / "audit")
    tenant_file = _today_file(tmp_path / "tenants" / "acme" / "audit")
    assert global_file.exists()
    assert "self_modify" in global_file.read_text(encoding="utf-8")
    assert not tenant_file.exists()


# --- signed chain still verifies per tenant --------------------------------

def test_signed_chain_verifies_for_tenant(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    from maverick.audit.signing import verify_chain

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    # Sign + verify within the tenant scope: the per-tenant signing key lives
    # under the tenant's own dir, so verification resolves it via the active
    # tenant -- exactly how a tenant-scoped run reads back its own chain.
    tok = set_tenant("acme")
    try:
        log = AuditLog(sign=True)
        assert log.record(_event("one"))
        assert log.record(_event("two"))
        day_file = _today_file(log.audit_dir)
        assert day_file.exists()
        assert verify_chain(day_file) == []  # signed chain intact for this tenant
    finally:
        reset_tenant(tok)


# --- two tenants are isolated ----------------------------------------------

def test_two_tenants_are_isolated(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    from maverick.audit.signing import verify_chain

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)

    acme_dir = tmp_path / ".maverick" / "tenants" / "acme" / "audit"
    globex_dir = tmp_path / ".maverick" / "tenants" / "globex" / "audit"

    tok = set_tenant("acme")
    try:
        AuditLog(sign=True).record(_event("acme-only secret"))
        # Each tenant's chain verifies within its own scope (key is per-tenant).
        assert verify_chain(_today_file(acme_dir)) == []
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        AuditLog(sign=True).record(_event("globex-only secret"))
        assert verify_chain(_today_file(globex_dir)) == []
    finally:
        reset_tenant(tok)

    acme_text = _today_file(acme_dir).read_text()
    globex_text = _today_file(globex_dir).read_text()

    # Each tenant sees only its own events -- no cross-tenant leakage.
    assert "acme-only secret" in acme_text
    assert "acme-only secret" not in globex_text
    assert "globex-only secret" in globex_text
    assert "globex-only secret" not in acme_text


def test_default_audit_log_is_cached_per_tenant(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _reset_default_logs(monkeypatch)

    acme_dir = tmp_path / ".maverick" / "tenants" / "acme" / "audit"
    globex_dir = tmp_path / ".maverick" / "tenants" / "globex" / "audit"

    tok = set_tenant("acme")
    try:
        acme_log = default_audit_log()
        assert acme_log.audit_dir == acme_dir
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        globex_log = default_audit_log()
        assert globex_log.audit_dir == globex_dir
    finally:
        reset_tenant(tok)

    tok = set_tenant("acme")
    try:
        assert default_audit_log() is acme_log
    finally:
        reset_tenant(tok)
    assert globex_log is not acme_log


def test_module_record_is_tenant_isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    _reset_default_logs(monkeypatch)

    acme_dir = tmp_path / ".maverick" / "tenants" / "acme" / "audit"
    globex_dir = tmp_path / ".maverick" / "tenants" / "globex" / "audit"

    tok = set_tenant("acme")
    try:
        assert record(EventKind.GOAL_START, goal_id=1, title="acme-only secret")
    finally:
        reset_tenant(tok)

    tok = set_tenant("globex")
    try:
        assert record(EventKind.GOAL_START, goal_id=2, title="globex-only secret")
    finally:
        reset_tenant(tok)

    acme_text = _today_file(acme_dir).read_text()
    globex_text = _today_file(globex_dir).read_text()

    assert "acme-only secret" in acme_text
    assert "acme-only secret" not in globex_text
    assert "globex-only secret" in globex_text
    assert "globex-only secret" not in acme_text
    assert not _today_file(tmp_path / ".maverick" / "audit").exists()
