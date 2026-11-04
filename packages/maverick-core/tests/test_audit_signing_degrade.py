"""Audit signing must FAIL CLOSED under a compliance floor when the `cryptography`
extra is missing -- it must never silently write unsigned rows while an operator
believes HIPAA-mode tamper-evidence is active. With
no floor it still degrades, but loudly (error, not a swallowed warning)."""
from __future__ import annotations

import logging

import maverick.audit.signing as signing
import maverick.audit.writer as writer
import maverick.compliance_profiles as compliance_profiles
import pytest
from maverick.audit.events import AuditEvent


def _force_missing_crypto(monkeypatch):
    """Make AuditSigner construction raise ImportError, as if `cryptography`
    (the audit-signing extra) were not installed."""
    def _boom(_path):
        raise ImportError("cryptography not installed")
    monkeypatch.setattr(signing, "AuditSigner", _boom)


def _event() -> AuditEvent:
    return AuditEvent(ts=1.0, kind="goal_start", agent="t", goal_id=None, payload={})


def test_degrade_is_loud_without_a_compliance_floor(tmp_path, monkeypatch, caplog):
    _force_missing_crypto(monkeypatch)
    monkeypatch.setattr(compliance_profiles, "requires_floor", lambda _floor: False)
    # Force signing on (the test suite disables secure-by-default via conftest).
    log = writer.AuditLog(tmp_path / "audit", sign=True)
    with caplog.at_level(logging.ERROR):
        ok = log.record(_event())
    assert ok is True  # no floor -> degrade gracefully to unsigned
    assert any(r.levelno >= logging.ERROR and "UNSIGNED" in r.getMessage()
               for r in caplog.records), "degrade must log at ERROR, not be silent"


@pytest.mark.parametrize(
    "failure",
    [ValueError("malformed chain tail"), OSError("audit key ACL denied")],
    ids=["corrupt-tail", "custody-failure"],
)
def test_non_dependency_signer_failure_never_downgrades_to_unsigned(
    tmp_path, monkeypatch, failure,
):
    def _boom(_path):
        raise failure

    monkeypatch.setattr(signing, "AuditSigner", _boom)
    monkeypatch.setattr(compliance_profiles, "requires_floor", lambda _floor: False)
    log = writer.AuditLog(tmp_path / "audit", sign=True)

    assert log.record(_event()) is False
    rows = list((tmp_path / "audit").glob("*.ndjson"))
    assert not rows or all(path.read_text(encoding="utf-8") == "" for path in rows)
    assert log._signing_enabled is True


def test_refuses_to_write_unsigned_under_a_compliance_floor(tmp_path, monkeypatch):
    _force_missing_crypto(monkeypatch)
    monkeypatch.setattr(compliance_profiles, "requires_floor", lambda _floor: True)
    log = writer.AuditLog(tmp_path / "audit")
    with pytest.raises(RuntimeError, match="refusing to write UNSIGNED"):
        log.record(_event())


@pytest.mark.parametrize(
    "failure",
    [
        OSError("audit key is unreadable"),
        ValueError("audit key material is invalid"),
        RuntimeError("audit signer backend failed"),
    ],
    ids=["os-error", "value-error", "runtime-error"],
)
def test_compliance_floor_refuses_every_signer_init_failure(
    tmp_path, monkeypatch, failure
):
    """A mandatory signing floor covers the signer, not just its dependency.

    Corrupt keys and backend/I/O failures must never disable signing and append
    plaintext merely because ``cryptography`` itself imported successfully.
    """
    def _boom(_path):
        raise failure

    monkeypatch.setattr(signing, "AuditSigner", _boom)
    monkeypatch.setattr(compliance_profiles, "requires_floor", lambda _floor: True)
    log = writer.AuditLog(tmp_path / "audit", sign=True)

    with pytest.raises(RuntimeError, match="refusing to write UNSIGNED") as exc:
        log.record(_event())

    assert exc.value.__cause__ is failure
    rows = list((tmp_path / "audit").glob("*.ndjson"))
    assert not rows or all(path.read_text(encoding="utf-8") == "" for path in rows)
    assert log._signing_enabled is True


def test_offhost_requirement_refuses_unsigned_audit_write(tmp_path, monkeypatch):
    def _offhost_required(_path):
        raise signing.OffHostSigningRequiredError(
            "off-host audit signing is required but no off-host key is configured"
        )

    monkeypatch.setattr(signing, "AuditSigner", _offhost_required)

    log = writer.AuditLog(tmp_path / "audit", sign=True)
    with pytest.raises(signing.OffHostSigningRequiredError, match="off-host audit signing is required"):
        log.record(_event())

    rows = list((tmp_path / "audit").glob("*.ndjson"))
    assert not rows or all(path.read_text() == "" for path in rows)
