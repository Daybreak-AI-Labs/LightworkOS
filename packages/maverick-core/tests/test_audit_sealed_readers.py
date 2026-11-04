"""Audit readers and rewriters must handle at-rest-sealed closed day-files.

Closed audit day-files are sealed at rest. The verifier and exporter read them
through the transparent reader (`sealing.segment_text`), and so must the three
other paths that read or rewrite a day-file:

  - `AuditLog.tail` / `AuditLog.grep` for an explicit past `day`,
  - `erase._process_file` (GDPR Art. 17 scrub/delete),
  - `signing.reanchor_file`'s write-back.

Read as raw plaintext, a sealed segment raises `UnicodeDecodeError` (a
ValueError, not the `OSError` the readers catch), so a reader would crash, the
GDPR erase would crash and never scrub the sealed data, and a rewrite would
silently replace the sealed blob with plaintext.
"""
from __future__ import annotations

import importlib.util

import pytest
from maverick import crypto_at_rest as car
from maverick.audit import signing
from maverick.audit.signing import AuditSigner

requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    for v in ("MAVERICK_ENCRYPT_AT_REST", "MAVERICK_ENCRYPTION_KEY", "MAVERICK_ENTERPRISE"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "atrest.key")
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")


def _signed_day(audit_dir, day, events):
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for e in events:
        signer.write(e)


def _seal(audit_dir, monkeypatch, today="2099-12-31"):
    from maverick.audit.sealing import seal_closed_segments
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    return seal_closed_segments(audit_dir, today=today)


@requires_crypto
def test_tail_reads_sealed_past_day(monkeypatch, tmp_path):
    from maverick.audit.writer import AuditLog
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01",
                [{"kind": "tool_call", "agent": "a"},
                 {"kind": "egress_blocked", "agent": "b"}])
    assert _seal(audit_dir, monkeypatch)["2020-01-01.ndjson"] == "sealed"

    rows = AuditLog(audit_dir).tail(day="2020-01-01")
    assert [r["kind"] for r in rows] == ["tool_call", "egress_blocked"]


@requires_crypto
def test_grep_reads_sealed_past_day(monkeypatch, tmp_path):
    from maverick.audit.writer import AuditLog
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01",
                [{"kind": "tool_call", "agent": "a"},
                 {"kind": "egress_blocked", "agent": "b"}])
    _seal(audit_dir, monkeypatch)

    rows = AuditLog(audit_dir).grep("egress_blocked", day="2020-01-01")
    assert [r["kind"] for r in rows] == ["egress_blocked"]


@requires_crypto
def test_scrub_user_handles_sealed_segment_and_keeps_it_sealed(monkeypatch, tmp_path):
    from maverick.audit.erase import scrub_user
    from maverick.audit.sealing import segment_text
    from maverick.crypto_at_rest import is_sealed

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01", [
        {"kind": "tool_call", "agent": "a", "channel": "slack", "user_id": "u1",
         "detail": "SECRET-PAYLOAD"},
        {"kind": "tool_call", "agent": "a", "channel": "slack", "user_id": "u2"},
    ])
    _seal(audit_dir, monkeypatch)
    sealed = audit_dir / "2020-01-01.ndjson"
    assert is_sealed(sealed.read_bytes())

    matched, scanned = scrub_user("slack", "u1", audit_dir=audit_dir)
    assert matched == 1

    # File stays sealed at rest -- the erase must not unseal a confidential
    # segment back to plaintext on disk.
    assert is_sealed(sealed.read_bytes())
    text = segment_text(sealed)
    assert "SECRET-PAYLOAD" not in text and "u1" not in text  # u1's row scrubbed
    assert "u2" in text                                       # u2 untouched
    # The re-anchored chain still verifies on the still-sealed file.
    assert signing.verify_chain(sealed) == []


@requires_crypto
def test_delete_user_handles_sealed_segment(monkeypatch, tmp_path):
    from maverick.audit.erase import delete_user
    from maverick.audit.sealing import segment_text
    from maverick.crypto_at_rest import is_sealed

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01", [
        {"kind": "tool_call", "channel": "slack", "user_id": "u1"},
        {"kind": "tool_call", "channel": "slack", "user_id": "u2"},
    ])
    _seal(audit_dir, monkeypatch)
    sealed = audit_dir / "2020-01-01.ndjson"

    deleted, _ = delete_user("slack", "u1", audit_dir=audit_dir)
    assert deleted == 1
    assert is_sealed(sealed.read_bytes())
    text = segment_text(sealed)
    assert "u1" not in text and "u2" in text
    assert signing.verify_chain(sealed) == []
