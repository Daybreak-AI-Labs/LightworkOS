"""Signed central-sink invariants for cross-suite audit projections."""
from __future__ import annotations

import hashlib
import json

import maverick.audit.signing as signing
import maverick.compliance_profiles as compliance_profiles
import pytest
from maverick.audit.events import AuditEvent, EventKind
from maverick.audit.signing import verify_chain
from maverick.audit.writer import (
    AuditLog,
    AuditWriteRefused,
    _prepare_private_audit_file,
)
from maverick.paths import data_dir, tenant_scope
from maverick.unified_audit import (
    StrictAuditProjectionSink,
    UnifiedAuditConfigError,
    UnifiedAuditError,
    UnifiedAuditIntegrityError,
    canonical_sha256,
)


def _payload() -> dict[str, object]:
    return {
        "projection_event_id": "d" * 64,
        "projection_schema": "lightwork.unified-audit-projection.v1",
        "tenant_sha256": "e" * 64,
        "source_id": "privacy_automation",
        "suite_id": "privacy_automation",
        "source_schema_version": 1,
        "source_authority_revision": 3,
        "source_authority_sha256": "3" * 64,
        "source_sequence": 17,
        "source_occurred_at": 100.0,
        "source_action": "record_changed",
        "source_actor_sha256": "a" * 64,
        "source_resource_sha256": "b" * 64,
        "source_payload_sha256": "c" * 64,
        "source_previous_sha256": "1" * 64,
        "source_record_sha256": "2" * 64,
        "source_page_sha256": "4" * 64,
        "source_head_sha256": "5" * 64,
        "source_terminal": True,
        "source_complete": True,
        "source_truncated": False,
        "source_watermark": 100.0,
        "source_limitations": [],
        "raw_source_payload_persisted": False,
    }


def _event(ts: float, **payload_overrides: object) -> AuditEvent:
    payload = _payload()
    payload.update(payload_overrides)
    return AuditEvent(
        ts=ts,
        kind=EventKind.UNIFIED_AUDIT_PROJECTION,
        agent="unified-audit-projector",
        payload=payload,
    )


@pytest.fixture
def sealed_history_sink(monkeypatch):
    from maverick.audit.sealing import seal_closed_segments
    from maverick.crypto_at_rest import is_sealed

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    with tenant_scope(tenant="sealed-sink-tenant"):
        audit_dir = data_dir("audit")
        old_path = audit_dir / "2026-08-29.ndjson"
        new_path = audit_dir / "2026-08-30.ndjson"
        _prepare_private_audit_file(old_path)
        _prepare_private_audit_file(new_path)
        old_log = AuditLog(audit_dir, sign=True)
        monkeypatch.setattr(old_log, "_rotate_if_needed", lambda: old_path)
        old_sink = StrictAuditProjectionSink(
            tenant_id="sealed-sink-tenant", audit_log=old_log, clock=lambda: 101.0,
        )
        event = _payload() | {"tenant_sha256": old_sink.tenant_sha256}
        old_receipt = old_sink.append(event)
        assert seal_closed_segments(audit_dir, today="2026-08-30")[old_path.name] == "sealed"
        assert is_sealed(old_path.read_bytes())
        assert verify_chain(old_path) == []

        new_log = AuditLog(audit_dir, sign=True)
        monkeypatch.setattr(new_log, "_rotate_if_needed", lambda: new_path)
        sink = StrictAuditProjectionSink(
            tenant_id="sealed-sink-tenant", audit_log=new_log, clock=lambda: 102.0,
        )
        yield sink, new_log, event, old_receipt, old_path, new_path


@pytest.mark.parametrize("replay_old", [False, True])
def test_strict_sink_reads_sealed_history_and_preserves_receipt_identity(
    sealed_history_sink, replay_old,
) -> None:
    from maverick.audit.sealing import segment_text

    sink, _log, old_event, old_receipt, old_path, new_path = sealed_history_sink
    event = old_event if replay_old else old_event | {"projection_event_id": "f" * 64}
    sealed_before = old_path.read_bytes()

    receipt = sink.append(event)

    assert receipt.projection_event_id == event["projection_event_id"]
    assert receipt.event_sha256 == canonical_sha256(event)
    assert receipt.tenant_sha256 == sink.tenant_sha256
    assert receipt.sink_identity_sha256 == sink.sink_identity_sha256
    assert sink.append(event) == receipt
    if replay_old:
        assert receipt == old_receipt
    rows = [
        json.loads(line)
        for path in (old_path, new_path)
        for line in segment_text(path, fail_soft=False).splitlines()
    ]
    assert len(rows) == (1 if replay_old else 2)
    matched = [row for row in rows if row["projection_event_id"] == event["projection_event_id"]]
    assert len(matched) == 1
    assert receipt.chain_sha256 == matched[0]["hash"]
    assert receipt.key_id_sha256 == hashlib.sha256(matched[0]["key_id"].encode("ascii")).hexdigest()
    assert receipt.signature_sha256 == hashlib.sha256(matched[0]["sig"].encode("ascii")).hexdigest()
    assert old_path.read_bytes() == sealed_before
    assert verify_chain(old_path) == verify_chain(new_path) == []


def test_strict_sink_sealed_history_keeps_tenant_and_conflict_rejections(
    sealed_history_sink,
) -> None:
    sink, log, event, _receipt, old_path, new_path = sealed_history_sink
    sealed_before = old_path.read_bytes()
    with pytest.raises(UnifiedAuditConfigError, match="outside the tenant"):
        StrictAuditProjectionSink(tenant_id="other-tenant", audit_log=log)
    with pytest.raises(UnifiedAuditError, match="refused an append"):
        sink.append(event | {"source_payload_sha256": "f" * 64})
    assert old_path.read_bytes() == sealed_before
    assert new_path.read_bytes() == b""


def test_strict_sink_refuses_unreadable_sealed_history_after_append(
    sealed_history_sink, monkeypatch,
) -> None:
    sink, log, event, _receipt, old_path, new_path = sealed_history_sink
    record = log.record_strict_signed

    def corrupt_after_append(audit_event):
        result = record(audit_event)
        assert result is True
        sealed = old_path.read_bytes()
        old_path.write_bytes(sealed[:-1] + bytes([sealed[-1] ^ 1]))
        return result

    monkeypatch.setattr(log, "record_strict_signed", corrupt_after_append)
    with pytest.raises(UnifiedAuditIntegrityError, match="receipt is unavailable"):
        sink.append(event | {"projection_event_id": "f" * 64})
    # The append happened; unreadable history must not yield a false receipt.
    assert verify_chain(new_path) == []
    assert len(new_path.read_text(encoding="utf-8").splitlines()) == 1


@pytest.mark.parametrize("sign", [False, True])
def test_projection_replay_is_append_once_across_days_and_writers(
    tmp_path,
    monkeypatch,
    sign: bool,
) -> None:
    audit_dir = tmp_path / ("signed" if sign else "unsigned")
    first_path = audit_dir / "2026-08-29.ndjson"
    second_path = audit_dir / "2026-08-30.ndjson"
    _prepare_private_audit_file(first_path)
    _prepare_private_audit_file(second_path)

    first = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(first, "_rotate_if_needed", lambda: first_path)
    first_write = first.record_strict_signed if sign else first.record
    assert first_write(_event(101.0)) is True

    retried = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(retried, "_rotate_if_needed", lambda: second_path)
    retry_write = retried.record_strict_signed if sign else retried.record
    assert retry_write(_event(102.0)) is True

    rows = [
        json.loads(line)
        for path in (first_path, second_path)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [
        row["projection_event_id"]
        for row in rows
        if row["kind"] == EventKind.UNIFIED_AUDIT_PROJECTION
    ] == ["d" * 64]
    assert second_path.read_text(encoding="utf-8") == ""
    if sign:
        assert verify_chain(first_path) == []
        assert {"hash", "prev_hash", "sig"} <= rows[0].keys()


@pytest.mark.parametrize("sign", [False, True])
def test_projection_identity_rejects_conflicting_content(
    tmp_path,
    monkeypatch,
    sign: bool,
) -> None:
    audit_dir = tmp_path / ("signed-conflict" if sign else "conflict")
    path = audit_dir / "2026-08-30.ndjson"
    _prepare_private_audit_file(path)
    first = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(first, "_rotate_if_needed", lambda: path)
    first_write = first.record_strict_signed if sign else first.record
    assert first_write(_event(101.0)) is True

    other_writer = AuditLog(audit_dir, sign=sign)
    monkeypatch.setattr(other_writer, "_rotate_if_needed", lambda: path)
    conflicting_write = (
        other_writer.record_strict_signed if sign else other_writer.record
    )
    assert conflicting_write(
        _event(102.0, source_payload_sha256="f" * 64)
    ) is False

    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert len(rows) == 1
    assert rows[0]["source_payload_sha256"] == "c" * 64
    if sign:
        assert verify_chain(path) == []


def test_signing_enabled_reports_resolved_state_and_is_read_only(tmp_path) -> None:
    unsigned = AuditLog(tmp_path / "unsigned-state", sign=False)
    signed = AuditLog(tmp_path / "signed-state", sign=True)

    assert unsigned.signing_enabled is False
    assert signed.signing_enabled is True
    with pytest.raises(AttributeError):
        signed.signing_enabled = False

    assert signed.record(_event(103.0)) is True
    assert signed.signing_enabled is True
    path = next((tmp_path / "signed-state").glob("*.ndjson"))
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert {"hash", "prev_hash", "sig"} <= row.keys()
    assert verify_chain(path) == []


def test_signing_enabled_reflects_runtime_environment_precedence(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")
    disabled = AuditLog(tmp_path / "env-disabled")
    assert disabled.signing_enabled is False

    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    enabled = AuditLog(tmp_path / "env-enabled")
    assert enabled.signing_enabled is True


@pytest.mark.parametrize(
    "projection_event_id",
    [None, "", "D" * 64, "d" * 63, "d" * 65, "d" * 257],
    ids=["missing", "empty", "uppercase", "short", "long", "oversize"],
)
def test_projection_identity_cannot_silently_disable_deduplication(
    tmp_path,
    projection_event_id,
) -> None:
    log = AuditLog(tmp_path / "invalid-identity", sign=False)

    assert log.record(_event(104.0, projection_event_id=projection_event_id)) is False
    rows = list((tmp_path / "invalid-identity").glob("*.ndjson"))
    assert not rows or all(path.read_text(encoding="utf-8") == "" for path in rows)


def test_strict_signed_write_refuses_before_optional_crypto_downgrade(
    tmp_path,
    monkeypatch,
) -> None:
    def missing_crypto(_path):
        raise ImportError("cryptography unavailable")

    monkeypatch.setattr(signing, "AuditSigner", missing_crypto)
    monkeypatch.setattr(compliance_profiles, "requires_floor", lambda _floor: False)
    log = AuditLog(tmp_path / "strict-missing-crypto", sign=True)

    with pytest.raises(AuditWriteRefused, match="unsigned fallback"):
        log.record_strict_signed(_event(105.0))

    assert log.signing_enabled is False
    rows = list((tmp_path / "strict-missing-crypto").glob("*.ndjson"))
    assert not rows or all(path.read_text(encoding="utf-8") == "" for path in rows)


def test_strict_signed_write_replays_once_and_refuses_unsigned_prior_identity(
    tmp_path,
) -> None:
    signed_dir = tmp_path / "strict-signed"
    signed = AuditLog(signed_dir, sign=True)
    assert signed.record_strict_signed(_event(106.0)) is True
    assert signed.record_strict_signed(_event(107.0)) is True
    signed_path = next(signed_dir.glob("*.ndjson"))
    assert len(signed_path.read_text(encoding="utf-8").splitlines()) == 1
    assert verify_chain(signed_path) == []

    unsigned_dir = tmp_path / "strict-over-unsigned"
    unsigned = AuditLog(unsigned_dir, sign=False)
    assert unsigned.record(_event(108.0)) is True
    strict = AuditLog(unsigned_dir, sign=True)
    assert strict.record_strict_signed(_event(109.0)) is False
    unsigned_path = next(unsigned_dir.glob("*.ndjson"))
    row = json.loads(unsigned_path.read_text(encoding="utf-8").splitlines()[0])
    assert "sig" not in row


def test_strict_signed_replay_refuses_a_tampered_prior_signature(tmp_path) -> None:
    audit_dir = tmp_path / "strict-tampered"
    original = AuditLog(audit_dir, sign=True)
    assert original.record_strict_signed(_event(110.0)) is True
    path = next(audit_dir.glob("*.ndjson"))
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    row["sig"] = "0" * 128
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert verify_chain(path)[0].reason == "bad_signature"

    replay = AuditLog(audit_dir, sign=True)
    assert replay.record_strict_signed(_event(111.0)) is False
    assert verify_chain(path)[0].reason == "bad_signature"
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1


def test_strict_signed_new_identity_refuses_a_tampered_destination_chain(
    tmp_path,
) -> None:
    audit_dir = tmp_path / "strict-tampered-before-new-id"
    original = AuditLog(audit_dir, sign=True)
    assert original.record_strict_signed(_event(112.0)) is True
    path = next(audit_dir.glob("*.ndjson"))
    row = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    row["sig"] = "0" * 128
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    assert verify_chain(path)[0].reason == "bad_signature"

    new_projection = AuditLog(audit_dir, sign=True)
    assert new_projection.record_strict_signed(
        _event(
            113.0,
            projection_event_id="f" * 64,
            source_sequence=18,
            source_previous_sha256="2" * 64,
            source_record_sha256="6" * 64,
        )
    ) is False
    assert verify_chain(path)[0].reason == "bad_signature"
    assert len(path.read_text(encoding="utf-8").splitlines()) == 1
