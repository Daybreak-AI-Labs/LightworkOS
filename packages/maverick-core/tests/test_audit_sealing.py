"""Audit segment sealing: closed day-files encrypt at rest; the readers and
'audit verify' stay transparent; the live day-file is left plaintext."""
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


@requires_crypto
def test_seal_reads_and_verify_stay_transparent(monkeypatch, tmp_path):
    from maverick.audit.export import iter_audit_events
    from maverick.audit.sealing import seal_closed_segments, segment_text
    from maverick.crypto_at_rest import is_sealed

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01",
                [{"kind": "egress_blocked", "agent": "a", "detail": "SECRET-PAYLOAD-x"}])
    today = "2099-12-31"
    _signed_day(audit_dir, today, [{"kind": "tool_call", "agent": "b"}])

    closed = audit_dir / "2020-01-01.ndjson"
    live = audit_dir / f"{today}.ndjson"
    assert b"SECRET-PAYLOAD-x" in closed.read_bytes()        # plaintext before sealing

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    report = seal_closed_segments(audit_dir, today=today)
    assert report["2020-01-01.ndjson"] == "sealed"
    assert report[f"{today}.ndjson"] == "skipped (current)"

    # On disk: the closed segment is sealed (no plaintext); the live one is not.
    assert is_sealed(closed.read_bytes())
    assert b"SECRET-PAYLOAD-x" not in closed.read_bytes()
    assert not is_sealed(live.read_bytes())

    # Reads decrypt transparently.
    assert "SECRET-PAYLOAD-x" in segment_text(closed)
    monkeypatch.setattr("maverick.paths.data_dir", lambda *a, **k: audit_dir)
    kinds = {e["kind"] for e in iter_audit_events(all_days=True)}
    assert {"egress_blocked", "tool_call"} <= kinds

    # The hash-chain still verifies on the sealed segment AND the live one.
    assert signing.verify_chain(closed) == []
    assert signing.verify_chain(live) == []


@requires_crypto
def test_seal_is_idempotent_and_refuses_without_at_rest(monkeypatch, tmp_path):
    from maverick.audit.sealing import seal_closed_segments
    from maverick.crypto_at_rest import EncryptionUnavailable

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01", [{"kind": "tool_call"}])

    # Explicitly off (under the secure default an unset flag means on):
    # sealing must refuse rather than leave half-state.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    with pytest.raises(EncryptionUnavailable):                 # off -> refuse, no half-state
        seal_closed_segments(audit_dir, today="2099-12-31")

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    r1 = seal_closed_segments(audit_dir, today="2099-12-31")
    assert r1["2020-01-01.ndjson"] == "sealed"
    r2 = seal_closed_segments(audit_dir, today="2099-12-31")    # idempotent
    assert r2["2020-01-01.ndjson"] == "already sealed"


@requires_crypto
def test_dry_run_writes_nothing(monkeypatch, tmp_path):
    from maverick.audit.sealing import seal_closed_segments
    from maverick.crypto_at_rest import is_sealed

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01", [{"kind": "tool_call"}])
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")

    r = seal_closed_segments(audit_dir, today="2099-12-31", dry_run=True)
    assert r["2020-01-01.ndjson"] == "would seal"
    assert not is_sealed((audit_dir / "2020-01-01.ndjson").read_bytes())   # untouched


@requires_crypto
def test_verify_chain_fails_closed_on_corrupt_sealed_segment(monkeypatch, tmp_path):
    from maverick.audit.sealing import SegmentReadError, seal_closed_segments, segment_text

    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    _signed_day(audit_dir, "2020-01-01", [{"kind": "tool_call", "detail": "SECRET"}])

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert seal_closed_segments(audit_dir, today="2099-12-31")["2020-01-01.ndjson"] == "sealed"

    sealed = audit_dir / "2020-01-01.ndjson"
    raw = bytearray(sealed.read_bytes())
    raw[-1] ^= 0x01
    sealed.write_bytes(bytes(raw))

    # Export remains fail-soft, but verification must not treat unreadable
    # signed evidence as a valid empty chain.
    assert segment_text(sealed) == ""
    with pytest.raises(SegmentReadError):
        segment_text(sealed, fail_soft=False)
    breaks = signing.verify_chain(sealed)
    assert breaks
    assert breaks[0].reason == "unreadable_segment"
