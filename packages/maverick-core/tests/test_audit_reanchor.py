"""Re-anchoring the signed audit chain after a GDPR erase.

A scrub/delete tombstones or removes audit rows but does NOT recompute the
Ed25519 prev_hash/hash/sig chain, so `maverick audit verify` then reports
breaks indistinguishable from tampering -- a routine privacy operation
destroying the trust anchor. erase now re-anchors the chain so it verifies
clean again, with the signed `erase` marker documenting the authorized cut.
"""

from __future__ import annotations

import pytest


def _have_crypto() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(not _have_crypto(), reason="cryptography not installed")


@pytest.fixture
def _isolate_keys(monkeypatch, tmp_path):
    """Point the audit signing key dir at the tmp tree.

    Patch the compatibility hook explicitly so the test never touches the
    active tenant's real audit-key directory.
    """
    from maverick.audit import signing

    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")


def _signed_log(tmp_path):
    """Build a signed 4-row audit log: alice, bob, alice, bob."""
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    ad = tmp_path / "audit"
    log = AuditLog(audit_dir=ad, sign=True)
    ts = 1000.0
    for ch, uid, title in [
        ("telegram", "alice", "alice goal one"),
        ("telegram", "bob", "bob goal"),
        ("telegram", "alice", "alice goal two"),
        ("telegram", "bob", "bob goal two"),
    ]:
        assert log.record(
            AuditEvent(
                ts=ts,
                kind=EventKind.GOAL_START,
                payload={"channel": ch, "user_id": uid, "title": title},
            )
        )
        ts += 1.0
    files = sorted(ad.glob("*.ndjson"))
    assert len(files) == 1
    return log, ad, files[0]


def test_scrub_user_restores_chain_after_preverified_erase(_isolate_keys, tmp_path):
    from maverick.audit.erase import scrub_user
    from maverick.audit.signing import verify_chain

    _log, ad, path = _signed_log(tmp_path)
    assert verify_chain(path) == []  # clean to start

    matched, _ = scrub_user("telegram", "alice", audit_dir=ad)
    assert matched == 2
    assert verify_chain(path) == []  # authorized scrub re-anchored cleanly

    # alice's identity (and her goal titles) are gone; bob's rows survive.
    text = path.read_text(encoding="utf-8")
    assert "alice" not in text
    assert "bob goal" in text


def test_reanchor_file_idempotent_on_clean_chain(_isolate_keys, tmp_path):
    """No erase happened: re-anchoring an already-consistent file under the
    same key must NOT rewrite it (deterministic Ed25519 -> identical bytes)."""
    from maverick.audit.signing import reanchor_file, verify_chain

    _log, _ad, path = _signed_log(tmp_path)
    before = path.read_text(encoding="utf-8")
    assert reanchor_file(path) == 0
    assert path.read_text(encoding="utf-8") == before
    assert verify_chain(path) == []


def test_reanchor_after_erase_keeps_signer_consistent(_isolate_keys, tmp_path):
    """End-to-end via AuditLog: after erase + re-anchor the chain verifies
    clean AND a subsequent record() chains onto the rewritten head, not a
    stale in-memory one."""
    from maverick.audit.erase import scrub_user
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.signing import verify_chain

    log, ad, path = _signed_log(tmp_path)
    scrub_user("telegram", "alice", audit_dir=ad)

    assert log.reanchor_after_erase() == 0
    assert verify_chain(path) == []

    # A new event after the re-anchor must extend the chain cleanly; if the
    # cached signer kept a stale head this would chain_mismatch.
    assert log.record(
        AuditEvent(
            ts=2000.0,
            kind=EventKind.GOAL_END,
            payload={"status": "succeeded", "result": None},
        )
    )
    assert verify_chain(path) == []


def test_reanchor_refuses_to_bless_prior_tampering(_isolate_keys, tmp_path):
    import json

    from maverick.audit.erase import scrub_user
    from maverick.audit.signing import reanchor_file, verify_chain

    _log, ad, path = _signed_log(tmp_path)
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    rows[1]["title"] = "tampered bob goal"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    assert verify_chain(path) != []
    before = path.read_text(encoding="utf-8")

    assert reanchor_file(path, force=True) == -1
    assert path.read_text(encoding="utf-8") == before

    matched, _ = scrub_user("telegram", "alice", audit_dir=ad)
    assert matched == 0
    assert path.read_text(encoding="utf-8") == before
    assert verify_chain(path) != []


def test_reanchor_noop_when_signing_disabled(tmp_path):
    """Unsigned log: nothing to re-anchor; the call is a no-op and the file
    is left byte-for-byte unchanged."""
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.writer import AuditLog

    ad = tmp_path / "audit"
    log = AuditLog(audit_dir=ad, sign=False)
    assert log.record(
        AuditEvent(
            ts=1.0,
            kind=EventKind.GOAL_START,
            payload={"channel": "t", "user_id": "x"},
        )
    )
    path = sorted(ad.glob("*.ndjson"))[0]
    before = path.read_text(encoding="utf-8")
    assert log.reanchor_after_erase() == 0
    assert path.read_text(encoding="utf-8") == before
