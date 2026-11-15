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


def test_erase_without_a_signer_leaves_the_day_untouched(_isolate_keys, tmp_path, monkeypatch):
    """The re-signed day is built in memory and published in one write, so an
    erase that cannot re-sign changes nothing and never leaves a broken day."""
    from maverick.audit import signing
    from maverick.audit.erase import scrub_user
    from maverick.audit.signing import verify_chain

    _log, ad, path = _signed_log(tmp_path)
    before = path.read_bytes()

    def no_signer():
        raise signing.OffHostSigningRequiredError("no off-host key here")

    monkeypatch.setattr(signing, "_load_or_create_keypair", no_signer)
    with pytest.raises(signing.OffHostSigningRequiredError):
        scrub_user("telegram", "alice", audit_dir=ad, strict=True)
    assert path.read_bytes() == before
    assert verify_chain(path) == []


def test_erase_of_a_day_with_unsigned_rows_keeps_it_verifiable(_isolate_keys, tmp_path):
    """A day that began unsigned, was signed, then had signing switched off
    again can be erased: the subject goes from every part, unsigned rows stay
    out of the chain, and the day verifies exactly as before."""
    from maverick.audit.erase import scrub_user
    from maverick.audit.events import AuditEvent, EventKind
    from maverick.audit.signing import verify_chain
    from maverick.audit.writer import AuditLog

    ad = tmp_path / "audit"
    for sign in (False, True, False):
        log = AuditLog(audit_dir=ad, sign=sign)
        for uid in ("alice", "bob"):
            assert log.record(AuditEvent(ts=1000.0, kind=EventKind.GOAL_START,
                                         payload={"channel": "telegram", "user_id": uid,
                                                  "title": f"{uid} goal"}))
    path = sorted(ad.glob("*.ndjson"))[0]
    before = [(b.line_no, b.reason) for b in verify_chain(path)]
    assert before == [(1, "unsigned"), (2, "unsigned"), (5, "unsigned"), (6, "unsigned")]

    matched, _ = scrub_user("telegram", "alice", audit_dir=ad, strict=True)
    assert matched == 3
    assert "alice" not in path.read_text(encoding="utf-8")
    assert [(b.line_no, b.reason) for b in verify_chain(path)] == before


def test_erase_never_signs_a_row_that_arrived_unsigned(_isolate_keys, tmp_path):
    """A forged unsigned row placed after the first signed row (with a line of
    carriage returns to skew line counting) stays unverifiable after an erase
    of another subject; it is never re-signed into the chain."""
    import json

    from maverick.audit.erase import scrub_user
    from maverick.audit.signing import verify_chain

    _log, ad, path = _signed_log(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    forged = json.dumps({"v": 1, "ts": 1.0, "kind": "approval", "agent": "admin",
                         "payload": {"approved": "wire $1M"}}) + "\n"
    path.write_text("\r" * 20 + "\n" + lines[0] + forged + "".join(lines[1:]), encoding="utf-8")
    before = [(b.line_no, b.reason) for b in verify_chain(path)]
    assert before == [(3, "unsigned")]

    matched, _ = scrub_user("telegram", "alice", audit_dir=ad, strict=True)
    assert matched == 2
    assert [(b.line_no, b.reason) for b in verify_chain(path)] == before
    assert '"sig"' not in path.read_text(encoding="utf-8").splitlines()[2]


def _anchored_past_day(tmp_path):
    """A completed, anchored signed day: alice, bob, alice, bob."""
    from maverick.audit.signing import ensure_anchors
    from maverick.audit.writer import reset_signer_after_erase

    _log, ad, path = _signed_log(tmp_path)
    past = path.with_name("2020-01-01.ndjson")
    path.rename(past)
    reset_signer_after_erase(ad)
    assert ensure_anchors(ad) == 1
    return ad, past


def _state(ad, path):
    from maverick.audit.signing import verify_anchors, verify_chain

    return ([(b.line_no, b.reason) for b in verify_chain(path)],
            [b.reason for b in verify_anchors(ad)])


@pytest.mark.parametrize("damage", ["truncated_tail", "stripped_last_row", "inserted_unsigned_row"])
def test_erase_refuses_a_day_whose_anchor_already_reports_a_break(_isolate_keys, tmp_path, damage):
    """Erase is never a repair: a day the tip ledger already flags is refused
    unchanged, and every break is still reported afterwards."""
    import json

    from maverick.audit.erase import erase_blockers, scrub_user

    ad, path = _anchored_past_day(tmp_path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if damage == "truncated_tail":
        lines = lines[:-1]
    elif damage == "stripped_last_row":
        row = json.loads(lines[-1])
        for field in ("hash", "sig", "key_id", "prev_hash"):
            row.pop(field)
        row["title"] = "edited"
        lines[-1] = json.dumps(row) + "\n"
    else:
        lines.append(json.dumps({"kind": "approval", "agent": "admin"}) + "\n")
    path.write_text("".join(lines), encoding="utf-8")
    before_bytes, before = path.read_bytes(), _state(ad, path)
    assert any(r.startswith("anchor_") for r in before[1])

    assert erase_blockers("telegram", "alice", audit_dir=ad)
    with pytest.raises(RuntimeError):
        scrub_user("telegram", "alice", audit_dir=ad, strict=True)
    assert path.read_bytes() == before_bytes
    assert _state(ad, path) == before


def test_an_anchored_day_stays_erasable_after_an_earlier_erase(_isolate_keys, tmp_path):
    from maverick.audit.erase import erase_blockers, scrub_user

    ad, path = _anchored_past_day(tmp_path)
    for subject in ("alice", "bob"):
        assert erase_blockers("telegram", subject, audit_dir=ad) == []
        assert scrub_user("telegram", subject, audit_dir=ad, strict=True)[0] == 2
        assert _state(ad, path) == ([], [])


def test_a_retired_key_without_its_public_key_names_the_key_to_restore(
        _isolate_keys, tmp_path, monkeypatch):
    from maverick.audit import signing
    from maverick.audit.erase import erase_blockers

    _log, ad, path = _signed_log(tmp_path)
    # The rows' key is no longer among the trusted public keys (a retired key
    # whose .pub file is gone).
    monkeypatch.setattr(signing, "trusted_audit_public_keys", dict)
    (blocker,) = erase_blockers("telegram", "alice", audit_dir=ad)
    assert "public key is not available" in blocker and "MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS" in blocker
    assert "backup restore" not in blocker


def test_erase_checks_the_chosen_checkpoint_folder_too(_isolate_keys, tmp_path):
    """Today's open day is never anchored, so a checkpoint in the folder an
    administrator chose is what catches a removed row: erase refuses it."""
    import json

    from maverick.audit.checkpoint_location import settings_path
    from maverick.audit.checkpoints import publish_checkpoint
    from maverick.audit.erase import erase_blockers, scrub_user

    _log, ad, path = _signed_log(tmp_path)
    chosen = tmp_path / "worm"
    chosen.mkdir()
    settings_path().parent.mkdir(parents=True, exist_ok=True)
    settings_path().write_text(json.dumps({"folder": str(chosen), "keys": []}), encoding="utf-8")
    publish_checkpoint(ad, chosen, day=path.stem)
    path.write_text("".join(path.read_text(encoding="utf-8").splitlines(keepends=True)[:-1]),
                    encoding="utf-8")
    before = path.read_bytes()

    (blocker,) = erase_blockers("telegram", "alice", audit_dir=ad)
    assert "published checkpoint" in blocker
    with pytest.raises(RuntimeError):
        scrub_user("telegram", "alice", audit_dir=ad, strict=True)
    assert path.read_bytes() == before

    chosen.rename(tmp_path / "gone")
    (blocker,) = erase_blockers("telegram", "alice", audit_dir=ad)
    assert str(chosen) in blocker
