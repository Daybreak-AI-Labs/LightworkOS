"""Independent live-day checkpoints detect valid-prefix audit truncation."""
from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timezone

import pytest

pytest.importorskip("cryptography")

from maverick.audit import (
    checkpoints,  # noqa: E402
    signing,  # noqa: E402
)
from maverick.audit.checkpoints import (  # noqa: E402
    AuditCheckpointError,
    latest_checkpoint_sequence,
    publish_checkpoint,
    retire_checkpoint,
    verify_checkpoints,
)
from maverick.audit.signing import (  # noqa: E402
    AuditSigner,
    ensure_anchors,
    record_retention_purge,
    rotate_audit_keypair,
    verify_chain,
)


@pytest.fixture
def isolated_audit(tmp_path, monkeypatch):
    audit_dir = tmp_path / "audit"
    checkpoint_dir = tmp_path / "independent-checkpoints"
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    return audit_dir, checkpoint_dir


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _write_rows(audit_dir, count: int):
    day_file = audit_dir / f"{_today()}.ndjson"
    signer = AuditSigner(day_file)
    for index in range(count):
        assert signer.write({"kind": "tool_call", "index": index})
    return day_file


def _digest(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _erase_record_store():
    """The erase records an erasure stores in the world model, in memory.

    Returns ``(records, store, lookup)``: ``store`` is the erase's
    ``on_rewrite`` hook and ``lookup`` what the publisher and verifier read.
    """
    records: list[dict] = []

    def store(summary):
        records.append({**summary, "erasure_id": "e" * 32,
                        "issued_at": datetime.now(timezone.utc).isoformat()})

    return records, store, lambda day: [record for record in records if record["day"] == day]


def test_publish_and_verify_live_day_checkpoint(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 3)

    checkpoint = publish_checkpoint(audit_dir, checkpoint_dir)

    assert checkpoint.name == "audit-checkpoint-00000000000000000001.ndjson"
    assert verify_chain(checkpoint) == []
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []
    assert latest_checkpoint_sequence(checkpoint_dir) == 1
    assert json.loads(checkpoint.read_text(encoding="utf-8"))["row_count"] == 3
    assert day_file.exists()


def test_same_tip_publish_is_idempotent(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 2)

    first = publish_checkpoint(audit_dir, checkpoint_dir)
    second = publish_checkpoint(audit_dir, checkpoint_dir)

    assert first == second
    assert latest_checkpoint_sequence(checkpoint_dir) == 1


def test_later_rows_preserve_checkpointed_prefix(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 2)
    publish_checkpoint(audit_dir, checkpoint_dir)
    signer = AuditSigner(day_file)
    assert signer.write({"kind": "tool_call", "index": 2})

    assert verify_checkpoints(audit_dir, checkpoint_dir) == []


def test_valid_prefix_truncation_is_detected(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 3)
    publish_checkpoint(audit_dir, checkpoint_dir)

    rows = day_file.read_text(encoding="utf-8").splitlines()
    day_file.write_text("\n".join(rows[:-1]) + "\n", encoding="utf-8")

    # The remaining prefix is internally valid; only the independent commitment
    # proves that a signed suffix existed and has been removed.
    assert verify_chain(day_file) == []
    reasons = {item.reason for item in verify_checkpoints(audit_dir, checkpoint_dir)}
    assert "audit_tail_truncated" in reasons


def test_checkpoint_tampering_is_detected(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 1)
    checkpoint = publish_checkpoint(audit_dir, checkpoint_dir)
    row = json.loads(checkpoint.read_text(encoding="utf-8"))
    row["row_count"] = 999
    checkpoint.chmod(0o600)
    checkpoint.write_text(json.dumps(row) + "\n", encoding="utf-8")

    reasons = {item.reason for item in verify_checkpoints(audit_dir, checkpoint_dir)}
    assert reasons == {"checkpoint_store_invalid"}


def test_trusted_minimum_detects_latest_checkpoint_rollback(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 1)
    publish_checkpoint(audit_dir, checkpoint_dir)
    assert AuditSigner(day_file).write({"kind": "tool_call", "index": 1})
    second = publish_checkpoint(audit_dir, checkpoint_dir)
    assert latest_checkpoint_sequence(checkpoint_dir) == 2

    second.chmod(0o600)
    second.unlink()

    reasons = {
        item.reason
        for item in verify_checkpoints(
            audit_dir,
            checkpoint_dir,
            minimum_sequence=2,
        )
    }
    assert "checkpoint_rollback" in reasons


def test_checkpoint_destination_cannot_live_under_audit_dir(isolated_audit):
    audit_dir, _checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 1)

    with pytest.raises(AuditCheckpointError, match="outside"):
        publish_checkpoint(audit_dir, audit_dir / "checkpoints")


def test_day_lock_prevents_stale_publisher_regression(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 1)
    snapshot_taken = threading.Event()
    release_snapshot = threading.Event()
    writer_started = threading.Event()
    writer_finished = threading.Event()
    original_snapshot = checkpoints._snapshot_day_for_publication

    def paused_snapshot(path, trusted_keys):
        snapshot = original_snapshot(path, trusted_keys)
        snapshot_taken.set()
        assert release_snapshot.wait(timeout=5)
        return snapshot

    monkeypatch.setattr(
        checkpoints,
        "_snapshot_day_for_publication",
        paused_snapshot,
    )
    publish_error = []

    def publisher():
        try:
            publish_checkpoint(audit_dir, checkpoint_dir)
        except Exception as exc:  # pragma: no cover - surfaced by assertion
            publish_error.append(exc)

    def writer():
        writer_started.set()
        signer = AuditSigner(day_file)
        assert signer.write({"kind": "tool_call", "index": 1})
        writer_finished.set()

    publishing = threading.Thread(target=publisher)
    publishing.start()
    assert snapshot_taken.wait(timeout=5)
    writing = threading.Thread(target=writer)
    writing.start()
    assert writer_started.wait(timeout=5)
    time.sleep(0.05)
    assert not writer_finished.is_set()
    release_snapshot.set()
    publishing.join(timeout=5)
    writing.join(timeout=5)
    assert not publish_error
    assert writer_finished.is_set()

    monkeypatch.setattr(
        checkpoints,
        "_snapshot_day_for_publication",
        original_snapshot,
    )
    publish_checkpoint(audit_dir, checkpoint_dir)
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(checkpoint_dir.glob("audit-checkpoint-*.ndjson"))
    ]
    assert [record["row_count"] for record in records] == [1, 2]
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []


def test_same_era_regression_is_refused_by_default(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 3)
    publish_checkpoint(audit_dir, checkpoint_dir)
    rows = day_file.read_text(encoding="utf-8").splitlines()
    day_file.write_text("\n".join(rows[:2]) + "\n", encoding="utf-8")
    assert verify_chain(day_file) == []

    with pytest.raises(AuditCheckpointError, match="changed within an era"):
        publish_checkpoint(audit_dir, checkpoint_dir)

    assert latest_checkpoint_sequence(checkpoint_dir) == 1


def test_failed_stage_verification_never_exposes_numbered_target(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 1)
    original_read = checkpoints._read_checkpoint

    def fail_staged_read(path, trusted_keys, *, expected_sequence):
        if path.name.endswith(".stage"):
            raise AuditCheckpointError("injected staged verification failure")
        return original_read(
            path,
            trusted_keys,
            expected_sequence=expected_sequence,
        )

    monkeypatch.setattr(checkpoints, "_read_checkpoint", fail_staged_read)
    with pytest.raises(AuditCheckpointError, match="injected"):
        publish_checkpoint(audit_dir, checkpoint_dir)

    assert list(checkpoint_dir.glob("audit-checkpoint-*.ndjson")) == []
    assert list(checkpoint_dir.glob("*.stage")) == []


def test_malformed_suffix_cannot_be_published_as_a_torn_snapshot(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 1)
    original_snapshot = checkpoints._snapshot_day_for_publication

    def inject_malformed_suffix(path, trusted_keys):
        with open(path, "ab") as stream:
            stream.write(b'{"torn":')
            stream.flush()
        return original_snapshot(path, trusted_keys)

    monkeypatch.setattr(
        checkpoints,
        "_snapshot_day_for_publication",
        inject_malformed_suffix,
    )
    with pytest.raises(AuditCheckpointError, match="malformed JSON"):
        publish_checkpoint(audit_dir, checkpoint_dir)

    assert list(checkpoint_dir.glob("audit-checkpoint-*.ndjson")) == []


def test_checkpoint_signature_and_parser_share_one_byte_snapshot(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 1)
    publish_checkpoint(audit_dir, checkpoint_dir)
    original_read = checkpoints._stable_read_regular_file
    reads = []

    def counted_read(path, *, maximum_bytes, attempts=3):
        reads.append(path.name)
        return original_read(
            path,
            maximum_bytes=maximum_bytes,
            attempts=attempts,
        )

    monkeypatch.setattr(
        checkpoints,
        "_stable_read_regular_file",
        counted_read,
    )
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []
    assert reads.count("audit-checkpoint-00000000000000000001.ndjson") == 1


@pytest.mark.usefixtures("local_audit_key_custody")
def test_pinned_key_set_supports_rotation_and_rejects_new_signer(
    isolated_audit,
):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 1)
    key_a = AuditSigner(day_file).public_key_hex
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        trusted_pubkeys=[key_a],
    )

    rotate_audit_keypair()
    rotated = AuditSigner(day_file)
    key_b = rotated.public_key_hex
    assert key_b != key_a
    assert rotated.write({"kind": "tool_call", "index": 1})
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        trusted_pubkeys=[key_a, key_b],
    )
    assert (
        verify_checkpoints(
            audit_dir,
            checkpoint_dir,
            trusted_pubkeys=[key_a, key_b],
        )
        == []
    )
    reasons = {
        item.reason
        for item in verify_checkpoints(
            audit_dir,
            checkpoint_dir,
            trusted_pubkeys=[key_a],
        )
    }
    assert reasons == {"checkpoint_store_invalid"}

    assert rotated.write({"kind": "tool_call", "index": 2})
    with pytest.raises(AuditCheckpointError, match="outside the pinned"):
        publish_checkpoint(
            audit_dir,
            checkpoint_dir,
            trusted_pubkeys=[key_a],
        )


def test_verifier_does_not_mutate_read_only_evidence_paths(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 1)
    key = AuditSigner(day_file).public_key_hex
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        trusted_pubkeys=[key],
    )
    before = {
        path: path.stat().st_mtime_ns
        for path in [day_file, checkpoint_dir, *checkpoint_dir.glob("*.ndjson")]
    }

    def mutation_forbidden(*_args, **_kwargs):
        raise AssertionError("read-only verifier attempted a mutation")

    monkeypatch.setattr(checkpoints, "ensure_private_directory", mutation_forbidden)
    monkeypatch.setattr(checkpoints, "cross_process_lock", mutation_forbidden)
    assert (
        verify_checkpoints(
            audit_dir,
            checkpoint_dir,
            trusted_pubkeys=[key],
        )
        == []
    )
    assert {
        path: path.stat().st_mtime_ns
        for path in [day_file, checkpoint_dir, *checkpoint_dir.glob("*.ndjson")]
    } == before


def test_verifier_scans_each_checkpointed_day_once(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 1)
    publish_checkpoint(audit_dir, checkpoint_dir)
    assert AuditSigner(day_file).write({"kind": "tool_call", "index": 1})
    publish_checkpoint(audit_dir, checkpoint_dir)
    original_snapshot = checkpoints._snapshot_day_unlocked
    scans = []

    def counted_snapshot(path, trusted_keys):
        scans.append(path.name)
        return original_snapshot(path, trusted_keys)

    monkeypatch.setattr(
        checkpoints,
        "_snapshot_day_unlocked",
        counted_snapshot,
    )
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []
    assert scans == [day_file.name]


def test_external_minimum_digest_detects_signed_fork(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    _write_rows(audit_dir, 1)
    checkpoint = publish_checkpoint(audit_dir, checkpoint_dir)

    reasons = {
        item.reason
        for item in verify_checkpoints(
            audit_dir,
            checkpoint_dir,
            minimum_sequence=1,
            minimum_digest="0" * 64,
        )
    }
    assert reasons == {"checkpoint_fork"}
    assert (
        verify_checkpoints(
            audit_dir,
            checkpoint_dir,
            minimum_sequence=1,
            minimum_digest=_digest(checkpoint),
        )
        == []
    )


def test_gdpr_reanchor_requires_explicit_signed_supersession(isolated_audit):
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day_file = audit_dir / f"{_today()}.ndjson"
    signer = AuditSigner(day_file)
    assert signer.write(
        {
            "kind": "tool_call",
            "channel": "slack",
            "user_id": "subject",
        }
    )
    assert signer.write({"kind": "tool_call", "index": 1})
    original = publish_checkpoint(audit_dir, checkpoint_dir)
    original_digest = _digest(original)
    _erased, store_erase_record, erase_records = _erase_record_store()

    matched, _written = scrub_user(
        "slack",
        "subject",
        audit_dir=audit_dir,
        on_rewrite=store_erase_record,
        checkpoint_dirs=[checkpoint_dir],
    )
    assert matched == 1
    assert AuditSigner(day_file).write(
        {
            "kind": "erase",
            "erasure_id": "test",
            "supersedes_checkpoint_sha256": original_digest,
        }
    )
    with pytest.raises(AuditCheckpointError, match="changed within an era"):
        publish_checkpoint(audit_dir, checkpoint_dir)

    supersession = publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        supersedes_checkpoint_sha256=original_digest,
        lifecycle_reason="gdpr_reanchor",
        erase_records=erase_records,
    )
    record = json.loads(supersession.read_text(encoding="utf-8"))
    assert record["record_type"] == "supersession"
    assert record["supersedes_checkpoint_sha256"] == original_digest
    assert record["lifecycle_reason"] == "gdpr_reanchor"
    assert (
        publish_checkpoint(
            audit_dir,
            checkpoint_dir,
            supersedes_checkpoint_sha256=original_digest,
            lifecycle_reason="gdpr_reanchor",
        )
        == supersession
    )
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []


def test_live_day_supersession_rejects_unbound_erase_marker(isolated_audit):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 2)
    original = publish_checkpoint(audit_dir, checkpoint_dir)
    original_digest = _digest(original)
    rows = day_file.read_text(encoding="utf-8").splitlines()
    day_file.write_text(rows[0] + "\n", encoding="utf-8")
    assert AuditSigner(day_file).write(
        {
            "kind": "erase",
            "erasure_id": "unrelated",
            "supersedes_checkpoint_sha256": "0" * 64,
        }
    )

    with pytest.raises(AuditCheckpointError, match="exact superseded checkpoint"):
        publish_checkpoint(
            audit_dir,
            checkpoint_dir,
            supersedes_checkpoint_sha256=original_digest,
            lifecycle_reason="gdpr_reanchor",
        )


def test_closed_day_gdpr_supersession_binds_signed_reanchor(
    isolated_audit,
):
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file = audit_dir / f"{day}.ndjson"
    signer = AuditSigner(day_file)
    assert signer.write(
        {
            "kind": "tool_call",
            "channel": "slack",
            "user_id": "subject",
        }
    )
    assert signer.write({"kind": "tool_call", "index": 1})
    assert ensure_anchors(audit_dir) == 1
    original = publish_checkpoint(audit_dir, checkpoint_dir, day=day)
    original_digest = _digest(original)
    _erased, store_erase_record, erase_records = _erase_record_store()

    matched, _written = scrub_user(
        "slack",
        "subject",
        audit_dir=audit_dir,
        on_rewrite=store_erase_record,
        checkpoint_dirs=[checkpoint_dir],
    )
    assert matched == 1
    supersession = publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=original_digest,
        lifecycle_reason="gdpr_reanchor",
        erase_records=erase_records,
    )

    record = json.loads(supersession.read_text(encoding="utf-8"))
    anchor_rows = [
        json.loads(line)
        for line in (audit_dir / signing.ANCHOR_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert record["evidence_sha256"] == anchor_rows[-1]["hash"]
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []


def test_later_matching_anchor_does_not_invalidate_live_supersession(
    isolated_audit,
    monkeypatch,
):
    audit_dir, checkpoint_dir = isolated_audit
    day_file = _write_rows(audit_dir, 2)
    original = publish_checkpoint(audit_dir, checkpoint_dir)
    original_digest = _digest(original)
    rows = day_file.read_text(encoding="utf-8").splitlines()
    day_file.write_text(rows[0] + "\n", encoding="utf-8")
    assert AuditSigner(day_file).write(
        {
            "kind": "erase",
            "erasure_id": "bound",
            "supersedes_checkpoint_sha256": original_digest,
        }
    )
    supersession = publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        supersedes_checkpoint_sha256=original_digest,
        lifecycle_reason="gdpr_reanchor",
        allow_missing_erase_record=True,
    )
    marker_digest = json.loads(
        supersession.read_text(encoding="utf-8")
    )["evidence_sha256"]

    # Simulate the day becoming eligible for a normal closed-day anchor after
    # publication. The later evidence must not replace the immutable evidence
    # digest already bound into the supersession.
    monkeypatch.setattr(signing, "_today_utc", lambda: "9999-12-31")
    assert ensure_anchors(audit_dir) == 1
    anchor_rows = [
        json.loads(line)
        for line in (audit_dir / signing.ANCHOR_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert anchor_rows[-1]["hash"] != marker_digest
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []


def _checkpointed_closed_day(audit_dir, checkpoint_dir, day="2000-01-01"):
    day_file = audit_dir / f"{day}.ndjson"
    signer = AuditSigner(day_file)
    assert signer.write({"kind": "tool_call", "channel": "slack", "user_id": "subject"})
    assert signer.write({"kind": "tool_call", "index": 1})
    assert signer.write({"kind": "tool_call", "index": 2})
    assert ensure_anchors(audit_dir) == 1
    return day_file, publish_checkpoint(audit_dir, checkpoint_dir, day=day)


def _rewrite_as_key_holder(audit_dir, day_file):
    """Drop a row, then re-sign and re-anchor the day with the signing key."""
    rows = [json.loads(line) for line in day_file.read_text(encoding="utf-8").splitlines()]
    del rows[1]
    text, _signed = signing.resign_rows(
        [("json", row) for row in rows], signing._load_or_create_keypair(),
    )
    day_file.write_text(text, encoding="utf-8")
    signing.reanchor_day_after_erase(audit_dir, day_file)
    assert signing.verify_anchors(audit_dir) == [] and verify_chain(day_file) == []


def test_key_holder_cannot_replace_a_retained_checkpoint_unreported(isolated_audit):
    # Whoever holds the signing key can drop a row, re-sign the day, re-anchor
    # it and publish a supersession. All of that verifies; the verifier who
    # retained the earlier checkpoint must still be told.
    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file, pinned = _checkpointed_closed_day(audit_dir, checkpoint_dir)
    pin = {"minimum_sequence": 1, "minimum_digest": _digest(pinned)}
    _erased, _store, erase_records = _erase_record_store()

    _rewrite_as_key_holder(audit_dir, day_file)
    request = {
        "day": day,
        "supersedes_checkpoint_sha256": pin["minimum_digest"],
        "lifecycle_reason": "gdpr_reanchor",
    }

    # No erasure stored a record of this rewrite, so the honest publisher refuses.
    for lookup in (None, erase_records):
        with pytest.raises(AuditCheckpointError, match="no stored erase record"):
            publish_checkpoint(audit_dir, checkpoint_dir, erase_records=lookup, **request)
    # The key holder is not bound by that refusal; the verifier is the control.
    publish_checkpoint(audit_dir, checkpoint_dir, allow_missing_erase_record=True, **request)

    assert verify_checkpoints(audit_dir, checkpoint_dir) == []
    found = verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **pin)
    assert [(item.sequence, item.reason) for item in found] == [
        (2, "superseded_without_erase_record")
    ]
    assert day in found[0].detail
    unchecked = verify_checkpoints(audit_dir, checkpoint_dir, **pin)
    assert [item.reason for item in unchecked] == ["superseded_erase_record_unchecked"]


def test_erasure_supersession_is_reported_until_the_verifier_retains_it(isolated_audit):
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file, pinned = _checkpointed_closed_day(audit_dir, checkpoint_dir)
    pin = {"minimum_sequence": 1, "minimum_digest": _digest(pinned)}
    erased, store_erase_record, erase_records = _erase_record_store()

    assert scrub_user("slack", "subject", audit_dir=audit_dir, on_rewrite=store_erase_record,
                      checkpoint_dirs=[checkpoint_dir])[0] == 1
    assert [(r["day"], r["rows_before"], r["rows_after"], r["rows_erased"]) for r in erased] == [
        (day, 3, 3, 1)
    ]
    supersession = publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=pin["minimum_digest"],
        lifecycle_reason="gdpr_reanchor",
        erase_records=erase_records,
    )

    found = verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **pin)
    assert [(item.sequence, item.reason) for item in found] == [(2, "superseded_after_pin")]
    assert "e" * 32 in found[0].detail and "1 of 3 rows" in found[0].detail
    # Reviewed and retained: the newer sequence verifies clean again.
    retained = {"minimum_sequence": 2, "minimum_digest": _digest(supersession)}
    assert verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **retained) == []

    # Replaced again by the key holder: the first replacement still shows its
    # erasure, and the one that can be compared with the log shows none.
    _rewrite_as_key_holder(audit_dir, day_file)
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=retained["minimum_digest"],
        lifecycle_reason="gdpr_reanchor",
        allow_missing_erase_record=True,
    )
    found = verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **pin)
    assert [(item.sequence, item.reason) for item in found] == [
        (2, "superseded_after_pin"),
        (3, "superseded_without_erase_record"),
    ]
    # With its erase record gone, the first one can no longer be judged at all.
    found = verify_checkpoints(audit_dir, checkpoint_dir, erase_records=lambda day: [], **pin)
    assert [(item.sequence, item.reason) for item in found] == [
        (2, "superseded_then_replaced"),
        (3, "superseded_without_erase_record"),
    ]
    assert "again" in found[0].detail and "could not be read" not in found[0].detail


def test_every_erasure_behind_a_replaced_checkpoint_is_reported(isolated_audit):
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for person in ("first", "second"):
        assert signer.write({"kind": "tool_call", "channel": "slack", "user_id": person})
    assert signer.write({"kind": "tool_call", "index": 2})
    assert ensure_anchors(audit_dir) == 1
    pinned = _digest(publish_checkpoint(audit_dir, checkpoint_dir, day=day))
    erased, store_erase_record, erase_records = _erase_record_store()
    for number, person in enumerate(("first", "second"), start=1):
        assert scrub_user("slack", person, audit_dir=audit_dir, on_rewrite=store_erase_record,
                          erase_records=erase_records, checkpoint_dirs=[checkpoint_dir])[0] == 1
        erased[-1]["erasure_id"] = str(number) * 32
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=pinned,
        lifecycle_reason="gdpr_reanchor",
        erase_records=erase_records,
    )

    (found,) = verify_checkpoints(
        audit_dir, checkpoint_dir, erase_records=erase_records,
        minimum_sequence=1, minimum_digest=pinned,
    )
    assert found.reason == "superseded_after_pin"
    # The newest record speaks for itself; the earlier one is named, not summed.
    assert f"erase record {'2' * 32} says 1 of 3 rows" in found.detail
    assert f"1 earlier erase record is also on file for this day ({'1' * 32})" in found.detail


def test_overlapping_erasures_of_one_day_keep_the_checkpoint_evidence(isolated_audit):
    # The second erasure must not rewrite the day between the first one's
    # rewrite and the storing of its erase record: it would find a day that no
    # longer matches the checkpoint, with no record to explain why, and its
    # own record would vouch for nothing.
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    signer = AuditSigner(audit_dir / f"{day}.ndjson")
    for person in ("first", "second"):
        assert signer.write({"kind": "tool_call", "channel": "slack", "user_id": person})
    assert signer.write({"kind": "tool_call", "index": 2})
    assert ensure_anchors(audit_dir) == 1
    pinned = _digest(publish_checkpoint(audit_dir, checkpoint_dir, day=day))
    erased, store_erase_record, erase_records = _erase_record_store()
    rewritten, proceed, results = threading.Event(), threading.Event(), {}

    def held_store(summary):
        rewritten.set()  # the day is rewritten, its record not yet stored
        assert proceed.wait(10)
        store_erase_record(summary)

    def erase(person, on_rewrite):
        results[person] = scrub_user(
            "slack", person, audit_dir=audit_dir, strict=True, on_rewrite=on_rewrite,
            erase_records=erase_records, checkpoint_dirs=[checkpoint_dir],
        )[0]

    first = threading.Thread(target=erase, args=("first", held_store))
    second = threading.Thread(target=erase, args=("second", store_erase_record))
    first.start()
    assert rewritten.wait(10)
    second.start()
    second.join(1)  # long enough to get in, if anything lets it
    proceed.set()
    first.join(10)
    second.join(10)

    assert results == {"first": 1, "second": 1}
    assert [record["checkpoints"] for record in erased] == [[pinned], [pinned]]
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=pinned,
        lifecycle_reason="gdpr_reanchor",
        erase_records=erase_records,
    )


def test_an_erasure_undone_by_a_restore_is_not_counted_as_still_in_effect(isolated_audit):
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file = audit_dir / f"{day}.ndjson"
    signer = AuditSigner(day_file)
    for person in ("alice", "bob"):
        assert signer.write({"kind": "tool_call", "channel": "slack", "user_id": person})
    assert signer.write({"kind": "tool_call", "index": 2})
    assert ensure_anchors(audit_dir) == 1
    pinned = _digest(publish_checkpoint(audit_dir, checkpoint_dir, day=day))
    original = day_file.read_bytes()
    _erased, store_erase_record, erase_records = _erase_record_store()
    erase = {"audit_dir": audit_dir, "on_rewrite": store_erase_record,
             "erase_records": erase_records, "checkpoint_dirs": [checkpoint_dir]}

    assert scrub_user("slack", "alice", **erase)[0] == 1
    day_file.write_bytes(original)  # as a backup restore does: alice is back
    signing.reanchor_day_after_erase(audit_dir, day_file)
    assert scrub_user("slack", "bob", **erase)[0] == 1
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=pinned,
        lifecycle_reason="gdpr_reanchor",
        erase_records=erase_records,
    )

    (found,) = verify_checkpoints(
        audit_dir, checkpoint_dir, erase_records=erase_records,
        minimum_sequence=1, minimum_digest=pinned,
    )
    assert "alice" in day_file.read_text(encoding="utf-8")
    assert "says 1 of 3 rows were erased" in found.detail
    assert "2 of 3" not in found.detail and "1 earlier erase record" in found.detail


@pytest.mark.parametrize("told", [True, False])
def test_a_genuine_erase_does_not_cover_an_earlier_unrecorded_change(isolated_audit, told):
    # The key holder changes a pinned day and keeps its row count; later a
    # genuine erasure for someone in that day runs. Its erase record must not
    # make the whole change look like that erasure.
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file, pinned = _checkpointed_closed_day(audit_dir, checkpoint_dir)
    rows = [json.loads(line) for line in day_file.read_text(encoding="utf-8").splitlines()]
    rows[1] = {"kind": "tool_call", "note": "filler"}
    text, _signed = signing.resign_rows(
        [("json", row) for row in rows], signing._load_or_create_keypair(),
    )
    day_file.write_text(text, encoding="utf-8")
    signing.reanchor_day_after_erase(audit_dir, day_file)
    erased, store_erase_record, erase_records = _erase_record_store()
    pin = {"minimum_sequence": 1, "minimum_digest": _digest(pinned)}

    # The person is erased whether or not the erase is told about the
    # checkpoint folder. Either way its record lists no checkpoint, so it
    # cannot back replacing the one that was pinned.
    assert scrub_user("slack", "subject", strict=True, audit_dir=audit_dir,
                      on_rewrite=store_erase_record, erase_records=erase_records,
                      checkpoint_dirs=[checkpoint_dir] if told else [])[0] == 1
    assert erased[0]["checkpoints"] == []
    request = {
        "day": day,
        "supersedes_checkpoint_sha256": pin["minimum_digest"],
        "lifecycle_reason": "gdpr_reanchor",
    }
    with pytest.raises(AuditCheckpointError, match="no stored erase record"):
        publish_checkpoint(audit_dir, checkpoint_dir, erase_records=erase_records, **request)
    publish_checkpoint(audit_dir, checkpoint_dir, allow_missing_erase_record=True, **request)
    found = verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **pin)
    assert [(item.sequence, item.reason) for item in found] == [
        (2, "superseded_without_erase_record")
    ]


def test_an_earlier_erasure_record_does_not_back_a_later_rewrite(isolated_audit):
    # An erase record matches a day that still holds the rows the erasure
    # left. Rows written after it are not covered: changing those must not
    # pass as that same, already reviewed, erasure.
    from maverick.audit.erase import scrub_user

    audit_dir, checkpoint_dir = isolated_audit
    day_file = audit_dir / f"{_today()}.ndjson"
    signer = AuditSigner(day_file)
    assert signer.write({"kind": "tool_call", "channel": "slack", "user_id": "subject"})
    assert signer.write({"kind": "tool_call", "index": 1})
    first = _digest(publish_checkpoint(audit_dir, checkpoint_dir))
    _erased, store_erase_record, erase_records = _erase_record_store()

    def supersede(digest, **options):
        assert AuditSigner(day_file).write(
            {"kind": "erase", "supersedes_checkpoint_sha256": digest}
        )
        return publish_checkpoint(
            audit_dir,
            checkpoint_dir,
            supersedes_checkpoint_sha256=digest,
            lifecycle_reason="gdpr_reanchor",
            **options,
        )

    assert scrub_user("slack", "subject", audit_dir=audit_dir, on_rewrite=store_erase_record,
                      checkpoint_dirs=[checkpoint_dir])[0] == 1
    supersede(first, erase_records=erase_records)
    assert AuditSigner(day_file).write({"kind": "tool_call", "note": "to be removed"})
    assert AuditSigner(day_file).write({"kind": "tool_call", "index": 2})
    later = publish_checkpoint(audit_dir, checkpoint_dir)
    retained = {"minimum_sequence": 3, "minimum_digest": _digest(later)}
    assert verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **retained) == []

    rows = [json.loads(line) for line in day_file.read_text(encoding="utf-8").splitlines()]
    del rows[3]  # after the erased prefix, inside the retained checkpoint
    text, _signed = signing.resign_rows(
        [("json", row) for row in rows], signing._load_or_create_keypair(),
    )
    day_file.write_text(text, encoding="utf-8")
    with pytest.raises(AuditCheckpointError, match="no stored erase record"):
        supersede(retained["minimum_digest"], erase_records=erase_records)
    publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        supersedes_checkpoint_sha256=retained["minimum_digest"],
        lifecycle_reason="gdpr_reanchor",
        allow_missing_erase_record=True,
    )

    found = verify_checkpoints(audit_dir, checkpoint_dir, erase_records=erase_records, **retained)
    assert [(item.sequence, item.reason) for item in found] == [
        (4, "superseded_without_erase_record")
    ]


def test_a_day_retired_after_the_retained_sequence_is_reported(isolated_audit):
    # Deleting a pinned day, recording a retention purge and retiring its
    # checkpoint are all signed with the same key as the log.
    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file, pinned = _checkpointed_closed_day(audit_dir, checkpoint_dir)
    pin = {"minimum_sequence": 1, "minimum_digest": _digest(pinned)}
    record = json.loads(pinned.read_text(encoding="utf-8"))

    day_file.unlink()
    assert record_retention_purge(
        audit_dir,
        [{"day": day, "row_count": record["row_count"], "tip_hash": record["tip_hash"]}],
    )
    retirement = retire_checkpoint(
        audit_dir,
        checkpoint_dir,
        supersedes_checkpoint_sha256=pin["minimum_digest"],
        lifecycle_reason="retention_purge",
    )

    assert verify_checkpoints(audit_dir, checkpoint_dir) == []
    found = verify_checkpoints(audit_dir, checkpoint_dir, **pin)
    assert [(item.sequence, item.reason) for item in found] == [(2, "retired_after_pin")]
    assert day in found[0].detail
    assert verify_checkpoints(
        audit_dir, checkpoint_dir, minimum_sequence=2, minimum_digest=_digest(retirement),
    ) == []


def test_retention_requires_signed_retirement_instead_of_false_clean(
    isolated_audit,
):
    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file = audit_dir / f"{day}.ndjson"
    signer = AuditSigner(day_file)
    assert signer.write({"kind": "tool_call", "index": 0})
    assert ensure_anchors(audit_dir) == 1
    checkpoint = publish_checkpoint(audit_dir, checkpoint_dir, day=day)
    checkpoint_digest = _digest(checkpoint)
    checkpoint_record = json.loads(checkpoint.read_text(encoding="utf-8"))

    day_file.unlink()
    assert record_retention_purge(
        audit_dir,
        [
            {
                "day": day,
                "row_count": checkpoint_record["row_count"],
                "tip_hash": checkpoint_record["tip_hash"],
            }
        ],
    )
    reasons = {
        item.reason for item in verify_checkpoints(audit_dir, checkpoint_dir)
    }
    assert reasons == {"checkpointed_day_missing"}

    retirement = retire_checkpoint(
        audit_dir,
        checkpoint_dir,
        supersedes_checkpoint_sha256=checkpoint_digest,
        lifecycle_reason="retention_purge",
    )
    retired_record = json.loads(retirement.read_text(encoding="utf-8"))
    assert retired_record["record_type"] == "retirement"
    assert retired_record["supersedes_checkpoint_sha256"] == checkpoint_digest
    assert (
        retire_checkpoint(
            audit_dir,
            checkpoint_dir,
            supersedes_checkpoint_sha256=checkpoint_digest,
            lifecycle_reason="retention_purge",
        )
        == retirement
    )
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []

    assert AuditSigner(day_file).write({"kind": "unexpected_restore"})
    reasons = {
        item.reason for item in verify_checkpoints(audit_dir, checkpoint_dir)
    }
    assert reasons == {"retired_day_present"}


def test_later_duplicate_retention_marker_does_not_invalidate_retirement(
    isolated_audit,
):
    audit_dir, checkpoint_dir = isolated_audit
    day = "2000-01-01"
    day_file = audit_dir / f"{day}.ndjson"
    assert AuditSigner(day_file).write({"kind": "tool_call", "index": 0})
    assert ensure_anchors(audit_dir) == 1
    checkpoint = publish_checkpoint(audit_dir, checkpoint_dir, day=day)
    checkpoint_digest = _digest(checkpoint)
    record = json.loads(checkpoint.read_text(encoding="utf-8"))
    entry = {
        "day": day,
        "row_count": record["row_count"],
        "tip_hash": record["tip_hash"],
    }
    day_file.unlink()
    assert record_retention_purge(audit_dir, [entry])
    retirement = retire_checkpoint(
        audit_dir,
        checkpoint_dir,
        supersedes_checkpoint_sha256=checkpoint_digest,
        lifecycle_reason="retention_purge",
    )
    bound_digest = json.loads(
        retirement.read_text(encoding="utf-8")
    )["evidence_sha256"]

    assert record_retention_purge(audit_dir, [entry])
    anchor_rows = [
        json.loads(line)
        for line in (audit_dir / signing.ANCHOR_FILENAME)
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert anchor_rows[-1]["hash"] != bound_digest
    assert verify_checkpoints(audit_dir, checkpoint_dir) == []
