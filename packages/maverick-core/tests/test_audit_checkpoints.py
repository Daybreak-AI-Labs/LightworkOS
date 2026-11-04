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

    matched, _written = scrub_user(
        "slack",
        "subject",
        audit_dir=audit_dir,
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

    matched, _written = scrub_user(
        "slack",
        "subject",
        audit_dir=audit_dir,
    )
    assert matched == 1
    supersession = publish_checkpoint(
        audit_dir,
        checkpoint_dir,
        day=day,
        supersedes_checkpoint_sha256=original_digest,
        lifecycle_reason="gdpr_reanchor",
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
