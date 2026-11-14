"""Actual bounded readers, framed history, and truthful evidence coverage."""
from __future__ import annotations

import io
import json
import os

import pytest
from click.testing import CliRunner
from maverick import crypto_at_rest as crypto
from maverick.audit import signing
from maverick.audit.reader import iter_events, tail_events
from maverick.audit.sealing import seal_closed_segments, segment_text
from maverick.audit.segments import READ_CHUNK, ReadReport, SegmentReadError, SegmentSnapshot
from maverick.audit.signing import AuditSigner
from maverick.file_lock import atomic_write_bytes, atomic_write_bytes_chunks, open_private_read
from maverick.sealed_stream import FRAME_SIZE, STREAM_MAGIC, encode_stream


@pytest.fixture(autouse=True)
def isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "11" * 32)
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "fixture.key")
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "signing-keys")


def test_large_live_tail_reads_only_suffix_and_exact_last_records(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    rows = 25000
    atomic_write_bytes_chunks(path, ((json.dumps({"i": i, "data": "x" * 700}) + "\n").encode() for i in range(rows)))
    report = ReadReport()
    result = tail_events(path, 20, report=report)
    assert [e["i"] for e in result] == list(range(rows - 20, rows))
    assert report.bytes_read <= READ_CHUNK + 8
    assert report.state == "readable_complete"
    assert report.scope == "requested_tail"
    assert report.verification == "not_requested"


def test_new_history_tail_is_bounded_and_preserves_every_signed_byte(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    signer = AuditSigner(path)
    for i in range(75):
        assert signer.write({"i": i, "data": "Ω" * 20000})
    original = path.read_bytes()
    assert len(original) > FRAME_SIZE * 2
    assert seal_closed_segments(path.parent, today="2099-01-01")[path.name] == "sealed"
    assert path.read_bytes().startswith(STREAM_MAGIC)
    assert crypto.unseal(path.read_bytes()) == original
    assert signing.verify_chain(path) == []
    report = ReadReport()
    assert [e["i"] for e in tail_events(path, 2, report=report)] == [73, 74]
    assert report.bytes_read < FRAME_SIZE + 5000
    assert not report.legacy_whole_blob
    assert not report.failures


@pytest.mark.parametrize("payload,expected,count", [
    (b"", "empty", 0),
    (b'{"i":1}\n', "readable_complete", 1),
    (b'{"i":1}\n{invalid}\n', "partial", 1),
    (b'{invalid}\n', "unreadable", 0),
    (b'{"i":1}\n{"i":', "partial", 1),
])
def test_read_coverage_distinguishes_empty_partial_and_unreadable(tmp_path, payload, expected, count):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, payload)
    report = ReadReport()
    assert len(list(iter_events(audit_dir=path.parent, all_days=True, report=report))) == count
    assert report.state == expected
    assert report.as_dict()["checkpoints"] == "not_verified"


def test_signed_export_verified_complete_but_never_claims_checkpoint_proof(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    signer = AuditSigner(path)
    signer.write({"kind": "tool_call", "n": 1})
    report = ReadReport()
    assert len(list(iter_events(audit_dir=path.parent, all_days=True, report=report, verify=True))) == 1
    assert report.state == "verified_complete"
    assert report.verification == "segment_chains_verified"
    assert report.as_dict()["anchors"] == "not_verified"
    raw = path.read_bytes().replace(b'"n": 1', b'"n": 2')
    atomic_write_bytes(path, raw)
    report = ReadReport()
    assert list(iter_events(audit_dir=path.parent, all_days=True, report=report, verify=True)) == []
    assert report.state == "unreadable"
    assert report.verification == "failed"


def test_unsigned_is_not_verified_and_early_closed_iterator_stays_partial(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n{"i":2}\n')
    report = ReadReport()
    assert list(iter_events(audit_dir=path.parent, all_days=True, report=report, verify=True)) == []
    assert report.verification == "failed"
    report = ReadReport()
    events = iter_events(audit_dir=path.parent, all_days=True, report=report)
    assert next(events) == {"i": 1}
    events.close()
    assert report.state == "partial"


def test_corrupt_frame_can_never_be_returned_and_strict_fails(tmp_path, monkeypatch):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n')
    seal_closed_segments(path.parent, today="2099-01-01")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "22" * 32)
    report = ReadReport()
    assert list(iter_events(audit_dir=path.parent, all_days=True, report=report)) == []
    assert report.state == "unreadable"
    with pytest.raises(SegmentReadError):
        list(iter_events(audit_dir=path.parent, all_days=True, strict=True))
    assert signing.verify_chain(path)[0].reason == "unreadable_segment"


def test_partial_live_tail_reports_truncated_final_record(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n{"i":2}\n{"i":')
    report = ReadReport()
    assert tail_events(path, 2, report=report) == [{"i": 1}, {"i": 2}]
    assert report.state == "partial"


def test_source_replacement_or_append_is_reported_after_snapshot(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n')
    with SegmentSnapshot(path, ReadReport()) as snapshot:
        with path.open("ab") as output:
            output.write(b'{"i":2}\n')
        with pytest.raises(SegmentReadError, match="changed"):
            list(snapshot.lines())


def test_same_size_same_timestamp_change_between_proof_and_export_is_detected(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b'{"i":1}\n')
    with SegmentSnapshot(path, ReadReport()) as snapshot:
        assert list(snapshot.lines()) == ['{"i":1}\n']
        before = path.stat()
        path.write_bytes(b'{"i":2}\n')
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with pytest.raises(SegmentReadError, match="between verification"):
            list(snapshot.lines())


def test_legacy_sealed_reader_retains_compatibility_and_reports_cost(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, crypto.seal(b'{"i":1}\n'))
    report = ReadReport()
    assert list(iter_events(audit_dir=path.parent, all_days=True, report=report)) == [{"i": 1}]
    assert report.legacy_whole_blob
    assert report.state == "readable_complete"
    assert segment_text(path, fail_soft=False) == '{"i":1}\n'


def test_stream_publication_failure_retains_exact_original_and_no_plaintext_temp(tmp_path, monkeypatch):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    original = b'{"secret":"do-not-publish"}\n'  # pragma: allowlist secret - synthetic plaintext retention sentinel
    atomic_write_bytes(path, original)
    actual = crypto.seal
    calls = 0
    def fail_manifest(payload):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise crypto.EncryptionUnavailable("injected failure")
        return actual(payload)
    monkeypatch.setattr(crypto, "seal", fail_manifest)
    with pytest.raises(crypto.EncryptionUnavailable):
        seal_closed_segments(path.parent, today="2099-01-01")
    assert path.read_bytes() == original
    assert not list(path.parent.glob("*.tmp"))


def test_private_stream_reader_refuses_hardlink_without_reading(tmp_path):
    original = tmp_path / "original"
    original.write_bytes(b"sensitive")
    target = tmp_path / "audit" / "2020-01-01.ndjson"
    target.parent.mkdir()
    os.link(original, target)
    with pytest.raises(PermissionError):
        open_private_read(target)


def test_framed_crypto_preserves_tenant_and_shared_authority_refusals(monkeypatch):
    from maverick.paths import tenant_scope
    from maverick.tenant import kms

    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    kms._clear_cache()
    try:
        with tenant_scope(tenant="acme"):
            blob = b"".join(encode_stream(io.BytesIO(b"private"), crypto.seal))
            assert crypto.unseal(blob) == b"private"
        with tenant_scope(tenant="beta"), pytest.raises(crypto.EncryptionUnavailable):
            crypto.unseal(blob)
        with tenant_scope(tenant="acme"), crypto.deployment_key_scope(), pytest.raises(crypto.EncryptionUnavailable, match="tenant-envelope"):
            crypto.unseal(blob)
        with tenant_scope(tenant="acme"), crypto.external_fleet_key_scope(), pytest.raises(crypto.EncryptionUnavailable, match="tenant-envelope"):
            crypto.unseal(blob)
    finally:
        kms._clear_cache()


def test_cli_separate_receipt_and_nonzero_incomplete_export(monkeypatch, tmp_path):
    from maverick.cli import main
    from maverick.paths import data_dir

    audit_dir = data_dir("audit")
    source = audit_dir / "2020-01-01.ndjson"
    atomic_write_bytes(source, b'{"i":1}\nBROKEN\n')
    output, receipt = tmp_path / "output.jsonl", tmp_path / "read-report.json"
    result = CliRunner().invoke(main, ["audit", "export", "--all", "-o", str(output), "--read-report", str(receipt)])
    assert result.exit_code == 1, result.output
    assert "partial" in result.stderr
    assert json.loads(output.read_text()) == {"i": 1}
    assert json.loads(receipt.read_text())["state"] == "partial"
    result = CliRunner().invoke(main, ["audit", "export", "--all", "--read-report", str(source)])
    assert result.exit_code != 0
    assert source.read_bytes() == b'{"i":1}\nBROKEN\n'


def test_unreadable_directory_cannot_be_reported_empty(tmp_path):
    root = tmp_path / "audit"
    root.write_bytes(b"not a directory")
    report = ReadReport()
    assert list(iter_events(audit_dir=root, all_days=True, report=report)) == []
    assert report.state == "unreadable"


@pytest.mark.parametrize("flag", ["--read-report", "--output"])
@pytest.mark.parametrize("relative", ["anchors.ndjson", "2019-01-01.ndjson", "worm/receipts.json", "future-report.json"])
def test_export_outputs_cannot_replace_any_audit_authority(tmp_path, flag, relative):
    from maverick.cli import main
    from maverick.paths import data_dir

    root = data_dir("audit")
    atomic_write_bytes(root / "2020-01-01.ndjson", b'{"i":1}\n')
    target = root / relative
    original = b"protected authority"
    if relative != "future-report.json":
        atomic_write_bytes(target, original)
    result = CliRunner().invoke(main, ["audit", "export", "--day", "2020-01-01", flag, str(target)])
    assert result.exit_code != 0, result.output
    assert "protected audit directory" in result.output
    if relative == "future-report.json":
        assert not target.exists()
    else:
        assert target.read_bytes() == original


@pytest.mark.parametrize("flag", ["--read-report", "--output"])
def test_export_outputs_refuse_outside_hardlink_to_unselected_evidence(tmp_path, flag):
    from maverick.cli import main
    from maverick.paths import data_dir

    root = data_dir("audit")
    atomic_write_bytes(root / "2020-01-01.ndjson", b'{"i":1}\n')
    protected = root / "anchors.ndjson"
    atomic_write_bytes(protected, b"protected anchors")
    alias = tmp_path / "outside-receipt.json"
    os.link(protected, alias)
    result = CliRunner().invoke(main, ["audit", "export", "--day", "2020-01-01", flag, str(alias)])
    assert result.exit_code != 0, result.output
    assert "hard link" in result.output
    assert protected.read_bytes() == alias.read_bytes() == b"protected anchors"


def test_export_receipt_canonical_dotdot_cannot_enter_audit_directory(tmp_path):
    from maverick.audit.export import validate_export_destination
    from maverick.paths import data_dir

    root = data_dir("audit")
    with pytest.raises(ValueError, match="protected audit directory"):
        validate_export_destination(root / ".." / "audit" / "anchors.ndjson")


def test_rotation_preserves_framed_history_and_fleet_refuses_local_keyring(monkeypatch):
    # Local rotation needs a node-local key: an injected key is rotated where it is managed.
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY")
    initial = b"".join(encode_stream(io.BytesIO(b"initial"), crypto.seal))
    crypto.rotate_at_rest_key()
    rotated = b"".join(encode_stream(io.BytesIO(b"rotated"), crypto.seal))
    crypto.rotate_at_rest_key()
    assert crypto.unseal(initial) == b"initial"
    assert crypto.unseal(rotated) == b"rotated"
    with crypto.external_fleet_key_scope(), pytest.raises(crypto.EncryptionUnavailable, match="node-local"):
        crypto.unseal(rotated)


def test_checkpoint_and_anchor_proof_stays_valid_after_framed_seal(tmp_path):
    from maverick.audit.checkpoints import publish_checkpoint, verify_checkpoints
    from maverick.audit.signing import ensure_anchors, verify_anchors

    audit_dir = tmp_path / "audit"
    path = audit_dir / "2020-01-01.ndjson"
    signer = AuditSigner(path)
    signer.write({"kind": "tool_call", "i": 1})
    ensure_anchors(audit_dir)
    independent = tmp_path / "independent-checkpoints"
    publish_checkpoint(audit_dir, independent, day="2020-01-01")
    seal_closed_segments(audit_dir, today="2099-01-01")
    assert verify_anchors(audit_dir) == []
    assert verify_checkpoints(audit_dir, independent) == []


def test_framed_worm_and_retention_preserve_custody(tmp_path):
    from maverick.audit import retention, worm
    from maverick.audit.signing import ensure_anchors, verify_anchors

    audit_dir = tmp_path / "audit"
    path = audit_dir / "2020-01-01.ndjson"
    signer = AuditSigner(path)
    signer.write({"kind": "tool_call", "i": 1})
    ensure_anchors(audit_dir)
    seal_closed_segments(audit_dir, today="2099-01-01")
    sink = worm.LocalWormSink(audit_dir / "worm" / "store")
    assert worm.push_closed_dayfiles(audit_dir=audit_dir, sink=sink)[path.name] == "pushed"
    assert worm.verify(audit_dir=audit_dir)[path.name] == "ok"
    assert len(retention.purge_audit_files(days=30, audit_dir=audit_dir)["removed"]) == 1
    assert not path.exists()
    assert verify_anchors(audit_dir) == []


def test_explicit_tenant_export_pins_crypto_without_leaking_scope_across_yield(monkeypatch):
    from maverick.paths import current_tenant_id, data_dir, tenant_scope
    from maverick.tenant import kms

    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    monkeypatch.setattr(signing, "KEY_DIR", signing._LEGACY_KEY_DIR)
    kms._clear_cache()
    try:
        with tenant_scope(tenant="acme"):
            directory = data_dir("audit")
            signer = AuditSigner(directory / "2020-01-01.ndjson")
            signer.write({"i": 1})
            signer.write({"i": 2})
            seal_closed_segments(directory, today="2099-01-01")
        with tenant_scope(tenant="beta"):
            report = ReadReport()
            events = iter_events(all_days=True, tenant="acme", report=report, verify=True)
            assert next(events)["i"] == 1
            assert current_tenant_id() == "beta"
            assert next(events)["i"] == 2
            assert current_tenant_id() == "beta"
            assert list(events) == []
            assert report.state == "verified_complete"
            assert current_tenant_id() == "beta"
    finally:
        kms._clear_cache()


def test_verification_failure_collection_is_bounded(tmp_path):
    path = tmp_path / "audit" / "2020-01-01.ndjson"
    atomic_write_bytes(path, b"BROKEN\n" * 10000)
    with SegmentSnapshot(path, ReadReport()) as snapshot:
        breaks = signing.verify_chain(path, lines=snapshot.lines(), max_breaks=64)
        assert len(breaks) == 64
    report = ReadReport()
    assert list(iter_events(audit_dir=path.parent, all_days=True, verify=True, report=report)) == []
    assert report.state == "unreadable"
    assert report.bytes_read <= READ_CHUNK + 8


@pytest.mark.parametrize("payload", [b'{"x":' + b'[' * 10000 + b'0' + b']' * 10000 + b'}\n', b'{"x":' + b'9' * 10000 + b'}\n'])
def test_pathological_json_verification_emits_failed_coverage_receipt(tmp_path, payload):
    from maverick.cli import main
    from maverick.paths import data_dir

    path = data_dir("audit") / "2020-01-01.ndjson"
    atomic_write_bytes(path, payload)
    assert signing.verify_chain(path)[0].reason == "malformed"
    report = ReadReport()
    assert list(iter_events(audit_dir=path.parent, all_days=True, report=report, verify=True)) == []
    assert report.failures == 1
    assert report.verification == "failed"
    assert report.state == "unreadable"
    receipt = tmp_path / "failed-coverage.json"
    result = CliRunner().invoke(main, ["audit", "export", "--all", "--verify", "--read-report", str(receipt)])
    assert result.exit_code == 1, result.output
    assert json.loads(receipt.read_text())["state"] == "unreadable"
