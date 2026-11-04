"""Focused contract tests for the read-only Evolution Ledger projection."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from maverick.approval_signing import ApprovalRequest, key_id, sign_request
from maverick.evolution_ledger import (
    build_promotion_receipt,
    project_evolution_ledger,
    verify_promotion_receipt,
)
from maverick.learning_proof import paired_lift
from maverick.self_improvement import (
    ArtifactRevision,
    PromotionLedger,
    PromotionRecord,
)


def _record(**overrides) -> PromotionRecord:
    values = {
        "id": "candidate-private-identifier",
        "rung": "code",
        "summary": "private promotion summary must never reach the projection",
        "baseline_score": 0.2,
        "candidate_score": 0.9,
        "promoted_at": 10.0,
        "approver_id": "a" * 16,
        "payload_sha256": "b" * 64,
        "approval_signature": "c" * 128,
        "model_risk_payload_sha256": "d" * 64,
        "samples": 8,
        "effect_ci_low": 0.1,
        "provenance": {
            "workspace_snapshot_sha256": "e" * 64,
            "proof_sha256": "f" * 64,
            "raw_locator": "C:/private/path/that-must-not-leak",
        },
        "audit_payload": {"private_note": "do not expose this text"},
    }
    values.update(overrides)
    return PromotionRecord(**values)


def _artifact(name: str, *, identity: str = "runtime:private") -> ArtifactRevision:
    return ArtifactRevision(identity=identity, sha256=(name[0] * 64), version=name)


def test_projection_is_digest_only_read_only_and_preserves_lifecycle_lineage(
    tmp_path: Path,
    monkeypatch,
):
    path = tmp_path / "promotions.json"
    ledger = PromotionLedger(path=path)
    record = _record()
    ledger.add(record)
    assert ledger.mark_rolled_back(record.id, at=20.0)
    before = {
        path: path.read_bytes(),
        Path(f"{path}.journal"): Path(f"{path}.journal").read_bytes(),
    }
    lock_path = Path(f"{path}.journal.lock")
    lock_path.unlink(missing_ok=True)

    def _must_not_query_mutating_ledger_api():
        raise AssertionError("a read-only projection must not call repairing ledger APIs")

    monkeypatch.setattr(ledger, "all", _must_not_query_mutating_ledger_api)
    monkeypatch.setattr(ledger, "transactions", _must_not_query_mutating_ledger_api)

    proof = paired_lift([0.1, 0.2], [0.2, 0.4], bootstrap=20)
    projection = project_evolution_ledger(
        ledger,
        dreams=[
            {
                "ts": 5.0,
                "kind": "failure_pattern",
                "domain": "sensitive-domain",
                "text": "private prompt\nprivate remediation",
                "evidence": 2,
            }
        ],
        hindsight=[
            {
                "ts": 6.0,
                "before": "private snapshot label",
                "n_goals": 4,
                "covered_now": 3,
                "covered_before": 2,
                "gained": 1,
                "regressed": 0,
            }
        ],
        proofs=[proof],
    )

    assert {target: target.read_bytes() for target in before} == before
    assert not lock_path.exists()
    entries = {entry.kind: entry for entry in projection.entries}
    assert set(entries) == {"dreaming", "hindsight", "proof", "promotion", "rollback"}
    assert entries["promotion"].snapshot_sha256 == "e" * 64
    assert "f" * 64 in entries["promotion"].lineage_sha256
    assert entries["rollback"].subject_sha256 == entries["promotion"].subject_sha256
    assert entries["promotion"].entry_sha256 in entries["rollback"].lineage_sha256

    rendered = json.dumps(projection.to_dict(), sort_keys=True)
    for private in (
        record.id,
        record.summary,
        record.approval_signature,
        "C:/private/path/that-must-not-leak",
        "do not expose this text",
        "private prompt",
        "private snapshot label",
        "sensitive-domain",
    ):
        assert private not in rendered
    assert "e" * 64 in rendered
    assert entries["dreaming"].integrity == "mutable_private_dream_store"
    assert entries["hindsight"].integrity == "aggregate_hindsight_ledger_unverified"
    assert entries["proof"].integrity == "runtime_lift_result_unbound"
    assert entries["promotion"].integrity == "hash_chained_local_promotion_ledger"


def test_committed_transaction_uses_only_artifact_and_transaction_digests(tmp_path: Path):
    ledger = PromotionLedger(path=tmp_path / "promotions.json")
    before = _artifact("before", identity="runtime:tenant-secret")
    after = _artifact("after", identity="runtime:tenant-secret")
    record = _record(id="transaction-private-id", promoted_at=1.0)
    ledger.prepare(
        record,
        before=before,
        after=after,
        prepared_at=2.0,
        transaction_id="private-transaction-id",
    )
    ledger.commit("private-transaction-id", artifact=after, at=3.0)
    assert ledger.mark_rolled_back(record.id, at=4.0)

    projection = project_evolution_ledger(ledger)
    entries = {entry.kind: entry for entry in projection.entries}
    promotion = entries["promotion"]
    rollback = entries["rollback"]
    assert promotion.artifact_sha256 == after.sha256
    assert promotion.entry_sha256 in rollback.lineage_sha256
    assert promotion.subject_sha256 == rollback.subject_sha256

    rendered = json.dumps(projection.to_dict(), sort_keys=True)
    assert "private-transaction-id" not in rendered
    assert "runtime:tenant-secret" not in rendered
    assert before.version not in rendered
    assert after.version not in rendered


def test_projection_does_not_repair_a_stale_promotion_compatibility_file(tmp_path: Path):
    path = tmp_path / "promotions.json"
    ledger = PromotionLedger(path=path)
    ledger.add(_record())
    journal_path = Path(f"{path}.journal")
    stale = b"[]\n"
    path.write_bytes(stale)
    journal_before = journal_path.read_bytes()
    lock_path = Path(f"{journal_path}.lock")
    lock_path.unlink(missing_ok=True)

    projection = project_evolution_ledger(ledger)

    assert [entry.kind for entry in projection.entries] == ["promotion"]
    assert path.read_bytes() == stale
    assert journal_path.read_bytes() == journal_before
    assert not lock_path.exists()


def test_promotion_receipt_verifies_signature_only_with_private_binding():
    ed25519 = pytest.importorskip(
        "cryptography.hazmat.primitives.asymmetric.ed25519",
        reason="cryptography required for approval signing",
    )
    from cryptography.hazmat.primitives import serialization

    private = ed25519.Ed25519PrivateKey.generate()
    private_hex = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    public_hex = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        .hex()
    )
    request = ApprovalRequest("candidate-kept-private", "code", "a" * 64)
    signature = sign_request(request, private_hex)
    receipt = build_promotion_receipt(
        _record(
            id=request.candidate_id,
            rung=request.rung,
            payload_sha256=request.payload_sha256,
            approval_signature=signature,
            approver_id=key_id(public_hex),
        )
    )

    rendered = json.dumps(receipt, sort_keys=True)
    assert request.candidate_id not in rendered
    assert signature not in rendered
    assert verify_promotion_receipt(receipt).approval_status == (
        "not_verifiable_without_private_binding"
    )
    verified = verify_promotion_receipt(
        receipt,
        approval_request=request,
        approval_signature=signature,
        trusted_pubkeys=[public_hex],
    )
    assert verified.receipt_valid is True
    assert verified.approval_status == "verified"
    assert verified.approval_signer_key_id == key_id(public_hex)

    tampered = dict(receipt)
    tampered["scores"] = {**receipt["scores"], "candidate": 0.1}
    invalid = verify_promotion_receipt(tampered)
    assert invalid.receipt_valid is False
    assert invalid.approval_status == "receipt_invalid"


def test_receipt_with_non_ascii_payload_digest_is_a_binding_mismatch():
    from maverick.evolution_ledger import _digest

    request = ApprovalRequest("candidate-kept-private", "code", "a" * 64)
    receipt = build_promotion_receipt(
        _record(
            id=request.candidate_id,
            rung=request.rung,
            payload_sha256=request.payload_sha256,
        )
    )
    # A self-consistent receipt supplied for verification can carry any text in
    # its unchecked payload digest; that is a mismatch, not a TypeError.
    forged = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    forged["payload_sha256"] = "é" * 64
    forged["receipt_sha256"] = _digest("promotion-receipt", forged)

    result = verify_promotion_receipt(
        forged,
        approval_request=request,
        approval_signature="c" * 128,
        trusted_pubkeys=[],
    )

    assert result.receipt_valid is True
    assert result.approval_status == "private_binding_mismatch"


def test_workspace_snapshot_id_is_not_misrepresented_as_a_content_digest():
    receipt = build_promotion_receipt(
        _record(
            provenance={
                "snapshot_id": "snap-0001-private",
                "snapshot_path": "C:/private/snap-0001.tar.gz",
            },
            audit_payload={},
        )
    )
    assert receipt["snapshot_sha256"] is None
    assert "workspace_snapshot_digest_not_recorded" in receipt["limitations"]
    rendered = json.dumps(receipt, sort_keys=True)
    assert "snap-0001-private" not in rendered
    assert "C:/private/snap-0001.tar.gz" not in rendered
