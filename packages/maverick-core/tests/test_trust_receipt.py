"""Trust receipts: bearer-verifiable evidence for one audited decision.

Every test here runs the production signer against the standalone verifier,
so a drift in either canonicalisation shows up as a failing test rather than
as a false accusation against an honest customer.
"""
from __future__ import annotations

import builtins
import json
import os
from pathlib import Path

import pytest

pytest.importorskip("cryptography")

from maverick import trust_receipt as tr  # noqa: E402
from maverick import trust_receipt_verify as tv  # noqa: E402

DAY = "2026-01-01"


# ---- fixtures ---------------------------------------------------------------

@pytest.fixture
def audit_dir(tmp_path):
    d = tmp_path / "audit"
    d.mkdir()
    return d


def _write_chain(audit_dir: Path, day: str, rows: list[dict]) -> Path:
    """Write a genuinely signed day-file using the production signer."""
    from maverick.audit.signing import AuditSigner
    path = audit_dir / f"{day}.ndjson"
    signer = AuditSigner(path)
    for row in rows:
        assert signer.write(dict(row))
    return path


def _rows() -> list[dict]:
    return [
        {"ts": 1.0, "kind": "tool_call", "agent": "worker-0-abc123",
         "name": "read_file", "input_summary": "..."},
        {"ts": 2.0, "kind": "governance_denied", "agent": "worker-0-abc123",
         "tool": "wire_transfer", "principal": "agent:finance-1",
         "rule": "deny_actions", "reason": "wire_transfer is denied by policy"},
        {"ts": 3.0, "kind": "tool_result", "agent": "worker-0-abc123",
         "name": "read_file", "status": "ok", "output_summary": "..."},
    ]


def _paired_rows(*, commitment: str | None = None,
                  input_summary: str = "private account 1234") -> list[dict]:
    from maverick.audit.events import (
        TOOL_CALL_COMMITMENT_ALGORITHM,
        tool_call_commitment,
    )

    fields = {
        "call_id": "ab" * 12,
        "name": "read_file",
        "agent": "worker-0-abc123",
        "goal_id": 7,
        "origin": "agent",
        "principal": "user:alice",
    }
    digest = commitment or tool_call_commitment(call_id=fields["call_id"])
    return [
        {"ts": 1.0, "kind": "tool_call", **fields,
         "call_commitment": digest,
         "call_commitment_algorithm": TOOL_CALL_COMMITMENT_ALGORITHM,
         "input_summary": input_summary},
        {"ts": 2.0, "kind": "tool_result", **fields,
         "call_commitment": digest,
         "call_commitment_algorithm": TOOL_CALL_COMMITMENT_ALGORITHM,
         "status": "ok", "output_summary": "ok"},
    ]


def _hashes(path: Path) -> list[str]:
    return [json.loads(ln)["hash"] for ln in path.read_text().splitlines() if ln.strip()]


def _key() -> str:
    from maverick.attestation import publisher_key
    return publisher_key()[1]


def _resign(receipt: dict) -> dict:
    """Re-sign an edited receipt with the real key (an insider edit)."""
    return tr.sign({k: v for k, v in receipt.items() if k != "signature"})


def _claim(result, name: str):
    return next(c for c in result.claims if c.name == name)


@pytest.fixture
def denial_receipt(audit_dir):
    path = _write_chain(audit_dir, DAY, _rows())
    denial = _hashes(path)[1]
    return tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=denial,
        include_suffix=True,
        now=1767225600.0,
    ))


# ---- happy paths ------------------------------------------------------------

def test_a_receipt_verifies_against_the_out_of_band_key(denial_receipt):
    result = tv.verify(denial_receipt, trusted_keys=[_key()])
    assert result.ok, result.reason
    assert _claim(result, "row_integrity").status == tv.HOLDS
    assert _claim(result, "claim_consistency").status == tv.HOLDS
    assert _claim(result, "chain_linkage").status == tv.HOLDS
    # No checkpoint and no anchor ledger: authentic and chained to a tip the
    # issuer computed, but nothing committed to that tip.
    assert _claim(result, "commitment").status == tv.INDETERMINATE
    assert result.depth == tv.DEPTH_SIGNED


@pytest.mark.parametrize("custody", ["colocated", "offhost"])
def test_key_source_label_does_not_promote_offline_assurance(denial_receipt, custody):
    denial_receipt["issuer"]["key_custody"] = custody
    result = tv.verify(_resign(denial_receipt), trusted_keys=[_key()])
    assert result.ok, result.reason
    assert result.depth == tv.DEPTH_SIGNED
    assert _claim(result, "commitment").status == tv.INDETERMINATE
    report = tv.format_report(result)
    if custody == "offhost":
        assert "does not establish isolated signing" in report
        assert "local signing process" in report
    else:
        assert "an actor who can read that key" in report


def test_the_claim_is_derived_from_the_row(denial_receipt):
    assert denial_receipt["claim"] == {
        "kind": "governance_denied", "decision": "denied", "tool": "wire_transfer",
        "occurred_at": 2.0, "principal": "agent:finance-1",
        "agent": "worker-0-abc123", "rule": "deny_actions",
        "reason": "wire_transfer is denied by policy",
    }
    assert denial_receipt["locator"]["position"] == 2
    assert denial_receipt["chain"]["row_count"] == 3
    assert len(denial_receipt["chain"]["suffix_ndjson"]) == 1


def test_the_row_hash_rule_matches_the_production_signer(audit_dir):
    path = _write_chain(audit_dir, DAY, _rows())
    for line in path.read_text().splitlines():
        row = json.loads(line)
        assert tv.audit_row_hash(row) == row["hash"]
        assert tv.key_id_of(_key()) == row["key_id"]


def test_the_anchor_ledger_commits_a_closed_day(audit_dir):
    from maverick.audit.signing import ensure_anchors
    path = _write_chain(audit_dir, DAY, _rows())
    assert ensure_anchors(audit_dir) >= 1
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_suffix=True,
    ))
    assert receipt["commitment"]["source"] == "anchor_ledger"
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert result.ok, result.reason
    # Issuer-signed, co-located: chained, never anchored.
    assert result.depth == tv.DEPTH_CHAINED


def test_anchor_ledger_uses_audit_keys_not_checkpoint_keys(audit_dir):
    from maverick.audit.signing import ensure_anchors

    path = _write_chain(audit_dir, DAY, _rows())
    assert ensure_anchors(audit_dir) >= 1
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_suffix=True,
    ))
    result = tv.verify(
        receipt,
        trusted_keys=[_key()],
        checkpoint_keys=["ab" * 32],
    )
    assert result.ok, result.reason
    assert _claim(result, "commitment").status == tv.HOLDS


def test_a_checkpoint_reaches_anchored_only_with_something_external(audit_dir, tmp_path):
    from maverick.audit.signing import ensure_anchors
    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    ckpt = tmp_path / "checkpoints"
    receipt = tr.sign(tr.build(audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1],
                               checkpoint_dir=ckpt, include_suffix=True))
    commitment = receipt["commitment"]
    assert commitment["source"] == "checkpoint"
    assert commitment["record"]["tip_hash"] == receipt["chain"]["tip_hash"]
    assert commitment["record"]["row_count"] == receipt["chain"]["row_count"]

    alone = tv.verify(receipt, trusted_keys=[_key()])
    assert alone.ok and alone.depth == tv.DEPTH_CHAINED

    by_digest = tv.verify(receipt, trusted_keys=[_key()],
                          anchor_digest=commitment["raw_sha256"])
    assert by_digest.ok and by_digest.depth == tv.DEPTH_ANCHORED

    by_file = tv.verify(receipt, trusted_keys=[_key()], checkpoint_dir=ckpt)
    assert by_file.ok and by_file.depth == tv.DEPTH_CHAINED
    assert any(
        "not independent" in note
        for note in _claim(by_file, "commitment").notes
    )


def test_checkpoint_uses_checkpoint_keys_not_audit_keys(audit_dir, tmp_path):
    from maverick.audit.signing import ensure_anchors

    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        checkpoint_dir=tmp_path / "checkpoints",
        include_suffix=True,
    ))
    result = tv.verify(
        receipt,
        trusted_keys=[_key()],
        checkpoint_keys=["ab" * 32],
    )
    assert not result.ok
    assert _claim(result, "commitment").status == tv.FAILS
    assert "not a trusted key" in _claim(result, "commitment").detail


def test_a_receipt_without_the_suffix_is_signed_depth_only(audit_dir):
    path = _write_chain(audit_dir, DAY, _rows())
    receipt = tr.sign(tr.build(audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1],
                               include_suffix=False))
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert result.ok
    assert _claim(result, "chain_linkage").status == tv.INDETERMINATE
    assert result.depth == tv.DEPTH_SIGNED


def test_a_valid_historical_v1_receipt_verifies_with_v1_claim_semantics(audit_dir):
    path = _write_chain(audit_dir, DAY, _rows())
    legacy = tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[0],
        include_suffix=True,
        now=1767225600.0,
    )
    legacy["schema_version"] = 1
    legacy.pop("disclosure")
    legacy.pop("execution_pair")
    legacy["claim"] = {
        "kind": "tool_call",
        "decision": "executed",
        "tool": "read_file",
        "occurred_at": 1.0,
        "agent": "worker-0-abc123",
    }

    result = tv.verify(tr.sign(legacy), trusted_keys=[_key()])

    assert result.ok, result.reason
    assert _claim(result, "claim_consistency").status == tv.HOLDS
    assert not any(claim.name == "disclosure" for claim in result.claims)
    assert not any(claim.name == "execution_pair" for claim in result.claims)
    assert any("legacy schema-v1" in finding for finding in result.findings)


@pytest.mark.parametrize("version", [None, True, "1", 0, 3, 99])
def test_malformed_and_unknown_receipt_versions_fail_closed(
    denial_receipt,
    version,
):
    edited = json.loads(json.dumps(denial_receipt))
    edited["schema_version"] = version

    result = tv.verify(_resign(edited), trusted_keys=[_key()])

    assert not result.ok
    assert result.depth == tv.DEPTH_NONE
    assert "schema version" in result.reason


def test_privacy_safe_default_omits_unrelated_later_rows(audit_dir):
    rows = [
        {"ts": 1.0, "kind": "governance_denied", "tool": "email",
         "reason": "policy"},
        {"ts": 2.0, "kind": "tool_result", "name": "crm_lookup",
         "status": "ok", "principal": "user:unrelated@example.test",
         "output_summary": "private customer health information"},
    ]
    path = _write_chain(audit_dir, DAY, rows)
    receipt = tr.build(audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[0])
    assert receipt["chain"]["suffix_ndjson"] == []
    encoded = json.dumps(receipt)
    assert "unrelated@example.test" not in encoded
    assert "private customer health information" not in encoded


def test_tool_result_receipt_omits_call_row_by_default(audit_dir):
    path = _write_chain(audit_dir, DAY, _paired_rows())
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1],
    ))
    assert receipt["execution_pair"] is None
    assert receipt["claim"]["decision"] == "result_recorded_ok_unpaired"
    assert receipt["disclosure"] == {
        "cited_row_included": True,
        "suffix_rows_included": 0,
        "execution_pair_included": False,
        "execution_pair_discloses_full_call_row": False,
    }
    assert "private account 1234" not in json.dumps(receipt)
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert result.ok, result.reason
    assert _claim(result, "execution_pair").status == tv.INDETERMINATE


def test_execution_pair_is_an_explicit_bounded_disclosure(audit_dir):
    path = _write_chain(audit_dir, DAY, _paired_rows())
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_execution_pair=True,
    ))
    assert receipt["claim"]["decision"] == "executed"
    assert receipt["disclosure"]["execution_pair_included"] is True
    assert receipt["disclosure"]["execution_pair_discloses_full_call_row"] is True
    assert "private account 1234" in json.dumps(receipt)
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert result.ok, result.reason
    assert _claim(result, "execution_pair").status == tv.HOLDS


def test_output_withheld_disposition_is_portable_claim_evidence(audit_dir):
    rows = _paired_rows()
    rows[1]["disposition"] = "output_withheld"
    path = _write_chain(audit_dir, DAY, rows)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_execution_pair=True,
    ))

    assert receipt["claim"]["decision"] == "executed"
    assert receipt["claim"]["disposition"] == "output_withheld"
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert result.ok, result.reason
    assert _claim(result, "claim_consistency").status == tv.HOLDS
    assert "disposition output_withheld" in tv.format_report(result)


@pytest.mark.parametrize("status", ["ok", "error"])
@pytest.mark.parametrize("include_execution_pair", [False, True])
def test_response_loss_receipt_keeps_execution_unknown(
        audit_dir, status, include_execution_pair):
    # A dispatched effect can complete even though result collection fails.
    # Transport status and a matching call row cannot resolve that uncertainty.
    rows = _paired_rows()
    rows[1].update(
        status=status,
        disposition="execution_unknown",
        output_summary="Tool response lost after dispatch; do not repeat the action.",
    )
    path = _write_chain(audit_dir, DAY, rows)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_execution_pair=include_execution_pair,
    ))

    assert receipt["claim"]["decision"] == "execution_unknown"
    assert receipt["claim"]["disposition"] == "execution_unknown"
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert result.ok, result.reason
    assert _claim(result, "row_integrity").status == tv.HOLDS
    assert _claim(result, "claim_consistency").status == tv.HOLDS
    assert _claim(result, "execution_pair").status == (
        tv.HOLDS if include_execution_pair else tv.INDETERMINATE
    )
    assert _claim(result, "claim_consistency").detail.startswith("execution_unknown ")


@pytest.mark.parametrize("status", ["ok", "error"])
@pytest.mark.parametrize("decision", ["executed", "failed"])
def test_unknown_execution_cannot_be_relabelled_as_a_definite_outcome(
        audit_dir, status, decision):
    rows = _paired_rows()
    rows[1].update(status=status, disposition="execution_unknown")
    path = _write_chain(audit_dir, DAY, rows)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_execution_pair=True,
    ))
    receipt["claim"]["decision"] = decision

    result = tv.verify(_resign(receipt), trusted_keys=[_key()])

    assert not result.ok
    assert _claim(result, "row_integrity").status == tv.HOLDS
    assert _claim(result, "claim_consistency").status == tv.FAILS
    assert _claim(result, "execution_pair").status == tv.HOLDS


def test_v2_pair_survives_real_writer_goal_resolution_and_anonymization(
        tmp_path, monkeypatch):
    from maverick.audit import (
        TOOL_CALL_COMMITMENT_ALGORITHM,
        audit_event,
        goal_context,
        tool_call_commitment,
    )
    from maverick.audit import writer as audit_writer

    monkeypatch.setenv("MAVERICK_ANON", "1")
    log = audit_writer.AuditLog(tmp_path / "audit", sign=False)
    monkeypatch.setattr(audit_writer, "default_audit_log", lambda: log)
    call_id = "ef" * 12
    commitment = tool_call_commitment(call_id=call_id)
    shared = {
        "name": "web_search",
        "origin": "flow",
        "principal": "user:alice@example.test",
        "call_id": call_id,
        "call_commitment": commitment,
        "call_commitment_algorithm": TOOL_CALL_COMMITMENT_ALGORITHM,
    }

    with goal_context(73):
        assert audit_event(
            "tool_call", agent="flow:action", goal_id=None,
            input_summary="find customer", **shared,
        )
        assert audit_event(
            "tool_result", agent="flow:action", goal_id=None,
            status="ok", output_summary="found", **shared,
        )

    path = next((tmp_path / "audit").glob("*.ndjson"))
    call, result = [json.loads(line) for line in path.read_text().splitlines()]
    assert call["goal_id"].startswith("goal_id#")
    assert call["principal"].startswith("principal#")
    assert "alice@example.test" not in path.read_text()
    assert call["goal_id"] == result["goal_id"]
    assert call["principal"] == result["principal"]
    assert tv._execution_pair_fields_match(result, {"call_row": call})


def test_execution_pair_rejects_uncommitted_correlation(audit_dir):
    path = _write_chain(audit_dir, DAY, _paired_rows(commitment="00" * 32))
    hashes = _hashes(path)
    receipt = tr.build(audit_dir=audit_dir, day=DAY, row_hash=hashes[1])
    call = json.loads(path.read_text().splitlines()[0])
    pair = {
        "call_row": call,
        "locator": {"day": DAY, "position": 1, "hash": hashes[0]},
    }
    receipt["execution_pair"] = pair
    receipt["claim"] = tv.derive_claim(receipt["row"], pair)
    receipt["disclosure"]["execution_pair_included"] = True
    receipt["disclosure"]["execution_pair_discloses_full_call_row"] = True
    result = tv.verify(tr.sign(receipt), trusted_keys=[_key()])
    assert not result.ok
    assert _claim(result, "execution_pair").status == tv.FAILS
    assert "commitment" in _claim(result, "execution_pair").detail


def test_execution_pair_rejects_unknown_result_status(audit_dir):
    rows = _paired_rows()
    rows[1]["status"] = "pending"
    path = _write_chain(audit_dir, DAY, rows)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        include_execution_pair=True,
    ))
    assert receipt["claim"]["decision"] == "result_recorded_unknown_status"
    result = tv.verify(receipt, trusted_keys=[_key()])
    assert not result.ok
    assert _claim(result, "execution_pair").status == tv.FAILS
    assert "closed values" in _claim(result, "execution_pair").detail


def test_execution_pair_call_row_has_a_hard_size_limit(audit_dir):
    path = _write_chain(
        audit_dir, DAY,
        _paired_rows(input_summary="x" * (256 * 1024)),
    )
    with pytest.raises(ValueError, match="oversized execution pair call row"):
        tr.build(
            audit_dir=audit_dir,
            day=DAY,
            row_hash=_hashes(path)[1],
            include_execution_pair=True,
        )


def test_anchor_request_rejects_suffix_omitted_receipt(audit_dir, tmp_path):
    from maverick.audit.signing import ensure_anchors

    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        checkpoint_dir=tmp_path / "checkpoints",
    ))
    result = tv.verify(
        receipt,
        trusted_keys=[_key()],
        anchor_digest=receipt["commitment"]["raw_sha256"],
    )
    assert not result.ok
    assert result.depth == tv.DEPTH_SIGNED
    assert "below required 'anchored'" in result.reason


# ---- provenance: fail closed ------------------------------------------------

def test_no_trusted_key_fails_closed(denial_receipt):
    result = tv.verify(denial_receipt, trusted_keys=[])
    assert not result.ok
    assert "trusted public key is required" in result.reason


def test_a_wrong_key_fails_provenance(denial_receipt):
    result = tv.verify(denial_receipt, trusted_keys=["ab" * 32])
    assert not result.ok
    assert "not a trusted key" in result.reason


def test_historical_row_key_cannot_authorize_a_new_envelope(denial_receipt):
    from cryptography.hazmat.primitives.asymmetric import ed25519

    body = {k: v for k, v in denial_receipt.items() if k != "signature"}
    old_private = ed25519.Ed25519PrivateKey.generate()
    old_public = old_private.public_key().public_bytes_raw().hex()
    forged = {**body, "signature": {
        "pubkey": old_public,
        "key_id": tv.key_id_of(old_public),
        "sig": old_private.sign(tv.canonical_bundle_bytes(body)).hex(),
    }}
    result = tv.verify(
        forged,
        trusted_keys=[_key()],
        historical_keys=[old_public],
    )
    assert not result.ok
    assert "provenance" in result.reason


def test_backdated_envelope_cannot_bypass_current_revocation(denial_receipt):
    backdated = json.loads(json.dumps(denial_receipt))
    backdated["issued_at"] = 100.0
    backdated = _resign(backdated)
    policy = {"pubkey": _key(), "revoked_at": 150.0}

    before_revocation = tv.verify(backdated, trusted_keys=[policy], now=125.0)
    assert before_revocation.ok, before_revocation.reason
    assert any(
        "not independently trusted event time" in finding
        for finding in before_revocation.findings
    )

    after_revocation = tv.verify(backdated, trusted_keys=[policy], now=200.0)
    assert not after_revocation.ok
    assert "provenance" in after_revocation.reason


def test_backdated_checkpoint_cannot_bypass_current_revocation(audit_dir, tmp_path):
    from maverick.audit.signing import ensure_anchors

    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        checkpoint_dir=tmp_path / "checkpoints",
        include_suffix=True,
    ))
    signed_at = tv._timestamp(receipt["commitment"]["record"]["created_at"])
    assert signed_at is not None
    result = tv.verify(
        receipt,
        trusted_keys=[_key()],
        checkpoint_keys=[{"pubkey": _key(), "revoked_at": signed_at + 1}],
        now=signed_at + 2,
    )
    assert not result.ok
    assert _claim(result, "commitment").status == tv.FAILS
    assert "verification time" in _claim(result, "commitment").detail


def test_an_attacker_cannot_substitute_their_own_key(denial_receipt):
    """A receipt re-signed by someone else carries a key the verifier does
    not trust, however valid the signature is over the edited contents."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    forged = json.loads(json.dumps(denial_receipt))
    forged["claim"]["decision"] = "executed"
    body = {k: v for k, v in forged.items() if k != "signature"}
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    forged = {**body, "signature": {
        "pubkey": pub.hex(), "key_id": tv.key_id_of(pub.hex()),
        "sig": priv.sign(tv.canonical_bundle_bytes(body)).hex()}}
    result = tv.verify(forged, trusted_keys=[_key()])
    assert not result.ok
    assert "provenance" in result.reason


# ---- tamper variants (insider re-signs with the real key) -------------------

def test_a_drifted_claim_fails_even_when_resigned(denial_receipt):
    edited = json.loads(json.dumps(denial_receipt))
    edited["claim"]["decision"] = "executed"
    result = tv.verify(_resign(edited), trusted_keys=[_key()])
    assert not result.ok
    assert _claim(result, "claim_consistency").status == tv.FAILS


def test_an_edited_row_fails_integrity(denial_receipt):
    edited = json.loads(json.dumps(denial_receipt))
    edited["row"]["reason"] = "approved after all"
    result = tv.verify(_resign(edited), trusted_keys=[_key()])
    assert not result.ok
    assert _claim(result, "row_integrity").status == tv.FAILS
    assert result.depth == tv.DEPTH_NONE


def test_an_edited_following_row_breaks_the_chain(denial_receipt):
    edited = json.loads(json.dumps(denial_receipt))
    nxt = json.loads(edited["chain"]["suffix_ndjson"][0])
    nxt["status"] = "error"
    edited["chain"]["suffix_ndjson"][0] = json.dumps(nxt)
    result = tv.verify(_resign(edited), trusted_keys=[_key()])
    assert not result.ok
    assert _claim(result, "chain_linkage").status == tv.FAILS


def test_a_row_count_that_disagrees_with_the_suffix_fails(denial_receipt):
    edited = json.loads(json.dumps(denial_receipt))
    edited["chain"]["row_count"] += 1
    result = tv.verify(_resign(edited), trusted_keys=[_key()])
    assert not result.ok
    assert _claim(result, "chain_linkage").status == tv.FAILS


def test_a_mismatched_out_of_band_digest_fails(audit_dir, tmp_path):
    from maverick.audit.signing import ensure_anchors
    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    receipt = tr.sign(tr.build(audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1],
                               checkpoint_dir=tmp_path / "checkpoints"))
    result = tv.verify(receipt, trusted_keys=[_key()], anchor_digest="00" * 32)
    assert not result.ok
    assert _claim(result, "commitment").status == tv.FAILS


@pytest.mark.parametrize("filename", ["../../outside.ndjson", "C:\\outside.ndjson"])
def test_checkpoint_filename_cannot_escape_selected_directory(
        audit_dir, tmp_path, filename):
    from maverick.audit.signing import ensure_anchors

    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    ckpt = tmp_path / "checkpoints"
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        checkpoint_dir=ckpt,
        include_suffix=True,
    ))
    edited = json.loads(json.dumps(receipt))
    edited["commitment"]["filename"] = filename
    result = tv.verify(_resign(edited), trusted_keys=[_key()], checkpoint_dir=ckpt)
    assert not result.ok
    assert "invalid checkpoint filename" in _claim(result, "commitment").detail


def test_oversized_checkpoint_is_rejected_without_unbounded_read(audit_dir, tmp_path):
    import stat

    from maverick.audit.signing import ensure_anchors

    path = _write_chain(audit_dir, DAY, _rows())
    ensure_anchors(audit_dir)
    ckpt = tmp_path / "checkpoints"
    receipt = tr.sign(tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=_hashes(path)[1],
        checkpoint_dir=ckpt,
        include_suffix=True,
    ))
    checkpoint = ckpt / receipt["commitment"]["filename"]
    checkpoint.chmod(stat.S_IREAD | stat.S_IWRITE)
    checkpoint.write_bytes(b"x" * (64 * 1024 + 1))
    result = tv.verify(receipt, trusted_keys=[_key()], checkpoint_dir=ckpt)
    assert not result.ok
    assert "cannot safely read" in _claim(result, "commitment").detail


# ---- minter honesty ---------------------------------------------------------

def test_minting_refuses_a_broken_chain(audit_dir):
    path = _write_chain(audit_dir, DAY, _rows())
    denial = _hashes(path)[1]
    text = path.read_text()
    path.write_text(text.replace("wire_transfer is denied", "wire_transfer is fine"))
    with pytest.raises(ValueError, match="broken chain"):
        tr.build(audit_dir=audit_dir, day=DAY, row_hash=denial)


def test_minting_never_mutates_the_evidence(audit_dir, tmp_path):
    path = _write_chain(audit_dir, DAY, _rows())
    before = path.read_bytes()
    out = tr.export(tmp_path / "r.json", audit_dir=audit_dir, day=DAY,
                    row_hash=_hashes(path)[1])
    assert out.exists()
    assert path.read_bytes() == before


def test_export_refuses_to_publish_without_preparation_audit(
        audit_dir, tmp_path, monkeypatch):
    path = _write_chain(audit_dir, DAY, _rows())
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: False)
    out = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError, match="preparation audit row"):
        tr.export(out, audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1])
    assert not out.exists()
    assert not list(tmp_path.glob(".*.pending-*"))


def test_export_surfaces_completion_audit_failure_as_recovery_state(
        audit_dir, tmp_path, monkeypatch):
    path = _write_chain(audit_dir, DAY, _rows())
    outcomes = iter((True, False))
    monkeypatch.setattr(
        "maverick.audit.audit_event", lambda *a, **k: next(outcomes),
    )
    out = tmp_path / "receipt.json"
    with pytest.raises(RuntimeError, match="pending recovery"):
        tr.export(out, audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1])
    assert out.exists()
    pending = list(tmp_path.glob(f".{out.name}.pending-*"))
    assert len(pending) == 1
    assert pending[0].read_bytes() == out.read_bytes()


def test_export_preserves_recovery_marker_when_publish_raises_after_visibility(
        audit_dir, tmp_path, monkeypatch):
    path = _write_chain(audit_dir, DAY, _rows())
    events: list[str] = []
    monkeypatch.setattr(
        "maverick.audit.audit_event",
        lambda kind, **_payload: events.append(str(kind)) or True,
    )

    def _publish_then_fail(target, data, **_kwargs):
        Path(target).write_bytes(data)
        raise OSError("simulated post-publication durability failure")

    monkeypatch.setattr(
        "maverick.file_lock.atomic_create_bytes", _publish_then_fail,
    )
    out = tmp_path / "receipt.json"

    with pytest.raises(RuntimeError, match="publication state is indeterminate"):
        tr.export(out, audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1])

    pending = list(tmp_path.glob(f".{out.name}.pending-*"))
    assert out.exists()
    assert len(pending) == 1
    assert pending[0].read_bytes() == out.read_bytes()
    assert events == ["trust_receipt_prepared"]


def test_export_never_clobbers_an_existing_recipient_file(
        audit_dir, tmp_path, monkeypatch):
    path = _write_chain(audit_dir, DAY, _rows())
    out = tmp_path / "receipt.json"
    out.write_bytes(b"recipient-owned")
    events: list[str] = []
    monkeypatch.setattr(
        "maverick.audit.audit_event",
        lambda kind, **_payload: events.append(str(kind)) or True,
    )

    with pytest.raises(FileExistsError):
        tr.export(out, audit_dir=audit_dir, day=DAY, row_hash=_hashes(path)[1])

    assert out.read_bytes() == b"recipient-owned"
    assert events == ["trust_receipt_prepared"]
    assert not list(tmp_path.glob(f".{out.name}.pending-*"))


def test_export_checks_the_final_serialized_byte_limit(tmp_path, monkeypatch):
    receipt = {
        "locator": {"day": DAY, "hash": "ab" * 32},
        "commitment": None,
        "signature": {"key_id": "cd" * 8},
        "oversized": "x" * 512,
    }
    monkeypatch.setattr(tr, "build", lambda **_kwargs: receipt)
    monkeypatch.setattr(tr, "sign", lambda value: value)
    monkeypatch.setattr(tv, "_MAX_RECEIPT_BYTES", 128)
    out = tmp_path / "too-large.json"

    with pytest.raises(ValueError, match="larger than the verifier"):
        tr.export(out)

    assert not out.exists()


def test_receipt_file_read_is_bounded(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * (8 * 1024 * 1024) + b"}")
    result = tr.verify(oversized, trusted_keys=[_key()])
    assert not result.ok
    assert "exceeds" in result.reason


def test_receipt_file_with_invalid_utf8_fails_closed(tmp_path):
    receipt = tmp_path / "invalid-utf8.json"
    receipt.write_bytes(b'{"claim":"\xff"}')

    result = tr.verify(receipt, trusted_keys=[_key()])

    assert not result.ok
    assert result.depth == tv.DEPTH_NONE
    assert "valid UTF-8" in result.reason


def test_receipt_file_symlink_or_reparse_alias_is_rejected(tmp_path):
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    alias = tmp_path / "receipt-alias.json"
    try:
        alias.symlink_to(receipt)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"this Windows account cannot create a symlink: {exc}")

    result = tr.verify(alias, trusted_keys=[_key()])

    assert not result.ok
    assert result.depth == tv.DEPTH_NONE
    assert "aliased file" in result.reason


def test_receipt_file_hardlink_is_rejected(tmp_path):
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    hardlink = tmp_path / "receipt-hardlink.json"
    os.link(receipt, hardlink)

    result = tr.verify(hardlink, trusted_keys=[_key()])

    assert not result.ok
    assert result.depth == tv.DEPTH_NONE
    assert "multiply-linked file" in result.reason


def test_receipt_identity_swap_during_read_is_rejected(tmp_path, monkeypatch):
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    real_open = builtins.open
    replacements = 0

    def _swap_before_open(file, mode="r", *args, **kwargs):
        nonlocal replacements
        if Path(file) == receipt and mode == "rb":
            replacement = tmp_path / f"replacement-{replacements}.json"
            replacements += 1
            replacement.write_text("{}", encoding="utf-8")
            os.replace(replacement, receipt)
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _swap_before_open)

    result = tr.verify(receipt, trusted_keys=[_key()])

    assert replacements == 3
    assert not result.ok
    assert result.depth == tv.DEPTH_NONE
    assert "identity changed before read" in result.reason


def test_build_uses_one_day_snapshot_for_verify_locate_and_pair(
        audit_dir, monkeypatch):
    path = _write_chain(audit_dir, DAY, _paired_rows())
    result_hash = _hashes(path)[1]
    stable_snapshot = tr._day_snapshot
    snapshots = 0

    def _snapshot_once(snapshot_path, *, maximum_bytes=tr._MAX_AUDIT_BYTES):
        nonlocal snapshots
        snapshots += 1
        text, lines = stable_snapshot(
            snapshot_path,
            maximum_bytes=maximum_bytes,
        )
        # If verification, lookup, or pairing re-reads the pathname instead of
        # using this stable byte snapshot, the replacement below breaks build.
        snapshot_path.write_bytes(b"not valid audit NDJSON")
        return text, lines

    monkeypatch.setattr(tr, "_day_snapshot", _snapshot_once)

    receipt = tr.build(
        audit_dir=audit_dir,
        day=DAY,
        row_hash=result_hash,
        include_execution_pair=True,
    )

    assert snapshots == 1
    assert receipt["row"]["hash"] == result_hash
    assert receipt["execution_pair"]["call_row"]["kind"] == "tool_call"
    assert receipt["claim"]["decision"] == "executed"


def test_unpaired_surrogate_is_rejected_as_a_verdict_not_a_crash():
    result = tv.verify({"bad": "\ud800"}, trusted_keys=[])
    assert not result.ok
    assert "valid UTF-8" in result.reason


def test_excessively_nested_suffix_is_a_failed_verdict_not_a_crash(
        denial_receipt):
    edited = json.loads(json.dumps(denial_receipt))
    edited["chain"]["suffix_ndjson"] = ["[" * 100_000 + "]" * 100_000]
    edited["disclosure"]["suffix_rows_included"] = 1

    result = tv.verify(_resign(edited), trusted_keys=[_key()])

    assert not result.ok
    assert _claim(result, "chain_linkage").status == tv.FAILS
    assert "excessively nested JSON" in _claim(result, "chain_linkage").detail


def test_wrapper_converts_unexpected_verifier_exception_to_closed_verdict(
        tmp_path, monkeypatch):
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(tv, "verify", lambda *_args, **_kwargs: 1 / 0)

    result = tr.verify(receipt, trusted_keys=[_key()])

    assert not result.ok
    assert result.depth == tv.DEPTH_NONE
    assert result.reason == "verification could not be completed safely"


def test_huge_envelope_timestamp_is_rejected_without_overflow(denial_receipt):
    edited = json.loads(json.dumps(denial_receipt))
    edited["issued_at"] = 10**400
    result = tv.verify(_resign(edited), trusted_keys=[_key()])
    assert not result.ok
    assert "finite timestamp" in result.reason


def test_an_unknown_row_is_a_lookup_error(audit_dir):
    _write_chain(audit_dir, DAY, _rows())
    with pytest.raises(LookupError):
        tr.build(audit_dir=audit_dir, day=DAY, row_hash="00" * 32)
    with pytest.raises(LookupError):
        tr.build(audit_dir=audit_dir, day="2025-12-31", row_hash="00" * 32)


def test_derive_claim_names_the_decision():
    assert tv.derive_claim({"kind": "governance_denied", "tool": "x",
                            "reason": "human approval not granted"})["decision"] \
        == "require_human_not_granted"
    assert tv.derive_claim({"kind": "tool_call", "name": "x"})["decision"] == "attempted"
    assert tv.derive_claim({"kind": "tool_result", "name": "x",
                            "status": "ok"})["decision"] \
        == "result_recorded_ok_unpaired"
    assert tv.derive_claim({"kind": "tool_result", "name": "x",
                            "status": "error"})["decision"] \
        == "result_recorded_error_unpaired"
    assert tv.derive_claim({"kind": "capability_denied", "tool": "x"})["decision"] == "denied"
    assert tv.derive_claim({"kind": "autonomy_gated", "tool": "x"})["decision"] == "gated"


def test_call_commitment_matches_the_production_event_helper():
    from maverick.audit.events import (
        TOOL_CALL_COMMITMENT_ALGORITHM,
        tool_call_commitment,
    )

    fields = {
        "call_id": "cd" * 12,
        "name": "web_search",
        "agent": "flow:action",
        "goal_id": None,
        "origin": "flow",
        "principal": "user:alice",
    }
    assert tv.TOOL_CALL_COMMITMENT_ALGORITHM == TOOL_CALL_COMMITMENT_ALGORITHM
    assert tv.tool_call_commitment(call_id=fields["call_id"]) \
        == tool_call_commitment(call_id=fields["call_id"])


# ---- standalone verifier ----------------------------------------------------

def test_the_verifier_source_is_self_contained_and_pinned():
    import hashlib
    text, digest = tr.verifier_source()
    source_bytes = Path(tv.__file__).read_bytes()
    assert text.encode("utf-8") == source_bytes
    assert hashlib.sha256(source_bytes).hexdigest() == digest
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            assert "maverick" not in stripped, f"leaked dependency: {stripped}"
        assert not stripped.startswith("from ."), f"relative import: {stripped}"


def test_the_standalone_verifier_runs_as_its_own_program(audit_dir, tmp_path, capsys):
    path = _write_chain(audit_dir, DAY, _rows())
    out = tr.export(tmp_path / "r.json", audit_dir=audit_dir, day=DAY,
                    row_hash=_hashes(path)[1])
    assert tv.main([str(out), "--key", _key()]) == 0
    assert "VERIFIED" in capsys.readouterr().out
    assert tv.main([str(out), "--key", "ab" * 32]) == 1
    assert tv.main([str(tmp_path / "missing.json"), "--key", "ab" * 32]) == 2
    capsys.readouterr()  # drain the text reports before the JSON run
    assert tv.main([str(out), "--key", _key(), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True


def test_standalone_verifier_contains_unexpected_verification_exception(
        tmp_path, monkeypatch, capsys):
    receipt = tmp_path / "receipt.json"
    receipt.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(tv, "verify", lambda *_args, **_kwargs: 1 / 0)

    assert tv.main([str(receipt), "--key", "ab" * 32]) == 2
    captured = capsys.readouterr()
    assert "verification could not be completed safely" in captured.err


def test_the_cli_mints_verifies_and_exports(audit_dir, tmp_path):
    import hashlib

    from click.testing import CliRunner
    from maverick.cli import main
    path = _write_chain(audit_dir, DAY, _rows())
    out = tmp_path / "r.json"
    runner = CliRunner()
    minted = runner.invoke(main, ["attest", "receipt", "mint", DAY, _hashes(path)[1],
                                  "-o", str(out), "--audit-dir", str(audit_dir)])
    assert minted.exit_code == 0, minted.output
    assert "denied wire_transfer" in minted.output
    assert json.loads(out.read_text())["chain"]["suffix_ndjson"] == []
    before = out.read_bytes()
    duplicate = runner.invoke(
        main,
        [
            "attest", "receipt", "mint", DAY, _hashes(path)[1],
            "-o", str(out), "--audit-dir", str(audit_dir),
        ],
    )
    assert duplicate.exit_code != 0
    assert "exist" in duplicate.output.lower()
    assert out.read_bytes() == before
    verified = runner.invoke(main, ["attest", "receipt", "verify", str(out),
                                    "--key", _key()])
    assert verified.exit_code == 0, verified.output
    assert "VERIFIED" in verified.output
    rejected = runner.invoke(main, ["attest", "receipt", "verify", str(out)])
    assert rejected.exit_code != 0
    verifier_path = tmp_path / "verify.py"
    exported = runner.invoke(main, ["attest", "receipt", "export-verifier",
                                    str(verifier_path)])
    assert exported.exit_code == 0, exported.output
    verifier_bytes = verifier_path.read_bytes()
    assert verifier_bytes == Path(tv.__file__).read_bytes()
    assert f"sha256:     {hashlib.sha256(verifier_bytes).hexdigest()}" in exported.output


def test_cli_export_verifier_never_clobbers_existing_path(tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main

    verifier_path = tmp_path / "verify.py"
    verifier_path.write_bytes(b"recipient-owned")

    result = CliRunner().invoke(
        main,
        ["attest", "receipt", "export-verifier", str(verifier_path)],
    )

    assert result.exit_code != 0
    assert "refusing to overwrite" in result.output
    assert verifier_path.read_bytes() == b"recipient-owned"


def test_cli_export_verifier_contains_write_errors(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    def _fail(*_args, **_kwargs):
        raise OSError("simulated private write failure")

    monkeypatch.setattr("maverick.file_lock.atomic_create_bytes", _fail)
    result = CliRunner().invoke(
        main,
        ["attest", "receipt", "export-verifier", str(tmp_path / "verify.py")],
    )

    assert result.exit_code != 0
    assert "could not export verifier safely" in result.output
    assert not isinstance(result.exception, OSError)


def test_cli_mint_contains_post_publication_readback_error(
        audit_dir, tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    path = _write_chain(audit_dir, DAY, _rows())
    out = tmp_path / "receipt.json"

    def _fail_readback(*_args, **_kwargs):
        raise ValueError("simulated replacement race")

    monkeypatch.setattr(tv, "load_receipt", _fail_readback)
    result = CliRunner().invoke(
        main,
        [
            "attest", "receipt", "mint", DAY, _hashes(path)[1],
            "-o", str(out), "--audit-dir", str(audit_dir),
        ],
    )

    assert result.exit_code != 0
    assert f"receipt was published at {out}" in result.output
    assert out.exists()
    assert not isinstance(result.exception, ValueError)
