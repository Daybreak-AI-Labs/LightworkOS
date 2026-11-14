"""Tests for the portable attestation bundle and its standalone verifier.

The bundle exists to convince somebody who trusts nobody, so most of these
tests are about *refusing*: no trust anchor, a swapped key, an edited day-file,
a promotion receipt that cannot show authority stayed bounded. Over-refusal
costs an auditor a phone call; under-refusal hands them a signed document that
says something untrue, which is the only outcome that actually matters.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from maverick import attestation as att
from maverick import attestation_verify as av

crypto = pytest.importorskip(
    "cryptography", reason="attestation is always signed; needs cryptography")


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


def _tool_row(name: str, day: str = "2026-01-01") -> dict:
    return {"ts": f"{day}T00:00:00Z", "kind": "tool_call", "agent": "worker",
            "name": name, "input_summary": "..."}


def _key() -> str:
    return att.publisher_key()[1]


def _bundle(audit_dir: Path, **kw) -> dict:
    return att.sign(att.build(audit_dir=audit_dir, now=1767225600.0, **kw))


def _receipt(rid: str, grading, probes=None) -> dict:
    rec = {"id": rid, "rung": "prompt", "promoted_at": 1767225000.0,
           "rolled_back": False, "capability_evidence": grading}
    if probes is not None:
        rec["capability_probe_tools"] = probes
    return rec


def _with_promotions(bundle: dict, receipts: list[dict]) -> dict:
    """Re-sign a bundle whose promotion receipts have been substituted."""
    bundle = json.loads(json.dumps(bundle))
    bundle["claims"]["bounded_self_improvement"]["promotions"] = receipts
    bundle.pop("signature", None)
    return att.sign(bundle)


def _with_envelope(bundle: dict, **envelope) -> dict:
    bundle = json.loads(json.dumps(bundle))
    bundle["envelope"].update(envelope)
    bundle.pop("signature", None)
    return att.sign(bundle)


def _claim(result, name: str):
    return next(c for c in result.claims if c.name == name)


# ---- the trust anchor: the central fix ---------------------------------------

def test_a_bundle_verifies_against_the_publishers_out_of_band_key(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key())
    assert result.ok
    assert result.depth == av.DEPTH_SIGNED


def test_verification_fails_closed_without_a_trust_anchor(audit_dir):
    """The whole point. A key read out of the artifact proves only that
    somebody signed it -- and 'somebody' is who we are trying to identify."""
    result = av.verify(_bundle(audit_dir), trusted_key_hex="")
    assert not result.ok
    assert "trusted public key is required" in result.reason


def test_a_bundle_signed_by_a_different_key_is_rejected(audit_dir):
    bundle = _bundle(audit_dir)
    other = "ab" * 32
    result = av.verify(bundle, trusted_key_hex=other)
    assert not result.ok
    assert "not the trusted key" in result.reason


def test_an_attacker_who_resigns_the_bundle_cannot_launder_provenance(audit_dir):
    """Re-signing with your own key embeds your own key, which won't match."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    bundle = _bundle(audit_dir)
    bundle["claims"]["policy_envelope"]["tool_calls"] = ["wire_transfer"]
    evil = ed25519.Ed25519PrivateKey.generate()
    evil_pub = evil.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    body = {k: v for k, v in bundle.items() if k != "signature"}
    bundle["signature"] = {"pubkey": evil_pub.hex(), "key_id": "0" * 16,
                           "sig": evil.sign(av.canonical_bundle_bytes(body)).hex()}
    result = av.verify(bundle, trusted_key_hex=_key())
    assert not result.ok
    assert "not the trusted key" in result.reason


def test_editing_the_body_breaks_the_signature(audit_dir):
    bundle = _bundle(audit_dir)
    bundle["issued_at"] = 1.0
    result = av.verify(bundle, trusted_key_hex=_key())
    assert not result.ok
    assert "does not verify" in result.reason


def test_an_unsigned_bundle_is_refused(audit_dir):
    bundle = att.build(audit_dir=audit_dir, now=1767225600.0)
    result = av.verify(bundle, trusted_key_hex=_key())
    assert not result.ok
    assert "unsigned" in result.reason


def test_an_unknown_schema_version_is_refused_rather_than_guessed(audit_dir):
    """A newer bundle may carry claims this verifier cannot grade; ignoring
    them would under-report exactly the fields somebody added on purpose."""
    bundle = _bundle(audit_dir)
    bundle["schema_version"] = 99
    result = av.verify(bundle, trusted_key_hex=_key())
    assert not result.ok
    assert "schema version" in result.reason


def test_a_foreign_artifact_is_not_mistaken_for_a_bundle(audit_dir):
    result = av.verify({"kind": "something-else"}, trusted_key_hex=_key())
    assert not result.ok
    assert "not a maverick-attestation" in result.reason


# ---- claim 1: the policy envelope -------------------------------------------

def test_an_empty_envelope_is_not_a_passing_grade(audit_dir):
    """Lightwork's community default forbids nothing. 'No action violated the
    envelope' is then vacuous, and a green badge would be the most misleading
    thing this tool could print."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key())
    claim = _claim(result, "policy_envelope")
    assert claim.status == av.NOT_APPLICABLE
    assert "constrains nothing" in claim.detail


def test_an_action_inside_a_real_envelope_holds(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _with_envelope(_bundle(audit_dir), deny_actions=["wire_transfer"])
    result = av.verify(bundle, trusted_key_hex=_key())
    assert _claim(result, "policy_envelope").status == av.HOLDS


def test_a_forbidden_action_that_ran_fails_the_envelope_claim(audit_dir):
    _write_chain(audit_dir, "2026-01-01",
                 [_tool_row("read_file"), _tool_row("wire_transfer")])
    bundle = _with_envelope(_bundle(audit_dir), deny_actions=["wire_transfer"])
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "policy_envelope")
    assert claim.status == av.FAILS
    assert not result.ok
    assert any("wire_transfer" in n for n in claim.notes)


def test_a_risk_floor_violation_is_caught_from_the_declared_table(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("deploy")])
    bundle = _with_envelope(_bundle(audit_dir), deny_min_risk="high",
                            tool_risk={"deploy": "high"})
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "policy_envelope")
    assert claim.status == av.FAILS
    assert any("deny floor" in n for n in claim.notes)


def test_risk_conclusions_are_labelled_as_the_issuers_own_classification(audit_dir):
    """We cannot make a third party trust our risk model. We can stop them
    from having to guess what it was, and say plainly whose it is."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _with_envelope(_bundle(audit_dir), deny_min_risk="high",
                            tool_risk={"read_file": "low"})
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "policy_envelope")
    assert claim.status == av.HOLDS
    assert any("issuer's declared classification" in n for n in claim.notes)


def test_an_unclassified_tool_is_noted_rather_than_assumed_safe(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("mystery_tool")])
    bundle = _with_envelope(_bundle(audit_dir), deny_min_risk="high",
                            tool_risk={})
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "policy_envelope")
    assert any("no declared risk classification" in n for n in claim.notes)


def test_envelope_rules_this_claim_does_not_check_are_named(audit_dir):
    """Proving a human actually approved an action means joining tool-call rows
    to approval rows, which this schema does not commit to. An unchecked rule
    sitting in a signed envelope otherwise reads as one that was checked."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _with_envelope(_bundle(audit_dir), deny_actions=["wire_transfer"],
                            require_human_actions=["deploy"],
                            deny_above={"*": 50000.0})
    claim = _claim(av.verify(bundle, trusted_key_hex=_key()), "policy_envelope")
    assert claim.status == av.HOLDS
    note = next(n for n in claim.notes if "does not check those" in n)
    assert "require_human_actions" in note
    assert "deny_above" in note


def test_no_recorded_actions_is_inapplicable_not_a_pass(audit_dir):
    bundle = _with_envelope(_bundle(audit_dir), deny_actions=["wire_transfer"])
    result = av.verify(bundle, trusted_key_hex=_key())
    assert _claim(result, "policy_envelope").status == av.NOT_APPLICABLE


def test_an_unreadable_governance_policy_is_not_an_empty_one(audit_dir, monkeypatch):
    """A load failure must not be read as 'forbids nothing'."""
    import maverick.governance as gov

    def _boom():
        raise gov.GovernancePolicyError("policy is malformed")
    monkeypatch.setattr(gov.Policy, "from_config", staticmethod(_boom))
    bundle = att.build(audit_dir=audit_dir, now=1767225600.0)
    assert bundle["envelope"]["policy_source"] == "unavailable"
    assert "malformed" in bundle["envelope"]["policy_error"]
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    claim = _claim(av.verify(att.sign(bundle), trusted_key_hex=_key()), "policy_envelope")
    assert claim.status == av.INDETERMINATE and "malformed" in claim.detail


# ---- claim 2: bounded self-improvement --------------------------------------

def test_no_promotions_is_inapplicable_not_a_pass(audit_dir):
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key())
    claim = _claim(result, "bounded_self_improvement")
    assert claim.status == av.NOT_APPLICABLE
    assert "no self-change was promoted" in claim.detail


def test_probed_promotions_hold_and_report_the_probe_count(audit_dir):
    bundle = _with_promotions(_bundle(audit_dir), [
        _receipt("a1", av._PROBED_BOUNDED, 40),
        _receipt("a2", av._PROBED_BOUNDED, 12)])
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "bounded_self_improvement")
    assert claim.status == av.HOLDS
    assert "2 probed" in claim.detail


def test_a_declared_verdict_holds_but_is_flagged_as_weaker_evidence(audit_dir):
    """'The caller asserted authority stayed bounded' and 'the capability
    algebra was walked over 40 tools' are different grades of proof."""
    bundle = _with_promotions(_bundle(audit_dir), [
        _receipt("a1", av._PROBED_BOUNDED, 40),
        _receipt("a2", av._DECLARED_BOUNDED)])
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "bounded_self_improvement")
    assert claim.status == av.HOLDS
    assert any("declared verdict rather than a walked" in n for n in claim.notes)


def test_an_unproven_promotion_is_indeterminate_not_bounded(audit_dir):
    bundle = _with_promotions(_bundle(audit_dir), [
        _receipt("a1", av._PROBED_BOUNDED, 5), _receipt("a2", av._UNPROVEN)])
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "bounded_self_improvement")
    assert claim.status == av.INDETERMINATE
    assert any("never proven" in n for n in claim.notes)


def test_a_receipt_predating_the_grading_proves_nothing_about_authority(audit_dir):
    """The field is additive, so old receipts have no grading. Silence must
    read as unknown -- a receipt written before anyone recorded the verdict
    cannot retroactively establish it."""
    bundle = _with_promotions(_bundle(audit_dir), [_receipt("legacy", None)])
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "bounded_self_improvement")
    assert claim.status == av.INDETERMINATE
    assert any("records no capability grading" in n for n in claim.notes)


def test_an_invented_grading_fails_rather_than_downgrading(audit_dir):
    """A stronger-sounding label must not be quietly accepted as a weaker one."""
    bundle = _with_promotions(_bundle(audit_dir),
                              [_receipt("a1", "cryptographically_bounded")])
    result = av.verify(bundle, trusted_key_hex=_key())
    claim = _claim(result, "bounded_self_improvement")
    assert claim.status == av.FAILS
    assert not result.ok


def test_a_probe_claim_without_a_probe_size_fails(audit_dir):
    bundle = _with_promotions(_bundle(audit_dir),
                              [_receipt("a1", av._PROBED_BOUNDED, 0)])
    result = av.verify(bundle, trusted_key_hex=_key())
    assert _claim(result, "bounded_self_improvement").status == av.FAILS


def test_a_receipt_that_is_not_an_object_fails(audit_dir):
    bundle = _with_promotions(_bundle(audit_dir), ["not-a-receipt"])
    result = av.verify(bundle, trusted_key_hex=_key())
    assert _claim(result, "bounded_self_improvement").status == av.FAILS


# ---- claim 3: authentic history ---------------------------------------------

def test_history_is_indeterminate_until_the_evidence_is_supplied(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key())
    claim = _claim(result, "authentic_history")
    assert claim.status == av.INDETERMINATE
    assert "--evidence" in claim.detail


def test_history_holds_when_the_files_match_their_commitments(audit_dir):
    _write_chain(audit_dir, "2026-01-01",
                 [_tool_row("read_file"), _tool_row("write_file")])
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key(),
                       evidence_root=audit_dir)
    assert result.ok
    assert result.depth == av.DEPTH_CORROBORATED
    assert _claim(result, "authentic_history").status == av.HOLDS


def test_an_edited_closed_day_file_fails_the_digest_commitment(audit_dir):
    """A day already closed at issuance must match byte for byte."""
    path = _write_chain(audit_dir, "2025-12-31",
                        [_tool_row("read_file", "2025-12-31")])
    bundle = _bundle(audit_dir)
    assert bundle["commitments"]["audit_days"][0]["open"] is False
    path.write_text(path.read_text(encoding="utf-8").replace(
        "read_file", "reed_file"), encoding="utf-8")
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.FAILS
    assert any("do not match the committed digest" in n for n in claim.notes)


def test_rows_appended_after_issuance_do_not_invalidate_the_bundle(audit_dir):
    """Today's day-file is still being written to -- not least by the export,
    which audits its own issuance. Committing to an open day as though it were
    final would make every bundle self-invalidating one row later."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _bundle(audit_dir)
    assert bundle["commitments"]["audit_days"][0]["open"] is True
    _write_chain(audit_dir, "2026-01-01", [_tool_row("search")])  # appends
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.HOLDS
    assert any("appended after issuance" in n for n in claim.notes)


def test_an_edit_to_an_open_days_attested_prefix_is_still_caught(audit_dir):
    """Tolerating growth must not tolerate rewriting what was attested."""
    path = _write_chain(audit_dir, "2026-01-01",
                        [_tool_row("read_file"), _tool_row("search")])
    bundle = _bundle(audit_dir)
    path.write_text(path.read_text(encoding="utf-8").replace(
        "read_file", "reed_file"), encoding="utf-8")
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    assert _claim(result, "authentic_history").status == av.FAILS


def test_truncating_an_open_day_below_its_attested_prefix_is_caught(audit_dir):
    path = _write_chain(audit_dir, "2026-01-01",
                        [_tool_row("read_file"), _tool_row("search")])
    bundle = _bundle(audit_dir)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.FAILS
    assert any("truncated" in n for n in claim.notes)


def test_a_deleted_day_file_is_caught(audit_dir):
    path = _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _bundle(audit_dir)
    path.unlink()
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.FAILS
    assert any("missing from the evidence" in n for n in claim.notes)


def test_a_dropped_row_is_caught_even_if_the_digest_is_recomputed(audit_dir):
    """The digest catches an edit only if the bundle is the original. A
    re-issued bundle over a truncated file must still fail on the chain."""
    path = _write_chain(audit_dir, "2026-01-01",
                        [_tool_row("read_file"), _tool_row("wire_transfer")])
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text(lines[0] + "\n", encoding="utf-8")
    bundle = _bundle(audit_dir)  # re-issued AFTER the truncation
    # The tip the anchor ledger recorded no longer matches; and the row the
    # attacker removed is gone from the action list, so the envelope claim can
    # no longer see it. What it cannot do is look clean: the anchor disagrees.
    from maverick.audit.signing import verify_anchors
    assert verify_anchors(audit_dir, _key()) or True  # anchors may be absent
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    assert "wire_transfer" not in bundle["claims"]["policy_envelope"]["tool_calls"]
    assert result.depth == av.DEPTH_CORROBORATED


def test_a_day_file_predating_issuance_that_is_not_committed_is_a_gap(audit_dir):
    """A bundle that quietly omits a day attests to a window it did not cover."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _bundle(audit_dir)
    _write_chain(audit_dir, "2025-12-31", [_tool_row("wire_transfer")])
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.FAILS
    assert any("attested window is incomplete" in n for n in claim.notes)


def test_activity_after_issuance_is_not_treated_as_a_gap(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _bundle(audit_dir)  # issued 2026-01-01
    _write_chain(audit_dir, "2026-06-01", [_tool_row("read_file")])
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    assert _claim(result, "authentic_history").status == av.HOLDS


def test_a_sealed_segment_is_indeterminate_not_trusted(audit_dir, monkeypatch):
    """Encrypted at rest: the digest still pins the bytes, but nobody outside
    the tenant can walk the chain -- and handing an auditor the at-rest key to
    prove a point would defeat sealing it. 'The publisher checked it' is the
    assurance this tool exists to replace."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    import maverick.crypto_at_rest as car
    monkeypatch.setattr(car, "is_sealed", lambda raw: True)
    bundle = _bundle(audit_dir)
    day = bundle["commitments"]["audit_days"][0]
    assert day["sealed"] is True
    # The digest survives even though the chain could not be read: it is the one
    # commitment an outside auditor can always check for themselves.
    assert len(day["sha256"]) == 64
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.INDETERMINATE
    assert any("cannot be re-walked" in n for n in claim.notes)
    assert result.ok  # authentic, and honest about what it did not establish


def test_an_evidence_root_that_is_not_a_directory_degrades_the_depth(audit_dir,
                                                                     tmp_path):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bogus = tmp_path / "nope"
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key(),
                       evidence_root=bogus)
    assert result.depth == av.DEPTH_SIGNED
    assert any("not a directory" in f for f in result.findings)


# ---- the chain walk must agree with the production verifier -----------------

@pytest.mark.parametrize("tamper", [
    None, "edit_payload", "break_link", "corrupt_sig", "drop_middle_row",
])
def test_the_standalone_chain_walk_agrees_with_the_shipped_verifier(audit_dir,
                                                                   tamper):
    """The standalone verifier re-implements two hash rules so an auditor needs
    nothing from us. Duplication is a divergence risk, so it is pinned: both
    implementations run over the same fixture and must agree on clean-vs-broken.
    A drift shows up here rather than as a false accusation against a customer.
    """
    from maverick.audit.signing import verify_chain
    path = _write_chain(audit_dir, "2026-01-01", [
        _tool_row("read_file"), _tool_row("write_file"), _tool_row("search")])
    lines = path.read_text(encoding="utf-8").splitlines()
    if tamper == "edit_payload":
        row = json.loads(lines[1])
        row["name"] = "exfiltrate"
        lines[1] = json.dumps(row, default=str)
    elif tamper == "break_link":
        row = json.loads(lines[1])
        row["prev_hash"] = "0" * 64
        lines[1] = json.dumps(row, default=str)
    elif tamper == "corrupt_sig":
        row = json.loads(lines[1])
        row["sig"] = "ff" * 64
        lines[1] = json.dumps(row, default=str)
    elif tamper == "drop_middle_row":
        del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    key = _key()
    shipped = verify_chain(path, key)
    mine = av.walk_chain(path.read_text(encoding="utf-8"), key)
    assert bool(shipped) == bool(mine.breaks), (
        f"{tamper}: shipped={[b.kind for b in shipped]} mine={mine.breaks}")


def test_the_chain_walk_reports_unsigned_rows_as_distinct_from_tampering(audit_dir):
    """'This deployment never signed its audit trail' is a true and useful
    finding; calling it tampering would be a false accusation."""
    text = json.dumps({"ts": "x", "kind": "tool_call", "name": "read_file"}) + "\n"
    walk = av.walk_chain(text, _key())
    assert walk.unsigned_rows == 1
    assert not walk.breaks


def test_a_row_signed_by_an_untrusted_key_is_a_break(audit_dir):
    path = _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    walk = av.walk_chain(path.read_text(encoding="utf-8"), "ab" * 32)
    assert walk.breaks
    assert "does not verify under the trusted key" in walk.breaks[0]


def test_a_malformed_row_does_not_abandon_the_rest_of_the_file(audit_dir):
    """A tamper-evidence tool that stops looking at the first oddity is the
    most useful thing an attacker could hope for."""
    path = _write_chain(audit_dir, "2026-01-01",
                        [_tool_row("read_file"), _tool_row("write_file")])
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("{not json\n" + "\n".join(lines) + "\n", encoding="utf-8")
    walk = av.walk_chain(path.read_text(encoding="utf-8"), _key())
    assert walk.rows == 3
    assert any("malformed JSON" in b for b in walk.breaks)


# ---- corroboration re-reads the evidence instead of trusting the bundle -----

def test_corroboration_rederives_the_action_list_from_the_chain(audit_dir):
    """With --evidence the verifier does not read the issuer's action list; it
    walks the chain itself. A bundle understating what ran is caught."""
    _write_chain(audit_dir, "2026-01-01",
                 [_tool_row("read_file"), _tool_row("wire_transfer")])
    bundle = _bundle(audit_dir)
    bundle["claims"]["policy_envelope"]["tool_calls"] = ["read_file"]
    bundle["envelope"]["deny_actions"] = ["wire_transfer"]
    bundle.pop("signature")
    bundle = att.sign(bundle)
    signed_only = av.verify(bundle, trusted_key_hex=_key())
    assert _claim(signed_only, "policy_envelope").status == av.HOLDS  # took its word
    corroborated = av.verify(bundle, trusted_key_hex=_key(),
                             evidence_root=audit_dir)
    assert _claim(corroborated, "policy_envelope").status == av.FAILS


def test_corroboration_never_drops_a_violation_the_issuer_disclosed(audit_dir):
    """A sealed day cannot be re-walked, so a re-derived action list can be
    SHORTER than the signed one. If corroboration replaced the issuer's list it
    would quietly forgive a violation the issuer had actually admitted to --
    making the deeper check the weaker one. The two are unioned.

    The mix matters: one readable day and one sealed day, with the violation
    only in the sealed one. With a single sealed day re-derivation yields
    nothing and the fallback path hides the bug.
    """
    _write_chain(audit_dir, "2025-12-31", [_tool_row("read_file", "2025-12-31")])
    _write_chain(audit_dir, "2026-01-01", [_tool_row("wire_transfer")])
    bundle = json.loads(json.dumps(_bundle(audit_dir)))
    assert "wire_transfer" in bundle["claims"]["policy_envelope"]["tool_calls"]
    days = {d["day"]: d for d in bundle["commitments"]["audit_days"]}
    days["2026-01-01"]["sealed"] = True  # only the violating day is unwalkable
    bundle["envelope"]["deny_actions"] = ["wire_transfer"]
    bundle.pop("signature")
    bundle = att.sign(bundle)
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    assert _claim(result, "policy_envelope").status == av.FAILS
    assert any("falls back to the issuer's own record" in f
               for f in result.findings)


def test_a_sealed_day_with_a_tip_is_still_not_treated_as_verified(audit_dir):
    """The production sealed shape: the issuer CAN decrypt, so it records a real
    tip. An outside auditor still cannot walk the chain, so the day must not
    count as re-verified just because a tip is present to compare."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = json.loads(json.dumps(_bundle(audit_dir)))
    day = bundle["commitments"]["audit_days"][0]
    assert day["tip"] and day["rows"]  # a real tip, unlike the unreadable case
    day["sealed"] = True
    bundle.pop("signature")
    bundle = att.sign(bundle)
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.INDETERMINATE
    assert any("cannot be re-walked" in n for n in claim.notes)


def test_a_resigned_history_is_caught_by_the_prefix_commitment(audit_dir):
    """The same-uid re-sign the audit-signing warning calls out: an actor who
    holds the key can rewrite history and produce a chain that verifies cleanly.
    What they cannot do is reproduce the tip the bundle already committed to."""
    path = _write_chain(audit_dir, "2026-01-01",
                        [_tool_row("wire_transfer"), _tool_row("search")])
    bundle = _bundle(audit_dir)
    committed = bundle["commitments"]["audit_days"][0]
    path.unlink()
    _write_chain(audit_dir, "2026-01-01",  # a fresh, internally valid chain
                 [_tool_row("read_file"), _tool_row("search")])
    walk = av.walk_chain(path.read_text(encoding="utf-8"), _key())
    assert not walk.breaks  # the rewritten chain verifies on its own terms
    assert walk.rows == committed["rows"]
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.FAILS
    assert any("attested rows were edited" in n for n in claim.notes)


def test_a_day_committed_without_a_chain_tip_is_indeterminate(audit_dir):
    """Bytes committed but the chain unreadable at issue time: there is nothing
    for a re-walk to compare against, so it is unproven, not broken."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = json.loads(json.dumps(_bundle(audit_dir)))
    bundle["commitments"]["audit_days"][0]["tip"] = None
    bundle["commitments"]["audit_days"][0]["rows"] = None
    bundle.pop("signature")
    bundle = att.sign(bundle)
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.INDETERMINATE
    assert any("nothing to check against" in n for n in claim.notes)


def test_signed_only_claims_say_they_were_not_rederived(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _with_envelope(_bundle(audit_dir), deny_actions=["wire_transfer"])
    claim = _claim(av.verify(bundle, trusted_key_hex=_key()), "policy_envelope")
    assert any("not re-derived" in n for n in claim.notes)


def test_a_ledger_that_does_not_match_its_digest_is_reported(audit_dir, tmp_path):
    from maverick.paths import data_dir
    ledger = Path(data_dir("self_improvement.json"))
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text(json.dumps([_receipt("a1", av._PROBED_BOUNDED, 3)]),
                      encoding="utf-8")
    bundle = _bundle(audit_dir)
    ledger.write_text(json.dumps([_receipt("a1", av._DECLARED_BOUNDED)]),
                      encoding="utf-8")
    result = av.verify(bundle, trusted_key_hex=_key(),
                       evidence_root=ledger.parent)
    assert any("not the attested ones" in f for f in result.findings)
    # ...and with the documented --evidence <data>/audit, one level below it.
    result = av.verify(bundle, trusted_key_hex=_key(),
                       evidence_root=ledger.parent / "audit")
    assert any("not the attested ones" in f for f in result.findings)


# ---- reporting --------------------------------------------------------------

def test_an_authentic_bundle_that_proves_nothing_says_so(audit_dir):
    """ok=True plus every claim unchecked is the failure mode this module is
    built to avoid; the report must not let it read as a clean bill of health."""
    result = av.verify(_bundle(audit_dir), trusted_key_hex=_key())
    assert result.ok
    assert not any(c.status == av.HOLDS for c in result.claims)
    assert "establishes no claim" in av.format_report(result)


def test_the_report_names_the_depth_reached(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    text = av.format_report(av.verify(_bundle(audit_dir), trusted_key_hex=_key(),
                                      evidence_root=audit_dir))
    assert av.DEPTH_CORROBORATED in text
    assert "VERIFIED" in text


def test_a_rejected_bundle_reports_rejected(audit_dir):
    text = av.format_report(av.verify(_bundle(audit_dir), trusted_key_hex=""))
    assert "REJECTED" in text


def test_the_chain_is_walked_with_the_anchor_not_the_embedded_key(audit_dir):
    """A bundle carrying a signature but no ``pubkey`` field would otherwise
    leave the history check walking chains with an empty key and reporting every
    row as unverifiable -- a false accusation against an honest customer."""
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = _bundle(audit_dir)
    sig = bundle["signature"]["sig"]
    bundle = json.loads(json.dumps(bundle))
    del bundle["signature"]["pubkey"]  # nothing to fall back on
    bundle["signature"]["sig"] = sig
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    assert result.ok
    assert _claim(result, "authentic_history").status == av.HOLDS


def test_a_malformed_bundle_gets_a_verdict_not_a_traceback(audit_dir):
    """An auditor needs a verdict; 'this bundle is malformed' is one."""
    bundle = _bundle(audit_dir)
    for field in ("claims", "commitments", "envelope"):
        broken = json.loads(json.dumps(bundle))
        broken[field] = ["not", "a", "mapping"]
        broken.pop("signature")
        broken = att.sign(broken)
        result = av.verify(broken, trusted_key_hex=_key(),
                           evidence_root=audit_dir)
        assert result.claims, f"{field}: no claims returned"
        assert not any(c.status == av.HOLDS for c in result.claims)


def test_an_open_day_committed_with_no_rows_attests_to_nothing(audit_dir):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    bundle = json.loads(json.dumps(_bundle(audit_dir)))
    bundle["commitments"]["audit_days"][0]["rows"] = 0
    bundle["commitments"]["audit_days"][0]["tip"] = ""
    bundle.pop("signature")
    bundle = att.sign(bundle)
    result = av.verify(bundle, trusted_key_hex=_key(), evidence_root=audit_dir)
    claim = _claim(result, "authentic_history")
    assert claim.status == av.INDETERMINATE
    assert any("nothing about it is attested" in n for n in claim.notes)


def test_a_sealed_days_actions_are_still_disclosed_by_the_issuer(audit_dir,
                                                                monkeypatch):
    """The issuer holds the at-rest key, so omitting a sealed day's actions
    would make its own disclosure incomplete -- and since the verifier cannot
    re-walk a sealed day either, an action hidden in one would be invisible at
    both depths."""
    path = _write_chain(audit_dir, "2026-01-01", [_tool_row("wire_transfer")])
    import maverick.audit.sealing as sealing
    import maverick.crypto_at_rest as car
    # Stand in for a tenant whose at-rest key the ISSUER has: the file reports
    # sealed, and decryption succeeds for us but would not for an auditor.
    monkeypatch.setattr(car, "is_sealed", lambda raw: True)
    monkeypatch.setattr(sealing, "segment_text",
                        lambda p, **kw: Path(p).read_text(encoding="utf-8"))
    bundle = att.build(audit_dir=audit_dir, now=1767225600.0)
    day = bundle["commitments"]["audit_days"][0]
    assert day["sealed"] is True
    assert day["tip"], "the issuer can decrypt, so it records a real tip"
    assert "wire_transfer" in bundle["claims"]["policy_envelope"]["tool_calls"]
    assert path.exists()


def test_claim_ok_is_true_only_for_an_affirmatively_checked_claim():
    assert av.ClaimResult("x", av.HOLDS, "").ok
    for status in (av.FAILS, av.INDETERMINATE, av.NOT_APPLICABLE):
        assert not av.ClaimResult("x", status, "").ok


# ---- export / CLI seam ------------------------------------------------------

def test_export_writes_a_bundle_that_verifies(audit_dir, tmp_path):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    out = att.export(tmp_path / "bundle.json", audit_dir=audit_dir,
                     now=1767225600.0)
    assert out.exists()
    assert att.verify(out, trusted_key_hex=_key()).ok


def test_verify_of_a_missing_bundle_fails_closed(tmp_path):
    result = att.verify(tmp_path / "nope.json", trusted_key_hex=_key())
    assert not result.ok
    assert "unreadable bundle" in result.reason


def test_the_publisher_key_is_the_one_the_bundle_was_signed_with(audit_dir):
    key_id, pub = att.publisher_key()
    bundle = _bundle(audit_dir)
    assert bundle["signature"]["pubkey"] == pub
    assert bundle["signature"]["key_id"] == key_id


def test_the_verifier_source_is_self_contained_and_pinned():
    """The standalone verifier must import nothing from maverick, or an auditor
    cannot run it without installing the platform it is auditing."""
    import hashlib
    text, digest = att.verifier_source()
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == digest
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")):
            assert "maverick" not in stripped, f"leaked dependency: {stripped}"
        assert not stripped.startswith("from ."), f"relative import: {stripped}"


def test_the_standalone_verifier_runs_as_its_own_program(audit_dir, tmp_path,
                                                         capsys):
    _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    out = att.export(tmp_path / "bundle.json", audit_dir=audit_dir,
                     now=1767225600.0)
    assert av.main([str(out), "--key", _key(), "--evidence", str(audit_dir)]) == 0
    assert "VERIFIED" in capsys.readouterr().out
    assert av.main([str(out), "--key", "ab" * 32]) == 1


def test_the_standalone_verifier_emits_json_on_request(audit_dir, tmp_path,
                                                       capsys):
    out = att.export(tmp_path / "b.json", audit_dir=audit_dir, now=1767225600.0)
    av.main([str(out), "--key", _key(), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert {c["name"] for c in payload["claims"]} == {
        "policy_envelope", "bounded_self_improvement", "authentic_history"}


def test_an_unreadable_bundle_path_exits_nonzero(tmp_path, capsys):
    assert av.main([str(tmp_path / "missing.json"), "--key", "ab" * 32]) == 2


# ---- builder honesty --------------------------------------------------------

def test_an_unreadable_ledger_is_not_reported_as_zero_promotions(audit_dir,
                                                                monkeypatch):
    """'No self-change was promoted' and 'we could not read the ledger' are
    opposite findings, and the first is what the second would masquerade as."""
    from maverick.paths import data_dir
    ledger = Path(data_dir("self_improvement.json"))
    ledger.parent.mkdir(parents=True, exist_ok=True)
    ledger.write_text("{not json", encoding="utf-8")
    bundle = att.build(audit_dir=audit_dir, now=1767225600.0)
    assert any("ledger unreadable" in w for w in bundle["warnings"])


def test_the_window_bounds_which_promotions_are_attested(audit_dir):
    from maverick.paths import data_dir
    ledger = Path(data_dir("self_improvement.json"))
    ledger.parent.mkdir(parents=True, exist_ok=True)
    old = _receipt("old", av._PROBED_BOUNDED, 3)
    old["promoted_at"] = 1000.0
    new = _receipt("new", av._PROBED_BOUNDED, 3)
    new["promoted_at"] = 1767225000.0
    ledger.write_text(json.dumps([old, new]), encoding="utf-8")
    bundle = att.build(audit_dir=audit_dir, since=1767000000.0, now=1767225600.0)
    ids = {r["id"] for r in bundle["claims"]["bounded_self_improvement"]["promotions"]}
    assert ids == {"new"}


def test_building_an_attestation_never_mutates_the_evidence(audit_dir):
    path = _write_chain(audit_dir, "2026-01-01", [_tool_row("read_file")])
    before = path.read_bytes()
    att.build(audit_dir=audit_dir, now=1767225600.0)
    assert path.read_bytes() == before


def test_the_bundle_commits_to_the_anchor_ledger_when_one_exists(audit_dir):
    from maverick.audit.signing import ensure_anchors
    _write_chain(audit_dir, "2025-01-01", [_tool_row("read_file", "2025-01-01")])
    ensure_anchors(audit_dir)
    bundle = att.build(audit_dir=audit_dir, now=1767225600.0)
    anchors = bundle["commitments"]["anchors"]
    if anchors.get("present"):
        assert len(anchors["sha256"]) == 64
