"""Real local native observations, encrypted issuance and independent verification."""
from __future__ import annotations

import copy
import hashlib
import json
import time
from dataclasses import replace

import pytest
from maverick import audit, config, crypto_at_rest
from maverick.audit import signing
from maverick.flow import action_episode_review as review
from maverick.flow import action_provenance as provenance
from maverick.flow import store
from maverick.governed_operations import digest

from test_support import action_episode_native as support
from test_support.action_episode_native import native as native


@pytest.fixture
def enabled(native, monkeypatch):
    settings = {**support.FLAGS, "action_recipe_lineage": True, "action_evidence_issuer": "local-test-issuer",
                "action_evidence_revoked_keys": []}
    monkeypatch.setattr(config, "get_flows", lambda: copy.deepcopy(settings))
    return native, settings


def accepted():
    selected, context = support._service(), support._context()
    source, run = support._start()
    support._enroll(source, run)
    support._resume(run.run_id)
    support._resume(run.run_id)
    row = support._row(source, run)
    accepted_row = selected.review(context, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], accepted=True, rationale="Native observations reviewed.")
    return selected, context, source, run, accepted_row


def grant(selected, context, source, run, row):
    return selected.grant_training(context, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], use_until=row["retain_until"] - 100,
        retain_derived_copies=True, rationale="Allow bounded recipe copies; downloads are not remotely erased.")


def issue(selected, context, source, run, row):
    return selected.export_signed(context, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], expected_grant_sha256=row["grant_sha256"])


def issued():
    selected, context, source, run, row = accepted()
    granted = grant(selected, context, source, run, row)
    bundle = issue(selected, context, source, run, granted)
    return selected, context, source, run, granted, bundle


def test_native_signed_bundle_covers_review_contract_and_generated_invocations(enabled):
    journal, _settings = enabled
    selected, context, source, run, granted, bundle = issued()
    verified = provenance.verify_bundle(bundle, trust=provenance.local_trust(context.tenant),
                                        expected_tenant=context.tenant, now=time.time())
    assert verified["live_status"] == "not_checked" and verified["signature_status"] == "trusted"
    assert verified["body"]["review_revision"] == granted["review_revision"] < granted["revision"]
    assert len(verified["body"]["steps"]) == 2
    assert selected.assert_bundle_current(context, bundle)["live_status"] == "accepted"
    assert issue(selected, context, source, run, granted) == bundle
    assert len(support._calls(journal)) == 2
    stored = selected.records.get(granted["id"])
    assert crypto_at_rest.is_sealed_str(stored["sensitive_envelope"])
    assert "bundle" not in stored and "episode" not in stored
    assert "issuance" not in selected.get(context, source.id, run.run_id, detail=True)["evidence"]
    verified["body"]["episode"]["inputs"]["customer"] = "changed"
    assert issue(selected, context, source, run, granted) == bundle


def test_unicode_commitments_use_their_declared_distinct_encodings(enabled, monkeypatch):
    monkeypatch.setattr(support, "INPUTS", {"customer": "Caf\u00e9", "quantity": 3})
    _selected, context, _source, _run, _grant, bundle = issued()
    body = bundle["body"]
    assert body["episode_sha256"] != body["capture_episode_sha256"]
    assert body["capture_episode_sha256"] == digest(body["episode"])
    assert body["episode_sha256"] == provenance.digest(body["episode"])
    provenance.verify_bundle(json.dumps(bundle, ensure_ascii=False).encode(), trust=provenance.local_trust(context.tenant),
                             expected_tenant=context.tenant, now=time.time())


@pytest.mark.parametrize("receipt", [False, 1, "throw"])
def test_pending_issuance_recovery_returns_identical_signed_bytes_without_effect_replay(enabled, monkeypatch, receipt):
    journal, _settings = enabled
    selected, context, source, run, row = accepted()
    row = grant(selected, context, source, run, row)
    original = audit.record

    def unavailable(*args, **kwargs):
        if receipt == "throw":
            raise OSError("audit temporarily unavailable")
        return receipt

    monkeypatch.setattr(audit, "record", unavailable)
    with pytest.raises(review.ActionEpisodeAuditPending):
        issue(selected, context, source, run, row)
    saved = selected.records.get(row["id"])
    assert saved["_audit_pending"]
    persisted = review._open(context, saved)["issuance"]["bundle"]
    pending = selected.get(context, source.id, run.run_id, detail=True)
    assert pending["status"] == "audit_pending" and "evidence" not in pending
    monkeypatch.setattr(audit, "record", original)
    recovered = issue(support._service(), context, source, run, row)
    assert recovered == persisted and len(support._calls(journal)) == 2


def test_withdrawal_preserves_acceptance_but_blocks_current_reuse(enabled):
    selected, context, source, run, _granted, bundle = issued()
    row = selected.get(context, source.id, run.run_id)
    args = {"expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
            "expected_review_sha256": row["review_sha256"], "rationale": "Withdraw this training use."}
    result = selected.withdraw(context, source.id, run.run_id, **args)
    assert result["status"] == "withdrawn"
    assert selected.withdraw(context, source.id, run.run_id, **args)["revision"] == result["revision"]
    payload = review._open(context, selected.records.get(row["id"]))
    assert payload["review"]["accepted"] is True and payload["issuance"]["bundle"] == bundle
    detail = selected.get(context, source.id, run.run_id, detail=True)
    assert "evidence" not in detail and detail["withdrawal_detail"] == {"rationale": args["rationale"]}
    assert payload["withdrawal"]["rationale"] == args["rationale"]
    assert result["withdrawal"]["rationale_sha256"] == digest(args["rationale"])
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    assert args["rationale"] not in json.dumps(events)
    with pytest.raises(review.ActionEpisodeConflict):
        selected.assert_bundle_current(context, bundle)
    verified = provenance.verify_bundle(bundle, trust=provenance.local_trust(context.tenant),
                                        expected_tenant=context.tenant, now=time.time())
    assert verified["live_status"] == "not_checked"


@pytest.mark.parametrize("boundary", ["sign", "seal"])
def test_authority_revoked_during_signing_or_sealing_cannot_expose_issuance(enabled, monkeypatch, boundary):
    selected, context, source, run, row = accepted()
    row = grant(selected, context, source, run, row)
    allowed = [True]
    selected.authorize = lambda *args: allowed[0]
    module, name = ((signing, "sign_detached_digest") if boundary == "sign" else (crypto_at_rest, "seal_to_str"))
    original = getattr(module, name)

    def revoke(*args, **kwargs):
        value = original(*args, **kwargs)
        allowed[0] = False
        return value

    monkeypatch.setattr(module, name, revoke)
    with pytest.raises(PermissionError):
        issue(selected, context, source, run, row)
    saved = selected.records.get(row["id"])
    assert saved["revision"] == row["revision"] and "bundle_sha256" not in saved


@pytest.mark.parametrize("field", ["issuer", "tenant", "purpose", "retain_until", "source_current_at_issue"])
def test_plain_hash_recomputation_never_substitutes_a_signed_body(enabled, field):
    _selected, context, _source, _run, _grant, bundle = issued()
    changed = copy.deepcopy(bundle)
    value = changed["body"][field]
    changed["body"][field] = (not value if type(value) is bool else value + 1 if type(value) in (int, float) else "other")
    changed["signature"]["digest"] = provenance.digest(changed["body"])
    with pytest.raises(ValueError):
        provenance.verify_bundle(changed, trust=provenance.local_trust(context.tenant),
                                 expected_tenant=context.tenant, now=time.time())


@pytest.mark.parametrize("change", ["unknown", "revoked", "tenant", "purpose", "public_key", "extra"])
def test_independent_trust_policy_is_exact_and_fail_closed(enabled, change):
    _selected, context, _source, _run, _grant, bundle = issued()
    trust = provenance.local_trust(context.tenant)
    key = bundle["signature"]["key_id"]
    if change == "unknown":
        trust["keys"] = {}
    elif change == "revoked":
        trust["revoked_keys"] = [key]
    elif change == "public_key":
        trust["keys"][key] = "00" * 32
    elif change == "extra":
        trust["allow_embedded_key"] = True
    else:
        trust[change] = "other"
    with pytest.raises(ValueError):
        provenance.verify_bundle(bundle, trust=trust, expected_tenant=context.tenant, now=time.time())


def test_cross_protocol_signature_over_bare_digest_is_rejected(enabled):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _selected, context, _source, _run, _grant, bundle = issued()
    private, _public, _key = signing._load_or_create_keypair()
    changed = copy.deepcopy(bundle)
    changed["signature"]["signature"] = Ed25519PrivateKey.from_private_bytes(private).sign(
        bytes.fromhex(changed["signature"]["digest"])).hex()
    with pytest.raises(ValueError, match="not trusted"):
        provenance.verify_bundle(changed, trust=provenance.local_trust(context.tenant),
                                 expected_tenant=context.tenant, now=time.time())


@pytest.mark.parametrize("raw", ['{"body":{},"body":{}}', '{"value":NaN}', b'\xff', '[' * 40 + '0' + ']' * 40])
def test_strict_parsing_rejects_duplicates_nonfinite_utf8_and_excess_depth(raw):
    with pytest.raises((ValueError, UnicodeError)):
        provenance.snapshot(raw)


def test_historical_source_edit_remains_eligible_but_recreation_does_not(enabled):
    selected, context, source, run, _row, bundle = issued()
    changed = store.load_flow(source.id)
    changed.name = "Ordinary new source version"
    store.save_flow(changed)
    assert selected.assert_bundle_current(context, bundle)["source_current"] is False
    store.delete_flow(source.id)
    store.save_flow(changed)
    with pytest.raises(review.ActionEpisodeConflict):
        selected.assert_bundle_current(context, bundle)


def test_expiry_owner_and_revoked_local_key_each_block_live_reuse(enabled):
    selected, context, source, run, _row, bundle = issued()
    with pytest.raises(ValueError, match="time window"):
        provenance.verify_bundle(bundle, trust=provenance.local_trust(context.tenant), expected_tenant=context.tenant,
                                 now=bundle["body"]["grant"]["use_until"])
    permissive = review.ActionEpisodeReviewService(lambda *args: True)
    with pytest.raises(PermissionError):
        permissive.assert_bundle_current(replace(context, resource_owner="other"), bundle)
    enabled[1]["action_evidence_revoked_keys"] = [bundle["signature"]["key_id"]]
    with pytest.raises(ValueError, match="not trusted"):
        selected.assert_bundle_current(context, bundle)


def test_grant_requires_current_human_explicit_copy_consent_and_bounded_deadline(enabled):
    selected, context, source, run, row = accepted()
    kwargs = {"expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
              "use_until": row["retain_until"], "retain_derived_copies": True, "rationale": "Allow derived copies."}
    with pytest.raises(ValueError, match="explicit"):
        selected.grant_training(context, source.id, run.run_id, **{**kwargs, "retain_derived_copies": 1})
    with pytest.raises(PermissionError):
        selected.grant_training(replace(context, human=False), source.id, run.run_id, **kwargs)
    with pytest.raises(review.ActionEpisodeConflict):
        selected.grant_training(context, source.id, run.run_id, **{**kwargs, "use_until": row["retain_until"] + 1})
    result = selected.grant_training(context, source.id, run.run_id, **kwargs)
    assert selected.grant_training(context, source.id, run.run_id, **kwargs)["revision"] == result["revision"]
    with pytest.raises(review.ActionEpisodeConflict):
        selected.grant_training(context, source.id, run.run_id, **{**kwargs, "use_until": row["retain_until"] - 1})


def test_full_public_key_fingerprint_is_returned_without_claiming_isolated_custody(enabled):
    _selected, context, _source, _run, _grant, bundle = issued()
    trust = provenance.local_trust(context.tenant)
    verified = provenance.verify_bundle(bundle, trust=trust, expected_tenant=context.tenant, now=time.time())
    assert verified["key_fingerprint"] == hashlib.sha256(bytes.fromhex(trust["keys"][bundle["signature"]["key_id"]])).hexdigest()
    assert set(verified) == {"body", "body_sha256", "signature", "signature_sha256", "trust_sha256", "key_fingerprint",
                             "signature_status", "commitments_status", "time_status", "live_status"}


@pytest.mark.parametrize("boundary", ["sign", "seal"])
def test_source_deleted_during_issuance_does_not_commit_or_expose_bundle(enabled, monkeypatch, boundary):
    selected, context, source, run, row = accepted()
    row = grant(selected, context, source, run, row)
    module, name = ((signing, "sign_detached_digest") if boundary == "sign" else (crypto_at_rest, "seal_to_str"))
    original = getattr(module, name)

    def delete_source(*args, **kwargs):
        value = original(*args, **kwargs)
        store.delete_flow(source.id)
        return value

    monkeypatch.setattr(module, name, delete_source)
    with pytest.raises(LookupError):
        issue(selected, context, source, run, row)
    saved = selected.records.get(row["id"])
    assert saved["revision"] == row["revision"] and "bundle_sha256" not in saved


def test_recovery_rechecks_authority_before_releasing_persisted_bytes(enabled, monkeypatch):
    selected, context, source, run, row = accepted()
    row = grant(selected, context, source, run, row)
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    with pytest.raises(review.ActionEpisodeAuditPending):
        issue(selected, context, source, run, row)
    persisted = review._open(context, selected.records.get(row["id"]))["issuance"]["bundle"]
    monkeypatch.setattr(audit, "record", original)
    selected.authorize = lambda *args: False
    with pytest.raises(PermissionError):
        issue(selected, context, source, run, row)
    assert selected.records.get(row["id"])["_audit_pending"]
    selected.authorize = lambda *args: True
    assert issue(selected, context, source, run, row) == persisted


def test_rotation_keeps_prior_trust_but_revocation_never_uses_backdated_time(enabled, local_audit_key_custody):
    _selected, context, _source, _run, _row, bundle = issued()
    old_key = bundle["signature"]["key_id"]
    new_key = signing.rotate_audit_keypair()
    assert new_key != old_key
    trust = provenance.local_trust(context.tenant)
    assert {old_key, new_key} <= set(trust["keys"])
    provenance.verify_bundle(bundle, trust=trust, expected_tenant=context.tenant, now=time.time())
    trust["revoked_keys"] = [old_key]
    with pytest.raises(ValueError, match="not trusted"):
        provenance.verify_bundle(bundle, trust=trust, expected_tenant=context.tenant, now=bundle["body"]["issued_at"])


def test_pending_withdrawal_blocks_content_and_recovers_without_rewriting_review(enabled, monkeypatch):
    selected, context, source, run, _grant, bundle = issued()
    row = selected.get(context, source.id, run.run_id)
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: 1)
    withdrawn = selected.withdraw(context, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], expected_review_sha256=row["review_sha256"],
        rationale="Withdraw consent for new training use.")
    assert withdrawn["status"] == "audit_pending" and withdrawn["committed_status"] == "withdrawn"
    assert "evidence" not in selected.get(context, source.id, run.run_id, detail=True)
    with pytest.raises(review.ActionEpisodeAuditPending):
        selected.assert_bundle_current(context, bundle)
    monkeypatch.setattr(audit, "record", original)
    recovered = selected.get(context, source.id, run.run_id)
    assert recovered["status"] == "withdrawn" and recovered["revision"] == withdrawn["revision"]
    assert review._open(context, selected.records.get(row["id"]))["review"] == bundle["body"]["review"]
    assert selected.get(context, source.id, run.run_id, detail=True)["withdrawal_detail"] == {
        "rationale": "Withdraw consent for new training use."}


def test_a_grant_from_a_reviewed_decision_still_issues_a_valid_signed_bundle(enabled):
    """The reviewed decision flow passes its decision identity to the grant. The
    signed bundle must still validate, or nothing granted that way can teach a flow."""
    selected, context, source, run, row = accepted()
    decision = {"operation": "a" * 32, "context": "b" * 64, "binding": "c" * 64}
    granted = selected.grant_training(context, source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], use_until=row["retain_until"] - 100,
        retain_derived_copies=True, rationale="Allow bounded recipe copies; downloads are not remotely erased.",
        decision=decision)
    bundle = issue(selected, context, source, run, granted)
    verified = provenance.verify_bundle(bundle, trust=provenance.local_trust(context.tenant),
                                        expected_tenant=context.tenant, now=time.time())
    assert verified["signature_status"] == "trusted"
