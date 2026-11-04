"""Native retained evidence: initial encryption, binding, authenticated CAS and expiry."""
from __future__ import annotations

import copy
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import pytest
from maverick import audit, crypto_at_rest
from maverick.flow import action_episode_review as review
from maverick.flow import store
from maverick.flow.approvals import paused_operation_binding
from maverick.paths import data_dir, tenant_scope

from test_support.action_episode_native import (
    ALLOWED,
    INPUTS,
    TENANT,
    TOOL_SCHEMAS,
    _calls,
    _context,
    _resume,
    _schema,
    _start,
)
from test_support.action_episode_native import native as native


def service(*, authorize=None, clock=time.time):
    return review.ActionEpisodeReviewService(authorize or (lambda ctx, _cap, flow_id:
        ctx == _context() and flow_id == "durable-native-actions"), clock=clock)


def enrollment(run, **changes):
    result = {"expected_pause_binding": paused_operation_binding(store.load_run(run.run_id)),
              "allowed_tools": ALLOWED, "input_schema": _schema(INPUTS),
              "tool_data_schemas": TOOL_SCHEMAS, "retain_until": time.time() + 3600}
    result.update(changes)
    return result


def ready(native, *, selected=None):
    selected = selected or service()
    source, run = _start()
    enrolled = selected.enroll(_context(), source.id, run.run_id, **enrollment(run))
    assert enrolled["status"] == "enrolled"
    assert _resume(run.run_id).status == "paused_approval"
    assert _resume(run.run_id).status == "completed"
    record = selected.get(_context(), source.id, run.run_id, detail=True)
    assert record["status"] == "awaiting_review" and len(_calls(native)) == 2
    return selected, source, run, record


def _accept(selected, source, run, row, **changes):
    args = {"expected_revision": row["revision"], "expected_episode_sha256": row["episode_sha256"],
            "accepted": True, "rationale": "Reviewed native business evidence for learning."}
    args.update(changes)
    return selected.review(_context(), source.id, run.run_id, **args)


def _path(row):
    return data_dir("flow_action_episodes", row["id"] + ".json")


def test_initial_local_record_explicitly_seals_raw_inputs_schemas_and_review(native):
    selected = service()
    source, run = _start()
    row = selected.enroll(_context(), source.id, run.run_id, **enrollment(run))
    raw = selected.records.get(row["id"])
    assert crypto_at_rest.is_sealed_str(raw["sensitive_envelope"])
    physical = _path(row).read_text(encoding="utf-8")
    assert physical.lstrip().startswith("{")  # Initial local rows themselves are plaintext JSON.
    assert '"inputs"' not in physical and '"customer"' not in physical and '"quantity"' not in physical
    envelope = json.loads(crypto_at_rest.unseal_from_str(raw["sensitive_envelope"]))
    assert envelope["payload"]["inputs"] == INPUTS
    assert "evidence" not in row and "sensitive_envelope" not in row
    assert selected.get(_context(), source.id, run.run_id, detail=True)["evidence"]["inputs"] == INPUTS
    events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    captured = [event for event in events if event.get("record_type") == "flow_action_episode"]
    assert captured and all(event["sig"] for event in captured)
    assert all('"customer"' not in json.dumps(event) and '"inputs"' not in json.dumps(event) for event in captured)


@pytest.mark.parametrize("failure", ["disabled", "plaintext"])
def test_enrollment_refuses_unencrypted_initial_writes(native, monkeypatch, failure):
    source, run = _start()
    if failure == "disabled":
        monkeypatch.setattr(crypto_at_rest, "at_rest_enabled", lambda: False)
    else:
        monkeypatch.setattr(crypto_at_rest, "seal_to_str", lambda text: text)
    with pytest.raises(crypto_at_rest.EncryptionUnavailable):
        service().enroll(_context(), source.id, run.run_id, **enrollment(run))
    assert service().records.count() == 0 and _calls(native) == []


@pytest.mark.parametrize("replacement", ["{}", "MVKAR1:not-ciphertext"])
def test_plaintext_or_prefix_only_payloads_are_never_fallback_decoded(native, replacement):
    source, run = _start()
    row = service().enroll(_context(), source.id, run.run_id, **enrollment(run))
    path = _path(row)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["sensitive_envelope"] = replacement
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="sealed envelope"):
        service().get(_context(), source.id, run.run_id, detail=True)


def test_ciphertext_from_another_record_is_rejected_after_successful_decryption(native):
    source, first = _start()
    first_row = service().enroll(_context(), source.id, first.run_id, **enrollment(first))
    _, second = _start()
    second_row = service().enroll(_context(), source.id, second.run_id, **enrollment(second))
    first_ciphertext = service().records.get(first_row["id"])["sensitive_envelope"]
    second_path = _path(second_row)
    raw = json.loads(second_path.read_text(encoding="utf-8"))
    raw["sensitive_envelope"] = first_ciphertext
    second_path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="envelope binding"):
        service().get(_context(), source.id, second.run_id, detail=True)


def test_old_revision_ciphertext_cannot_replace_newer_captured_steps(native):
    source, run = _start()
    row = service().enroll(_context(), source.id, run.run_id, **enrollment(run))
    first_ciphertext = service().records.get(row["id"])["sensitive_envelope"]
    _resume(run.run_id)
    raw = json.loads(_path(row).read_text(encoding="utf-8"))
    assert raw["revision"] > 1
    raw["sensitive_envelope"] = first_ciphertext
    _path(row).write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError, match="envelope binding"):
        service().get(_context(), source.id, run.run_id, detail=True)


def test_enrollment_retry_is_idempotent_but_changed_contract_conflicts(native):
    source, run = _start()
    args = enrollment(run)
    first = service().enroll(_context(), source.id, run.run_id, **args)
    repeated = service().enroll(_context(), source.id, run.run_id, **args)
    assert repeated["id"] == first["id"] and repeated["revision"] == first["revision"]
    with pytest.raises(review.ActionEpisodeConflict, match="different capture"):
        service().enroll(_context(), source.id, run.run_id, **{**args, "retain_until": args["retain_until"] + 10})


def test_enrollment_cannot_reconstruct_earlier_unretained_actions(native):
    source, run = _start()
    middle = _resume(run.run_id)
    assert len(_calls(native)) == 1
    with pytest.raises(review.ActionEpisodeConflict, match="initial approval"):
        service().enroll(_context(), source.id, run.run_id, **enrollment(middle))


@pytest.mark.parametrize("value", [True, "tomorrow", float("inf"), -1])
def test_retention_timestamp_is_strict_and_finite(native, value):
    source, run = _start()
    with pytest.raises(ValueError):
        service().enroll(_context(), source.id, run.run_id, **enrollment(run, retain_until=value))


def test_retention_cannot_exceed_seven_days(native):
    source, run = _start()
    with pytest.raises(ValueError, match="seven days"):
        service().enroll(_context(), source.id, run.run_id,
                         **enrollment(run, retain_until=time.time() + review.MAX_RETENTION_SECONDS + 100))


@pytest.mark.parametrize("change", [
    lambda s: s.update(additionalProperties=True),
    lambda s: s.update(required=[]),
    lambda s: s.update(required=["customer", "customer", "quantity"]),
    lambda s: s.update(**{"$ref": "https://must-not-fetch.test/schema"}),
    lambda s: s["properties"]["customer"].update(pattern="(a+)+$"),
    lambda s: s["properties"]["customer"].pop("maxLength"),
    lambda s: s["properties"]["customer"].update(maxLength=1025),
    lambda s: s["properties"]["quantity"].update(minimum=False),
    lambda s: s["properties"]["quantity"].pop("maximum"),
    lambda s: s["properties"].update(extra={"type": "string", "maxLength": 10}),
    lambda s: s["properties"]["customer"].update(type=["string"]),
    lambda s: s["properties"]["customer"].update(type={"type": "string"}),
])
def test_retention_schemas_are_closed_bounded_and_nonprogrammable(native, change):
    source, run = _start()
    schema = _schema(INPUTS)
    change(schema)
    with pytest.raises(ValueError):
        service().enroll(_context(), source.id, run.run_id, **enrollment(run, input_schema=schema))
    assert service().records.count() == 0


def test_schema_bound_violation_after_effect_marks_evidence_unusable(native):
    source, run = _start()
    schemas = copy.deepcopy(TOOL_SCHEMAS)
    schemas["episode_lookup"]["result"]["properties"]["customer_id"]["maxLength"] = 1
    service().enroll(_context(), source.id, run.run_id, **enrollment(run, tool_data_schemas=schemas))
    assert _resume(run.run_id).status == "paused_approval"
    assert _resume(run.run_id).status == "completed"
    assert len(_calls(native)) == 2
    assert service().get(_context(), source.id, run.run_id)["status"] == "unusable"


def test_review_is_separate_from_native_execution_approvals(native):
    selected, source, run, row = ready(native)
    with pytest.raises(review.ActionEpisodeConflict, match="no accepted"):
        selected.export(_context(), source.id, run.run_id)
    accepted = _accept(selected, source, run, row)
    assert accepted["status"] == "accepted"
    bundle = selected.export(_context(), source.id, run.run_id)
    assert bundle["episode"]["inputs"] == INPUTS
    assert bundle["review"]["authenticated"] is True
    assert bundle["review"]["reviewer"] == _context().actor
    assert bundle["review"]["episode_sha256"] == row["episode_sha256"]
    assert len(_calls(native)) == 2
    assert selected.review(_context(), source.id, run.run_id, expected_revision=row["revision"],
        expected_episode_sha256=row["episode_sha256"], accepted=True,
        rationale="Reviewed native business evidence for learning.")["revision"] == accepted["revision"]


@pytest.mark.parametrize("changes", [{"expected_revision": 1}, {"expected_episode_sha256": "0" * 64},
                                     {"accepted": "true"}, {"accepted": 1}])
def test_review_requires_exact_evidence_revision_and_literal_verdict(native, changes):
    selected, source, run, row = ready(native)
    with pytest.raises((ValueError, review.ActionEpisodeConflict)):
        _accept(selected, source, run, row, **changes)


def test_human_flag_without_authorization_is_insufficient(native):
    source, run = _start()
    with pytest.raises(PermissionError):
        service(authorize=lambda *a: 1).enroll(_context(), source.id, run.run_id, **enrollment(run))
    with pytest.raises(PermissionError):
        service(authorize=lambda *a: True).enroll(replace(_context(), human=False),
                                                source.id, run.run_id, **enrollment(run))


def test_current_authority_is_checked_again_after_encryption(native, monkeypatch):
    source, run = _start()
    allowed = [True]
    original = crypto_at_rest.seal_to_str

    def seal_and_revoke(text):
        encrypted = original(text)
        allowed[0] = False
        return encrypted

    monkeypatch.setattr(crypto_at_rest, "seal_to_str", seal_and_revoke)
    with pytest.raises(PermissionError):
        service(authorize=lambda *a: allowed[0]).enroll(_context(), source.id, run.run_id, **enrollment(run))
    assert service().records.count() == 0


def test_review_authority_revoked_during_encryption_cannot_commit(native, monkeypatch):
    selected, source, run, row = ready(native)
    allowed = [True]
    selected.authorize = lambda *args: allowed[0]
    original = crypto_at_rest.seal_to_str

    def seal_and_revoke(text):
        encrypted = original(text)
        allowed[0] = False
        return encrypted

    monkeypatch.setattr(crypto_at_rest, "seal_to_str", seal_and_revoke)
    with pytest.raises(PermissionError):
        _accept(selected, source, run, row)
    saved = selected.records.get(row["id"])
    assert saved["revision"] == row["revision"] and saved["status"] == "awaiting_review"


def test_default_metadata_and_audit_never_include_business_evidence(native):
    selected, source, run, row = ready(native)
    metadata = selected.get(_context(), source.id, run.run_id)
    assert "evidence" not in metadata and "sensitive_envelope" not in metadata
    accepted = _accept(selected, source, run, row)
    raw = selected.records.get(row["id"])
    assert crypto_at_rest.is_sealed_str(raw["sensitive_envelope"])
    assert '"arguments"' not in _path(row).read_text(encoding="utf-8")
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event.get("record_type") == "flow_action_episode"]
    assert any(event["action"] == "action_episode_reviewed" for event in events)
    assert all("business evidence" not in json.dumps(event) and '"inputs"' not in json.dumps(event) for event in events)
    assert accepted["audit_status"] == "delivered"


@pytest.mark.parametrize("receipt", [False, None, 1])
def test_review_committed_with_pending_audit_withholds_evidence_and_recovers(native, monkeypatch, receipt):
    selected, source, run, row = ready(native)
    original = audit.record
    monkeypatch.setattr(audit, "record", lambda *a, **k: receipt)
    pending = _accept(selected, source, run, row)
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "accepted"
    assert "evidence" not in pending
    assert "evidence" not in selected.get(_context(), source.id, run.run_id, detail=True)
    with pytest.raises(review.ActionEpisodeAuditPending):
        selected.export(_context(), source.id, run.run_id)
    monkeypatch.setattr(audit, "record", original)
    recovered = selected.get(_context(), source.id, run.run_id, detail=True)
    assert recovered["status"] == "accepted" and recovered["revision"] == pending["revision"]
    assert selected.export(_context(), source.id, run.run_id)["review"]["authenticated"] is True
    assert len(_calls(native)) == 2


def test_conflicting_reviewers_cannot_replace_a_committed_verdict(native):
    _selected, source, run, row = ready(native)
    barrier = threading.Barrier(2)

    def commit(accepted):
        selected = service()
        barrier.wait(timeout=5)
        try:
            return _accept(selected, source, run, row, accepted=accepted)
        except review.ActionEpisodeConflict:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(commit, (True, False)))
    winners = [result for result in results if result is not None]
    assert len(winners) == 1 and winners[0]["revision"] == row["revision"] + 1


def test_expiry_on_access_strips_ciphertext_and_keeps_digest_tombstone(native):
    selected, source, run, row = ready(native)
    _accept(selected, source, run, row)
    expired_service = service(clock=lambda: row["retain_until"] + 1)
    expired = expired_service.get(_context(), source.id, run.run_id, detail=True)
    assert expired["status"] == "expired" and "evidence" not in expired
    raw = selected.records.get(row["id"])
    assert "sensitive_envelope" not in raw and raw["episode_sha256"] == row["episode_sha256"]
    with pytest.raises(review.ActionEpisodeConflict):
        expired_service.export(_context(), source.id, run.run_id)
    assert selected.records.count() == 1


def test_historical_source_edit_keeps_original_evidence_attribution(native):
    selected, source, run, row = ready(native)
    # Accepted while current; a later edit of the procedure must not rewrite
    # the retained evidence (and a learning decision after an edit is refused).
    _accept(selected, source, run, row)
    changed = store.load_flow(source.id)
    changed.nodes["update"].params["quantity"] = 88
    store.save_flow(changed)
    bundle = selected.export(_context(), source.id, run.run_id)
    assert bundle["provenance"]["source_current"] is False
    assert bundle["episode"]["steps"][1]["arguments"]["quantity"] == 3


def test_learning_decision_after_a_procedure_edit_is_refused(native):
    selected, source, run, row = ready(native)
    changed = store.load_flow(source.id)
    changed.nodes["update"].params["quantity"] = 88
    store.save_flow(changed)
    with pytest.raises(review.ActionEpisodeConflict, match="reviewed procedure changed"):
        _accept(selected, source, run, row)


@pytest.mark.parametrize("change", ["owner", "recreate"])
def test_changed_owner_or_definition_generation_withholds_retained_evidence(native, change):
    selected, source, run, row = ready(native)
    current = store.load_flow(source.id)
    if change == "owner":
        current.owner = "other-owner"
    else:
        store.delete_flow(source.id)
    store.save_flow(current)
    with pytest.raises((PermissionError, review.ActionEpisodeConflict)):
        selected.get(_context(), source.id, run.run_id, detail=True)


def test_other_tenant_or_owner_cannot_read_or_export_retained_evidence(native):
    selected, source, run, row = ready(native)
    _accept(selected, source, run, row)
    permissive = service(authorize=lambda *a: True)
    with pytest.raises(PermissionError):
        permissive.get(replace(_context(), resource_owner="foreign-owner"), source.id, run.run_id, detail=True)
    with pytest.raises(LookupError):
        permissive.export(replace(_context(), tenant="other-tenant"), source.id, run.run_id)
    with tenant_scope(tenant="other-tenant"):
        assert selected.records.get(row["id"]) is None
    with tenant_scope(tenant=TENANT):
        assert selected.records.get(row["id"]) is not None
