"""Independent failure-injection review of exact approvals and promotion proof."""
from __future__ import annotations

from dataclasses import replace

import pytest
from maverick import config
from maverick.governed_operations import (
    ActionReviewRequiredError,
    ApprovalBindingError,
    ServiceContext,
)
from maverick.paths import current_tenant_id, tenant_scope
from maverick.vendor_evidence_evolution import BINDINGS, EvidenceRenewalEvolution
from maverick.vendor_onboarding import VendorOnboardingService
from maverick.vendor_onboarding_adapters import (
    EvidenceDocument,
    FakeGoogleDriveEvidence,
    FakeJiraTickets,
    JiraTickets,
    jira_body,
    resolve_connection,
)

NOW = 1_800_000_000.0


@pytest.fixture
def environment(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[vendor_onboarding]\nenable=true\n[vendor_management]\nenable=true\n"
        "[ai_vendor_risk]\nenable=true\n[model_risk_assurance]\nenable=true\n"
        "[flows]\nenable=true\n", encoding="utf-8",
    )
    config.reset_config_cache()
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *args, **kwargs: True)
    ctx = ServiceContext("customer-a", "user:reviewer", "procurement",
                         "user:reviewer", "jira", human=True)
    docs = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "v1", NOW - 100, b"Data is encrypted at rest and in transit.",
    )})
    tickets, denied = FakeJiraTickets(), set()
    service = VendorOnboardingService(docs, tickets, lambda c, cap, resource: cap not in denied,
                                      clock=lambda: NOW)
    yield service, ctx, docs, tickets, denied
    config.reset_config_cache()


def _assessed(service, ctx):
    row = service.intake(ctx, "Synthetic vendor", "security-paper", "VEND", "Synthetic pilot")
    row = service.collect_evidence(ctx, row["id"], row["revision"])
    return service.assess(ctx, row["id"], row["revision"])


def _approved(service, ctx):
    row = _assessed(service, ctx)
    row = service.review(ctx, row["id"], row["revision"], "approved", "Limited synthetic pilot")
    row = service.prepare_action(ctx, row["id"], row["revision"])
    return service.approve_action(
        ctx,
        row["id"],
        row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )


@pytest.mark.parametrize("reviewed_binding", [None, "0" * 64, "not-a-digest"])
def test_direct_approval_requires_the_exact_reviewed_card(
    environment, reviewed_binding,
):
    service, ctx, _, tickets, _ = environment
    row = _assessed(service, ctx)
    row = service.review(
        ctx,
        row["id"],
        row["revision"],
        "approved",
        "Limited synthetic pilot",
    )
    row = service.prepare_action(ctx, row["id"], row["revision"])

    with pytest.raises(ApprovalBindingError) as rejected:
        service.approve_action(
            ctx,
            row["id"],
            row["revision"],
            reviewed_binding,
        )

    assert rejected.value.code == "approval_binding_invalid"
    assert service.get(ctx, row["id"]) == row
    assert tickets.creates == 0


def test_expired_review_card_is_retired_before_direct_approval(environment):
    service, ctx, _, tickets, _ = environment
    row = _assessed(service, ctx)
    row = service.review(
        ctx,
        row["id"],
        row["revision"],
        "approved",
        "Limited synthetic pilot",
    )
    row = service.prepare_action(ctx, row["id"], row["revision"])
    binding = row["operation"]["approval_card"]["binding_sha256"]
    service.clock = lambda: NOW + 3601

    with pytest.raises(ApprovalBindingError) as rejected:
        service.approve_action(ctx, row["id"], row["revision"], binding)

    assert rejected.value.code == "approval_expired"
    current = service.get(ctx, row["id"])
    assert current["stage"] == "review_approved"
    assert current["operation"] is None
    assert current["operation_history"][-1]["invalidated_reason"] == "approval_expired"
    assert tickets.creates == 0


@pytest.mark.parametrize("change", ["expired", "reviewer_revoked"])
def test_approval_changes_during_durable_claim_cannot_execute(environment, monkeypatch, change):
    service, ctx, _, tickets, denied = environment
    row = _approved(service, ctx)
    save = service._save

    def claim_then_change(*args, **kwargs):
        stored = save(*args, **kwargs)
        if kwargs.get("stage") == "executing":
            if change == "expired":
                service.clock = lambda: NOW + 3601
            else:
                denied.add("action.approve")
        return stored

    monkeypatch.setattr(service, "_save", claim_then_change)
    with pytest.raises(ApprovalBindingError):
        service.execute(ctx, row["id"])
    assert tickets.creates == 0
    result = service.get(ctx, row["id"])
    assert result["stage"] == "review_approved"
    assert result["operation"] is None
    assert result["operation_history"][-1]["state"] == "invalidated"


def test_credential_rotation_after_last_service_check_cannot_change_effect_authority(environment, monkeypatch):
    from maverick import vendor_onboarding

    service, ctx, _, tickets, _ = environment
    row = _approved(service, ctx)
    apply = vendor_onboarding.apply_declared

    def rotate_then_apply(operation, callback):
        tickets.version = "rotated-after-final-service-check"
        return apply(operation, callback)

    monkeypatch.setattr(vendor_onboarding, "apply_declared", rotate_then_apply)
    with pytest.raises(ActionReviewRequiredError) as rejected:
        service.execute(ctx, row["id"])

    assert rejected.value.code == "approval_authority_changed"
    assert tickets.creates == 0
    result = service.get(ctx, row["id"])
    assert result["stage"] == "review_approved"
    assert result["operation"] is None
    assert result["operation_history"][-1]["state"] == "invalidated"
    assert result["operation_history"][-1]["invalidated_reason"] == "approval_authority_changed"


def test_role_loss_before_read_retires_approval_before_role_restore(environment):
    service, ctx, _, tickets, _ = environment
    row = _approved(service, ctx)
    denied_ctx = replace(
        ctx,
        authorization_role="read_only",
        authorization_policy="read-only-policy-v2",
    )
    service.authorize = lambda candidate, *_: candidate.authorization_role != "read_only"

    with pytest.raises(ApprovalBindingError) as rejected:
        service.execute(denied_ctx, row["id"])

    assert rejected.value.code == "approval_authority_changed"
    assert tickets.creates == 0
    current = service.get(ctx, row["id"])
    assert current["stage"] == "review_approved"
    assert current["operation"] is None
    assert current["operation_history"][-1]["state"] == "invalidated"
    assert current["operation_history"][-1]["invalidated_reason"] == "approval_authority_changed"

    with pytest.raises(ValueError, match="approved operation required"):
        service.execute(ctx, row["id"])
    assert tickets.creates == 0


def _renewal_input(now):
    return {"due_at": NOW + 1000, "now": now, "evidence_status": "available",
            "source_version": "v1", "expected_source_version": "v1",
            "downstream_version": "v1", "expected_downstream_version": "v1",
            "customer_accepted": True}


def test_evaluation_category_labels_cannot_substitute_for_real_adversarial_cases(environment):
    _, ctx, *_ = environment
    evolution = EvidenceRenewalEvolution(lambda *args: True)
    observations = []
    for index, offset in enumerate((10, 20, 2000)):
        observation = evolution.observe(
            ctx, _renewal_input(NOW + offset), "fresh" if offset < 1000 else "renewal_due",
            source_case_id=f"synthetic-{index}", source_workflow_version="v1",
            rationale="Independently authored synthetic observation",
        )
        observations.append(observation["id"])
    proposal = evolution.propose(ctx, observations, bindings=BINDINGS, rationale="Reviewed bindings")
    cases = [{"id": str(index), "category": category, "inputs": _renewal_input(NOW + 100),
              "expected": "fresh", "bindings": BINDINGS, "material": "internally_authored_synthetic"}
             for index, category in enumerate(("held_out", "changed_inputs", "invalid_bindings",
                                                "changed_downstream", "invalid_inputs"))]
    with pytest.raises(ValueError):
        evolution.evaluate(ctx, proposal["id"], cases)


def test_connection_resolution_obeys_explicit_tenant_without_ambient_scope(environment, monkeypatch):
    from maverick import connections

    _, ctx, *_ = environment
    looked_up = []

    def connection(reference):
        looked_up.append(current_tenant_id())
        return {"connector": "jira", "owner": ctx.credential_authority,
                "token": "synthetic-local-token", "revision": "v1", "base_url": "https://jira.example.test"}

    monkeypatch.setattr(connections, "enabled", lambda: True)
    monkeypatch.setattr(connections, "get_connection", connection)
    monkeypatch.setattr(connections, "_may_use", lambda *args: True)
    with tenant_scope(tenant="customer-b"):
        resolve_connection(ctx)
        assert current_tenant_id() == "customer-b"
    assert looked_up == [ctx.tenant]


def test_missing_external_version_cannot_be_verified_as_complete_evidence(environment, monkeypatch):
    _, ctx, *_ = environment
    adapter = JiraTickets()
    payload = {"project": "VEND", "summary": "Synthetic", "description": "Reviewed",
               "marker": "lightwork-vop-" + "1" * 32}
    response = {"key": "VEND-1", "fields": jira_body(payload)["fields"]}
    monkeypatch.setattr(adapter, "_request", lambda *args, **kwargs: response)
    try:
        observed = adapter.verify(ctx, "VEND-1", payload)
    except (ValueError, RuntimeError):
        return
    assert observed["verified"] is False


def test_corrected_review_recovery_cannot_report_different_answers_as_applied(environment, monkeypatch):
    service, ctx, *_ = environment
    row = _assessed(service, ctx)
    question = next(iter(row["assessment"]["answers"]))
    save = service._save

    def unavailable(*args, **kwargs):
        raise OSError("saga storage unavailable after domain review")

    monkeypatch.setattr(service, "_save", unavailable)
    with pytest.raises(OSError):
        service.review(ctx, row["id"], row["revision"], "approved", "First reviewed interpretation",
                       corrections={question: {"answer": "yes", "note": "First interpretation"}})
    monkeypatch.setattr(service, "_save", save)
    # A retry is allowed to reject the changed intent or create the exact new
    # corrected assessment. It must not attest that un-applied answers were used.
    try:
        recovered = service.review(
            ctx, row["id"], row["revision"], "approved", "Changed interpretation after recovery",
            corrections={question: {"answer": "no", "note": "Changed interpretation"}},
        )
    except (ValueError, RuntimeError):
        return
    assert recovered["assessment"]["answers"][question]["answer"] == "no"
    assert recovered["review_history"][-1]["corrections"][question]["answer"] == "no"
