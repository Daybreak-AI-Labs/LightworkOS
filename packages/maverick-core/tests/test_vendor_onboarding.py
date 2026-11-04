"""Offline acceptance of approval/evidence/effect/customer boundaries."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from maverick import config, provider_cost_cap, vendor_onboarding
from maverick.governed_operations import (
    ApprovalBindingError,
    ServiceContext,
    digest,
    operation_binding,
)
from maverick.governed_records import RecordConflict
from maverick.paths import tenant_scope
from maverick.vendor_onboarding import VendorOnboardingService
from maverick.vendor_onboarding_adapters import (
    CredentialAuthorityChanged,
    EvidenceDocument,
    FakeGoogleDriveEvidence,
    FakeJiraTickets,
    ProviderMultipleMatches,
)

NOW = 1_800_000_000.0
TEXT = b"We do not train models on customer data. Data is encrypted at rest and in transit."
POLICY = Path(__file__).resolve().parents[3] / "scripts/acceptance/fixtures/vendor-documents/northstar-policy.pdf"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_REPLICA_COUNT", raising=False)
    monkeypatch.delenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", raising=False)
    (tmp_path / "config.toml").write_text(
        "[vendor_onboarding]\nenable=true\n[vendor_management]\nenable=true\n"
        "[ai_vendor_risk]\nenable=true\n[model_risk_assurance]\nenable=true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    monkeypatch.setattr(audit, "record_global", lambda *a, **kw: True)
    ctx = ServiceContext(
        "customer-a", "reviewer@example.test", "procurement",
        "reviewer@example.test", "jira", human=True,
        authorization_role="operator", authorization_policy="operator-policy-v1",
        budget_authority="tenant-budget-v1",
        workspace_authority="workspace-generation-1",
    )
    docs = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "1", NOW - 86400, TEXT,
    )})
    tickets = FakeJiraTickets()
    denied = set()
    svc = VendorOnboardingService(docs, tickets, lambda c, cap, res: cap not in denied,
                                  clock=lambda: NOW)
    yield svc, ctx, docs, tickets, denied
    config.reset_config_cache()


def reviewed(svc, ctx):
    row = svc.intake(ctx, "Synthetic Acme AI", "security-paper", "VEND", "Draft support replies")
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    assert row["evidence"]["status"] == "available"
    row = svc.assess(ctx, row["id"], row["revision"])
    return svc.review(ctx, row["id"], row["revision"], "approved",
                      "Gaps accepted for restricted synthetic pilot", review_seconds=12.5)


def approved(svc, ctx):
    row = reviewed(svc, ctx)
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    return svc.approve_action(
        ctx,
        row["id"],
        row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )


def test_case_provider_calls_are_bound_to_the_vendor_work_item(setup, monkeypatch):
    service, ctx, docs, *_ = setup
    ledger = Path(os.environ["MAVERICK_HOME"]) / "provider-spend-test.json"
    monkeypatch.setattr(provider_cost_cap, "_ledger_path", lambda: ledger)
    monkeypatch.setattr(provider_cost_cap, "_shared_world", lambda: None)
    original_fetch = docs.fetch
    calls = 0

    def metered_fetch(bound_ctx, document_id):
        nonlocal calls
        calls += 1
        held = provider_cost_cap.reserve(
            "gdrive", 0.25, request_id=f"document-read-{calls}",
        )
        provider_cost_cap.settle(held, 0.2)
        return original_fetch(bound_ctx, document_id)

    monkeypatch.setattr(docs, "fetch", metered_fetch)
    row = service.intake(
        ctx, "Attributed vendor", "security-paper", "VEND", "Attribute evidence cost",
    )
    service.collect_evidence(ctx, row["id"], row["revision"])

    with tenant_scope(tenant=ctx.tenant):
        receipts = provider_cost_cap.reservations_for_work_item(
            f"vendor:{row['id']}", path=ledger,
        )
    assert len(receipts.receipts) == 1
    assert receipts.receipts[0].provider == "gdrive"
    assert receipts.receipts[0].state == "settled"


def test_intake_submission_key_is_durable_under_replay_and_concurrency(setup):
    service, ctx, _, tickets, _ = setup
    arguments = dict(
        vendor_name="Idempotent synthetic vendor",
        document_id="security-paper",
        project="VEND",
        purpose="One stable intake despite a lost response",
        submission_key="customer-submit-0001",
    )
    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _index: service.intake(ctx, **arguments), range(6)))
    assert len({row["id"] for row in results}) == 1
    assert len({row["revision"] for row in results}) == 1
    assert len(service.list(ctx)) == 1
    assert tickets.creates == 0
    with tenant_scope(tenant=ctx.tenant):
        stored = vendor_onboarding._CASES.get(results[0]["id"])
    assert stored["intake_idempotency"]["key_sha256"] == hashlib.sha256(
        arguments["submission_key"].encode("utf-8")
    ).hexdigest()
    assert arguments["submission_key"] not in str(stored)
    assert results[0]["intake_idempotency"] == {
        "state": "bound", "scope": "tenant_resource_owner",
    }

    with pytest.raises(
        vendor_onboarding.VendorOnboardingIdempotencyConflict,
        match="different vendor request",
    ):
        service.intake(ctx, **dict(arguments, purpose="Changed customer objective"))
    assert len(service.list(ctx)) == 1


@pytest.mark.parametrize("submission_key", ["short", "contains a space key", "x" * 129, None])
def test_intake_submission_key_validation_and_legacy_compatibility(setup, submission_key):
    service, ctx, *_ = setup
    arguments = dict(
        vendor_name="Submission key validation vendor",
        document_id="security-paper",
        project="VEND",
        purpose="Validate intake identity",
        submission_key=submission_key,
    )
    if submission_key is None:
        first = service.intake(ctx, **arguments)
        second = service.intake(ctx, **arguments)
        assert first["id"] != second["id"]
        return
    with pytest.raises(ValueError, match="submission_key"):
        service.intake(ctx, **arguments)


def test_submission_keys_and_queue_cursors_are_tenant_scoped(setup):
    service, ctx, *_ = setup
    arguments = dict(
        vendor_name="Tenant scoped request",
        document_id="security-paper",
        project="VEND",
        purpose="Keep request identity inside one tenant",
        submission_key="same-customer-key-0001",
    )
    first = service.intake(ctx, **arguments)
    service.intake(
        ctx,
        **dict(arguments, vendor_name="Tenant scoped request two",
               submission_key="same-customer-key-0002"),
    )
    page = service.list_page(ctx, limit=1)
    assert page["has_more"] is True

    other = replace(ctx, tenant="customer-b", workspace_authority="workspace-generation-b")
    second = service.intake(other, **arguments)
    assert second["id"] != first["id"]
    assert [row["id"] for row in service.list(other)] == [second["id"]]
    with pytest.raises(ValueError, match="cursor"):
        service.list_page(other, limit=1, cursor=page["next_cursor"])


def test_queue_pagination_and_unresolved_filter_cover_three_pages_without_duplicates(setup):
    from maverick import vendor_onboarding
    from maverick.paths import tenant_scope

    service, ctx, *_ = setup
    created = []
    unresolved = set()
    for index in range(9):
        row = service.intake(
            ctx,
            f"Paged vendor {index}",
            "security-paper",
            "VEND",
            f"Stable page {index}",
            submission_key=f"paged-submission-{index:04d}",
        )
        created.append(row["id"])
        if index % 2 == 0:
            unresolved.add(row["id"])
            with tenant_scope(tenant=ctx.tenant):
                vendor_onboarding._CASES.update(
                    row["id"],
                    lambda value: value.update(
                        stage="reconciliation_required",
                        operation={"state": "reconciliation_required"},
                    ),
                    expected_revision=row["revision"],
                    action="test_unresolved_queue_fixture",
                    actor=ctx.actor,
                )

    def collect(view):
        cursor, seen, pages = "", [], 0
        while True:
            page = service.list_page(ctx, limit=2, cursor=cursor, view=view)
            pages += 1
            assert page["schema"] == "lightwork.vendor-onboarding.case-page.v1"
            assert page["record_reads"] <= 8
            seen.extend(item["id"] for item in page["cases"])
            if not page["has_more"]:
                assert page["next_cursor"] is None
                break
            assert page["next_cursor"] and page["next_cursor"] != cursor
            cursor = page["next_cursor"]
            assert pages < 20
        assert len(seen) == len(set(seen))
        return seen, pages

    all_ids, all_pages = collect("all")
    unresolved_ids, unresolved_pages = collect("unresolved")
    assert set(all_ids) == set(created)
    assert set(unresolved_ids) == unresolved
    assert all_pages >= 3 and unresolved_pages >= 3
    for cursor in ["not base64!", "e30", "x" * 769]:
        with pytest.raises(ValueError, match="cursor"):
            service.list_page(ctx, cursor=cursor)


def test_draft_edits_are_revision_bound_and_restart_only_affected_review(setup):
    service, ctx, *_ = setup
    row = reviewed(service, ctx)
    original_revision = row["revision"]

    rescheduled = service.update_draft(
        ctx,
        row["id"],
        original_revision,
        project=row["project"],
        purpose=row["purpose"],
        freshness_days=row["freshness_days"],
        due_at=NOW + 30 * 86400,
    )
    assert rescheduled["revision"] == original_revision + 1
    assert rescheduled["stage"] == row["stage"]
    assert rescheduled["evidence"] == row["evidence"]
    assert rescheduled["assessment"] == row["assessment"]
    assert rescheduled["due_at"] == NOW + 30 * 86400

    changed = service.update_draft(
        ctx,
        row["id"],
        rescheduled["revision"],
        project="RISK",
        purpose="Assess a newly declared customer use",
        freshness_days=180,
        due_at=NOW + 45 * 86400,
    )
    assert changed["stage"] == "intake"
    assert changed["evidence"] is None and changed["assessment"] is None
    assert changed["operation"] is None

    with pytest.raises(RecordConflict):
        service.update_draft(
            ctx,
            row["id"],
            original_revision,
            project="OPS",
            purpose="A stale tab must not overwrite current details",
            freshness_days=90,
            due_at=NOW + 60 * 86400,
        )
    current = service.get(ctx, row["id"])
    assert current["revision"] == changed["revision"]
    assert current["project"] == "RISK"
    assert current["purpose"] == "Assess a newly declared customer use"


@pytest.mark.parametrize("action", ["intake", "get", "list", "execute", "reconcile", "cancel", "renewal", "evidence_version"])
def test_unsupported_deployment_blocks_before_saga_storage_or_provider_access(setup, monkeypatch, tmp_path, action):
    from maverick import governed_records, vendor_onboarding

    service, ctx, _, tickets, _ = setup
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "2")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_PG_DSN", "postgresql://synthetic.invalid/unused")
    # A valid shared-store selection must not be mistaken for a supported
    # supplier saga topology. Selection itself does not contact Postgres.
    assert governed_records._selection().kind == "postgres"
    assert governed_records._selection().shared_required is True
    touched = []

    def forbidden(*args, **kwargs):
        touched.append(True)
        raise AssertionError("unsupported deployment reached local saga or external access")

    monkeypatch.setattr(vendor_onboarding, "cross_process_lock", forbidden)
    monkeypatch.setattr(vendor_onboarding._CASES, "_backend", forbidden)
    monkeypatch.setattr(service.documents, "version", forbidden)
    operations = {
        "intake": lambda: service.intake(ctx, "Unsupported request", "security-paper", "VEND", "Stop before mutation"),
        "get": lambda: service.get(ctx, "VON-unused"),
        "list": lambda: service.list(ctx),
        "execute": lambda: service.execute(ctx, "VON-unused"),
        "reconcile": lambda: service.reconcile(ctx, "VON-unused"),
        "cancel": lambda: service.cancel(ctx, "VON-unused", 1, "No supported topology"),
        "renewal": lambda: service.check_renewal(ctx, "VON-unused"),
        "evidence_version": lambda: service.current_evidence_version(ctx, {"document_id": "security-paper"}),
    }
    before = {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")}
    with pytest.raises(ValueError, match="installation") as error:
        operations[action]()
    assert error.value.code == "unsupported_deployment"
    assert error.value.next_action
    assert touched == []
    assert {path.relative_to(tmp_path).as_posix() for path in tmp_path.rglob("*")} == before
    assert tickets.creates == 0


@pytest.mark.parametrize("value", ["2", "3", "0", "-1", "1.0", "two", ""])
def test_deployment_readiness_rejects_unsupported_or_invalid_replica_count(setup, monkeypatch, value):
    from maverick import vendor_onboarding

    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", value)
    state = vendor_onboarding.deployment_readiness()
    assert state["supported"] is False
    assert state["code"] in {"unsupported_deployment", "deployment_configuration_unavailable"}
    assert state["message"] and state["next_action"]


@pytest.mark.parametrize("origin", ["environment", "global_config", "invalid_config", "unreadable_config"])
def test_deployment_readiness_uses_global_override_and_fails_closed(setup, monkeypatch, tmp_path, origin):
    from maverick import vendor_onboarding

    if origin == "environment":
        monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "yes")
    else:
        path = tmp_path / "config.toml"
        suffix = ("\n[deployment]\nallow_multiple_control_planes=true\n" if origin == "global_config" else
                  "\n[deployment]\nallow_multiple_control_planes='invalid'\n" if origin == "invalid_config" else
                  "\n[broken-private-token\n")
        path.write_text(path.read_text() + suffix)
        config.reset_config_cache()
    # A tenant overlay cannot hide a global unsupported topology.
    tenant_directory = tmp_path / "tenants/customer-a"
    tenant_directory.mkdir(parents=True, exist_ok=True)
    (tenant_directory / "config.toml").write_text("[deployment]\nallow_multiple_control_planes=false\n")
    with tenant_scope(tenant="customer-a"):
        state = vendor_onboarding.deployment_readiness()
    assert state["supported"] is False
    assert "broken-private-token" not in str(state)
    assert "config.toml" not in str(state)
    assert state["next_action"]


def test_supported_deployment_readiness_is_read_only_and_is_not_connection_readiness(setup, monkeypatch, tmp_path):
    from maverick import vendor_onboarding

    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "false")
    before = {path.relative_to(tmp_path).as_posix(): path.read_bytes()
              for path in tmp_path.rglob("*") if path.is_file()}
    state = vendor_onboarding.deployment_readiness()
    assert state["supported"] is True
    assert state["profile"] == "single_persistent_application_replica"
    assert "connection" in state["next_action"].lower()
    assert {path.relative_to(tmp_path).as_posix(): path.read_bytes()
            for path in tmp_path.rglob("*") if path.is_file()} == before


@pytest.mark.parametrize("point", ["after_claim", "after_create"])
def test_deployment_drift_preserves_durable_uncertainty_without_more_effects(setup, monkeypatch, point):
    from maverick import vendor_onboarding

    service, ctx, _, tickets, _ = setup
    row = approved(service, ctx)
    if point == "after_claim":
        save = service._save

        def drift_after_claim(*args, **kwargs):
            saved = save(*args, **kwargs)
            if kwargs.get("stage") == "executing":
                monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "true")
            return saved

        monkeypatch.setattr(service, "_save", drift_after_claim)
    else:
        create = tickets.create

        def drift_after_create(*args, **kwargs):
            receipt = create(*args, **kwargs)
            monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "true")
            return receipt

        monkeypatch.setattr(tickets, "create", drift_after_create)
    with pytest.raises(vendor_onboarding.VendorOnboardingDeploymentError):
        service.execute(ctx, row["id"])
    # No fallback reconciliation/audit write is allowed under the unsupported
    # configuration. Its previously durable claim remains the uncertainty.
    monkeypatch.delenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES")
    persisted = service.get(ctx, row["id"])
    assert persisted["stage"] == "executing"
    assert persisted["revision"] == row["revision"] + 1
    assert persisted["operation"]["attempts"] == 1
    assert persisted["operation"]["receipt"] is None
    assert persisted["work_item"]["technical_effect"] == "indeterminate"
    expected_creates = int(point == "after_create")
    assert tickets.creates == expected_creates
    assert service.execute(ctx, row["id"])["stage"] == "reconciliation_required"
    recovered = service.reconcile(ctx, row["id"])
    assert recovered["work_item"]["technical_effect"] == ("verified" if expected_creates else "indeterminate")
    assert tickets.creates == expected_creates


def test_environment_single_instance_protection_has_canonical_precedence(setup, monkeypatch, tmp_path):
    from maverick import vendor_onboarding

    path = tmp_path / "config.toml"
    path.write_text(path.read_text() + "\n[deployment]\nallow_multiple_control_planes=true\n")
    config.reset_config_cache()
    monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "false")
    assert vendor_onboarding.deployment_readiness()["supported"] is True
    monkeypatch.setenv("MAVERICK_ALLOW_MULTIPLE_CONTROL_PLANES", "invalid")
    assert vendor_onboarding.deployment_readiness()["code"] == "deployment_configuration_unavailable"


@pytest.mark.parametrize("phase", ["intake", "prepared", "approved"])
def test_cancellation_before_dispatch_freezes_intent_without_external_effect(setup, phase):
    svc, ctx, docs, tickets, _ = setup
    row = (svc.intake(ctx, "Cancelled intake", "security-paper", "VEND", "Stop this request")
           if phase == "intake" else reviewed(svc, ctx))
    if phase != "intake":
        row = svc.prepare_action(ctx, row["id"], row["revision"])
    if phase == "approved":
        row = svc.approve_action(
            ctx, row["id"], row["revision"],
            row["operation"]["approval_card"]["binding_sha256"],
        )
    original = row.get("operation")
    cancelled = svc.cancel(ctx, row["id"], row["revision"], "No longer required")
    assert cancelled["stage"] == "cancelled"
    assert cancelled["work_item"]["lifecycle"] == "Cancelled"
    assert cancelled["work_item"]["technical_effect"] == "not_verified"
    assert cancelled["outcome"] is None
    assert cancelled["cancellation"]["dispatch_state_at_cancellation"] == "not_dispatched"
    assert cancelled["cancellation"]["effect_reversal"] == "not_requested"
    assert cancelled["cancellation"]["requested_by"] == ctx.actor
    assert cancelled["cancellation"]["authority"] == ctx.binding()
    assert cancelled["operation"] is None
    if original:
        archived = cancelled["operation_history"][-1]
        assert archived["id"] == original["id"]
        assert archived["approval"] == original["approval"]
        assert archived["invalidated_reason"] == "local_intent_cancelled"
    reopened = VendorOnboardingService(docs, tickets, svc.authorize, clock=svc.clock)
    assert reopened.get(ctx, row["id"])["cancellation"] == cancelled["cancellation"]
    for method in ("collect_evidence", "assess", "prepare_action", "approve_action"):
        with pytest.raises(ValueError, match="cancelled"):
            args = (
                (ctx, row["id"], cancelled["revision"], None)
                if method == "approve_action"
                else (ctx, row["id"], cancelled["revision"])
            )
            getattr(reopened, method)(*args)
    with pytest.raises(ValueError, match="cancelled"):
        reopened.execute(ctx, row["id"])
    repeated = reopened.cancel(ctx, row["id"], cancelled["revision"], "No longer required")
    assert repeated["revision"] == cancelled["revision"]
    assert tickets.creates == 0


def test_cancelled_request_is_not_reopened_as_overdue_attention(setup):
    svc, ctx, _, tickets, _ = setup
    row = svc.intake(
        ctx,
        "Cancelled overdue request",
        "security-paper",
        "VEND",
        "Stop this expired request",
        due_at=NOW - 1,
    )
    cancelled = svc.cancel(ctx, row["id"], row["revision"], "No longer required")

    assert cancelled["stage"] == "cancelled"
    assert cancelled["attention"] == {
        "state": "cancelled",
        "kind": "workflow",
        "requires_attention": False,
        "effective_at": cancelled["cancellation"]["requested_at"],
        "as_of": NOW,
    }
    assert tickets.creates == 0


def test_cancellation_after_lost_receipt_retains_uncertainty_and_read_only_recovery(setup):
    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    tickets.timeout_after_success = True
    row = svc.execute(ctx, row["id"])
    assert tickets.creates == 1 and len(tickets.state) == 1
    operation = row["operation"]
    cancelled = svc.cancel(ctx, row["id"], row["revision"], "Stop while checking delivery")
    assert cancelled["stage"] == "reconciliation_required"
    assert cancelled["work_item"]["lifecycle"] == "Needs reconciliation"
    assert cancelled["work_item"]["technical_effect"] == "indeterminate"
    assert cancelled["operation"] == operation
    assert cancelled["cancellation"]["dispatch_state_at_cancellation"] == "possibly_dispatched"
    assert cancelled["cancellation"]["effect_reversal"] == "not_requested"
    reopened = VendorOnboardingService(docs, tickets, svc.authorize, clock=svc.clock)
    with pytest.raises(ValueError, match="cancelled"):
        reopened.execute(ctx, row["id"])
    reconciled = reopened.reconcile(ctx, row["id"])
    assert reconciled["stage"] == "cancelled"
    assert reconciled["operation"]["state"] == "verified"
    assert reconciled["operation"]["external_confirmation"]["verified"] is True
    assert reconciled["work_item"]["lifecycle"] == "Cancelled"
    assert reconciled["work_item"]["technical_effect"] == "verified"
    assert reconciled["work_item"]["business_outcome"] == "pending"
    assert reconciled["work_item"]["next_action"] == "closed_external_effect_retained"
    assert reconciled["cancellation"] == cancelled["cancellation"]
    assert reconciled["outcome"] is None
    with pytest.raises(ValueError, match="cancelled"):
        reopened.accept(ctx, row["id"], reconciled["revision"], True, "Do not fabricate acceptance")
    assert tickets.creates == 1 and len(tickets.state) == 1


def test_cancellation_preserves_verified_effect_and_rechecks_changed_external_state(setup):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    row = svc.execute(ctx, row["id"])
    cancelled = svc.cancel(ctx, row["id"], row["revision"], "Priorities changed")
    assert cancelled["operation"] == row["operation"]
    assert cancelled["cancellation"]["technical_effect_at_cancellation"] == "verified"
    assert cancelled["work_item"]["technical_effect"] == "verified"
    tickets.verify_unavailable = True
    uncertain = svc.reconcile(ctx, row["id"])
    assert uncertain["stage"] == "reconciliation_required"
    assert uncertain["work_item"]["technical_effect"] == "indeterminate"
    assert uncertain["operation"]["external_confirmation"] == row["operation"]["external_confirmation"]
    assert uncertain["cancellation"] == cancelled["cancellation"]
    assert tickets.creates == 1


def test_cancellation_requires_current_human_authority_and_current_revision(setup):
    svc, ctx, _, tickets, denied = setup
    row = approved(svc, ctx)
    denied.add("action.cancel")
    with pytest.raises(PermissionError):
        svc.cancel(ctx, row["id"], row["revision"], "Denied")
    denied.clear()
    with pytest.raises(PermissionError):
        svc.cancel(replace(ctx, human=False), row["id"], row["revision"], "Worker cannot decide")
    with pytest.raises(KeyError):
        svc.cancel(replace(ctx, tenant="another"), row["id"], row["revision"], "Wrong workspace")
    with pytest.raises(KeyError):
        svc.cancel(replace(ctx, resource_owner="another"), row["id"], row["revision"], "Wrong owner")
    with pytest.raises(RecordConflict):
        svc.cancel(ctx, row["id"], row["revision"] - 1, "Stale review")
    with pytest.raises(ValueError, match="rationale"):
        svc.cancel(ctx, row["id"], row["revision"], " ")
    assert svc.get(ctx, row["id"])["revision"] == row["revision"]
    assert tickets.creates == 0


def test_cancellation_does_not_rewrite_a_customer_decision(setup):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    row = svc.execute(ctx, row["id"])
    row = svc.accept(ctx, row["id"], row["revision"], True, "Accepted before cancellation")
    with pytest.raises(ValueError, match="customer decision"):
        svc.cancel(ctx, row["id"], row["revision"], "Cannot erase acceptance")
    assert svc.get(ctx, row["id"])["outcome"] == row["outcome"]
    assert tickets.creates == 1


def test_cancellation_arriving_during_dispatch_cannot_overwrite_new_effect_state(setup, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    dispatched, release, cancellation_started = Event(), Event(), Event()
    original_create = tickets.create

    def commit_then_wait(*args, **kwargs):
        original_create(*args, **kwargs)
        dispatched.set()
        assert release.wait(10), "test did not release synthetic provider"
        raise TimeoutError("synthetic receipt lost after committed dispatch")

    def cancel_earlier_revision():
        cancellation_started.set()
        return svc.cancel(ctx, row["id"], row["revision"], "Arrived after dispatch")

    monkeypatch.setattr(tickets, "create", commit_then_wait)
    with ThreadPoolExecutor(max_workers=2) as workers:
        executing = workers.submit(svc.execute, ctx, row["id"])
        try:
            assert dispatched.wait(10)
            cancelling = workers.submit(cancel_earlier_revision)
            assert cancellation_started.wait(10)
        finally:
            release.set()
        uncertain = executing.result(timeout=10)
        with pytest.raises(RecordConflict):
            cancelling.result(timeout=10)
    assert uncertain["stage"] == "reconciliation_required"
    cancelled = svc.cancel(ctx, row["id"], uncertain["revision"], "Reviewed uncertain delivery")
    assert cancelled["operation"] == uncertain["operation"]
    assert cancelled["work_item"]["lifecycle"] == "Needs reconciliation"
    assert svc.reconcile(ctx, row["id"])["work_item"]["technical_effect"] == "verified"
    assert tickets.creates == 1 and len(tickets.state) == 1


def test_authority_revoked_after_claim_forces_fresh_review_without_dispatch(
    setup, monkeypatch,
):
    svc, ctx, _, tickets, denied = setup
    row = approved(svc, ctx)
    original = svc._save

    def revoke_after_claim(*args, **kwargs):
        saved = original(*args, **kwargs)
        if kwargs.get("stage") == "executing":
            denied.add("action.execute")
        return saved

    monkeypatch.setattr(svc, "_save", revoke_after_claim)
    with pytest.raises(ApprovalBindingError, match="prepare and review"):
        svc.execute(ctx, row["id"])
    assert tickets.creates == 0
    row = svc.get(ctx, row["id"])
    assert row["stage"] == "review_approved"
    assert row["operation"] is None
    assert row["operation_history"][-1]["state"] == "invalidated"
    assert row["operation_history"][-1]["invalidated_reason"] == (
        "approval_authority_changed"
    )
    assert tickets.creates == 0


def test_cancellation_keeps_durable_audit_receipt_when_audit_delivery_is_unavailable(setup, monkeypatch):
    from maverick import audit

    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    deliveries = []
    monkeypatch.setattr(audit, "record", lambda kind, **fields: deliveries.append(fields) or False)
    row = svc.cancel(ctx, row["id"], row["revision"], "Stop with pending audit delivery")
    assert deliveries[-1]["action"] == "vendor_onboarding_cancelled"
    assert deliveries[-1]["actor"] == ctx.actor
    assert deliveries[-1]["tenant"] == ctx.tenant
    assert deliveries[-1]["record_id"] == row["id"]
    reopened = VendorOnboardingService(docs, tickets, svc.authorize, clock=svc.clock)
    stored = reopened.get(ctx, row["id"])
    pending = stored["_audit_pending"]
    assert any(item["action"] == "vendor_onboarding_cancelled" for item in pending)
    assert stored["cancellation"] == row["cancellation"]
    assert tickets.creates == 0


def test_worker_authority_schema_is_explicit_and_closed(setup):
    _, ctx, *_ = setup
    assert ctx.binding()["authority_schema"] == "lightwork.worker-authority.v1"
    with pytest.raises(ValueError, match="unsupported worker authority schema"):
        replace(ctx, authority_schema="lightwork.worker-authority.v2")


@pytest.mark.parametrize("purpose", [None, "", " \t\n", "x" * 4001],
                         ids=["none", "empty", "whitespace", "oversized"])
def test_invalid_intake_purpose_does_not_register_vendor(setup, purpose):
    from maverick import vendor_management

    svc, ctx, _, tickets, _ = setup
    with pytest.raises(ValueError, match="purpose"):
        svc.intake(ctx, "Rejected intake vendor", "security-paper", "VEND", purpose)
    with tenant_scope(tenant=ctx.tenant):
        assert vendor_management.list_vendors() == []
    assert svc.list(ctx) == []
    assert tickets.creates == 0


def test_journey_contract_is_pinned_and_legacy_records_keep_v1(setup, monkeypatch):
    from maverick import vendor_onboarding

    svc, ctx, *_ = setup
    admitted = svc.intake(ctx, "Synthetic pinned contract", "security-paper", "VEND",
                          "Evaluate a limited support assistant")
    contract = admitted["journey_contract"]
    assert contract == vendor_onboarding.CURRENT_JOURNEY_CONTRACT_REF
    assert admitted["work_item"]["process"] == contract
    assert admitted["work_item"]["objective"] == "Evaluate a limited support assistant"
    assert admitted["work_item"]["supported_deployment"]["topology"] == "single_persistent_application_replica"
    assert admitted["work_item"]["technical_effect"] == "not_verified"
    assert admitted["work_item"]["business_outcome"] == "pending"

    legacy = svc.intake(ctx, "Synthetic legacy contract", "security-paper", "VEND", "Legacy request")
    with tenant_scope(tenant=ctx.tenant):
        stored = vendor_onboarding._CASES.update(
            legacy["id"], lambda value: value.pop("journey_contract"),
            expected_revision=legacy["revision"], action="test_legacy_fixture", actor=ctx.actor,
        )

    future = dict(contract, version=contract["version"] + 1, sha256="f" * 64)
    monkeypatch.setattr(vendor_onboarding, "CURRENT_JOURNEY_CONTRACT_REF", future)
    reopened = svc.get(ctx, admitted["id"])
    assert reopened["journey_contract"] == contract
    assert reopened["work_item"]["process"] == contract

    reopened_legacy = svc.get(ctx, legacy["id"])
    assert reopened_legacy["revision"] == stored["revision"]
    assert reopened_legacy["journey_contract"] == vendor_onboarding.JOURNEY_CONTRACT_V1_REF
    assert reopened_legacy["work_item"]["contract_binding"] == "legacy_schema_default"
    assert next(row for row in svc.list(ctx) if row["id"] == legacy["id"])["work_item"] == reopened_legacy["work_item"]


def test_unknown_case_or_journey_contract_cannot_reach_mutation(setup):
    from maverick import vendor_onboarding

    svc, ctx, _, tickets, _ = setup
    row = svc.intake(ctx, "Synthetic unsupported contract", "security-paper", "VEND", "Rejected mutation")
    with tenant_scope(tenant=ctx.tenant):
        unsupported = vendor_onboarding._CASES.update(
            row["id"], lambda value: value.update(schema="lightwork.vendor-onboarding.v999"),
            expected_revision=row["revision"], action="test_unknown_schema_fixture", actor=ctx.actor,
        )
    with pytest.raises(ValueError, match="unsupported vendor onboarding schema"):
        svc.set_documents(ctx, row["id"], unsupported["revision"], [], [])
    with tenant_scope(tenant=ctx.tenant):
        assert vendor_onboarding._CASES.get(row["id"]) == unsupported
    assert tickets.creates == 0

    with tenant_scope(tenant=ctx.tenant):
        supported_schema = vendor_onboarding._CASES.update(
            row["id"], lambda value: value.update(
                schema="lightwork.vendor-onboarding.v1",
                journey_contract={"id": "supplier-evidence-onboarding", "version": 999, "sha256": "0" * 64},
            ), expected_revision=unsupported["revision"], action="test_unknown_contract_fixture", actor=ctx.actor,
        )
    with pytest.raises(ValueError, match="unsupported journey contract"):
        svc.set_documents(ctx, row["id"], supported_schema["revision"], [], [])
    with tenant_scope(tenant=ctx.tenant):
        assert vendor_onboarding._CASES.get(row["id"]) == supported_schema
    assert tickets.creates == 0


@pytest.mark.parametrize(("stage", "lifecycle", "next_action"), [
    ("intake", "Draft", "obtain_evidence"),
    ("evidence_collected", "Ready", "build_assessment"),
    ("pending_review", "Awaiting approval", "review_assessment"),
    ("review_approved", "Ready", "prepare_action"),
    ("review_rejected", "Failed", "correct_or_close"),
    ("action_pending_approval", "Awaiting approval", "approve_action"),
    ("action_approved", "Ready", "execute_action"),
    ("executing", "Running", "wait_or_reconcile"),
    ("reconciliation_required", "Needs reconciliation", "reconcile"),
    ("execution_completed", "Verified", "accept_or_reject"),
    ("acceptance_reevaluation_required", "Awaiting approval", "start_reevaluation_request"),
    ("accepted", "Accepted", "check_renewal"),
    ("customer_rejected", "Failed", "closed"),
])
def test_every_case_stage_has_an_explicit_work_item_state(setup, stage, lifecycle, next_action):
    svc, ctx, *_ = setup
    row = svc.intake(ctx, "Synthetic state map", "security-paper", "VEND", "Map state")
    operation = {"state": "verified"} if stage in {
        "execution_completed", "acceptance_reevaluation_required", "accepted", "customer_rejected"
    } else None
    outcome = {"accepted": stage == "accepted"} if stage in {"accepted", "customer_rejected"} else None
    projected = svc._present(dict(row, stage=stage, operation=operation, outcome=outcome))
    assert projected["work_item"]["lifecycle"] == lifecycle
    assert projected["work_item"]["next_action"] == next_action


def test_multiple_documents_conflicts_and_secondary_version_guard(setup):
    svc, ctx, docs, tickets, _ = setup
    docs.documents[(ctx.tenant, "policy")] = EvidenceDocument("policy", "1", NOW - 100,
        b"Model provenance is documented with provider and version.")
    docs.documents[(ctx.tenant, "exception")] = EvidenceDocument("exception", "1", NOW - 100,
        b"Model provenance is undisclosed.")
    row = svc.intake(ctx, "Synthetic multiple sources", "", "VEND", "Source comparison",
                     document_ids=["policy", "exception"])
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    assert row["document_ids"] == ["exception", "policy"]
    assert svc.current_evidence_version(ctx, row) == row["evidence"]["version"]
    reordered = dict(row, evidence=dict(row["evidence"], documents=list(reversed(row["evidence"]["documents"]))))
    assert svc.current_evidence_version(ctx, reordered) == row["evidence"]["version"]
    assert svc._evidence_set(list(reversed(row["evidence"]["documents"]))) == svc._evidence_set(row["evidence"]["documents"])
    row = svc.assess(ctx, row["id"], row["revision"])
    assert row["assessment"]["answers"]["aiv_provenance"]["answer"] == "unknown"
    assert "Conflicting" in row["assessment"]["answers"]["aiv_provenance"]["note"]
    row = svc.review(ctx, row["id"], row["revision"], "approved", "Human accepts documented unresolved conflict")
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    docs.documents[(ctx.tenant, "policy")] = replace(docs.documents[(ctx.tenant, "policy")], version="2")
    with pytest.raises(
        vendor_onboarding.VendorOnboardingEvidenceReviewRequired,
        match="prior review cannot be reused",
    ) as rejected:
        svc.approve_action(
            ctx, row["id"], row["revision"],
            row["operation"]["approval_card"]["binding_sha256"],
        )
    assert rejected.value.code == "evidence_reevaluation_required"
    invalidated = svc.get(ctx, row["id"])
    assert invalidated["stage"] == "acceptance_reevaluation_required"
    assert invalidated["operation"] is None
    assert invalidated["operation_history"][-1]["invalidated_reason"] == "evidence_reevaluation_required"
    assert invalidated["review_history"] == row["review_history"]
    check = invalidated["acceptance_evidence_check"]
    assert check["status"] == "reevaluation_required"
    assert [(item["document_id"], item["status"]) for item in check["documents"]] == [
        ("exception", "current"),
        ("policy", "changed"),
    ]
    assert invalidated["exceptions"][-1]["source_references"] == [
        check["documents"][1]["reference"],
    ]
    assert invalidated["exceptions"][-1]["decision_point"] == "action_authorization"
    blocked_revision = invalidated["revision"]
    with pytest.raises(vendor_onboarding.VendorOnboardingEvidenceReviewRequired):
        svc.prepare_action(ctx, row["id"], blocked_revision)
    assert svc.get(ctx, row["id"])["revision"] == blocked_revision

    reevaluation = svc.intake(
        ctx,
        invalidated["vendor_name"],
        invalidated["document_id"],
        invalidated["project"],
        "Reevaluate changed evidence",
        document_ids=invalidated["document_ids"],
        renewal_of=invalidated["id"],
    )
    assert reevaluation["renewal_of"] == invalidated["id"]
    assert reevaluation["review_history"] == []
    reevaluated = svc.collect_evidence(
        ctx, reevaluation["id"], reevaluation["revision"],
    )
    assert reevaluated["assessment"] is None
    assert any(change["change"] == "changed"
               for change in reevaluated["evidence"]["changes"]["documents"])
    assert tickets.creates == 0


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        ("version", "changed"),
        ("bytes", "changed"),
        ("expired", "expired"),
        ("unavailable", "unavailable"),
    ],
)
def test_action_approval_records_source_specific_reevaluation_without_stale_review(
        setup, failure, expected_status):
    svc, ctx, docs, tickets, _ = setup
    now = [NOW]
    svc.clock = lambda: now[0]
    row = reviewed(svc, ctx)
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    prepared_operation = row["operation"]
    source = docs.documents[(ctx.tenant, "security-paper")]
    if failure == "version":
        docs.documents[(ctx.tenant, "security-paper")] = replace(
            source, version="2", modified_at=NOW,
        )
    elif failure == "bytes":
        docs.documents[(ctx.tenant, "security-paper")] = replace(
            source, content=b"Changed bytes with the reviewed source version retained.",
        )
    elif failure == "expired":
        now[0] = row["evidence"]["fresh_until"]
    else:
        docs.unavailable = True

    with pytest.raises(
        vendor_onboarding.VendorOnboardingEvidenceReviewRequired,
        match="approval or acceptance",
    ) as rejected:
        svc.approve_action(
            ctx,
            row["id"],
            row["revision"],
            prepared_operation["approval_card"]["binding_sha256"],
        )
    assert rejected.value.code == "evidence_reevaluation_required"
    current = svc.get(ctx, row["id"])
    assert current["stage"] == "acceptance_reevaluation_required"
    assert current["operation"] is None
    assert current["operation_history"][-1]["id"] == prepared_operation["id"]
    assert current["operation_history"][-1]["state"] == "invalidated"
    assert current["operation_history"][-1]["invalidated_reason"] == "evidence_reevaluation_required"
    assert current["assessment"]["assessment_sha256"] == row["assessment"]["assessment_sha256"]
    assert current["review_history"] == row["review_history"]
    check = current["acceptance_evidence_check"]
    assert check["status"] == "reevaluation_required"
    assert len(check["documents"]) == 1
    assert check["documents"][0]["document_id"] == "security-paper"
    assert check["documents"][0]["status"] == expected_status
    assert current["exceptions"][-1]["decision_point"] == "action_authorization"
    assert current["exceptions"][-1]["source_references"] == [
        check["documents"][0]["reference"],
    ]
    assert current["work_item"]["next_action"] == "start_reevaluation_request"
    assert current["work_item"]["technical_effect"] == "not_verified"
    assert tickets.creates == 0


def test_case_scoped_pdf_upload_clears_approval_and_cannot_inherit_new_upload_time(setup):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    operation = row["operation"]["id"]
    row = svc.upload_document(ctx, row["id"], row["revision"], content=POLICY.read_bytes(),
        name="Synthetic policy.pdf", mime="application/pdf", document_date=NOW - 400 * 86400)
    assert row["assessment"] is None and row["operation"] is None
    assert row["operation_history"][-1]["id"] == operation
    assert row["operation_history"][-1]["state"] == "invalidated"
    uploaded = row["uploads"][0]
    assert uploaded["fresh_until"] < NOW
    assert uploaded["date_basis"] == "uploader_asserted_document_date"
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    assert row["evidence"]["source"] == "evidence_set"
    row = svc.assess(ctx, row["id"], row["revision"])
    row = svc.review(ctx, row["id"], row["revision"], "approved", "Synthetic expired evidence review")
    with pytest.raises(ValueError, match="freshness expired"):
        svc.prepare_action(ctx, row["id"], row["revision"])
    assert tickets.creates == 0
    other = svc.intake(ctx, "Synthetic other upload owner", "", "VEND", "Cannot reuse another case upload")
    with pytest.raises(ValueError, match="belonging to this case"):
        svc.set_documents(ctx, other["id"], other["revision"], [], [uploaded["document_id"]])


def test_reviewed_upload_is_transient_bound_to_actor_revision_and_explicit_consent(setup, monkeypatch):
    svc, ctx, _, tickets, denied = setup
    row = svc.intake(ctx, "Reviewed upload", "", "VEND", "Review file")
    args = dict(content=TEXT, name="Synthetic.txt", mime="text/plain", document_date=NOW - 100)
    preview = svc.preview_upload(ctx, row["id"], row["revision"], **args)
    assert preview["text"] == TEXT.decode() and preview["saved"] is False
    assert svc.get(ctx, row["id"])["revision"] == row["revision"]
    assert svc.get(ctx, row["id"])["uploads"] == []
    commit = dict(args, expires_at=preview["expires_at"], review_digest=preview["review_digest"], confirm=True)
    with pytest.raises(ValueError, match="account or request changed"):
        svc.upload_reviewed(replace(ctx, actor="different-reviewer"), row["id"], row["revision"], **commit)
    with pytest.raises(ValueError, match="Confirm"):
        svc.upload_reviewed(ctx, row["id"], row["revision"], **dict(commit, confirm=False))
    with pytest.raises(ValueError, match="account or request changed"):
        svc.upload_reviewed(ctx, row["id"], row["revision"], **dict(commit, content=b"Changed text"))
    with pytest.raises(ValueError, match="expired"):
        svc.upload_reviewed(ctx, row["id"], row["revision"], **dict(commit, expires_at=NOW))
    with pytest.raises(KeyError):
        svc.upload_reviewed(replace(ctx, tenant="another-customer"), row["id"], row["revision"], **commit)
    denied.add("evidence.upload")
    with pytest.raises(PermissionError):
        svc.upload_reviewed(ctx, row["id"], row["revision"], **commit)
    denied.clear()
    saved = svc.upload_reviewed(ctx, row["id"], row["revision"], **commit)
    assert saved["uploads"][0]["reviewed_by"] == ctx.actor
    assert saved["assessment"] is None and tickets.creates == 0
    with pytest.raises(RecordConflict):
        svc.upload_reviewed(ctx, row["id"], row["revision"], **commit)
    monkeypatch.setattr(config, "vendor_reviewed_uploads_enabled", lambda: False)
    with pytest.raises(PermissionError, match="disabled"):
        svc.preview_upload(ctx, saved["id"], saved["revision"], **args)


def test_pdf_transcription_keeps_source_bytes_separate_and_never_invents_pdf_locations(setup):
    import hashlib

    svc, ctx, _, _, _ = setup
    row = svc.intake(ctx, "Transcribed upload", "", "VEND", "Review unreadable PDF")
    original = b"%PDF-1.4\nunsupported scanned synthetic fixture"
    args = dict(content=original, name="Scan.pdf", mime="application/pdf", document_date=NOW - 100)
    refused = svc.preview_upload(ctx, row["id"], row["revision"], **args)
    assert refused["status"] == "extraction_failed" and refused["can_transcribe"]
    with pytest.raises(ValueError, match="No supported text"):
        svc.upload_reviewed(ctx, row["id"], row["revision"], **args, confirm=True,
                            review_digest=refused["review_digest"], expires_at=refused["expires_at"])
    args["transcription"] = "Model provenance is documented with provider and version."
    preview = svc.preview_upload(ctx, row["id"], row["revision"], **args)
    saved = svc.upload_reviewed(ctx, row["id"], row["revision"], **args, confirm=True,
                               review_digest=preview["review_digest"], expires_at=preview["expires_at"])
    upload = saved["uploads"][0]
    citation = upload["extracted"]["answers"]["aiv_provenance"]["citations"][0]
    assert citation["document_sha256"] == hashlib.sha256(original).hexdigest()
    assert citation["extracted_text_sha256"] == hashlib.sha256(args["transcription"].encode()).hexdigest()
    assert citation["text_origin"] == "human_transcription" and citation["transcription_paragraph"] == 1
    assert "pages" not in citation
    assert upload["extraction"]["method"] == "human_transcription"


def test_uploaded_only_case_preserves_evidence_for_renewal_and_rechecks_snapshot(setup, monkeypatch):
    from maverick.vendor_evidence_evolution import EvidenceRenewalEvolution

    svc, ctx, _, tickets, _ = setup
    def forbidden_drive(*args, **kwargs):
        raise PermissionError("No Drive connection enrolled for uploaded evidence")
    monkeypatch.setattr(svc.documents, "authority_version", forbidden_drive)
    monkeypatch.setattr(svc.documents, "fetch", forbidden_drive)
    monkeypatch.setattr(svc.documents, "head", forbidden_drive)
    row = svc.intake(ctx, "Synthetic uploaded policy", "", "VEND", "Upload without Drive source")
    row = svc.upload_document(ctx, row["id"], row["revision"], content=POLICY.read_bytes(),
        name="Synthetic policy.pdf", mime="application/pdf", document_date=NOW - 100)
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    row = svc.assess(ctx, row["id"], row["revision"])
    row = svc.review(ctx, row["id"], row["revision"], "approved", "Synthetic reviewer accepts cited assertions")
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    assert row["operation"]["preconditions"]["document_credential_version"] == "not_applicable:retained_uploads"
    row = svc.approve_action(
        ctx, row["id"], row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )
    row = svc.execute(ctx, row["id"])
    row = svc.accept(ctx, row["id"], row["revision"], True, "Synthetic acceptance")
    evolution = EvidenceRenewalEvolution(svc.authorize, clock=svc.clock)
    observed = evolution.observe_case(ctx, svc, row["id"], "fresh", rationale="Check uploaded snapshot provenance")
    assert observed["inputs"]["source_version"] == row["evidence"]["version"]
    renewal = svc.intake(ctx, row["vendor_name"], "", "VEND", "Renewal", renewal_of=row["id"])
    renewal = svc.collect_evidence(ctx, renewal["id"], renewal["revision"])
    assert renewal["uploads"][0]["modified_at"] == row["uploads"][0]["modified_at"]
    assert renewal["evidence"]["changes"]["documents"][0]["change"] == "unchanged"
    upload_id = renewal["uploads"][0]["document_id"]
    renewal = svc.set_documents(ctx, renewal["id"], renewal["revision"], [], [])
    renewal = svc.upload_document(ctx, renewal["id"], renewal["revision"],
        content=b"Model provenance is undisclosed.", name="Changed statement.txt", mime="text/plain", document_date=NOW)
    renewal = svc.collect_evidence(ctx, renewal["id"], renewal["revision"])
    changes = renewal["evidence"]["changes"]["documents"]
    assert {item["change"] for item in changes} == {"added", "removed"}
    assert next(item for item in changes if item["document_id"] == upload_id)["before_version"] == "1"
    assert svc.get(ctx, row["id"]) == row
    assert tickets.creates == 1


def test_failed_document_blocks_partial_assessment_and_selection_is_bounded(setup):
    svc, ctx, *_ = setup
    row = svc.intake(ctx, "Synthetic incomplete packet", "", "VEND", "Missing secondary file",
                     document_ids=["security-paper", "missing"])
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    assert {item["status"] for item in row["evidence"]["documents"]} == {"missing", "available"}
    with pytest.raises(ValueError, match="available"):
        svc.assess(ctx, row["id"], row["revision"])
    with pytest.raises(ValueError, match="once"):
        svc.set_documents(ctx, row["id"], row["revision"], ["duplicate", "duplicate"], [])
    with pytest.raises(ValueError, match="at most 8"):
        svc.set_documents(ctx, row["id"], row["revision"], [str(i) for i in range(9)], [])


def test_complete_workflow_keeps_execution_acceptance_and_release_separate(setup):
    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    row = svc.execute(ctx, row["id"])
    assert row["stage"] == "execution_completed"
    assert row["operation"]["external_confirmation"]["verified"] is True
    assert row["outcome"] is None
    assert row["work_item"]["lifecycle"] == "Verified"
    assert row["work_item"]["technical_effect"] == "verified"
    assert row["work_item"]["business_outcome"] == "pending"
    duplicate = svc.execute(ctx, row["id"])
    assert duplicate["revision"] == row["revision"]
    assert tickets.creates == 1
    row = svc.accept(ctx, row["id"], row["revision"], True, "Accepted by procurement")
    assert row["outcome"]["accepted"] is True
    assert row["outcome"]["released"] is False
    assert row["metrics"]["human_review_seconds"] == 12.5
    assert row["outcome"]["execution_cost_usd"] == 0.0
    assert row["outcome"]["journey_contract"] == row["journey_contract"]
    assert row["work_item"]["lifecycle"] == "Accepted"
    assert row["work_item"]["business_outcome"] == "accepted"
    renewal = svc.intake(ctx, "Synthetic Acme AI", "security-paper", "VEND", "Annual renewal",
                         renewal_of=row["id"])
    assert renewal["renewal_of"] == row["id"]
    assert renewal["vendor_id"] == row["vendor_id"]
    assert renewal["outcome"] is None


def test_expired_acceptance_opens_linked_renewal_with_fresh_review_and_approval(setup):
    svc, ctx, docs, tickets, _ = setup
    clock = [NOW]
    svc.clock = lambda: clock[0]
    accepted = approved(svc, ctx)
    accepted = svc.execute(ctx, accepted["id"])
    accepted = svc.accept(
        ctx,
        accepted["id"],
        accepted["revision"],
        True,
        "Accepted against the reviewed current result",
    )
    original_binding = accepted["operation"]["approval_card"]["binding_sha256"]
    clock[0] = accepted["outcome"]["renewal_due_at"] + 1
    source = docs.documents[(ctx.tenant, "security-paper")]
    docs.documents[(ctx.tenant, "security-paper")] = replace(
        source,
        version="2",
        modified_at=clock[0],
        content=source.content + b" Annual evidence refresh.",
    )

    frozen_parent = copy.deepcopy(svc.get(ctx, accepted["id"]))
    assert frozen_parent["attention"] == {
        "state": "overdue",
        "kind": "evidence_renewal",
        "requires_attention": True,
        "effective_at": accepted["outcome"]["renewal_due_at"],
        "as_of": clock[0],
    }
    renewal_page = svc.list_page(ctx, view="renewal")
    assert [item["id"] for item in renewal_page["cases"]] == [accepted["id"]]
    assert renewal_page["page_counts"]["admitted"] == 1
    assert renewal_page["page_counts"]["renewal_attention"] == 1

    renewal = svc.intake(
        ctx,
        accepted["vendor_name"],
        "security-paper",
        accepted["project"],
        "Annual evidence renewal",
        renewal_of=accepted["id"],
    )
    assert renewal["renewal_of"] == accepted["id"]
    assert renewal["work_item"]["parent_work_item_id"] == accepted["id"]
    assert renewal["assessment"] is None
    assert renewal["review_history"] == []
    assert renewal["operation"] is None
    assert renewal["outcome"] is None
    renewal_items = svc.list_page(ctx, view="renewal")["cases"]
    assert {item["id"] for item in renewal_items} == {accepted["id"], renewal["id"]}

    renewal = svc.collect_evidence(ctx, renewal["id"], renewal["revision"])
    evidence_change = renewal["evidence"]["changes"]["documents"]
    assert len(evidence_change) == 1
    assert evidence_change[0]["source"] == "gdrive"
    assert evidence_change[0]["document_id"] == "security-paper"
    assert evidence_change[0]["change"] == "changed"
    assert evidence_change[0]["before_version"] == "1"
    assert evidence_change[0]["after_version"] == "2"
    renewal = svc.assess(ctx, renewal["id"], renewal["revision"])
    renewal = svc.review(
        ctx,
        renewal["id"],
        renewal["revision"],
        "approved",
        "Reviewed the renewed source and its changed evidence",
    )
    renewal = svc.prepare_action(ctx, renewal["id"], renewal["revision"])
    assert renewal["operation"]["approval_card"]["binding_sha256"] != original_binding
    assert renewal["operation"]["state"] == "prepared"
    renewal = svc.approve_action(
        ctx,
        renewal["id"],
        renewal["revision"],
        renewal["operation"]["approval_card"]["binding_sha256"],
    )
    assert renewal["operation"]["state"] == "approved"
    assert renewal["operation"]["approval"]["reviewer"] == ctx.actor
    assert svc.get(ctx, accepted["id"]) == frozen_parent
    assert tickets.creates == 1


def test_business_rejection_retains_admission_rationale_and_verified_effect(setup):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    row = svc.execute(ctx, row["id"])
    rejected = svc.accept(
        ctx,
        row["id"],
        row["revision"],
        False,
        "The verified task does not satisfy the current procurement need",
    )

    assert rejected["stage"] == "customer_rejected"
    assert rejected["outcome"]["accepted"] is False
    assert rejected["outcome"]["rationale"] == (
        "The verified task does not satisfy the current procurement need"
    )
    assert rejected["outcome"]["reviewer"] == ctx.actor
    assert rejected["outcome"]["decided_at"] == NOW
    assert rejected["work_item"]["technical_effect"] == "verified"
    assert rejected["work_item"]["business_outcome"] == "rejected"
    assert rejected["attention"]["state"] == "rejected"
    assert rejected["attention"]["requires_attention"] is False

    page = svc.list_page(ctx, view="all")
    assert [item["id"] for item in page["cases"]] == [rejected["id"]]
    assert page["page_counts"] == {
        "admitted": 1,
        "accepted": 0,
        "rejected": 1,
        "needs_reconciliation": 0,
        "renewal_attention": 0,
    }
    assert page["cases"][0]["work_item"]["technical_effect"] == "verified"
    assert page["cases"][0]["work_item"]["business_outcome"] == "rejected"
    assert tickets.creates == 1


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        ("version", "changed"),
        ("bytes", "changed"),
        ("expired", "expired"),
        ("unavailable", "unavailable"),
    ],
)
def test_acceptance_rechecks_every_reviewed_source_without_reusing_stale_review(
        setup, failure, expected_status):
    svc, ctx, docs, tickets, _ = setup
    now = [NOW]
    svc.clock = lambda: now[0]
    row = approved(svc, ctx)
    row = svc.execute(ctx, row["id"])
    reviewed_assessment = row["assessment"]["assessment_sha256"]
    reviewed_history = list(row["review_history"])
    source = docs.documents[(ctx.tenant, "security-paper")]
    if failure == "version":
        docs.documents[(ctx.tenant, "security-paper")] = replace(
            source, version="2", modified_at=NOW,
        )
    elif failure == "bytes":
        docs.documents[(ctx.tenant, "security-paper")] = replace(
            source, content=b"Source bytes changed without an honest version increment.",
        )
    elif failure == "expired":
        now[0] = source.modified_at + 365 * 86400
    else:
        docs.unavailable = True

    with pytest.raises(
        vendor_onboarding.VendorOnboardingEvidenceReviewRequired,
        match="start a reevaluation",
    ) as rejected:
        svc.accept(ctx, row["id"], row["revision"], True, "Accept stale evidence")
    assert rejected.value.code == "evidence_reevaluation_required"
    current = svc.get(ctx, row["id"])
    assert current["stage"] == "acceptance_reevaluation_required"
    assert current["operation"]["state"] == "verified"
    assert current["operation"]["id"] == row["operation"]["id"]
    assert current["outcome"] is None
    assert current["assessment"]["assessment_sha256"] == reviewed_assessment
    assert current["review_history"] == reviewed_history
    assert current["acceptance_evidence_check"]["status"] == "reevaluation_required"
    assert len(current["acceptance_evidence_check"]["documents"]) == 1
    assert current["acceptance_evidence_check"]["documents"][0]["status"] == expected_status
    assert current["acceptance_evidence_check"]["documents"][0]["document_id"] == "security-paper"
    assert current["work_item"]["technical_effect"] == "verified"
    assert current["work_item"]["business_outcome"] == "pending"
    assert tickets.creates == 1

    blocked_revision = current["revision"]
    with pytest.raises(vendor_onboarding.VendorOnboardingEvidenceReviewRequired):
        svc.accept(ctx, current["id"], current["revision"], True, "Retry old review")
    assert svc.get(ctx, current["id"])["revision"] == blocked_revision
    reevaluation = svc.intake(
        ctx,
        current["vendor_name"],
        "security-paper",
        "VEND",
        "Reevaluate current evidence",
        renewal_of=current["id"],
    )
    assert reevaluation["renewal_of"] == current["id"]
    assert reevaluation["assessment"] is None
    assert reevaluation["review_history"] == []
    assert tickets.creates == 1


def test_evidence_export_withholds_lost_source_and_redacts_human_secret(setup, monkeypatch):
    svc, ctx, docs, tickets, denied = setup
    private_id = "private-source-never-export"
    private_content = (
        b"WITHHELD-SOURCE-CONTENT. Model provenance is documented with provider and version."
    )
    docs.documents[(ctx.tenant, private_id)] = EvidenceDocument(
        private_id, "private-v1", NOW - 100, private_content,
    )
    row = svc.intake(
        ctx,
        "Synthetic export vendor",
        "",
        "VEND",
        "Review a two-source packet",
        document_ids=["security-paper", private_id],
    )
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    row = svc.assess(ctx, row["id"], row["revision"])
    row = svc.review(
        ctx, row["id"], row["revision"], "approved",
        "Reviewed every cited claim and retained each unsupported answer as unknown",
    )
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    row = svc.approve_action(
        ctx, row["id"], row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )
    row = svc.execute(ctx, row["id"])
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"  # pragma: allowlist secret
    row = svc.accept(
        ctx, row["id"], row["revision"], True,
        f"Accepted reviewed limits; API_TOKEN={secret}",
    )

    fetch = docs.fetch

    def partially_denied(context, document_id):
        if document_id == private_id:
            raise PermissionError("private source credential value must not escape")
        return fetch(context, document_id)

    monkeypatch.setattr(docs, "fetch", partially_denied)
    preview = svc.preview_evidence_export(ctx, row["id"], row["revision"])
    assert preview["schema"] == vendor_onboarding.EVIDENCE_EXPORT_SCHEMA
    assert preview["manifest"]["included_count"] == 1
    assert preview["manifest"]["withheld_count"] == 1
    assert preview["manifest"]["complete"] is False
    withheld = preview["manifest"]["withheld"][0]
    assert set(withheld) == {"reference", "dependency_type", "disposition", "reason"}
    assert withheld["reference"].startswith("EVR-")
    assert withheld["reason"] == "current_source_access_unavailable"
    serialized = json.dumps(preview, sort_keys=True)
    assert private_id not in serialized
    assert private_content.decode() not in serialized
    assert secret not in serialized
    assert "private source credential" not in serialized
    assert "[REDACTED:" in serialized

    claim_ids = {claim["claim_id"] for claim in preview["claims"]}
    assert claim_ids == set(row["assessment"]["answers"])
    included_refs = {item["reference"] for item in preview["manifest"]["included"]}
    withheld_refs = {item["reference"] for item in preview["manifest"]["withheld"]}
    for claim in preview["claims"]:
        assert set(claim["evidence_refs"]) <= included_refs
        assert set(claim["withheld_evidence_refs"]) <= withheld_refs
        assert claim["evidence_refs"] or claim["review_justification"]
        assert {citation["evidence_ref"] for citation in claim["citations"]} <= included_refs

    downloaded = svc.download_evidence_export(
        ctx,
        row["id"],
        row["revision"],
        confirm=True,
        expected_export_sha256=preview["binding_sha256"],
    )
    assert downloaded["binding_sha256"] == preview["binding_sha256"]
    monkeypatch.setattr(docs, "fetch", fetch)
    with pytest.raises(ValueError, match="changed; preview"):
        svc.download_evidence_export(
            ctx,
            row["id"],
            row["revision"],
            confirm=True,
            expected_export_sha256=preview["binding_sha256"],
        )
    denied.add("evidence.export")
    with pytest.raises(PermissionError, match="evidence.export"):
        svc.preview_evidence_export(ctx, row["id"], row["revision"])
    assert tickets.creates == 1


def test_model_is_never_human_approval(setup):
    svc, ctx, *_ = setup
    row = svc.intake(ctx, "Synthetic Acme AI", "security-paper", "VEND", "Synthetic request")
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    row = svc.assess(ctx, row["id"], row["revision"])
    with pytest.raises(PermissionError, match="human"):
        svc.review(replace(ctx, human=False), row["id"], row["revision"], "approved", "Model says approve")
    with pytest.raises(ValueError, match="human-reviewed"):
        svc.prepare_action(ctx, row["id"], row["revision"])


@pytest.mark.parametrize("state", ["missing", "empty", "corrupted", "unavailable"])
def test_evidence_absence_and_failure_are_not_valid_empty_assessments(setup, state):
    svc, ctx, docs, *_ = setup
    if state == "missing":
        docs.documents.clear()
    elif state == "unavailable":
        docs.unavailable = True
    else:
        docs.documents[(ctx.tenant, "security-paper")] = EvidenceDocument(
            "security-paper", "1", NOW - 10, b"" if state == "empty" else b"\xff",
        )
    row = svc.intake(ctx, "Synthetic Acme AI", "security-paper", "VEND", "Synthetic request")
    row = svc.collect_evidence(ctx, row["id"], row["revision"])
    assert row["evidence"]["status"] == state
    with pytest.raises(ValueError, match="available"):
        svc.assess(ctx, row["id"], row["revision"])


@pytest.mark.parametrize(
    "change",
    [
        "source", "credential", "permission", "actor", "owner", "role",
        "role_policy", "budget", "workspace", "expired",
    ],
)
def test_approval_preconditions_and_authority_rechecked_before_effect(setup, change):
    svc, ctx, docs, tickets, denied = setup
    row = approved(svc, ctx)
    if change == "source":
        docs.documents[(ctx.tenant, "security-paper")] = EvidenceDocument("security-paper", "2", NOW, TEXT)
    elif change == "credential":
        tickets.version = "revoked-and-replaced"
    elif change == "permission":
        denied.add("action.execute")
    elif change == "actor":
        ctx = replace(ctx, actor="other-human")
    elif change == "owner":
        ctx = replace(ctx, resource_owner="other-owner")
    elif change == "role":
        ctx = replace(ctx, authorization_role="admin")
    elif change == "role_policy":
        ctx = replace(ctx, authorization_policy="operator-policy-v2")
    elif change == "budget":
        ctx = replace(ctx, budget_authority="tenant-budget-v2")
    elif change == "workspace":
        ctx = replace(ctx, workspace_authority="workspace-generation-2")
    else:
        svc.clock = lambda: NOW + 4000
    with pytest.raises((ValueError, PermissionError, KeyError)):
        svc.execute(ctx, row["id"])
    assert tickets.creates == 0


def test_timeout_after_success_is_reconciled_without_second_create(setup):
    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    tickets.timeout_after_success = True
    row = svc.execute(ctx, row["id"])
    assert row["stage"] == "reconciliation_required"
    assert tickets.creates == 1
    # A new service object sees durable intent and an independent provider state.
    restarted = VendorOnboardingService(docs, tickets, svc.authorize, clock=svc.clock)
    restarted.execute(ctx, row["id"])
    row = restarted.reconcile(ctx, row["id"])
    assert row["operation"]["state"] == "verified"
    assert row["operation"]["external_confirmation"]["reconciled"] is True
    assert tickets.creates == 1


def test_receipt_storage_failure_and_restart_do_not_retry_effect(setup, monkeypatch):
    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    save = svc._save

    def fail_after_effect(*args, **kwargs):
        if tickets.creates:
            raise OSError("synthetic disk outage")
        return save(*args, **kwargs)

    monkeypatch.setattr(svc, "_save", fail_after_effect)
    with pytest.raises(OSError):
        svc.execute(ctx, row["id"])
    assert tickets.creates == 1
    restarted = VendorOnboardingService(docs, tickets, svc.authorize, clock=svc.clock)
    assert restarted.get(ctx, row["id"])["operation"]["state"] == "executing"
    row = restarted.reconcile(ctx, row["id"])
    assert row["operation"]["state"] == "verified"
    assert tickets.creates == 1


def test_unavailable_verifier_and_changed_downstream_state_do_not_accept(setup):
    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    tickets.verify_unavailable = True
    row = svc.execute(ctx, row["id"])
    assert row["operation"]["state"] == "reconciliation_required"
    with pytest.raises(ValueError, match="verified external"):
        svc.accept(ctx, row["id"], row["revision"], True, "Must not accept")
    tickets.verify_unavailable = False
    row = svc.reconcile(ctx, row["id"])
    key = row["operation"]["external_confirmation"]["key"]
    tickets.state[(ctx.tenant, key)]["payload"]["summary"] = "changed by someone else"
    with pytest.raises(ValueError, match="external state changed"):
        svc.accept(ctx, row["id"], row["revision"], True, "Must not accept")


def test_malformed_verification_receipt_never_becomes_a_verified_effect(setup, monkeypatch):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    monkeypatch.setattr(tickets, "verify", lambda *args, **kwargs: {"verified": True})
    row = svc.execute(ctx, row["id"])
    assert row["stage"] == "reconciliation_required"
    assert row["operation"]["state"] == "reconciliation_required"
    assert row["operation"]["external_confirmation"] is None
    assert row["outcome"] is None
    assert tickets.creates == 1


def test_corrections_link_superseded_evidence_and_invalidate_action(setup):
    svc, ctx, docs, tickets, _ = setup
    row = approved(svc, ctx)
    original_id = row["assessment"]["id"]
    qid = next(iter(row["assessment"]["answers"]))
    row = svc.review(ctx, row["id"], row["revision"], "approved", "Corrected reviewer interpretation",
                     corrections={qid: {"answer": "unknown", "note": "Needs confirmation"}})
    assert row["assessment"]["id"] != original_id
    assert row["review_history"][-1]["supersedes"]["id"] == original_id
    assert row["operation"] is None
    assert row["operation_history"][-1]["state"] == "invalidated"
    with pytest.raises(ValueError, match="approved operation"):
        svc.execute(ctx, row["id"])
    assert tickets.creates == 0


def test_tenant_scope_ignores_ambient_and_never_pools_customer_data(setup, monkeypatch):
    from maverick import audit

    svc, ctx, docs, tickets, _ = setup
    events = []
    monkeypatch.setattr(audit, "record", lambda kind, **payload: events.append((kind, payload)) or True)
    with tenant_scope(tenant="ambient-untrusted"):
        row = approved(svc, ctx)
    other = replace(ctx, tenant="customer-b")
    assert svc.list(other) == []
    with pytest.raises(KeyError):
        svc.get(other, row["id"])
    assert tickets.find(other, row["operation"]["payload"]) == []
    with pytest.raises(FileNotFoundError):
        docs.fetch(other, "security-paper")
    assert any(
        kind == audit.EventKind.CAPABILITY_DENIED
        and payload["reason"] == "resource_scope_mismatch"
        and payload["tenant"] == "customer-b"
        and payload["resource_sha256"] == digest(row["id"])
        for kind, payload in events
    )


@pytest.mark.parametrize("expired", [False, True])
def test_approval_from_another_intent_cannot_be_replayed(setup, expired):
    from maverick import vendor_onboarding

    svc, ctx, _, tickets, _ = setup
    first = approved(svc, ctx)
    second = approved(svc, ctx)
    replayed = dict(second["operation"], approval=dict(first["operation"]["approval"]))
    if expired:
        svc.clock = lambda: second["operation"]["expires_at"] + 1
    with tenant_scope(tenant=ctx.tenant):
        vendor_onboarding._CASES.update(
            second["id"],
            lambda value: value.update(operation=replayed),
            expected_revision=second["revision"],
            action="test_cross_intent_approval_replay",
            actor=ctx.actor,
        )
    with pytest.raises(PermissionError, match="(?i)exact operation"):
        svc.execute(ctx, second["id"])
    assert tickets.creates == 0


def test_optional_shield_absence_keeps_kernel_authority_enforced(setup, monkeypatch):
    import builtins

    svc, ctx, _, tickets, denied = setup
    original_import = builtins.__import__

    def without_shield(name, *args, **kwargs):
        if name == "maverick_shield" or name.startswith("maverick_shield."):
            raise ImportError("optional shield is not installed")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_shield)
    row = approved(svc, ctx)
    row = svc.execute(ctx, row["id"])
    assert row["operation"]["state"] == "verified"
    assert tickets.creates == 1
    blocked = approved(svc, ctx)
    denied.add("action.execute")
    with pytest.raises(PermissionError, match="action.execute"):
        svc.execute(ctx, blocked["id"])
    assert tickets.creates == 1


@pytest.mark.parametrize(
    ("outcome", "expected_reason", "match_count"),
    [
        ("no_match", "no_matching_effect_observed", 0),
        ("multiple_matches", "multiple_matching_effects_observed", 2),
        ("access_unavailable", "current_connection_access_unavailable", None),
    ],
)
def test_uncertain_reconciliation_records_safe_observations_without_replaying_write(
    setup, monkeypatch, outcome, expected_reason, match_count,
):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)

    def lose_create_receipt(bound_ctx, payload, operation_id, *, expected_credential_version=None):
        tickets._credential(expected_credential_version)
        tickets.creates += 1
        raise TimeoutError("synthetic result unavailable before a receipt was retained")

    monkeypatch.setattr(tickets, "create", lose_create_receipt)
    row = svc.execute(ctx, row["id"])
    assert row["stage"] == "reconciliation_required"
    assert tickets.creates == 1
    payload = row["operation"]["payload"]
    if outcome == "multiple_matches":
        tickets.state[(ctx.tenant, "VEND-1")] = {"payload": payload, "version": "1"}
        tickets.state[(ctx.tenant, "VEND-2")] = {"payload": payload, "version": "1"}
    elif outcome == "access_unavailable":
        tickets.version = "synthetic-jira-credential-v2"

    row = svc.reconcile(ctx, row["id"])
    assert row["stage"] == "reconciliation_required"
    assert row["operation"]["last_reconciliation"]["outcome"] == outcome
    assert row["reconciliation_history"][-1]["read_only"] is True
    assert row["reconciliation_history"][-1]["checked_by"] == ctx.actor
    assert tickets.creates == 1
    assert svc.execute(ctx, row["id"])["stage"] == "reconciliation_required"
    assert tickets.creates == 1

    summary = svc.list_page(ctx, limit=10, view="unresolved")["cases"][0]["reconciliation"]
    assert summary["uncertainty"] == {
        "state": "unresolved",
        "reason": expected_reason,
        "explanation": summary["uncertainty"]["explanation"],
    }
    assert summary["safe_next_check"]["mode"] == "read_only"
    assert summary["responsible_operator"]["principal"] == ctx.actor
    assert summary["resolution"]["automatic_compensation_supported"] is False
    assert summary["resolution"]["unreviewed_replacement_allowed"] is False
    assert summary["resolution"]["requires_separate_review"] is True
    readback = next(
        observation for observation in summary["known_observations"]
        if observation["kind"] == "authoritative_readback"
    )
    assert readback["state"] == outcome
    if match_count is None:
        assert "match_count" not in readback
    else:
        assert readback["match_count"] == match_count


def test_bounded_provider_continuation_records_a_truthful_match_lower_bound(
    setup, monkeypatch,
):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    tickets.timeout_after_success = True
    uncertain = svc.execute(ctx, row["id"])
    assert uncertain["stage"] == "reconciliation_required"

    calls = []

    def multiple(*args, **kwargs):
        calls.append("find")
        raise ProviderMultipleMatches(minimum=3)

    monkeypatch.setattr(tickets, "find", multiple)
    result = svc.reconcile(ctx, row["id"])
    observation = result["operation"]["last_reconciliation"]
    assert observation["outcome"] == "multiple_matches"
    assert observation["match_count_lower_bound"] == 3
    assert "match_count" not in observation
    summary = result["reconciliation"]
    readback = next(
        item for item in summary["known_observations"]
        if item["kind"] == "authoritative_readback"
    )
    assert readback["state"] == "multiple_matches"
    assert readback["match_count_lower_bound"] == 3
    assert "match_count" not in readback
    assert summary["safe_next_check"]["kind"] == "review_ambiguity"
    assert calls == ["find"]
    assert tickets.creates == 1


@pytest.mark.parametrize("loss", ["permission", "credential"])
def test_current_authority_loss_projects_an_access_path_without_provider_reads(
    setup, monkeypatch, loss,
):
    svc, ctx, _, tickets, denied = setup
    row = approved(svc, ctx)
    tickets.timeout_after_success = True
    uncertain = svc.execute(ctx, row["id"])
    assert uncertain["stage"] == "reconciliation_required"
    if loss == "permission":
        denied.add("action.reconcile")
    else:
        tickets.version = "synthetic-jira-credential-v2"

    provider_calls = []
    monkeypatch.setattr(
        tickets, "find", lambda *args, **kwargs: provider_calls.append("find") or [],
    )
    monkeypatch.setattr(
        tickets, "verify", lambda *args, **kwargs: provider_calls.append("verify") or {},
    )
    projected = svc.get(ctx, row["id"])
    queued = svc.list_page(ctx, limit=10, view="unresolved")["cases"][0]
    for visible in (projected, queued):
        summary = visible["reconciliation"]
        assert summary["uncertainty"]["reason"] == "current_connection_access_unavailable"
        assert summary["safe_next_check"] == {
            "kind": "restore_access",
            "label": "Restore the original Jira connection access, then check status",
            "mode": "read_only",
            "href": "/connections",
        }
    assert provider_calls == []
    assert tickets.creates == 1
    if loss == "permission":
        with pytest.raises(PermissionError, match="action.reconcile"):
            svc.reconcile(ctx, row["id"])
        assert provider_calls == []
        assert tickets.creates == 1


def test_successful_reconciliation_retains_read_only_observation_history(setup):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    tickets.timeout_after_success = True
    row = svc.execute(ctx, row["id"])
    assert row["operation"]["state"] == "reconciliation_required"
    row = svc.reconcile(ctx, row["id"])
    assert row["operation"]["state"] == "verified"
    assert row["operation"]["last_reconciliation"]["outcome"] == "exact_match_verified"
    assert row["reconciliation_history"][-1] == row["operation"]["last_reconciliation"]
    assert row["reconciliation_history"][-1]["match_count"] == 1
    assert row["reconciliation_history"][-1]["read_only"] is True
    assert tickets.creates == 1


def test_credential_change_after_create_stays_ambiguous_and_is_not_retried(
    setup, monkeypatch,
):
    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)

    def changed_before_readback(*args, **kwargs):
        raise CredentialAuthorityChanged(
            "credential rotated after the provider accepted the create"
        )

    monkeypatch.setattr(tickets, "verify", changed_before_readback)
    uncertain = svc.execute(ctx, row["id"])
    assert tickets.creates == 1
    assert uncertain["stage"] == "reconciliation_required"
    assert uncertain["operation"]["state"] == "reconciliation_required"
    assert uncertain["operation"]["receipt"]["key"] == "VEND-1"
    assert uncertain["operation"]["failure_kind"] == "CredentialAuthorityChanged"
    assert uncertain["operation_history"] == []

    still_uncertain = svc.execute(ctx, row["id"])
    assert still_uncertain["stage"] == "reconciliation_required"
    assert tickets.creates == 1


def test_legacy_approval_without_role_or_budget_binding_requires_new_review(setup):
    from maverick import vendor_onboarding

    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    legacy = dict(row["operation"], context=dict(row["operation"]["context"]))
    legacy["context"].pop("authorization_role")
    legacy["context"].pop("authorization_policy")
    legacy["context"].pop("budget_authority")
    legacy["context"].pop("workspace_authority")
    legacy["context"].pop("authority_schema")
    legacy["approval"] = dict(
        legacy["approval"], binding_sha256=operation_binding(legacy),
    )
    with tenant_scope(tenant=ctx.tenant):
        vendor_onboarding._CASES.update(
            row["id"],
            lambda value: value.update(operation=legacy),
            expected_revision=row["revision"],
            action="test_legacy_unbound_operation",
            actor=ctx.actor,
        )
    with pytest.raises(PermissionError, match="(?i)authority changed"):
        svc.execute(ctx, row["id"])
    assert tickets.creates == 0


def test_stale_revision_cannot_overwrite_review(setup):
    svc, ctx, _, tickets, _ = setup
    row = reviewed(svc, ctx)
    assert row["revision"] == 4
    prepared = svc.prepare_action(ctx, row["id"], row["revision"])
    assert prepared["revision"] == 5
    question = next(iter(row["assessment"]["answers"]))
    with pytest.raises(RecordConflict):
        svc.review(ctx, row["id"], row["revision"], "approved", "Conflicting correction",
                   corrections={question: {"answer": "unknown", "note": "Stale writer"}})
    assert svc.get(ctx, row["id"])["revision"] == 5
    assert tickets.creates == 0


@pytest.mark.parametrize("change", ["legacy", "role", "budget", "workspace", "reviewer"])
def test_attempted_effect_can_be_read_back_with_current_authority(setup, change):
    from maverick import vendor_onboarding

    svc, ctx, _, tickets, _ = setup
    row = approved(svc, ctx)
    tickets.timeout_after_success = True
    row = svc.execute(ctx, row["id"])
    operation = row["operation"]
    if change == "legacy":
        operation = dict(operation, context={
            key: value for key, value in operation["context"].items()
            if key not in {"authorization_role", "authorization_policy", "budget_authority",
                           "workspace_authority", "authority_schema"}
        })
        operation["approval"] = dict(operation["approval"],
                                     binding_sha256=operation_binding(operation))
        with tenant_scope(tenant=ctx.tenant):
            vendor_onboarding._CASES.update(
                row["id"], lambda value: value.update(operation=operation),
                expected_revision=row["revision"], action="legacy_effect_fixture", actor=ctx.actor,
            )
    elif change == "role":
        ctx = replace(ctx, authorization_role="admin", authorization_policy="admin-policy")
    elif change == "budget":
        ctx = replace(ctx, budget_authority="revised-budget")
    elif change == "workspace":
        ctx = replace(ctx, workspace_authority="returned-to-workspace")
    else:
        ctx = replace(ctx, actor="second-reviewer@example.test")
    svc.authorize = lambda candidate, *_: candidate.binding() == ctx.binding()
    recovered = svc.reconcile(ctx, row["id"])
    assert recovered["operation"]["state"] == "verified"
    accepted = svc.accept(ctx, row["id"], recovered["revision"], True, "Checked existing result")
    assert accepted["outcome"]["reviewer"] == ctx.actor
    assert accepted["operation"]["context"] == operation["context"]
    assert tickets.creates == 1


@pytest.mark.parametrize("field,value", [
    ("credential_ref", "another-jira"), ("credential_authority", "another-owner"),
])
def test_readback_cannot_change_original_effect_credential_scope(setup, monkeypatch, field, value):
    svc, ctx, _, tickets, _ = setup
    row = svc.execute(ctx, approved(svc, ctx)["id"])
    changed = replace(ctx, **{field: value})
    reads = []
    monkeypatch.setattr(tickets, "find", lambda *a, **kw: reads.append("find") or [])
    monkeypatch.setattr(tickets, "verify", lambda *a, **kw: reads.append("verify") or {})
    with pytest.raises(PermissionError, match="(?i)(credential|scope)"):
        svc.reconcile(changed, row["id"])
    with pytest.raises(PermissionError, match="(?i)(credential|scope)"):
        svc.accept(changed, row["id"], row["revision"], True, "Should be blocked")
    assert reads == []
    assert tickets.creates == 1


def test_stale_prepared_authority_returns_case_to_reviewable_state(setup):
    svc, ctx, _, tickets, _ = setup
    row = reviewed(svc, ctx)
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    changed = replace(ctx, workspace_authority="new-generation")
    svc.authorize = lambda candidate, *_: candidate.binding() == changed.binding()
    with pytest.raises(PermissionError, match="(?i)authority changed"):
        svc.approve_action(
            changed, row["id"], row["revision"],
            row["operation"]["approval_card"]["binding_sha256"],
        )
    reopened = svc.get(changed, row["id"])
    assert reopened["stage"] == "review_approved"
    assert reopened["operation"] is None
    prepared = svc.prepare_action(changed, row["id"], reopened["revision"])
    assert prepared["operation"]["id"] != row["operation"]["id"]
    assert tickets.creates == 0


def test_changed_source_before_approval_opens_source_specific_reevaluation(setup):
    svc, ctx, docs, tickets, _ = setup
    row = reviewed(svc, ctx)
    row = svc.prepare_action(ctx, row["id"], row["revision"])
    docs.documents[(ctx.tenant, "security-paper")] = EvidenceDocument("security-paper", "2", NOW, TEXT)
    with pytest.raises(vendor_onboarding.VendorOnboardingEvidenceReviewRequired):
        svc.approve_action(
            ctx, row["id"], row["revision"],
            row["operation"]["approval_card"]["binding_sha256"],
        )
    reopened = svc.get(ctx, row["id"])
    assert reopened["operation"] is None
    assert reopened["stage"] == "acceptance_reevaluation_required"
    assert reopened["acceptance_evidence_check"]["documents"][0]["status"] == "changed"
    assert reopened["acceptance_evidence_check"]["documents"][0]["document_id"] == "security-paper"
    assert reopened["work_item"]["next_action"] == "start_reevaluation_request"
    assert tickets.creates == 0


def test_reconciliation_rejects_rewritten_historical_approval(setup):
    from maverick import vendor_onboarding

    svc, ctx, _, tickets, _ = setup
    row = svc.execute(ctx, approved(svc, ctx)["id"])
    changed = dict(row["operation"], context=dict(row["operation"]["context"], actor="forged-reviewer"))
    with tenant_scope(tenant=ctx.tenant):
        vendor_onboarding._CASES.update(
            row["id"], lambda value: value.update(operation=changed),
            expected_revision=row["revision"], action="tampered_history_fixture", actor=ctx.actor,
        )
    with pytest.raises(ValueError, match="approval binding"):
        svc.reconcile(ctx, row["id"])
    assert tickets.creates == 1
