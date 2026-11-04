"""Real dashboard routing through the offline vendor application service."""
from __future__ import annotations

import base64
from dataclasses import replace
from html.parser import HTMLParser

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick.governed_operations import ServiceContext
from maverick.vendor_onboarding import VendorOnboardingService
from maverick.vendor_onboarding_adapters import (
    EvidenceDocument,
    FakeGoogleDriveEvidence,
    FakeJiraTickets,
)
from maverick_dashboard.app import app
from maverick_dashboard.vendor_onboarding_composition import WorkflowBinding

BASE = "/api/v1/vendor-onboarding/cases"
NOW = 1_800_000_000.0


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_TENANT", "synthetic-a")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    (tmp_path / "config.toml").write_text(
        '[vendor_onboarding]\nenable=true\nresource_owner="procurement"\n'
        '[vendor_management]\nenable=true\n[ai_vendor_risk]\nenable=true\n'
        '[model_risk_assurance]\nenable=true\n', encoding="utf-8",
    )
    config.reset_config_cache()
    ctx = ServiceContext("synthetic-a", "user:reviewer", "procurement",
                         "user:reviewer", "jira", human=True)
    docs = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "v1", NOW - 100, b"We do not train on customer data.",
    )})
    tickets = FakeJiraTickets()
    service = VendorOnboardingService(docs, tickets, lambda c, cap, res: c.binding() == ctx.binding(),
                                      clock=lambda: NOW)
    monkeypatch.setattr(app.state, "vendor_onboarding_binding_factory",
                        lambda request: WorkflowBinding(service, ctx))
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    yield client, service, ctx, tickets
    config.reset_config_cache()


def _intake(client):
    result = client.post(BASE, json={"vendor_name": "Synthetic Support AI",
        "document_id": "security-paper", "project": "VEND", "purpose": "Draft replies"})
    assert result.status_code == 201, result.text
    return result.json()


def _step(client, row, step, **extra):
    if step == "approve-action":
        extra.setdefault(
            "approval_binding_sha256",
            row["operation"]["approval_card"]["binding_sha256"],
        )
    result = client.post(f"{BASE}/{row['id']}/{step}",
                         json={"expected_revision": row["revision"], **extra})
    assert result.status_code == 200, result.text
    return result.json()


def test_pilot_claim_blocks_vendor_provider_reads_until_all_cases_are_admitted(web):
    from maverick.paths import tenant_scope
    from maverick_dashboard import outcome_accounting_bridge, outcome_pilots

    client, service, ctx, tickets = web
    rows = [
        client.post(BASE, json={
            "vendor_name": f"Pilot vendor {index}",
            "document_id": "security-paper",
            "project": "VEND",
            "purpose": f"Pilot evidence case {index}",
        }).json()
        for index in range(1, 5)
    ]
    sources = {
        row["id"]: {
            "unstarted": True,
            "input_version": f"vendor-input-{index}",
            "first_started_at": None,
        }
        for index, row in enumerate(rows, start=1)
    }
    body = {
        "title": "Vendor admission gate",
        "customer": "Example team",
        "workflow": "Collect vendor evidence",
        "criteria": "Evidence is current and reviewable",
        "operation_id": "vendor-start-gate-operation",
        "cases": [
            {"kind": "vendor", "reference": row["id"], "label": row["vendor_name"]}
            for row in rows
        ],
    }
    with tenant_scope(tenant=ctx.tenant):
        pending = outcome_pilots.create(
            body, context="vendor-context", actor=ctx.actor,
            resolve=lambda _kind, reference: sources[reference],
        )

    path = f"{BASE}/{rows[0]['id']}/collect-evidence"
    provider_reads = []
    original_fetch = service.documents.fetch

    def observed_fetch(*args, **kwargs):
        provider_reads.append((args, kwargs))
        return original_fetch(*args, **kwargs)

    service.documents.fetch = observed_fetch
    refused = client.post(path, json={"expected_revision": rows[0]["revision"]})
    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert detail["code"] == "outcome_pilot_admission_incomplete"
    assert detail["current"]["id"] == rows[0]["id"]
    assert detail["current"]["stage"] == "intake"
    current = service.get(ctx, rows[0]["id"])
    assert current["stage"] == "intake"
    assert current["evidence"] is None
    assert current["metrics"]["document_reads"] == 0
    assert provider_reads == []
    assert tickets.creates == 0

    with tenant_scope(tenant=ctx.tenant):
        manifest = outcome_accounting_bridge.admit_pilot(
            pending, resolve=lambda _kind, reference: sources[reference],
        )
        outcome_pilots.complete_admission(
            pending["id"], manifest, context="vendor-context", actor=ctx.actor,
            resolve=lambda _kind, reference: sources[reference],
        )
    collected = client.post(path, json={"expected_revision": rows[0]["revision"]})
    assert collected.status_code == 200, collected.text
    assert collected.json()["stage"] == "evidence_collected"
    assert service.get(ctx, rows[0]["id"])["metrics"]["document_reads"] == 1
    assert len(provider_reads) == 1


def test_http_intake_replay_opens_one_stable_case_and_changed_payload_conflicts(web):
    client, service, ctx, tickets = web
    body = {
        "submission_key": "browser-submit-key-0001",
        "vendor_name": "Stable browser intake",
        "document_id": "security-paper",
        "project": "VEND",
        "purpose": "Recover after a lost response",
    }
    first = client.post(BASE, json=body)
    replay = client.post(BASE, json=body)
    assert first.status_code == replay.status_code == 201
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["revision"] == first.json()["revision"]
    assert len(service.list(ctx)) == 1

    changed = client.post(BASE, json=dict(body, purpose="A different request"))
    assert changed.status_code == 409
    detail = changed.json()["detail"]
    assert detail["code"] == "idempotency_conflict"
    assert detail["current"] == {
        "schema": "lightwork.vendor-onboarding.conflict-current.v1",
        "id": first.json()["id"],
        "revision": first.json()["revision"],
        "stage": "intake",
        "updated_at": first.json()["updated_at"],
        "vendor_name": "Stable browser intake",
        "work_item": {
            "lifecycle": "Draft",
            "next_action": "obtain_evidence",
            "technical_effect": "not_verified",
            "business_outcome": "pending",
        },
    }
    assert "evidence" not in detail["current"]
    assert len(service.list(ctx)) == 1 and tickets.creates == 0


def test_http_two_tab_draft_edit_returns_current_case_without_silent_overwrite(web):
    client, service, ctx, _ = web
    created = client.post(BASE, json={
        "submission_key": "two-tab-draft-key-0001",
        "vendor_name": "Two tab vendor",
        "document_id": "security-paper",
        "project": "VEND",
        "purpose": "Original intended use",
        "freshness_days": 365,
        "due_at": 1_900_000_000.0,
    })
    assert created.status_code == 201, created.text
    row = created.json()
    first = client.post(f"{BASE}/{row['id']}/draft", json={
        "expected_revision": row["revision"],
        "project": "RISK",
        "purpose": "First tab intended use",
        "freshness_days": 180,
        "due_at": 1_910_000_000.0,
    })
    assert first.status_code == 200, first.text

    stale = client.post(f"{BASE}/{row['id']}/draft", json={
        "expected_revision": row["revision"],
        "project": "OPS",
        "purpose": "Second tab stale change",
        "freshness_days": 90,
        "due_at": 1_920_000_000.0,
    })
    assert stale.status_code == 409
    detail = stale.json()["detail"]
    assert detail["code"] == "revision_conflict"
    assert detail["current"]["revision"] == first.json()["revision"]
    retained = service.get(ctx, row["id"])
    assert retained["project"] == "RISK"
    assert retained["purpose"] == "First tab intended use"


@pytest.mark.parametrize("submission_key", ["short", "contains space key", "x" * 129])
def test_http_rejects_malformed_submission_keys_without_creating_a_case(web, submission_key):
    client, service, ctx, tickets = web
    result = client.post(BASE, json={
        "submission_key": submission_key,
        "vendor_name": "Rejected key vendor",
        "document_id": "security-paper",
        "project": "VEND",
        "purpose": "Must not be admitted",
    })
    assert result.status_code == 422
    assert service.list(ctx) == [] and tickets.creates == 0


def test_http_queue_has_stable_three_page_navigation_and_unresolved_filter(web):
    from maverick import vendor_onboarding
    from maverick.paths import tenant_scope

    client, _, ctx, tickets = web
    created, unresolved = set(), set()
    for index in range(7):
        response = client.post(BASE, json={
            "submission_key": f"api-page-submit-{index:04d}",
            "vendor_name": f"API page vendor {index}",
            "document_id": "security-paper",
            "project": "VEND",
            "purpose": f"Three page API case {index}",
        })
        assert response.status_code == 201, response.text
        row = response.json()
        created.add(row["id"])
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
                    action="test_api_unresolved_queue_fixture",
                    actor=ctx.actor,
                )

    def collect(view, limit):
        cursor, seen, pages = "", [], 0
        while True:
            response = client.get(BASE, params={"limit": limit, "cursor": cursor, "view": view})
            assert response.status_code == 200, response.text
            page = response.json()
            assert page["schema"] == "lightwork.vendor-onboarding.case-page.v1"
            assert page["view"] == view and page["record_reads"] <= max(limit * 4, limit + 1)
            seen.extend(row["id"] for row in page["cases"])
            pages += 1
            if not page["has_more"]:
                assert page["next_cursor"] is None
                break
            assert page["next_cursor"] and page["next_cursor"] != cursor
            cursor = page["next_cursor"]
            assert pages < 20
        assert len(seen) == len(set(seen))
        return set(seen), pages

    all_ids, all_pages = collect("all", 2)
    unresolved_ids, unresolved_pages = collect("unresolved", 1)
    assert all_ids == created and unresolved_ids == unresolved
    assert all_pages >= 3 and unresolved_pages >= 3
    malformed = client.get(BASE, params={"cursor": "not base64!"})
    assert malformed.status_code == 409
    assert malformed.json()["detail"]["code"] == "workflow_rejected"
    assert tickets.creates == 0


@pytest.mark.parametrize("lost_receipt", [False, True])
def test_customer_cancellation_after_dispatch_keeps_effect_and_readback(web, lost_receipt):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(client, row, "review", decision="approved", rationale="Reviewed evidence")
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)
    tickets.timeout_after_success = lost_receipt
    row = _step(client, row, "execute", confirm=True)
    cancelled = _step(client, row, "cancel", confirm=True, rationale="Stop this request")
    assert cancelled["cancellation"]["effect_reversal"] == "not_requested"
    assert cancelled["cancellation"]["requested_by"] == ctx.actor
    assert cancelled["operation"] == row["operation"]
    assert cancelled["outcome"] is None
    assert cancelled["work_item"]["technical_effect"] == ("indeterminate" if lost_receipt else "verified")
    assert client.post(f"{BASE}/{row['id']}/execute", json={
        "expected_revision": cancelled["revision"], "confirm": True,
    }).status_code == 409
    reconciled = _step(client, cancelled, "reconcile", confirm=True)
    assert reconciled["stage"] == "cancelled"
    assert reconciled["work_item"]["technical_effect"] == "verified"
    assert reconciled["work_item"]["business_outcome"] == "pending"
    assert client.post(f"{BASE}/{row['id']}/accept", json={
        "expected_revision": reconciled["revision"], "accepted": True, "rationale": "No false success",
    }).status_code == 409
    assert service.get(ctx, row["id"])["cancellation"] == cancelled["cancellation"]
    assert tickets.creates == 1 and len(tickets.state) == 1


def test_customer_cancellation_validates_confirmation_authority_and_revision(web):
    client, service, ctx, tickets = web
    row = _intake(client)
    path = f"{BASE}/{row['id']}/cancel"
    body = {"expected_revision": row["revision"], "rationale": "Stop before dispatch"}
    assert client.post(path, json=body).status_code == 422
    assert client.post(path, json=dict(body, confirm=False)).status_code == 422
    assert client.post(path, json=dict(body, confirm=True, tenant="forged")).status_code == 422
    assert client.post(path, json=dict(body, confirm=True, effect_reversed=True)).status_code == 422
    service.authorize = lambda candidate, capability, resource: capability != "action.cancel"
    denied = client.post(path, json=dict(body, confirm=True))
    assert denied.status_code == 403
    service.authorize = lambda candidate, capability, resource: candidate.binding() == ctx.binding()
    row = _step(client, row, "collect-evidence")
    conflict = client.post(path, json=dict(body, confirm=True))
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "revision_conflict"
    cancelled = _step(client, row, "cancel", confirm=True, rationale=body["rationale"])
    assert cancelled["stage"] == "cancelled"
    assert cancelled["cancellation"]["dispatch_state_at_cancellation"] == "not_dispatched"
    assert tickets.creates == 0


def test_http_blank_purpose_does_not_leave_a_registered_vendor(web):
    from maverick import vendor_management
    from maverick.paths import tenant_scope

    client, service, ctx, tickets = web
    response = client.post(BASE, json={"vendor_name": "Rejected HTTP intake vendor",
        "document_id": "security-paper", "project": "VEND", "purpose": "   "})
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "schema": "lightwork.error.v1", "code": "workflow_rejected",
        "message": "purpose must be a nonempty string of at most 4000 characters",
        "retryable": False,
        "next_action": "Review the current case state and correct the requested action.",
    }
    with tenant_scope(tenant=ctx.tenant):
        assert vendor_management.list_vendors() == []
    assert service.list(ctx) == []
    assert tickets.creates == 0


def test_http_case_exposes_pinned_work_item_contract(web):
    client, *_ = web
    row = _intake(client)
    assert row["journey_contract"] == row["work_item"]["process"]
    assert row["work_item"]["schema"] == "lightwork.contract.work-item.v1"
    assert row["work_item"]["objective"] == "Draft replies"
    assert row["work_item"]["technical_effect"] == "not_verified"
    assert row["work_item"]["business_outcome"] == "pending"
    reopened = client.get(f"{BASE}/{row['id']}")
    assert reopened.status_code == 200
    assert reopened.json()["work_item"] == row["work_item"]
    listed = client.get(BASE).json()["cases"]
    assert listed[0]["work_item"] == row["work_item"]
    assert listed[0]["owner"] == row["owner"]
    assert listed[0]["updated_at"] == row["updated_at"]
    assert listed[0]["next_action"] == "obtain_evidence"
    assert listed[0]["blocker"] is None
    assert "evidence" not in listed[0] and "operation" not in listed[0]
    assert "intake_idempotency" not in listed[0]


def test_http_contract_and_revision_failures_have_stable_error_codes(web):
    from maverick import vendor_onboarding
    from maverick.paths import tenant_scope

    client, _, ctx, _ = web
    row = _intake(client)
    changed = _step(client, row, "collect-evidence")
    stale = client.post(f"{BASE}/{row['id']}/assess", json={"expected_revision": row["revision"]})
    assert stale.status_code == 409
    assert stale.json()["detail"]["code"] == "revision_conflict"
    assert stale.json()["detail"]["retryable"] is False
    assert "Reload" in stale.json()["detail"]["next_action"]
    current = stale.json()["detail"]["current"]
    assert current["id"] == changed["id"]
    assert current["revision"] == changed["revision"]
    assert current["stage"] == changed["stage"]
    assert set(current) == {
        "schema", "id", "revision", "stage", "updated_at", "vendor_name", "work_item",
    }
    assert "evidence" not in current and "operation" not in current

    with tenant_scope(tenant=ctx.tenant):
        vendor_onboarding._CASES.update(
            row["id"], lambda value: value.update(schema="lightwork.vendor-onboarding.v999"),
            expected_revision=changed["revision"], action="test_unknown_schema_fixture", actor=ctx.actor,
        )
    unsupported = client.get(f"{BASE}/{row['id']}")
    assert unsupported.status_code == 409
    assert unsupported.json()["detail"]["code"] == "unsupported_record_version"
    assert unsupported.json()["detail"]["schema"] == "lightwork.error.v1"
    assert unsupported.json()["detail"]["retryable"] is False


def test_http_platform_contract_error_is_stable_and_provider_failure_is_redacted(web, monkeypatch):
    from maverick.platform_contracts import PlatformContractError

    client, service, *_ = web
    monkeypatch.setattr(service, "get", lambda *args: (_ for _ in ()).throw(
        PlatformContractError("work item lifecycle is unsupported", code="invalid_transition")
    ))
    incompatible = client.get(f"{BASE}/VON-incompatible")
    assert incompatible.status_code == 409
    assert incompatible.json()["detail"]["code"] == "invalid_transition"
    assert incompatible.json()["detail"]["message"] == "work item lifecycle is unsupported"

    monkeypatch.setattr(service, "get", lambda *args: (_ for _ in ()).throw(
        RuntimeError("provider payload included api_key=plaintext-secret-value")
    ))
    unavailable = client.get(f"{BASE}/VON-unavailable")
    assert unavailable.status_code == 503
    assert unavailable.json()["detail"]["code"] == "operation_unavailable"
    assert "plaintext-secret-value" not in unavailable.text
    assert "RuntimeError" not in unavailable.text


def test_reviewed_file_preview_is_private_nonmutating_and_requires_exact_confirmation(web):
    client, service, ctx, tickets = web
    row = _intake(client)
    body = dict(expected_revision=row["revision"], name="Synthetic.txt", mime="text/plain",
                document_date=NOW - 100, content_base64=base64.b64encode(b"Model provenance is documented with provider and version.").decode())
    response = client.post(f"{BASE}/{row['id']}/upload-preview", json=body)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    preview = response.json()
    assert preview["saved"] is False and preview["text"]
    assert service.get(ctx, row["id"])["uploads"] == []
    result = client.post(f"{BASE}/{row['id']}/upload-reviewed", json=body)
    assert result.status_code == 409
    committed = dict(body, confirm=True, review_digest=preview["review_digest"], expires_at=preview["expires_at"])
    result = client.post(f"{BASE}/{row['id']}/upload-reviewed", json=committed)
    assert result.status_code == 200, result.text
    assert result.json()["uploads"][0]["reviewed_by"] == ctx.actor
    assert tickets.creates == 0
    assert client.post(f"{BASE}/{row['id']}/upload-reviewed", json=committed).status_code == 409


def test_preview_validation_does_not_echo_private_document_fields(web):
    client, *_ = web
    row = _intake(client)
    response = client.post(f"{BASE}/{row['id']}/upload-preview", json={
        "expected_revision": row["revision"], "name": "Synthetic.txt", "mime": "text/plain",
        "document_date": NOW - 100, "content_base64": "PRIVATE INVALID CONTENT", "transcription": "private supplied text",
    })
    assert response.status_code == 422
    assert "PRIVATE" not in response.text and "private supplied" not in response.text


def test_http_workflow_review_correction_external_confirmation_and_acceptance(web):
    client, service, ctx, tickets = web
    row = _intake(client)
    row = _step(client, row, "collect-evidence")
    row = _step(client, row, "assess")
    qid = next(iter(row["assessment"]["answers"]))
    row = _step(client, row, "review", decision="approved", rationale="Restricted pilot",
                corrections={qid: {"answer": "unknown", "note": "Request clearer evidence"}},
                review_seconds=4.5)
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)
    row = _step(client, row, "execute", confirm=True)
    assert row["operation"]["external_confirmation"]["verified"] is True
    assert row["outcome"] is None
    row = _step(client, row, "accept", accepted=True, rationale="Accepted for the pilot")
    assert row["outcome"]["accepted"] is True
    assert row["outcome"]["released"] is False
    assert tickets.creates == 1
    assert service.get(ctx, row["id"])["metrics"]["human_review_seconds"] == 4.5
    assert len(client.get(BASE).json()["cases"]) == 1
    check = client.post(f"{BASE}/{row['id']}/check-renewal",
                        json={"expected_revision": row["revision"]})
    assert check.status_code == 200, check.text
    assert check.json()["classification"] == "human_fallback"
    assert tickets.creates == 1  # Readiness never triggers another external action.
    renewal_page = client.get(BASE, params={"view": "renewal"})
    assert renewal_page.status_code == 200, renewal_page.text
    assert [item["id"] for item in renewal_page.json()["cases"]] == [row["id"]]
    assert renewal_page.json()["cases"][0]["attention"]["kind"] == "evidence_renewal"
    assert client.post(f"{BASE}/{row['id']}/check-renewal", json={
        "expected_revision": row["revision"], "now": 0, "customer_accepted": True,
    }).status_code == 422
    assert client.post(f"{BASE}/{row['id']}/check-renewal", json={
        "expected_revision": row["revision"] - 1,
    }).status_code == 409


def test_http_business_rejection_remains_in_admitted_results_with_verified_effect(web):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Reviewed the current evidence and stated gaps",
    )
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)
    row = _step(client, row, "execute", confirm=True)
    rejected = _step(
        client,
        row,
        "accept",
        accepted=False,
        rationale="The verified delivery does not meet the current business need",
    )

    assert rejected["stage"] == "customer_rejected"
    assert rejected["outcome"]["reviewer"] == ctx.actor
    assert rejected["outcome"]["rationale"] == (
        "The verified delivery does not meet the current business need"
    )
    assert rejected["work_item"]["technical_effect"] == "verified"
    assert rejected["work_item"]["business_outcome"] == "rejected"
    assert rejected["attention"]["state"] == "rejected"

    results = client.get(BASE, params={"view": "closed"})
    assert results.status_code == 200, results.text
    page = results.json()
    assert page["page_counts"]["admitted"] == 1
    assert page["page_counts"]["rejected"] == 1
    assert page["cases"][0]["id"] == rejected["id"]
    assert page["cases"][0]["work_item"]["technical_effect"] == "verified"
    assert page["cases"][0]["work_item"]["business_outcome"] == "rejected"
    assert service.get(ctx, rejected["id"])["outcome"] == rejected["outcome"]
    assert tickets.creates == 1


def test_http_acceptance_reports_changed_evidence_and_opens_reevaluation(web):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(client, row, "review", decision="approved", rationale="Reviewed current source")
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)
    row = _step(client, row, "execute", confirm=True)
    source = service.documents.documents[(ctx.tenant, "security-paper")]
    service.documents.documents[(ctx.tenant, "security-paper")] = replace(
        source, version="v2", modified_at=NOW,
    )

    blocked = client.post(f"{BASE}/{row['id']}/accept", json={
        "expected_revision": row["revision"],
        "accepted": True,
        "rationale": "Accept the prior review",
    })
    assert blocked.status_code == 409, blocked.text
    detail = blocked.json()["detail"]
    assert detail["code"] == "evidence_reevaluation_required"
    assert detail["current"]["stage"] == "acceptance_reevaluation_required"
    assert "evidence" not in detail["current"]
    current = client.get(f"{BASE}/{row['id']}").json()
    assert current["operation"]["state"] == "verified"
    assert current["outcome"] is None
    assert current["acceptance_evidence_check"]["documents"][0]["status"] == "changed"
    assert current["acceptance_evidence_check"]["documents"][0]["document_id"] == "security-paper"
    assert tickets.creates == 1
    reevaluation = client.post(BASE, json={
        "vendor_name": current["vendor_name"],
        "document_id": "security-paper",
        "project": current["project"],
        "purpose": "Reevaluate changed evidence",
        "renewal_of": current["id"],
    })
    assert reevaluation.status_code == 201, reevaluation.text
    assert reevaluation.json()["review_history"] == []
    assert tickets.creates == 1


def test_http_action_approval_opens_changed_source_reevaluation_and_blocks_retry(web):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Reviewed the current source",
    )
    row = _step(client, row, "prepare-action")
    source = service.documents.documents[(ctx.tenant, "security-paper")]
    service.documents.documents[(ctx.tenant, "security-paper")] = replace(
        source, version="v2", modified_at=NOW,
    )

    blocked = client.post(f"{BASE}/{row['id']}/approve-action", json={
        "expected_revision": row["revision"],
        "approval_binding_sha256": row["operation"]["approval_card"]["binding_sha256"],
        "confirm": True,
    })
    assert blocked.status_code == 409, blocked.text
    detail = blocked.json()["detail"]
    assert detail["code"] == "evidence_reevaluation_required"
    assert detail["current"]["stage"] == "acceptance_reevaluation_required"
    assert detail["current"]["work_item"]["technical_effect"] == "not_verified"
    assert "evidence" not in detail["current"]
    current = client.get(f"{BASE}/{row['id']}").json()
    assert current["operation"] is None
    assert current["review_history"] == row["review_history"]
    assert current["acceptance_evidence_check"]["documents"][0]["status"] == "changed"
    assert current["acceptance_evidence_check"]["documents"][0]["document_id"] == "security-paper"
    assert tickets.creates == 0

    retry = client.post(f"{BASE}/{row['id']}/prepare-action", json={
        "expected_revision": current["revision"],
    })
    assert retry.status_code == 409, retry.text
    assert retry.json()["detail"]["code"] == "evidence_reevaluation_required"
    assert retry.json()["detail"]["current"]["revision"] == current["revision"]

    reevaluation = client.post(BASE, json={
        "vendor_name": current["vendor_name"],
        "document_id": "security-paper",
        "project": current["project"],
        "purpose": "Reevaluate changed evidence",
        "renewal_of": current["id"],
    })
    assert reevaluation.status_code == 201, reevaluation.text
    assert reevaluation.json()["renewal_of"] == current["id"]
    assert reevaluation.json()["review_history"] == []
    assert tickets.creates == 0


def test_http_evidence_export_requires_reviewed_manifest_and_exact_confirmation(web):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(client, row, "review", decision="approved", rationale="Reviewed export claims")
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)
    row = _step(client, row, "execute", confirm=True)
    row = _step(client, row, "accept", accepted=True, rationale="Accept reviewed export")

    preview = client.post(f"{BASE}/{row['id']}/evidence-export-preview", json={
        "expected_revision": row["revision"],
    })
    assert preview.status_code == 200, preview.text
    assert preview.headers["cache-control"] == "no-store"
    assert preview.headers["x-content-type-options"] == "nosniff"
    bundle = preview.json()
    assert bundle["case"]["id"] == row["id"]
    assert {claim["claim_id"] for claim in bundle["claims"]} == set(row["assessment"]["answers"])
    assert all(claim["evidence_refs"] or claim["review_justification"]
               for claim in bundle["claims"])
    assert client.post(f"{BASE}/{row['id']}/evidence-export", json={
        "expected_revision": row["revision"],
        "expected_export_sha256": bundle["binding_sha256"],
    }).status_code == 422
    downloaded = client.post(f"{BASE}/{row['id']}/evidence-export", json={
        "expected_revision": row["revision"],
        "expected_export_sha256": bundle["binding_sha256"],
        "confirm": True,
    })
    assert downloaded.status_code == 200, downloaded.text
    assert downloaded.json()["binding_sha256"] == bundle["binding_sha256"]
    assert downloaded.headers["content-type"].startswith("application/json")
    assert downloaded.headers["content-disposition"] == (
        f'attachment; filename="lightwork-evidence-{row["id"]}.json"'
    )
    service.authorize = lambda candidate, capability, resource: (
        candidate.binding() == ctx.binding() and capability != "evidence.export"
    )
    denied = client.post(f"{BASE}/{row['id']}/evidence-export-preview", json={
        "expected_revision": row["revision"],
    })
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "permission_denied"
    assert tickets.creates == 1


def test_http_active_markup_is_plain_text_and_unsupported_media_never_mutates_case(web):
    client, service, ctx, tickets = web
    row = client.post(BASE, json={
        "vendor_name": "Synthetic markup source",
        "document_ids": [],
        "project": "VEND",
        "purpose": "Verify inert preview rendering",
    }).json()
    active = b"<script>window.activeMarkupExecuted=true</script><img src=x onerror=alert(1)>"
    common = {
        "expected_revision": row["revision"],
        "name": "active.txt",
        "document_date": NOW - 100,
        "content_base64": base64.b64encode(active).decode(),
    }
    unsupported = client.post(f"{BASE}/{row['id']}/upload-preview", json={
        **common, "mime": "text/html",
    })
    assert unsupported.status_code == 409
    assert "unsupported document format" in unsupported.json()["detail"]["message"]
    assert service.get(ctx, row["id"])["revision"] == row["revision"]
    assert service.get(ctx, row["id"])["uploads"] == []
    preview = client.post(f"{BASE}/{row['id']}/upload-preview", json={
        **common, "mime": "text/plain",
    })
    assert preview.status_code == 200, preview.text
    assert preview.json()["text"] == active.decode()
    assert preview.json()["status"] == "available"
    assert preview.json()["saved"] is False
    assert service.get(ctx, row["id"])["uploads"] == []
    assert tickets.creates == 0


def test_http_rejects_forged_authority_unknown_steps_and_stale_versions(web):
    client, *_ = web
    row = _intake(client)
    rejected = client.post(BASE, json={"vendor_name": "Fake", "document_id": "doc",
        "project": "VEND", "purpose": "test", "human": True, "tenant": "other"})
    assert rejected.status_code == 422
    assert client.post(f"{BASE}/{row['id']}/delete-everything", json={"expected_revision": 1}).status_code == 422
    _step(client, row, "collect-evidence")
    assert client.post(f"{BASE}/{row['id']}/assess", json={"expected_revision": row["revision"]}).status_code == 409


def test_http_document_picker_and_case_upload_preserve_dates_and_require_new_assessment(web):
    client, service, ctx, tickets = web
    found = client.get("/api/v1/vendor-onboarding/documents", params={"query": "security"})
    assert found.status_code == 200
    assert found.json()["documents"][0]["id"] == "security-paper"
    row = client.post(BASE, json={"vendor_name": "Synthetic upload", "document_ids": [],
                                 "project": "VEND", "purpose": "Upload in the app"}).json()
    result = client.post(f"{BASE}/{row['id']}/upload", params={"expected_revision": row["revision"],
        "name": "policy.txt", "document_date": NOW - 100}, headers={"Content-Type": "text/plain"},
        content=b"Model provenance is documented with provider and version.")
    assert result.status_code == 200, result.text
    uploaded = result.json()
    assert uploaded["uploads"][0]["modified_at"] == NOW - 100
    assert uploaded["uploads"][0]["date_basis"] == "uploader_asserted_document_date"
    assert uploaded["assessment"] is None
    assert client.post(f"{BASE}/{row['id']}/upload", params={"expected_revision": row["revision"],
        "name": "policy.txt", "document_date": NOW - 100}, headers={"Content-Type": "text/plain"},
        content=b"Stale request").status_code == 409
    collected = _step(client, uploaded, "collect-evidence")
    assert collected["evidence"]["source"] == "upload"
    assert service.get(ctx, row["id"])["metrics"]["document_reads"] == 0
    assert tickets.creates == 0


@pytest.mark.parametrize("name,mime,content,status", [
    ("policy.txt", "text/plain", b"x" * (1024 * 1024 + 1), 413),
    ("policy.bin", "application/octet-stream", b"binary", 415),
    ("../policy.txt", "text/plain", b"policy", 409),
    ("policy.txt", "text/plain", b"\xff", 409),
], ids=["oversized", "unsupported-mime", "path-name", "invalid-utf8"])
def test_http_upload_rejects_unsupported_oversized_or_unsafe_input_without_mutating(web, name, mime, content, status):
    client, service, ctx, tickets = web
    row = _intake(client)
    result = client.post(f"{BASE}/{row['id']}/upload", params={"expected_revision": row["revision"],
        "name": name, "document_date": NOW - 100}, headers={"Content-Type": mime}, content=content)
    assert result.status_code == status, result.text
    assert service.get(ctx, row["id"]) == row
    assert tickets.creates == 0


def test_http_unreadable_pdf_is_visible_and_blocks_assessment(web):
    client, *_ = web
    row = _intake(client)
    result = client.post(f"{BASE}/{row['id']}/upload", params={"expected_revision": row["revision"],
        "name": "scanned.pdf", "document_date": NOW - 100}, headers={"Content-Type": "application/pdf"},
        content=b"%PDF-1.4\nunsupported image-only test document")
    assert result.status_code == 200
    row = result.json()
    assert row["uploads"][0]["status"] == "extraction_failed"
    row = _step(client, row, "collect-evidence")
    assert row["evidence"]["status"] == "extraction_failed"
    assert client.post(f"{BASE}/{row['id']}/assess", json={"expected_revision": row["revision"]}).status_code == 409
    row = _step(client, row, "documents", document_ids=["security-paper"], upload_ids=[])
    assert row["uploads"] == []


def test_http_requires_separate_explicit_approval_and_blocks_cross_origin(web):
    client, _, _, tickets = web
    row = _intake(client)
    response = client.post(f"{BASE}/{row['id']}/execute",
                           json={"expected_revision": row["revision"], "confirm": True})
    assert response.status_code == 409
    assert client.post(f"{BASE}/{row['id']}/approve-action",
                       json={"expected_revision": row["revision"], "confirm": False}).status_code == 422
    assert client.post(BASE, headers={"Origin": "https://attacker.invalid"}, json={}).status_code == 403
    assert tickets.creates == 0


def test_http_approval_requires_the_exact_reviewed_card_binding(web):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Reviewed the exact current evidence",
    )
    row = _step(client, row, "prepare-action")
    endpoint = f"{BASE}/{row['id']}/approve-action"

    missing = client.post(endpoint, json={
        "expected_revision": row["revision"],
        "confirm": True,
    })
    assert missing.status_code == 422
    assert service.get(ctx, row["id"]) == row

    changed = client.post(endpoint, json={
        "expected_revision": row["revision"],
        "confirm": True,
        "approval_binding_sha256": "0" * 64,
    })
    assert changed.status_code == 409
    assert changed.json()["detail"]["code"] == "approval_binding_invalid"
    assert service.get(ctx, row["id"]) == row
    assert tickets.creates == 0

    approved = _step(client, row, "approve-action", confirm=True)
    assert approved["operation"]["state"] == "approved"


def test_view_only_vendor_approval_is_audited_and_remains_unapproved(
    web, monkeypatch,
):
    from maverick import audit
    from maverick_dashboard import auth

    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Reviewed the current evidence",
    )
    row = _step(client, row, "prepare-action")
    recorded = []
    monkeypatch.setattr(auth, "has_permission", lambda _request, _permission: False)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:viewer")
    monkeypatch.setattr(
        audit,
        "audit_event",
        lambda kind, **payload: recorded.append((kind, payload)) or True,
    )

    denied = client.post(
        f"{BASE}/{row['id']}/approve-action",
        json={
            "expected_revision": row["revision"],
            "confirm": True,
            "approval_binding_sha256": row["operation"]["approval_card"][
                "binding_sha256"
            ],
        },
    )

    assert denied.status_code == 403
    assert service.get(ctx, row["id"]) == row
    assert tickets.creates == 0
    assert len(recorded) == 1
    kind, payload = recorded[0]
    assert kind == audit.EventKind.CAPABILITY_DENIED
    assert payload["principal"] == "user:viewer"
    assert len(payload["resource_sha256"]) == 64
    assert row["id"] not in str(payload)
    assert row["vendor_name"] not in str(payload)


def test_http_returns_reapproval_recovery_for_changed_budget_binding(web, monkeypatch):
    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Approved for a bounded synthetic check",
    )
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)

    changed = replace(ctx, budget_authority="tenant-budget-v2")
    service.authorize = lambda _context, _capability, _resource: True
    monkeypatch.setattr(
        app.state,
        "vendor_onboarding_binding_factory",
        lambda _request: WorkflowBinding(service, changed),
    )
    response = client.post(
        f"{BASE}/{row['id']}/execute",
        json={"expected_revision": row["revision"], "confirm": True},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "schema": "lightwork.error.v1",
        "code": "approval_authority_changed",
        "message": "Operation authority changed; prepare and review a new action.",
        "retryable": False,
        "next_action": "Reload the case, prepare the current action, and review it again.",
    }
    recovered = client.get(f"{BASE}/{row['id']}")
    assert recovered.status_code == 200
    assert recovered.json()["stage"] == "review_approved"
    assert recovered.json()["operation"] is None
    assert recovered.json()["operation_history"][-1]["invalidated_reason"] == (
        "approval_authority_changed"
    )
    prepared = _step(client, recovered.json(), "prepare-action")
    assert prepared["stage"] == "action_pending_approval"
    assert tickets.creates == 0


def test_http_role_loss_retires_approval_before_permission_denial_and_restore(
    web,
    monkeypatch,
):
    from maverick_dashboard import vendor_onboarding_api as api

    client, service, ctx, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Approved for a bounded synthetic check",
    )
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)

    permission = [True]
    current_context = [ctx]

    def require_current_permission(_request, _permission):
        if not permission[0]:
            raise HTTPException(403, "insufficient role for this action")

    service.authorize = (
        lambda candidate, _capability, _resource:
        candidate.authorization_role != "read_only"
    )
    monkeypatch.setattr(api, "require_permission", require_current_permission)
    monkeypatch.setattr(
        app.state,
        "vendor_onboarding_binding_factory",
        lambda _request: WorkflowBinding(service, current_context[0]),
    )

    permission[0] = False
    current_context[0] = replace(
        ctx,
        authorization_role="read_only",
        authorization_policy="read-only-policy-v2",
    )
    denied = client.post(
        f"{BASE}/{row['id']}/execute",
        json={"expected_revision": row["revision"], "confirm": True},
    )

    assert denied.status_code == 409
    assert denied.json()["detail"]["code"] == "approval_authority_changed"
    # The execute-only binding marker must not weaken any later route.
    assert client.get(f"{BASE}/{row['id']}").status_code == 403
    current = service.get(ctx, row["id"])
    assert current["stage"] == "review_approved"
    assert current["operation"] is None
    assert current["operation_history"][-1]["invalidated_reason"] == (
        "approval_authority_changed"
    )
    assert tickets.creates == 0

    permission[0] = True
    current_context[0] = ctx
    restored = client.post(
        f"{BASE}/{row['id']}/execute",
        json={"expected_revision": current["revision"], "confirm": True},
    )
    assert restored.status_code == 409
    assert restored.json()["detail"]["code"] == "workflow_rejected"
    assert tickets.creates == 0


def test_http_cross_tenant_worker_and_export_return_no_foreign_content(web, monkeypatch):
    client, service, ctx, tickets = web
    row = _intake(client)
    row = _step(client, row, "collect-evidence")
    row = _step(client, row, "assess")
    row = _step(
        client,
        row,
        "review",
        decision="approved",
        rationale="Reviewed synthetic evidence",
    )
    row = _step(client, row, "prepare-action")
    row = _step(client, row, "approve-action", confirm=True)
    service.authorize = lambda _context, _capability, _resource: True
    other = replace(ctx, tenant="synthetic-b", workspace_authority="workspace-b")
    monkeypatch.setattr(
        app.state,
        "vendor_onboarding_binding_factory",
        lambda _request: WorkflowBinding(service, other),
    )

    listing = client.get(BASE)
    assert listing.status_code == 200
    assert listing.json()["cases"] == []
    assert listing.json()["has_more"] is False
    assert row["id"] not in listing.text
    exported = client.get(f"{BASE}/{row['id']}")
    assert exported.status_code == 404
    assert row["vendor_name"] not in exported.text
    assert row["purpose"] not in exported.text
    for path, body in (
        ("execute", {"expected_revision": row["revision"], "confirm": True}),
        ("evidence-export-preview", {"expected_revision": row["revision"]}),
        (
            "evidence-export",
            {
                "expected_revision": row["revision"],
                "confirm": True,
                "expected_export_sha256": "0" * 64,
            },
        ),
    ):
        response = client.post(f"{BASE}/{row['id']}/{path}", json=body)
        assert response.status_code == 404
        assert row["vendor_name"] not in response.text
        assert row["purpose"] not in response.text
    assert tickets.creates == 0


def test_stock_composition_rejects_anonymous_or_static_identity(web, monkeypatch):
    from maverick_dashboard.vendor_onboarding_composition import bind_request

    client, *_ = web
    monkeypatch.setattr(app.state, "vendor_onboarding_binding_factory", bind_request)
    response = client.get(BASE)
    assert response.status_code == 403
    assert "named authenticated" in response.text


def test_stock_composition_allows_upload_only_but_drive_read_still_requires_enrollment(web, monkeypatch):
    from maverick import connections
    from maverick.paths import tenant_scope
    from maverick.vendor_onboarding_adapters import GoogleDriveEvidence
    from maverick_dashboard import vendor_onboarding_composition as composition

    monkeypatch.setattr(composition, "require_permission", lambda *args: None)
    monkeypatch.setattr(composition, "caller_principal", lambda *args: "user:reviewer")
    monkeypatch.setattr(composition, "caller_role", lambda *args: "operator")
    monkeypatch.setattr(connections, "enabled", lambda: True)
    monkeypatch.setattr(connections, "get_connection", lambda name: {
        "name": "jira", "owner": "user:reviewer", "connector": "jira", "revision": "1",
    } if name == "jira" else None)
    with tenant_scope(tenant="synthetic-a"):
        context = composition._context(object())
    assert context.credential_authority == "user:reviewer"
    assert context.authorization_role == "operator"
    assert context.authorization_policy.startswith("sha256:")
    assert context.budget_authority.startswith("sha256:")
    assert context.workspace_authority.startswith("sha256:")
    with pytest.raises(PermissionError, match="authority.*unavailable"):
        GoogleDriveEvidence().search(context, "policy")


def test_budget_authority_changes_with_tenant_spend_controls(monkeypatch):
    from types import SimpleNamespace

    from maverick.tenant import registry
    from maverick_dashboard import vendor_onboarding_composition as composition

    record = SimpleNamespace(
        id="tenant-a", status="active", plan="team", billing_status="current",
        max_daily_dollars=25.0, feature_overrides={}, updated_at=10.0,
    )
    monkeypatch.setattr(registry, "get_tenant", lambda _tenant: record)
    before = composition._budget_authority("tenant-a")
    record.max_daily_dollars = 10.0
    record.updated_at = 11.0
    after = composition._budget_authority("tenant-a")
    assert before.startswith("sha256:")
    assert after.startswith("sha256:")
    assert after != before


@pytest.fixture
def stock_workspace(web, monkeypatch):
    from types import SimpleNamespace

    from maverick import connections
    from maverick.paths import tenant_scope
    from maverick.tenant import registry
    from maverick_dashboard import rbac, workspace_tenants
    from maverick_dashboard import vendor_onboarding_composition as composition

    _, original, ctx, tickets = web
    # Native provisioning precedes membership and retained workflow data;
    # the lifecycle guard correctly refuses adopting a previously used name.
    registry.create_tenant(ctx.tenant)
    rbac.set_role(ctx.actor, "operator")
    rbac.set_tenant_role(ctx.tenant, ctx.actor, "operator")
    workspace_tenants.set_selection(ctx.actor, ctx.tenant)
    monkeypatch.setattr(connections, "get_connection", lambda _: {"owner": ctx.actor})
    request = SimpleNamespace(state=SimpleNamespace(
        principal=SimpleNamespace(principal=ctx.actor),
        workspace_tenant_source="principal_selection",
    ))
    with tenant_scope(tenant=ctx.tenant):
        binding = composition.bind_request(request)
    service = binding.service
    service.documents, service.tickets, service.clock = original.documents, tickets, original.clock
    current = binding.context
    row = service.intake(current, "Synthetic stock authority", "security-paper", "VEND", "Draft replies")
    row = service.collect_evidence(current, row["id"], row["revision"])
    row = service.assess(current, row["id"], row["revision"])
    row = service.review(current, row["id"], row["revision"], "approved", "Reviewed synthetic evidence")
    row = service.prepare_action(current, row["id"], row["revision"])
    row = service.approve_action(
        current,
        row["id"],
        row["revision"],
        row["operation"]["approval_card"]["binding_sha256"],
    )
    return service, current, row, tickets, request


@pytest.mark.parametrize("revoke_reviewer", [False, True])
def test_distinct_authorized_reviewer_can_approve_and_preparer_can_execute(
    stock_workspace, web, monkeypatch, revoke_reviewer,
):
    from maverick_dashboard import auth, rbac, workspace_tenants
    from maverick_dashboard import vendor_onboarding_composition as composition

    client, _, _, tickets = web
    service, preparer, _, _, _ = stock_workspace
    reviewer = "user:second-reviewer"
    rbac.set_role(reviewer, "operator")
    rbac.set_tenant_role(preparer.tenant, reviewer, "viewer")
    workspace_tenants.set_selection(reviewer, preparer.tenant)

    def principal(request):
        return "user:" + request.headers.get("X-Test-User", "reviewer")
    monkeypatch.setattr(auth, "caller_principal", principal)
    monkeypatch.setattr(composition, "caller_principal", principal)

    def binding(request):
        result = composition.bind_request(request)
        result.service.documents = service.documents
        result.service.tickets = tickets
        result.service.clock = service.clock
        return result

    monkeypatch.setattr(app.state, "vendor_onboarding_binding_factory", binding)
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(client, row, "review", decision="approved", rationale="Reviewed evidence")
    row = _step(client, row, "prepare-action")
    approval_body = {
        "expected_revision": row["revision"], "confirm": True,
        "approval_binding_sha256": row["operation"]["approval_card"]["binding_sha256"],
    }
    endpoint = f"{BASE}/{row['id']}/approve-action"
    denied = client.post(endpoint, json=approval_body, headers={"X-Test-User": "second-reviewer"})
    assert denied.status_code == 403
    assert client.get(f"{BASE}/{row['id']}").json()["operation"]["state"] == "prepared"

    rbac.set_tenant_role(preparer.tenant, reviewer, "operator")
    approved = client.post(endpoint, json=approval_body, headers={"X-Test-User": "second-reviewer"})
    assert approved.status_code == 200, approved.text
    operation = approved.json()["operation"]
    assert operation["state"] == "approved"
    assert operation["context"]["actor"] == preparer.actor
    assert operation["approval"]["reviewer"] == reviewer
    assert operation["approval"]["reviewer_context"]["actor"] == reviewer

    if revoke_reviewer:
        rbac.remove_tenant_role(preparer.tenant, reviewer)
        rbac.set_role(reviewer, "viewer")
    executed = client.post(f"{BASE}/{row['id']}/execute", json={
        "expected_revision": approved.json()["revision"], "confirm": True,
    })
    if revoke_reviewer:
        assert executed.status_code == 409
        assert executed.json()["detail"]["code"] == "approval_authority_changed"
        rbac.set_tenant_role(preparer.tenant, reviewer, "operator")
        retired = client.get(f"{BASE}/{row['id']}").json()
        assert retired["operation"] is None
        assert retired["operation_history"][-1]["invalidated_reason"] == "approval_authority_changed"
        assert tickets.creates == 0
        return
    assert executed.status_code == 200, executed.text
    assert executed.json()["operation"]["state"] == "verified"
    assert tickets.creates == 1


@pytest.mark.parametrize("timing", ["before_claim", "after_claim"])
def test_stock_worker_rechecks_revoked_membership_before_effect(stock_workspace, monkeypatch, timing):
    from maverick_dashboard import rbac

    service, ctx, row, tickets, _ = stock_workspace
    if timing == "before_claim":
        rbac.remove_tenant_role(ctx.tenant, ctx.actor)
    else:
        original = service._preconditions
        calls = []

        def revoke_after_claim(*args):
            result = original(*args)
            calls.append(True)
            if len(calls) == 2:
                rbac.remove_tenant_role(ctx.tenant, ctx.actor)
            return result

        monkeypatch.setattr(service, "_preconditions", revoke_after_claim)
    try:
        service.execute(ctx, row["id"])
    except (HTTPException, PermissionError):
        pass
    assert tickets.creates == 0


def test_stock_worker_denies_suspended_tenant(stock_workspace):
    from maverick.paths import tenant_scope
    from maverick.tenant import registry
    from maverick_dashboard import vendor_onboarding_composition as composition

    service, ctx, row, tickets, request = stock_workspace
    registry.suspend_tenant(ctx.tenant)
    with tenant_scope(tenant=ctx.tenant), pytest.raises(HTTPException):
        composition._context(request)
    with pytest.raises(HTTPException):
        service.execute(ctx, row["id"])
    assert tickets.creates == 0


def test_current_workspace_can_accept_existing_effect_after_switch_back(stock_workspace):
    from maverick.paths import tenant_scope
    from maverick_dashboard import vendor_onboarding_composition as composition
    from maverick_dashboard import workspace_tenants

    service, ctx, row, tickets, request = stock_workspace
    row = service.execute(ctx, row["id"])
    workspace_tenants.set_selection(ctx.actor, "synthetic-b")
    workspace_tenants.set_selection(ctx.actor, ctx.tenant)
    with tenant_scope(tenant=ctx.tenant):
        current = composition._context(request)
    accepted = service.accept(current, row["id"], row["revision"], True, "Verified deliverable")
    assert accepted["outcome"]["accepted"] is True
    assert tickets.creates == 1


def test_stock_cancellation_denies_revoked_membership_without_changing_effect(stock_workspace):
    from maverick_dashboard import rbac

    service, ctx, row, tickets, _ = stock_workspace
    row = service.execute(ctx, row["id"])
    rbac.remove_tenant_role(ctx.tenant, ctx.actor)
    with pytest.raises(HTTPException):
        service.cancel(ctx, row["id"], row["revision"], "Revoked member")
    from maverick import vendor_onboarding
    from maverick.paths import tenant_scope

    with tenant_scope(tenant=ctx.tenant):
        persisted = vendor_onboarding._CASES.get(row["id"])
    assert persisted["revision"] == row["revision"]
    assert not persisted.get("cancellation")
    assert tickets.creates == 1


def test_current_workspace_can_cancel_and_reconcile_after_switch_back(stock_workspace):
    from maverick.paths import tenant_scope
    from maverick_dashboard import vendor_onboarding_composition as composition
    from maverick_dashboard import workspace_tenants

    service, ctx, row, tickets, request = stock_workspace
    tickets.timeout_after_success = True
    row = service.execute(ctx, row["id"])
    workspace_tenants.set_selection(ctx.actor, "synthetic-b")
    workspace_tenants.set_selection(ctx.actor, ctx.tenant)
    with tenant_scope(tenant=ctx.tenant):
        current = composition._context(request)
    assert current.binding() != ctx.binding()
    cancelled = service.cancel(current, row["id"], row["revision"], "Stop after switching back")
    assert cancelled["operation"]["context"] == row["operation"]["context"]
    assert cancelled["cancellation"]["authority"] == current.binding()
    reconciled = service.reconcile(current, row["id"])
    assert reconciled["work_item"]["technical_effect"] == "verified"
    assert reconciled["cancellation"] == cancelled["cancellation"]
    assert tickets.creates == 1


@pytest.mark.parametrize("step", ["approve-action", "execute"])
def test_precondition_provider_errors_are_not_disclosed_in_reapproval_response(web, monkeypatch, step):
    client, service, _, tickets = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    row = _step(client, row, "review", decision="approved", rationale="Reviewed evidence")
    row = _step(client, row, "prepare-action")
    if step == "execute":
        row = _step(client, row, "approve-action", confirm=True)

    def unavailable(*args):
        raise ValueError("Authorization: synthetic-private-provider-value")

    monkeypatch.setattr(service.documents, "head", unavailable)
    body = {"expected_revision": row["revision"], "confirm": True}
    if step == "approve-action":
        body["approval_binding_sha256"] = row["operation"]["approval_card"][
            "binding_sha256"
        ]
    response = client.post(f"{BASE}/{row['id']}/{step}", json=body)
    assert response.status_code == 409, response.text
    assert "synthetic-private-provider-value" not in response.text
    assert response.json()["detail"]["code"] == "approval_preconditions_changed"
    assert tickets.creates == 0


@pytest.mark.parametrize("source", ["config", "dashboard", "environment"])
def test_stock_budget_policy_change_requires_new_action_review(stock_workspace, monkeypatch, tmp_path, source):
    import os
    from pathlib import Path

    from maverick import runtime_overrides
    from maverick.paths import tenant_scope
    from maverick_dashboard import vendor_onboarding_composition as composition

    service, ctx, row, tickets, request = stock_workspace
    if source == "config":
        path = Path(os.environ["MAVERICK_CONFIG"])
        path.write_text(path.read_text(encoding="utf-8") + "\n[budget]\nmax_tool_calls=10\n", encoding="utf-8")
        config.reset_config_cache()
    elif source == "dashboard":
        monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
        runtime_overrides.set_budget(0.01)
    else:
        monkeypatch.setenv("MAVERICK_BUDGET_DOLLARS", "0.02")
    with tenant_scope(tenant=ctx.tenant):
        current = composition._context(request)
    assert current.budget_authority != ctx.budget_authority
    with pytest.raises(PermissionError) as rejected:
        service.execute(current, row["id"])
    assert rejected.value.code == "approval_authority_changed"
    assert service.get(current, row["id"])["operation"] is None
    assert tickets.creates == 0


def test_role_authority_changes_with_custom_permission_policy(monkeypatch):
    from maverick_dashboard import rbac
    from maverick_dashboard import vendor_onboarding_composition as composition

    permissions = [{"operate", "view"}]
    monkeypatch.setattr(rbac, "permissions_for", lambda _role: frozenset(permissions[0]))
    before = composition._role_authority("customer-operator")
    permissions[0] = {"operate", "view", "audit"}
    after = composition._role_authority("customer-operator")
    assert after != before


def test_workspace_authority_changes_after_switch_away_and_back(monkeypatch):
    from types import SimpleNamespace

    from maverick_dashboard import vendor_onboarding_composition as composition
    from maverick_dashboard import workspace_tenants

    request = SimpleNamespace(state=SimpleNamespace(workspace_tenant_source="principal_selection"))
    binding = ["tenant-a", 1]
    monkeypatch.setattr(
        workspace_tenants,
        "get_selection_binding",
        lambda _principal: tuple(binding),
    )
    before = composition._workspace_authority(request, "user:reviewer", "tenant-a")
    binding[1] = 3
    after = composition._workspace_authority(request, "user:reviewer", "tenant-a")
    assert after != before
    binding[0] = "tenant-b"
    with pytest.raises(HTTPException, match="Workspace changed") as rejected:
        composition._workspace_authority(request, "user:reviewer", "tenant-a")
    assert rejected.value.status_code == 409


def test_model_context_cannot_review(web, monkeypatch):
    client, service, ctx, _ = web
    row = _step(client, _step(client, _intake(client), "collect-evidence"), "assess")
    machine = replace(ctx, human=False)
    service.authorize = lambda c, cap, res: c.actor == ctx.actor
    monkeypatch.setattr(app.state, "vendor_onboarding_binding_factory",
                        lambda request: WorkflowBinding(service, machine))
    response = client.post(f"{BASE}/{row['id']}/review", json={
        "expected_revision": row["revision"], "decision": "approved", "rationale": "Model says so"})
    assert response.status_code == 403


def test_existing_dashboard_page_and_asset_are_usable(web):
    client, *_ = web
    response = client.get("/third-party/vendor-onboarding")
    assert response.status_code == 200, response.text
    from test_support.plain_language import developer_terms, visible_text

    page_text = visible_text(response.text)
    assert "Human review" in page_text
    assert "Approve this exact Jira task" in page_text
    assert "What this request delivers" in page_text
    assert "Cancel local work" in page_text
    assert "any Jira ticket already created remains" in page_text
    assert developer_terms(response.text) == []
    for gone in ("file IDs", "SHA-256", "JSON export", "No OCR", "MiB"):
        assert gone not in page_text
    assert "no-store" in response.headers["cache-control"]
    asset = client.get("/static/lightwork-vendor-onboarding.js")
    assert asset.status_code == 200
    assert "textContent" in asset.text
    assert "innerHTML" not in asset.text


def test_offline_demonstration_page_renders_its_request_form(web, monkeypatch):
    """The demonstration hides setup, but the request form still has its error summary."""
    client, *_ = web
    monkeypatch.setattr(client.app.state, "vendor_onboarding_demo", True, raising=False)
    response = client.get("/third-party/vendor-onboarding")
    assert response.status_code == 200, response.text[:500]
    assert "Offline simulation." in response.text
    assert 'id="vo-intake-errors"' in response.text and 'id="vs-form"' not in response.text


def test_vendor_page_gives_local_operator_an_individual_signin_path(web, monkeypatch):
    client, *_ = web
    monkeypatch.setattr("maverick_dashboard.vendor_onboarding_page.caller_principal", lambda _request: None)
    monkeypatch.setattr("maverick_dashboard.vendor_onboarding_page.local_owner_setup_available", lambda _request: True)
    response = client.get("/third-party/vendor-onboarding")
    assert response.status_code == 200
    assert 'data-named-signin="false"' in response.text
    assert "Set up individual sign-ins for vendor reviews" in response.text
    assert 'href="/auth/local-owner"' in response.text
    assert 'href="/users"' in response.text


def test_vendor_page_without_workspace_shows_workspace_picker(web, monkeypatch):
    client, *_ = web
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(
        "maverick_dashboard.vendor_onboarding_page.current_tenant_id_strict",
        lambda: None,
    )
    response = client.get(
        "/third-party/vendor-onboarding", headers={"Accept": "text/html"}
    )
    assert response.status_code == 409
    assert "Choose a workspace" in response.text
    assert "Refresh before continuing" not in response.text


def test_vendor_page_has_one_main_landmark_and_labelled_decision_fields(web):
    class Markup(HTMLParser):
        def __init__(self):
            super().__init__()
            self.elements = []

        def handle_starttag(self, tag, attrs):
            self.elements.append((tag, dict(attrs)))

    client, *_ = web
    response = client.get("/third-party/vendor-onboarding")
    assert response.status_code == 200, response.text
    markup = Markup()
    markup.feed(response.text)
    main = [attrs for tag, attrs in markup.elements if tag == "main"]
    assert len(main) == 1
    assert main[0]["id"] == "content"
    root = next((tag, attrs) for tag, attrs in markup.elements if attrs.get("id") == "vendor-onboarding")
    assert root[0] == "section"
    assert root[1]["aria-labelledby"] == "vo-title"
    ids = [attrs["id"] for _, attrs in markup.elements if "id" in attrs]
    assert len(ids) == len(set(ids)), "Duplicate IDs break labels and request controls"
    label_targets = {attrs.get("for") for tag, attrs in markup.elements if tag == "label"}
    for field in ("vo-rationale", "vo-acceptance-reason", "vo-vendor", "vo-document",
                  "vo-project", "vo-purpose", "vo-freshness", "vo-due", "vo-renewal",
                  "vo-case-project", "vo-case-purpose", "vo-case-freshness", "vo-case-due",
                  "vo-cancellation-reason", "vo-case-filter"):
        assert field in label_targets
    assert {"vo-page-previous", "vo-page-next", "vo-page-status"}.issubset(ids)
    message = next(attrs for _, attrs in markup.elements if attrs.get("id") == "vo-message")
    assert message["aria-live"] == "polite"
