"""Legal matter isolation, lifecycle and exact reviewed worker execution."""
from __future__ import annotations

import json
import secrets

import pytest
from maverick import audit, config, governed_records
from maverick.governed_records import RecordConflict
from maverick.legal_workforce_catalog import ROLES
from maverick.legal_workspace import STORE, LegalService
from maverick.paths import tenant_scope

MATTER = {"title": "Acme supplier renewal", "area": "commercial", "objective": "Assess renewal options",
          "department": "Procurement", "business_owner": "Taylor", "jurisdiction": "Tennessee"}
SOURCE = {"title": "Executed supplier agreement", "kind": "agreement", "reference": "Agreement §4",
          "text": "Give notice by 2027-01-01. Liability is capped at fees paid.", "status": "executed"}


@pytest.fixture
def legal(tmp_path, monkeypatch):
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "state"))
    settings = tmp_path / "config.toml"
    settings.write_text("[legal_workspace]\nenable = true\n[enterprise]\nenable = false\n")
    monkeypatch.setenv("MAVERICK_CONFIG", str(settings))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    for key in ("MAVERICK_TENANT", "MAVERICK_GOVERNED_RECORDS_BACKEND", "MAVERICK_REPLICA_COUNT", "MAVERICK_PG_DSN", "MAVERICK_WORLD_BACKEND"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    config.reset_config_cache()
    with tenant_scope(tenant="legal-a"):
        service = LegalService("legal-a", "user:counsel", human=True, authorize=lambda: True)
        yield service
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def execute(service, action, args, row=None, key=None):
    material = service.prepare(action, args, row["id"] if row else "")
    return service.execute(material, key or secrets.token_hex(16))


def setup_matter(service):
    row = execute(service, "create_matter", MATTER)
    return execute(service, "source", SOURCE, row)


def assignment(service, row, role="commercial_associate"):
    return execute(service, "assignment", {"role_id": role, "title": "Review agreement", "instructions": "Explain the liability provision",
                   "source_ids": [row["sources"][0]["id"]]}, row)


def test_nine_roles_have_distinct_supported_deliverables():
    assert len(ROLES) == 9
    assert sum(role["level"] == "paralegal" for role in ROLES) == 4
    assert len({role["id"] for role in ROLES}) == 9
    assert all(role["deliverable"] and role["instructions"] for role in ROLES)


def test_create_is_durable_idempotent_and_receipt_is_not_public(legal):
    material = legal.prepare("create_matter", MATTER)
    first = legal.execute(material, "create-one")
    again = legal.execute(material, "create-one")
    assert first == again
    assert len(legal.list_matters()) == 1
    assert "_operations" not in first
    assert STORE.get(first["id"])["_operations"]["create-one"]


def test_matter_acl_is_not_bypassed_by_tenant_or_admin_style_access(legal):
    row = setup_matter(legal)
    other = LegalService("legal-a", "user:other-admin", human=True, authorize=lambda: True)
    assert other.list_matters() == []
    with pytest.raises(PermissionError):
        other.get(row["id"])
    execute(legal, "access", {"principal": "user:other-admin", "grant": True}, row)
    assert other.get(row["id"])["title"] == MATTER["title"]
    with pytest.raises(PermissionError):
        other.prepare("edit_matter", {**MATTER, "status": "active"}, row["id"])
    execute(legal, "access", {"principal": "user:other-admin", "grant": False}, row)
    with pytest.raises(PermissionError):
        other.get(row["id"])


def test_cross_tenant_read_and_write_refused(legal):
    row = setup_matter(legal)
    with tenant_scope(tenant="legal-b"):
        other = LegalService("legal-b", "user:counsel", human=True, authorize=lambda: True)
        assert other.list_matters() == []
        with pytest.raises(PermissionError):
            other.get(row["id"])
        with pytest.raises(PermissionError):
            legal.list_matters()


def test_stale_review_does_not_overwrite_new_work(legal):
    row = setup_matter(legal)
    review = legal.prepare("source", {**SOURCE, "title": "Second source"}, row["id"])
    execute(legal, "source", {**SOURCE, "title": "Third source"}, row)
    with pytest.raises(RecordConflict):
        legal.execute(review, "stale")
    assert len(legal.get(row["id"])["sources"]) == 2


def test_machine_cannot_approve_or_create_matter(legal):
    machine = LegalService("legal-a", "user:counsel", human=False, authorize=lambda: True)
    with pytest.raises(PermissionError):
        machine.prepare("create_matter", MATTER)


def test_obligations_require_exact_source_and_human_confirmation(legal):
    row = setup_matter(legal)
    args = {"title": "Notice", "source_id": row["sources"][0]["id"], "quote": "Give notice by 2027-01-01.",
            "owner": "Taylor", "due_date": "2027-01-01", "basis": "Express contractual notice date"}
    with pytest.raises(ValueError):
        execute(legal, "obligation", {**args, "quote": "Not in agreement"}, row)
    with pytest.raises(ValueError):
        execute(legal, "obligation", {**args, "due_date": "2027-02-30"}, row)
    row = execute(legal, "obligation", args, row)
    identity = row["obligations"][0]["id"]
    with pytest.raises(ValueError):
        execute(legal, "review_obligation", {"obligation_id": identity, "state": "completed", "reason": "Done"}, row)
    row = execute(legal, "review_obligation", {"obligation_id": identity, "state": "confirmed", "reason": "Counsel verified the clause and date"}, row)
    assert row["obligations"][0]["reviewed_by"] == "user:counsel"


def test_engagement_clearance_budget_invoice_exceptions_and_duplicate(legal):
    row = setup_matter(legal)
    row = execute(legal, "engagement", {"firm": "Example firm", "contact": "Counsel", "scope": "Assess termination",
                  "deliverables": "Options memo", "budget": 1000, "max_hourly_rate": 300}, row)
    identity = row["engagements"][0]["id"]
    with pytest.raises(ValueError):
        execute(legal, "review_engagement", {"engagement_id": identity, "state": "approved", "note": "Approved"}, row)
    for state in ("conflicts_cleared", "approved"):
        row = execute(legal, "review_engagement", {"engagement_id": identity, "state": state, "note": "Recorded by counsel"}, row)
    invoice = {"engagement_id": identity, "reference": "INV-1", "amount": 1100, "hourly_rate": 400, "description": "Memo preparation"}
    row = execute(legal, "invoice", invoice, row)
    assert len(row["invoices"][0]["exceptions"]) == 2
    with pytest.raises(ValueError, match="already recorded"):
        execute(legal, "invoice", invoice, row)
    assert legal.overview()["spend"]["USD"] == {"budget": 100000, "invoiced": 110000}
    assert {entry["kind"] for entry in legal.overview()["attention"]} >= {"invoices", "budget"}


def test_contract_requires_separate_approvals_before_execution(legal):
    row = setup_matter(legal)
    args = {"title": "Acme agreement", "counterparty": "Acme", "source_id": row["sources"][0]["id"], "commercial_owner": "Taylor"}
    row = execute(legal, "contract", args, row)
    contract = row["contracts"][0]["id"]
    with pytest.raises(ValueError, match="approvals"):
        execute(legal, "edit_contract", {**args, "contract_id": contract, "stage": "executed"}, row)
    for kind in ("legal", "commercial", "signing"):
        row = execute(legal, "decision", {"kind": kind, "title": kind + " approval", "owner": "Taylor", "options": "Accept terms", "contract_id": contract}, row)
        row = execute(legal, "review_decision", {"decision_id": row["decisions"][-1]["id"], "state": "approved", "reason": "Authority confirmed"}, row)
    row = execute(legal, "edit_contract", {**args, "contract_id": contract, "stage": "executed"}, row)
    assert row["contracts"][0]["stage"] == "executed"
    row = execute(legal, "source", {**SOURCE, "text": "An entirely different executed agreement."}, row)
    with pytest.raises(ValueError, match="approvals"):
        execute(legal, "edit_contract", {**args, "contract_id": contract, "source_id": row["sources"][-1]["id"], "stage": "executed"}, row)


@pytest.mark.parametrize("role", [role["id"] for role in ROLES])
def test_each_worker_runs_only_selected_evidence_once_and_requires_review(legal, monkeypatch, role):
    from maverick import legal_workspace_runtime as runtime
    from maverick.llm import LLMResponse
    row = setup_matter(legal)
    row = execute(legal, "source", {**SOURCE, "title": "Excluded record", "text": "This evidence must not enter the provider packet."}, row)
    row = assignment(legal, row, role)
    calls = []
    monkeypatch.setattr(config, "any_provider_configured", lambda: True)

    def complete(_client, **kwargs):
        kwargs["dispatch_guard"]()
        packet = json.loads(kwargs["messages"][0]["content"])
        calls.append(packet)
        assert len(packet["sources"]) == 1
        assert "must not enter" not in json.dumps(packet)
        assert kwargs["tools"] == [] and kwargs["max_physical_attempts"] == 1
        source = packet["sources"][0]
        result = {"summary": "Review prepared", "draft": "Consider the limitation of liability.", "questions": ["Is there an approved playbook?"],
                  "findings": [{"claim": "Liability cap", "source_id": source["id"], "quote": "Liability is capped at fees paid."}]}
        return LLMResponse(json.dumps(result), None, [], "end_turn")
    monkeypatch.setattr(runtime.LLM, "complete", complete)
    material = legal.prepare("run", {"assignment_id": row["assignments"][0]["id"]}, row["id"])
    result = legal.execute(material, "run-once")
    assert result["assignments"][0]["state"] == "awaiting_review"
    legal.execute(material, "run-once")
    assert len(calls) == 1
    accepted = execute(legal, "review_assignment", {"assignment_id": result["assignments"][0]["id"], "state": "accepted", "note": "Verified all source passages and legal analysis"}, result)
    assert accepted["assignments"][0]["state"] == "accepted"


def test_bad_citation_is_flagged_and_cannot_be_accepted(legal, monkeypatch):
    from maverick import legal_workspace_runtime as runtime
    from maverick.llm import LLMResponse
    row = assignment(legal, setup_matter(legal))
    monkeypatch.setattr(config, "any_provider_configured", lambda: True)
    output = {"summary": "Draft", "draft": "Unsupported finding", "findings": [{"claim": "Invented", "source_id": "other-matter", "quote": "Invented"}], "questions": []}
    monkeypatch.setattr(runtime.LLM, "complete", lambda *args, **kwargs: LLMResponse(json.dumps(output), None, [], "end_turn"))
    row = execute(legal, "run", {"assignment_id": row["assignments"][0]["id"]}, row)
    assert row["assignments"][0]["citation_errors"]
    with pytest.raises(ValueError, match="citations"):
        execute(legal, "review_assignment", {"assignment_id": row["assignments"][0]["id"], "state": "accepted", "note": "Accept"}, row)


def test_cancellation_during_provider_call_drops_late_draft(legal, monkeypatch):
    from maverick import legal_workspace_runtime as runtime
    from maverick.llm import LLMResponse
    row = assignment(legal, setup_matter(legal))
    monkeypatch.setattr(config, "any_provider_configured", lambda: True)
    def complete(*_args, **_kwargs):
        execute(legal, "review_assignment", {"assignment_id": row["assignments"][0]["id"], "state": "cancelled", "note": "Scope changed"}, row)
        return LLMResponse("{}", None, [], "end_turn")
    monkeypatch.setattr(runtime.LLM, "complete", complete)
    result = execute(legal, "run", {"assignment_id": row["assignments"][0]["id"]}, row)
    assert result["assignments"][0]["state"] == "cancelled"
    assert not result["assignments"][0].get("output")


def test_overview_excludes_restricted_matters_and_tracks_unresolved_work(legal):
    row = assignment(legal, setup_matter(legal))
    with pytest.raises(ValueError, match="Resolve"):
        execute(legal, "edit_matter", {**MATTER, "status": "closed"}, row)
    overview = legal.overview()
    assert overview["workers"][4]["assignments"] == 1
    other = LegalService("legal-a", "user:other", human=True, authorize=lambda: True)
    assert other.overview()["matters"] == []
    assert other.overview()["attention"] == []


def test_counsel_packet_export_contains_only_explicitly_selected_sources(legal):
    row = setup_matter(legal)
    original_source = row["sources"][0]["id"]
    row = execute(legal, "source", {**SOURCE, "title": "Internal strategy", "text": "Do not disclose this strategy to outside counsel."}, row)
    terms = {"firm": "Example firm", "contact": "Counsel", "scope": "Assess termination",
             "deliverables": "Options memo", "budget": 1000, "max_hourly_rate": 300}
    row = execute(legal, "engagement", terms, row)
    engagement = row["engagements"][0]["id"]
    packet = {"engagement_id": engagement, "title": "Counsel packet", "instructions": "Evaluate our options", "source_ids": [original_source]}
    with pytest.raises(ValueError, match="Approve"):
        execute(legal, "packet", packet, row)
    for state in ("conflicts_cleared", "approved"):
        row = execute(legal, "review_engagement", {"engagement_id": engagement, "state": state, "note": "Confirmed by counsel"}, row)
    row = execute(legal, "packet", packet, row)
    exported = legal.export(row["id"], row["packets"][0]["id"])
    assert [source["id"] for source in exported["sources"]] == [original_source]
    assert "Do not disclose" not in json.dumps(exported)
    row = execute(legal, "edit_engagement", {**terms, "engagement_id": engagement, "budget": 2000}, row)
    assert row["engagements"][0]["state"] == "proposed"
    assert row["engagements"][0]["versions"][0]["budget"] == 100000


def test_failed_provider_attempt_is_retained_without_automatic_retry(legal, monkeypatch):
    from maverick import legal_workspace_runtime as runtime
    row = assignment(legal, setup_matter(legal))
    monkeypatch.setattr(config, "any_provider_configured", lambda: True)
    calls = []
    def fail(*_args, **_kwargs):
        calls.append(True)
        raise RuntimeError("private provider detail must never be shown")
    monkeypatch.setattr(runtime.LLM, "complete", fail)
    material = legal.prepare("run", {"assignment_id": row["assignments"][0]["id"]}, row["id"])
    result = legal.execute(material, "failed-once")
    assert result["assignments"][0]["state"] == "failed"
    assert "private provider detail" not in json.dumps(result)
    legal.execute(material, "failed-once")
    assert len(calls) == 1


def test_access_audit_failure_does_not_release_matter_details(legal, monkeypatch):
    row = setup_matter(legal)
    monkeypatch.setattr(audit, "audit_event", lambda *args, **kwargs: False)
    with pytest.raises(RuntimeError, match="access"):
        legal.get(row["id"])
    with pytest.raises(RuntimeError, match="access"):
        legal.overview()


def test_revoked_authority_prevents_prepared_worker_from_dispatching(legal, monkeypatch):
    row = assignment(legal, setup_matter(legal))
    monkeypatch.setattr(config, "any_provider_configured", lambda: True)
    material = legal.prepare("run", {"assignment_id": row["assignments"][0]["id"]}, row["id"])
    legal.authorize = lambda: False
    with pytest.raises(PermissionError):
        legal.execute(material, "revoked")


def test_budget_clamps_to_existing_workspace_limits(monkeypatch):
    from maverick.legal_workspace_runtime import _budget
    monkeypatch.setattr(config, "get_budget_overrides", lambda: {"max_dollars": 0.5, "max_wall_seconds": 60})
    budget = _budget({"max_dollars": 10, "max_seconds": 300})
    assert budget.max_dollars == 0.5
    assert budget.max_wall_seconds == 60
    assert budget.max_tool_calls == 0
