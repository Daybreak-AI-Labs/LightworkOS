"""Executable restricted renewal flow, promotion, rollback and changed-state fallback."""
from __future__ import annotations

from dataclasses import replace

import pytest
from maverick import config
from maverick.flow import store
from maverick.governed_operations import ServiceContext, digest
from maverick.paths import tenant_scope
from maverick.vendor_evidence_evolution import BINDINGS, EvidenceRenewalEvolution


def inputs(**changes):
    return dict({"due_at": 2_000_000_000.0, "now": 1_999_000_000.0,
                 "evidence_status": "available", "source_version": "doc-v1",
                 "expected_source_version": "doc-v1", "downstream_version": "ticket-v1",
                 "expected_downstream_version": "ticket-v1", "customer_accepted": True}, **changes)


def held_out():
    cases = [
        ("fresh", "held_out", inputs(now=1_999_999_000.0), "fresh", BINDINGS),
        ("boundary", "changed_inputs", inputs(now=2_000_000_000.0), "renewal_due", BINDINGS),
        ("overdue", "held_out", inputs(now=2_000_000_500.0), "renewal_due", BINDINGS),
        ("source-change", "changed_inputs", inputs(source_version="doc-v99", now=1_999_999_001.0),
         "human_fallback", BINDINGS),
        ("downstream-change", "changed_downstream", inputs(downstream_version="ticket-v99"),
         "human_fallback", BINDINGS),
        ("invalid-binding", "invalid_bindings", inputs(now=1_999_999_002.0),
         "human_fallback", {"due_at": "now", "now": "due_at"}),
        ("invalid-time", "invalid_inputs", inputs(now="not-a-timestamp"), "human_fallback", BINDINGS),
        ("unaccepted", "held_out", inputs(customer_accepted=False), "human_fallback", BINDINGS),
    ]
    return [{"id": key, "category": category, "inputs": values, "expected": expected,
             "bindings": bindings, "material": "internally_authored_synthetic"}
            for key, category, values, expected, bindings in cases]


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text("[vendor_onboarding]\nenable=true\n[flows]\nenable=true\n"
                                           "[vendor_management]\nenable=true\n[ai_vendor_risk]\nenable=true\n"
                                           "[model_risk_assurance]\nenable=true\n",
                                           encoding="utf-8")
    config.reset_config_cache()
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    monkeypatch.setattr(audit, "record_global", lambda *a, **kw: True)
    ctx = ServiceContext("customer-a", "human@example.test", "procurement",
                         "human@example.test", "jira", human=True)
    evolution = EvidenceRenewalEvolution(lambda *args: True)
    yield evolution, ctx
    config.reset_config_cache()


def proposal(evolution, ctx):
    observations = []
    for index, now in enumerate((1_999_000_001.0, 1_999_000_002.0, 2_000_001_000.0)):
        row = evolution.observe(ctx, inputs(now=now), "fresh" if now < 2_000_000_000 else "renewal_due",
                                source_case_id=f"synthetic-reviewed-case-{index}",
                                source_workflow_version="baseline-agent-v1",
                                rationale="Internally authored synthetic review observation")
        observations.append(row["id"])
    return evolution.propose(ctx, observations, bindings=BINDINGS,
                             rationale="Reviewed both time bindings and unchanged-source prerequisite")


def evaluated(evolution, ctx):
    candidate = proposal(evolution, ctx)
    return evolution.evaluate(ctx, candidate["id"], held_out())


def promoted(evolution, ctx):
    candidate = evaluated(evolution, ctx)
    return evolution.promote(ctx, candidate["id"], candidate["revision"],
                             rationale="Human approves this restricted definition")


def test_actual_flow_runs_only_after_human_promotion_and_persists_across_restart(setup):
    evolution, ctx = setup
    candidate = evaluated(evolution, ctx)
    assert candidate["evaluation"]["passed"] == candidate["evaluation"]["n"] == 8
    assert candidate["evaluation"]["model_calls"] == 0
    assert candidate["evaluation"]["candidate_seconds"] > 0
    assert candidate["evaluation"]["baseline_seconds"] > 0
    assert evolution.run(ctx, inputs())["classification"] == "human_fallback"
    with pytest.raises(PermissionError):
        evolution.promote(replace(ctx, human=False), candidate["id"], candidate["revision"], rationale="Model approves")
    active = evolution.promote(ctx, candidate["id"], candidate["revision"], rationale="Reviewed exact version")
    assert active["active"]["version"] == 2
    restart = EvidenceRenewalEvolution(lambda *a: True)
    result = restart.run(ctx, inputs())
    assert result["classification"] == "fresh"
    assert result["workflow_version"] == 2
    assert restart.run(ctx, inputs(now=2_000_000_000.0))["classification"] == "renewal_due"
    with tenant_scope(tenant=ctx.tenant):
        versions = store.list_versions(active["active"]["flow_id"])
        assert [v.version for v in versions] == [1, 2]
        assert versions[0].nodes[versions[0].start].kind == "agent"
        assert versions[1].nodes[versions[1].start].kind == "scope"


def test_rollback_restores_agent_definition_as_new_version(setup):
    evolution, ctx = setup
    active = promoted(evolution, ctx)
    rolled_back = evolution.rollback(ctx, active["revision"], rationale="Return this step to human review")
    assert rolled_back["active"] is None
    assert evolution.run(ctx, inputs())["classification"] == "human_fallback"
    with tenant_scope(tenant=ctx.tenant):
        restored = store.load_flow(active["active"]["flow_id"])
        assert restored.version == 3
        assert restored.nodes[restored.start].kind == "agent"


def test_promoted_provenance_retains_exact_review_after_later_evaluation(setup):
    from maverick import vendor_evidence_evolution as renewal

    evolution, ctx = setup
    candidate = evaluated(evolution, ctx)
    activated = evolution.promote(ctx, candidate["id"], candidate["revision"],
                                  rationale="Approve this exact evaluation and reviewed bindings")
    approval = activated["active"]
    assert approval["candidate_revision"] == candidate["revision"]
    assert approval["evaluation_sha256"] == digest(candidate["evaluation"])
    assert approval["bindings_sha256"] == digest(candidate["bindings"])

    # A later evaluation adds evidence to the candidate record; it must not
    # silently rewrite which report the human approved for this activation.
    cases = held_out()
    cases.append({"id": "additional-fresh-case", "category": "held_out",
                  "inputs": inputs(now=1_999_999_123.0), "expected": "fresh",
                  "bindings": BINDINGS, "material": "internally_authored_synthetic"})
    reevaluated = evolution.evaluate(ctx, candidate["id"], cases)
    assert reevaluated["revision"] > approval["candidate_revision"]
    assert digest(reevaluated["evaluation"]) != approval["evaluation_sha256"]
    with tenant_scope(tenant=ctx.tenant):
        persisted = renewal._ACTIVE.get("VEA-current")
    assert persisted["active"] == approval
    assert persisted["revision"] == activated["revision"]
    assert evolution.run(ctx, inputs())["classification"] == "fresh"


@pytest.mark.parametrize("changes", [
    {"source_version": "changed"}, {"downstream_version": "changed"},
    {"evidence_status": "unavailable"}, {"customer_accepted": False},
    {"now": "tomorrow"}, {"now": True}, {"due_at": float("nan")},
    {"unexpected_permission": "write_jira"},
])
def test_changed_or_invalid_inputs_keep_human_fallback(setup, changes):
    evolution, ctx = setup
    promoted(evolution, ctx)
    assert evolution.run(ctx, inputs(**changes))["classification"] == "human_fallback"


def test_changed_saved_definition_cannot_expand_candidate_permissions(setup):
    evolution, ctx = setup
    active = promoted(evolution, ctx)
    with tenant_scope(tenant=ctx.tenant):
        flow = store.load_flow(active["active"]["flow_id"])
        flow.nodes[flow.start].body.nodes["renew"].assignments = {"classification": "fresh"}
        store.save_flow(flow, expected_version=2)
    assert evolution.run(ctx, inputs())["classification"] == "human_fallback"


def test_failed_or_overlapping_evaluation_cannot_be_promoted(setup):
    evolution, ctx = setup
    candidate = proposal(evolution, ctx)
    with pytest.raises(ValueError, match="passing held-out"):
        evolution.promote(ctx, candidate["id"], candidate["revision"], rationale="Premature")
    cases = held_out()
    cases[0]["inputs"] = inputs(now=1_999_000_001.0)
    with pytest.raises(ValueError, match="overlap"):
        evolution.evaluate(ctx, candidate["id"], cases)
    cases = held_out()
    cases[0]["expected"] = "renewal_due"
    candidate = evolution.evaluate(ctx, candidate["id"], cases)
    assert candidate["evaluation"]["passed"] == 7
    with pytest.raises(ValueError, match="passing held-out"):
        evolution.promote(ctx, candidate["id"], candidate["revision"], rationale="Failed evaluation")


def test_cross_customer_candidate_and_activation_are_inaccessible(setup):
    evolution, ctx = setup
    candidate = evaluated(evolution, ctx)
    other = replace(ctx, tenant="customer-b")
    with pytest.raises(KeyError):
        evolution.promote(other, candidate["id"], candidate["revision"], rationale="Cross customer")
    assert evolution.run(other, inputs())["classification"] == "human_fallback"


def test_invalid_bindings_cannot_be_inferred_from_tool_name(setup):
    evolution, ctx = setup
    with pytest.raises(ValueError, match="typed bindings"):
        evolution.propose(ctx, [], bindings={"tool": "date_time"}, rationale="Tool name alone")


def test_evaluation_rejects_customer_material_for_reusable_cases(setup):
    evolution, ctx = setup
    candidate = proposal(evolution, ctx)
    cases = held_out()
    cases[0]["material"] = "another_customer_records"
    with pytest.raises(ValueError, match="internally authored"):
        evolution.evaluate(ctx, candidate["id"], cases)


def test_flow_config_remains_authoritative_after_human_promotion(setup, monkeypatch):
    evolution, ctx = setup
    promoted(evolution, ctx)
    monkeypatch.setenv("MAVERICK_FLOWS", "0")
    result = evolution.run(ctx, inputs())
    assert result["classification"] == "human_fallback"
    assert result["reason"] == "flow execution disabled"
    candidate = evaluated(evolution, ctx)
    with pytest.raises(RuntimeError, match="flows"):
        evolution.promote(ctx, candidate["id"], candidate["revision"], rationale="Cannot override operator switch")


@pytest.fixture
def accepted_workflow(setup):
    from maverick.vendor_onboarding import VendorOnboardingService
    from maverick.vendor_onboarding_adapters import (
        EvidenceDocument,
        FakeGoogleDriveEvidence,
        FakeJiraTickets,
    )

    evolution, ctx = setup
    now = [1_999_000_000.0]
    evolution.clock = lambda: now[0]
    docs = FakeGoogleDriveEvidence({(ctx.tenant, "security-paper"): EvidenceDocument(
        "security-paper", "provider-source-v1", now[0] - 100,
        b"Data is encrypted at rest and in transit. We do not train models on customer data.",
    )})
    tickets = FakeJiraTickets()
    service = VendorOnboardingService(docs, tickets, evolution.authorize, clock=lambda: now[0])
    case = service.intake(ctx, "Synthetic accepted vendor", "security-paper", "VEND", "Reviewed renewal case",
                          freshness_days=1)
    case = service.collect_evidence(ctx, case["id"], case["revision"])
    case = service.assess(ctx, case["id"], case["revision"])
    case = service.review(ctx, case["id"], case["revision"], "approved", "Restricted synthetic pilot")
    case = service.prepare_action(ctx, case["id"], case["revision"])
    case = service.approve_action(
        ctx,
        case["id"],
        case["revision"],
        case["operation"]["approval_card"]["binding_sha256"],
    )
    case = service.execute(ctx, case["id"])
    case = service.accept(ctx, case["id"], case["revision"], True, "Synthetic customer acceptance")
    return evolution, ctx, service, case, docs, tickets, now


def test_observe_case_derives_versions_digests_and_domain_identity(accepted_workflow):
    evolution, ctx, service, case, docs, tickets, now = accepted_workflow
    with tenant_scope(tenant="untrusted-ambient-tenant"):
        observation = evolution.observe_case(ctx, service, case["id"], "fresh", rationale="Human checked renewal")
    assert observation["capture_origin"] == "accepted_vendor_case"
    assert observation["source_case_id"] == case["id"]
    assert observation["source_case_revision"] == case["revision"]
    assert observation["source_workflow_version"] == case["outcome"]["workflow_schema"]
    assert observation["evidence_sha256"] == case["outcome"]["evidence_sha256"]
    assert observation["assessment_id"] == case["assessment"]["id"]
    assert observation["assessment_revision"] == case["assessment"]["revision"]
    assert observation["assessment_sha256"] == case["assessment"]["assessment_sha256"]
    assert observation["inputs"]["due_at"] == case["outcome"]["renewal_due_at"]
    assert observation["inputs"]["source_version"] == "provider-source-v1"
    assert observation["inputs"]["now"] == now[0]
    assert observation["external_confirmation"]["verified"] is True
    assert observation["source_provenance_sha256"] == digest({
        key: observation[key] for key in (
            "capture_origin", "source_case_id", "source_case_revision", "source_workflow_version",
            "source_step", "evidence_sha256", "assessment_id", "assessment_revision",
            "assessment_sha256", "operation_id", "external_confirmation", "integration_mode",
        )
    })
    assert tickets.creates == 1


def test_observe_case_rejects_unaccepted_forged_or_other_tenant_sources(accepted_workflow):
    evolution, ctx, service, case, *_ = accepted_workflow
    unaccepted = service.intake(ctx, "Unaccepted synthetic vendor", "security-paper", "VEND", "No acceptance yet")
    with pytest.raises(ValueError, match="acceptance"):
        evolution.observe_case(ctx, service, unaccepted["id"], "fresh", rationale="Must reject")
    with pytest.raises(KeyError):
        evolution.observe_case(ctx, service, "VON-missing", "fresh", rationale="Fabricated case")
    with pytest.raises(KeyError):
        evolution.observe_case(replace(ctx, tenant="customer-b"), service, case["id"], "fresh", rationale="Other tenant")
    with pytest.raises(PermissionError):
        evolution.observe_case(replace(ctx, human=False), service, case["id"], "fresh", rationale="Model output")
    with pytest.raises(TypeError):
        evolution.observe_case(ctx, service, case["id"], "fresh", rationale="Forged caller input",
                               values=inputs(), source_workflow_version="forged")


@pytest.mark.parametrize("corruption", ["evidence_digest", "assessment_digest", "source_bytes", "missing_version"])
def test_observe_case_refuses_inconsistent_evidence_and_run_keeps_fallback(accepted_workflow, corruption):
    from maverick import vendor_onboarding

    evolution, ctx, service, case, docs, tickets, _ = accepted_workflow
    if corruption == "source_bytes":
        document = docs.documents[(ctx.tenant, "security-paper")]
        docs.documents[(ctx.tenant, "security-paper")] = replace(document, content=b"Forged bytes under unchanged version")
    elif corruption == "missing_version":
        key = case["operation"]["external_confirmation"]["key"]
        tickets.state[(ctx.tenant, key)]["version"] = None
    else:
        def tamper(row):
            if corruption == "evidence_digest":
                row["evidence"]["content_sha256"] = "f" * 64
            else:
                row["outcome"]["assessment_sha256"] = "f" * 64
        with tenant_scope(tenant=ctx.tenant):
            vendor_onboarding._CASES.update(case["id"], tamper, expected_revision=case["revision"],
                                            action="synthetic_fault_injection", actor=ctx.actor)
    with pytest.raises(ValueError):
        evolution.observe_case(ctx, service, case["id"], "fresh", rationale="Cannot learn from unverified provenance")
    assert service.check_renewal(ctx, case["id"])["classification"] == "human_fallback"


def test_accepted_case_observations_train_promoted_workflow_used_by_service(accepted_workflow):
    evolution, ctx, service, case, docs, tickets, now = accepted_workflow
    due = case["outcome"]["renewal_due_at"]
    observed = []
    for offset, label in ((-300, "fresh"), (-10, "fresh"), (1, "renewal_due")):
        now[0] = due + offset
        observed.append(evolution.observe_case(ctx, service, case["id"], label,
                                               rationale="Human-reviewed synthetic timestep"))
    candidate = evolution.propose(ctx, [row["id"] for row in observed], bindings=BINDINGS,
                                   rationale="Bindings reviewed against recorded accepted-case observations")
    candidate = evolution.evaluate(ctx, candidate["id"], held_out())
    evolution.promote(ctx, candidate["id"], candidate["revision"], rationale="Explicit human promotion")
    result = service.check_renewal(ctx, case["id"])
    assert result["classification"] == "renewal_due"
    assert result["source_case_id"] == case["id"]
    assert result["source_case_revision"] == case["revision"]
    assert result["workflow_version"] == 2
    assert tickets.creates == 1
    document = docs.documents[(ctx.tenant, "security-paper")]
    docs.documents[(ctx.tenant, "security-paper")] = replace(document, version="provider-source-v2")
    assert service.check_renewal(ctx, case["id"])["classification"] == "human_fallback"
