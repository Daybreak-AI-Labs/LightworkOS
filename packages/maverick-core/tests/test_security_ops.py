"""Security/GRC deterministic engines, CAS stores, and human gates."""

from __future__ import annotations

import time
from datetime import datetime, timezone

import pytest
from maverick import security_ops
from maverick.assessment import (
    FRAMEWORK_SOURCES,
    AssessmentSession,
    get_template,
    template_department,
)

SECURITY_TYPES = {
    "soc2",
    "iso27001",
    "nist_csf",
    "nist_800_53",
    "cis_v8",
    "pci_dss",
    "hipaa",
    "cmmc_l2",
    "fedramp_moderate",
}


@pytest.fixture(autouse=True)
def _isolate_security_state(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    import maverick.audit as audit

    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)


def _approved_evidence(title: str = "Security observation") -> dict:
    evidence = security_ops.map_evidence(
        title,
        "A reviewed security observation documents the affected system and exposure.",
        submitted_by="risk-analyst",
    )
    approved = security_ops.decide_evidence(
        evidence["id"],
        "approved",
        "A human reviewer verified the source and excerpt.",
        "evidence-reviewer",
        evidence["revision"],
    )
    assert approved is not None
    return approved


def _risk_evidence(title: str = "Risk observation") -> dict:
    return _approved_evidence(title)


def test_security_ops_gate_is_global_strict_and_malformed_values_fail_closed(monkeypatch):
    from maverick import config

    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {"security_ops": {"enable": False}},
    )
    monkeypatch.setattr(
        config,
        "load_global_config",
        lambda: {"security_ops": {"enable": True}},
    )
    assert security_ops.enabled() is True

    for malformed in ("false", 1, [], {"value": True}):
        monkeypatch.setattr(
            config,
            "load_global_config",
            lambda value=malformed: {"security_ops": {"enable": value}},
        )
        assert security_ops.enabled() is False

    monkeypatch.setattr(config, "load_global_config", dict)
    assert security_ops.enabled() is True

    monkeypatch.setattr(
        config,
        "load_global_config",
        lambda: {"security_ops": {"enable": True}},
    )
    monkeypatch.setattr(
        config,
        "config_source_errors",
        lambda **_kwargs: {"operator.toml": "malformed"},
    )
    assert security_ops.enabled() is False


def test_security_frameworks_are_deep_sourced_and_routed():
    expected_minimum = {
        "soc2": 40,
        "iso27001": 93,
        "nist_csf": 22,
        "nist_800_53": 20,
        "cis_v8": 18,
        "pci_dss": 12,
        "hipaa": 20,
        "cmmc_l2": 14,
        "fedramp_moderate": 20,
    }
    for assessment_type, minimum in expected_minimum.items():
        template = get_template(assessment_type)
        assert template is not None
        assert len(template.questions) >= minimum
        assert len({question.id for question in template.questions}) == len(template.questions)
        assert template_department(assessment_type) == "security"
        source = FRAMEWORK_SOURCES[assessment_type]
        assert source["version"] and source["source_url"].startswith("https://")
        assert all(question.guidance for question in template.questions)
    iso = get_template("iso27001")
    assert iso is not None
    assert {question.id for question in iso.questions} >= {
        "iso_a_5_1",
        "iso_a_6_8",
        "iso_a_7_14",
        "iso_a_8_34",
    }


def test_cmmc_crosswalk_uses_only_level_two_control_families():
    valid_families = {
        "AC", "AT", "AU", "CA", "CM", "IA", "IR",
        "MA", "MP", "PE", "PS", "RA", "SC", "SI",
    }

    for objective in security_ops.CONTROL_CATALOG:
        mapped = set(objective["mappings"].get("cmmc_l2", ()))
        assert mapped <= valid_families, (objective["id"], mapped - valid_families)


@pytest.mark.parametrize("assessment_type", sorted(SECURITY_TYPES))
def test_security_frameworks_use_existing_inherent_residual_scoring(
    assessment_type,
):
    template = get_template(assessment_type)
    assert template is not None
    session = AssessmentSession(type=assessment_type, subject="GlobalCo")
    for question in template.questions:
        session.record(question.id, question.risk_answer)
    result = session.evaluate()
    assert result.inherent_risk == "high"
    assert result.residual_risk == "high"
    assert len(result.findings) == len(template.questions)


def test_control_register_soa_crosswalk_and_revision_cas():
    controls = security_ops.initialize_control_register(
        owner="ciso@example.com", created_by="user:admin"
    )
    assert len(controls) == len(security_ops.CONTROL_CATALOG)
    identity = next(row for row in controls if row["canonical_id"] == "IAM-01")
    assert {"soc2", "iso27001", "nist_csf", "cis_v8"} <= set(identity["mappings"])
    updated = security_ops.upsert_control(
        {
            "implementation_status": "planned",
            "applicable": True,
            "applicability_rationale": "Customer and workforce access is in scope.",
        },
        control_id=identity["id"],
        expected_revision=identity["revision"],
        updated_by="user:owner",
    )
    assert updated is not None and updated["implementation_status"] == "planned"
    with pytest.raises(security_ops.RecordConflict):
        security_ops.upsert_control(
            {"implementation_status": "not_implemented"},
            control_id=identity["id"],
            expected_revision=identity["revision"],
            updated_by="user:stale",
        )
    assert security_ops.statement_of_applicability("soc2")
    crosswalk = security_ops.control_crosswalk("IAM-01", "nist_csf")
    assert crosswalk[0]["mappings"]["nist_csf"] == ["PR.AA"]

    with pytest.raises(security_ops.SecurityTransitionError, match="cited evidence"):
        security_ops.upsert_control(
            {"implementation_status": "implemented"},
            control_id=identity["id"],
            expected_revision=updated["revision"],
            updated_by="user:owner",
        )
    assert security_ops.get_control(identity["id"])["revision"] == updated["revision"]


def test_control_title_round_trips_dashboard_500_character_contract():
    created_title = "C" * 400
    control = security_ops.upsert_control(
        {
            "framework": "internal",
            "control_id": "LONG-TITLE-001",
            "title": created_title,
            "owner": "control-owner",
        },
        updated_by="control-owner",
    )
    assert control is not None and control["title"] == created_title

    updated_title = "U" * 400
    updated = security_ops.upsert_control(
        {"title": updated_title},
        control_id=control["id"],
        expected_revision=control["revision"],
        updated_by="control-owner",
    )
    assert updated is not None and updated["title"] == updated_title


def test_dashboard_control_contract_preserves_reviewed_evidence_gate():
    control = security_ops.upsert_control(
        {
            "framework": "internal",
            "control_id": "SEC-001",
            "title": "Administrative access review",
            "implementation_status": "not_started",
            "owner": "control-owner",
            "applicability_rationale": "Privileged identities are in scope.",
            "crosswalk": ["soc2:CC6.2", "iso27001:A.5.18"],
            "evidence_ids": [],
        },
        updated_by="user:admin",
    )
    assert control is not None
    assert control["framework"] == "internal"
    assert control["control_id"] == "SEC-001"
    assert control["crosswalk"] == ["soc2:CC6.2", "iso27001:A.5.18"]
    assert security_ops.statement_of_applicability("internal") == [control]
    custom_crosswalk = security_ops.control_crosswalk("SEC-001", "soc2")
    assert custom_crosswalk[0]["mappings"] == {"soc2": ["CC6.2"]}

    evidence = security_ops.map_evidence(
        "Quarterly access review",
        "SEC-001 requires administrative access accounts to be inspected quarterly.",
        control_ids=[control["id"]],
        submitted_by="collector",
    )
    assert evidence["verdicts"][0]["status"] == "present"
    approved = security_ops.decide_evidence(
        evidence["id"],
        "approved",
        "Artifact verified against the source system.",
        "auditor",
        evidence["revision"],
    )
    applied = security_ops.apply_evidence_to_control(
        control["id"], evidence["id"], "implemented", "control-owner", control["revision"]
    )
    assert approved is not None and applied is not None
    assert applied["evidence_ids"] == [evidence["id"]]
    with pytest.raises(ValueError, match="reviewed evidence"):
        security_ops.upsert_control(
            {"evidence_ids": ["EVD-unreviewed"]},
            control_id=control["id"],
            expected_revision=applied["revision"],
            updated_by="user:admin",
        )


def test_control_owners_are_required_at_the_core_boundary():
    with pytest.raises(ValueError, match="control owner is required"):
        security_ops.initialize_control_register()

    with pytest.raises(ValueError, match="control owner is required"):
        security_ops.upsert_control(
            {
                "framework": "internal",
                "control_id": "OWNER-001",
                "title": "Named ownership",
                "owner": "   ",
            },
            updated_by="user:admin",
        )

    control = security_ops.upsert_control(
        {
            "framework": "internal",
            "control_id": "OWNER-002",
            "title": "Named ownership",
            "owner": "security-owner",
        },
        updated_by="user:admin",
    )
    with pytest.raises(ValueError, match="control owner is required"):
        security_ops.upsert_control(
            {"owner": ""},
            control_id=control["id"],
            expected_revision=control["revision"],
            updated_by="user:admin",
        )


def test_evidence_mapper_quotes_source_and_never_auto_approves():
    control = security_ops.upsert_control(
        {
            "canonical_id": "IAM-02",
            "owner": "security-owner",
            "applicability_rationale": "Administrative access is in scope.",
        },
        updated_by="user:admin",
    )
    assert control is not None
    evidence = security_ops.map_evidence(
        "Access standard",
        "The company enforces multi-factor authentication (MFA) and unique user IDs "
        "for all administrative access.",
        control_ids=["IAM-02"],
        submitted_by="collector",
    )
    verdict = evidence["verdicts"][0]
    assert verdict["status"] == "present"
    assert "multi-factor authentication" in verdict["evidence_quote"]
    assert evidence["extraction_confidence"] == "untrusted"
    assert evidence["review_required"] is True
    assert evidence["status"] == "pending_review"
    with pytest.raises(security_ops.SecurityTransitionError):
        security_ops.apply_evidence_to_control(
            control["id"],
            evidence["id"],
            implementation_status="implemented",
            applied_by="control-owner",
            expected_revision=control["revision"],
        )
    approved = security_ops.decide_evidence(
        evidence["id"],
        "approved",
        rationale="Source artifact manually verified.",
        decided_by="auditor",
        expected_revision=evidence["revision"],
    )
    applied = security_ops.apply_evidence_to_control(
        control["id"],
        evidence["id"],
        implementation_status="implemented",
        applied_by="control-owner",
        expected_revision=control["revision"],
    )
    assert approved is not None and applied is not None
    assert applied["evidence_ids"] == [evidence["id"]]
    assert applied["implementation_status"] == "implemented"


@pytest.mark.parametrize(
    "statement",
    [
        "Multi-factor authentication is not phishing-resistant.",
        "Multi-factor authentication will be phishing-resistant next year.",
    ],
)
def test_evidence_mapper_never_marks_non_current_authentication_claim_present(statement):
    evidence = security_ops.map_evidence(
        "Authentication claim",
        statement,
        control_ids=["IAM-02"],
        submitted_by="collector",
    )

    verdict = evidence["verdicts"][0]
    assert verdict["status"] == "partial"
    assert verdict["status"] != "present"
    assert verdict["negation_or_future_language"] is True
    assert verdict["evidence_quote"] == statement


@pytest.mark.parametrize(
    "statement",
    [
        (
            "Multi-factor authentication is enforced today, but phishing-resistant "
            "authentication is planned for next year."
        ),
        (
            "Multi-factor authentication is enforced today. It is not "
            "phishing-resistant for sensitive access."
        ),
    ],
)
def test_evidence_mapper_keeps_mixed_current_and_non_current_claims_partial(statement):
    evidence = security_ops.map_evidence(
        "Mixed authentication posture",
        statement,
        control_ids=["IAM-02"],
        submitted_by="collector",
    )

    verdict = evidence["verdicts"][0]
    assert verdict["status"] == "partial"
    assert verdict["negation_or_future_language"] is True


@pytest.mark.parametrize(
    "statement",
    [
        (
            "MFA is planned for contractors, but administrators currently use "
            "multi-factor authentication and phishing-resistant security keys."
        ),
        (
            "Multi-factor authentication is not enabled for guest accounts. "
            "Sensitive administrative access currently uses MFA with "
            "phishing-resistant hardware keys."
        ),
    ],
)
def test_evidence_mapper_uses_separate_current_claim_after_non_current_claim(statement):
    evidence = security_ops.map_evidence(
        "Scoped authentication posture",
        statement,
        control_ids=["IAM-02"],
        submitted_by="collector",
    )

    verdict = evidence["verdicts"][0]
    assert verdict["status"] == "present"
    assert verdict["negation_or_future_language"] is True
    assert "phishing-resistant" in verdict["evidence_quote"]


def test_evidence_mapper_accepts_framework_crosswalk_references():
    evidence = security_ops.map_evidence(
        "SOC 2 access evidence",
        "Quarterly access reviews enforce least privilege and MFA for administrators.",
        control_ids=["CC6.1"],
        submitted_by="collector",
    )
    verdicts = {verdict["control_id"]: verdict for verdict in evidence["verdicts"]}
    mapped = set(verdicts)
    assert {"AST-01", "IAM-01", "IAM-02"} <= mapped
    assert verdicts["IAM-01"]["status"] == "present"
    assert verdicts["IAM-02"]["status"] in {"present", "partial"}


def test_partial_evidence_cannot_overstate_control_implementation():
    control = security_ops.upsert_control(
        {
            "canonical_id": "IAM-02",
            "owner": "security-owner",
            "applicability_rationale": "Administrative access is in scope.",
        },
        updated_by="control-owner",
    )
    evidence = security_ops.map_evidence(
        "Authentication note",
        "MFA is required for administrators.",
        control_ids=["IAM-02"],
        submitted_by="collector",
    )
    assert evidence["verdicts"][0]["status"] == "partial"
    approved = security_ops.decide_evidence(
        evidence["id"],
        "approved",
        "The excerpt was checked against the source.",
        "auditor",
        evidence["revision"],
    )
    assert approved is not None and control is not None
    with pytest.raises(security_ops.SecurityTransitionError, match="cannot mark"):
        security_ops.apply_evidence_to_control(
            control["id"],
            evidence["id"],
            "implemented",
            "control-owner",
            control["revision"],
        )
    assert security_ops.get_control(control["id"])["revision"] == control["revision"]

    applied = security_ops.apply_evidence_to_control(
        control["id"],
        evidence["id"],
        "partial",
        "control-owner",
        control["revision"],
    )
    assert applied is not None and applied["implementation_status"] == "partial"


def test_approved_evidence_cannot_be_revoked_while_it_supports_posture():
    control = security_ops.upsert_control(
        {
            "canonical_id": "IAM-02",
            "owner": "security-owner",
            "applicability_rationale": "Administrative access is in scope.",
        },
        updated_by="control-owner",
    )
    evidence = security_ops.map_evidence(
        "Authentication proof",
        "Multi-factor authentication and phishing-resistant security keys are enforced.",
        control_ids=["IAM-02"],
        submitted_by="collector",
    )
    approved = security_ops.decide_evidence(
        evidence["id"],
        "approved",
        "The source was reviewed.",
        "auditor",
        evidence["revision"],
    )
    applied = security_ops.apply_evidence_to_control(
        control["id"],
        evidence["id"],
        "implemented",
        "control-owner",
        control["revision"],
    )
    assert approved is not None and applied is not None
    assert security_ops.readiness_report("soc2")["controls_implemented"] == 1

    with pytest.raises(security_ops.SecurityTransitionError, match="supports governance"):
        security_ops.decide_evidence(
            evidence["id"],
            "rejected",
            "Approval should be withdrawn.",
            "auditor",
            approved["revision"],
        )
    assert security_ops.get_evidence(evidence["id"])["status"] == "approved"

    downgraded = security_ops.upsert_control(
        {"implementation_status": "planned"},
        control_id=control["id"],
        expected_revision=applied["revision"],
        updated_by="control-owner",
    )
    assert downgraded is not None and downgraded["evidence_ids"] == []
    rejected = security_ops.decide_evidence(
        evidence["id"],
        "rejected",
        "The control no longer relies on this artifact.",
        "auditor",
        approved["revision"],
    )
    assert rejected is not None and rejected["status"] == "rejected"
    assert security_ops.readiness_report("soc2")["controls_implemented"] == 0

def test_security_audit_outbox_is_durable_without_revision_churn(monkeypatch):
    import maverick.audit as audit

    evidence = _risk_evidence("Credential theft observation")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    risk = security_ops.register_risk(
        "Credential theft",
        4,
        5,
        "risk-owner",
        likelihood_rationale="Credential abuse has been observed repeatedly.",
        impact_rationale="Compromise could expose privileged systems.",
        evidence_ids=[evidence["id"]],
        created_by="user:creator",
    )
    assert risk["_audit_pending"]
    revision = risk["revision"]
    event_id = risk["_audit_pending"][0]["event_id"]
    captured = []

    def accept(kind, **payload):
        captured.append((kind, payload))
        return True

    monkeypatch.setattr(audit, "record", accept)
    assert security_ops.retry_pending_audits(limit=100) == 1
    stored = security_ops.get_risk(risk["id"])
    assert stored is not None and stored["revision"] == revision
    assert "_audit_pending" not in stored
    assert captured[0][0] == "security_record_changed"
    assert captured[0][1]["event_id"] == event_id


def test_risk_scores_require_rationales_and_existing_evidence():
    with pytest.raises(ValueError, match="likelihood rationale"):
        security_ops.register_risk(
            "Unsupported score",
            3,
            4,
            "risk-owner",
            impact_rationale="A material service could be affected.",
            evidence_ids=["EVD-missing"],
        )

    with pytest.raises(ValueError, match="unknown risk evidence"):
        security_ops.register_risk(
            "Unknown source",
            3,
            4,
            "risk-owner",
            likelihood_rationale="The activity recurs monthly.",
            impact_rationale="A material service could be affected.",
            evidence_ids=["EVD-missing"],
        )

    pending = security_ops.map_evidence(
        "Unreviewed observation",
        "A security observation awaits human source review.",
        submitted_by="risk-analyst",
    )
    with pytest.raises(security_ops.SecurityTransitionError, match="human-approved"):
        security_ops.register_risk(
            "Unreviewed source",
            3,
            4,
            "risk-owner",
            likelihood_rationale="The activity may recur monthly.",
            impact_rationale="A material service could be affected.",
            evidence_ids=[pending["id"]],
        )


def test_risk_treatment_exception_and_poam_expiry(monkeypatch):
    now = 2_000_000_000.0
    monkeypatch.setattr(security_ops.time, "time", lambda: now)
    evidence = _risk_evidence("Public storage observation")
    risk = security_ops.register_risk(
        "Public storage",
        5,
        5,
        "ciso",
        likelihood_rationale="The public policy is active on an internet-facing bucket.",
        impact_rationale="The bucket contains regulated customer records.",
        evidence_ids=[evidence["id"]],
    )
    treated = security_ops.set_risk_treatment(
        risk["id"],
        "mitigate",
        "Restrict bucket and add monitoring.",
        2,
        4,
        "cloud-owner",
        updated_by="ciso",
        expected_revision=risk["revision"],
        residual_likelihood_rationale="A deny policy makes recurrence unlikely.",
        residual_impact_rationale="Monitoring limits exposure but the data remains sensitive.",
        evidence_ids=[evidence["id"]],
    )
    assert treated is not None
    assert treated["residual_score"] == 8
    assert treated["residual_rating"] == "medium"
    exception = security_ops.grant_risk_exception(
        risk["id"],
        "cloud-owner",
        "Migration window approved.",
        now + 10 * 86400,
        granted_by="ciso",
        expected_revision=treated["revision"],
    )
    assert exception is not None
    assert security_ops.list_risks()[0]["exception_due"] is True
    poam = security_ops.create_poam(
        "Restrict public storage",
        "cloud-owner",
        now - 1,
        control_ids=["CFG-01"],
        milestones=[{"title": "Apply policy"}],
    )
    assert security_ops.list_poams()[0]["overdue"] is True
    triggered = security_ops.trigger_poam_review(
        poam["id"],
        "Material cloud change",
        triggered_by="auditor",
        expected_revision=poam["revision"],
    )
    assert triggered is not None
    assert triggered["review_trigger"]["reason"] == "Material cloud change"


def test_vendor_carry_forward_is_explicitly_stale_and_review_gated():
    first = security_ops.assess_vendor(
        "CloudCo",
        {key: True for key, _, _ in security_ops.VENDOR_CHECKS},
        owner="vendor-owner",
        assessed_by="analyst",
    )
    second = security_ops.assess_vendor(
        "CloudCo",
        {"mfa": False},
        carry_forward_from=first["id"],
        owner="vendor-owner",
        assessed_by="analyst",
    )
    assert second["status"] == "pending_review"
    assert second["review_required"] is True
    carried = [item for item in second["checks"] if item["carried_forward"]]
    assert carried and all(item["requires_revalidation"] for item in carried)
    assert second["residual_risk"] == "high"
    assert security_ops.latest_vendor_assessment("cloudco")["id"] == second["id"]


def test_policy_lifecycle_requires_humans_and_cas():
    policy = security_ops.create_policy("Access Policy", "policy-owner")
    review = security_ops.transition_policy(
        policy["id"], "review", actor="reviewer", expected_revision=policy["revision"]
    )
    assert review is not None
    approved = security_ops.transition_policy(
        policy["id"],
        "approved",
        actor="ciso",
        note="Approved for publication.",
        expected_revision=review["revision"],
    )
    assert approved is not None and approved["next_review_at"]
    attested = security_ops.attest_policy(
        policy["id"],
        "employee:42",
        "I read and understand this policy.",
        attested_by="employee:42",
        expected_revision=approved["revision"],
    )
    assert attested is not None and attested["status"] == "attested"
    assert len(attested["attestations"]) == 1
    with pytest.raises(security_ops.RecordConflict):
        security_ops.transition_policy(
            policy["id"],
            "review",
            actor="stale",
            expected_revision=policy["revision"],
        )


def test_global_regulatory_clock_metadata_and_human_anchors():
    clocks = {clock["key"]: clock for clock in security_ops.list_regulatory_clock_packs()}
    assert clocks["nis2_early_24h"]["deadline"] == {"amount": 24, "unit": "hours"}
    assert clocks["nis2_final_1mo"]["anchor"] == "incident_notification"
    assert clocks["singapore_pdpa_3d"]["anchor"] == "notifiable_determination"
    assert clocks["australia_ndb_assess_30d"]["deadline"]["amount"] == 30
    assert clocks["australia_ndb_notice_asap"]["deadline"] is None
    assert clocks["canada_pipeda_asap"]["deadline"] is None
    assert clocks["sec_8k_4bd"]["anchor"] == "materiality_determination"
    assert clocks["sec_8k_4bd"]["deadline"]["unit"] == "business_days"
    assert all(clock["source_url"].startswith("https://") for clock in clocks.values())

    monday = datetime(2026, 7, 20, 12, tzinfo=timezone.utc).timestamp()
    incident = security_ops.open_incident(
        "Material service compromise",
        severity="high",
        mitre_techniques=["T1078"],
        clock_ids=["sec_8k_4bd", "canada_pipeda_asap"],
        reported_by="soc",
        discovered_at=monday,
    )
    assert all(
        clock["state"] == "awaiting_human_applicability" for clock in incident["regulatory_clocks"]
    )
    running = security_ops.start_incident_clock(
        incident["id"],
        "sec_8k_4bd",
        monday,
        started_by="securities-counsel",
        expected_revision=incident["revision"],
    )
    assert running is not None
    sec = next(clock for clock in running["regulatory_clocks"] if clock["key"] == "sec_8k_4bd")
    assert datetime.fromtimestamp(sec["deadline_at"], tz=timezone.utc).weekday() == 4
    decided = security_ops.decide_incident_notification(
        incident["id"],
        "sec_8k_4bd",
        True,
        rationale="Counsel determined the incident material.",
        decided_by="securities-counsel",
        expected_revision=running["revision"],
    )
    assert decided is not None
    canada_decided = security_ops.decide_incident_notification(
        incident["id"],
        "canada_pipeda_asap",
        False,
        rationale="Counsel documented that the Canadian notice duty does not apply.",
        decided_by="privacy-counsel",
        expected_revision=decided["revision"],
    )
    assert canada_decided is not None
    contained = security_ops.record_incident_phase(
        incident["id"],
        "containment",
        "Compromised credentials disabled and affected workloads isolated.",
        recorded_by="incident-commander",
        expected_revision=canada_decided["revision"],
    )
    eradicated = security_ops.record_incident_phase(
        incident["id"],
        "eradication",
        "Persistence removed and credentials rotated.",
        recorded_by="incident-commander",
        expected_revision=contained["revision"],
    )
    phased = security_ops.record_incident_phase(
        incident["id"],
        "recovery",
        "Service restored from verified image.",
        recorded_by="incident-commander",
        expected_revision=eradicated["revision"],
    )
    closed = security_ops.close_incident(
        incident["id"],
        "Recovery validated; follow-up tracked in POA&M.",
        closed_by="incident-commander",
        expected_revision=phased["revision"],
    )
    assert closed is not None and closed["status"] == "closed"


def test_incident_closure_resolves_clocks_and_closed_state_is_immutable():
    incident = security_ops.open_incident(
        "Multi-jurisdiction incident",
        clock_ids=["nis2_early_24h", "canada_pipeda_asap"],
        reported_by="incident-commander",
    )
    contained = security_ops.record_incident_phase(
        incident["id"],
        "containment",
        "Affected service isolated.",
        recorded_by="incident-commander",
        expected_revision=incident["revision"],
    )
    eradicated = security_ops.record_incident_phase(
        incident["id"],
        "eradication",
        "Persistence removed.",
        recorded_by="incident-commander",
        expected_revision=contained["revision"],
    )
    recovered = security_ops.record_incident_phase(
        incident["id"],
        "recovery",
        "Recovery completed.",
        recorded_by="incident-commander",
        expected_revision=eradicated["revision"],
    )
    assert recovered is not None

    with pytest.raises(security_ops.SecurityTransitionError, match="regulatory clocks"):
        security_ops.close_incident(
            incident["id"],
            "Recovery validated.",
            closed_by="incident-commander",
            expected_revision=recovered["revision"],
        )
    after_rejected_close = security_ops.get_incident(incident["id"])
    assert after_rejected_close is not None
    assert after_rejected_close["revision"] == recovered["revision"]

    running = security_ops.start_incident_clock(
        incident["id"],
        "nis2_early_24h",
        time.time(),
        started_by="legal",
        expected_revision=recovered["revision"],
    )
    assert running is not None
    with pytest.raises(security_ops.SecurityTransitionError, match="regulatory clocks"):
        security_ops.close_incident(
            incident["id"],
            "Recovery validated.",
            closed_by="incident-commander",
            expected_revision=running["revision"],
        )
    assert security_ops.get_incident(incident["id"])["revision"] == running["revision"]

    documented = security_ops.decide_incident_notification(
        incident["id"],
        "nis2_early_24h",
        False,
        rationale="Counsel documented non-applicability.",
        decided_by="legal",
        expected_revision=running["revision"],
    )
    assert documented is not None
    with pytest.raises(
        security_ops.SecurityTransitionError, match="started regulatory clock"
    ):
        security_ops.decide_incident_notification(
            incident["id"],
            "canada_pipeda_asap",
            True,
            rationale="Counsel determined notification is required.",
            decided_by="legal",
            expected_revision=documented["revision"],
        )
    assert security_ops.get_incident(incident["id"])["revision"] == documented["revision"]
    canada_running = security_ops.start_incident_clock(
        incident["id"],
        "canada_pipeda_asap",
        time.time(),
        started_by="legal",
        expected_revision=documented["revision"],
    )
    assert canada_running is not None
    resolved = security_ops.decide_incident_notification(
        incident["id"],
        "canada_pipeda_asap",
        True,
        rationale="Counsel determined notification is required.",
        decided_by="legal",
        expected_revision=canada_running["revision"],
    )
    assert resolved is not None
    assert {clock["state"] for clock in resolved["regulatory_clocks"]} == {
        "documented_not_notifiable",
        "notify",
    }
    with pytest.raises(security_ops.SecurityTransitionError, match="cannot be restarted"):
        security_ops.start_incident_clock(
            incident["id"],
            "nis2_early_24h",
            time.time(),
            started_by="legal",
            expected_revision=resolved["revision"],
        )
    assert security_ops.get_incident(incident["id"])["revision"] == resolved["revision"]
    closed = security_ops.close_incident(
        incident["id"],
        "Recovery and notification decisions validated.",
        closed_by="incident-commander",
        expected_revision=resolved["revision"],
    )
    assert closed is not None and closed["status"] == "closed"
    closed_snapshot = security_ops.get_incident(incident["id"])
    assert closed_snapshot is not None

    closed_mutations = (
        lambda: security_ops.start_incident_clock(
            incident["id"],
            "nis2_early_24h",
            time.time(),
            started_by="legal",
            expected_revision=closed["revision"],
        ),
        lambda: security_ops.decide_incident_notification(
            incident["id"],
            "nis2_early_24h",
            True,
            rationale="Attempted revision.",
            decided_by="legal",
            expected_revision=closed["revision"],
        ),
        lambda: security_ops.close_incident(
            incident["id"],
            "Attempted re-close.",
            closed_by="incident-commander",
            expected_revision=closed["revision"],
        ),
    )
    for mutate in closed_mutations:
        with pytest.raises(security_ops.SecurityTransitionError, match="closed incident"):
            mutate()
        current = security_ops.get_incident(incident["id"])
        assert current is not None and current["revision"] == closed_snapshot["revision"]

    with pytest.raises(security_ops.RecordConflict):
        security_ops.start_incident_clock(
            incident["id"],
            "nis2_early_24h",
            time.time(),
            started_by="stale-operator",
            expected_revision=resolved["revision"],
        )
    assert security_ops.get_incident(incident["id"])["revision"] == closed_snapshot["revision"]


def test_incident_closure_requires_a_chronologically_complete_response():
    base = time.time() - 300
    incident = security_ops.open_incident(
        "Out-of-order response record",
        reported_by="incident-commander",
    )
    recovered_first = security_ops.record_incident_phase(
        incident["id"],
        "recovery",
        "Recovery was initially entered before the preceding workpapers.",
        recorded_by="incident-commander",
        expected_revision=incident["revision"],
        occurred_at=base + 200,
    )
    contained_late = security_ops.record_incident_phase(
        incident["id"],
        "containment",
        "Containment timestamp is too late for this recovery event.",
        recorded_by="incident-commander",
        expected_revision=recovered_first["revision"],
        occurred_at=base + 250,
    )
    eradicated_late = security_ops.record_incident_phase(
        incident["id"],
        "eradication",
        "Eradication timestamp is also too late.",
        recorded_by="incident-commander",
        expected_revision=contained_late["revision"],
        occurred_at=base + 275,
    )

    with pytest.raises(security_ops.SecurityTransitionError, match="chronologically ordered"):
        security_ops.close_incident(
            incident["id"],
            "The entered sequence is not valid.",
            closed_by="incident-commander",
            expected_revision=eradicated_late["revision"],
        )
    assert security_ops.get_incident(incident["id"])["revision"] == eradicated_late["revision"]

    corrected_recovery = security_ops.record_incident_phase(
        incident["id"],
        "recovery",
        "Recovery revalidated after containment and eradication.",
        recorded_by="incident-commander",
        expected_revision=eradicated_late["revision"],
        occurred_at=base + 290,
    )
    closed = security_ops.close_incident(
        incident["id"],
        "Chronological response workpapers validated.",
        closed_by="incident-commander",
        expected_revision=corrected_recovery["revision"],
    )
    assert closed is not None and closed["status"] == "closed"


def test_dashboard_custom_clock_payload_is_normalised_without_legal_decision():
    clock = security_ops.upsert_regulatory_clock(
        {
            "title": "Example business-day notice",
            "jurisdiction": "Example jurisdiction",
            "source_url": "https://example.test/notice-rule",
            "source_title": "Example notice rule",
            "anchor": "human_notifiability_determination",
            "deadline_seconds": 3 * 86400,
            "deadline_kind": "business",
            "status": "custom",
        },
        updated_by="legal-ops",
    )
    assert clock is not None
    assert clock["key"] == "custom_example_business_day_notice"
    assert clock["deadline"] == {"amount": 3, "unit": "business_days"}
    assert clock["deadline_seconds"] == 3 * 86400
    assert "Human applicability" in clock["applicability"]

    asap = security_ops.upsert_regulatory_clock(
        {
            "title": "Example immediate notice",
            "jurisdiction": "Example jurisdiction",
            "source_url": "https://example.test/immediate-rule",
            "source_title": "Example immediate rule",
            "anchor": "human_notifiability_determination",
            "deadline_kind": "asap",
            "status": "custom",
        },
        updated_by="legal-ops",
    )
    assert asap is not None and asap["deadline"] is None
    assert asap["deadline_seconds"] is None


def test_audit_engagement_control_tests_findings_and_board_report():
    security_ops.initialize_control_register(owner="ciso")
    evidence = _approved_evidence("Access review sample")
    engagement = security_ops.create_audit_engagement(
        "SOC 2 readiness", "soc2", "Production platform", "audit-owner"
    )
    requested = security_ops.add_evidence_request(
        engagement["id"],
        "Provide access-review evidence.",
        "iam-owner",
        time_stamp := datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp(),
        control_ids=["IAM-01"],
        requested_by="auditor",
        expected_revision=engagement["revision"],
    )
    assert requested is not None and time_stamp > 0
    tested = security_ops.record_control_test(
        engagement["id"],
        "IAM-01",
        "Inspect quarterly access review sample.",
        "fail",
        evidence_ids=[evidence["id"]],
        tested_by="auditor",
        expected_revision=requested["revision"],
    )
    finding = security_ops.add_audit_finding(
        engagement["id"],
        "Access review evidence incomplete",
        "high",
        control_ids=["IAM-01"],
        owner="iam-owner",
        created_by="auditor",
        expected_revision=tested["revision"],
    )
    assert finding is not None
    with pytest.raises(security_ops.SecurityTransitionError):
        security_ops.update_audit_engagement_status(
            engagement["id"],
            "complete",
            updated_by="auditor",
            expected_revision=finding["revision"],
        )
    report = security_ops.program_report()
    assert report["controls"]["total"] == len(security_ops.CONTROL_CATALOG)
    assert report["audits"]["open_findings"] == 1
    board = security_ops.render_board_report(report)
    assert "Security & GRC Board Readiness Report" in board
    assert "not certification" in board


def test_audit_completion_requires_resolved_requests_and_findings():
    evidence = _approved_evidence("Lifecycle audit evidence")
    engagement = security_ops.create_audit_engagement(
        "Lifecycle audit", "internal", "Production", "audit-owner"
    )
    requested = security_ops.add_evidence_request(
        engagement["id"],
        "Provide access evidence.",
        "iam-owner",
        time.time() + 86400,
        requested_by="auditor",
        expected_revision=engagement["revision"],
    )
    assert requested is not None
    with pytest.raises(security_ops.SecurityTransitionError, match="evidence requests"):
        security_ops.update_audit_engagement_status(
            engagement["id"], "complete", "auditor", requested["revision"]
        )
    assert security_ops.get_audit_engagement(engagement["id"])["revision"] == requested["revision"]

    request_id = requested["evidence_requests"][0]["id"]
    with pytest.raises(ValueError, match="at least one cited evidence"):
        security_ops.update_evidence_request(
            engagement["id"],
            request_id,
            "accepted",
            updated_by="auditor",
            expected_revision=requested["revision"],
        )
    assert security_ops.get_audit_engagement(engagement["id"])["revision"] == requested["revision"]

    submitted = security_ops.update_evidence_request(
        engagement["id"],
        request_id,
        "submitted",
        evidence_ids=[evidence["id"]],
        updated_by="auditor",
        expected_revision=requested["revision"],
    )
    assert submitted is not None
    with pytest.raises(security_ops.SecurityTransitionError, match="evidence requests"):
        security_ops.update_audit_engagement_status(
            engagement["id"], "closed", "auditor", submitted["revision"]
        )
    assert security_ops.get_audit_engagement(engagement["id"])["revision"] == submitted["revision"]

    accepted = security_ops.update_evidence_request(
        engagement["id"],
        request_id,
        "accepted",
        evidence_ids=[evidence["id"]],
        updated_by="auditor",
        expected_revision=submitted["revision"],
    )
    finding = security_ops.add_audit_finding(
        engagement["id"],
        "Unresolved access exception",
        "high",
        created_by="auditor",
        expected_revision=accepted["revision"],
    )
    assert finding is not None
    finding_id = finding["findings"][0]["id"]
    with pytest.raises(security_ops.SecurityTransitionError, match="findings"):
        security_ops.update_audit_engagement_status(
            engagement["id"], "complete", "auditor", finding["revision"]
        )

    in_progress = security_ops.update_audit_finding(
        engagement["id"],
        finding_id,
        "in_progress",
        "auditor",
        finding["revision"],
    )
    assert in_progress is not None
    with pytest.raises(security_ops.SecurityTransitionError, match="findings"):
        security_ops.update_audit_engagement_status(
            engagement["id"], "closed", "auditor", in_progress["revision"]
        )
    assert security_ops.get_audit_engagement(engagement["id"])["revision"] == in_progress[
        "revision"
    ]

    resolved = security_ops.update_audit_finding(
        engagement["id"],
        finding_id,
        "resolved",
        "auditor",
        in_progress["revision"],
    )
    completed = security_ops.update_audit_engagement_status(
        engagement["id"], "complete", "auditor", resolved["revision"]
    )
    assert completed is not None and completed["status"] == "complete"


def test_terminal_audit_workpapers_require_explicit_review_reopen():
    evidence = _approved_evidence("Audit operating sample")
    engagement = security_ops.create_audit_engagement(
        "Terminal audit", "internal", "Production", "audit-owner"
    )
    requested = security_ops.add_evidence_request(
        engagement["id"],
        "Provide operating evidence.",
        "control-owner",
        time.time() + 86400,
        requested_by="auditor",
        expected_revision=engagement["revision"],
    )
    request_id = requested["evidence_requests"][0]["id"]
    accepted = security_ops.update_evidence_request(
        engagement["id"],
        request_id,
        "accepted",
        evidence_ids=[evidence["id"]],
        updated_by="auditor",
        expected_revision=requested["revision"],
    )
    finding = security_ops.add_audit_finding(
        engagement["id"],
        "Documented observation",
        "low",
        created_by="auditor",
        expected_revision=accepted["revision"],
    )
    finding_id = finding["findings"][0]["id"]
    resolved = security_ops.update_audit_finding(
        engagement["id"], finding_id, "resolved", "auditor", finding["revision"]
    )
    completed = security_ops.update_audit_engagement_status(
        engagement["id"], "complete", "auditor", resolved["revision"]
    )
    assert completed is not None

    def workpaper_mutations(expected_revision):
        return (
            lambda: security_ops.add_evidence_request(
                engagement["id"],
                "Late request.",
                "control-owner",
                time.time() + 86400,
                requested_by="auditor",
                expected_revision=expected_revision,
            ),
            lambda: security_ops.update_evidence_request(
                engagement["id"],
                request_id,
                "closed",
                updated_by="auditor",
                expected_revision=expected_revision,
            ),
            lambda: security_ops.record_control_test(
                engagement["id"],
                "CTRL-1",
                "Late test.",
                "pass",
                tested_by="auditor",
                expected_revision=expected_revision,
            ),
            lambda: security_ops.add_audit_finding(
                engagement["id"],
                "Late finding",
                "low",
                created_by="auditor",
                expected_revision=expected_revision,
            ),
            lambda: security_ops.update_audit_finding(
                engagement["id"],
                finding_id,
                "closed",
                "auditor",
                expected_revision,
            ),
        )

    for mutate in workpaper_mutations(completed["revision"]):
        with pytest.raises(security_ops.SecurityTransitionError, match="move it to review"):
            mutate()
        assert security_ops.get_audit_engagement(engagement["id"]) == completed

    with pytest.raises(security_ops.SecurityTransitionError, match="may only move"):
        security_ops.update_audit_engagement_status(
            engagement["id"], "fieldwork", "auditor", completed["revision"]
        )
    with pytest.raises(security_ops.RecordConflict):
        security_ops.update_audit_engagement_status(
            engagement["id"], "review", "stale-auditor", resolved["revision"]
        )
    assert security_ops.get_audit_engagement(engagement["id"]) == completed

    reopened = security_ops.update_audit_engagement_status(
        engagement["id"], "review", "auditor", completed["revision"]
    )
    tested = security_ops.record_control_test(
        engagement["id"],
        "CTRL-1",
        "Reopened test.",
        "pass",
        evidence_ids=[evidence["id"]],
        tested_by="auditor",
        expected_revision=reopened["revision"],
    )
    closed = security_ops.update_audit_engagement_status(
        engagement["id"], "closed", "auditor", tested["revision"]
    )
    assert closed is not None and closed["status"] == "closed"
    for mutate in workpaper_mutations(closed["revision"]):
        with pytest.raises(security_ops.SecurityTransitionError, match="move it to review"):
            mutate()
        assert security_ops.get_audit_engagement(engagement["id"]) == closed

    with pytest.raises(security_ops.SecurityTransitionError, match="may only move to review"):
        security_ops.update_audit_engagement_status(
            engagement["id"], "planned", "auditor", closed["revision"]
        )
    reopened_closed = security_ops.update_audit_engagement_status(
        engagement["id"], "review", "auditor", closed["revision"]
    )
    assert reopened_closed is not None and reopened_closed["status"] == "review"
    reopened_request = security_ops.add_evidence_request(
        engagement["id"],
        "Reopened engagement request.",
        "control-owner",
        time.time() + 86400,
        requested_by="auditor",
        expected_revision=reopened_closed["revision"],
    )
    assert reopened_request is not None
    assert reopened_request["evidence_requests"][-1]["status"] == "open"


def test_dashboard_closed_audit_and_poam_states():
    poam = security_ops.create_poam("Close test", "owner", time.time() + 86400)
    closed_poam = security_ops.update_poam(
        poam["id"],
        "closed",
        updated_by="owner",
        expected_revision=poam["revision"],
    )
    assert closed_poam is not None and closed_poam["closed_by"] == "owner"
    assert security_ops.list_poams()[0]["overdue"] is False

    engagement = security_ops.create_audit_engagement(
        "Close test", "internal", "Production", "audit-owner"
    )
    assert engagement["status"] == "planned"
    closed = security_ops.update_audit_engagement_status(
        engagement["id"], "closed", "audit-owner", engagement["revision"]
    )
    assert closed is not None and closed["status"] == "closed"


def test_program_report_types_cover_every_security_template():
    # SECURITY_ASSESSMENT_TYPES is the program report's default filter; a
    # template missing here silently drops its assessments from the
    # report (iso42001 was the one that slipped).
    from maverick.assessment import TEMPLATES

    assert "iso42001" in security_ops.SECURITY_ASSESSMENT_TYPES
    assert set(TEMPLATES) >= security_ops.SECURITY_ASSESSMENT_TYPES
