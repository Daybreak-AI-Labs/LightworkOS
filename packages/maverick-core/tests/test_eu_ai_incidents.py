from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import maverick.eu_ai_incidents as incident_api
import pytest
from maverick.eu_ai_incidents import (
    ARTICLE_73_SOURCE_URL,
    Article73ConfigurationError,
    Article73IncidentRegister,
    Article73StateError,
    HumanAuthority,
    RecordConflict,
    calculate_article_73_clock,
    report_template,
)
from maverick.paths import tenant_scope


@pytest.fixture(autouse=True)
def _enable_article_73_core(monkeypatch):
    monkeypatch.setattr(incident_api, "enabled", lambda: True)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _open(
    register: Article73IncidentRegister,
    *,
    outcomes=("serious_harm_to_health",),
    widespread_infringement: bool = False,
    causality: str = "reasonable_likelihood",
    member_states=("DE",),
):
    return register.open_incident(
        "Potential high-risk AI incident",
        asset_id="ai-system-17",
        asset_version="deployment-2026-08-28",
        awareness_at=time.time() - 60,
        occurred_at=time.time() - 120,
        summary="A bounded internal summary that requires human legal review.",
        operator_role="provider",
        asserted_high_risk="yes",
        asserted_union_market="yes",
        incident_member_states=member_states,
        outcomes=outcomes,
        widespread_infringement=widespread_infringement,
        causality=causality,
        evidence_refs=({"id": "evidence-1", "sha256": _sha("evidence")},),
        opened_by="incident-ingestor",
    )


def _route(
    register: Article73IncidentRegister,
    incident: dict,
    *,
    authority: HumanAuthority | None = None,
):
    return register.record_routing_decision(
        incident["id"],
        decision="report_to_authority",
        threshold_determination="met",
        applicability_determination="applies",
        rationale="Counsel confirmed the recorded threshold and routing basis.",
        authority_refs=("DE-market-surveillance-route",),
        authority=authority
        or HumanAuthority("user:legal-reviewer", "legal_counsel"),
        expected_revision=incident["revision"],
    )


def _initial_details() -> dict:
    return {
        "system_purpose": "Supports a bounded infrastructure dispatch decision.",
        "causal_assessment_summary": "A reasonable likelihood is under investigation.",
        "consequences": "Serious health harm was reported; scope remains under review.",
        "investigation_status": "ongoing",
        "investigation_summary": "Logs and the deployed artifact have been preserved.",
        "corrective_actions": "The affected route is paused pending human review.",
        "preservation_actions": "Immutable log and deployment digests were retained.",
        "contact_reference": "contact-on-file-17",
        "known_missing_fields": ["investigation_summary"],
    }


def _final_details() -> dict:
    return {
        "system_name": "Dispatch Decision Support",
        "system_model": "bounded-classifier",
        "software_version": "deployment-2026-08-28",
        "system_purpose": "Supports a bounded infrastructure dispatch decision.",
        "causal_assessment_summary": "The review established a causal relationship.",
        "consequences": "The bounded affected population and harm were confirmed.",
        "estimated_users_affected": 7,
        "system_operator_type": "professional_user",
        "investigation_status": "completed",
        "investigation_summary": "The preserved deployment and logs were reviewed.",
        "planned_investigations": "No further investigation is currently planned.",
        "root_cause_conclusion": "A version-bound classifier defect was confirmed.",
        "corrective_actions": "The route was disabled and a corrected release deployed.",
        "preservation_actions": "Original artifacts and logs remain immutable.",
        "risk_assessment_reviewed": "yes",
        "risk_assessment_still_adequate": "no",
        "risk_assessment_results": "The risk assessment was revised for this failure mode.",
        "final_reportability_conclusion": "reportable",
        "provider_organization_reference": "provider-record-17",
        "submitter_contact_reference": "submitter-contact-17",
        "initial_reporter_contact_reference": "reporter-contact-17",
        "contact_reference": "contact-on-file-17",
        "related_report_references": ["initial-filing-17", "update-filing-17"],
        "other_regulatory_report_references": ["nis2-incident-17"],
        "known_missing_fields": [],
        "attestation_accepted": True,
    }


@pytest.mark.parametrize(
    ("outcomes", "widespread", "expected_days", "expected_rule"),
    [
        ((), False, 15, "article_73_paragraph_2"),
        (("serious_harm_to_health",), False, 15, "article_73_paragraph_2"),
        (("death",), False, 10, "article_73_paragraph_4"),
        (
            ("critical_infrastructure_irreversible_disruption",),
            False,
            2,
            "article_73_paragraph_3",
        ),
        ((), True, 2, "article_73_paragraph_3"),
        (
            ("death", "critical_infrastructure_irreversible_disruption"),
            False,
            2,
            "article_73_paragraph_3",
        ),
    ],
)
def test_article_73_clock_uses_earliest_2_10_15_day_outer_limit(
    outcomes,
    widespread,
    expected_days,
    expected_rule,
):
    awareness = 1_800_000_000.0
    clock = calculate_article_73_clock(
        awareness,
        outcomes=outcomes,
        widespread_infringement=widespread,
        causality="established",
    )

    assert clock["outer_limit_days"] == expected_days
    assert clock["notice"] == incident_api.NON_LEGAL_NOTICE
    expected_date = (
        datetime.fromtimestamp(awareness, tz=ZoneInfo("UTC")).date()
        + timedelta(days=expected_days)
    )
    limit = datetime.fromtimestamp(clock["outer_limit_at"], tz=ZoneInfo("UTC"))
    assert clock["outer_limit_local_date"] == expected_date.isoformat()
    assert limit.date() == expected_date
    assert (limit.hour, limit.minute, limit.second) == (23, 59, 59)
    assert clock["authority_calendar_confirmation_required"] is True
    assert clock["rule"] == expected_rule
    assert clock["timing"].startswith("immediately")
    assert clock["not_gdpr_72_hours"] is True
    assert clock["source_url"] == ARTICLE_73_SOURCE_URL


def test_article_73_uses_calendar_days_not_elapsed_hour_aliases_across_dst():
    zone = ZoneInfo("Europe/Berlin")
    awareness = datetime(2026, 3, 27, 23, 30, tzinfo=zone).timestamp()

    clock = calculate_article_73_clock(
        awareness,
        outcomes=("critical_infrastructure_irreversible_disruption",),
        causality="established",
        calendar_timezone="Europe/Berlin",
    )
    deadline = datetime.fromtimestamp(clock["outer_limit_at"], tz=zone)

    assert clock["outer_limit_days"] == 2
    assert clock["calendar_timezone"] == "Europe/Berlin"
    assert deadline.isoformat() == "2026-03-29T23:59:59+02:00"
    assert clock["outer_limit_at"] - awareness != 48 * 60 * 60
    assert clock["not_gdpr_72_hours"] is True


def test_article_73_thresholds_are_closed_and_causality_keeps_immediate_trigger():
    with pytest.raises(ValueError, match="outcome"):
        calculate_article_73_clock(
            1_800_000_000,
            outcomes=("economic_loss_only",),
        )

    death = calculate_article_73_clock(
        1_800_000_000,
        outcomes=("death",),
        causality="suspected",
    )
    assert death["immediate_trigger"] == "causal_link_suspected_or_established"
    assert death["immediate_trigger_ready"] is True

    health = calculate_article_73_clock(
        1_800_000_000,
        outcomes=("serious_harm_to_health",),
        causality="suspected",
    )
    assert health["immediate_trigger"] == (
        "causal_link_established_or_reasonably_likely"
    )
    assert health["immediate_trigger_ready"] is False


def test_report_template_is_explicitly_internal_and_source_bound():
    template = report_template("final")

    assert template["kind"] == "final"
    assert template["legal_source_url"] == ARTICLE_73_SOURCE_URL
    assert template["template_status"] == (
        "lightwork_internal_informed_by_commission_draft"
    )
    assert "corrective_actions" in template["final_required_text_fields"]
    assert "eu_database_registration_id" in template["fields"]
    assert "risk_assessment_reviewed" in template["fields"]
    assert "submitter_contact_reference" in template["fields"]
    assert template["fields"]["attestation_accepted"] is False
    assert "not legal advice" in template["notice"].lower()


def test_full_initial_update_final_reporting_lifecycle_is_human_gated():
    register = Article73IncidentRegister()
    with tenant_scope(tenant="article-73-lifecycle"):
        incident = _route(register, _open(register))
        assert incident["status"] == "reporting_required"
        route = incident["routing_history"][-1]
        assert route["actor_type"] == "human"
        assert route["authority_role"] == "legal_counsel"

        incident = register.draft_report(
            incident["id"],
            kind="initial",
            details=_initial_details(),
            prepared_by="user:incident-preparer",
            expected_revision=incident["revision"],
        )
        initial = incident["reports"][-1]
        assert incident["status"] == "drafting"
        assert initial["payload"]["known_missing_fields"] == [
            "investigation_summary"
        ]

        incident = register.approve_report(
            incident["id"],
            initial["id"],
            authority=HumanAuthority(
                "user:compliance-approver", "regulatory_compliance_officer"
            ),
            expected_revision=incident["revision"],
        )
        incident = register.record_submission(
            incident["id"],
            initial["id"],
            submission_reference="authority-receipt-initial-17",
            receipt_sha256=_sha("initial authority receipt"),
            authority=HumanAuthority(
                "user:compliance-approver", "regulatory_compliance_officer"
            ),
            expected_revision=incident["revision"],
        )
        assert incident["status"] == "initial_submitted"
        assert incident["reports"][-1]["submission"]["authority_refs"] == [
            "DE-market-surveillance-route"
        ]

        update_details = _initial_details()
        update_details["investigation_summary"] = (
            "The bounded investigation has identified the affected release."
        )
        update_details["known_missing_fields"] = []
        incident = register.draft_report(
            incident["id"],
            kind="update",
            details=update_details,
            prepared_by="user:incident-preparer",
            expected_revision=incident["revision"],
        )
        update = incident["reports"][-1]
        incident = register.approve_report(
            incident["id"],
            update["id"],
            authority=HumanAuthority("user:legal-approver", "legal_counsel"),
            expected_revision=incident["revision"],
        )
        incident = register.record_submission(
            incident["id"],
            update["id"],
            submission_reference="authority-receipt-update-17",
            receipt_sha256=_sha("update authority receipt"),
            authority=HumanAuthority("user:legal-approver", "legal_counsel"),
            expected_revision=incident["revision"],
        )
        assert incident["status"] == "follow_up"

        incident = register.draft_report(
            incident["id"],
            kind="final",
            details=_final_details(),
            prepared_by="user:incident-preparer",
            expected_revision=incident["revision"],
        )
        final = incident["reports"][-1]
        incident = register.approve_report(
            incident["id"],
            final["id"],
            authority=HumanAuthority(
                "user:provider-representative",
                "authorized_provider_representative",
            ),
            expected_revision=incident["revision"],
        )
        incident = register.record_submission(
            incident["id"],
            final["id"],
            submission_reference="authority-receipt-final-17",
            receipt_sha256=_sha("final authority receipt"),
            authority=HumanAuthority(
                "user:provider-representative",
                "authorized_provider_representative",
            ),
            expected_revision=incident["revision"],
        )

        assert incident["status"] == "final_submitted"
        assert [report["kind"] for report in incident["reports"]] == [
            "initial",
            "update",
            "final",
        ]
        assert all(report["status"] == "submitted" for report in incident["reports"])
        assert register.get_report_payload(incident["id"], final["id"]) == final[
            "payload"
        ]


def test_safe_projection_is_bounded_audit_evidence_without_report_narratives():
    register = Article73IncidentRegister()
    with tenant_scope(tenant="article-73-safe-projection"):
        incident = _route(register, _open(register, outcomes=("death",)))
        details = _final_details()
        details["investigation_summary"] = "SENSITIVE INTERNAL INVESTIGATION DETAIL"
        incident = register.draft_report(
            incident["id"],
            kind="final",
            details=details,
            prepared_by="user:preparer-secret",
            expected_revision=incident["revision"],
        )
        report = incident["reports"][-1]
        incident = register.approve_report(
            incident["id"],
            report["id"],
            authority=HumanAuthority("user:approver-secret", "legal_counsel"),
            expected_revision=incident["revision"],
        )
        incident = register.record_submission(
            incident["id"],
            report["id"],
            submission_reference="external-secret-reference",
            receipt_sha256=_sha("safe projection receipt"),
            authority=HumanAuthority("user:approver-secret", "legal_counsel"),
            expected_revision=incident["revision"],
        )
        projection = register.safe_projection(incident["id"])

        assert projection is not None
        rendered = json.dumps(projection, sort_keys=True)
        assert "SENSITIVE INTERNAL INVESTIGATION DETAIL" not in rendered
        assert "external-secret-reference" not in rendered
        assert "user:preparer-secret" not in rendered
        assert "user:approver-secret" not in rendered
        assert projection["reports"][0]["payload_sha256"] == report[
            "payload_sha256"
        ]
        assert projection["clock"]["status"] == "submission_recorded"
        assert projection["clock"]["first_submission_within_base_limit"] is True
        assert projection["reports"][0]["authority_refs"] == [
            "DE-market-surveillance-route"
        ]


def test_tenant_isolation_hides_record_and_safe_list():
    register = Article73IncidentRegister()
    with tenant_scope(tenant="article-73-tenant-alpha"):
        alpha = _open(register)
        assert register.get(alpha["id"])["tenant_sha256"] == alpha["tenant_sha256"]

    with tenant_scope(tenant="article-73-tenant-beta"):
        assert register.get(alpha["id"]) is None
        assert register.list_safe() == []
        beta = _open(register, outcomes=("death",))

    with tenant_scope(tenant="article-73-tenant-alpha"):
        assert register.get(beta["id"]) is None
        assert [item["incident_id"] for item in register.list_safe()] == [alpha["id"]]


def test_unbound_tenant_and_non_human_authority_fail_closed(monkeypatch):
    register = Article73IncidentRegister()
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import client

    client.reset_client_cache()
    with pytest.raises(Article73StateError, match="explicit tenant"):
        _open(register)

    with pytest.raises(ValueError, match="authenticated user"):
        HumanAuthority("agent:legal-reviewer", "legal_counsel")
    with pytest.raises(ValueError, match="authority role"):
        HumanAuthority("user:legal-reviewer", "automation")


def test_global_wrappers_are_default_off_and_use_the_governed_register(monkeypatch):
    monkeypatch.setattr(incident_api, "enabled", lambda: False)
    with pytest.raises(Article73ConfigurationError, match="disabled"):
        incident_api.list_incidents()

    monkeypatch.setattr(incident_api, "enabled", lambda: True)
    with tenant_scope(tenant="article-73-global-wrapper"):
        opened = incident_api.open_incident(
            "Wrapper triage",
            asset_id="wrapper-system",
            asset_version="wrapper-version",
            awareness_at=time.time() - 1,
            summary="A bounded wrapper smoke test.",
            opened_by="wrapper-ingestor",
        )
        assert incident_api.get_incident(opened["id"])["id"] == opened["id"]
        assert incident_api.get_safe_projection(opened["id"])["incident_id"] == (
            opened["id"]
        )
        assert [item["incident_id"] for item in incident_api.list_incidents()] == [
            opened["id"]
        ]


def test_future_awareness_is_rejected_instead_of_extending_the_clock():
    register = Article73IncidentRegister()
    with tenant_scope(tenant="article-73-future-awareness"):
        with pytest.raises(ValueError, match="awareness_at cannot be in the future"):
            register.open_incident(
                "Future awareness",
                asset_id="future-system",
                asset_version="future-version",
                awareness_at=time.time() + 3_600,
                summary="This clock anchor must fail closed.",
                opened_by="incident-ingestor",
            )


def test_invalid_transitions_and_stale_cas_are_rejected():
    register = Article73IncidentRegister()
    with tenant_scope(tenant="article-73-invalid-transitions"):
        incident = _open(register)
        with pytest.raises(Article73StateError, match="decision is required"):
            register.draft_report(
                incident["id"],
                kind="initial",
                details=_initial_details(),
                prepared_by="user:incident-preparer",
                expected_revision=incident["revision"],
            )

        stale_revision = incident["revision"]
        incident = _route(register, incident)
        with pytest.raises(RecordConflict):
            register.record_routing_decision(
                incident["id"],
                decision="legal_review_required",
                threshold_determination="uncertain",
                applicability_determination="uncertain",
                rationale="A stale reviewer should not overwrite the final route.",
                authority=HumanAuthority("user:other-counsel", "legal_counsel"),
                expected_revision=stale_revision,
            )
        with pytest.raises(Article73StateError, match="first report"):
            register.draft_report(
                incident["id"],
                kind="update",
                details=_initial_details(),
                prepared_by="user:incident-preparer",
                expected_revision=incident["revision"],
            )
        with pytest.raises(Article73StateError, match="incomplete"):
            register.draft_report(
                incident["id"],
                kind="final",
                details={"investigation_status": "completed"},
                prepared_by="user:incident-preparer",
                expected_revision=incident["revision"],
            )

        incident = register.draft_report(
            incident["id"],
            kind="initial",
            details=_initial_details(),
            prepared_by="user:incident-preparer",
            expected_revision=incident["revision"],
        )
        report = incident["reports"][-1]
        with pytest.raises(Article73StateError, match="before approval"):
            register.get_report_payload(incident["id"], report["id"])
        with pytest.raises(Article73StateError, match="approved report"):
            register.record_submission(
                incident["id"],
                report["id"],
                submission_reference="premature-submission",
                receipt_sha256=_sha("premature"),
                authority=HumanAuthority("user:legal-reviewer", "legal_counsel"),
                expected_revision=incident["revision"],
            )
        with pytest.raises(Article73StateError, match="four-eyes"):
            register.approve_report(
                incident["id"],
                report["id"],
                authority=HumanAuthority("user:incident-preparer", "legal_counsel"),
                expected_revision=incident["revision"],
            )
        incident = register.approve_report(
            incident["id"],
            report["id"],
            authority=HumanAuthority("user:legal-reviewer", "legal_counsel"),
            expected_revision=incident["revision"],
        )
        with pytest.raises(ValueError, match="submitted_at cannot be in the future"):
            register.record_submission(
                incident["id"],
                report["id"],
                submission_reference="future-submission",
                receipt_sha256=_sha("future receipt"),
                authority=HumanAuthority("user:legal-reviewer", "legal_counsel"),
                expected_revision=incident["revision"],
                submitted_at=time.time() + 3_600,
            )


def test_human_do_not_report_decision_is_terminal_and_requires_negative_basis():
    register = Article73IncidentRegister()
    with tenant_scope(tenant="article-73-not-reportable"):
        incident = _open(register, outcomes=(), causality="not_supported")
        with pytest.raises(Article73StateError, match="negative threshold"):
            register.record_routing_decision(
                incident["id"],
                decision="do_not_report",
                threshold_determination="met",
                applicability_determination="applies",
                rationale="This contradictory result must fail.",
                authority=HumanAuthority("user:legal-reviewer", "legal_counsel"),
                expected_revision=incident["revision"],
            )

        incident = register.record_routing_decision(
            incident["id"],
            decision="do_not_report",
            threshold_determination="not_met",
            applicability_determination="applies",
            rationale="Counsel determined the Article 3(49) threshold was not met.",
            authority=HumanAuthority("user:legal-reviewer", "legal_counsel"),
            expected_revision=incident["revision"],
        )
        assert incident["status"] == "not_reportable"
        with pytest.raises(Article73StateError, match="cannot receive"):
            register.draft_report(
                incident["id"],
                kind="initial",
                details=_initial_details(),
                prepared_by="user:incident-preparer",
                expected_revision=incident["revision"],
            )
