from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest
from maverick import ai_evidence_analysis as evidence
from maverick import assessment as assessment_ops
from maverick import assessment_evidence_autopopulation as autopop
from maverick.paths import tenant_scope

NOW = 1_900_000_000.0
TENANT = "assessment-evidence-tenant"


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)


def _assessment() -> dict:
    with tenant_scope(tenant=TENANT):
        session = assessment_ops.AssessmentSession(type="pia", subject="Acme processing")
        assessment_ops.save_session(session)
        record = assessment_ops.load_saved(session.id)
    assert record is not None
    return record


def _criterion() -> evidence.EvidenceCriterion:
    raw = evidence.EvidenceCriterion(
        criterion_id="pia_security",
        revision=1,
        control_ref="control-encryption",
        control_revision=1,
        control_sha256=_hex("control"),
        legal_basis_ref="basis-security",
        legal_basis_revision=1,
        legal_basis_sha256=_hex("basis"),
        stakeholder_requirement_ref="stakeholder-security",
        stakeholder_requirement_revision=1,
        stakeholder_requirement_sha256=_hex("stakeholder"),
        expected_fact_code="FACT.encryption",
        gap_code="gap-encryption",
        remediation_code="remediate-encryption",
        weight_bps=10_000,
        criterion_sha256="0" * 64,
    )
    return replace(raw, criterion_sha256=evidence.criterion_sha256(raw))


def _evidence_record(*, disposition: str = "evidence_supported", confidence: int = 9_500):
    tenant_sha = autopop._tenant_digest(TENANT)
    criterion = _criterion()
    criteria = evidence.EvidenceCriteriaAuthority(
        tenant_sha256=tenant_sha,
        criteria_set_id="assessment-pia-v1",
        revision=1,
        criteria=(criterion,),
        valid_until=NOW + 3_600,
        revoked=False,
        authority_sha256=_hex("criteria-authority"),
    )
    artifact_authority = evidence.EvidenceArtifactAuthority(
        tenant_sha256=tenant_sha,
        artifact_id="artifact-security",
        media_type=evidence.MEDIA_PDF,
        content_sha256=_hex("artifact"),
        byte_length=100,
        source_ref="vendor-dpa",
        source_revision=2,
        acquired_at=NOW - 60,
        valid_until=NOW + 3_600,
        revoked=False,
        authority_sha256=_hex("artifact-authority"),
    )
    artifact = evidence.EvidenceArtifactRecord(
        artifact_id="artifact-security",
        media_type=evidence.MEDIA_PDF,
        content_sha256=_hex("artifact"),
        byte_length=100,
        source_ref="vendor-dpa",
        source_revision=2,
        acquired_at=NOW - 60,
        artifact_authority_sha256=artifact_authority.authority_sha256,
        descriptor_sha256=_hex("descriptor"),
    )
    adapter = evidence.EvidenceAdapterAuthority(
        stage="analysis",
        adapter_id="adapter-one",
        revision=1,
        implementation_sha256=_hex("implementation"),
        configuration_sha256=_hex("configuration"),
        deterministic=True,
        network_access=False,
        untrusted_content_mode="data_only",
        legal_conclusion_enabled=False,
        valid_until=NOW + 3_600,
        revoked=False,
        authority_sha256=_hex("adapter-authority"),
    )
    extraction_adapter = replace(
        adapter,
        stage="extraction",
        authority_sha256=_hex("extraction-adapter-authority"),
    )
    fact = evidence.ExtractedEvidenceFact(
        fact_id="fact-security",
        fact_code="FACT.encryption",
        locator_sha256=_hex("locator"),
        value_sha256=_hex("value"),
        confidence_bps=confidence,
        fact_sha256=_hex("fact"),
    )
    extraction = evidence.EvidenceExtractionOutput(
        schema=evidence.EXTRACTION_OUTPUT_SCHEMA,
        request_sha256=_hex("extract-request"),
        artifact_descriptor_sha256=artifact.descriptor_sha256,
        criteria_authority_sha256=criteria.authority_sha256,
        adapter_authority_sha256=extraction_adapter.authority_sha256,
        deterministic=True,
        facts=(fact,) if disposition != "evidence_missing" else (),
        output_sha256=_hex("extract-output"),
    )
    criterion_assessment = evidence.CriterionEvidenceAssessment(
        criterion_id=criterion.criterion_id,
        criterion_sha256=criterion.criterion_sha256,
        disposition=disposition,
        fact_ids=(fact.fact_id,) if disposition == "evidence_supported" else (),
        confidence_bps=confidence,
        rationale_code="direct_evidence" if disposition == "evidence_supported" else "no_matching_evidence",
        assessment_sha256=_hex("criterion-assessment-" + disposition),
    )
    analysis = evidence.EvidenceAnalysisAdapterOutput(
        schema=evidence.ANALYSIS_OUTPUT_SCHEMA,
        request_sha256=_hex("analysis-request"),
        artifact_descriptor_sha256=artifact.descriptor_sha256,
        criteria_authority_sha256=criteria.authority_sha256,
        extraction_output_sha256=extraction.output_sha256,
        adapter_authority_sha256=adapter.authority_sha256,
        deterministic=True,
        assessments=(criterion_assessment,),
        output_sha256=_hex("analysis-output"),
    )
    return evidence.EvidenceAnalysisRecord(
        analysis_id="analysis-security",
        tenant_sha256=tenant_sha,
        artifact_authority=artifact_authority,
        artifact=artifact,
        criteria_authority=criteria,
        extraction_adapter_authority=extraction_adapter,
        analysis_adapter_authority=adapter,
        extraction=extraction,
        adapter_analysis=analysis,
        summary=evidence.EvidenceSummary(1, 1, 0, 0, 0, 1, _hex("summary")),
        justification=evidence.JustificationScore(
            "test", (), confidence, 10_000, _hex("score")
        ),
        gaps=(),
        provenance=(
            evidence.EvidenceProvenanceLink(
                1,
                "source_authority",
                artifact_authority.authority_sha256,
                artifact.descriptor_sha256,
                "0" * 64,
                _hex("provenance"),
            ),
        ),
        provenance_sha256=_hex("provenance"),
        submitter_sha256=_hex("submitter"),
        status="review_approved",
        human_review_required=True,
        review_decision="approve",
        review_authority=None,
        reviewed_at=NOW - 30,
        revocation_authority=None,
        revocation_reason_code=None,
        revoked_at=None,
        legal_or_compliance_conclusion=False,
        notice=evidence.NON_CONCLUSION_NOTICE,
        valid_until=NOW + 3_600,
        retained_until=NOW + 7_200,
        created_at=NOW - 120,
        updated_at=NOW - 30,
        revision=2,
        previous_integrity_sha256=_hex("previous"),
        integrity_sha256=_hex("analysis-integrity"),
    )


def _service(record, evidence_record, *, apply_enabled=True, clock=lambda: NOW):
    return autopop.AssessmentEvidenceService(
        tenant_id=TENANT,
        settings=autopop.AssessmentEvidenceSettings(
            apply_enabled=apply_enabled,
            retention_seconds=60,
        ),
        assessment_resolver=lambda assessment_id: (
            record if assessment_id == record["id"] else None
        ),
        evidence_resolver=lambda analysis_id: (
            evidence_record if analysis_id == evidence_record.analysis_id else None
        ),
        clock=clock,
    )


def test_proposal_is_cited_review_only_and_idempotent():
    assessment = _assessment()
    released = _evidence_record()
    service = _service(assessment, released)
    with tenant_scope(tenant=TENANT):
        proposal = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="create-one",
        )
        replay = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="create-one",
        )
        unchanged = assessment_ops.load_saved(assessment["id"])

    assert replay["id"] == proposal["id"]
    assert proposal["status"] == "pending_review"
    assert proposal["candidates"][0]["question_id"] == "pia_security"
    assert proposal["candidates"][0]["answer"] == "yes"
    assert proposal["candidates"][0]["eligible_for_apply"] is True
    citation = proposal["candidates"][0]["citations"][0]
    assert citation["analysis_integrity_sha256"] == released.integrity_sha256
    assert citation["facts"][0]["locator_sha256"] == _hex("locator")
    assert "text" not in str(citation).lower()
    assert unchanged is not None and unchanged["answers"] == {}
    assert unchanged["revision"] == assessment["revision"]


def test_independent_approval_then_separate_apply_fills_only_unanswered():
    assessment = _assessment()
    released = _evidence_record()
    service = _service(assessment, released)
    with tenant_scope(tenant=TENANT):
        proposal = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="create-two",
        )
        with pytest.raises(autopop.AssessmentEvidenceTransitionError, match="creator"):
            service.review_proposal(
                proposal["id"],
                decision="approve",
                selected_question_ids=["pia_security"],
                rationale="reviewed evidence",
                actor="creator",
                expected_revision=proposal["revision"],
                idempotency_key="review-self",
            )
        approved = service.review_proposal(
            proposal["id"],
            decision="approve",
            selected_question_ids=["pia_security"],
            rationale="reviewed evidence",
            actor="reviewer",
            expected_revision=proposal["revision"],
            idempotency_key="review-two",
        )
        before_apply = assessment_ops.load_saved(assessment["id"])
        applied = service.apply_proposal(
            proposal["id"],
            actor="operator",
            expected_revision=approved["revision"],
            expected_assessment_revision=assessment["revision"],
            idempotency_key="apply-two",
        )
        after_apply = assessment_ops.load_saved(assessment["id"])
        replay = service.apply_proposal(
            proposal["id"],
            actor="operator",
            expected_revision=applied["revision"],
            expected_assessment_revision=assessment["revision"],
            idempotency_key="apply-two",
        )

    assert before_apply is not None and before_apply["answers"] == {}
    assert applied["status"] == "applied"
    assert replay["revision"] == applied["revision"]
    assert after_apply is not None
    answer = after_apply["answers"]["pia_security"]
    assert answer["answer"] == "yes"
    assert answer["ai_metadata"]["source"] == {
        "kind": "document_evidence",
        "ref": proposal["id"],
        "sha256": proposal["proposal_sha256"],
    }
    assert answer["ai_metadata"]["application_receipt"]["schema"] == (
        autopop.APPLICATION_RECEIPT_SCHEMA
    )
    assert after_apply["status"] == "pending_review"


def test_application_recovery_requires_applier_only_receipt():
    assessment = _assessment()
    released = _evidence_record()
    service = _service(assessment, released)
    with tenant_scope(tenant=TENANT):
        proposal = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="recovery-receipt",
        )
        candidate = proposal["candidates"][0]
        first = autopop.apply_answers_to_assessment(
            assessment["id"],
            [candidate],
            proposal_id=proposal["id"],
            proposal_sha256=proposal["proposal_sha256"],
            actor="operator",
            expected_revision=assessment["revision"],
        )
        replay = autopop.apply_answers_to_assessment(
            assessment["id"],
            [candidate],
            proposal_id=proposal["id"],
            proposal_sha256=proposal["proposal_sha256"],
            actor="different-operator",
            expected_revision=assessment["revision"],
        )
    assert replay == first


def test_user_authorable_ai_metadata_cannot_spoof_application_recovery():
    assessment = _assessment()
    released = _evidence_record()
    service = _service(assessment, released)
    with tenant_scope(tenant=TENANT):
        proposal = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="spoofed-recovery",
        )
        candidate = proposal["candidates"][0]

        def add_answer(record):
            record["answers"]["pia_security"] = {
                "answer": candidate["answer"],
                "note": "ordinary user answer",
            }

        answered = assessment_ops._rewrite_saved(  # noqa: SLF001 - adversarial fixture
            assessment["id"],
            add_answer,
            expected_revision=assessment["revision"],
        )
        assert answered is not None
        spoofed = assessment_ops.set_assessment_answer_ai_metadata(
            assessment["id"],
            "pia_security",
            confidence=0.95,
            flags=["human_review_required"],
            source_kind="document_evidence",
            source_ref=proposal["id"],
            source_sha256=proposal["proposal_sha256"],
            recorded_by="operator",
            expected_revision=answered["revision"],
        )
        assert spoofed is not None
        with pytest.raises(autopop.AssessmentEvidenceConflict, match="changed"):
            autopop.apply_answers_to_assessment(
                assessment["id"],
                [candidate],
                proposal_id=proposal["id"],
                proposal_sha256=proposal["proposal_sha256"],
                actor="operator",
                expected_revision=assessment["revision"],
            )


def test_missing_or_low_confidence_evidence_never_becomes_applicable():
    assessment = _assessment()
    released = _evidence_record(disposition="evidence_missing", confidence=0)
    service = _service(assessment, released)
    with tenant_scope(tenant=TENANT):
        proposal = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="create-missing",
        )
        with pytest.raises(autopop.AssessmentEvidenceValidationError, match="eligible"):
            service.review_proposal(
                proposal["id"],
                decision="approve",
                selected_question_ids=["pia_security"],
                rationale="reviewed",
                actor="reviewer",
                expected_revision=proposal["revision"],
                idempotency_key="approve-missing",
            )
    assert proposal["candidates"][0]["answer"] == "unknown"
    assert proposal["candidates"][0]["eligible_for_apply"] is False


def test_apply_gate_and_stale_or_overwrite_paths_fail_closed():
    assessment = _assessment()
    released = _evidence_record()
    disabled = _service(assessment, released, apply_enabled=False)
    with tenant_scope(tenant=TENANT):
        proposal = disabled.create_proposal(
            assessment["id"], [released.analysis_id], actor="creator", idempotency_key="off-create"
        )
        approved = disabled.review_proposal(
            proposal["id"],
            decision="approve",
            selected_question_ids=["pia_security"],
            rationale="reviewed",
            actor="reviewer",
            expected_revision=proposal["revision"],
            idempotency_key="off-review",
        )
        with pytest.raises(autopop.AssessmentEvidenceConfigError, match="disabled"):
            disabled.apply_proposal(
                proposal["id"],
                actor="operator",
                expected_revision=approved["revision"],
                expected_assessment_revision=assessment["revision"],
                idempotency_key="off-apply",
            )


def test_retention_scrubs_candidates_and_integrity_remains_verifiable():
    clock = [NOW]
    assessment = _assessment()
    released = _evidence_record()
    service = _service(assessment, released, clock=lambda: clock[0])
    with tenant_scope(tenant=TENANT):
        proposal = service.create_proposal(
            assessment["id"], [released.analysis_id], actor="creator", idempotency_key="expire"
        )
        clock[0] = NOW + 61
        purged = service.purge_expired(limit=10)
        report = service.verify_integrity()
    assert purged == (proposal["id"],)
    with tenant_scope(tenant=TENANT), pytest.raises(autopop.AssessmentEvidenceNotFound):
        service.get_proposal(proposal["id"])
    assert report.records == 0 and report.expired == 0 and report.verified is True


def test_retention_purge_releases_the_configured_capacity_slot():
    clock = [NOW]
    assessment = _assessment()
    released = _evidence_record()
    service = autopop.AssessmentEvidenceService(
        tenant_id=TENANT,
        settings=autopop.AssessmentEvidenceSettings(
            apply_enabled=True,
            retention_seconds=60,
            max_records=1,
        ),
        assessment_resolver=lambda identifier: (
            assessment if identifier == assessment["id"] else None
        ),
        evidence_resolver=lambda identifier: (
            released if identifier == released.analysis_id else None
        ),
        clock=lambda: clock[0],
    )
    with tenant_scope(tenant=TENANT):
        first = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="capacity-first",
        )
        clock[0] = NOW + 61
        assert service.purge_expired(limit=1) == (first["id"],)
        second = service.create_proposal(
            assessment["id"],
            [released.analysis_id],
            actor="creator",
            idempotency_key="capacity-second",
        )
    assert second["id"] != first["id"]


def test_settings_and_mapping_contracts_are_closed():
    with pytest.raises(autopop.AssessmentEvidenceValidationError, match="apply_enabled"):
        autopop.AssessmentEvidenceSettings(apply_enabled=1)  # type: ignore[arg-type]
    assessment = _assessment()
    released = _evidence_record()
    authority = autopop.derive_exact_mapping_authority(
        TENANT, assessment, [released], now=NOW
    )
    assert authority.mappings[0].question_id == "pia_security"
    assert authority.mappings[0].supported_answer == "yes"
    assert autopop.mapping_authority_sha256(authority) == authority.authority_sha256
