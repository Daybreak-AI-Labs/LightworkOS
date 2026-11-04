"""Acceptance and adversarial tests for governed third-party AI vendor risk."""
from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest
from maverick import ai_vendor_risk as avr
from maverick import model_risk_assurance as mra
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        "enable = true\n"
        "\n[model_risk_assurance]\n"
        "enable = true\n"
        "gate_promotions = true\n",
        encoding="utf-8",
    )
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _safe_answers() -> dict[str, str]:
    return {
        "aiv_provenance": "yes",
        "aiv_training_data": "yes",
        "aiv_subprocessors": "yes",
        "aiv_evaluation": "yes",
        "aiv_incidents": "no",
        "aiv_eu_role": "yes",
        "aiv_retention": "yes",
        "aiv_human_oversight": "yes",
    }


def test_feature_gate_is_explicit_and_depends_on_model_risk(tmp_path):
    from maverick import config

    assert avr.enabled() is False
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        config_path.read_text(encoding="utf-8")
        + "\n[ai_vendor_risk]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert avr.enabled() is True


def _full_vendor_document() -> bytes:
    return (
        b"Model provenance is documented with the foundation model provider and version. "
        b"Training-data sources are documented and licensed. Customer prompts are never "
        b"used for training. The subprocessor list is published and updated with advance "
        b"notice. The vendor provides evaluation reports and red-team evidence. No material "
        b"AI incidents have occurred in the last 24 months. Under the EU AI Act, Acme acts "
        b"as provider and customers act as deployers. Prompts are retained for 30 days and "
        b"then deleted. Human reviewers can override and stop generated outputs."
    )


def test_questionnaire_covers_every_required_ai_vendor_domain():
    assert len(avr.AI_VENDOR_QUESTIONS) == 8
    identifiers = {question.id for question in avr.AI_VENDOR_QUESTIONS}
    assert identifiers == {
        "aiv_provenance",
        "aiv_training_data",
        "aiv_subprocessors",
        "aiv_evaluation",
        "aiv_incidents",
        "aiv_eu_role",
        "aiv_retention",
        "aiv_human_oversight",
    }


@pytest.mark.parametrize("qid,text", [
    ("aiv_provenance", "Model provenance is not documented."),
    ("aiv_training_data", "Training-data sources are not documented or licensed."),
    ("aiv_subprocessors", "The subprocessor list is not published."),
    ("aiv_evaluation", "The vendor does not provide evaluation reports."),
    ("aiv_incidents", "We have not experienced an AI incident."),
    ("aiv_eu_role", "Under the EU AI Act we are not identified as the provider."),
    ("aiv_retention", "Customer data is not retained for 30 days."),
    ("aiv_human_oversight", "Human oversight is not implemented."),
    ("aiv_provenance", "Model provenance is planned to be documented."),
    ("aiv_provenance", "Model provenance is documented but is not documented for old models."),
    ("aiv_incidents", "It is not true that no AI incidents have occurred."),
    ("aiv_incidents", "AI incident history is not clear."),
])
def test_document_negation_and_uncertainty_cannot_create_affirmative_control(qid, text):
    with tenant_scope(tenant="acme"):
        extracted = avr.extract_answers_from_document(text.encode(), "text/plain")
    answer = extracted["answers"].get(qid)
    assert answer is None or answer["answer"] == "unknown"
    if answer is not None:
        assert answer["confidence"] == 0
    assert extracted["review_required"]


def test_document_matching_does_not_cross_sentence_boundaries():
    with tenant_scope(tenant="acme"):
        extracted = avr.extract_answers_from_document(b"Model provenance requires review. Something unrelated is documented.", "text/plain")
    assert "aiv_provenance" not in extracted["answers"]
    assert avr.AI_VENDOR_TEMPLATE.type == "ai_vendor_risk"


def test_public_questionnaire_is_exactly_template_bound():
    with tenant_scope(tenant="acme"):
        questionnaire = avr.questionnaire()

    assert questionnaire["schema"] == "lightwork.ai-vendor-questionnaire.v1"
    assert questionnaire["template_revision"] == 1
    assert len(questionnaire["template_digest"]) == 64
    assert [row["id"] for row in questionnaire["questions"]] == [
        question.id for question in avr.AI_VENDOR_QUESTIONS
    ]
    assert "certification" in questionnaire["notice"]


def test_vendor_attestation_is_distinct_review_required_provenance():
    attestation_sha = _hex("vendor-portal-submission")
    with tenant_scope(tenant="acme"):
        draft = avr.draft_vendor_assessment(
            "Acme AI",
            answers={"aiv_provenance": "no"},
            attested_answers=_safe_answers(),
            attestation_sha256=attestation_sha,
            actor="user:risk-owner",
            use_prior=False,
        )

    assert draft["answers"]["aiv_provenance"]["answer"] == "no"
    assert draft["answer_sources"]["aiv_provenance"] == {
        "kind": "manual",
        "confidence": 1.0,
    }
    for question_id, source in draft["answer_sources"].items():
        if question_id == "aiv_provenance":
            continue
        assert source == {
            "kind": "vendor_attested",
            "confidence": 0.75,
            "review_required": True,
            "submission_sha256": attestation_sha,
        }
    assert draft["status"] == "pending_review"

    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="attestation_sha256"):
            avr.draft_vendor_assessment(
                "No Digest",
                attested_answers={"aiv_provenance": "yes"},
                actor="user:risk-owner",
                use_prior=False,
            )


def test_every_operation_requires_explicit_tenant_authority():
    with pytest.raises(avr.AIVendorRiskStateError, match="explicit tenant"):
        avr.draft_vendor_assessment("Acme", actor="risk-owner")
    with pytest.raises(avr.AIVendorRiskStateError, match="explicit tenant"):
        avr.list_vendor_assessments()
    with pytest.raises(avr.AIVendorRiskStateError, match="explicit tenant"):
        avr.extract_answers_from_document(b"policy", "text/plain")


def test_document_extraction_produces_all_answers_with_bound_citations():
    with tenant_scope(tenant="acme"):
        result = avr.extract_answers_from_document(
            _full_vendor_document(),
            "text/plain",
            source="gdrive",
            document_id="contract-123",
            ref={"drive": "risk", "item": "123"},
        )

    assert result["schema"] == avr.AI_VENDOR_DOCUMENT_SCHEMA
    assert result["review_required"] is True
    assert result["unanswered"] == []
    assert {qid: row["answer"] for qid, row in result["answers"].items()} == _safe_answers()
    evidence = result["document_evidence"]
    assert evidence["schema"] == "lightwork.document-extraction-evidence.v1"
    assert "contract-123" not in json.dumps(result)
    for row in result["answers"].values():
        assert 0 < row["confidence"] <= 0.88
        assert 1 <= len(row["citations"]) <= 3
        for citation in row["citations"]:
            assert citation["document_sha256"] == evidence["document_sha256"]
            assert citation["source_binding_sha256"] == evidence["source_binding_sha256"]
            assert citation["quote"]


def test_document_citation_redacts_secret_and_never_persists_full_text():
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    document = (
        "Model provenance is documented with provider and version " + secret + ". "
        "This unrelated confidential paragraph must not be retained anywhere."
    ).encode("utf-8")
    with tenant_scope(tenant="acme"):
        extracted = avr.extract_answers_from_document(
            document,
            "text/plain",
            source="upload",
            document_id="vendor-policy",
        )
        draft = avr.draft_vendor_assessment(
            "Acme AI",
            document_results=[extracted],
            actor="risk-owner",
            use_prior=False,
        )

    serialized = json.dumps({"extracted": extracted, "draft": draft})
    assert secret not in serialized
    assert "[REDACTED:openai_api_key]" in serialized
    assert "unrelated confidential paragraph" not in json.dumps(draft)
    assert draft["answer_sources"]["aiv_provenance"]["kind"] == "document"


def test_conflicting_document_cannot_be_overruled_by_second_clear_document():
    with tenant_scope(tenant="acme"):
        conflict = avr.extract_answers_from_document(
            b"Model provenance is documented. Model provenance is undisclosed.", "text/plain", document_id="conflict")
        clear = avr.extract_answers_from_document(
            b"Model provenance is documented with provider and version.", "text/plain", document_id="clear")
        assert conflict["answers"]["aiv_provenance"]["answer"] == "unknown"
        for results in ([conflict, clear], [clear, conflict]):
            draft = avr.draft_vendor_assessment("Synthetic conflict", document_results=results,
                                                actor="risk-owner", use_prior=False)
            assert draft["answers"]["aiv_provenance"]["answer"] == "unknown"
            assert "Conflicting" in draft["answers"]["aiv_provenance"]["note"]


def test_tampered_document_citation_is_rejected_before_governed_write():
    with tenant_scope(tenant="acme"):
        extracted = avr.extract_answers_from_document(
            _full_vendor_document(), "text/plain"
        )
        tampered = copy.deepcopy(extracted)
        tampered["answers"]["aiv_provenance"]["citations"][0]["quote"] = "fabricated"
        with pytest.raises(avr.AIVendorRiskStateError, match="display digest"):
            avr.draft_vendor_assessment(
                "Acme", document_results=[tampered], actor="risk-owner"
            )
        assert avr.list_vendor_assessments()["count"] == 0


def test_document_answer_cannot_be_transplanted_between_tenants():
    with tenant_scope(tenant="acme"):
        extracted = avr.extract_answers_from_document(
            _full_vendor_document(), "text/plain"
        )
    with tenant_scope(tenant="globex"):
        with pytest.raises(avr.AIVendorRiskStateError, match="tenant binding"):
            avr.draft_vendor_assessment(
                "Acme", document_results=[extracted], actor="risk-owner"
            )


def test_deterministic_draft_uses_shared_assessment_engine_semantics():
    with tenant_scope(tenant="acme"):
        draft = avr.draft_vendor_assessment(
            "Acme AI",
            answers={"aiv_provenance": "no", "aiv_incidents": "yes"},
            actor="risk-owner",
            use_prior=False,
        )

    result = draft["result"]
    assert result["type"] == "ai_vendor_risk"
    assert result["total"] == 8
    assert result["answered"] == 2
    assert result["risk_rating"] == "high"
    assert {finding["kind"] for finding in result["findings"]} == {"risk", "unverified"}
    assert draft["template_digest"]
    assert draft["template_snapshot"]["type"] == "ai_vendor_risk"
    assert draft["status"] == "pending_review"
    assert draft["review_required"] is True


def test_recomputed_plain_hash_cannot_bypass_semantic_result_validation():
    with tenant_scope(tenant="acme"):
        draft = avr.draft_vendor_assessment(
            "Acme AI", answers=_safe_answers(), actor="risk-owner", use_prior=False
        )
        tampered = copy.deepcopy(draft)
        tampered["result"]["risk_rating"] = "critical"
        tampered["assessment_sha256"] = avr._sha256(avr._assessment_payload(tampered))
        with pytest.raises(avr.AIVendorRiskStateError, match="deterministic result"):
            avr._validated_record(tampered)


def test_current_manual_answer_overrides_document_and_prior():
    with tenant_scope(tenant="acme"):
        first = avr.draft_vendor_assessment(
            "Acme AI", answers=_safe_answers(), actor="first", use_prior=False
        )
        approved = avr.review_vendor_assessment(
            first["id"],
            decision="approved",
            rationale="Reviewed against the diligence packet.",
            reviewer="reviewer",
            expected_revision=first["revision"],
        )
        assert approved["status"] == "approved"
        doc = avr.extract_answers_from_document(
            b"Model provenance is unavailable and undisclosed.", "text/plain"
        )
        second = avr.draft_vendor_assessment(
            "Acme AI",
            answers={"aiv_provenance": "yes"},
            document_results=[doc],
            actor="second",
        )

    assert second["answers"]["aiv_provenance"]["answer"] == "yes"
    assert second["answer_sources"]["aiv_provenance"]["kind"] == "manual"
    assert "aiv_provenance" not in second["skipped_prior_questions"]
    assert set(second["skipped_prior_questions"]) == set(_safe_answers()) - {
        "aiv_provenance"
    }


def test_only_approved_prior_answers_are_skipped_and_digest_cited():
    with tenant_scope(tenant="acme"):
        pending = avr.draft_vendor_assessment(
            "Pending Corp", answers=_safe_answers(), actor="author", use_prior=False
        )
        assert pending["status"] == "pending_review"
        assert avr.prior_answer_plan("Pending Corp")["skipped"] == {}

        first = avr.draft_vendor_assessment(
            "Approved Corp", answers=_safe_answers(), actor="author", use_prior=False
        )
        first = avr.review_vendor_assessment(
            first["id"],
            decision="approved",
            rationale="Human review complete.",
            reviewer="reviewer",
            expected_revision=first["revision"],
        )
        plan = avr.prior_answer_plan("Approved Corp")
        second = avr.draft_vendor_assessment("Approved Corp", actor="author")

    assert set(plan["skipped"]) == set(_safe_answers())
    assert plan["ask"] == []
    assert set(second["skipped_prior_questions"]) == set(_safe_answers())
    assert all(
        citation["assessment_sha256"] == first["assessment_sha256"]
        for citation in second["prior_citations"]
    )


def test_reuses_existing_security_vendor_memory_only_for_matching_semantics():
    from maverick import security_ops

    with tenant_scope(tenant="acme"):
        legacy = security_ops.assess_vendor(
            "Legacy AI Vendor",
            {"subprocessors": True},
            assessed_by="security-analyst",
        )
        security_ops.decide_vendor_assessment(
            legacy["id"],
            "approved",
            "Security review accepted.",
            "security-reviewer",
            legacy["revision"],
        )
        plan = avr.prior_answer_plan("Legacy AI Vendor")

    assert set(plan["skipped"]) == {"aiv_subprocessors"}
    reused = plan["skipped"]["aiv_subprocessors"]
    assert reused["answer"] == "yes"
    assert reused["source_kind"] == "security_vendor_memory"
    assert "aiv_evaluation" in plan["ask"]
    assert "aiv_retention" in plan["ask"]


def test_governed_records_are_tenant_isolated_and_list_is_metadata_only():
    with tenant_scope(tenant="acme"):
        record = avr.draft_vendor_assessment(
            "Private Vendor", answers=_safe_answers(), actor="owner", use_prior=False
        )
        page = avr.list_vendor_assessments(limit=1)
        assert page["count"] == 1
        assert page["limit"] == 1
        assert "answers" not in page["items"][0]
        assert "documents" not in page["items"][0]

    with tenant_scope(tenant="globex"):
        assert avr.get_vendor_assessment(record["id"]) is None
        assert avr.list_vendor_assessments()["count"] == 0


def test_projection_refuses_unapproved_draft():
    with tenant_scope(tenant="acme"):
        draft = avr.draft_vendor_assessment(
            "Acme", answers=_safe_answers(), actor="owner", use_prior=False
        )
        with pytest.raises(avr.AIVendorRiskStateError, match="approved"):
            avr.model_risk_evidence_payload(draft["id"])


def test_approved_findings_project_to_current_model_risk_artifact():
    with tenant_scope(tenant="acme"):
        officer = mra.ModelRiskAssuranceOfficer()
        artifact = _hex("vendor-model-v1")
        observation = officer.observe_asset(
            asset_type="provider",
            source="vendor_registry",
            source_id="acme-ai",
            display_name="Acme AI",
            version_digest=artifact,
            actor="inventory-owner",
            observed_at=time.time(),
        )
        draft = avr.draft_vendor_assessment(
            "Acme AI", answers=_safe_answers(), actor="assessor", use_prior=False
        )
        approved = avr.review_vendor_assessment(
            draft["id"],
            decision="approved",
            rationale="All cited evidence was independently reviewed.",
            reviewer="vendor-risk-owner",
            expected_revision=draft["revision"],
        )
        projected = avr.project_to_model_risk(
            approved["id"],
            observation["asset_id"],
            actor="vendor-risk-owner",
            valid_until=time.time() + 86400,
            officer=officer,
        )

    assert projected["evidence_kind"] == "vendor_assessment"
    assert projected["result"] == "passed"
    assert projected["artifact_digest"] == artifact
    assert projected["scope_digest"] == approved["assessment_sha256"]
    assert projected["status"] == "pending_review"
    assert projected["metrics"]["ai_vendor_record_id"] == approved["id"]
    assert "vendor" not in projected["metrics"]


def test_unknown_answers_project_as_inconclusive_not_passed():
    with tenant_scope(tenant="acme"):
        draft = avr.draft_vendor_assessment(
            "Unknown Corp", actor="assessor", use_prior=False
        )
        approved = avr.review_vendor_assessment(
            draft["id"],
            decision="approved",
            rationale="Accepted only as an incomplete diligence record.",
            reviewer="vendor-risk-owner",
            expected_revision=draft["revision"],
        )
        payload = avr.model_risk_evidence_payload(approved["id"])

    assert payload["result"] == "inconclusive"
    assert payload["metrics"]["answered"] == 0
    assert payload["metrics"]["findings"] == 8


def test_document_ref_has_strict_structural_bounds():
    with tenant_scope(tenant="acme"):
        with pytest.raises(ValueError, match="at most 32 fields"):
            avr.extract_answers_from_document(
                _full_vendor_document(),
                "text/plain",
                ref={str(index): index for index in range(33)},
            )


def test_review_is_compare_and_swap_governed():
    with tenant_scope(tenant="acme"):
        draft = avr.draft_vendor_assessment(
            "Acme", answers=_safe_answers(), actor="owner", use_prior=False
        )
        with pytest.raises(RecordConflict):
            avr.review_vendor_assessment(
                draft["id"],
                decision="approved",
                rationale="Reviewed.",
                reviewer="reviewer",
                expected_revision=draft["revision"] + 1,
            )
