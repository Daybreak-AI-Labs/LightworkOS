from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
from pathlib import Path

import pytest
from maverick import compliance_scoping as scoping


class MutableClock:
    def __init__(self, value: float = 2_100_000_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def authority(tmp_path: Path):
    actor = {"value": "author"}
    clock = MutableClock()
    store = scoping.ComplianceScopingStore(
        tmp_path / "compliance-scoping.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: actor["value"],
        signing_key_resolver=lambda _tenant, _ref: b"s" * 32,
        clock=clock,
    )
    return store, actor, clock


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def questions() -> list[dict[str, object]]:
    return [
        {
            "question_id": "q_org_size",
            "question_ref": "ref:question-org-size",
            "domain": "organization",
            "answer_type": "integer",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_industry",
            "question_ref": "ref:question-industry",
            "domain": "industry",
            "answer_type": "single_choice",
            "options": ["finance", "software"],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_jurisdiction",
            "question_ref": "ref:question-jurisdiction",
            "domain": "jurisdiction",
            "answer_type": "multi_choice",
            "options": ["eu", "us"],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_data",
            "question_ref": "ref:question-data",
            "domain": "data",
            "answer_type": "single_choice",
            "options": ["none", "personal", "regulated"],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_system",
            "question_ref": "ref:question-system",
            "domain": "system",
            "answer_type": "boolean",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_vendor",
            "question_ref": "ref:question-vendor",
            "domain": "vendor",
            "answer_type": "boolean",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_ai",
            "question_ref": "ref:question-ai",
            "domain": "ai",
            "answer_type": "boolean",
            "options": [],
            "required": True,
            "condition": None,
        },
        {
            "question_id": "q_ai_model",
            "question_ref": "ref:question-ai-model",
            "domain": "ai",
            "answer_type": "opaque_ref",
            "options": [],
            "required": True,
            "condition": {
                "question_id": "q_ai",
                "operator": "equals",
                "value": True,
            },
        },
        {
            "question_id": "q_operational",
            "question_ref": "ref:question-operational",
            "domain": "operational",
            "answer_type": "single_choice",
            "options": ["critical", "standard"],
            "required": True,
            "condition": None,
        },
    ]


def rules() -> list[dict[str, object]]:
    return [
        {
            "rule_id": "rule_baseline",
            "conditions": [],
            "framework_ref": "framework-baseline",
            "control_refs": ["control-inventory"],
            "overlap_refs": ["overlap-asset-register"],
            "reason_code": "baseline_scope",
        },
        {
            "rule_id": "rule_eu",
            "conditions": [
                {
                    "question_id": "q_jurisdiction",
                    "operator": "contains",
                    "value": "eu",
                }
            ],
            "framework_ref": "framework-eu-privacy",
            "control_refs": ["control-data-rights", "control-records"],
            "overlap_refs": ["overlap-privacy-program"],
            "reason_code": "eu_operations",
        },
        {
            "rule_id": "rule_ai",
            "conditions": [
                {"question_id": "q_ai", "operator": "equals", "value": True}
            ],
            "framework_ref": "framework-ai-governance",
            "control_refs": ["control-ai-inventory"],
            "overlap_refs": ["overlap-model-inventory"],
            "reason_code": "ai_system_present",
        },
        {
            "rule_id": "rule_critical",
            "conditions": [
                {
                    "question_id": "q_operational",
                    "operator": "equals",
                    "value": "critical",
                }
            ],
            "framework_ref": "framework-resilience",
            "control_refs": ["control-recovery"],
            "overlap_refs": ["overlap-business-continuity"],
            "reason_code": "critical_operation",
        },
    ]


def publish_questionnaire(
    store: scoping.ComplianceScopingStore,
    actor: dict[str, str],
    tenant: str = "tenant-a",
    *,
    questionnaire_id: str = "scope-v1",
    operation_suffix: str = "a",
) -> scoping.QuestionnaireVersion:
    actor["value"] = "author"
    created = store.create_questionnaire_version(
        tenant,
        questionnaire_id,
        questions=questions(),
        rules=rules(),
        expected_latest_version=0,
        idempotency_key=f"create-{operation_suffix}",
    )
    actor["value"] = "reviewer"
    return store.publish_questionnaire(
        tenant,
        questionnaire_id,
        created.version,
        expected_revision=created.revision,
        idempotency_key=f"publish-{operation_suffix}",
    )


def create_assessment(
    store: scoping.ComplianceScopingStore,
    actor: dict[str, str],
    clock: MutableClock,
    *,
    tenant: str = "tenant-a",
    assessment_id: str = "assessment-a",
    operation_suffix: str = "a",
) -> scoping.ScopingAssessment:
    actor["value"] = "operator"
    return store.create_assessment(
        tenant,
        assessment_id,
        questionnaire_id="scope-v1",
        questionnaire_version=1,
        retained_until=clock() + 120,
        idempotency_key=f"assessment-{operation_suffix}",
    )


def answer_all(
    store: scoping.ComplianceScopingStore,
    assessment: scoping.ScopingAssessment,
    *,
    tenant: str = "tenant-a",
) -> scoping.ScopingAssessment:
    values: dict[str, object] = {
        "q_org_size": 250,
        "q_industry": "finance",
        "q_jurisdiction": ["eu", "us"],
        "q_data": "regulated",
        "q_system": True,
        "q_vendor": True,
        "q_ai": True,
        "q_ai_model": "ref:model-catalog-entry",
        "q_operational": "critical",
    }
    current = assessment
    for index, (question_id, value) in enumerate(values.items(), start=1):
        current = store.record_response(
            tenant,
            assessment.assessment_id,
            question_id,
            value=value,
            evidence_sha256=digest(f"evidence-{question_id}"),
            evidence_ref=f"evidence:receipt-{question_id}",
            expected_revision=current.revision,
            idempotency_key=f"response-{index}",
        )
    return current


def compute_finalize_export(
    store: scoping.ComplianceScopingStore,
    actor: dict[str, str],
    clock: MutableClock,
    assessment: scoping.ScopingAssessment,
) -> tuple[scoping.ScopeResult, scoping.SignedScopeExport]:
    actor["value"] = "operator"
    scope = store.compute_scope(
        "tenant-a",
        assessment.assessment_id,
        "scope-result-a",
        responsibility_assignments={
            "first_line": "ref:business-owner",
            "second_line": "ref:risk-owner",
            "control_owner": "ref:control-owner",
            "evidence_owner": "ref:evidence-owner",
        },
        expected_assessment_revision=assessment.revision,
        idempotency_key="compute",
    )
    actor["value"] = "scope-approver"
    approved = store.approve_scope(
        "tenant-a",
        scope.scope_id,
        expected_revision=scope.revision,
        idempotency_key="approve",
    )
    actor["value"] = "operator"
    finalized = store.finalize_scope(
        "tenant-a",
        scope.scope_id,
        expected_revision=approved.revision,
        idempotency_key="finalize",
    )
    exported = store.export_scope(
        "tenant-a",
        finalized.scope_id,
        "scope-export-a",
        signing_key_ref="vault:scope-signing-key-v1",
        retained_until=clock() + 100,
        idempotency_key="export",
    )
    return finalized, exported


def test_exact_two_level_gate_is_default_off(monkeypatch, tmp_path: Path) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    disabled = (
        {},
        {"tech_risk_compliance": {"enable": True}},
        {
            "tech_risk_compliance": {
                "enable": False,
                "scoping": {"enable": True},
            }
        },
        {
            "tech_risk_compliance": {
                "enable": True,
                "scoping": {"enable": False},
            }
        },
    )
    for index, configured in enumerate(disabled):
        monkeypatch.setattr(config, "load_config", lambda value=configured: value)
        assert scoping.enabled() is False
        with pytest.raises(scoping.ComplianceScopingConfigError):
            scoping.ComplianceScopingStore(
                tmp_path / f"disabled-{index}.sqlite3",
                principal_resolver=lambda: "principal",
            )
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "tech_risk_compliance": {
                "enable": True,
                "scoping": {"enable": True},
            }
        },
    )
    assert scoping.enabled() is True


def test_public_operations_have_no_actor_argument_and_require_authentication(
    tmp_path: Path,
) -> None:
    for name, method in inspect.getmembers(
        scoping.ComplianceScopingStore, predicate=inspect.isfunction
    ):
        if name.startswith("_") or name == "product_boundaries":
            continue
        assert "actor" not in inspect.signature(method).parameters
        assert "actor_ref" not in inspect.signature(method).parameters
    store = scoping.ComplianceScopingStore(
        tmp_path / "anonymous.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: None,
        signing_key_resolver=lambda _tenant, _ref: b"s" * 32,
    )
    with pytest.raises(scoping.ComplianceScopingPermissionDenied):
        store.get_questionnaire("tenant-a", "scope-v1", 1)


def test_tenant_canonicalization_isolation_and_tenant_scoped_integrity(authority) -> None:
    store, actor, _clock = authority
    publish_questionnaire(
        store,
        actor,
        "Cafe\u0301",
        questionnaire_id="scope-a",
        operation_suffix="a",
    )
    publish_questionnaire(
        store,
        actor,
        "tenant-b",
        questionnaire_id="scope-b",
        operation_suffix="b",
    )
    assert store.get_questionnaire("Caf\u00e9", "scope-a", 1).tenant_id == "Caf\u00e9"
    with pytest.raises(scoping.ComplianceScopingNotFound):
        store.get_questionnaire("tenant-b", "scope-a", 1)
    before = store.verify_integrity("Caf\u00e9")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE scope_publications SET payload_json=? "
            "WHERE tenant_id=? AND questionnaire_id=?",
            ('{"tenant_id":"tenant-b"}', "tenant-b", "scope-b"),
        )
    assert store.verify_integrity("Caf\u00e9") == before
    with pytest.raises(scoping.ComplianceScopingIntegrityError):
        store.verify_integrity("tenant-b")


def test_questionnaire_is_immutable_and_requires_distinct_reviewer(authority) -> None:
    store, actor, _clock = authority
    with store._connect() as configured_connection:
        assert configured_connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert configured_connection.execute("PRAGMA synchronous").fetchone()[0] == 2
    created = store.create_questionnaire_version(
        "tenant-a",
        "scope-v1",
        questions=questions(),
        rules=rules(),
        expected_latest_version=0,
        idempotency_key="create",
    )
    with pytest.raises(scoping.ComplianceScopingPermissionDenied, match="distinct"):
        store.publish_questionnaire(
            "tenant-a",
            "scope-v1",
            1,
            expected_revision=created.revision,
            idempotency_key="same-human",
        )
    with sqlite3.connect(store.path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE scope_questionnaires SET payload_json='{}' "
                "WHERE tenant_id='tenant-a'"
            )
    actor["value"] = "reviewer"
    published = store.publish_questionnaire(
        "tenant-a",
        "scope-v1",
        1,
        expected_revision=created.revision,
        idempotency_key="publish",
    )
    assert published.status == "published"
    assert published.created_by != published.reviewed_by


def test_closed_conditions_reject_bypass_and_inactive_answers(authority) -> None:
    store, actor, clock = authority
    bad_questions = questions()
    bad_questions[0] = dict(bad_questions[0])
    bad_questions[0]["condition"] = {
        "question_id": "q_ai",
        "operator": "__import__",
        "value": True,
    }
    with pytest.raises(scoping.ComplianceScopingValidationError):
        store.create_questionnaire_version(
            "tenant-a",
            "bad-scope",
            questions=bad_questions,
            rules=rules(),
            expected_latest_version=0,
            idempotency_key="bad-conditions",
        )
    bad_rules = rules()
    bad_rules[0] = dict(bad_rules[0])
    bad_rules[0]["conditions"] = [
        {
            "question_id": "q_ai",
            "operator": "equals",
            "value": True,
            "python": "eval(secret)",
        }
    ]
    with pytest.raises(scoping.ComplianceScopingValidationError):
        store.create_questionnaire_version(
            "tenant-a",
            "bad-rules",
            questions=questions(),
            rules=bad_rules,
            expected_latest_version=0,
            idempotency_key="bad-rules",
        )

    publish_questionnaire(store, actor)
    assessment = create_assessment(store, actor, clock)
    assessment = store.record_response(
        "tenant-a",
        assessment.assessment_id,
        "q_ai",
        value=False,
        evidence_sha256=digest("no-ai"),
        evidence_ref="evidence:no-ai",
        expected_revision=assessment.revision,
        idempotency_key="no-ai",
    )
    with pytest.raises(scoping.ComplianceScopingConflict, match="not active"):
        store.record_response(
            "tenant-a",
            assessment.assessment_id,
            "q_ai_model",
            value="ref:secret-model",
            evidence_sha256=digest("inactive"),
            evidence_ref="evidence:inactive",
            expected_revision=assessment.revision,
            idempotency_key="inactive-answer",
        )


def test_required_traversal_is_deterministic_and_responses_use_cas_idempotency(
    authority,
) -> None:
    store, actor, clock = authority
    publish_questionnaire(store, actor)
    assessment = create_assessment(store, actor, clock)
    first_ids = tuple(
        item.question_id
        for item in store.next_required_questions("tenant-a", assessment.assessment_id)
    )
    assert first_ids == (
        "q_org_size",
        "q_industry",
        "q_jurisdiction",
        "q_data",
        "q_system",
        "q_vendor",
        "q_ai",
        "q_operational",
    )
    answered = store.record_response(
        "tenant-a",
        assessment.assessment_id,
        "q_org_size",
        value=100,
        evidence_sha256=digest("org"),
        evidence_ref="evidence:org",
        expected_revision=assessment.revision,
        idempotency_key="response-org",
    )
    replay = store.record_response(
        "tenant-a",
        assessment.assessment_id,
        "q_org_size",
        value=100,
        evidence_sha256=digest("org"),
        evidence_ref="evidence:org",
        expected_revision=assessment.revision,
        idempotency_key="response-org",
    )
    assert replay == answered
    with pytest.raises(scoping.ComplianceScopingConflict, match="different canonical"):
        store.record_response(
            "tenant-a",
            assessment.assessment_id,
            "q_org_size",
            value=101,
            evidence_sha256=digest("org"),
            evidence_ref="evidence:org",
            expected_revision=assessment.revision,
            idempotency_key="response-org",
        )
    with pytest.raises(scoping.ComplianceScopingConflict, match="CAS"):
        store.record_response(
            "tenant-a",
            assessment.assessment_id,
            "q_industry",
            value="finance",
            evidence_sha256=digest("industry"),
            evidence_ref="evidence:industry",
            expected_revision=assessment.revision,
            idempotency_key="stale-response",
        )


def test_deterministic_scope_assignments_overlap_and_four_eyes_finalization(
    authority,
) -> None:
    store, actor, clock = authority
    publish_questionnaire(store, actor)
    assessment = answer_all(store, create_assessment(store, actor, clock))
    actor["value"] = "operator"
    scope = store.compute_scope(
        "tenant-a",
        assessment.assessment_id,
        "scope-result-a",
        responsibility_assignments={
            "first_line": "ref:business-owner",
            "second_line": "ref:risk-owner",
            "control_owner": "ref:control-owner",
            "evidence_owner": "ref:evidence-owner",
        },
        expected_assessment_revision=assessment.revision,
        idempotency_key="compute",
    )
    assert scope.applicable_frameworks == (
        "framework-ai-governance",
        "framework-baseline",
        "framework-eu-privacy",
        "framework-resilience",
    )
    assert tuple(item["control_ref"] for item in scope.control_applicability) == (
        "control-ai-inventory",
        "control-inventory",
        "control-data-rights",
        "control-records",
        "control-recovery",
    )
    assert {item["reason_code"] for item in scope.overlaps} == {
        "ai_system_present",
        "baseline_scope",
        "critical_operation",
        "eu_operations",
    }
    assert scope.crosswalks == scope.overlaps
    with pytest.raises(scoping.ComplianceScopingPermissionDenied, match="distinct"):
        store.approve_scope(
            "tenant-a",
            scope.scope_id,
            expected_revision=scope.revision,
            idempotency_key="self-approve",
        )
    with pytest.raises(scoping.ComplianceScopingConflict, match="approved"):
        store.finalize_scope(
            "tenant-a",
            scope.scope_id,
            expected_revision=scope.revision,
            idempotency_key="early-finalize",
        )
    actor["value"] = "approver"
    approved = store.approve_scope(
        "tenant-a",
        scope.scope_id,
        expected_revision=scope.revision,
        idempotency_key="approve",
    )
    actor["value"] = "operator"
    finalized = store.finalize_scope(
        "tenant-a",
        scope.scope_id,
        expected_revision=approved.revision,
        idempotency_key="finalize",
    )
    assert finalized.status == "finalized"
    assert finalized.approved_by == "approver"


def test_signed_export_retention_purge_and_no_raw_evidence_or_secrets(authority) -> None:
    store, actor, clock = authority
    publish_questionnaire(store, actor)
    assessment = answer_all(store, create_assessment(store, actor, clock))
    finalized, exported = compute_finalize_export(store, actor, clock, assessment)
    assert exported.body_sha256 == digest(
        json.dumps(
            exported.body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    )
    assert len(exported.signature_hmac_sha256) == 64
    assert store.get_export("tenant-a", exported.export_id) == exported
    raw_evidence = "raw audit document with customer secret"
    database_bytes = store.path.read_bytes()
    wal_path = Path(f"{store.path}-wal")
    if wal_path.exists():
        database_bytes += wal_path.read_bytes()
    assert raw_evidence.encode() not in database_bytes
    assert b"literal-provider-secret" not in database_bytes
    with pytest.raises(scoping.ComplianceScopingValidationError):
        store.record_response(
            "tenant-a",
            assessment.assessment_id,
            "q_org_size",
            value=1,
            evidence_sha256=digest(raw_evidence),
            evidence_ref="literal-provider-secret",
            expected_revision=assessment.revision,
            idempotency_key="secret-evidence",
        )

    assert finalized.status == "finalized"
    clock.advance(121)
    assert store.purge_expired(
        "tenant-a", cutoff=clock(), idempotency_key="purge"
    ) == {"exports": 1, "assessments": 1}
    with pytest.raises(scoping.ComplianceScopingNotFound):
        store.get_assessment("tenant-a", assessment.assessment_id)
    with pytest.raises(scoping.ComplianceScopingNotFound):
        store.get_scope("tenant-a", finalized.scope_id)
    assert store.get_questionnaire("tenant-a", "scope-v1", 1).status == "published"


def test_signature_and_row_tampering_are_detected(authority) -> None:
    store, actor, clock = authority
    publish_questionnaire(store, actor)
    assessment = answer_all(store, create_assessment(store, actor, clock))
    _finalized, exported = compute_finalize_export(store, actor, clock, assessment)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM scope_exports WHERE tenant_id=? AND export_id=?",
            ("tenant-a", exported.export_id),
        ).fetchone()
        payload = json.loads(row[0])
        payload["signature_hmac_sha256"] = "0" * 64
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        connection.execute(
            "UPDATE scope_exports SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND export_id=?",
            (
                canonical,
                hashlib.sha256(canonical.encode("ascii")).hexdigest(),
                "tenant-a",
                exported.export_id,
            ),
        )
    with pytest.raises(scoping.ComplianceScopingIntegrityError, match="signature"):
        store.get_export("tenant-a", exported.export_id)

    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE scope_assessments SET payload_json=? WHERE tenant_id=?",
            ('{"tenant_id":"tenant-a"}', "tenant-a"),
        )
    with pytest.raises(scoping.ComplianceScopingIntegrityError):
        store.verify_integrity("tenant-a")


def test_non_ascii_export_signature_is_an_integrity_error_not_a_type_error(authority) -> None:
    # An edited non-ASCII signature must not raise TypeError from
    # hmac.compare_digest instead of the signature refusal.
    store, actor, clock = authority
    publish_questionnaire(store, actor)
    assessment = answer_all(store, create_assessment(store, actor, clock))
    _finalized, exported = compute_finalize_export(store, actor, clock, assessment)
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM scope_exports WHERE tenant_id=? AND export_id=?",
            ("tenant-a", exported.export_id),
        ).fetchone()
        payload = json.loads(row[0])
        payload["signature_hmac_sha256"] = "é" * 64
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        )
        connection.execute(
            "UPDATE scope_exports SET payload_json=?,integrity_sha256=? "
            "WHERE tenant_id=? AND export_id=?",
            (
                canonical,
                hashlib.sha256(canonical.encode("ascii")).hexdigest(),
                "tenant-a",
                exported.export_id,
            ),
        )
    with pytest.raises(scoping.ComplianceScopingIntegrityError, match="signature"):
        store.get_export("tenant-a", exported.export_id)


def test_honest_local_product_boundaries() -> None:
    assert scoping.ComplianceScopingStore.product_boundaries() == {
        "provider_neutral": True,
        "licensed_framework_text_included": False,
        "legal_advice": False,
        "automatic_external_discovery": False,
        "certification": False,
        "live_provider_acceptance_verified": False,
        "free_text_evidence_persisted": False,
        "secret_values_persisted": False,
        "rules_use_arbitrary_evaluation": False,
    }
