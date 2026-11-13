from __future__ import annotations

import hashlib
import inspect
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import maverick.third_party_lifecycle as lifecycle_module
import pytest
from maverick.third_party_lifecycle import (
    LIVE_PROVIDER_ACCEPTANCE_VERIFIED,
    LIVE_PROVIDER_OPERATIONS,
    ThirdPartyLifecycleConfigError,
    ThirdPartyLifecycleConflict,
    ThirdPartyLifecycleIntegrityError,
    ThirdPartyLifecycleNotFound,
    ThirdPartyLifecyclePermissionDenied,
    ThirdPartyLifecycleStore,
    ThirdPartyLifecycleValidationError,
)

DAY = 24 * 60 * 60
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64


class Clock:
    def __init__(self, value: float = 2_000_000_000.0) -> None:
        self.value = value
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self.value

    def advance(self, seconds: float) -> None:
        with self._lock:
            self.value += seconds


class Principal:
    def __init__(self, value: str | None = "author") -> None:
        self.value = value

    def __call__(self) -> str | None:
        return self.value


@pytest.fixture
def authority(tmp_path: Path) -> tuple[ThirdPartyLifecycleStore, Clock, Principal]:
    clock = Clock()
    principal = Principal()
    tokens = iter(f"token-{index}" for index in range(1, 100))
    store = ThirdPartyLifecycleStore(
        tmp_path / "private" / "lifecycle.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        clock=clock,
        token_factory=lambda: next(tokens),
    )
    return store, clock, principal


def question(
    question_id: str,
    domain: str,
    *,
    response_type: str = "boolean",
    required: bool = True,
    options: list[str] | None = None,
    condition: dict[str, object] | None = None,
    risk_rules: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "question_id": question_id,
        "domain": domain,
        "prompt_ref": f"prompt.{question_id}",
        "response_type": response_type,
        "required": required,
        "options": options or [],
        "condition": condition,
        "risk_rules": risk_rules or [],
    }


def conditional_questions() -> list[dict[str, object]]:
    return [
        question(
            "security_control",
            "security",
            risk_rules=[
                {
                    "operator": "equals",
                    "value": False,
                    "severity": "high",
                    "reason_code": "security_control_absent",
                }
            ],
        ),
        question(
            "privacy_scope",
            "privacy",
            response_type="single_choice",
            options=["low", "high"],
            condition={
                "question_id": "security_control",
                "operator": "equals",
                "value": True,
            },
            risk_rules=[
                {
                    "operator": "equals",
                    "value": "high",
                    "severity": "high",
                    "reason_code": "high_privacy_scope",
                }
            ],
        ),
    ]


def create_approved_template(
    store: ThirdPartyLifecycleStore,
    principal: Principal,
    tenant: str = "tenant-a",
    template_id: str = "assessment.standard",
) -> None:
    principal.value = "author"
    pending = store.create_template_version(
        tenant,
        template_id,
        title_ref="title.assessment.standard",
        questions=conditional_questions(),
        mitigation_rules=[
            {
                "reason_code": "high_privacy_scope",
                "recommendation_code": "limit_data_scope",
                "task_code": "privacy_remediation",
                "minimum_severity": "high",
            }
        ],
        expected_latest_version=0,
        idempotency_key=f"create-{tenant}-{template_id}",
    )
    assert pending.state == "pending_approval"
    principal.value = "reviewer"
    approved = store.approve_template_version(
        tenant,
        template_id,
        1,
        expected_revision=1,
        idempotency_key=f"approve-{tenant}-{template_id}",
    )
    assert approved.state == "approved"


def evaluated_owner_review_assessment(
    store: ThirdPartyLifecycleStore,
    principal: Principal,
    vendor_ref: str,
    tenant: str = "tenant-a",
) -> None:
    """Give ``vendor_ref`` the complete, evaluated assessment activation needs."""
    create_approved_template(store, principal, tenant)
    assessment_id = f"assessment-{vendor_ref}"
    principal.value = "creator"
    store.create_assessment(
        tenant,
        assessment_id,
        vendor_ref=vendor_ref,
        template_id="assessment.standard",
        template_version=1,
        owner_ref="owner",
        respondent_assignments={
            "security_control": "respondent-security",
            "privacy_scope": "respondent-privacy",
        },
        retention_seconds=DAY,
        idempotency_key=f"{assessment_id}-create",
    )
    principal.value = "respondent-security"
    first = store.record_response(
        tenant, assessment_id, "security_control", value=True,
        evidence_sha256=DIGEST_A, evidence_refs=["evidence.security"],
        expected_revision=1, idempotency_key=f"{assessment_id}-security",
    )
    principal.value = "respondent-privacy"
    second = store.record_response(
        tenant, assessment_id, "privacy_scope", value="low",
        evidence_sha256=DIGEST_B, evidence_refs=["evidence.privacy"],
        expected_revision=first.revision, idempotency_key=f"{assessment_id}-privacy",
    )
    principal.value = "owner"
    result = store.evaluate_assessment(
        tenant, assessment_id, expected_revision=second.revision,
        idempotency_key=f"{assessment_id}-evaluate",
    )
    assert result.route == "owner_review"


def dependencies() -> list[dict[str, str]]:
    return [
        {
            "dependency_id": "access.crm",
            "kind": "access",
            "reference": "ref.crm.account",
            "evidence_sha256": DIGEST_A,
        },
        {
            "dependency_id": "contract.primary",
            "kind": "contract",
            "reference": "ref.contract.primary",
            "evidence_sha256": DIGEST_B,
        },
    ]


def offboarding_tasks() -> list[dict[str, object]]:
    return [
        {
            "task_id": "task.revoke.crm",
            "dependency_id": "access.crm",
            "action": "revoke_access",
            "assignee_ref": "owner",
            "callback_required": True,
        },
        {
            "task_id": "task.close.contract",
            "dependency_id": "contract.primary",
            "action": "notify_owner",
            "assignee_ref": "owner",
            "callback_required": False,
        },
    ]


def test_exact_default_off_gate_and_runtime_actor_derivation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert lifecycle_module.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": False,
                "lifecycle": {"enable": True},
            }
        },
    )
    assert lifecycle_module.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": True,
                "lifecycle": {"enabled": True},
            }
        },
    )
    assert lifecycle_module.enabled() is False
    with pytest.raises(ThirdPartyLifecycleConfigError):
        ThirdPartyLifecycleStore(tmp_path / "disabled.sqlite3")
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "third_party_management": {
                "enable": True,
                "lifecycle": {"enable": True},
            }
        },
    )
    assert lifecycle_module.enabled() is True
    monkeypatch.setattr(config, "config_source_errors", lambda: ["bad config"])
    assert lifecycle_module.enabled() is False

    principal = Principal(None)
    store = ThirdPartyLifecycleStore(
        tmp_path / "enabled.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
    )
    with pytest.raises(ThirdPartyLifecyclePermissionDenied):
        store.create_lifecycle(
            "tenant",
            "lifecycle",
            vendor_ref="vendor",
            owner_ref="owner",
            dependencies=[],
            retention_seconds=DAY,
            idempotency_key="create",
        )
    for method_name in (
        "create_template_version",
        "approve_template_version",
        "record_response",
        "transition_lifecycle",
        "approve_offboarding_completion",
    ):
        assert "actor" not in inspect.signature(getattr(store, method_name)).parameters


def test_unicode_tenant_isolation_strict_ids_and_private_sqlite(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    principal.value = "owner"
    record = store.create_lifecycle(
        "Cafe\u0301",
        "lifecycle-1",
        vendor_ref="vendor-1",
        owner_ref="owner",
        dependencies=dependencies(),
        retention_seconds=DAY,
        idempotency_key="unicode-create",
    )
    assert record.tenant_id == "Café"
    assert store.get_lifecycle("Café", "lifecycle-1") == record
    with pytest.raises(ThirdPartyLifecycleNotFound):
        store.get_lifecycle("tenant-b", "lifecycle-1")
    with pytest.raises(ThirdPartyLifecycleValidationError):
        store.get_lifecycle("Café", "../lifecycle")
    with pytest.raises(ThirdPartyLifecycleValidationError):
        store.create_lifecycle(
            "Café",
            "lifecycle-2",
            vendor_ref="raw vendor name",
            owner_ref="owner",
            dependencies=[],
            retention_seconds=DAY,
            idempotency_key="bad-reference",
        )
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_context_heads_are_bounded_tenant_exact_and_count_current_records(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    principal.value = "owner"
    first = store.create_lifecycle(
        "tenant-a",
        "lifecycle-a",
        vendor_ref="vendor-a",
        owner_ref="owner",
        dependencies=dependencies(),
        retention_seconds=DAY,
        idempotency_key="context-lifecycle-a",
    )
    store.create_lifecycle(
        "tenant-a",
        "lifecycle-b",
        vendor_ref="vendor-b",
        owner_ref="owner",
        dependencies=[],
        retention_seconds=DAY,
        idempotency_key="context-lifecycle-b",
    )

    assert store.list_lifecycles("tenant-a", limit=1) == (first,)
    assert store.list_lifecycles("tenant-b", limit=1) == ()
    assert store.list_assessments("tenant-a", limit=1) == ()
    assert store.list_offboarding_plans("tenant-a", limit=1) == ()
    assert store.context_record_counts("tenant-a") == {
        "assessments": 0,
        "lifecycles": 2,
        "offboarding_plans": 0,
    }


def test_template_four_eyes_versioning_and_closed_conditions(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    principal.value = "author"
    pending = store.create_template_version(
        "tenant-a",
        "template",
        title_ref="title.template",
        questions=conditional_questions(),
        mitigation_rules=[],
        expected_latest_version=0,
        idempotency_key="template-create",
    )
    with pytest.raises(ThirdPartyLifecyclePermissionDenied):
        store.approve_template_version(
            "tenant-a",
            "template",
            1,
            expected_revision=pending.revision,
            idempotency_key="template-self-approve",
        )
    principal.value = "reviewer"
    approved = store.approve_template_version(
        "tenant-a",
        "template",
        1,
        expected_revision=1,
        idempotency_key="template-approve",
    )
    assert approved.approved_by == "reviewer"
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.create_template_version(
            "tenant-a",
            "template",
            title_ref="title.template.v2",
            questions=conditional_questions(),
            mitigation_rules=[],
            expected_latest_version=0,
            idempotency_key="template-bad-cas",
        )
    invalid = conditional_questions()
    invalid[0]["condition"] = {
        "question_id": "future-question",
        "operator": "equals",
        "value": True,
    }
    with pytest.raises(ThirdPartyLifecycleValidationError):
        store.create_template_version(
            "tenant-a",
            "invalid",
            title_ref="title.invalid",
            questions=invalid,
            mitigation_rules=[],
            expected_latest_version=0,
            idempotency_key="invalid-condition",
        )


def test_conditional_branching_evidence_routing_idempotency_and_cas(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    create_approved_template(store, principal)
    principal.value = "creator"
    assessment = store.create_assessment(
        "tenant-a",
        "assessment-1",
        vendor_ref="vendor-1",
        template_id="assessment.standard",
        template_version=1,
        owner_ref="owner",
        respondent_assignments={
            "security_control": "respondent-security",
            "privacy_scope": "respondent-privacy",
        },
        retention_seconds=DAY,
        idempotency_key="assessment-create",
    )
    assert assessment.revision == 1
    assert store.required_questions("tenant-a", "assessment-1") == ("security_control",)

    principal.value = "respondent-privacy"
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.record_response(
            "tenant-a",
            "assessment-1",
            "privacy_scope",
            value="high",
            evidence_sha256=DIGEST_A,
            evidence_refs=["evidence.privacy"],
            expected_revision=1,
            idempotency_key="response-inactive",
        )

    principal.value = "respondent-security"
    first = store.record_response(
        "tenant-a",
        "assessment-1",
        "security_control",
        value=True,
        evidence_sha256=DIGEST_A,
        evidence_refs=["evidence.security"],
        expected_revision=1,
        idempotency_key="response-security",
    )
    replay = store.record_response(
        "tenant-a",
        "assessment-1",
        "security_control",
        value=True,
        evidence_sha256=DIGEST_A,
        evidence_refs=["evidence.security"],
        expected_revision=1,
        idempotency_key="response-security",
    )
    assert replay == first
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.record_response(
            "tenant-a",
            "assessment-1",
            "security_control",
            value=False,
            evidence_sha256=DIGEST_A,
            evidence_refs=["evidence.security"],
            expected_revision=1,
            idempotency_key="response-security",
        )
    assert store.required_questions("tenant-a", "assessment-1") == (
        "security_control",
        "privacy_scope",
    )

    principal.value = "respondent-privacy"
    second = store.record_response(
        "tenant-a",
        "assessment-1",
        "privacy_scope",
        value="high",
        evidence_sha256=DIGEST_B,
        evidence_refs=["evidence.privacy"],
        expected_revision=2,
        idempotency_key="response-privacy",
    )
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.record_response(
            "tenant-a",
            "assessment-1",
            "privacy_scope",
            value="low",
            evidence_sha256=DIGEST_B,
            evidence_refs=["evidence.privacy"],
            expected_revision=2,
            idempotency_key="response-privacy-stale",
        )
    principal.value = "owner"
    result = store.evaluate_assessment(
        "tenant-a",
        "assessment-1",
        expected_revision=second.revision,
        idempotency_key="assessment-evaluate",
    )
    assert result.missing_questions == ()
    assert result.route == "remediation_required"
    assert result.highest_severity == "high"
    assert result.reason_codes == ("high_privacy_scope",)
    assert result.recommendations[0]["recommendation_code"] == "limit_data_scope"


def test_attested_response_batch_is_atomic_pinned_and_idempotent(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    create_approved_template(store, principal)
    principal.value = "creator"
    assessment = store.create_assessment(
        "tenant-a",
        "assessment-batch",
        vendor_ref="vendor",
        template_id="assessment.standard",
        template_version=1,
        owner_ref="owner",
        respondent_assignments={
            "security_control": "respondent",
            "privacy_scope": "respondent",
        },
        retention_seconds=DAY,
        idempotency_key="assessment-batch-create",
    )
    template = store.get_template_version("tenant-a", "assessment.standard", 1)
    principal.value = "respondent"
    responses = {
        "security_control": {
            "value": True,
            "evidence_sha256": DIGEST_A,
            "evidence_refs": ["attestation.security"],
        },
        "privacy_scope": {
            "value": "high",
            "evidence_sha256": DIGEST_B,
            "evidence_refs": ["attestation.privacy"],
        },
    }
    receipt = store.record_response_batch(
        "tenant-a",
        assessment.assessment_id,
        responses=responses,
        attestation_sha256=DIGEST_C,
        expected_revision=assessment.revision,
        expected_assessment_sha256=assessment.integrity_sha256,
        expected_template_revision=template.revision,
        expected_template_sha256=template.integrity_sha256,
        idempotency_key="assessment-batch-final",
    )
    assert receipt.assessment_revision == 2
    assert receipt.question_ids == ("privacy_scope", "security_control")
    replay = store.record_response_batch(
        "tenant-a",
        assessment.assessment_id,
        responses=responses,
        attestation_sha256=DIGEST_C,
        expected_revision=assessment.revision,
        expected_assessment_sha256=assessment.integrity_sha256,
        expected_template_revision=template.revision,
        expected_template_sha256=template.integrity_sha256,
        idempotency_key="assessment-batch-final",
    )
    assert replay == receipt
    stored = store.get_assessment("tenant-a", assessment.assessment_id)
    assert stored.revision == 2
    assert stored.route == "not_evaluated"
    assert stored.responses["privacy_scope"]["evidence_status"] == (
        "respondent_attestation_unverified"
    )
    with pytest.raises(ThirdPartyLifecycleConflict, match="different canonical content"):
        store.record_response_batch(
            "tenant-a",
            assessment.assessment_id,
            responses={
                **responses,
                "privacy_scope": {**responses["privacy_scope"], "value": "low"},
            },
            attestation_sha256=DIGEST_C,
            expected_revision=assessment.revision,
            expected_assessment_sha256=assessment.integrity_sha256,
            expected_template_revision=template.revision,
            expected_template_sha256=template.integrity_sha256,
            idempotency_key="assessment-batch-final",
        )


def test_attested_response_batch_rejects_hidden_question_without_partial_write(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    create_approved_template(store, principal)
    principal.value = "creator"
    assessment = store.create_assessment(
        "tenant-a",
        "assessment-hidden-batch",
        vendor_ref="vendor",
        template_id="assessment.standard",
        template_version=1,
        owner_ref="owner",
        respondent_assignments={
            "security_control": "respondent",
            "privacy_scope": "respondent",
        },
        retention_seconds=DAY,
        idempotency_key="assessment-hidden-batch-create",
    )
    template = store.get_template_version("tenant-a", "assessment.standard", 1)
    principal.value = "respondent"
    with pytest.raises(ThirdPartyLifecycleConflict, match="not active"):
        store.record_response_batch(
            "tenant-a",
            assessment.assessment_id,
            responses={
                "security_control": {
                    "value": False,
                    "evidence_sha256": DIGEST_A,
                    "evidence_refs": ["attestation.security"],
                },
                "privacy_scope": {
                    "value": "high",
                    "evidence_sha256": DIGEST_B,
                    "evidence_refs": ["attestation.privacy"],
                },
            },
            attestation_sha256=DIGEST_C,
            expected_revision=assessment.revision,
            expected_assessment_sha256=assessment.integrity_sha256,
            expected_template_revision=template.revision,
            expected_template_sha256=template.integrity_sha256,
            idempotency_key="assessment-hidden-batch-final",
        )
    unchanged = store.get_assessment("tenant-a", assessment.assessment_id)
    assert unchanged.revision == 1
    assert unchanged.responses == {}


def test_assessment_tasks_export_and_bounded_purge(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, clock, principal = authority
    create_approved_template(store, principal)
    principal.value = "creator"
    assessment = store.create_assessment(
        "tenant-a",
        "assessment-retained",
        vendor_ref="vendor",
        template_id="assessment.standard",
        template_version=1,
        owner_ref="owner",
        respondent_assignments={
            "security_control": "respondent",
            "privacy_scope": "respondent",
        },
        retention_seconds=DAY,
        idempotency_key="assessment-retained-create",
    )
    principal.value = "owner"
    assessment = store.set_assessment_task(
        "tenant-a",
        assessment.assessment_id,
        "task-1",
        status="completed",
        reason_code="high_privacy_scope",
        assignee_ref="owner",
        evidence_sha256=DIGEST_A,
        evidence_ref="evidence.task",
        due_at=clock() + 60,
        expected_revision=assessment.revision,
        idempotency_key="assessment-task",
    )
    report = store.export_assessment(
        "tenant-a",
        assessment.assessment_id,
        "export-assessment",
        retention_seconds=DAY,
        idempotency_key="assessment-export",
    )
    assert report.body["assessment_integrity_sha256"] == assessment.integrity_sha256
    assert "no_live_provider_operation" in report.body["limitations"]
    clock.advance(DAY + 1)
    counts = store.purge_expired("tenant-a", before=clock(), idempotency_key="assessment-purge")
    assert counts["assessments"] == 1
    assert counts["exports"] == 1
    assert (
        store.purge_expired("tenant-a", before=clock(), idempotency_key="assessment-purge")
        == counts
    )
    with pytest.raises(ThirdPartyLifecycleNotFound):
        store.get_assessment("tenant-a", "assessment-retained")
    assert store.verify_integrity("tenant-a").audit_events > 0


def test_lifecycle_transitions_are_cas_safe_under_concurrency(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    # Without an evaluated assessment "active" would always conflict and the
    # race would be decided by the activation gate, not the revision CAS.
    evaluated_owner_review_assessment(store, principal, "vendor")
    principal.value = "owner"
    store.create_lifecycle(
        "tenant-a",
        "concurrent",
        vendor_ref="vendor",
        owner_ref="owner",
        dependencies=[],
        retention_seconds=DAY,
        idempotency_key="concurrent-create",
    )

    def transition(target: str) -> str:
        try:
            return store.transition_lifecycle(
                "tenant-a",
                "concurrent",
                target,
                reason_code=f"move_{target}",
                expected_revision=1,
                idempotency_key=f"concurrent-{target}",
            ).stage
        except ThirdPartyLifecycleConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(transition, ("active", "suspended")))
    assert outcomes.count("conflict") == 1
    assert len(set(outcomes) & {"active", "suspended"}) == 1


def test_offboarding_four_eyes_legal_hold_no_silent_completion_and_recovery(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, clock, principal = authority
    # Activation requires the vendor's complete, evaluated assessment.
    evaluated_owner_review_assessment(store, principal, "vendor-1")
    principal.value = "owner"
    lifecycle = store.create_lifecycle(
        "tenant-a",
        "lifecycle-1",
        vendor_ref="vendor-1",
        owner_ref="owner",
        dependencies=dependencies(),
        retention_seconds=DAY,
        idempotency_key="lifecycle-create",
    )
    lifecycle = store.transition_lifecycle(
        "tenant-a",
        lifecycle.lifecycle_id,
        "active",
        reason_code="onboarding_accepted",
        expected_revision=lifecycle.revision,
        idempotency_key="lifecycle-active",
    )
    plan = store.begin_offboarding(
        "tenant-a",
        lifecycle.lifecycle_id,
        "plan-1",
        tasks=offboarding_tasks(),
        legal_hold=True,
        legal_hold_evidence_ref="legal.hold.case",
        maximum_callback_attempts=2,
        expected_lifecycle_revision=lifecycle.revision,
        idempotency_key="offboarding-begin",
    )
    assert "legal_hold_active" in plan.blockers
    with pytest.raises(ThirdPartyLifecyclePermissionDenied):
        store.approve_offboarding_completion(
            "tenant-a",
            plan.plan_id,
            completion_attestation_ref="attestation.self",
            expected_plan_revision=plan.revision,
            expected_lifecycle_revision=3,
            idempotency_key="offboarding-self-approval",
        )
    principal.value = "approver"
    with pytest.raises(ThirdPartyLifecycleConflict, match="legal_hold_active"):
        store.approve_offboarding_completion(
            "tenant-a",
            plan.plan_id,
            completion_attestation_ref="attestation.held",
            expected_plan_revision=plan.revision,
            expected_lifecycle_revision=3,
            idempotency_key="offboarding-held",
        )
    principal.value = "owner"
    plan = store.set_legal_hold(
        "tenant-a",
        plan.plan_id,
        active=False,
        evidence_ref="legal.hold.release",
        expected_revision=plan.revision,
        idempotency_key="legal-hold-release",
    )
    assert "legal_hold_active" not in plan.blockers
    assert plan.legal_hold is False and plan.legal_hold_evidence_ref is None

    principal.value = "worker"
    claimed = store.claim_callbacks("tenant-a", limit=1, lease_seconds=30)
    assert len(claimed) == 1
    callback = claimed[0]
    lease_token = callback.lease_token or "missing"
    principal.value = "owner"
    leased_export = store.export_lifecycle(
        "tenant-a",
        lifecycle.lifecycle_id,
        "leased-lifecycle-export",
        retention_seconds=DAY,
        idempotency_key="leased-lifecycle-export-create",
    )
    callback_evidence = leased_export.body["callbacks"][0]
    assert "lease_token" not in callback_evidence["record"]
    assert (
        callback_evidence["record"]["lease_token_sha256"]
        == hashlib.sha256(lease_token.encode()).hexdigest()
    )
    assert callback_evidence["redactions"] == ["lease_token"]
    principal.value = "worker"
    callback = store.fail_callback(
        "tenant-a",
        callback.callback_id,
        lease_token=lease_token,
        error_code="temporary_outage",
        retry_after_seconds=10,
        expected_revision=callback.revision,
        idempotency_key="callback-fail-1",
    )
    assert callback.state == "pending"
    assert store.claim_callbacks("tenant-a", limit=1, lease_seconds=30) == ()
    clock.advance(11)
    callback = store.claim_callbacks("tenant-a", limit=1, lease_seconds=30)[0]
    callback = store.fail_callback(
        "tenant-a",
        callback.callback_id,
        lease_token=callback.lease_token or "missing",
        error_code="second_outage",
        retry_after_seconds=10,
        expected_revision=callback.revision,
        idempotency_key="callback-fail-2",
    )
    assert callback.state == "dead_letter"
    assert any(
        blocker.startswith("callback_dead_letter:")
        for blocker in store.get_offboarding_plan("tenant-a", plan.plan_id).blockers
    )

    principal.value = "owner"
    callback = store.requeue_dead_letter(
        "tenant-a",
        callback.callback_id,
        reason_code="adapter_recovered",
        expected_revision=callback.revision,
        idempotency_key="callback-requeue",
    )
    principal.value = "worker"
    callback = store.claim_callbacks("tenant-a", limit=1, lease_seconds=30)[0]
    callback = store.acknowledge_callback(
        "tenant-a",
        callback.callback_id,
        lease_token=callback.lease_token or "missing",
        delivery_evidence_sha256=DIGEST_C,
        expected_revision=callback.revision,
        idempotency_key="callback-ack",
    )
    assert callback.state == "delivered"
    # Delivery is explicit evidence but cannot silently complete either task.
    after_delivery = store.get_offboarding_plan("tenant-a", plan.plan_id)
    assert all(task["status"] == "open" for task in after_delivery.tasks)
    principal.value = "approver"
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.approve_offboarding_completion(
            "tenant-a",
            plan.plan_id,
            completion_attestation_ref="attestation.too-early",
            expected_plan_revision=plan.revision,
            expected_lifecycle_revision=3,
            idempotency_key="offboarding-too-early",
        )
    principal.value = "owner"
    plan = store.set_offboarding_task(
        "tenant-a",
        plan.plan_id,
        "task.revoke.crm",
        status="completed",
        evidence_sha256=DIGEST_A,
        attestation_ref="attestation.access",
        expected_revision=plan.revision,
        idempotency_key="task-access-complete",
    )
    plan = store.set_offboarding_task(
        "tenant-a",
        plan.plan_id,
        "task.close.contract",
        status="completed",
        evidence_sha256=DIGEST_B,
        attestation_ref="attestation.contract",
        expected_revision=plan.revision,
        idempotency_key="task-contract-complete",
    )
    assert plan.blockers == ()
    principal.value = "approver"
    completed = store.approve_offboarding_completion(
        "tenant-a",
        plan.plan_id,
        completion_attestation_ref="attestation.independent",
        expected_plan_revision=plan.revision,
        expected_lifecycle_revision=3,
        idempotency_key="offboarding-complete",
    )
    assert completed.completed_by == "approver"
    assert store.get_lifecycle("tenant-a", lifecycle.lifecycle_id).stage == "offboarded"
    principal.value = "owner"
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.transition_lifecycle(
            "tenant-a",
            lifecycle.lifecycle_id,
            "active",
            reason_code="prohibited_reactivation",
            expected_revision=4,
            idempotency_key="offboarded-reactivation",
        )
    clock.advance(DAY + 1)
    purge = store.purge_expired("tenant-a", before=clock(), idempotency_key="offboarded-purge")
    assert purge["lifecycles"] == 1
    assert purge["offboarding_plans"] == 1
    assert purge["callbacks"] == 1
    with pytest.raises(ThirdPartyLifecycleNotFound):
        store.get_lifecycle("tenant-a", lifecycle.lifecycle_id)


def test_default_lease_token_accepts_urlsafe_leading_symbols(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(lifecycle_module.secrets, "token_urlsafe", lambda _size: "-leading-token")
    clock = Clock()
    principal = Principal("owner")
    store = ThirdPartyLifecycleStore(
        tmp_path / "default-token.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        clock=clock,
    )
    record = store.create_lifecycle(
        "tenant-a",
        "default-token",
        vendor_ref="vendor",
        owner_ref="owner",
        dependencies=[dependencies()[0]],
        retention_seconds=DAY,
        idempotency_key="default-token-lifecycle",
    )
    store.begin_offboarding(
        "tenant-a",
        record.lifecycle_id,
        "default-token-plan",
        tasks=[offboarding_tasks()[0]],
        legal_hold=False,
        legal_hold_evidence_ref=None,
        maximum_callback_attempts=3,
        expected_lifecycle_revision=record.revision,
        idempotency_key="default-token-plan-create",
    )
    principal.value = "worker"

    claimed = store.claim_callbacks("tenant-a", limit=1, lease_seconds=5)

    assert claimed[0].lease_token == "lease:-leading-token"


def test_expired_lease_is_recovered_and_old_token_is_rejected(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, clock, principal = authority
    principal.value = "owner"
    record = store.create_lifecycle(
        "tenant-a",
        "lease-recovery",
        vendor_ref="vendor",
        owner_ref="owner",
        dependencies=[dependencies()[0]],
        retention_seconds=DAY,
        idempotency_key="lease-lifecycle",
    )
    store.begin_offboarding(
        "tenant-a",
        record.lifecycle_id,
        "lease-plan",
        tasks=[offboarding_tasks()[0]],
        legal_hold=False,
        legal_hold_evidence_ref=None,
        maximum_callback_attempts=3,
        expected_lifecycle_revision=record.revision,
        idempotency_key="lease-plan-create",
    )
    principal.value = "worker"
    first = store.claim_callbacks("tenant-a", limit=1, lease_seconds=5)[0]
    old_token = first.lease_token or "missing"
    clock.advance(6)
    recovered = store.claim_callbacks("tenant-a", limit=1, lease_seconds=5)[0]
    assert recovered.lease_token != old_token
    with pytest.raises(ThirdPartyLifecycleConflict):
        store.acknowledge_callback(
            "tenant-a",
            recovered.callback_id,
            lease_token=old_token,
            delivery_evidence_sha256=DIGEST_A,
            expected_revision=recovered.revision,
            idempotency_key="stale-lease-ack",
        )


def test_tamper_detection_covers_records_audit_and_operations(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    principal.value = "owner"
    store.create_lifecycle(
        "tenant-a",
        "tamper",
        vendor_ref="vendor",
        owner_ref="owner",
        dependencies=[],
        retention_seconds=DAY,
        idempotency_key="tamper-create",
    )
    assert store.verify_integrity("tenant-a").audit_events == 1
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "UPDATE lifecycles SET payload_json='{}' "
            "WHERE tenant_id='tenant-a' AND lifecycle_id='tamper'"
        )
    with pytest.raises(ThirdPartyLifecycleIntegrityError):
        store.verify_integrity("tenant-a")

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT payload_json FROM audit_events WHERE tenant_id='tenant-a'"
        ).fetchone()
        assert row is not None
        connection.execute(
            "UPDATE audit_events SET integrity_sha256=? WHERE tenant_id='tenant-a'",
            (DIGEST_C,),
        )
    with pytest.raises(ThirdPartyLifecycleIntegrityError):
        store.verify_integrity("tenant-a")


def test_honest_provider_boundary_and_lifecycle_export(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
) -> None:
    store, _, principal = authority
    assert LIVE_PROVIDER_OPERATIONS is False
    assert LIVE_PROVIDER_ACCEPTANCE_VERIFIED is False
    assert not hasattr(store, "execute_callback")
    principal.value = "owner"
    lifecycle = store.create_lifecycle(
        "tenant-a",
        "exported",
        vendor_ref="vendor",
        owner_ref="owner",
        dependencies=[],
        retention_seconds=DAY,
        idempotency_key="exported-create",
    )
    report = store.export_lifecycle(
        "tenant-a",
        lifecycle.lifecycle_id,
        "lifecycle-export",
        retention_seconds=DAY,
        idempotency_key="lifecycle-export-create",
    )
    assert report.body["lifecycle_integrity_sha256"] == lifecycle.integrity_sha256
    assert "callbacks_are_delivery_intent_not_external_writes" in report.body["limitations"]
    assert store.verify_integrity("tenant-a").verified_records > 0


def _record_connections(monkeypatch) -> list[sqlite3.Connection]:
    opened: list[sqlite3.Connection] = []
    real_connect = sqlite3.connect

    def recording_connect(*args, **kwargs):
        connection = real_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", recording_connect)
    return opened


def test_offboarding_hold_refusal_closes_every_ledger_connection(
    authority: tuple[ThirdPartyLifecycleStore, Clock, Principal],
    monkeypatch,
) -> None:
    """The completion gate derives the legal-hold blocker through ledger connections
    that must be closed, not only committed (Windows keeps the ledger locked)."""
    store, clock, principal = authority
    evaluated_owner_review_assessment(store, principal, "vendor-1")
    principal.value = "owner"
    lifecycle = store.create_lifecycle(
        "tenant-a",
        "lifecycle-1",
        vendor_ref="vendor-1",
        owner_ref="owner",
        dependencies=dependencies(),
        retention_seconds=DAY,
        idempotency_key="lifecycle-create",
    )
    lifecycle = store.transition_lifecycle(
        "tenant-a",
        lifecycle.lifecycle_id,
        "active",
        reason_code="onboarding_accepted",
        expected_revision=lifecycle.revision,
        idempotency_key="lifecycle-active",
    )
    plan = store.begin_offboarding(
        "tenant-a",
        lifecycle.lifecycle_id,
        "plan-1",
        tasks=offboarding_tasks(),
        legal_hold=True,
        legal_hold_evidence_ref="legal.hold.case",
        maximum_callback_attempts=2,
        expected_lifecycle_revision=lifecycle.revision,
        idempotency_key="offboarding-begin",
    )
    principal.value = "approver"
    opened = _record_connections(monkeypatch)
    try:
        with pytest.raises(ThirdPartyLifecycleConflict, match="legal_hold_active"):
            store.approve_offboarding_completion(
                "tenant-a",
                plan.plan_id,
                completion_attestation_ref="attestation.held",
                expected_plan_revision=plan.revision,
                expected_lifecycle_revision=3,
                idempotency_key="offboarding-held",
            )
        assert opened, "the completion gate should read the ledger"
        for connection in opened:
            with pytest.raises(sqlite3.ProgrammingError):  # a closed connection refuses work
                connection.execute("SELECT 1")
    finally:
        for connection in opened:
            connection.close()
