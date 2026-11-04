"""Acceptance tests for immutable, independently authorized promotion."""

from __future__ import annotations

import hashlib
from contextlib import nullcontext

import pytest
from maverick import config, governed_records
from maverick.candidate_promotion import (
    ArtifactCommitment,
    ArtifactObservation,
    CanaryInvariant,
    CanaryObservation,
    CandidatePromotionConflict,
    CandidatePromotionDenied,
    CandidatePromotionInterrupted,
    CandidatePromotionNotFound,
    CandidatePromotions,
    DeploymentEffectReceipt,
    DeploymentObservation,
    DeploymentReconciliation,
    LineageCommitment,
    PromotionAuthority,
    PromotionPolicy,
    PromotionTarget,
    PromotionTargetPreset,
    ResourceRequirements,
    RunPromotionAdmission,
    StudyClaim,
    TrustedStudyAdmission,
)

TENANT = "tenant-a"
REQUESTER = "user:researcher"
REVIEWER = "user:release-reviewer"
OPERATOR = "user:release-operator"
FUTURE = 4_102_444_800.0


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Adapter:
    def __init__(self, state):
        self.state = state

    def observe(self, tenant, target_id):
        self.state["calls"].append("observe")
        return DeploymentObservation(
            tenant=tenant,
            target_id=target_id,
            active_artifact_sha256=self.state["active_sha256"],
            state_schema="lightwork.state:v1",
            queued_intent_schema="lightwork.intent:v1",
            external_state_sha256=_sha("external-before"),
            pending_intents_sha256=_sha("pending-before"),
            rollback_handle="artifact:rollback/previous",
            rollback_compatible=True,
            evidence_sha256=_sha("observe"),
        )

    def stage(self, manifest):
        self.state["calls"].append("stage")
        if self.state.get("fail_stage"):
            raise RuntimeError("fixture stage response was lost")
        return DeploymentEffectReceipt(
            tenant=TENANT,
            target_id="installed-lightwork",
            operation_id="stage-one",
            action="stage",
            before_sha256=self.state["previous_sha256"],
            after_sha256=self.state["candidate_sha256"],
            evidence_sha256=_sha("stage"),
        )

    def activate(self, manifest, stage_receipt):
        self.state["calls"].append("activate")
        self.state["active_sha256"] = self.state["candidate_sha256"]
        return DeploymentEffectReceipt(
            tenant=TENANT,
            target_id="installed-lightwork",
            operation_id="activate-one",
            action="activate",
            before_sha256=self.state["previous_sha256"],
            after_sha256=self.state["candidate_sha256"],
            evidence_sha256=_sha("activate"),
        )

    def canary(self, manifest):
        self.state["calls"].append("canary")
        if self.state.get("fail_canary_observation"):
            raise RuntimeError("fixture canary observation was unavailable")
        return CanaryObservation(
            tenant=TENANT,
            target_id="installed-lightwork",
            active_artifact_sha256=self.state["active_sha256"],
            metrics=(("error_rate", self.state["error_rate"]),),
            evidence_sha256=_sha("canary"),
        )

    def rollback(self, manifest, rollback_handle):
        self.state["calls"].append("rollback")
        before = self.state["active_sha256"]
        self.state["active_sha256"] = self.state["previous_sha256"]
        return DeploymentEffectReceipt(
            tenant=TENANT,
            target_id="installed-lightwork",
            operation_id="rollback-one",
            action="rollback",
            before_sha256=before,
            after_sha256=self.state["previous_sha256"],
            evidence_sha256=_sha("rollback"),
        )

    def reconcile(self, manifest):
        self.state["calls"].append("reconcile")
        return DeploymentReconciliation(
            tenant=TENANT,
            target_id="installed-lightwork",
            active_artifact_sha256=self.state["active_sha256"],
            state_schema="lightwork.state:v1",
            queued_intent_schema="lightwork.intent:v1",
            state_restored=True,
            pending_intents_reconciled=True,
            external_state_reconciled=True,
            evidence_sha256=_sha("reconcile"),
        )


@pytest.fixture
def promotion(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()

    candidate = _sha("candidate-bundle")
    previous = _sha("previous-bundle")
    state = {
        "candidate_sha256": candidate,
        "previous_sha256": previous,
        "active_sha256": previous,
        "artifact_sha256": candidate,
        "artifact_authority": _sha("artifact-authority-v1"),
        "rights_active": True,
        "rights_epoch": "v1",
        "study_conclusion": "qualified",
        "study_report": "study-report",
        "study_authority": "v1",
        "target_preset_authority": "v1",
        "authority_epochs": {REVIEWER: "v1", OPERATOR: "v1"},
        "authority_actions": {
            REVIEWER: tuple(sorted({"review", "stage", "activate", "canary", "rollback", "reconcile"})),
            OPERATOR: tuple(sorted({"stage", "activate", "canary", "rollback", "reconcile"})),
        },
        "error_rate": 0.01,
        "calls": [],
    }

    lineage = (
        LineageCommitment(
            kind="dataset",
            asset_id="dataset-one",
            version="v1",
            manifest_sha256=_sha("dataset-manifest"),
            required_action_if_revoked="retrain",
        ),
    )

    def run_resolver(tenant, principal, run_id):
        if not state["rights_active"]:
            raise PermissionError("rights revoked")
        study_admission = TrustedStudyAdmission(
            tenant=tenant,
            run_id=run_id,
            run_manifest_sha256=_sha("run-manifest"),
            result_sha256=_sha("result"),
            output_artifact_sha256=candidate,
            study=StudyClaim(
                report_sha256=_sha(state["study_report"]),
                conclusion=state["study_conclusion"],
                conclusion_evidence_sha256=_sha("study-conclusion"),
                evaluator_id="independent-evaluator",
                evaluator_version="v1",
                metric_protocol_sha256=_sha("metric-protocol"),
            ),
            artifacts=(ArtifactCommitment(
                artifact_id="candidate-bundle",
                kind="bundle",
                source_ref="artifact:candidates/candidate-one",
                sha256=candidate,
                size_bytes=123,
            ),),
            authority_sha256=_sha("study:" + state["study_authority"]),
        )
        return RunPromotionAdmission(
            tenant=tenant,
            principal=principal,
            candidate_principal="research-worker:one",
            run_id=run_id,
            run_manifest_sha256=_sha("run-manifest"),
            registry_binding_sha256=_sha("registry-binding"),
            result_sha256=_sha("result"),
            output_artifact_sha256=candidate,
            lineage=lineage,
            authority_sha256=_sha("rights:" + state["rights_epoch"]),
            study_admission=study_admission,
        )

    def artifact_resolver(tenant, source_ref):
        return ArtifactObservation(
            tenant=tenant,
            source_ref=source_ref,
            sha256=state["artifact_sha256"],
            size_bytes=123,
            authority_sha256=state["artifact_authority"],
        )

    def authority_resolver(tenant, principal):
        actions = state["authority_actions"].get(principal, ())
        epoch = state["authority_epochs"].get(principal, "missing")
        return PromotionAuthority(
            tenant=tenant,
            principal=principal,
            role=(
                "release_reviewer"
                if principal in {REVIEWER, REQUESTER}
                else "release_operator"
            ),
            actions=actions,
            authorization_sha256=_sha(f"{principal}:{epoch}"),
            valid_until=FUTURE,
        )

    def policy_resolver():
        return PromotionPolicy(
            policy_id="customer-release",
            version=state.get("policy_version", "v1"),
            allowed_targets=("installed-lightwork",),
            role_actions=(
                ("release_operator", tuple(sorted({"stage", "activate", "canary", "rollback", "reconcile"}))),
                ("release_reviewer", tuple(sorted({"review", "stage", "activate", "canary", "rollback", "reconcile"}))),
            ),
            canary_invariants=(CanaryInvariant("error_rate", "at_most", 0.05),),
        )

    def target_preset_resolver(tenant, preset_id):
        assert tenant == TENANT
        return PromotionTargetPreset(
            preset_id=preset_id,
            target=PromotionTarget(
                target_id="installed-lightwork",
                expected_active_sha256=previous,
                state_schema="lightwork.state:v1",
                queued_intent_schema="lightwork.intent:v1",
                external_reconciliation_schema="lightwork.reconciliation:v1",
            ),
            resources=ResourceRequirements(
                max_memory_bytes=512 * 1024 * 1024,
                max_storage_bytes=1024 * 1024 * 1024,
                max_cpu_cores=1.0,
                required_providers=(),
            ),
            authority_sha256=_sha("preset:" + state["target_preset_authority"]),
        )

    service = CandidatePromotions(
        run_admission_resolver=run_resolver,
        artifact_resolver=artifact_resolver,
        target_preset_resolver=target_preset_resolver,
        completed_runs_resolver=lambda _tenant, _principal: ("run-one",),
        authority_resolver=authority_resolver,
        policy_resolver=policy_resolver,
        deployment_adapter=_Adapter(state),
        effect_fence=nullcontext,
    )
    service._test_state = state
    yield service, state
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _request(service, *, conclusion="qualified", candidate_id="candidate-one"):
    # The test controls the trusted evaluator fixture. The request has no study fields.
    service._test_state["study_conclusion"] = conclusion
    return service.request(
        TENANT,
        REQUESTER,
        candidate_id=candidate_id,
        run_id="run-one",
        target_preset="installed-lightwork",
    )


def _review(service, record):
    return service.review(
        TENANT,
        REVIEWER,
        record["candidate_id"],
        expected_revision=record["revision"],
        approve=True,
        reason_code="qualified_release",
        evidence_sha256=_sha("human-review"),
    )


def test_a1_changed_candidate_is_rejected_before_deployment_effect(promotion):
    service, state = promotion
    record = _review(service, _request(service))
    state["artifact_sha256"] = _sha("substituted-bundle")

    with pytest.raises(CandidatePromotionConflict, match="changed after evaluation"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=record["revision"])

    assert state["calls"] == []


def test_a2_candidate_and_requester_cannot_approve_their_own_candidate(promotion):
    service, state = promotion
    record = _request(service)
    state["authority_actions"][REQUESTER] = ("review",)
    state["authority_epochs"][REQUESTER] = "v1"

    with pytest.raises(CandidatePromotionDenied, match="cannot approve"):
        service.review(
            TENANT,
            REQUESTER,
            "candidate-one",
            expected_revision=record["revision"],
            approve=True,
            reason_code="self_approval",
            evidence_sha256=_sha("forged-review"),
        )

    assert service.inspect(TENANT, REQUESTER, "candidate-one")["state"] == "awaiting_review"
    assert state["calls"] == []


def test_reviewer_authority_rotation_invalidates_approval_before_stage(promotion):
    service, state = promotion
    record = _review(service, _request(service))
    state["authority_epochs"][REVIEWER] = "v2"

    with pytest.raises(CandidatePromotionDenied, match="approval authority changed"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=record["revision"])

    assert state["calls"] == []


def test_policy_change_invalidates_review_before_stage(promotion):
    service, state = promotion
    record = _review(service, _request(service))
    state["policy_version"] = "v2"

    with pytest.raises(CandidatePromotionDenied, match="approval is missing, stale, or expired"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=record["revision"])

    assert state["calls"] == []


def test_a3_revoked_lineage_blocks_with_specific_remediation(promotion):
    service, state = promotion
    record = _review(service, _request(service))
    state["rights_active"] = False

    with pytest.raises(CandidatePromotionDenied, match="research rights deny"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=record["revision"])

    blocked = service.inspect(TENANT, OPERATOR, "candidate-one")
    assert blocked["state"] == "blocked"
    assert blocked["block"]["reason_code"] == "lineage_rights_changed"
    assert blocked["block"]["remediation"] == [{
        "kind": "dataset",
        "asset_id": "dataset-one",
        "version": "v1",
        "manifest_sha256": _sha("dataset-manifest"),
        "required_action": "retrain",
    }]
    assert state["calls"] == []


def test_a4_failed_canary_rolls_back_and_reconciles_compatible_state(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    staged = service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=reviewed["revision"])
    active = service.activate(TENANT, OPERATOR, "candidate-one", expected_revision=staged["revision"])
    state["error_rate"] = 0.50

    rolled_back = service.assess_canary(
        TENANT, OPERATOR, "candidate-one", expected_revision=active["revision"],
    )

    assert rolled_back["state"] == "rolled_back"
    assert state["active_sha256"] == state["previous_sha256"]
    assert state["calls"] == ["observe", "stage", "activate", "canary", "rollback", "reconcile"]
    assert rolled_back["deployment"]["reconciliation"]["pending_intents_reconciled"] is True
    assert rolled_back["deployment"]["canary"]["passed"] is False


def test_canary_cannot_trigger_rollback_without_current_rollback_authority(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    staged = service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=reviewed["revision"])
    active = service.activate(TENANT, OPERATOR, "candidate-one", expected_revision=staged["revision"])
    state["calls"].clear()
    state["authority_actions"][OPERATOR] = ("canary",)
    state["error_rate"] = 0.50

    with pytest.raises(CandidatePromotionDenied, match="denies this action"):
        service.assess_canary(
            TENANT, OPERATOR, "candidate-one", expected_revision=active["revision"],
        )

    assert state["calls"] == []
    assert state["active_sha256"] == state["candidate_sha256"]


def test_expired_review_cannot_disable_post_deployment_canary_rollback(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    staged = service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=reviewed["revision"])
    canary = service.activate(TENANT, OPERATOR, "candidate-one", expected_revision=staged["revision"])
    service.store.authoritative_time = lambda: float(canary["review"]["expires_at"]) + 1
    state["error_rate"] = 0.50

    rolled_back = service.assess_canary(
        TENANT, OPERATOR, "candidate-one", expected_revision=canary["revision"]
    )

    assert rolled_back["state"] == "rolled_back"
    assert state["active_sha256"] == state["previous_sha256"]


def test_policy_drift_after_activation_triggers_rollback_with_current_authority(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    staged = service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=reviewed["revision"])
    canary = service.activate(TENANT, OPERATOR, "candidate-one", expected_revision=staged["revision"])
    state["policy_version"] = "v2"

    rolled_back = service.assess_canary(
        TENANT, OPERATOR, "candidate-one", expected_revision=canary["revision"]
    )

    assert rolled_back["state"] == "rolled_back"
    assert "canary" not in state["calls"][3:]
    assert state["calls"][-2:] == ["rollback", "reconcile"]


def test_unavailable_canary_observation_triggers_safe_rollback(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    staged = service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=reviewed["revision"])
    canary = service.activate(TENANT, OPERATOR, "candidate-one", expected_revision=staged["revision"])
    state["fail_canary_observation"] = True

    rolled_back = service.assess_canary(
        TENANT, OPERATOR, "candidate-one", expected_revision=canary["revision"]
    )

    assert rolled_back["state"] == "rolled_back"
    assert state["calls"][-3:] == ["canary", "rollback", "reconcile"]


def test_uncertain_effect_can_be_reconciled_after_review_expiry_without_replay(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    state["fail_stage"] = True
    with pytest.raises(CandidatePromotionInterrupted):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=reviewed["revision"])
    uncertain = service.inspect(TENANT, OPERATOR, "candidate-one")
    service.store.authoritative_time = lambda: float(uncertain["review"]["expires_at"]) + 1
    stage_calls = state["calls"].count("stage")

    reconciled = service.reconcile(
        TENANT, OPERATOR, "candidate-one", expected_revision=uncertain["revision"]
    )

    assert reconciled["state"] == "rolled_back"
    assert state["calls"].count("stage") == stage_calls
    assert state["calls"][-1] == "reconcile"


@pytest.mark.parametrize("conclusion", ["negative", "inconclusive"])
def test_a5_nonqualifying_study_is_complete_without_advancement(promotion, conclusion):
    service, state = promotion
    record = _request(service, conclusion=conclusion)

    assert record["state"] == "not_advancing"
    assert record["block"] == {
        "reason_code": f"study_{conclusion}",
        "detail": "The study remains complete, but this result cannot advance to production.",
        "remediation": [],
    }
    with pytest.raises(CandidatePromotionConflict, match="not awaiting review"):
        _review(service, record)
    assert state["calls"] == []


def test_trusted_study_change_blocks_before_human_review(promotion):
    service, state = promotion
    record = _request(service)
    state["study_report"] = "substituted-study-report"

    with pytest.raises(CandidatePromotionDenied, match="run evidence changed"):
        _review(service, record)

    retained = service.inspect(TENANT, REVIEWER, record["candidate_id"])
    assert retained["state"] == "blocked"
    assert state["calls"] == []


def test_trusted_study_change_blocks_before_staging_effect(promotion):
    service, state = promotion
    reviewed = _review(service, _request(service))
    state["study_authority"] = "v2"

    with pytest.raises(CandidatePromotionDenied, match="run evidence changed"):
        service.stage(
            TENANT,
            OPERATOR,
            reviewed["candidate_id"],
            expected_revision=reviewed["revision"],
        )

    retained = service.inspect(TENANT, OPERATOR, reviewed["candidate_id"])
    assert retained["state"] == "blocked"
    assert state["calls"] == []


def test_request_contract_rejects_caller_authored_study_claim(promotion):
    service, _state = promotion

    with pytest.raises(TypeError, match="unexpected keyword argument 'study'"):
        service.request(
            TENANT,
            REQUESTER,
            candidate_id="forged-candidate",
            run_id="run-one",
            target_preset="installed-lightwork",
            study=StudyClaim(
                report_sha256=_sha("forged-report"),
                conclusion="qualified",
                conclusion_evidence_sha256=_sha("forged-evidence"),
                evaluator_id="browser",
                evaluator_version="v1",
                metric_protocol_sha256=_sha("metric-protocol"),
            ),
        )
    with pytest.raises(CandidatePromotionNotFound):
        service.inspect(TENANT, REQUESTER, "forged-candidate")


def test_uncertain_stage_is_durable_and_cannot_be_blindly_replayed(promotion):
    service, state = promotion
    record = _review(service, _request(service))
    state["fail_stage"] = True

    with pytest.raises(CandidatePromotionInterrupted, match="uncertain"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=record["revision"])

    uncertain = service.inspect(TENANT, OPERATOR, "candidate-one")
    assert uncertain["state"] == "uncertain"
    with pytest.raises(CandidatePromotionConflict, match="authorized revision"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=uncertain["revision"])
    assert state["calls"].count("stage") == 1


def test_unbound_artifact_authority_rotation_requires_fresh_review(promotion):
    service, state = promotion
    record = _review(service, _request(service))
    state["artifact_authority"] = _sha("artifact-authority-v2")

    with pytest.raises(CandidatePromotionConflict, match="authority changed"):
        service.stage(TENANT, OPERATOR, "candidate-one", expected_revision=record["revision"])

    assert state["calls"] == []
