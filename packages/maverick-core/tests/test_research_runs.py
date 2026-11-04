"""Acceptance-focused tests for governed research run and attempt records."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, replace
from unittest.mock import patch

import pytest
from maverick import config, governed_records
from maverick.candidate_promotion import (
    ArtifactCommitment,
    StudyClaim,
    TrustedStudyAdmission,
)
from maverick.paths import tenant_scope
from maverick.research_registry import (
    DataUseAuthority,
    RegistryReviewAuthority,
    ResearchRegistry,
    ResearchRegistryDenied,
    verified_training_receipt_resolver,
)
from maverick.research_runs import (
    ResearchDispatchReceipt,
    ResearchMaterializationUnavailable,
    ResearchMetric,
    ResearchResourceCaps,
    ResearchResourceCost,
    ResearchRunAuthority,
    ResearchRunConflict,
    ResearchRunInterrupted,
    ResearchRunNotFound,
    ResearchRuns,
    ResearchWorkerAuthority,
)

TENANT = "tenant-a"
FUTURE = 4_102_444_800.0


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def services(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()
    state = {
        "grants": {},
        "dispatches": [],
        "provider_work_items": [],
        "study_contexts": [],
        "study_conclusion": "qualified",
    }

    def data_use(tenant, decision_id, expected_sha256):
        grant = state["grants"].get(decision_id)
        if (
            tenant != TENANT
            or grant is None
            or expected_sha256 != _sha(decision_id)
            or not grant["active"]
        ):
            raise ResearchRegistryDenied("current data-use rights are unavailable")
        return DataUseAuthority(
            tenant=tenant,
            decision_id=decision_id,
            decision_sha256=expected_sha256,
            asset_id=grant["asset_id"],
            action=grant["action"],
            purpose_codes=(grant["purpose"],),
            expires_at=FUTURE,
            authority_sha256=_sha(f"authority:{decision_id}:{grant['epoch']}"),
        )

    registry = ResearchRegistry(
        data_use_resolver=data_use,
        review_authority_resolver=lambda tenant, principal: RegistryReviewAuthority(
            tenant,
            principal,
            _sha(f"registry-review:{tenant}:{principal}"),
        ),
    )

    class Adapter:
        def materialize_and_dispatch(self, request):
            from maverick.provider_cost_cap import _current_work_item

            state["provider_work_items"].append(_current_work_item())
            state["dispatches"].append(request)
            return ResearchDispatchReceipt(
                tenant=request.tenant,
                run_id=request.run_id,
                attempt=request.attempt,
                request_sha256=request.request_sha256,
                dispatch_id=f"dispatch-{request.attempt}",
                adapter_id="bounded-fixture",
                adapter_version="v1",
                adapter_authority_sha256=_sha("adapter-authority"),
                materialized_dataset_sha256s=tuple(
                    item.content_sha256 for item in request.datasets
                ),
                dispatched_at=1_000.0 + request.attempt,
            )

    def promotion_study(context):
        state["study_contexts"].append(context)
        return TrustedStudyAdmission(
            tenant=context.tenant,
            run_id=context.run_id,
            run_manifest_sha256=context.run_manifest_sha256,
            result_sha256=context.result_sha256,
            output_artifact_sha256=context.output_artifact_sha256,
            study=StudyClaim(
                report_sha256=_sha(f"report:{context.sha256}"),
                conclusion=state["study_conclusion"],
                conclusion_evidence_sha256=_sha(f"conclusion:{context.sha256}"),
                evaluator_id="trusted-study-evaluator",
                evaluator_version="v1",
                metric_protocol_sha256=context.metric_protocol_sha256,
            ),
            artifacts=(ArtifactCommitment(
                artifact_id=f"{context.run_id}-output",
                kind="bundle",
                source_ref=f"artifact:research/{context.run_id}/output",
                sha256=context.output_artifact_sha256,
                size_bytes=1,
            ),),
            authority_sha256=_sha("trusted-study-authority:v1"),
        )

    runs = ResearchRuns(
        registry=registry,
        authority_resolver=lambda tenant, principal: ResearchRunAuthority(
            tenant,
            principal,
            _sha(f"run-authority:{tenant}:{principal}"),
        ),
        worker_authority_resolver=lambda tenant, principal: ResearchWorkerAuthority(
            tenant,
            principal,
            _sha(f"worker-authority:{tenant}:{principal}"),
        ),
        effect_adapter=Adapter(),
        promotion_study_resolver=promotion_study,
    )
    yield registry, runs, state
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _dataset(
    registry,
    state,
    *,
    dataset_id="dataset-one",
    action="analyze",
    purpose="research_evaluation",
    content_sha256=None,
    parent_datasets=(),
):
    decision_id = f"decision-{dataset_id}"
    state["grants"][decision_id] = {
        "asset_id": dataset_id,
        "action": action,
        "purpose": purpose,
        "active": True,
        "epoch": "v1",
    }
    reference = registry.register_dataset(
        TENANT,
        "user:maker",
        dataset_id=dataset_id,
        version="v1",
        source_ref=f"catalog:datasets/{dataset_id}/v1",
        content_sha256=content_sha256 or _sha(f"bytes:{dataset_id}"),
        license_id="tenant-research-license",
        license_evidence_sha256=_sha(f"license:{dataset_id}"),
        allowed_purposes=(purpose,),
        usage_constraints=("tenant only", "no redistribution"),
        data_use_action=action,
        data_use_decision_id=decision_id,
        data_use_decision_sha256=_sha(decision_id),
        parent_datasets=parent_datasets,
    )
    draft = registry.inspect(TENANT, reference)
    return registry.approve(
        TENANT,
        f"user:reviewer-{dataset_id}",
        reference,
        expected_revision=draft["revision"],
    )


def _plan(
    runs,
    dataset,
    *,
    run_id="run-one",
    action="analyze",
    purpose="research_evaluation",
    model=None,
    environment_id="research-sandbox",
    environment_version="v1",
    environment_sha256=None,
):
    return runs.plan(
        TENANT,
        "user:researcher",
        run_id=run_id,
        run_version="v1",
        experiment_id="experiment-one",
        experiment_version="v3",
        purpose=purpose,
        action=action,
        code_revision=_sha("source")[:40],
        code_sha256=_sha("source-tree"),
        environment_id=environment_id,
        environment_version=environment_version,
        environment_sha256=environment_sha256 or _sha("environment"),
        seed=42,
        dataset_refs=(dataset,),
        model_ref=model,
        resource_caps=ResearchResourceCaps(
            max_wall_seconds=3_600,
            max_provider_calls=100,
            max_storage_bytes=1_000_000,
            max_cost="25.00",
            currency="USD",
        ),
        metric_protocol_sha256=_sha("metric-protocol"),
    )


def _cost(label, amount):
    return ResearchResourceCost(
        category="compute",
        basis="observed",
        quantity="60",
        unit="seconds",
        amount=amount,
        currency="USD",
        evidence_sha256=_sha(f"cost:{label}"),
        source_ref=f"artifact:costs/{label}",
    )


def test_a1_service_read_rights_do_not_admit_training(services):
    registry, runs, state = services
    dataset = _dataset(
        registry,
        state,
        dataset_id="service-data",
        action="read",
        purpose="service_delivery",
    )
    planned = _plan(
        runs,
        dataset,
        action="train",
        purpose="model_training",
    )

    with pytest.raises(ResearchRegistryDenied, match="not approved for this purpose"):
        runs.queue(
            TENANT,
            "user:researcher",
            planned["run_id"],
            expected_revision=planned["revision"],
        )

    retained = runs.inspect(TENANT, "user:researcher", planned["run_id"])
    assert retained["status"] == "planned"
    assert state["dispatches"] == []


def test_dispatch_binds_nested_provider_calls_to_stable_run_identity(services):
    from maverick.provider_cost_cap import _current_work_item

    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset, run_id="provider-bound-run")
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )

    running = runs.start(
        TENANT,
        "user:worker",
        queued["run_id"],
        expected_revision=queued["revision"],
    )

    assert running["status"] == "running"
    assert state["provider_work_items"] == ["research:provider-bound-run"]
    assert _current_work_item() is None


def test_a2_worker_rechecks_revoked_rights_before_materialization(services):
    registry, runs, state = services
    dataset = _dataset(
        registry,
        state,
        dataset_id="training-data",
        action="train",
        purpose="model_training",
    )
    planned = _plan(
        runs,
        dataset,
        action="train",
        purpose="model_training",
    )
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )
    state["grants"]["decision-training-data"]["active"] = False

    with pytest.raises(ResearchRegistryDenied, match="rights are unavailable"):
        runs.start(
            TENANT,
            "user:worker",
            queued["run_id"],
            expected_revision=queued["revision"],
        )

    retained = runs.inspect(TENANT, "user:researcher", queued["run_id"])
    assert retained["status"] == "queued"
    assert retained["attempts"][0]["dispatch_receipt"] is None
    assert state["dispatches"] == []


def test_a3_failed_retry_versions_costs_corrections_and_export_are_reconstructable(
    services,
):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )
    running = runs.start(
        TENANT,
        "user:worker",
        queued["run_id"],
        expected_revision=queued["revision"],
    )
    failed = runs.finish(
        TENANT,
        "user:worker",
        running["run_id"],
        expected_revision=running["revision"],
        outcome="failed",
        result_idempotency_key="failed-result",
        costs=(_cost("failed", "0.40"),),
        failure_code="evaluation_failed",
        failure_evidence_sha256=_sha("failed-evidence"),
    )
    failed_cost = failed["attempts"][0]["costs"][0]
    corrected = runs.correct_cost(
        TENANT,
        "user:researcher",
        failed["run_id"],
        expected_revision=failed["revision"],
        attempt_number=1,
        correction_key="failed-cost-correction",
        correction_of=failed_cost["event_sha256"],
        replacement=_cost("failed-settled", "0.45"),
    )
    replayed_correction = runs.correct_cost(
        TENANT,
        "user:researcher",
        failed["run_id"],
        expected_revision=failed["revision"],
        attempt_number=1,
        correction_key="failed-cost-correction",
        correction_of=failed_cost["event_sha256"],
        replacement=_cost("failed-settled", "0.45"),
    )
    assert replayed_correction["revision"] == corrected["revision"]
    retried = runs.retry(
        TENANT,
        "user:researcher",
        corrected["run_id"],
        expected_revision=corrected["revision"],
    )
    queued_again = runs.queue(
        TENANT,
        "user:researcher",
        retried["run_id"],
        expected_revision=retried["revision"],
    )
    running_again = runs.start(
        TENANT,
        "user:worker",
        queued_again["run_id"],
        expected_revision=queued_again["revision"],
    )
    metric = ResearchMetric(
        name="accuracy",
        value="0.95",
        evaluator_id="sealed-evaluator",
        evaluator_version="v2",
        source_artifact_sha256=_sha("metric-artifact"),
        lineage_sha256=_sha("metric-lineage"),
    )
    completed = runs.finish(
        TENANT,
        "user:worker",
        running_again["run_id"],
        expected_revision=running_again["revision"],
        outcome="completed",
        result_idempotency_key="successful-result",
        costs=(_cost("success", "0.60"),),
        metrics=(metric,),
        output_artifact_sha256=_sha("candidate-artifact"),
    )
    replayed = runs.finish(
        TENANT,
        "user:worker",
        running_again["run_id"],
        expected_revision=running_again["revision"],
        outcome="completed",
        result_idempotency_key="successful-result",
        costs=(_cost("success", "0.60"),),
        metrics=(metric,),
        output_artifact_sha256=_sha("candidate-artifact"),
    )
    assert replayed["revision"] == completed["revision"]
    assert state["provider_work_items"] == ["research:run-one", "research:run-one"]

    first = runs.export(TENANT, "user:researcher", completed["run_id"])
    assert first == runs.export(TENANT, "user:researcher", completed["run_id"])
    exported = json.loads(first)
    attempts = exported["run"]["attempts"]
    assert [attempt["status"] for attempt in attempts] == ["failed", "completed"]
    assert attempts[0]["version_binding"] == attempts[1]["version_binding"]
    assert [event["cost"]["amount"] for event in attempts[0]["costs"]] == [
        "0.4",
        "0.45",
    ]
    assert attempts[0]["costs"][1]["correction_of"] == failed_cost["event_sha256"]
    assert attempts[1]["metrics"] == [asdict(metric)]
    assert exported["cost_summary"] == {
        "effective_amounts": {"USD": "1.05"},
        "incomplete": False,
        "effective_event_count": 2,
    }
    assert exported["data_statement"]["contains_raw_customer_data"] is False
    assert exported["data_statement"]["raw_deletion_claims_weight_influence_removed"] is False


def test_a4_revocation_graph_finds_retrieval_and_weight_derivatives(services):
    registry, _runs, state = services
    experience = _dataset(
        registry,
        state,
        dataset_id="experience",
    )
    retrieval = _dataset(
        registry,
        state,
        dataset_id="retrieval-index",
        parent_datasets=(experience,),
    )
    weights = registry.register_model(
        TENANT,
        "user:maker",
        model_id="candidate-weights",
        version="v1",
        source_ref="artifact:models/candidate-weights/v1",
        artifact_sha256=_sha("candidate-weights"),
        license_id="internal-research-license",
        license_evidence_sha256=_sha("weight-license"),
        allowed_purposes=("research_evaluation",),
        usage_constraints=("tenant only",),
        provider_model_identity="candidate-weights-v1",
        immutable_provider_revision=_sha("weight-revision"),
        dataset_lineage=(experience,),
        dataset_lineage_purpose="research_evaluation",
    )
    weights = registry.approve(
        TENANT,
        "user:weight-reviewer",
        weights,
        expected_revision=1,
    )
    source = registry.inspect(TENANT, experience)
    registry.revoke(
        TENANT,
        "user:privacy-reviewer",
        experience,
        expected_revision=source["revision"],
        reason_code="use_revoked",
        evidence_sha256=_sha("revocation-evidence"),
    )

    impact = registry.derivative_impact(TENANT, experience)
    impacted = {
        (item["reference"]["kind"], item["reference"]["asset_id"]): item
        for item in impact["derivatives"]
    }
    assert impacted[("dataset", "retrieval-index")]["required_action"] == "invalidate_dataset"
    assert impacted[("model", "candidate-weights")]["required_action"] == "retire_or_retrain_model"
    assert impact["raw_deletion_removes_weight_influence"] is False
    assert retrieval.manifest_sha256
    assert weights.manifest_sha256


def test_a5_unpinnable_provider_identity_window_is_in_run_export(services):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    model = registry.register_model(
        TENANT,
        "user:maker",
        model_id="provider-candidate",
        version="v1",
        source_ref="catalog:models/provider-candidate/v1",
        artifact_sha256=_sha("provider-output"),
        license_id="provider-research-license",
        license_evidence_sha256=_sha("provider-license"),
        allowed_purposes=("research_evaluation",),
        usage_constraints=("tenant only",),
        provider_model_identity="provider-returned-2026-09-08",
        immutable_provider_revision=None,
        observed_from=1_000.0,
        observed_until=2_000.0,
        reproducibility_limitation=(
            "Provider exposes no immutable revision; exact replay cannot be guaranteed."
        ),
    )
    model = registry.approve(
        TENANT,
        "user:model-reviewer",
        model,
        expected_revision=1,
    )
    planned = _plan(runs, dataset, model=model)
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )

    exported = json.loads(runs.export(TENANT, "user:researcher", queued["run_id"]))
    model_binding = exported["run"]["attempts"][0]["registry_binding"]["model"]
    assert model_binding["provider_model_identity"] == ("provider-returned-2026-09-08")
    assert model_binding["immutable_provider_revision"] is None
    assert (model_binding["observed_from"], model_binding["observed_until"]) == (
        1_000.0,
        2_000.0,
    )
    assert "exact replay cannot be guaranteed" in model_binding["reproducibility_limitation"]


def test_signed_training_receipt_binds_run_and_trained_model(services):
    from maverick.training import receipts as tr

    from tests.test_training_receipts import _approval, _evidence, _keypair

    registry, runs, state = services
    dataset_hash = _sha("signed-training-dataset")
    dataset = _dataset(
        registry,
        state,
        dataset_id="signed-training-data",
        action="train",
        purpose="model_training",
        content_sha256=dataset_hash,
    )
    base_artifact = _sha("signed-base-model")
    base_model = registry.register_model(
        TENANT,
        "user:maker",
        model_id="base-model",
        version="v1",
        source_ref="catalog:models/base-model/v1",
        artifact_sha256=base_artifact,
        license_id="apache-2.0",
        license_evidence_sha256=_sha("base-license"),
        allowed_purposes=("model_training",),
        usage_constraints=("tenant only",),
        provider_model_identity="base-model-v1",
        immutable_provider_revision=_sha("base-revision"),
    )
    base_model = registry.approve(
        TENANT,
        "user:base-reviewer",
        base_model,
        expected_revision=1,
    )
    output_artifact = _sha("signed-output-adapter")
    environment_id = "privacy-assessment"
    environment_version = "1.0.0"
    environment_sha256 = _sha("signed-environment")
    evidence = _evidence(tenant_id=TENANT)
    evidence = replace(
        evidence,
        run_id="signed-training-run",
        dataset_sha256=dataset_hash,
        environment_id=environment_id,
        environment_version=environment_version,
        environment_sha256=environment_sha256,
        training=replace(
            evidence.training,
            source_revision=_sha("source")[:40],
            deterministic_seed=42,
        ),
        base_model=replace(evidence.base_model, artifact_sha256=base_artifact),
        adapter=replace(evidence.adapter, artifact_sha256=output_artifact),
    )
    approver_private, approver_public, approver_key_id = _keypair()
    approval = _approval(evidence, approver_private, approver_key_id)
    with (
        tenant_scope(tenant=TENANT),
        patch.object(
            tr,
            "_server_training_approver_registry",
            return_value={approver_key_id: approver_public},
        ),
    ):
        issued = tr.issue_training_receipt(evidence, approval)
    receipt_key_id = issued.receipt["key_id"]
    registry.training_receipt_resolver = verified_training_receipt_resolver(
        trusted_receipt_pubkeys={receipt_key_id: issued.signing_public_key},
        trusted_approver_pubkeys={approver_key_id: approver_public},
    )
    planned = _plan(
        runs,
        dataset,
        run_id="signed-training-run",
        action="train",
        purpose="model_training",
        model=base_model,
        environment_id=environment_id,
        environment_version=environment_version,
        environment_sha256=environment_sha256,
    )
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )
    running = runs.start(
        TENANT,
        "user:worker",
        queued["run_id"],
        expected_revision=queued["revision"],
    )
    completed = runs.finish(
        TENANT,
        "user:worker",
        running["run_id"],
        expected_revision=running["revision"],
        outcome="completed",
        result_idempotency_key="signed-result",
        costs=(
            ResearchResourceCost(
                category="training",
                basis="settled",
                quantity="3600",
                unit="seconds",
                amount="4.25",
                currency="USD",
                evidence_sha256=_sha("signed-training-cost"),
                source_ref="artifact:costs/signed-training",
            ),
        ),
        output_artifact_sha256=output_artifact,
        training_receipt_id=issued.receipt["receipt_id"],
        training_receipt_sha256=issued.receipt["receipt_payload_sha256"],
    )
    receipt_binding = completed["attempts"][0]["terminal"]["training_receipt_authority"]
    assert receipt_binding["run_id"] == "signed-training-run"
    assert receipt_binding["dataset_sha256"] == dataset_hash
    assert receipt_binding["output_artifact_sha256"] == output_artifact

    candidate = registry.register_model(
        TENANT,
        "user:maker",
        model_id="trained-candidate",
        version="v1",
        source_ref="artifact:models/trained-candidate/v1",
        artifact_sha256=output_artifact,
        license_id="internal-research-license",
        license_evidence_sha256=_sha("candidate-license"),
        allowed_purposes=("model_training",),
        usage_constraints=("tenant only",),
        provider_model_identity="trained-candidate-v1",
        immutable_provider_revision=_sha("candidate-revision"),
        dataset_lineage=(dataset,),
        dataset_lineage_purpose="model_training",
        model_lineage=(base_model,),
        provenance_kind="trained",
        training_receipt_id=issued.receipt["receipt_id"],
        training_receipt_sha256=issued.receipt["receipt_payload_sha256"],
        training_dataset_sha256=dataset_hash,
    )
    candidate = registry.approve(
        TENANT,
        "user:candidate-reviewer",
        candidate,
        expected_revision=1,
    )
    admitted = registry.resolve_model(
        TENANT,
        candidate,
        purpose="model_training",
    )
    assert admitted.provenance_kind == "trained"
    assert admitted.training_receipt_authority == (
        registry.resolve_training_receipt(
            TENANT,
            issued.receipt["receipt_id"],
            issued.receipt["receipt_payload_sha256"],
        )
    )

    with pytest.raises(ResearchRegistryDenied, match="stale, forged"):
        registry.resolve_training_receipt(
            TENANT,
            issued.receipt["receipt_id"],
            _sha("forged-receipt"),
        )


def test_materialization_interface_and_shared_backend_fail_closed(
    services,
    monkeypatch,
):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )
    monkeypatch.setattr(
        governed_records.GovernedRecordStore,
        "backend_kind",
        property(lambda _self: "postgres"),
    )

    with pytest.raises(
        ResearchMaterializationUnavailable,
        match="transactional authority and materialization guard",
    ):
        runs.start(
            TENANT,
            "user:worker",
            queued["run_id"],
            expected_revision=queued["revision"],
        )
    assert state["dispatches"] == []


def test_interrupted_dispatch_is_retained_and_cannot_be_retried(services):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )

    class UncertainAdapter:
        def materialize_and_dispatch(self, request):
            state["dispatches"].append(request)
            raise OSError("provider connection lost after dispatch")

    runs.effect_adapter = UncertainAdapter()
    with pytest.raises(ResearchRunInterrupted, match="automatic retry is blocked"):
        runs.start(
            TENANT,
            "user:worker",
            queued["run_id"],
            expected_revision=queued["revision"],
        )
    retained = runs.inspect(TENANT, "user:researcher", queued["run_id"])
    assert retained["status"] == "interrupted"
    assert retained["attempts"][0]["terminal"]["external_effect_reversed"] is False
    assert retained["attempts"][0]["costs"][0]["cost"]["basis"] == "unknown"
    assert retained["cost_summary"]["incomplete"] is True
    with pytest.raises(ResearchRunConflict, match="interrupted work"):
        runs.retry(
            TENANT,
            "user:researcher",
            retained["run_id"],
            expected_revision=retained["revision"],
        )


def test_export_and_promotion_recheck_rights_and_forensic_history_remains(
    services,
):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )
    running = runs.start(
        TENANT,
        "user:worker",
        queued["run_id"],
        expected_revision=queued["revision"],
    )
    completed = runs.finish(
        TENANT,
        "user:worker",
        running["run_id"],
        expected_revision=running["revision"],
        outcome="completed",
        result_idempotency_key="result-one",
        costs=(_cost("completed", "0.10"),),
        output_artifact_sha256=_sha("output"),
    )
    promotion = runs.admit_promotion(
        TENANT,
        "user:researcher",
        completed["run_id"],
    )
    assert promotion["output_artifact_sha256"] == _sha("output")
    assert promotion["principal"] == "user:researcher"
    assert promotion["candidate_principal"] == "user:worker"
    assert promotion["run_manifest_sha256"] == completed["manifest_sha256"]
    assert promotion["result_sha256"] == completed["attempts"][0]["terminal"]["result_sha256"]
    assert promotion["authority_sha256"] == completed["submit_authority"]["authorization_sha256"]
    assert promotion["study_admission"]["study"]["conclusion"] == "qualified"
    assert promotion["study_admission"]["result_sha256"] == promotion["result_sha256"]
    assert promotion["study_context_sha256"] == state["study_contexts"][-1].sha256
    assert promotion["lineage"] == [{
        "kind": "dataset",
        "asset_id": "dataset-one",
        "version": "v1",
        "manifest_sha256": dataset.manifest_sha256,
        "required_action_if_revoked": "reevaluate",
    }]
    with pytest.raises(ResearchRunConflict, match="not bound to the completed run"):
        runs.admit_promotion(
            TENANT,
            "user:researcher",
            completed["run_id"],
            trusted_study_resolver=lambda context: replace(
                runs.promotion_study_resolver(context),
                result_sha256=_sha("fabricated-result"),
            ),
        )
    state["grants"]["decision-dataset-one"]["active"] = False

    with pytest.raises(ResearchRegistryDenied, match="rights are unavailable"):
        runs.export(TENANT, "user:researcher", completed["run_id"])
    with pytest.raises(ResearchRegistryDenied, match="rights are unavailable"):
        runs.admit_promotion(
            TENANT,
            "user:researcher",
            completed["run_id"],
        )
    retained = runs.inspect(TENANT, "user:researcher", completed["run_id"])
    assert retained["status"] == "completed"
    assert retained["attempts"][0]["terminal"]["result_sha256"]


def test_pre_dispatch_cancel_is_retained_without_reversal_claim(services):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)
    cancelled = runs.cancel(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
        reason_code="operator_cancelled",
        evidence_sha256=_sha("cancel-evidence"),
    )

    assert cancelled["status"] == "cancelled"
    assert cancelled["attempts"][0]["status"] == "cancelled"
    assert cancelled["attempts"][0]["terminal"]["external_effect_reversed"] is False
    assert state["dispatches"] == []


def test_run_reads_are_tenant_scoped_and_queries_are_bounded(services):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)

    with pytest.raises(ResearchRunNotFound):
        runs.inspect("tenant-b", "user:researcher", planned["run_id"])
    with pytest.raises(ValueError, match="between 1 and 256"):
        runs.list(TENANT, "user:researcher", limit=257)
    assert [item["run_id"] for item in runs.list(TENANT, "user:researcher")] == [planned["run_id"]]


def test_no_materialization_adapter_leaves_queued_attempt_untouched(services):
    registry, runs, state = services
    dataset = _dataset(registry, state)
    planned = _plan(runs, dataset)
    queued = runs.queue(
        TENANT,
        "user:researcher",
        planned["run_id"],
        expected_revision=planned["revision"],
    )
    runs.effect_adapter = None

    with pytest.raises(ResearchMaterializationUnavailable, match="no trusted dataset"):
        runs.start(
            TENANT,
            "user:worker",
            queued["run_id"],
            expected_revision=queued["revision"],
        )
    retained = runs.inspect(TENANT, "user:researcher", queued["run_id"])
    assert retained["status"] == "queued"
    assert state["dispatches"] == []
