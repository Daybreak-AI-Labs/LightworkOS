"""Production composition tests for the guarded promotion workflow."""

from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest
from maverick import config, governed_records
from maverick.candidate_promotion import (
    ArtifactCommitment,
    ArtifactObservation,
    LineageCommitment,
    PromotionAuthority,
    PromotionTarget,
    PromotionTargetPreset,
    ResourceRequirements,
    RunPromotionAdmission,
    StudyClaim,
    TrustedStudyAdmission,
)
from maverick_dashboard import candidate_promotion_composition as composition


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _config(**changes):
    section = {
        "enable": True,
        "allowed_targets": ["installed-lightwork"],
        "review_ttl_seconds": 3600,
        "canary_metric": "error_rate",
        "canary_comparison": "at_most",
        "canary_threshold": 0.05,
    }
    section.update(changes)
    return {"candidate_promotion": section}


def _policy(monkeypatch):
    monkeypatch.delenv("MAVERICK_CANDIDATE_PROMOTION", raising=False)
    return composition.policy_from_config(_config())


def test_policy_is_opt_in_closed_and_digest_changes_with_canary(monkeypatch):
    monkeypatch.delenv("MAVERICK_CANDIDATE_PROMOTION", raising=False)
    assert composition.policy_from_config({}) is None
    first = composition.policy_from_config(_config())
    second = composition.policy_from_config(_config(canary_threshold=0.1))
    assert first is not None and second is not None
    assert first.allowed_targets == ("installed-lightwork",)
    assert first.permits("release_admin", "rollback") is True
    assert first.sha256 != second.sha256

    with pytest.raises(composition.CandidatePromotionCompositionError, match="unsupported"):
        composition.policy_from_config(_config(browser_can_authorize=True))
    with pytest.raises(composition.CandidatePromotionCompositionError, match="unique"):
        composition.policy_from_config(_config(allowed_targets=["same", "same"]))


def test_build_refuses_missing_deployment_authorities(monkeypatch):
    monkeypatch.setattr(composition, "_policy", lambda: _policy(monkeypatch))
    with pytest.raises(composition.CandidatePromotionCompositionError, match="artifact resolver"):
        composition.build_candidate_promotions(SimpleNamespace())
    state = SimpleNamespace(candidate_promotion_artifact_resolver=lambda *_args: None)
    with pytest.raises(composition.CandidatePromotionCompositionError, match="trusted study"):
        composition.build_candidate_promotions(state)


def test_default_run_admission_passes_only_server_owned_study_resolver(monkeypatch):
    from maverick_dashboard import research_workspace_api

    calls = []
    def trusted_resolver(context):
        return context

    class Runs:
        def admit_promotion(self, tenant, principal, run_id, **kwargs):
            calls.append((tenant, principal, run_id, kwargs))
            return {
                "tenant": tenant,
                "principal": principal,
                "candidate_principal": "research-worker:one",
                "run_id": run_id,
                "run_manifest_sha256": _sha("run"),
                "registry_binding_sha256": _sha("registry"),
                "result_sha256": _sha("result"),
                "output_artifact_sha256": _sha("candidate"),
                "lineage": [{
                    "kind": "dataset",
                    "asset_id": "cases",
                    "version": "v1",
                    "manifest_sha256": _sha("cases"),
                    "required_action_if_revoked": "reevaluate",
                }],
                "authority_sha256": _sha("run-authority"),
                "study_admission": {
                    "tenant": tenant,
                    "run_id": run_id,
                    "run_manifest_sha256": _sha("run"),
                    "result_sha256": _sha("result"),
                    "output_artifact_sha256": _sha("candidate"),
                    "study": {
                        "report_sha256": _sha("report"),
                        "conclusion": "qualified",
                        "conclusion_evidence_sha256": _sha("conclusion"),
                        "evaluator_id": "independent",
                        "evaluator_version": "v1",
                        "metric_protocol_sha256": _sha("protocol"),
                    },
                    "artifacts": [{
                        "artifact_id": "candidate",
                        "kind": "bundle",
                        "source_ref": "artifact:candidates/one",
                        "sha256": _sha("candidate"),
                        "size_bytes": 9,
                    }],
                    "authority_sha256": _sha("study-authority"),
                },
            }

    monkeypatch.setattr(research_workspace_api, "_run_service", lambda _state: Runs())
    admission = composition._run_admission(
        SimpleNamespace(),
        "tenant-a",
        "user:researcher@example.test",
        "run-one",
        trusted_resolver,
    )

    assert admission.study_admission.study.conclusion == "qualified"
    assert calls == [(
        "tenant-a",
        "user:researcher@example.test",
        "run-one",
        {"trusted_study_resolver": trusted_resolver},
    )]


def test_built_service_derives_worker_and_rechecks_server_artifact(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()
    policy = _policy(monkeypatch)
    candidate_sha = _sha("candidate")

    class Adapter:
        observe = stage = activate = canary = rollback = reconcile = lambda *args: None

    def run_admission(tenant, principal, run_id):
        study_admission = TrustedStudyAdmission(
            tenant=tenant,
            run_id=run_id,
            run_manifest_sha256=_sha("run"),
            result_sha256=_sha("result"),
            output_artifact_sha256=candidate_sha,
            study=StudyClaim(
                report_sha256=_sha("report"),
                conclusion="qualified",
                conclusion_evidence_sha256=_sha("conclusion"),
                evaluator_id="independent",
                evaluator_version="v1",
                metric_protocol_sha256=_sha("protocol"),
            ),
            artifacts=(ArtifactCommitment(
                artifact_id="candidate",
                kind="bundle",
                source_ref="artifact:candidates/one",
                sha256=candidate_sha,
                size_bytes=9,
            ),),
            authority_sha256=_sha("study-authority"),
        )
        return RunPromotionAdmission(
            tenant=tenant,
            principal=principal,
            candidate_principal="research-worker:one",
            run_id=run_id,
            run_manifest_sha256=_sha("run"),
            registry_binding_sha256=_sha("registry"),
            result_sha256=_sha("result"),
            output_artifact_sha256=candidate_sha,
            lineage=(LineageCommitment(
                kind="dataset",
                asset_id="cases",
                version="v1",
                manifest_sha256=_sha("cases"),
                required_action_if_revoked="retrain",
            ),),
            authority_sha256=_sha("run-authority"),
            study_admission=study_admission,
        )

    def target_preset(tenant, preset_id):
        assert tenant == "tenant-a"
        return PromotionTargetPreset(
            preset_id=preset_id,
            target=PromotionTarget(
                target_id="installed-lightwork",
                expected_active_sha256=_sha("previous"),
                state_schema="lightwork.state.v1",
                queued_intent_schema="lightwork.intents.v1",
                external_reconciliation_schema="lightwork.reconciliation.v1",
            ),
            resources=ResourceRequirements(1, 1, 1.0),
            authority_sha256=_sha("target-preset-authority"),
        )

    state = SimpleNamespace(
        candidate_promotion_artifact_resolver=lambda tenant, source: ArtifactObservation(
            tenant=tenant,
            source_ref=source,
            sha256=candidate_sha,
            size_bytes=9,
            authority_sha256=_sha("artifact-authority"),
        ),
        candidate_promotion_deployment_adapter=Adapter(),
        candidate_promotion_run_admission_resolver=run_admission,
        candidate_promotion_target_preset_resolver=target_preset,
        candidate_promotion_completed_runs_resolver=lambda *_args: ("run-one",),
        candidate_promotion_authority_resolver=lambda tenant, principal: PromotionAuthority(
            tenant=tenant,
            principal=principal,
            role="release_admin",
            actions=("review",),
            authorization_sha256=_sha("reviewer"),
            valid_until=4_102_444_800.0,
        ),
        candidate_promotion_policy_resolver=lambda: policy,
    )
    monkeypatch.setattr(composition, "_policy", lambda: policy)
    service = composition.build_candidate_promotions(state)
    result = service.request(
        "tenant-a",
        "user:researcher@example.test",
        candidate_id="candidate-one",
        run_id="run-one",
        target_preset="installed-lightwork",
    )
    assert result["state"] == "awaiting_review"
    assert result["candidate_principal"] == "research-worker:one"
    assert service.proposal_options(
        "tenant-a", "user:researcher@example.test"
    ) == {
        "completed_runs": ["run-one"],
        "target_presets": [
            {"preset_id": "installed-lightwork", "target_id": "installed-lightwork"}
        ],
    }
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def test_install_preserves_explicit_factory_and_adds_probe():
    sentinel = object()
    app = SimpleNamespace(state=SimpleNamespace(candidate_promotions_factory=sentinel))
    composition.install_candidate_promotion_composition(app)
    assert app.state.candidate_promotions_factory is sentinel
    assert callable(app.state.candidate_promotion_capability_probe)
    assert app.state.candidate_promotion_composition_installed is True
