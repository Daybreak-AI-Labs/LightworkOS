"""Focused tests for governed research assets and job-time revalidation."""

from __future__ import annotations

import hashlib

import pytest
from maverick import config, governed_records
from maverick.research_registry import (
    ConsentAuthority,
    DataUseAuthority,
    RegistryReviewAuthority,
    ResearchAssetRef,
    ResearchRegistry,
    ResearchRegistryDenied,
    ResearchRegistryNotFound,
)

TENANT = "tenant-a"
FUTURE = 4_102_444_800.0


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@pytest.fixture
def registry(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    config.reset_config_cache()
    governed_records._reset_process_authority_pin_for_testing()
    state = {"rights": True, "consent": True, "review_epoch": "v1"}

    def resolve_data_use(tenant, decision_id, expected_sha256):
        if not state["rights"]:
            raise ResearchRegistryDenied("rights revoked")
        if (tenant, decision_id, expected_sha256) != (
            TENANT,
            "decision-one",
            _sha("decision-one"),
        ):
            raise ResearchRegistryDenied("decision mismatch")
        return DataUseAuthority(
            tenant=tenant,
            decision_id=decision_id,
            decision_sha256=expected_sha256,
            asset_id="dataset-one",
            action="analyze",
            purpose_codes=("research_evaluation",),
            expires_at=FUTURE,
            authority_sha256=_sha("current-data-use-authority"),
        )

    def resolve_consent(tenant, record_id):
        return ConsentAuthority(
            tenant=tenant,
            record_id=record_id,
            evidence_sha256=_sha("consent"),
            allowed_purposes=("research_evaluation",),
            valid_until=FUTURE,
            revoked=not state["consent"],
        )

    service = ResearchRegistry(
        data_use_resolver=resolve_data_use,
        consent_resolver=resolve_consent,
        review_authority_resolver=lambda tenant, principal: RegistryReviewAuthority(
            tenant,
            principal,
            _sha(f"review-authority:{tenant}:{principal}:{state['review_epoch']}"),
        ),
    )
    yield service, state
    governed_records._reset_process_authority_pin_for_testing()
    config.reset_config_cache()


def _dataset(service: ResearchRegistry, *, with_consent: bool = False) -> ResearchAssetRef:
    reference = service.register_dataset(
        TENANT,
        "user:maker",
        dataset_id="dataset-one",
        version="v1",
        source_ref="https://catalog.example/datasets/one/v1",
        content_sha256=_sha("dataset bytes"),
        license_id="customer-research-license",
        license_evidence_sha256=_sha("license"),
        allowed_purposes=("research_evaluation",),
        usage_constraints=("tenant only", "no redistribution"),
        data_use_action="analyze",
        data_use_decision_id="decision-one",
        data_use_decision_sha256=_sha("decision-one"),
        consent_record_id="consent-one" if with_consent else None,
        consent_evidence_sha256=_sha("consent") if with_consent else None,
    )
    draft = service.inspect(TENANT, reference)
    return service.approve(
        TENANT,
        "user:reviewer",
        reference,
        expected_revision=draft["revision"],
    )


def test_dataset_version_requires_independent_approval_and_current_authority(registry):
    service, state = registry
    reference = service.register_dataset(
        TENANT,
        "user:maker",
        dataset_id="dataset-one",
        version="v1",
        source_ref="catalog:datasets/one/v1",
        content_sha256=_sha("dataset bytes"),
        license_id="customer-research-license",
        license_evidence_sha256=_sha("license"),
        allowed_purposes=("research_evaluation",),
        usage_constraints=("tenant only",),
        data_use_action="analyze",
        data_use_decision_id="decision-one",
        data_use_decision_sha256=_sha("decision-one"),
    )

    with pytest.raises(ResearchRegistryDenied, match="not currently approved"):
        service.resolve_dataset(TENANT, reference, purpose="research_evaluation")
    with pytest.raises(ResearchRegistryDenied, match="different named reviewer"):
        service.approve(
            TENANT,
            "user:maker",
            reference,
            expected_revision=1,
        )

    approved = service.approve(
        TENANT,
        "user:reviewer",
        reference,
        expected_revision=1,
    )
    admission = service.resolve_dataset(TENANT, approved, purpose="research_evaluation")
    assert admission.reference == approved
    assert admission.content_sha256 == _sha("dataset bytes")
    assert admission.data_use_authority.action == "analyze"
    assert (
        admission.approval_sha256
        == service.inspect(TENANT, approved)["approval"]["approval_sha256"]
    )
    with pytest.raises(ResearchRegistryDenied, match="requested action"):
        service.resolve_dataset(
            TENANT,
            approved,
            purpose="research_evaluation",
            action="train",
        )

    state["rights"] = False
    with pytest.raises(ResearchRegistryDenied, match="rights revoked"):
        service.resolve_dataset(TENANT, approved, purpose="research_evaluation")
    state["rights"] = True
    state["review_epoch"] = "v2"
    with pytest.raises(ResearchRegistryDenied, match="reviewer authority changed"):
        service.resolve_dataset(TENANT, approved, purpose="research_evaluation")


def test_dataset_registration_rejects_unavailable_rights_before_durable_ingestion(
    registry,
):
    service, state = registry
    state["rights"] = False

    with pytest.raises(ResearchRegistryDenied, match="rights revoked"):
        service.register_dataset(
            TENANT,
            "user:maker",
            dataset_id="dataset-one",
            version="v1",
            source_ref="catalog:datasets/one/v1",
            content_sha256=_sha("dataset bytes"),
            license_id="customer-research-license",
            license_evidence_sha256=_sha("license"),
            allowed_purposes=("research_evaluation",),
            usage_constraints=("tenant only",),
            data_use_action="analyze",
            data_use_decision_id="decision-one",
            data_use_decision_sha256=_sha("decision-one"),
        )

    assert service.list(TENANT) == []


def test_consent_reference_is_revalidated_and_forged_or_cross_tenant_refs_fail(registry):
    service, state = registry
    reference = _dataset(service, with_consent=True)
    assert (
        service.resolve_dataset(TENANT, reference, purpose="research_evaluation").consent_authority
        is not None
    )

    state["consent"] = False
    with pytest.raises(ResearchRegistryDenied, match="consent is revoked"):
        service.resolve_dataset(TENANT, reference, purpose="research_evaluation")
    forged = ResearchAssetRef(
        kind="dataset",
        asset_id=reference.asset_id,
        version=reference.version,
        manifest_sha256="f" * 64,
    )
    with pytest.raises(ResearchRegistryNotFound):
        service.resolve_dataset("tenant-b", reference, purpose="research_evaluation")
    with pytest.raises(Exception, match="stale or forged"):
        service.resolve_dataset(TENANT, forged, purpose="research_evaluation")


def test_unpinnable_model_records_identity_window_and_revocation_impact(registry):
    service, _state = registry
    dataset = _dataset(service)
    model = service.register_model(
        TENANT,
        "user:maker",
        model_id="candidate-weights",
        version="v1",
        source_ref="artifact:models/candidate-weights/v1",
        artifact_sha256=_sha("weights"),
        license_id="internal-research-license",
        license_evidence_sha256=_sha("model-license"),
        allowed_purposes=("research_evaluation",),
        usage_constraints=("tenant only", "no redistribution"),
        provider_model_identity="provider-returned-model-2026-09",
        immutable_provider_revision=None,
        observed_from=1_000.0,
        observed_until=2_000.0,
        reproducibility_limitation="Provider does not expose an immutable revision; replay is approximate.",
        dataset_lineage=(dataset,),
        dataset_lineage_purpose="research_evaluation",
    )
    model = service.approve(
        TENANT,
        "user:model-reviewer",
        model,
        expected_revision=1,
    )

    admission = service.resolve_model(TENANT, model, purpose="research_evaluation")
    assert admission.provider_model_identity == "provider-returned-model-2026-09"
    assert admission.immutable_provider_revision is None
    assert admission.observed_from == 1_000.0
    assert "approximate" in admission.reproducibility_limitation

    dataset_state = service.inspect(TENANT, dataset)
    service.revoke(
        TENANT,
        "user:privacy-reviewer",
        dataset,
        expected_revision=dataset_state["revision"],
        reason_code="consent_revoked",
        evidence_sha256=_sha("revocation"),
    )
    impact = service.derivative_impact(TENANT, dataset)
    assert impact["raw_deletion_removes_weight_influence"] is False
    assert impact["derivatives"] == [
        {
            "reference": {
                "kind": "model",
                "asset_id": "candidate-weights",
                "version": "v1",
                "manifest_sha256": model.manifest_sha256,
                "schema": "lightwork.research-registry-ref.v1",
            },
            "state": "approved",
            "required_action": "retire_or_retrain_model",
        }
    ]
    with pytest.raises(ResearchRegistryDenied, match="not currently approved"):
        service.resolve_model(TENANT, model, purpose="research_evaluation")


def test_mutable_provider_alias_cannot_be_mislabeled_as_pinned(registry):
    service, _state = registry
    with pytest.raises(ValueError, match="mutable provider revision"):
        service.register_model(
            TENANT,
            "user:maker",
            model_id="mutable-model",
            version="v1",
            source_ref="catalog:models/mutable/v1",
            artifact_sha256=_sha("weights"),
            license_id="internal-research-license",
            license_evidence_sha256=_sha("model-license"),
            allowed_purposes=("research_evaluation",),
            usage_constraints=("tenant only",),
            provider_model_identity="provider-model",
            immutable_provider_revision="latest",
        )


def test_synthetic_dataset_requires_explicit_reconstructable_provenance(registry):
    service, _state = registry
    common = {
        "dataset_id": "dataset-one",
        "version": "v1",
        "source_ref": "artifact:generators/fixture/v1",
        "content_sha256": _sha("synthetic rows"),
        "license_id": "synthetic-research-license",
        "license_evidence_sha256": _sha("synthetic-license"),
        "allowed_purposes": ("research_evaluation",),
        "usage_constraints": ("tenant only",),
        "data_use_action": "analyze",
        "data_use_decision_id": "decision-one",
        "data_use_decision_sha256": _sha("decision-one"),
        "provenance_kind": "synthetic",
    }
    with pytest.raises(ValueError, match="synthetic datasets require"):
        service.register_dataset(TENANT, "user:maker", **common)

    reference = service.register_dataset(
        TENANT,
        "user:maker",
        **common,
        synthetic_generator_id="fixture-generator",
        synthetic_generator_version="v1",
        synthetic_generator_sha256=_sha("fixture-generator"),
        synthetic_config_sha256=_sha("fixture-config"),
        synthetic_seed=73,
    )
    manifest = service.inspect(TENANT, reference)["manifest"]
    assert manifest["provenance_kind"] == "synthetic"
    assert manifest["synthetic_provenance"] == {
        "generator_id": "fixture-generator",
        "generator_version": "v1",
        "generator_sha256": _sha("fixture-generator"),
        "config_sha256": _sha("fixture-config"),
        "seed": 73,
    }


def test_research_job_rechecks_registry_rights_before_candidate_effect(registry):
    from maverick.research_jobs import (
        ResearchAuthority,
        ResearchDispatchAuthority,
        ResearchJobs,
        ResearchProfile,
        ResearchUnavailable,
    )

    service, state = registry
    dataset = _dataset(service)
    calls = {"runner": 0}
    profile = ResearchProfile.from_config(
        {
            "enable": True,
            "image_id": "sha256:" + "2" * 64,
            "evaluators": {"smoke": {"version": "v1", "stdout_sha256": _sha("answer\n")}},
        }
    )

    class Runner:
        def __init__(self, _image, *, limits):
            calls["runner"] += 1

    kwargs = {
        "authority_resolver": lambda tenant, principal: ResearchAuthority(
            tenant, principal, "1" * 64
        ),
        "dispatch_authority_resolver": lambda tenant, principal: ResearchDispatchAuthority(
            tenant, principal, "2" * 64
        ),
        "profile_resolver": lambda: profile,
        "runner_factory": Runner,
    }
    jobs = ResearchJobs(**kwargs, registry=service)
    row = jobs.submit(
        TENANT,
        "user:researcher",
        files={"main.py": "print('answer')"},
        evaluator_id="smoke",
        idempotency_key="registry-job",
        dataset_refs=(dataset,),
    )
    assert row["registry"]["datasets"][0]["reference"]["manifest_sha256"] == (
        dataset.manifest_sha256
    )
    review = jobs.review(TENANT, "user:admin", row["id"])

    state["rights"] = False
    result = jobs.run(
        TENANT,
        row["id"],
        expected_revision=row["revision"],
        dispatcher="user:admin",
        review_sha256=review["review_sha256"],
    )
    assert result["status"] == "review_required"
    assert calls["runner"] == 0

    no_registry = ResearchJobs(**kwargs)
    with pytest.raises(ResearchUnavailable, match="governed registry"):
        no_registry.submit(
            TENANT,
            "user:researcher",
            files={"main.py": "print('answer')"},
            evaluator_id="smoke",
            idempotency_key="missing-registry",
            dataset_refs=(dataset,),
        )
    with pytest.raises(ValueError, match="invalid dataset registry reference"):
        jobs.submit(
            TENANT,
            "user:researcher",
            files={"main.py": "print('answer')"},
            evaluator_id="smoke",
            idempotency_key="raw-metadata",
            dataset_refs=({"dataset_id": "dataset-one", "license": "claimed"},),
        )


def test_source_only_research_jobs_remain_compatible_without_registry(registry):
    from maverick.research_jobs import (
        ResearchAuthority,
        ResearchDispatchAuthority,
        ResearchJobs,
        ResearchProfile,
    )

    profile = ResearchProfile.from_config(
        {
            "enable": True,
            "image_id": "sha256:" + "3" * 64,
            "evaluators": {"smoke": {"version": "v1", "stdout_sha256": _sha("answer\n")}},
        }
    )
    jobs = ResearchJobs(
        authority_resolver=lambda tenant, principal: ResearchAuthority(tenant, principal, "4" * 64),
        dispatch_authority_resolver=lambda tenant, principal: ResearchDispatchAuthority(
            tenant, principal, "5" * 64
        ),
        profile_resolver=lambda: profile,
    )
    row = jobs.submit(
        TENANT,
        "user:researcher",
        files={"main.py": "print('answer')"},
        evaluator_id="smoke",
        idempotency_key="source-only",
    )
    assert row["status"] == "queued"
    assert row["registry"]["datasets"] == []
    assert row["registry"]["model"] is None


def test_default_adapter_revalidates_real_data_use_decision(tmp_path, monkeypatch):
    from maverick import data_use_governance as dug
    from maverick import data_use_policy_compiler as compiler_module
    from maverick.data_use_policy_compiler import DataUsePolicyCompiler
    from maverick.research_registry import resolve_data_use_authority

    from tests.test_data_use_governance import (
        Clock,
        _authorize,
        _policy,
        _ready,
        _request,
    )

    store = dug.DataUseGovernanceStore(tmp_path / "dug.sqlite", clock=Clock())
    _ready(store)
    _policy(store, "research-allow", "allow", control_id="allow-research")
    _request(store, "research-request")
    decision = _authorize(store, "research-request")
    assert decision["outcome"] == "allow"
    monkeypatch.setattr(dug, "DataUseGovernanceStore", lambda _path: store)
    monkeypatch.setattr(
        compiler_module,
        "DataUsePolicyCompiler",
        lambda authority: DataUsePolicyCompiler(authority, clock=lambda: 1_000.0),
    )

    result = resolve_data_use_authority(
        "tenant-alpha",
        decision["decision_id"],
        decision["decision_sha256"],
    )

    assert result.tenant == "tenant-alpha"
    assert result.asset_id == "customers"
    assert result.action == "read"
    assert result.purpose_codes == ("analytics",)
    assert result.decision_sha256 == decision["decision_sha256"]


def test_registry_list_is_bounded_exact_and_tenant_scoped(registry):
    service, _ = registry
    reference = service.register_dataset(
        TENANT,
        "user:maker",
        dataset_id="dataset-one",
        version="v1",
        source_ref="artifact:datasets/one/v1",
        content_sha256=_sha("dataset bytes"),
        license_id="customer-research-license",
        license_evidence_sha256=_sha("license"),
        allowed_purposes=("research_evaluation",),
        usage_constraints=("tenant only",),
        data_use_action="analyze",
        data_use_decision_id="decision-one",
        data_use_decision_sha256=_sha("decision-one"),
    )
    rows = service.list(TENANT, kind="dataset", limit=1)
    assert len(rows) == 1
    assert rows[0]["reference"] == {
        "kind": "dataset",
        "asset_id": "dataset-one",
        "version": "v1",
        "manifest_sha256": reference.manifest_sha256,
        "schema": "lightwork.research-registry-ref.v1",
    }
    assert rows[0]["registered_by"] == "user:maker"
    assert service.list("tenant-b", kind="dataset") == []
    assert service.list(TENANT, kind="model") == []
    with pytest.raises(ValueError, match="between 1 and 250"):
        service.list(TENANT, limit=251)
