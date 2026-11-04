"""Governed core for the Model Risk & AI Assurance Officer."""
from __future__ import annotations

import copy
import hashlib
import json
import time

import pytest
from maverick import evidence_graph
from maverick import model_risk_assurance as mra
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _training_commitment(artifact_digest: str, *, label: str = "one") -> dict[str, str]:
    return {
        "schema": "lightwork.training-transparency-commitment.v1",
        "dataset_sha256": _hex(f"training-dataset:{label}"),
        "environment_sha256": _hex(f"training-environment:{label}"),
        "base_model_artifact_sha256": _hex(f"base-model:{label}"),
        "adapter_sha256": artifact_digest,
        "approval_subject_sha256": _hex(f"approval-subject:{label}"),
        "receipt_payload_sha256": _hex(f"receipt-payload:{label}"),
        "event_hash": _hex(f"receipt-event:{label}"),
        "key_id": _hex(f"receipt-key:{label}")[:16],
    }


def _training_assurance_commitment(
    artifact_digest: str,
    *,
    label: str = "one",
) -> dict[str, str]:
    return {
        "schema": "lightwork.training-assurance-commitment.v1",
        "dataset_sha256": _hex(f"training-dataset:{label}"),
        "base_model_license_id": "Apache-2.0",
        "base_model_license_evidence_sha256": _hex(f"license:{label}"),
        "evaluation_run_sha256": _hex(f"evaluation-run:{label}"),
        "sealed_holdout_sha256": _hex(f"sealed-holdout:{label}"),
        "qualification_evidence_sha256": _hex(f"qualification:{label}"),
        "qualification_policy_sha256": _hex(f"qualification-policy:{label}"),
        "adapter_sha256": artifact_digest,
        "receipt_payload_sha256": _hex(f"receipt-payload:{label}"),
    }


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    _write_config(tmp_path)
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _write_config(tmp_path, *, enabled: str = "true", gate: str = "true", graph: str = "true"):
    (tmp_path / "config.toml").write_text(
        "[evidence_graph]\n"
        f"enable = {graph}\n"
        "\n[model_risk_assurance]\n"
        f"enable = {enabled}\n"
        f"gate_promotions = {gate}\n",
        encoding="utf-8",
    )


def _observe(
    officer: mra.ModelRiskAssuranceOfficer,
    label: str,
    *,
    asset_type: str = "model",
    digest: str | None = None,
    expected_revision: int = 0,
):
    return officer.observe_asset(
        asset_type=asset_type,
        source="test_registry",
        source_id=label,
        display_name=label.replace("-", " ").title(),
        version_digest=digest or _hex(f"{label}-v1"),
        actor="inventory-operator",
        expected_revision=expected_revision,
        observed_at=time.time(),
        metadata={"environment": "test", "version": 1},
        dependencies=[],
    )


def _declare(
    officer: mra.ModelRiskAssuranceOfficer,
    observation: dict,
    *,
    third_party: bool = False,
    safety_critical: bool = False,
):
    proposed = officer.declare_asset(
        observation["asset_id"],
        owner="AI Risk Committee",
        purpose="Governed decision-support service.",
        intended_use="Assist trained operators; never make an irreversible decision alone.",
        risk_tier="high" if safety_critical else "medium",
        risk_context={
            "human_oversight": True,
            "safety_critical": safety_critical,
            "third_party": third_party,
            "high_risk_domains": ["critical_infrastructure"] if safety_critical else [],
            "transparency_signals": ["human_interaction"],
        },
        eu_ai_act={
            "category": "not_applicable",
            "asserted_by": "qualified-reviewer",
            "asserted_at": time.time(),
            "as_of": "2026-07-21",
            "source_ref": mra.EU_AI_ACT_METADATA["source"],
            "rationale": "The reviewed deployment context is outside the asserted scope.",
        },
        actor="model-owner",
    )
    return officer.review_declaration(
        observation["asset_id"],
        decision="approved",
        rationale="Owner, use, controls, and dated applicability assertion reviewed.",
        reviewer="independent-risk-reviewer",
        expected_revision=proposed["revision"],
    )


def _approved_evidence(
    officer: mra.ModelRiskAssuranceOfficer,
    observation: dict,
    evaluator: dict,
    kind: str,
    *,
    label: str | None = None,
    result: str = "passed",
    lifetime: float = 3600,
    scope_digest: str | None = None,
):
    now = time.time()
    row = officer.record_evidence(
        observation["asset_id"],
        source_id=label or f"{kind}-run-1",
        evidence_kind=kind,
        result=result,
        scope_digest=scope_digest or _hex(f"scope:{kind}:{label or 'one'}"),
        artifact_digest=observation["version_digest"],
        evaluator_digest=evaluator["version_digest"],
        evaluator_asset_id=evaluator["asset_id"],
        summary=f"Bounded {kind} result for the exact artifact and evaluator.",
        metrics={
            "cases": 42,
            "pass_rate": 1.0 if result == "passed" else 0.0,
        },
        observed_at=now,
        valid_until=now + lifetime,
        actor="evaluation-runner",
    )
    return officer.review_evidence(
        row["id"],
        decision="approved",
        rationale="Receipt, scope, evaluator, and artifact bindings reviewed.",
        reviewer="assurance-reviewer",
        expected_revision=row["revision"],
    )


def _approved_training_evidence(
    officer: mra.ModelRiskAssuranceOfficer,
    observation: dict,
    *,
    lifetime: float = 3600,
    label: str = "one",
):
    now = time.time()
    commitment = _training_commitment(
        observation["version_digest"],
        label=label,
    )
    assurance = _training_assurance_commitment(
        observation["version_digest"],
        label=label,
    )
    row = officer._record_evidence(  # noqa: SLF001 - verified-boundary fixture
        observation["asset_id"],
        source_id=f"training_receipt:{commitment['receipt_payload_sha256']}",
        evidence_kind="training_run",
        result="passed",
        scope_digest=mra._training_evidence_scope(  # noqa: SLF001
            commitment,
            assurance,
        ),
        artifact_digest=observation["version_digest"],
        evaluator_digest=None,
        summary="Verified tenant-private training receipt commitment.",
        metrics={
            "training_receipt_commitment": commitment,
            "training_assurance_commitment": assurance,
        },
        observed_at=now,
        valid_until=now + lifetime,
        actor="training-receipt-verifier",
        verified_training_commitment=commitment,
        verified_training_assurance=assurance,
    )
    return officer.review_evidence(
        row["id"],
        decision="approved",
        rationale="Receipt commitment and exact adapter binding reviewed.",
        reviewer="assurance-reviewer",
        expected_revision=row["revision"],
    )


def _promotion_fixture(
    officer: mra.ModelRiskAssuranceOfficer,
    *,
    training_lifetime: float = 3600,
    data_scope_matches: bool = True,
):
    artifact = _observe(officer, "candidate-model")
    evaluator = _observe(officer, "frozen-evaluator", asset_type="tool")
    declaration = _declare(officer, artifact)
    evaluation = _approved_evidence(officer, artifact, evaluator, "evaluation")
    red_team = _approved_evidence(officer, artifact, evaluator, "red_team")
    training_run = _approved_training_evidence(
        officer,
        artifact,
        lifetime=training_lifetime,
    )
    data_assessment = _approved_evidence(
        officer,
        artifact,
        evaluator,
        "data_assessment",
        scope_digest=(
            training_run["metrics"]["training_receipt_commitment"][
                "dataset_sha256"
            ]
            if data_scope_matches
            else _hex("different-training-dataset")
        ),
    )
    payload = _hex("candidate-payload")
    authorization = officer.authorize_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
        asset_id=artifact["asset_id"],
        artifact_revision=artifact["revision"],
        artifact_digest=artifact["version_digest"],
        declaration_revision=declaration["revision"],
        evaluator_asset_id=evaluator["asset_id"],
        evaluator_revision=evaluator["revision"],
        evaluator_digest=evaluator["version_digest"],
        evidence_ids=[
            evaluation["id"],
            red_team["id"],
            training_run["id"],
            data_assessment["id"],
        ],
        reviewer="change-advisory-board",
        rationale="Exact candidate, evaluator, and current assurance receipts reviewed.",
        expires_at=time.time() + 1800,
    )
    return artifact, evaluator, declaration, evaluation, red_team, payload, authorization


def test_inventory_is_deterministic_explainable_and_covers_all_asset_types():
    officer = mra.ModelRiskAssuranceOfficer()
    rows = [
        _observe(officer, f"asset-{kind}", asset_type=kind)
        for kind in ("model", "agent", "tool", "dataset", "provider")
    ]
    assert {row["identity"]["asset_type"] for row in rows} == {
        "model", "agent", "tool", "dataset", "provider",
    }
    first = rows[0]
    assert first["asset_id"] == mra.stable_asset_id(
        "model", "test_registry", "asset-model",
    )
    assert first["snapshot_sha256"]
    assert first["evidence_node_id"].startswith("EGN-")
    assert [row["asset_id"] for row in officer.list_inventory()] == sorted(
        row["asset_id"] for row in rows
    )


def test_default_authority_clock_comes_from_the_governed_decision_store(monkeypatch):
    officer = mra.ModelRiskAssuranceOfficer()
    monkeypatch.setattr(
        officer._decisions,
        "authoritative_time",
        lambda: 1_900_000_000.0,
    )

    assert officer._now() == 1_900_000_000.0


def test_integrated_inventory_refuses_an_unbounded_namespace():
    class TooManyObservations:
        def list(self, *, limit=None):
            assert limit == 5_001
            return [{"asset_id": f"asset-{index}"} for index in range(limit)]

    officer = mra.ModelRiskAssuranceOfficer(observations=TooManyObservations())
    with pytest.raises(mra.ModelRiskStateError, match="5000-record operational limit"):
        officer.list_inventory()


def test_profile_is_mapping_not_automatic_legal_classification_or_certification():
    profile = mra.assurance_profile({
        "prohibited_signals": ["social_scoring"],
        "high_risk_domains": ["employment"],
        "transparency_signals": ["human_interaction"],
        "human_oversight": False,
    })
    assert profile["screening_level"] == "critical"
    eu = profile["framework_mappings"]["eu_ai_act"]
    assert eu["asserted_category"] == "undetermined"
    assert eu["applicability"] == "human_review_required"
    assert profile["legal_certification"] is False
    assert profile["compliance_verdict"] == "not_provided"
    assert profile["framework_mappings"]["nist_ai_rmf"]["version"] == "1.0"
    assert profile["framework_mappings"]["nist_ai_rmf"]["version_status"] == "under_revision"
    assert profile["framework_mappings"]["iso_iec_42001"]["standard"] == "ISO/IEC 42001:2023"

    officer = mra.ModelRiskAssuranceOfficer()
    observation = _observe(officer, "unclassified")
    declaration = officer.declare_asset(
        observation["asset_id"],
        owner="owner",
        purpose="Decision support",
        intended_use="Human-reviewed analysis",
        actor="owner",
    )
    with pytest.raises(ValueError, match="dated human EU AI Act assertion"):
        officer.review_declaration(
            observation["asset_id"],
            decision="approved",
            rationale="Do not let a generated screen approve itself.",
            reviewer="reviewer",
            expected_revision=declaration["revision"],
        )


def test_stale_observation_cas_cannot_mutate_evidence_graph():
    officer = mra.ModelRiskAssuranceOfficer()
    current = _observe(officer, "race-target")
    before = {row["id"] for row in evidence_graph.list_nodes()}
    rejected_digest = _hex("rejected-stale-writer")
    with pytest.raises(RecordConflict, match="observation changed"):
        _observe(
            officer,
            "race-target",
            digest=rejected_digest,
            expected_revision=0,
        )
    after = {row["id"] for row in evidence_graph.list_nodes()}
    assert after == before
    assert officer.get_observation(current["asset_id"])["version_digest"] == current["version_digest"]


def test_identical_observation_retry_is_idempotent_and_keeps_approval_authority():
    officer = mra.ModelRiskAssuranceOfficer()
    current = _observe(officer, "idempotent-target")
    before_nodes = {row["id"] for row in evidence_graph.list_nodes()}
    retried = _observe(
        officer,
        "idempotent-target",
        digest=current["version_digest"],
        expected_revision=current["revision"],
    )
    assert retried["revision"] == current["revision"]
    assert {row["id"] for row in evidence_graph.list_nodes()} == before_nodes


def test_disabled_evidence_graph_fails_before_authority_write(tmp_path):
    from maverick import config

    _write_config(tmp_path, graph="false")
    config.reset_config_cache()
    officer = mra.ModelRiskAssuranceOfficer()
    with pytest.raises(mra.ModelRiskConfigError, match="requires .*evidence_graph"):
        _observe(officer, "must-not-persist")
    assert officer.list_inventory() == []
    assert evidence_graph.list_nodes() == []


def test_declarations_and_observations_use_explicit_cas_and_stale_authority_findings():
    officer = mra.ModelRiskAssuranceOfficer()
    observation = _observe(officer, "changing-model")
    approved = _declare(officer, observation)
    with pytest.raises(RecordConflict):
        officer.update_declaration(
            observation["asset_id"],
            expected_revision=1,
            actor="stale-editor",
            purpose="Stale overwrite",
        )
    updated_observation = _observe(
        officer,
        "changing-model",
        digest=_hex("changing-model-v2"),
        expected_revision=observation["revision"],
    )
    assert updated_observation["revision"] == observation["revision"] + 1
    assert approved["revision"] == officer.get_declaration(observation["asset_id"])["revision"]
    kinds = {
        row["finding_type"]
        for row in officer.findings()
        if row["asset_id"] == observation["asset_id"]
    }
    assert "stale_declaration_authority" in kinds


def test_evidence_is_bounded_review_gated_expiring_and_citation_bound():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, "evidence-model")
    evaluator = _observe(officer, "evidence-evaluator", asset_type="tool")
    now = time.time()
    with pytest.raises(ValueError, match="after observed_at"):
        officer.record_evidence(
            artifact["asset_id"],
            source_id="bad-expiry",
            evidence_kind="evaluation",
            result="passed",
            scope_digest=_hex("scope"),
            artifact_digest=artifact["version_digest"],
            evaluator_digest=evaluator["version_digest"],
            evaluator_asset_id=evaluator["asset_id"],
            observed_at=now,
            valid_until=now,
            actor="runner",
        )
    with pytest.raises(ValueError, match="sensitive key"):
        officer.record_evidence(
            artifact["asset_id"],
            source_id="bad-metrics",
            evidence_kind="evaluation",
            result="passed",
            scope_digest=_hex("scope"),
            artifact_digest=artifact["version_digest"],
            evaluator_digest=evaluator["version_digest"],
            evaluator_asset_id=evaluator["asset_id"],
            metrics={"api_token": "not-permitted"},
            observed_at=now,
            valid_until=now + 60,
            actor="runner",
        )
    evidence = officer.record_evidence(
        artifact["asset_id"],
        source_id="expiring-eval",
        evidence_kind="evaluation",
        result="passed",
        scope_digest=_hex("scope"),
        artifact_digest=artifact["version_digest"],
        evaluator_digest=evaluator["version_digest"],
        evaluator_asset_id=evaluator["asset_id"],
        observed_at=now,
        valid_until=now + 10,
        actor="runner",
    )
    assert evidence["status"] == "pending_review"
    reviewed = officer.review_evidence(
        evidence["id"],
        decision="approved",
        rationale="Exact receipt reviewed.",
        reviewer="human",
        expected_revision=evidence["revision"],
    )
    assert officer.get_evidence(reviewed["id"], now=now + 1)["freshness"] == "current"
    assert officer.get_evidence(reviewed["id"], now=now + 11)["freshness"] == "stale"
    node = evidence_graph.get(reviewed["evidence_node_id"])
    assert node["attributes"]["evidence_payload_sha256"] == reviewed["payload_sha256"]


def test_verified_training_receipt_registers_only_commitment_and_needs_review(
    monkeypatch,
):
    from maverick.training import receipts as training_receipts

    officer = mra.ModelRiskAssuranceOfficer()
    raw_private_receipt = {
        "receipt_id": "tenant-private-receipt-1",
        "public_key": "self-disclosed-key-must-not-be-trusted",
        "private_training_content": "DO-NOT-PERSIST",
    }
    receipt_trust = {"0123456789abcdef": "external-receipt-trust"}
    approver_trust = {"fedcba9876543210": "external-approver-trust"}
    calls = {}

    def _read(receipt_id, **kwargs):
        assert receipt_id == "tenant-private-receipt-1"
        calls["read"] = kwargs
        return raw_private_receipt

    def _verify(receipt, **kwargs):
        assert receipt is raw_private_receipt
        calls.update(kwargs)
        return _training_commitment(_hex("tenant-adapter"))

    def _assure(receipt, **kwargs):
        assert receipt is raw_private_receipt
        calls.update(kwargs)
        return _training_assurance_commitment(_hex("tenant-adapter"))

    monkeypatch.setattr(
        training_receipts,
        "read_verified_training_receipt",
        _read,
    )
    monkeypatch.setattr(
        training_receipts,
        "public_transparency_commitment",
        _verify,
    )
    monkeypatch.setattr(
        training_receipts,
        "model_risk_assurance_commitment",
        _assure,
    )
    monkeypatch.setattr(
        training_receipts,
        "server_training_trust_registries",
        lambda: (receipt_trust, approver_trust),
    )

    with tenant_scope(tenant="alpha"):
        artifact = _observe(
            officer,
            "tenant-trained-adapter",
            digest=_hex("tenant-adapter"),
        )
        row = officer.record_verified_training_receipt_evidence(
            artifact["asset_id"],
            receipt_id="tenant-private-receipt-1",
            actor="training-receipt-verifier",
            valid_until=time.time() + 600,
        )

        assert row["evidence_kind"] == "training_run"
        assert row["status"] == "pending_review"
        assert row["result"] == "passed"
        assert set(row["metrics"]) == {
            "training_receipt_commitment",
            "training_assurance_commitment",
        }
        assert (
            row["metrics"]["training_assurance_commitment"][
                "base_model_license_id"
            ]
            == "Apache-2.0"
        )
        serialized = json.dumps(row)
        assert "DO-NOT-PERSIST" not in serialized
        assert "self-disclosed-key" not in serialized
        assert "tenant-private-receipt-1" not in serialized
        assert calls == {
            "read": {
                "trusted_receipt_pubkeys": receipt_trust,
                "trusted_approver_pubkeys": approver_trust,
                "expected_tenant_id": "alpha",
            },
            "trusted_receipt_pubkeys": receipt_trust,
            "trusted_approver_pubkeys": approver_trust,
            "expected_tenant_id": "alpha",
        }

        now = time.time()
        with pytest.raises(ValueError, match="verified tenant-private receipt"):
            officer.record_evidence(
                artifact["asset_id"],
                source_id="caller-asserted-training-run",
                evidence_kind="training_run",
                result="passed",
                scope_digest=_hex("caller-scope"),
                artifact_digest=artifact["version_digest"],
                metrics={"training_receipt_commitment": row["metrics"]},
                observed_at=now,
                valid_until=now + 60,
                actor="untrusted-caller",
            )

        approved = officer.review_evidence(
            row["id"],
            decision="approved",
            rationale="External trust and exact receipt commitment reviewed.",
            reviewer="model-risk-reviewer",
            expected_revision=row["revision"],
        )
        assert approved["status"] == "approved"


def test_unverified_or_artifact_mismatched_training_receipt_is_not_registered(
    monkeypatch,
):
    from maverick.training import receipts as training_receipts

    officer = mra.ModelRiskAssuranceOfficer()
    with tenant_scope(tenant="alpha"):
        artifact = _observe(
            officer,
            "mismatched-training-adapter",
            digest=_hex("expected-adapter"),
        )
        monkeypatch.setattr(
            training_receipts,
            "read_verified_training_receipt",
            lambda _receipt_id, **_kwargs: (_ for _ in ()).throw(
                ValueError("unverified"),
            ),
        )
        monkeypatch.setattr(
            training_receipts,
            "server_training_trust_registries",
            lambda: ({}, {}),
        )
        with pytest.raises(mra.ModelRiskStateError, match="could not be verified"):
            officer.record_verified_training_receipt_evidence(
                artifact["asset_id"],
                receipt_id="unverified-receipt",
                actor="training-receipt-verifier",
                valid_until=time.time() + 600,
            )
        assert officer.list_evidence() == []

        monkeypatch.setattr(
            training_receipts,
            "read_verified_training_receipt",
            lambda _receipt_id, **_kwargs: {"public_key": "self-disclosed"},
        )
        monkeypatch.setattr(
            training_receipts,
            "public_transparency_commitment",
            lambda *_args, **_kwargs: _training_commitment(
                _hex("different-adapter"),
            ),
        )
        monkeypatch.setattr(
            training_receipts,
            "model_risk_assurance_commitment",
            lambda *_args, **_kwargs: _training_assurance_commitment(
                _hex("different-adapter"),
            ),
        )
        monkeypatch.setattr(
            training_receipts,
            "server_training_trust_registries",
            lambda: (
                {"0123456789abcdef": "external"},
                {"fedcba9876543210": "external"},
            ),
        )
        with pytest.raises(mra.ModelRiskStateError, match="different artifact bytes"):
            officer.record_verified_training_receipt_evidence(
                artifact["asset_id"],
                receipt_id="mismatched-receipt",
                actor="training-receipt-verifier",
                valid_until=time.time() + 600,
            )
        assert officer.list_evidence() == []


def test_promotion_gate_binds_exact_candidate_artifact_evaluator_and_evidence():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact, evaluator, _, _, _, payload, authorization = _promotion_fixture(officer)
    assert authorization["binding_sha256"]
    assert officer.verify_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
    ) == (True, "exact model-risk authority is current and approved")
    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=_hex("swapped-payload"),
    )
    assert allowed is False
    assert "differs from human approval" in reason

    _observe(
        officer,
        "frozen-evaluator",
        asset_type="tool",
        digest=_hex("frozen-evaluator-v2"),
        expected_revision=evaluator["revision"],
    )
    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
    )
    assert allowed is False
    assert "evaluator observation authority is stale" in reason
    assert officer.get_observation(artifact["asset_id"])["version_digest"] == artifact["version_digest"]


@pytest.mark.parametrize(
    "missing_kind",
    ["training_run", "data_assessment", "evaluation", "red_team"],
)
def test_weights_gate_requires_complete_exact_evidence_set(missing_kind):
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, f"missing-{missing_kind}-model")
    evaluator = _observe(
        officer,
        f"missing-{missing_kind}-evaluator",
        asset_type="tool",
    )
    declaration = _declare(officer, artifact)
    evidence = {
        "training_run": _approved_training_evidence(
            officer,
            artifact,
            label=missing_kind,
        ),
        "data_assessment": _approved_evidence(
            officer,
            artifact,
            evaluator,
            "data_assessment",
            label=f"data-{missing_kind}",
        ),
        "evaluation": _approved_evidence(
            officer,
            artifact,
            evaluator,
            "evaluation",
            label=f"evaluation-{missing_kind}",
        ),
        "red_team": _approved_evidence(
            officer,
            artifact,
            evaluator,
            "red_team",
            label=f"red-team-{missing_kind}",
        ),
    }
    payload = _hex(f"candidate-missing-{missing_kind}")
    officer.authorize_promotion_candidate(
        candidate_id=f"candidate-missing-{missing_kind}",
        rung="weights",
        payload_sha256=payload,
        asset_id=artifact["asset_id"],
        artifact_revision=artifact["revision"],
        artifact_digest=artifact["version_digest"],
        declaration_revision=declaration["revision"],
        evaluator_asset_id=evaluator["asset_id"],
        evaluator_revision=evaluator["revision"],
        evaluator_digest=evaluator["version_digest"],
        evidence_ids=[
            row["id"] for kind, row in evidence.items() if kind != missing_kind
        ],
        reviewer="change-advisory-board",
        rationale="Exercise one missing evidence class at a time.",
        expires_at=time.time() + 600,
    )

    allowed, reason = officer.verify_promotion_candidate(
        candidate_id=f"candidate-missing-{missing_kind}",
        rung="weights",
        payload_sha256=payload,
    )
    assert allowed is False
    assert missing_kind in reason


def test_enabled_gate_preserves_non_weights_evidence_requirements(monkeypatch):
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, "non-weights-model")
    evaluator = _observe(officer, "non-weights-evaluator", asset_type="tool")
    declaration = _declare(officer, artifact)
    evaluation = _approved_evidence(officer, artifact, evaluator, "evaluation")
    red_team = _approved_evidence(officer, artifact, evaluator, "red_team")
    payload = _hex("non-weights-candidate")
    officer.authorize_promotion_candidate(
        candidate_id="non-weights-candidate",
        rung="config",
        payload_sha256=payload,
        asset_id=artifact["asset_id"],
        artifact_revision=artifact["revision"],
        artifact_digest=artifact["version_digest"],
        declaration_revision=declaration["revision"],
        evaluator_asset_id=evaluator["asset_id"],
        evaluator_revision=evaluator["revision"],
        evaluator_digest=evaluator["version_digest"],
        evidence_ids=[evaluation["id"], red_team["id"]],
        reviewer="change-advisory-board",
        rationale="The existing non-weights assurance set remains sufficient.",
        expires_at=time.time() + 600,
    )
    monkeypatch.setattr(mra, "_DEFAULT", officer)

    assert mra.promotion_gate_enabled() is True
    assert mra.verify_promotion_candidate(
        candidate_id="non-weights-candidate",
        rung="config",
        payload_sha256=payload,
    ) == (True, "exact model-risk authority is current and approved")


def test_promotion_rejects_legacy_red_team_approval_without_producer_binding():
    from maverick import evidence_graph

    officer = mra.ModelRiskAssuranceOfficer()
    (
        artifact,
        evaluator,
        declaration,
        evaluation,
        red_team,
        _payload,
        _authorization,
    ) = _promotion_fixture(officer)
    evidence_store = officer._evidence  # noqa: SLF001 - legacy-record fixture

    def remove_producer(row):
        row.pop("producer_actor", None)

    legacy = evidence_store.update(
        red_team["id"],
        remove_producer,
        expected_revision=red_team["revision"],
        action="simulate_legacy_red_team_record",
        actor="migration-test",
    )
    assert legacy is not None
    with pytest.raises(ValueError, match="source_review_separation_invalid"):
        evidence_graph.project_model_risk_evidence(
            legacy["id"],
            actor="migration-test",
        )
    payload = _hex("legacy-red-team-candidate")
    officer.authorize_promotion_candidate(
        candidate_id="legacy-red-team-candidate",
        rung="config",
        payload_sha256=payload,
        asset_id=artifact["asset_id"],
        artifact_revision=artifact["revision"],
        artifact_digest=artifact["version_digest"],
        declaration_revision=declaration["revision"],
        evaluator_asset_id=evaluator["asset_id"],
        evaluator_revision=evaluator["revision"],
        evaluator_digest=evaluator["version_digest"],
        evidence_ids=[evaluation["id"], legacy["id"]],
        reviewer="change-advisory-board",
        rationale="Legacy record must fail closed during authority verification.",
        expires_at=time.time() + 600,
    )

    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="legacy-red-team-candidate",
        rung="config",
        payload_sha256=payload,
    )
    assert allowed is False
    assert reason == "red-team evidence lacks independent producer review"
    assert any(
        row["finding_type"] == "red_team_evidence_missing"
        for row in officer.findings()
        if row["asset_id"] == artifact["asset_id"]
    )


def test_weights_gate_rejects_data_assessment_for_other_training_data():
    officer = mra.ModelRiskAssuranceOfficer()
    _, _, _, _, _, payload, _ = _promotion_fixture(
        officer,
        data_scope_matches=False,
    )

    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
    )
    assert allowed is False
    assert reason == "data-assessment evidence covers different training data"


def test_stale_or_revoked_training_run_evidence_fails_weights_gate_closed():
    with tenant_scope(tenant="stale-training"):
        stale_officer = mra.ModelRiskAssuranceOfficer()
        _, _, _, _, _, payload, _ = _promotion_fixture(
            stale_officer,
            training_lifetime=30,
        )
        stale_training = next(
            row for row in stale_officer.list_evidence()
            if row["evidence_kind"] == "training_run"
        )
        stale_officer._clock = (  # noqa: SLF001 - authority-clock expiry regression
            lambda: float(stale_training["valid_until"]) + 1
        )
        allowed, reason = stale_officer.verify_promotion_candidate(
            candidate_id="candidate-001",
            rung="weights",
            payload_sha256=payload,
        )
        assert allowed is False
        assert "evidence expired" in reason

    with tenant_scope(tenant="revoked-training"):
        revoked_officer = mra.ModelRiskAssuranceOfficer()
        _, _, _, _, _, payload, _ = _promotion_fixture(revoked_officer)
        training = next(
            row for row in revoked_officer.list_evidence()
            if row["evidence_kind"] == "training_run"
        )
        revoked_officer.review_evidence(
            training["id"],
            decision="revoked",
            rationale="The trusted receipt authority revoked this training run.",
            reviewer="assurance-reviewer",
            expected_revision=training["revision"],
        )
        allowed, reason = revoked_officer.verify_promotion_candidate(
            candidate_id="candidate-001",
            rung="weights",
            payload_sha256=payload,
        )
        assert allowed is False
        assert "evidence authority is stale" in reason


def test_promotion_expiry_uses_authority_clock_not_caller_clock():
    officer = mra.ModelRiskAssuranceOfficer()
    _, _, _, _, _, payload, authorization = _promotion_fixture(officer)
    authority_now = float(authorization["expires_at"]) + 1.0
    officer._clock = lambda: authority_now  # noqa: SLF001 - controlled authority-clock test

    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
        now=float(authorization["expires_at"]) - 1.0,
    )

    assert allowed is False
    assert "expired" in reason


def test_promotion_accepts_distinct_current_per_evidence_evaluators():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, "evaluator-binding-model")
    evaluator = _observe(officer, "approved-evaluator", asset_type="tool")
    other_evaluator = _observe(officer, "other-evaluator", asset_type="tool")
    declaration = _declare(officer, artifact)
    wrong_evaluation = _approved_evidence(
        officer, artifact, other_evaluator, "evaluation",
    )
    red_team = _approved_evidence(officer, artifact, evaluator, "red_team")
    payload = _hex("evaluator-binding-candidate")
    officer.authorize_promotion_candidate(
        candidate_id="candidate-evaluator-binding",
        rung="config",
        payload_sha256=payload,
        asset_id=artifact["asset_id"],
        artifact_revision=artifact["revision"],
        artifact_digest=artifact["version_digest"],
        declaration_revision=declaration["revision"],
        evaluator_asset_id=evaluator["asset_id"],
        evaluator_revision=evaluator["revision"],
        evaluator_digest=evaluator["version_digest"],
        evidence_ids=[wrong_evaluation["id"], red_team["id"]],
        reviewer="change-advisory-board",
        rationale="Each evidence kind has its own exact current evaluator binding.",
        expires_at=time.time() + 600,
    )
    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-evaluator-binding",
        rung="config",
        payload_sha256=payload,
    )
    assert allowed is True
    assert reason == "exact model-risk authority is current and approved"


def test_findings_reject_evidence_from_a_rotated_evaluator():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, "finding-evaluator-model")
    evaluator = _observe(officer, "finding-evaluator", asset_type="tool")
    _declare(officer, artifact)
    _approved_evidence(officer, artifact, evaluator, "evaluation")
    _approved_evidence(officer, artifact, evaluator, "red_team")
    before = {
        row["finding_type"]
        for row in officer.findings()
        if row["asset_id"] == artifact["asset_id"]
    }
    assert "evaluation_evidence_missing" not in before
    assert "red_team_evidence_missing" not in before

    _observe(
        officer,
        "finding-evaluator",
        asset_type="tool",
        digest=_hex("finding-evaluator:v2"),
        expected_revision=evaluator["revision"],
    )
    after = {
        row["finding_type"]
        for row in officer.findings()
        if row["asset_id"] == artifact["asset_id"]
    }
    assert "evaluation_evidence_missing" in after
    assert "red_team_evidence_missing" in after


def test_revoked_or_expired_evidence_fails_promotion_closed():
    officer = mra.ModelRiskAssuranceOfficer()
    _, _, _, evaluation, _, payload, _ = _promotion_fixture(officer)
    revoked = officer.review_evidence(
        evaluation["id"],
        decision="revoked",
        rationale="Evaluator contamination discovered.",
        reviewer="assurance-reviewer",
        expected_revision=evaluation["revision"],
    )
    assert revoked["status"] == "revoked"
    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
    )
    assert allowed is False
    assert "evidence authority is stale" in reason


def test_inherited_graph_approval_lazily_revokes_and_expires(monkeypatch):
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, "graph-authority-model")
    evaluator = _observe(officer, "graph-authority-evaluator", asset_type="tool")
    approved = _approved_evidence(officer, artifact, evaluator, "evaluation")
    projected = next(
        row for row in evidence_graph.list_nodes()
        if (row.get("review") or {}).get("inherited_from") == approved["id"]
    )
    assert projected["status"] == "approved"
    assert projected["freshness"] == "current"
    assert projected["authority_validation"]["status"] == "current"
    assert projected["review"]["authority_revision"] == approved["revision"]

    officer.review_evidence(
        approved["id"],
        decision="revoked",
        rationale="The approved source receipt was withdrawn.",
        reviewer="assurance-reviewer",
        expected_revision=approved["revision"],
    )
    stale = evidence_graph.get(projected["id"])
    assert stale["status"] == "authority_stale"
    assert stale["freshness"] == "stale"
    assert stale["authority_validation"]["status"] == "stale"

    fresh = _approved_evidence(
        officer,
        artifact,
        evaluator,
        "red_team",
        label="short-lived-red-team",
        lifetime=30,
    )
    fresh_node = next(
        row for row in evidence_graph.list_nodes()
        if (row.get("review") or {}).get("inherited_from") == fresh["id"]
    )
    monkeypatch.setattr(evidence_graph.time, "time", lambda: float(fresh["valid_until"]) + 1)
    expired = evidence_graph.get(fresh_node["id"])
    assert expired["status"] == "authority_stale"
    assert expired["freshness"] == "stale"
    assert expired["authority_validation"]["reason"] == "source_expired"


def test_drift_incident_and_stale_risk_acceptance_block_promotion():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact, evaluator, _, _, _, payload, _ = _promotion_fixture(officer)
    drift = _approved_evidence(
        officer,
        artifact,
        evaluator,
        "drift_monitoring",
        result="failed",
    )
    finding = next(
        row for row in officer.findings()
        if row["asset_id"] == artifact["asset_id"] and row["finding_type"] == "drift_detected"
    )
    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001", rung="weights", payload_sha256=payload,
    )
    assert allowed is False and "drift_detected" in reason
    acceptance = officer.accept_risk(
        finding["id"],
        finding_sha256=finding["finding_sha256"],
        rationale="Bounded canary exposure with human monitoring.",
        reviewer="risk-owner",
        expires_at=time.time() + 600,
    )
    assert acceptance["status"] == "accepted"
    assert officer.verify_promotion_candidate(
        candidate_id="candidate-001", rung="weights", payload_sha256=payload,
    )[0] is True

    officer.review_evidence(
        drift["id"],
        decision="revoked",
        rationale="The drift receipt itself is no longer trusted.",
        reviewer="assurance-reviewer",
        expected_revision=drift["revision"],
    )
    allowed, reason = officer.verify_promotion_candidate(
        candidate_id="candidate-001", rung="weights", payload_sha256=payload,
    )
    assert allowed is False and "drift_detected" in reason

    incident_evidence = _approved_evidence(
        officer,
        artifact,
        evaluator,
        "incident_analysis",
        label="incident-analysis-1",
    )
    officer.record_incident(
        artifact["asset_id"],
        source_id="incident-001",
        severity="critical",
        summary="Unexpected autonomous action crossed a declared boundary.",
        occurred_at=time.time(),
        evidence_ids=[incident_evidence["id"]],
        actor="incident-commander",
    )
    critical = next(
        row for row in officer.findings()
        if row["asset_id"] == artifact["asset_id"]
        and row["finding_type"] == "active_incident"
    )
    with pytest.raises(ValueError, match="critical findings cannot"):
        officer.accept_risk(
            critical["id"],
            finding_sha256=critical["finding_sha256"],
            rationale="Must not suppress this.",
            reviewer="risk-owner",
            expires_at=time.time() + 600,
        )


def test_deployment_lineage_requires_gate_and_exact_predecessor():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact, _, _, _, _, payload, _ = _promotion_fixture(officer)
    deployed = officer.record_deployment(
        deployment_id="prod-model-primary",
        candidate_id="candidate-001",
        rung="weights",
        payload_sha256=payload,
        predecessor_digest=None,
        expected_revision=0,
        actor="release-controller",
    )
    assert deployed["artifact_digest"] == artifact["version_digest"]
    assert deployed["promotion_binding_sha256"]
    with pytest.raises(RecordConflict, match="lineage changed"):
        officer.record_deployment(
            deployment_id="prod-model-primary",
            candidate_id="candidate-001",
            rung="weights",
            payload_sha256=payload,
            predecessor_digest=artifact["version_digest"],
            expected_revision=0,
            actor="stale-release-controller",
        )


def test_tenant_scoping_denies_cross_tenant_reads():
    officer = mra.ModelRiskAssuranceOfficer()
    with tenant_scope(tenant="alpha"):
        alpha = _observe(officer, "shared-external-id")
        assert officer.get_observation(alpha["asset_id"]) is not None
    with tenant_scope(tenant="beta"):
        assert officer.get_observation(alpha["asset_id"]) is None
        beta = _observe(officer, "shared-external-id")
        assert beta["asset_id"] == alpha["asset_id"]
        assert officer.list_inventory() == [beta]
    with tenant_scope(tenant="alpha"):
        assert officer.list_inventory() == [alpha]


def test_signed_pack_requires_external_trust_and_detects_tampering():
    officer = mra.ModelRiskAssuranceOfficer()
    artifact = _observe(officer, "pack-model")
    _declare(officer, artifact)
    pack = officer.render_assurance_pack(actor="assurance-officer", asset_id=artifact["asset_id"])
    assert pack["schema"] == mra.PACK_SCHEMA
    assert pack["legal_certification"] is False
    assert pack["compliance_verdict"] == "not_provided"
    key_id = pack["attestation"]["key_id"]
    public_key = pack["attestation"]["public_key"]
    assert mra.verify_assurance_pack(pack, trusted_pubkeys={key_id: public_key}) is True
    assert mra.verify_assurance_pack(pack, trusted_pubkeys={}) is False
    changed = copy.deepcopy(pack)
    changed["notice"] = "Certified"
    assert mra.verify_assurance_pack(changed, trusted_pubkeys={key_id: public_key}) is False
    assert "certification" in json.dumps(pack).lower()
    with pytest.raises(ValueError, match="clock-skew"):
        officer.render_assurance_pack(
            actor="backdating-attempt",
            asset_id=artifact["asset_id"],
            generated_at=time.time() - 301,
        )


def test_feature_and_promotion_switches_are_explicit_and_malformed_policy_denies(tmp_path):
    from maverick import config

    assert mra.enabled() is True
    assert mra.promotion_gate_enabled() is True
    _write_config(tmp_path, enabled="true", gate="false")
    config.reset_config_cache()
    assert mra.enabled() is True
    assert mra.promotion_gate_enabled() is False
    allowed, reason = mra.verify_promotion_candidate(
        candidate_id="missing",
        rung="weights",
        payload_sha256=_hex("missing"),
    )
    assert allowed is True and "disabled" in reason

    _write_config(tmp_path, enabled="true", gate='"sometimes"')
    config.reset_config_cache()
    assert mra.enabled() is False
    with pytest.raises(mra.ModelRiskConfigError, match="must be a boolean"):
        mra.promotion_gate_enabled()
    allowed, reason = mra.verify_promotion_candidate(
        candidate_id="missing",
        rung="weights",
        payload_sha256=_hex("missing"),
    )
    assert allowed is False and "policy unavailable" in reason


def test_promotion_gate_requires_readable_enabled_evidence_graph(tmp_path):
    from maverick import config

    _write_config(tmp_path, enabled="true", gate="true", graph="false")
    config.reset_config_cache()

    with pytest.raises(mra.ModelRiskConfigError, match="evidence_graph"):
        mra.promotion_gate_enabled()
    allowed, reason = mra.verify_promotion_candidate(
        candidate_id="candidate-missing-graph",
        rung="config",
        payload_sha256=_hex("candidate-missing-graph"),
    )
    assert allowed is False
    assert "policy unavailable" in reason


def test_module_facade_uses_one_local_governed_authority():
    row = mra.observe_asset(
        asset_type="model",
        source="facade",
        source_id="facade-model",
        display_name="Facade Model",
        version_digest=_hex("facade-model"),
        actor="operator",
        observed_at=time.time(),
    )
    assert mra.get_observation(row["asset_id"])["id"] == row["id"]
    assert mra.list_inventory() == [row]
    assert mra._DEFAULT.backend_kind == "local"


def test_bounded_inventory_input_rejects_secrets_and_oversized_collections():
    officer = mra.ModelRiskAssuranceOfficer()
    with pytest.raises(ValueError, match="sensitive key"):
        officer.observe_asset(
            asset_type="model",
            source="registry",
            source_id="secret-bearing",
            display_name="Unsafe",
            version_digest=_hex("unsafe"),
            metadata={"access_token": "do-not-store"},
            actor="operator",
            observed_at=time.time(),
        )
    with pytest.raises(ValueError, match="exceeds 128 items"):
        officer.observe_asset(
            asset_type="model",
            source="registry",
            source_id="too-many-dependencies",
            display_name="Too Many",
            version_digest=_hex("many"),
            dependencies=[f"dependency_{index}" for index in range(129)],
            actor="operator",
            observed_at=time.time(),
        )
    assert officer.list_inventory() == []
