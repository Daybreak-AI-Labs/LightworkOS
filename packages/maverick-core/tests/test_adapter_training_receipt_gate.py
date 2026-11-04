"""Training-receipt interlock for governed adapter promotion."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from maverick import adapter_rung as ar
from maverick.paths import tenant_scope
from maverick.training import qualification as q
from maverick.training import receipts
from maverick.training.specialist_models import load_catalog

# The qualification gate enforces a maximum evidence age against the real
# clock, so fixed calendar dates rot (this file failed on 2026-08-23 with a
# 2026-07-23 anchor). Anchor the scenario one day in the past instead; every
# ordering between the timestamps is preserved exactly.
_BASE = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)


def _stamp(minutes: int) -> str:
    return (_BASE + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


COMPLETED_AT = _stamp(0)
MEASURED_AT = _stamp(30)
ISSUED_AT = _stamp(60)
_QUALIFIED_NOW = _BASE + timedelta(minutes=60)
#: The qualification window anchors to measured_at (q.MAX_EVIDENCE_AGE).
_EXPIRES = _BASE + timedelta(minutes=30) + q.MAX_EVIDENCE_AGE


def _manifest(tmp_path) -> ar.AdapterManifest:
    directory = tmp_path / "adapter"
    directory.mkdir()
    (directory / "adapter.safetensors").write_bytes(b"adapter-weights")
    manifest = ar.AdapterManifest(
        adapter_id="privacy-reviewer-v1",
        base_model="ollama:Qwen/Qwen3.5-9B",
        trainer="prime-rl",
        dataset_sha256="1" * 64,
        examples=40,
        tenant_id="tenant-a",
    )
    manifest.save(directory)
    return manifest


def _receipt(adapter_sha256: str) -> dict:
    evidence = _qualification(adapter_sha256)
    policy = q.default_policy("standard")
    decision = q.evaluate_qualification(evidence, policy)
    return {
        "evidence": {
            "run_id": evidence.run_id,
            "tenant_id": "tenant-a",
            "completed_at": COMPLETED_AT,
            "dataset_sha256": "1" * 64,
            "environment_sha256": "a" * 64,
            "environment_id": "privacy",
            "base_model": {
                "model_id": evidence.base_model_id,
                "revision": evidence.model_revision,
                "license_id": evidence.base_model_license_id,
                "license_evidence_sha256": (evidence.base_model_license_evidence_sha256),
                "artifact_sha256": (evidence.runtime.base_model_artifact_sha256),
                "artifact_manifest_sha256": (evidence.runtime.base_model_artifact_manifest_sha256),
                "tokenizer_sha256": (evidence.runtime.base_model_tokenizer_sha256),
                "artifact_format": (evidence.runtime.base_model_artifact_format),
            },
            "adapter": {
                "adapter_id": "privacy-reviewer-v1",
                "artifact_sha256": adapter_sha256,
                "artifact_format": evidence.runtime.adapter_artifact_format,
                "checkpoint_sha256": (evidence.runtime.adapter_checkpoint_sha256),
                "runtime_compatibility_sha256": (
                    evidence.runtime.adapter_runtime_compatibility_sha256
                ),
            },
            "training": {"backend": "prime-rl"},
            "evaluation": {
                "protocol_sha256": "c" * 64,
                "run_sha256": evidence.evaluation_run_sha256,
                "sealed_holdout_sha256": evidence.sealed_holdout_sha256,
                "qualification_evidence_sha256": decision.evidence_sha256,
                "qualification_policy_sha256": decision.policy_sha256,
            },
        },
        "issued_at": ISSUED_AT,
    }


def _commitment() -> dict[str, str]:
    return {
        "receipt_payload_sha256": "2" * 64,
        "event_hash": "3" * 64,
        "key_id": "4" * 16,
        "approval_subject_sha256": "5" * 64,
    }


def _receipt_binding(adapter_sha256: str = "9" * 64) -> dict[str, str]:
    receipt = _receipt(adapter_sha256)["evidence"]
    base_model = receipt["base_model"]
    adapter = receipt["adapter"]
    evaluation = receipt["evaluation"]
    return {
        **_commitment(),
        "training_run_id": receipt["run_id"],
        "training_completed_at": receipt["completed_at"],
        "receipt_issued_at": ISSUED_AT,
        "dataset_sha256": receipt["dataset_sha256"],
        "environment_sha256": receipt["environment_sha256"],
        "environment_id": receipt["environment_id"],
        "adapter_id": adapter["adapter_id"],
        "adapter_sha256": adapter["artifact_sha256"],
        "training_backend": receipt["training"]["backend"],
        "base_model_id": base_model["model_id"],
        "base_model_revision": base_model["revision"],
        "base_model_license_id": base_model["license_id"],
        "base_model_license_evidence_sha256": (base_model["license_evidence_sha256"]),
        "base_model_artifact_sha256": base_model["artifact_sha256"],
        "base_model_artifact_manifest_sha256": (base_model["artifact_manifest_sha256"]),
        "base_model_tokenizer_sha256": base_model["tokenizer_sha256"],
        "base_model_artifact_format": base_model["artifact_format"],
        "adapter_artifact_format": adapter["artifact_format"],
        "adapter_checkpoint_sha256": adapter["checkpoint_sha256"],
        "adapter_runtime_compatibility_sha256": (adapter["runtime_compatibility_sha256"]),
        "evaluation_protocol_sha256": evaluation["protocol_sha256"],
        "evaluation_run_sha256": evaluation["run_sha256"],
        "sealed_holdout_sha256": evaluation["sealed_holdout_sha256"],
        "qualification_evidence_sha256": (evaluation["qualification_evidence_sha256"]),
        "qualification_policy_sha256": (evaluation["qualification_policy_sha256"]),
    }


def test_verified_receipt_binds_exact_tenant_data_model_and_adapter(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    manifest = _manifest(tmp_path)
    digest = ar.payload_digest_dir(tmp_path / "adapter")
    receipt = _receipt(digest)
    monkeypatch.setattr(ar, "_model_improvement_receipt_required", lambda: True)
    verified: dict[str, object] = {}

    def read_verified(receipt_id, **kwargs):
        assert receipt_id == "receipt-1"
        verified.update(kwargs)
        return receipt

    monkeypatch.setattr(
        receipts,
        "read_verified_training_receipt",
        read_verified,
    )
    receipt_keys = {"4" * 16: "6" * 64}
    approver_keys = {"7" * 16: "8" * 64}
    monkeypatch.setattr(
        receipts,
        "server_training_trust_registries",
        lambda: (receipt_keys, approver_keys),
    )
    monkeypatch.setattr(
        receipts,
        "public_transparency_commitment",
        lambda value, **_kwargs: _commitment() if value is receipt else {},
    )

    with tenant_scope(tenant="tenant-a"):
        binding = ar._verified_training_receipt_binding(
            receipt_id="receipt-1",
            manifest=manifest,
            adapter_sha256=digest,
        )

    assert binding == _receipt_binding(digest)
    assert verified["expected_tenant_id"] == "tenant-a"


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("adapter", "9" * 64, "different adapter bytes"),
        ("dataset", "9" * 64, "different training dataset"),
        ("base_model", "org/other-model", "different base model"),
    ],
)
def test_verified_receipt_refuses_artifact_binding_mismatch(
    tmp_path,
    monkeypatch,
    field,
    value,
    message,
):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    manifest = _manifest(tmp_path)
    digest = ar.payload_digest_dir(tmp_path / "adapter")
    receipt = _receipt(digest)
    if field == "adapter":
        receipt["evidence"]["adapter"]["artifact_sha256"] = value
    elif field == "dataset":
        receipt["evidence"]["dataset_sha256"] = value
    else:
        receipt["evidence"]["base_model"]["model_id"] = value
    monkeypatch.setattr(ar, "_model_improvement_receipt_required", lambda: True)
    monkeypatch.setattr(
        receipts,
        "read_verified_training_receipt",
        lambda _receipt_id, **_kwargs: receipt,
    )
    monkeypatch.setattr(
        receipts,
        "server_training_trust_registries",
        lambda: ({}, {}),
    )

    with tenant_scope(tenant="tenant-a"):
        with pytest.raises(ValueError, match=message):
            ar._verified_training_receipt_binding(
                receipt_id="receipt-1",
                manifest=manifest,
                adapter_sha256=digest,
            )


def test_receipt_gate_is_inert_when_model_improvement_is_disabled(
    tmp_path,
    monkeypatch,
):
    manifest = _manifest(tmp_path)
    monkeypatch.setattr(ar, "_model_improvement_receipt_required", lambda: False)
    monkeypatch.setattr(
        receipts,
        "read_verified_training_receipt",
        lambda _receipt_id: pytest.fail("disabled gate read a receipt"),
    )

    assert (
        ar._verified_training_receipt_binding(
            receipt_id=None,
            manifest=manifest,
            adapter_sha256=ar.payload_digest_dir(tmp_path / "adapter"),
        )
        is None
    )


def _qualification(adapter_sha256: str) -> q.QualificationEvidence:
    catalog = load_catalog()
    candidate = catalog.get("qwen35-9b")
    runtime = q.RuntimeEvidence(
        engine="vllm",
        engine_version="1.0.0",
        base_model_artifact_format="safetensors-bf16",
        base_model_artifact_sha256="2" * 64,
        base_model_artifact_manifest_sha256="3" * 64,
        base_model_tokenizer_sha256="f" * 64,
        adapter_artifact_format="safetensors-lora",
        adapter_sha256=adapter_sha256,
        adapter_checkpoint_sha256="4" * 64,
        adapter_runtime_compatibility_sha256="5" * 64,
        deployment_manifest_sha256="e" * 64,
        container_or_lock_sha256="0" * 64,
        hardware_profile_sha256="1" * 64,
        context_tokens=8_192,
        concurrency=1,
    )
    return q.QualificationEvidence(
        run_id="qualification-0001",
        catalog_id=candidate.catalog_id,
        catalog_sha256=catalog.digest,
        dataset_sha256="1" * 64,
        base_model_id=candidate.model_id,
        model_revision=candidate.upstream_revision,
        base_model_license_id=candidate.license_id,
        base_model_license_evidence_sha256="6" * 64,
        evaluation_protocol_sha256="c" * 64,
        evaluation_run_sha256="7" * 64,
        sealed_holdout_sha256="8" * 64,
        environment_sha256s={"privacy": "a" * 64},
        runtime=runtime,
        quality=q.QualityMetrics(
            task_pass_rate=0.95,
            schema_pass_rate=1.0,
            citation_precision=1.0,
            citation_recall=0.98,
            false_negative_rate=0.01,
            expected_calibration_error=0.02,
            tool_argument_pass_rate=1.0,
            jailbreak_block_rate=1.0,
            pii_reproduction_rate=0.0,
            first_pass_acceptance_rate=0.95,
            quantization_quality_loss=0.01,
        ),
        performance=q.PerformanceMetrics(
            ttft_p95_ms=500,
            decode_tokens_per_second_p50=50,
            peak_memory_gib=12,
            requests_per_second=1,
            cost_per_million_output_tokens=0,
        ),
        sample_size=200,
        holdout_sealed=True,
        measured_at=MEASURED_AT,
    )


def _model_improvement_binding(
    adapter_sha256: str,
    *,
    evidence: q.QualificationEvidence | None = None,
) -> dict:
    measured = evidence or _qualification(adapter_sha256)
    policy = q.default_policy("standard")
    decision = q.evaluate_qualification(
        measured,
        policy,
        now=_QUALIFIED_NOW,
    )
    receipt_binding = {
        **_receipt_binding(adapter_sha256),
        "dataset_sha256": measured.dataset_sha256,
        "base_model_id": measured.base_model_id,
        "base_model_revision": measured.model_revision,
        "base_model_license_id": measured.base_model_license_id,
        "base_model_license_evidence_sha256": (measured.base_model_license_evidence_sha256),
        "base_model_artifact_sha256": (measured.runtime.base_model_artifact_sha256),
        "base_model_artifact_manifest_sha256": (
            measured.runtime.base_model_artifact_manifest_sha256
        ),
        "base_model_tokenizer_sha256": (measured.runtime.base_model_tokenizer_sha256),
        "base_model_artifact_format": (measured.runtime.base_model_artifact_format),
        "adapter_artifact_format": measured.runtime.adapter_artifact_format,
        "adapter_checkpoint_sha256": (measured.runtime.adapter_checkpoint_sha256),
        "adapter_runtime_compatibility_sha256": (
            measured.runtime.adapter_runtime_compatibility_sha256
        ),
        "evaluation_protocol_sha256": measured.evaluation_protocol_sha256,
        "evaluation_run_sha256": measured.evaluation_run_sha256,
        "sealed_holdout_sha256": measured.sealed_holdout_sha256,
        "qualification_evidence_sha256": decision.evidence_sha256,
        "qualification_policy_sha256": decision.policy_sha256,
    }
    qualification = ar._verified_qualification_binding(
        evidence=measured,
        policy=policy,
        receipt_binding=receipt_binding,
        adapter_sha256=adapter_sha256,
        model_improvement_policy={
            "enable": True,
            "require_signed_receipt": True,
        },
    )
    return {
        "schema": ar.MODEL_IMPROVEMENT_BINDING_SCHEMA,
        "policy_sha256": ar._model_improvement_policy_digest(
            {"enable": True, "require_signed_receipt": True},
        ),
        "training_receipt": receipt_binding,
        "qualification": qualification,
    }


def test_qualification_is_evaluated_and_bound_into_approved_pointer(
    tmp_path,
    monkeypatch,
):
    digest = "9" * 64
    evidence = _qualification(digest)
    policy = q.default_policy("standard")
    monkeypatch.setattr(ar, "_model_improvement_enabled", lambda: True)

    qualification = ar._verified_qualification_binding(
        evidence=evidence,
        policy=policy,
        receipt_binding=_receipt_binding(),
        adapter_sha256=digest,
    )
    binding = {
        "schema": ar.MODEL_IMPROVEMENT_BINDING_SCHEMA,
        "policy_sha256": "7" * 64,
        "training_receipt": _receipt_binding(),
        "qualification": qualification,
    }
    pointer = {
        "tenant_id": "tenant-a",
        "promotion_record_id": "promotion-1",
        "adapter_id": "adapter-1",
        "base_model": "ollama:Qwen/Qwen3.5-9B",
        "dataset_sha256": "1" * 64,
        "payload_sha256": digest,
        "serving": {"mode": "manual"},
        "model_improvement": binding,
    }
    first = ar._authority_payload(
        pointer,
        artifact_identity="tenant:tenant-a:adapter-pointer",
        ledger_path=(tmp_path / "ledger.json").resolve(),
    )
    changed = {
        **binding,
        "qualification": {
            **qualification,
            "evidence_sha256": "8" * 64,
        },
    }
    second = ar._authority_payload(
        {**pointer, "model_improvement": changed},
        artifact_identity="tenant:tenant-a:adapter-pointer",
        ledger_path=(tmp_path / "ledger.json").resolve(),
    )

    assert qualification is not None
    assert (
        qualification["evidence_sha256"]
        == q.evaluate_qualification(
            evidence,
            policy,
        ).evidence_sha256
    )
    assert first != second


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"artifact": "8" * 64}, "different adapter bytes"),
        ({"revision": "8" * 40}, "exact catalog artifact"),
        ({"environment": {"other": "8" * 64}}, "different environment"),
        ({"protocol": "8" * 64}, "evaluation_protocol_sha256"),
    ],
)
def test_qualification_refuses_cross_run_binding(
    monkeypatch,
    change,
    message,
):
    digest = "9" * 64
    evidence = _qualification(digest)
    if "artifact" in change:
        evidence = replace(
            evidence,
            runtime=replace(
                evidence.runtime,
                adapter_sha256=change["artifact"],
            ),
        )
    elif "revision" in change:
        evidence = replace(
            evidence,
            model_revision=change["revision"],
        )
    elif "environment" in change:
        evidence = replace(
            evidence,
            environment_sha256s=change["environment"],
        )
    else:
        evidence = replace(
            evidence,
            evaluation_protocol_sha256=change["protocol"],
        )
    monkeypatch.setattr(ar, "_model_improvement_enabled", lambda: True)

    with pytest.raises(ValueError, match=message):
        ar._verified_qualification_binding(
            evidence=evidence,
            policy=q.default_policy("standard"),
            receipt_binding=_receipt_binding(digest),
            adapter_sha256=digest,
        )


def test_govern_adapter_change_calls_receipt_gate_before_evaluation(
    tmp_path,
    monkeypatch,
):
    manifest = _manifest(tmp_path)
    manifest.tenant_id = ""
    manifest.save(tmp_path / "adapter")
    controller = SimpleNamespace(
        approval_verifier=object(),
        rung_policy={"weights": {"require_human": True}},
        ledger=SimpleNamespace(durable=True, path=None),
    )
    monkeypatch.setattr(
        ar,
        "_configure_adapter_governance",
        lambda **_kwargs: (controller, None, ()),
    )
    monkeypatch.setattr(ar, "recover_adapter_promotions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        ar,
        "_verified_training_receipt_binding",
        lambda **_kwargs: (_ for _ in ()).throw(ValueError("missing signed receipt")),
    )
    score_called = False

    def score_fn(_model, _case_ids):
        nonlocal score_called
        score_called = True
        return {}

    result = ar.govern_adapter_change(
        tmp_path / "adapter",
        ["case-1", "case-2"],
        score_fn=score_fn,
        store=ar.AdapterStore(root=tmp_path / "store"),
    )

    assert not result.promoted
    assert result.reason == "training receipt refused: missing signed receipt"
    assert score_called is False


def test_govern_adapter_change_refuses_bytes_changed_during_staging(
    tmp_path,
    monkeypatch,
):
    manifest = _manifest(tmp_path)
    controller = SimpleNamespace(
        approval_verifier=object(),
        rung_policy={"weights": {"require_human": True}},
        ledger=SimpleNamespace(durable=True, path=None),
    )
    monkeypatch.setattr(
        ar,
        "_configure_adapter_governance",
        lambda **_kwargs: (controller, None, ()),
    )
    monkeypatch.setattr(ar, "recover_adapter_promotions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        ar,
        "_model_improvement_policy",
        lambda: {
            "enable": False,
            "require_signed_receipt": True,
        },
    )
    store = ar.AdapterStore(root=tmp_path / "store", tenant_id="tenant-a")
    monkeypatch.setattr(
        store,
        "stage_payload",
        lambda *_args, **_kwargs: (
            tmp_path / "staged",
            replace(manifest, payload_sha256="9" * 64),
        ),
    )

    def score_fn(model_ref, case_ids):
        return dict.fromkeys(case_ids, "+adapter:" in model_ref)

    with tenant_scope(tenant="tenant-a"):
        result = ar.govern_adapter_change(
            tmp_path / "adapter",
            [f"case-{index}" for index in range(8)],
            score_fn=score_fn,
            store=store,
        )

    assert not result.promoted
    assert result.reason == (
        "adapter immutable staging refused: payload bytes changed after "
        "training receipt and qualification"
    )


def test_routing_revalidates_non_extendable_qualification_expiry(monkeypatch):
    digest = "9" * 64
    improvement = _model_improvement_binding(digest)
    policy = {"enable": True, "require_signed_receipt": True}
    monkeypatch.setattr(ar, "_model_improvement_policy", lambda: policy)
    pointer = {
        "adapter_id": "privacy-reviewer-v1",
        "base_model": "ollama:Qwen/Qwen3.5-9B",
        "dataset_sha256": "1" * 64,
        "payload_sha256": digest,
        "model_improvement": improvement,
        "serving": {"mode": "manual"},
    }

    ar._revalidate_model_improvement_pointer(
        pointer,
        now=_EXPIRES - timedelta(minutes=1),
    )
    with pytest.raises(ValueError, match="expired"):
        ar._revalidate_model_improvement_pointer(
            pointer,
            now=_EXPIRES,
        )

    extended = {
        **improvement,
        "qualification": {
            **improvement["qualification"],
            "expires_at": (
                _EXPIRES + timedelta(days=1)
            ).isoformat().replace("+00:00", "Z"),
        },
    }
    with pytest.raises(ValueError, match="not derived"):
        ar._revalidate_model_improvement_pointer(
            {**pointer, "model_improvement": extended},
            now=_EXPIRES - timedelta(minutes=1),
        )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("engine", "vllm"),
        ("engine_version", "9.9.9"),
        ("context_tokens", 16_384),
        ("concurrency", 8),
    ],
)
def test_deployment_attestation_refuses_runtime_tuple_drift(
    field,
    replacement,
):
    digest = "9" * 64
    evidence = _qualification(digest)
    runtime = replace(
        evidence.runtime,
        engine="ollama",
        engine_version="0.10.0",
    )
    evidence = replace(evidence, runtime=runtime)
    improvement = _model_improvement_binding(digest, evidence=evidence)
    required = ar._model_improvement_runtime_requirement(improvement)
    actual = {**required, field: replacement}
    binding = {
        "model_name": "qualified-model",
        "modelfile_sha256": "a" * 64,
        "deployment": {
            "version": 1,
            "provider": "ollama",
            "verified": True,
            "model_name": "qualified-model",
            "source_modelfile_sha256": "a" * 64,
            "model_digest": "b" * 64,
            "verified_at": 1.0,
            "model_improvement_runtime": actual,
            "model_improvement_runtime_sha256": required["runtime_attestation_sha256"],
        },
    }

    with pytest.raises(ValueError, match="another qualified runtime"):
        ar._validate_deployment_attestation(
            binding,
            required_runtime=required,
        )


def test_deployment_attestation_refuses_runtime_digest_drift():
    digest = "9" * 64
    evidence = _qualification(digest)
    evidence = replace(
        evidence,
        runtime=replace(
            evidence.runtime,
            engine="ollama",
            engine_version="0.10.0",
        ),
    )
    improvement = _model_improvement_binding(digest, evidence=evidence)
    required = ar._model_improvement_runtime_requirement(improvement)
    binding = {
        "model_name": "qualified-model",
        "modelfile_sha256": "a" * 64,
        "deployment": {
            "version": 1,
            "provider": "ollama",
            "verified": True,
            "model_name": "qualified-model",
            "source_modelfile_sha256": "a" * 64,
            "model_digest": "b" * 64,
            "verified_at": 1.0,
            "model_improvement_runtime": required,
            "model_improvement_runtime_sha256": "c" * 64,
        },
    }

    with pytest.raises(ValueError, match="runtime digest"):
        ar._validate_deployment_attestation(
            binding,
            required_runtime=required,
        )
