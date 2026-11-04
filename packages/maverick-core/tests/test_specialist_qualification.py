"""Measured specialist-model qualification is exact and fail-closed."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from maverick.training import qualification as q
from maverick.training.specialist_models import load_catalog

NOW = datetime(2026, 7, 23, 16, 0, tzinfo=timezone.utc)


def _evidence() -> q.QualificationEvidence:
    catalog = load_catalog()
    candidate = catalog.get("qwen35-9b")
    digest = "a" * 64
    runtime = q.RuntimeEvidence(
        engine="vllm",
        engine_version="0.13.0",
        base_model_artifact_format="safetensors-bf16",
        base_model_artifact_sha256="0" * 64,
        base_model_artifact_manifest_sha256=digest,
        base_model_tokenizer_sha256=digest,
        adapter_artifact_format="safetensors-lora",
        adapter_sha256="1" * 64,
        adapter_checkpoint_sha256="2" * 64,
        adapter_runtime_compatibility_sha256="3" * 64,
        deployment_manifest_sha256="4" * 64,
        container_or_lock_sha256=digest,
        hardware_profile_sha256=digest,
        context_tokens=16_384,
        concurrency=4,
    )
    return q.QualificationEvidence(
        run_id="qwen35-9b-standard-0001",
        catalog_id="qwen35-9b",
        catalog_sha256=catalog.digest,
        dataset_sha256="9" * 64,
        base_model_id=candidate.model_id,
        model_revision=candidate.upstream_revision,
        base_model_license_id=candidate.license_id,
        base_model_license_evidence_sha256="8" * 64,
        evaluation_protocol_sha256="d" * 64,
        evaluation_run_sha256="7" * 64,
        sealed_holdout_sha256="6" * 64,
        environment_sha256s={
            "privacy_assessment_v1": "e" * 64,
            "dsar_routing_v1": "f" * 64,
        },
        runtime=runtime,
        quality=q.QualityMetrics(
            task_pass_rate=0.95,
            schema_pass_rate=0.995,
            citation_precision=0.99,
            citation_recall=0.97,
            false_negative_rate=0.02,
            expected_calibration_error=0.03,
            tool_argument_pass_rate=0.99,
            jailbreak_block_rate=0.99,
            pii_reproduction_rate=0.0,
            first_pass_acceptance_rate=0.92,
            quantization_quality_loss=0.01,
        ),
        performance=q.PerformanceMetrics(
            ttft_p95_ms=750,
            decode_tokens_per_second_p50=45,
            peak_memory_gib=19,
            requests_per_second=1.2,
            cost_per_million_output_tokens=0.35,
        ),
        sample_size=500,
        holdout_sealed=True,
        measured_at="2026-07-23T15:00:00Z",
    )


def test_exact_measured_tuple_qualifies_and_is_content_addressed():
    decision = q.evaluate_qualification(
        _evidence(),
        q.default_policy("standard"),
        now=NOW,
    )

    assert decision.qualified is True
    assert len(decision.evidence_sha256) == 64
    assert len(decision.policy_sha256) == 64
    assert decision.runtime_attestation_sha256 == (
        q.runtime_attestation_sha256(_evidence().runtime)
    )
    assert decision.expires_at == "2026-08-22T15:00:00Z"
    assert decision.failures == ()


def test_unsealed_or_small_holdout_fails():
    evidence = replace(_evidence(), sample_size=25, holdout_sealed=False)
    decision = q.evaluate_qualification(
        evidence,
        q.default_policy("standard"),
        now=NOW,
    )

    assert decision.qualified is False
    assert any("sample_size" in failure for failure in decision.failures)
    assert any("not sealed" in failure for failure in decision.failures)


@pytest.mark.parametrize(
    ("field", "value", "failure"),
    [
        ("schema_pass_rate", 0.98, "schema_pass_rate"),
        ("false_negative_rate", 0.10, "false_negative_rate"),
        ("expected_calibration_error", 0.10, "expected_calibration_error"),
        ("pii_reproduction_rate", 0.001, "pii_reproduction_rate"),
        ("quantization_quality_loss", 0.03, "quantization_quality_loss"),
    ],
)
def test_quality_failures_are_deterministic(field, value, failure):
    evidence = _evidence()
    evidence = replace(
        evidence,
        quality=replace(evidence.quality, **{field: value}),
    )

    decision = q.evaluate_qualification(
        evidence,
        q.default_policy("standard"),
        now=NOW,
    )

    assert decision.qualified is False
    assert any(failure in reason for reason in decision.failures)


def test_edge_profile_enforces_single_device_memory_budget():
    evidence = _evidence()
    evidence = replace(
        evidence,
        runtime=replace(evidence.runtime, concurrency=1),
        performance=replace(
            evidence.performance,
            peak_memory_gib=8.5,
            decode_tokens_per_second_p50=20,
        ),
    )

    decision = q.evaluate_qualification(
        evidence,
        q.default_policy("edge"),
        now=NOW,
    )

    assert decision.qualified is False
    assert any("peak_memory_gib" in reason for reason in decision.failures)


def test_profile_enforces_measured_cost_ceiling():
    evidence = _evidence()
    evidence = replace(
        evidence,
        performance=replace(
            evidence.performance,
            cost_per_million_output_tokens=2.01,
        ),
    )

    decision = q.evaluate_qualification(
        evidence,
        q.default_policy("standard"),
        now=NOW,
    )

    assert decision.qualified is False
    assert any(
        "cost_per_million_output_tokens" in reason
        for reason in decision.failures
    )


def test_malformed_or_mutable_bindings_are_refused():
    with pytest.raises(q.QualificationError, match="immutable commit"):
        q.evaluate_qualification(
            replace(_evidence(), model_revision="main"),
            q.default_policy("standard"),
            now=NOW,
        )
    with pytest.raises(q.QualificationError, match="SHA-256"):
        evidence = _evidence()
        q.evaluate_qualification(
            replace(
                evidence,
                runtime=replace(
                    evidence.runtime,
                    base_model_tokenizer_sha256="latest",
                ),
            ),
            q.default_policy("standard"),
            now=NOW,
        )


def test_policy_can_tighten_but_cannot_weaken_release_floor():
    evidence = _evidence()
    stricter = replace(
        q.default_policy("standard"),
        minimum_sample_size=200,
        maximum_false_negative_rate=0.04,
    )
    assert q.evaluate_qualification(evidence, stricter, now=NOW).qualified

    weakened = replace(
        q.default_policy("standard"),
        minimum_sample_size=1,
        maximum_false_negative_rate=0.5,
    )
    with pytest.raises(q.QualificationError, match="non-overridable"):
        q.evaluate_qualification(evidence, weakened, now=NOW)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"catalog_sha256": "9" * 64}, "current specialist-model catalog"),
        ({"catalog_id": "unknown-model"}, "catalog or candidate"),
        ({"model_revision": "9" * 40}, "exact catalog artifact"),
    ],
)
def test_catalog_candidate_and_revision_are_exact(change, message):
    with pytest.raises(q.QualificationError, match=message):
        q.evaluate_qualification(
            replace(_evidence(), **change),
            q.default_policy("standard"),
            now=NOW,
        )


def test_catalog_context_and_license_are_non_overridable():
    evidence = _evidence()
    oversized_runtime = replace(
        evidence.runtime,
        context_tokens=262_145,
        deployment_manifest_sha256="0" * 64,
    )
    oversized_runtime = replace(
        oversized_runtime,
        deployment_manifest_sha256=q.runtime_attestation_sha256(
            oversized_runtime,
        ),
    )
    with pytest.raises(q.QualificationError, match="context exceeds"):
        q.evaluate_qualification(
            replace(evidence, runtime=oversized_runtime),
            q.default_policy("standard"),
            now=NOW,
        )
    with pytest.raises(q.QualificationError, match="license"):
        q.evaluate_qualification(
            replace(evidence, base_model_license_id="MIT"),
            q.default_policy("standard"),
            now=NOW,
        )


def test_runtime_attestation_binds_the_independent_deployment_manifest():
    evidence = _evidence()
    changed = replace(
        evidence.runtime,
        deployment_manifest_sha256="9" * 64,
    )
    assert q.runtime_attestation_sha256(changed) != (
        q.runtime_attestation_sha256(evidence.runtime)
    )


@pytest.mark.parametrize(
    ("measured_at", "message"),
    [
        (
            (NOW + timedelta(minutes=6)).isoformat().replace("+00:00", "Z"),
            "future-dated",
        ),
        (
            (NOW - timedelta(days=31)).isoformat().replace("+00:00", "Z"),
            "stale",
        ),
    ],
)
def test_evidence_has_bounded_freshness(measured_at, message):
    with pytest.raises(q.QualificationError, match=message):
        q.evaluate_qualification(
            replace(_evidence(), measured_at=measured_at),
            q.default_policy("standard"),
            now=NOW,
        )
