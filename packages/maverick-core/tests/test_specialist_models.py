"""Candidate-catalog integrity and conservative deployment planning."""
from __future__ import annotations

import hashlib
import json
from importlib.resources import files

import pytest
from maverick.training import specialist_models as models


def test_builtin_catalog_is_content_addressed_and_evidence_labelled():
    catalog = models.load_catalog()
    blob = models.catalog_path().read_bytes()

    assert len(catalog.models) == 13
    assert catalog.as_of == "2026-07-23"
    assert catalog.digest == hashlib.sha256(blob).hexdigest()
    for candidate in catalog.models:
        assert len(candidate.upstream_revision) == 40
        assert candidate.license_id
        for url in (candidate.license_url, candidate.model_card_url):
            if url.startswith("https://huggingface.co/"):
                assert candidate.upstream_revision in url
                assert "/main" not in url
        assert candidate.planning_basis == "engineering_judgment_not_benchmark"
        assert candidate.status in {
            "primary_bakeoff",
            "secondary_bakeoff",
            "upper_bound",
            "watchlist",
        }
        for artifact in candidate.artifacts:
            assert artifact.revision in artifact.source_url
            assert artifact.format in {
                "safetensors-bf16",
                "safetensors-fp16",
                "safetensors-fp8",
                "safetensors-gptq-int4",
                "safetensors-mxfp4",
                "safetensors-nvfp4",
                "gguf-q4_0",
                "onnx-int4",
            }


def test_loaded_digest_cannot_change_when_catalog_file_changes(tmp_path):
    path = tmp_path / "catalog.json"
    path.write_bytes(models.catalog_path().read_bytes())
    catalog = models.load_catalog(path)
    parsed_digest = catalog.digest

    path.write_bytes(path.read_bytes() + b"\n")

    assert catalog.digest == parsed_digest
    assert models.load_catalog(path).digest != parsed_digest


def test_artifact_formats_are_exact_and_never_aliased():
    candidate = models.load_catalog().get("qwen35-35b-a3b")
    exact = models.estimate_deployment(
        candidate,
        available_memory_gib=48,
        artifact_format="safetensors-gptq-int4",
    )
    different_four_bit_format = models.estimate_deployment(
        candidate,
        available_memory_gib=48,
        artifact_format="gguf-q4_0",
    )

    assert exact.weights_gib == 22.74
    assert exact.artifact_revision == "3af5ca2972faf6de1fd6f4efc4d8d319ca751e8b"
    assert different_four_bit_format.size_evidence == "parameter_arithmetic_estimate"
    assert different_four_bit_format.artifact_revision == ""
    assert "no catalog artifact exists for this exact format" in (
        different_four_bit_format.warnings
    )


def test_revision_pin_is_not_misrepresented_as_a_file_manifest():
    candidate = models.load_catalog().get("gpt-oss-20b")
    estimate = models.estimate_deployment(
        candidate,
        available_memory_gib=24,
    )

    assert estimate.fits is True
    assert estimate.artifact_reproducible is False
    assert estimate.artifact_manifest_sha256 == ""
    assert any("signed manifest digest" in warning for warning in estimate.warnings)


def test_only_moe_architectures_receive_expert_weight_warning():
    catalog = models.load_catalog()
    dense_effective = models.estimate_deployment(
        catalog.get("gemma4-e4b"),
        available_memory_gib=16,
    )
    moe = models.estimate_deployment(
        catalog.get("qwen35-35b-a3b"),
        available_memory_gib=48,
    )

    assert not any("active MoE" in warning for warning in dense_effective.warnings)
    assert any("architecture-specific" in warning for warning in dense_effective.warnings)
    assert any("active MoE" in warning for warning in moe.warnings)


def test_candidate_matrix_is_planning_only_and_keeps_non_fits_visible():
    matrix = models.candidate_matrix("reviewer", available_memory_gib=8)

    assert matrix
    assert all("reviewer" in candidate.roles for candidate, _estimate in matrix)
    assert any(not estimate.fits for _candidate, estimate in matrix)
    assert all(
        estimate.warnings[0].startswith("planning estimate only")
        for _candidate, estimate in matrix
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("as_of", "23 July 2026", "ISO calendar date"),
        ("status", "recommended", "status must be one of"),
        ("upstream_revision", "main", "immutable 40-character commit"),
        ("planning_basis", "benchmark", "disclose non-benchmark judgment"),
    ],
)
def test_catalog_rejects_ambiguous_governance_fields(
    tmp_path,
    field,
    value,
    message,
):
    raw = json.loads(models.catalog_path().read_text(encoding="utf-8"))
    if field == "as_of":
        raw[field] = value
    else:
        raw["models"][0][field] = value
    path = tmp_path / f"{field}.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(models.SpecialistModelError, match=message):
        models.load_catalog(path)


def test_catalog_is_present_in_the_training_package():
    package = files("maverick.training")
    assert package.joinpath("specialist_models.v1.json").is_file()


def test_catalog_rejects_duplicate_nonstandard_and_unexpected_fields(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema":"lightwork.specialist-model-catalog.v1",'
        '"schema":"lightwork.specialist-model-catalog.v1",'
        '"as_of":"2026-07-23","models":[]}',
        encoding="utf-8",
    )
    with pytest.raises(models.SpecialistModelError, match="duplicates field"):
        models.load_catalog(duplicate)

    nonstandard = tmp_path / "nonstandard.json"
    nonstandard.write_text(
        '{"schema":"lightwork.specialist-model-catalog.v1",'
        '"as_of":"2026-07-23","models":[NaN]}',
        encoding="utf-8",
    )
    with pytest.raises(models.SpecialistModelError, match="non-standard JSON"):
        models.load_catalog(nonstandard)

    raw = json.loads(models.catalog_path().read_text(encoding="utf-8"))
    raw["models"][0]["unreviewed_claim"] = True
    unexpected = tmp_path / "unexpected.json"
    unexpected.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(models.SpecialistModelError, match="unexpected fields"):
        models.load_catalog(unexpected)


def test_catalog_rejects_mutable_hugging_face_evidence_urls(tmp_path):
    raw = json.loads(models.catalog_path().read_text(encoding="utf-8"))
    raw["models"][0]["license_url"] = (
        "https://huggingface.co/Qwen/Qwen3.5-4B/blob/main/LICENSE"
    )
    path = tmp_path / "mutable-license.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(models.SpecialistModelError, match="mutable main"):
        models.load_catalog(path)
