"""Resource refusal must never manufacture a partial synthesized consensus."""
from __future__ import annotations

import copy

import pytest
from maverick.flow import composed_operator as engine
from maverick.flow import learned_operator as scalar


def _example():
    spec = {"inputs": {"x": {"type": "integer", "min": -10, "max": 10}},
            "output_type": "integer", "constants": [0, 1]}
    rows = [{"inputs": {"x": value}, "output": value} for value in (0, 2)]
    return spec, rows


def test_search_exhaustion_after_a_matching_atom_cannot_return_partial_artifact(monkeypatch):
    spec, rows = _example()
    monkeypatch.setattr(engine, "MAX_PRODUCTIONS", 3)
    with pytest.raises(engine.SynthesisLimit, match="no partial"):
        engine.synthesize(spec, rows, max_operations=2, operators=["add", "mul"])


def test_prediction_budget_cannot_claim_consensus_from_first_matching_production(monkeypatch):
    spec, rows = _example()
    artifact = engine.synthesize(spec, rows, max_operations=2, operators=["add", "mul"])
    engine.validate_artifact(artifact)
    monkeypatch.setattr(engine, "MAX_PREDICTION_EVALUATIONS", 1)
    result = engine.evaluate(artifact, {"x": 3})
    assert not result.applied and result.reason == "evaluation_limit"
    assert engine.partitions(artifact, {"x": 3}) is None


def test_rehashed_deleted_production_cannot_shrink_the_version_space():
    spec, rows = _example()
    artifact = engine.synthesize(spec, rows, max_operations=2, operators=["add", "mul"])
    forged = copy.deepcopy(artifact)
    root = forged["states"][forged["roots"][-1]]
    assert len(root["alternatives"]) > 1
    root["alternatives"].pop()
    forged.pop("artifact_sha256")
    forged["artifact_sha256"] = scalar._digest(forged)
    with pytest.raises(ValueError, match="complete learned"):
        engine.validate_artifact(forged)
    assert engine.evaluate(forged, {"x": 3}).reason == "invalid_artifact"
    assert engine.evaluate(artifact, {"x": 3}).applied


@pytest.mark.parametrize("max_operations", [True, 0, 5, 1.0, "2"])
def test_operation_budget_is_a_strict_bounded_integer(max_operations):
    with pytest.raises(ValueError, match="max_operations"):
        engine.synthesize(*_example(), max_operations=max_operations)


@pytest.mark.parametrize("operators", [[], ["add", "add"], ["eval"], [1], "add"])
def test_grammar_must_name_supported_unique_instructions(operators):
    with pytest.raises(ValueError, match="operators"):
        engine.synthesize(*_example(), operators=operators)


def test_validation_and_prediction_caches_do_not_alias_caller_artifact():
    artifact = engine.synthesize(*_example(), max_operations=1, operators=["add"])
    engine.validate_artifact(artifact)
    identity = artifact["artifact_sha256"]
    retained = copy.deepcopy(artifact)
    artifact["states"].clear()
    assert engine.evaluate(artifact, {"x": 3}).reason == "invalid_artifact"
    result = engine.evaluate(retained, {"x": 3})
    assert result.applied and result.value == 3 and result.artifact_digest == identity
