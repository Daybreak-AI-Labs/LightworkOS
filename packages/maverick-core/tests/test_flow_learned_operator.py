"""Executable-learning semantics, complete version spaces and hostile artifacts."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json

import pytest
from maverick.flow.learned_operator import (
    evaluate,
    refine,
    synthesize,
    validate_artifact,
)


def numbers(*names, low=0, high=20, output="integer", constants=None):
    return {"inputs": {name: {"type": "integer", "min": low, "max": high} for name in names},
            "output_type": output, "constants": constants or []}


def row(output, **inputs):
    return {"inputs": inputs, "output": output}


def arithmetic():
    return synthesize(numbers("quantity", "unit_price"), [
        row(6, quantity=2, unit_price=3), row(28, quantity=7, unit_price=4),
        row(0, quantity=0, unit_price=9),
    ])


def resign(artifact):
    payload = {k: v for k, v in artifact.items() if k != "artifact_sha256"}
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    artifact["artifact_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    return artifact


def test_learns_multiplication_and_executes_every_declared_small_domain_pair():
    artifact = arithmetic()
    validate_artifact(artifact)
    assert artifact["candidates"] == [["mul", ["field", "quantity"], ["field", "unit_price"]]]
    for quantity, price in itertools.product(range(21), repeat=2):
        decision = evaluate(artifact, {"quantity": quantity, "unit_price": price})
        assert decision.applied
        assert decision.value == quantity * price
        assert decision.reason == "agreement"


def test_ambiguity_abstains_and_counterexamples_refine_without_mutating_prior():
    original = synthesize(numbers("x", "y"), [row(0, x=0, y=0), row(1, x=1, y=1)])
    before = copy.deepcopy(original)
    assert evaluate(original, {"x": 2, "y": 3}).reason == "ambiguity"
    updated = refine(original, [row(2, x=2, y=3), row(2, x=4, y=2)])
    assert original == before
    assert len(updated["candidates"]) < len(original["candidates"])
    assert updated["artifact_sha256"] != original["artifact_sha256"]
    for x, y in itertools.product(range(21), repeat=2):
        decision = evaluate(updated, {"x": x, "y": y})
        assert decision.applied and decision.value == min(x, y)


def test_threshold_classification_learns_boundary_from_examples():
    spec = numbers("amount", high=1000, output="string", constants=[100, "review", "automatic"])
    artifact = synthesize(spec, [row("automatic", amount=0), row("automatic", amount=99),
                               row("review", amount=100), row("review", amount=850)])
    for amount in range(1001):
        result = evaluate(artifact, {"amount": amount})
        assert result.applied
        assert result.value == ("review" if amount >= 100 else "automatic")


def test_text_transform_preserves_typed_unicode_output():
    artifact = synthesize({"inputs": {"code": {"type": "string", "max_length": 30}},
                           "output_type": "string"},
                          [row("AB-1", code="ab-1"), row("ÉCOLE", code="école")])
    result = evaluate(artifact, {"code": "ßx"})
    assert result.applied and result.value == "SSX"


def test_boolean_is_not_integer_or_truthiness_coerced():
    artifact = synthesize({"inputs": {"active": {"type": "boolean"}}, "output_type": "boolean"},
                          [row(False, active=True), row(True, active=False)])
    assert evaluate(artifact, {"active": False}).value is True
    for value in [0, 1, "false", None, [], {}]:
        assert evaluate(artifact, {"active": value}).reason == "outside_domain"


@pytest.mark.parametrize("data", [{}, {"quantity": True, "unit_price": 2},
    {"quantity": 2.0, "unit_price": 2}, {"quantity": "2", "unit_price": 2},
    {"quantity": -1, "unit_price": 2}, {"quantity": 21, "unit_price": 2},
    {"quantity": 2, "unit_price": None}])
def test_runtime_domain_abstention(data):
    result = evaluate(arithmetic(), data)
    assert not result.applied and result.reason == "outside_domain"
    assert result.artifact_digest and result.candidate_count == 1


def test_unrelated_runtime_fields_are_not_read_or_copied():
    unrelated = object()
    result = evaluate(arithmetic(), {"quantity": 2, "unit_price": 3, "unrelated": unrelated})
    assert result.applied and result.value == 6


def test_recomputed_hash_cannot_hide_removal_of_disagreeing_programs():
    artifact = synthesize(numbers("x", "y"), [row(0, x=0, y=0), row(1, x=1, y=1)])
    artifact["candidates"] = [["field", "x"]]
    resign(artifact)
    with pytest.raises(ValueError, match="complete learned version space"):
        validate_artifact(artifact)
    assert evaluate(artifact, {"x": 2, "y": 3}).reason == "invalid_artifact"


@pytest.mark.parametrize("mutation", [
    lambda a: a["candidates"].append(["shell", "payload"]),
    lambda a: a.update(example_count=True),
    lambda a: a.update(schema="future-version"),
    lambda a: a.update(extra="unexpected"),
    lambda a: a["examples"][0].update(output=9),
    lambda a: a["spec"]["inputs"]["quantity"].update(max=10**13),
    lambda a: a.update(artifact_sha256="0" * 64),
])
def test_artifact_changes_never_execute(mutation):
    artifact = arithmetic()
    mutation(artifact)
    assert evaluate(artifact, {"quantity": 2, "unit_price": 3}).reason == "invalid_artifact"


def test_mutation_after_cached_validation_is_detected():
    artifact = arithmetic()
    validate_artifact(artifact)
    artifact["candidates"][0][0] = "add"
    assert evaluate(artifact, {"quantity": 2, "unit_price": 3}).reason == "invalid_artifact"


def test_evidence_permutation_and_duplicates_do_not_manufacture_support():
    spec = numbers("x", "y")
    first, second = row(5, x=2, y=3), row(11, x=7, y=4)
    one = synthesize(spec, [first, second])
    two = synthesize(spec, [second, first, first])
    assert one == two and one["example_count"] == 2


def test_conflicting_correction_requires_explicit_evidence_replacement():
    artifact = arithmetic()
    with pytest.raises(ValueError, match="conflicting outputs"):
        refine(artifact, [row(99, quantity=2, unit_price=3)])


def test_unsupported_behavior_produces_no_artifact():
    with pytest.raises(ValueError, match="no program"):
        synthesize(numbers("x"), [row(7, x=1), row(16, x=2), row(33, x=3)])


@pytest.mark.parametrize("spec, examples", [
    (numbers("x"), [row(1, x=1), row(1, x=1)]),
    (numbers("x"), [row(1, x=1, z=2), row(2, x=2)]),
    (numbers("x"), [row(1, x=True), row(2, x=2)]),
    (numbers("x"), [row(True, x=1), row(2, x=2)]),
    (numbers("x", constants=[float("nan")]), [row(1, x=1), row(2, x=2)]),
    ({"inputs": {"x": {"type": "integer", "min": False, "max": 3}},
      "output_type": "integer"}, [row(1, x=1), row(2, x=2)]),
    ({"inputs": {"x": {"type": "integer", "min": 3, "max": 0}},
      "output_type": "integer"}, [row(1, x=1), row(2, x=2)]),
])
def test_malformed_training_input_is_rejected(spec, examples):
    with pytest.raises(ValueError):
        synthesize(spec, examples)


def test_training_limits_never_return_truncated_success(monkeypatch):
    import maverick.flow.learned_operator as module

    monkeypatch.setattr(module, "_MAX_SEARCH", 1)
    with pytest.raises(ValueError, match="search limit"):
        arithmetic()


def test_survivor_limit_never_selects_a_convenient_subset(monkeypatch):
    import maverick.flow.learned_operator as module

    monkeypatch.setattr(module, "MAX_CANDIDATES", 1)
    with pytest.raises(ValueError, match="distinguishing examples"):
        synthesize(numbers("x", "y"), [row(0, x=0, y=0), row(1, x=1, y=1)])


def test_cycles_and_excessive_depth_are_rejected_without_recursing_forever():
    cyclic = {}
    cyclic["cycle"] = cyclic
    assert evaluate(cyclic, {}).reason == "invalid_artifact"


def test_unicode_expansion_beyond_output_limit_abstains():
    artifact = synthesize({"inputs": {"code": {"type": "string", "max_length": 1024}},
                           "output_type": "string"},
                          [row("AB", code="ab"), row("ÉC", code="éc")])
    assert evaluate(artifact, {"code": "ß" * 1024}).reason == "outside_domain"


def test_finite_grammar_agreement_is_not_a_claim_about_unknown_business_truth():
    # The caller supplies these labels. Neither the learner nor its digest can
    # establish that this multiplication is the customer's actual pricing rule.
    artifact = arithmetic()
    assert set(artifact) == {"schema", "spec", "examples", "candidates", "examples_sha256",
                             "example_count", "artifact_sha256"}
    assert "accuracy" not in artifact and "verified_business_rule" not in artifact
