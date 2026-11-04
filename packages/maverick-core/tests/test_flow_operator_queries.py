"""End-to-end question/answer learning without a model or external effects."""
from __future__ import annotations

import copy
import itertools

import pytest
from maverick.flow.learned_operator import evaluate, synthesize
from maverick.flow.operator_queries import answer_question, propose_question, validate_question


def ambiguous():
    return synthesize({"inputs": {name: {"type": "integer", "min": 0, "max": 4}
                                  for name in ("x", "y")}, "output_type": "integer"},
                      [{"inputs": {"x": 0, "y": 0}, "output": 0},
                       {"inputs": {"x": 1, "y": 1}, "output": 1}])


def test_self_directed_questions_converge_to_reviewed_minimum_on_complete_domain():
    artifact = ambiguous()
    original = copy.deepcopy(artifact)
    lineage = []
    for _ in range(12):
        question = propose_question(artifact, max_probes=25)
        validate_question(artifact, question)
        assert question["coverage"]["complete"]
        if question["status"] == "equivalent":
            break
        assert question["status"] == "found"
        values = question["inputs"]
        # The label comes from an independent explicit test oracle, not from
        # picking the learner's most popular predicted answer.
        label = min(values["x"], values["y"])
        parent = artifact["artifact_sha256"]
        next_artifact = answer_question(artifact, question, label)
        assert next_artifact["artifact_sha256"] != parent
        assert len(next_artifact["candidates"]) < len(artifact["candidates"])
        assert next_artifact["example_count"] == artifact["example_count"] + 1
        expected = next(row["candidate_count"] for row in question["predictions"]
                        if row["output"] == label)
        assert len(next_artifact["candidates"]) == expected
        lineage.append((parent, question["question_sha256"], next_artifact["artifact_sha256"]))
        artifact = next_artifact
    else:
        pytest.fail("bounded finite-domain refinement failed to converge")
    assert lineage and original == ambiguous()
    for x, y in itertools.product(range(5), repeat=2):
        decision = evaluate(artifact, {"x": x, "y": y})
        assert decision.applied and decision.value == min(x, y)


def test_each_valid_answer_retains_exact_partition_and_does_not_modify_question():
    artifact = ambiguous()
    question = propose_question(artifact, max_probes=25)
    frozen = copy.deepcopy(question)
    for prediction in question["predictions"]:
        refined = answer_question(artifact, question, prediction["output"])
        assert len(refined["candidates"]) == prediction["candidate_count"]
        assert evaluate(refined, question["inputs"]).value == prediction["output"]
    assert question == frozen


def test_answer_outside_grammar_refuses_without_forgetting_prior_examples():
    artifact = ambiguous()
    question = propose_question(artifact, max_probes=25)
    original = copy.deepcopy(artifact)
    with pytest.raises(ValueError, match="no program"):
        answer_question(artifact, question, 1000)
    assert artifact == original


def test_refined_artifact_cannot_accept_a_stale_parent_question():
    artifact = ambiguous()
    question = propose_question(artifact, max_probes=25)
    refined = answer_question(artifact, question, question["predictions"][0]["output"])
    with pytest.raises(ValueError, match="does not match"):
        answer_question(refined, question, question["predictions"][0]["output"])


def test_cache_returns_independent_objects_and_never_trusts_changed_coverage():
    artifact = ambiguous()
    question = propose_question(artifact, max_probes=25)
    original = copy.deepcopy(question)
    question["inputs"]["x"] = 500
    question["predictions"][0]["candidate_count"] = 0
    question["coverage"]["complete"] = False
    assert propose_question(artifact, max_probes=25) == original
    with pytest.raises(ValueError):
        validate_question(artifact, question)


def test_zero_remaining_disagreement_cannot_manufacture_an_answer_request():
    artifact = synthesize({"inputs": {"x": {"type": "integer", "min": 0, "max": 1}},
                           "output_type": "integer"},
                          [{"inputs": {"x": 0}, "output": 0}, {"inputs": {"x": 1}, "output": 1}])
    question = propose_question(artifact, max_probes=2)
    assert question["status"] == "equivalent"
    assert "inputs" not in question and question["predictions"] == []
    with pytest.raises(ValueError, match="only a found"):
        answer_question(artifact, question, 1)
