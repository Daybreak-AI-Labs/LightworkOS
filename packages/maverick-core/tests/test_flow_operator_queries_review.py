"""Independent witness, partition, coverage and tamper oracles for active learning."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json

import pytest
from maverick.flow import learned_operator as engine
from maverick.flow import operator_queries as queries


def _key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _row(output, **inputs):
    return {"inputs": inputs, "output": output}


def _ints(*names, low=0, high=3):
    return {name: {"type": "integer", "min": low, "max": high} for name in names}


def _run(program, inputs):
    """Independent interpreter, not the engine's execution helper."""
    op, *args = program
    if op == "field":
        return inputs[args[0]]
    if op == "literal":
        return args[0]
    if op == "if":
        branch = args[1] if _run(args[0], inputs) else args[2]
        return _run(branch, inputs)
    values = [_run(arg, inputs) for arg in args]
    operations = {
        "strip": lambda a: a.strip(), "upper": lambda a: a.upper(), "lower": lambda a: a.lower(),
        "not": lambda a: not a, "add": lambda a, b: a + b, "sub": lambda a, b: a - b,
        "mul": lambda a, b: a * b, "min": min, "max": max,
        "eq": lambda a, b: a == b, "lt": lambda a, b: a < b, "le": lambda a, b: a <= b,
    }
    return operations[op](*values)


def _partitions(artifact, inputs):
    outputs = {}
    for program in artifact["candidates"]:
        output = _run(program, inputs)
        key = _key(output)
        if key not in outputs:
            outputs[key] = {"output": output, "candidate_count": 0}
        outputs[key]["candidate_count"] += 1
    return [outputs[key] for key in sorted(outputs)]


def _small_domain(artifact):
    names, values = [], []
    for name, definition in artifact["spec"]["inputs"].items():
        names.append(name)
        if definition["type"] == "boolean":
            values.append([False, True])
        else:
            assert definition["type"] == "integer"
            values.append(range(definition["min"], definition["max"] + 1))
    return [dict(zip(names, items, strict=True)) for items in itertools.product(*values)]


def _question_hash(question):
    payload = {key: value for key, value in question.items() if key != "question_sha256"}
    return hashlib.sha256(_key(payload).encode("utf-8")).hexdigest()


def _ambiguous():
    return engine.synthesize({"inputs": _ints("x", "y"), "output_type": "integer"},
                             [_row(0, x=0, y=0), _row(1, x=1, y=1)])


def _assert_witness(artifact, question):
    assert question["status"] == "found"
    assert question["schema"] == "lightwork.operator-question.v1"
    assert question["artifact_sha256"] == artifact["artifact_sha256"]
    assert question["question_sha256"] == _question_hash(question)
    assert set(question["inputs"]) == set(artifact["spec"]["inputs"])
    assert question["predictions"] == _partitions(artifact, question["inputs"])
    counts = [partition["candidate_count"] for partition in question["predictions"]]
    assert len(counts) > 1
    assert sum(counts) == question["candidate_count"] == len(artifact["candidates"])
    assert question["worst_case_candidates"] == max(counts)
    assert engine.evaluate(artifact, question["inputs"]).reason == "ambiguity"


@pytest.mark.parametrize("case", ["integers", "booleans", "mixed"])
def test_full_domain_query_matches_independent_minimax_oracle(case):
    if case == "integers":
        artifact = _ambiguous()
    elif case == "booleans":
        artifact = engine.synthesize(
            {"inputs": {name: {"type": "boolean"} for name in ("a", "b")}, "output_type": "boolean"},
            [_row(False, a=False, b=False), _row(True, a=True, b=True)],
        )
    else:
        artifact = engine.synthesize(
            {"inputs": {**_ints("x", high=2), "flag": {"type": "boolean"}},
             "output_type": "integer", "constants": [0, 2]},
            [_row(0, x=0, flag=False), _row(1, x=1, flag=True)],
        )
    domain = _small_domain(artifact)
    options = []
    for inputs in domain:
        partitions = _partitions(artifact, inputs)
        if len(partitions) > 1:
            score = (max(row["candidate_count"] for row in partitions), -len(partitions), _key(inputs))
            options.append((score, inputs))
    assert options
    question = queries.propose_question(artifact, max_probes=len(domain))
    _assert_witness(artifact, question)
    assert question["inputs"] == min(options, key=lambda option: option[0])[1]
    coverage = question["coverage"]
    assert coverage["strategy"] == "exhaustive"
    assert coverage["domain_size"] == coverage["examined"] == len(domain)
    assert coverage["complete"] is True and coverage["invalid_probes"] == 0
    assert coverage["requested_probe_budget"] == coverage["effective_probe_budget"] == len(domain)
    assert queries.validate_question(artifact, question) is None
    assert queries.propose_question(copy.deepcopy(artifact), max_probes=len(domain)) == question


def test_equivalence_requires_full_coverage_not_exhaustion_of_a_probe_pool():
    artifact = engine.synthesize({"inputs": _ints("x", low=1, high=3), "output_type": "integer"},
                                 [_row(1, x=1), _row(2, x=2)])
    assert len(artifact["candidates"]) > 1  # Different syntax, identical values throughout this domain.
    full = queries.propose_question(artifact, max_probes=3)
    assert full["status"] == "equivalent"
    assert full["coverage"]["complete"] is True and full["coverage"]["examined"] == 3
    partial = queries.propose_question(artifact, max_probes=2)
    assert partial["status"] == "search_exhausted"
    assert partial["coverage"]["complete"] is False
    assert partial["coverage"]["examined"] <= 2
    for question in (full, partial):
        assert "inputs" not in question
        assert question["predictions"] == [] and question["worst_case_candidates"] is None
        with pytest.raises(ValueError):
            queries.answer_question(artifact, question, 1)


@pytest.mark.parametrize("strings", [False, True])
def test_single_survivor_in_large_domain_is_not_global_execution_proof(strings):
    if strings:
        artifact = engine.synthesize(
            {"inputs": {"text": {"type": "string", "max_length": 1024}}, "output_type": "string"},
            [_row("A", text="a"), _row("B", text="b")],
        )
    else:
        artifact = engine.synthesize(
            {"inputs": _ints("x", high=10**12), "output_type": "integer"},
            [_row(0, x=0), _row(1, x=1), _row(4, x=2)],
        )
    assert len(artifact["candidates"]) == 1
    question = queries.propose_question(artifact, max_probes=16)
    assert question["status"] == "search_exhausted"
    assert question["coverage"]["strategy"] == "bounded"
    assert question["coverage"]["complete"] is False
    assert question["coverage"]["domain_size"] == (None if strings else 10**12 + 1)


def test_nonlinear_witness_leaves_the_training_roots_zero_and_one():
    artifact = engine.synthesize(
        {"inputs": _ints("x", low=-(10**12), high=10**12), "output_type": "integer"},
        [_row(0, x=0), _row(1, x=1)],
    )
    assert ["field", "x"] in artifact["candidates"]
    assert ["mul", ["field", "x"], ["field", "x"]] in artifact["candidates"]
    question = queries.propose_question(artifact, max_probes=32)
    _assert_witness(artifact, question)
    assert question["inputs"]["x"] not in (0, 1)
    assert question["coverage"]["complete"] is False


def test_bounded_search_finds_exact_unobserved_threshold_boundary():
    boundary = 400_000_000_003
    artifact = engine.synthesize(
        {"inputs": _ints("amount", high=10**12), "output_type": "string",
         "constants": [boundary, "low", "high"]},
        [_row("low", amount=0), _row("high", amount=10**12)],
    )
    question = queries.propose_question(artifact, max_probes=32)
    _assert_witness(artifact, question)
    assert question["inputs"] == {"amount": boundary}


def test_field_comparison_queries_synchronize_overlapping_domains():
    artifact = engine.synthesize(
        {"inputs": {**_ints("x", low=100, high=10**12), **_ints("y", high=10**12 - 100)},
         "output_type": "boolean"},
        [_row(True, x=100, y=101), _row(False, x=102, y=101)],
    )
    question = queries.propose_question(artifact, max_probes=64)
    _assert_witness(artifact, question)
    assert question["inputs"]["x"] == question["inputs"]["y"]
    assert 100 <= question["inputs"]["x"] <= 10**12 - 100
    assert all(type(row["output"]) is bool for row in question["predictions"])


def test_string_question_is_a_valid_witness_without_alphabet_completeness_claim():
    artifact = engine.synthesize(
        {"inputs": {"text": {"type": "string", "max_length": 3}}, "output_type": "string"},
        [_row("a", text="a"), _row("b", text="b")],
    )
    question = queries.propose_question(artifact, max_probes=64)
    _assert_witness(artifact, question)
    assert len(question["inputs"]["text"]) <= 3
    question["inputs"]["text"].encode("utf-8")
    assert question["coverage"]["domain_size"] is None
    assert question["coverage"]["complete"] is False


@pytest.mark.parametrize("budget", [True, False, 0, -1, 1.0, None, "2", 4097])
def test_probe_budget_is_strict_and_bounded(budget):
    with pytest.raises(ValueError):
        queries.propose_question(_ambiguous(), max_probes=budget)


def test_candidate_evaluation_budget_reduces_the_effective_probe_cap():
    artifact = engine.synthesize(
        {"inputs": _ints("a", "b", "c", "d", high=20), "output_type": "integer"},
        [_row(0, a=0, b=0, c=0, d=0), _row(1, a=1, b=1, c=1, d=1)],
    )
    assert len(artifact["candidates"]) > 1_000_000 // 4096
    question = queries.propose_question(artifact, max_probes=4096)
    coverage = question["coverage"]
    expected = 1_000_000 // len(artifact["candidates"])
    assert coverage["requested_probe_budget"] == 4096
    assert coverage["effective_probe_budget"] == expected < 4096
    assert 0 <= coverage["examined"] <= expected
    assert coverage["examined"] * len(artifact["candidates"]) <= 1_000_000
    assert coverage["domain_size"] == 21**4 and coverage["complete"] is False


def test_huge_cartesian_domain_is_capped_without_claiming_json_sized_cardinality():
    names = ("a", "b", "c", "d", "e", "f")
    artifact = engine.synthesize(
        {"inputs": _ints(*names, low=-(10**12), high=10**12),
         "output_type": "boolean", "constants": [0, False, True]},
        [{"inputs": dict.fromkeys(names, 0), "output": True},
         {"inputs": dict.fromkeys(names, 1), "output": False}],
    )
    question = queries.propose_question(artifact, max_probes=4)
    coverage = question["coverage"]
    assert coverage["domain_size"] is None and coverage["strategy"] == "bounded"
    assert coverage["complete"] is False and coverage["examined"] <= 4
    assert question["status"] != "equivalent"


@pytest.mark.parametrize("damage", [
    lambda question: question["predictions"][0].update(candidate_count=0),
    lambda question: question["predictions"][0].update(output="FORGED"),
    lambda question: question.update(worst_case_candidates=0),
    lambda question: question["coverage"].update(examined=False),
    lambda question: question.update(candidate_count=True),
    lambda question: question.update(artifact_sha256="0" * 64),
    lambda question: question.update(inputs={"x": 0, "y": 0}),
    lambda question: question.update(extra="untrusted"),
])
def test_rehashed_question_tampering_cannot_rewrite_witness_evidence(damage):
    artifact = _ambiguous()
    question = queries.propose_question(artifact)
    damage(question)
    question["question_sha256"] = _question_hash(question)
    with pytest.raises(ValueError):
        queries.validate_question(artifact, question)
    with pytest.raises(ValueError):
        queries.answer_question(artifact, question, 0)


def test_answer_refines_exact_old_question_without_mutating_or_relabeling_evidence():
    artifact = _ambiguous()
    before = copy.deepcopy(artifact)
    question = queries.propose_question(artifact)
    before_question = copy.deepcopy(question)
    output = question["predictions"][0]["output"]
    expected_candidates = {_key(program) for program in artifact["candidates"]
                           if _key(_run(program, question["inputs"])) == _key(output)}
    updated = queries.answer_question(artifact, question, output)
    assert {_key(program) for program in updated["candidates"]} == expected_candidates
    assert len(updated["candidates"]) == question["predictions"][0]["candidate_count"]
    assert {_key(row) for row in updated["examples"]} == {
        *(_key(row) for row in artifact["examples"]),
        _key({"inputs": question["inputs"], "output": output}),
    }
    assert len(updated["candidates"]) < len(artifact["candidates"])
    assert artifact == before and question == before_question
    with pytest.raises(ValueError):
        queries.validate_question(updated, question)
    result = engine.evaluate(updated, question["inputs"])
    assert result.applied and type(result.value) is type(output) and result.value == output


@pytest.mark.parametrize("output", [True, 2.0, "2", None, 999])
def test_answer_rejects_wrong_type_or_unsupported_label_without_altering_prior(output):
    artifact = _ambiguous()
    before = copy.deepcopy(artifact)
    question = queries.propose_question(artifact)
    with pytest.raises(ValueError):
        queries.answer_question(artifact, question, output)
    assert artifact == before


def test_public_mutation_cannot_poison_question_cache_or_validate_deleted_candidates():
    artifact = _ambiguous()
    question = queries.propose_question(artifact)
    original = copy.deepcopy(question)
    queries.validate_question(artifact, question)
    question["inputs"]["x"] = -999
    question["predictions"].clear()
    question["coverage"]["complete"] = "forged"
    assert queries.propose_question(artifact) == original
    assert queries.validate_question(artifact, original) is None
    artifact["candidates"] = [["field", "x"]]
    artifact["artifact_sha256"] = hashlib.sha256(_key({
        key: value for key, value in artifact.items() if key != "artifact_sha256"
    }).encode()).hexdigest()
    with pytest.raises(ValueError):
        queries.propose_question(artifact)
    with pytest.raises(ValueError):
        queries.validate_question(artifact, original)
