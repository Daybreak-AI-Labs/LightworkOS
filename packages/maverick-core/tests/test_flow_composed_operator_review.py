"""Independent, uncompressed tree oracle for composed scalar learning.

The reference enumerator intentionally never groups training vectors, removes
commutative variants, or calls a production enumeration/evaluation helper.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
from functools import lru_cache

import pytest
from maverick.flow import composed_operator as engine

_KINDS = ("boolean", "integer", "string")
_INVALID = object()
_SIGNATURES = (
    *((name, ("string",), "string") for name in ("strip", "lower", "upper")),
    ("not", ("boolean",), "boolean"),
    *((name, ("integer", "integer"), "integer")
      for name in ("add", "sub", "mul", "min", "max")),
    *(("eq", (kind, kind), "boolean") for kind in _KINDS),
    *((name, ("integer", "integer"), "boolean") for name in ("lt", "le")),
    *(("if", ("boolean", kind, kind), kind) for kind in _KINDS),
)
_ALL_OPERATORS = sorted({signature[0] for signature in _SIGNATURES})


def _key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _row(output, **inputs):
    return {"inputs": inputs, "output": output}


def _integers(*names, low=-3, high=4):
    return {name: {"type": "integer", "min": low, "max": high} for name in names}


def _kind(value):
    return {bool: "boolean", int: "integer", str: "string"}[type(value)]


def _bounded(value):
    if type(value) is bool:
        return value
    if type(value) is int:
        return value if abs(value) <= 10**24 else _INVALID
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError:
            return _INVALID
        return value if len(value) <= 1024 else _INVALID
    return _INVALID


def _run(tree, inputs):
    """Interpret complete trees with bounded intermediate values and lazy if."""
    op, *args = tree
    if op == "field":
        return inputs[args[0]]
    if op == "literal":
        return args[1]  # The explicit kind keeps False and 0 distinct tree atoms.
    if op == "if":
        condition = _run(args[0], inputs)
        if condition is _INVALID:
            return _INVALID
        assert type(condition) is bool
        return _run(args[1] if condition else args[2], inputs)
    values = [_run(child, inputs) for child in args]
    if any(value is _INVALID for value in values):
        return _INVALID
    operations = {
        "strip": lambda a: a.strip(), "upper": lambda a: a.upper(),
        "lower": lambda a: a.lower(), "not": lambda a: not a,
        "add": lambda a, b: a + b, "sub": lambda a, b: a - b,
        "mul": lambda a, b: a * b, "min": min, "max": max,
        "eq": lambda a, b: a == b, "lt": lambda a, b: a < b,
        "le": lambda a, b: a <= b,
    }
    return _bounded(operations[op](*values))


def _compositions(total, arity):
    if arity == 1:
        yield (total,)
        return
    for first in range(total + 1):
        for remaining in _compositions(total - first, arity - 1):
            yield (first, *remaining)


@lru_cache(maxsize=20)
def _trees(spec_json, maximum, operators):
    """All ordered typed trees by exact operation count, without pruning."""
    spec = json.loads(spec_json)
    levels = [{kind: [] for kind in _KINDS} for _ in range(maximum + 1)]
    for name, definition in sorted(spec["inputs"].items()):
        levels[0][definition["type"]].append(("field", name))
    constants = {_key(value): value for value in spec.get("constants", [])}
    for key in sorted(constants):
        value = constants[key]
        levels[0][_kind(value)].append(("literal", _kind(value), value))
    for cost in range(1, maximum + 1):
        for op, operands, result in _SIGNATURES:
            if op not in operators:
                continue
            for allocation in _compositions(cost - 1, len(operands)):
                groups = [levels[child_cost][kind]
                          for child_cost, kind in zip(allocation, operands, strict=True)]
                for children in itertools.product(*groups):
                    levels[cost][result].append((op, *children))
    flattened = tuple(tree for level in levels for tree in level[spec["output_type"]])
    # This assertion guards the test oracle's derivation counting itself.
    assert len(flattened) == len({_key(tree) for tree in flattened})
    return flattened


def _consistent(spec, examples, maximum, operators):
    survivors = []
    for tree in _trees(_key(spec), maximum, tuple(sorted(operators))):
        outputs = [_run(tree, example["inputs"]) for example in examples]
        if all(output is not _INVALID and _key(output) == _key(example["output"])
               for output, example in zip(outputs, examples, strict=True)):
            survivors.append(tree)
    return survivors


def _partitions(trees, inputs):
    result = {}
    for tree in trees:
        output = _run(tree, inputs)
        if output is _INVALID:
            return None
        key = _key(output)
        result.setdefault(key, {"output": output, "candidate_count": 0})
        result[key]["candidate_count"] += 1
    return [result[key] for key in sorted(result)]


def _assert_partition(artifact, trees, inputs):
    expected = _partitions(trees, inputs)
    assert engine.partitions(artifact, inputs) == expected
    decision = engine.evaluate(artifact, inputs)
    assert decision.candidate_count == len(trees)
    assert decision.artifact_digest == artifact["artifact_sha256"]
    if expected is not None and len(expected) == 1:
        assert decision.applied is True and decision.reason == "agreement"
        assert type(decision.value) is type(expected[0]["output"])
        assert decision.value == expected[0]["output"]
    else:
        assert decision.applied is False
        assert decision.reason == ("outside_domain" if expected is None else "ambiguity")


def _assert_exact(spec, examples, maximum, operators, probes):
    artifact = engine.synthesize(spec, examples, max_operations=maximum, operators=operators)
    trees = _consistent(spec, examples, maximum, operators)
    assert trees, "the test fixture must retain at least one complete syntax tree"
    assert artifact["schema"] == "lightwork.composed-operator.v1"
    assert engine.validate_artifact(artifact) is None
    assert engine.candidate_count(artifact) == len(trees)
    assert type(engine.evaluation_cost(artifact)) is int
    assert engine.evaluation_cost(artifact) > 0
    for inputs in probes:
        _assert_partition(artifact, trees, inputs)
    return artifact, trees


@pytest.mark.parametrize("maximum", [1, 2, 3, 4])
def test_all_nested_products_preserve_same_training_different_unseen_trees(maximum):
    spec = {"inputs": _integers("x"), "output_type": "integer"}
    examples = [_row(0, x=0), _row(1, x=1)]
    artifact, trees = _assert_exact(spec, examples, maximum, ["mul"],
                                   [{"x": value} for value in range(-3, 5)])
    # Every binary shape remains; training-vector equivalence never proves x == x*x.
    assert len(trees) == [2, 4, 9, 23][maximum - 1]
    assert engine.evaluate(artifact, {"x": 2}).reason == "ambiguity"


@pytest.mark.parametrize("maximum", [1, 2, 3])
def test_ordered_commutative_trees_and_constant_only_arithmetic_count(maximum):
    spec = {"inputs": _integers("x", "y"), "output_type": "integer", "constants": [0]}
    examples = [_row(0, x=0, y=0), _row(0, x=1, y=1)]
    _assert_exact(spec, examples, maximum, ["mul"],
                  [{"x": x, "y": y} for x, y in itertools.product((-2, 0, 3), repeat=2)])


@pytest.mark.parametrize("maximum", [2, 3, 4])
def test_multistep_text_normalization_all_orderings_and_unicode(maximum):
    spec = {"inputs": {"text": {"type": "string", "max_length": 30}},
            "output_type": "string", "constants": ["junk"]}
    examples = [_row("A", text=" a "), _row("B", text=" b ")]
    _assert_exact(spec, examples, maximum, ["strip", "lower", "upper"],
                  [{"text": value} for value in (" ss ", " ßx ", "\tÉcole\n", "", "İx")])


@pytest.mark.parametrize("output", ["boolean", "integer", "string"])
def test_every_default_operator_matches_small_unpruned_grammar(output):
    spec = {"inputs": {**_integers("x", "y"), "flag": {"type": "boolean"},
                       "text": {"type": "string", "max_length": 8}},
            "output_type": output, "constants": [False, 0, 1, "fixed"]}
    labels = {"boolean": (False, True), "integer": (0, 1), "string": ("a", "B")}
    examples = [_row(labels[output][0], x=0, y=0, flag=False, text="a"),
                _row(labels[output][1], x=1, y=1, flag=True, text="B")]
    probes = [{"x": x, "y": y, "flag": flag, "text": text}
              for x, y, flag, text in itertools.product((-1, 2), (0, 3), (False, True), ("A", "z"))]
    artifact, trees = _assert_exact(spec, examples, 1, _ALL_OPERATORS, probes)
    default = engine.synthesize(spec, examples, max_operations=1)
    assert default == artifact
    assert engine.candidate_count(default) == len(trees)


def test_nested_comparison_and_boolean_negation_keep_exact_typed_counts():
    spec = {"inputs": {**_integers("x", low=0, high=3), "flag": {"type": "boolean"}},
            "output_type": "boolean", "constants": [False, True, 0, 1]}
    examples = [_row(True, x=0, flag=False), _row(False, x=1, flag=True)]
    _assert_exact(spec, examples, 2, ["eq", "not", "lt", "le"],
                  [{"x": x, "flag": flag} for x, flag in itertools.product(range(4), (False, True))])


def test_condition_can_be_composed_and_branch_order_is_not_collapsed():
    spec = {"inputs": _integers("x"), "output_type": "integer", "constants": [-1, 0, 1]}
    examples = [_row(-1, x=-2), _row(1, x=2)]
    _assert_exact(spec, examples, 2, ["lt", "if"],
                  [{"x": value} for value in range(-3, 5)])


@pytest.mark.parametrize("output", ["boolean", "integer", "string"])
def test_all_operator_two_step_compositions_match_uncompressed_oracle(output):
    spec = {"inputs": {**_integers("x"), "flag": {"type": "boolean"},
                       "text": {"type": "string", "max_length": 12}},
            "output_type": output, "constants": [0, False, ""]}
    labels = {"boolean": (False, True), "integer": (0, 1), "string": ("a", "B")}
    examples = [_row(labels[output][0], x=0, flag=False, text="a"),
                _row(labels[output][1], x=1, flag=True, text="B")]
    probes = [{"x": x, "flag": flag, "text": text}
              for x, flag, text in itertools.product((-2, 0, 3), (False, True), (" A ", "ß"))]
    _assert_exact(spec, examples, 2, _ALL_OPERATORS, probes)


def test_repeated_group_references_are_independent_tree_occurrences():
    spec = {"inputs": {**_integers("x"), "flag": {"type": "boolean"}},
            "output_type": "integer", "constants": [0, False, True]}
    examples = [_row(0, x=0, flag=True), _row(1, x=1, flag=True)]
    _assert_exact(spec, examples, 3, ["mul", "not", "if"],
                  [{"x": x, "flag": flag} for x, flag in itertools.product((-2, 0, 3), (False, True))])


def test_lazy_if_retains_invalid_inactive_training_subtree():
    spec = {"inputs": {"text": {"type": "string", "max_length": 1024},
                       "flag": {"type": "boolean"}}, "output_type": "string"}
    examples = [_row("ß" * 600, text="ß" * 600, flag=True),
                _row("ß" * 601, text="ß" * 601, flag=True)]
    artifact, trees = _assert_exact(spec, examples, 2, ["upper", "if"],
                                   [{"text": "ß" * 602, "flag": True},
                                    {"text": "ß" * 602, "flag": False},
                                    {"text": "mixed", "flag": False}])
    lazy = ("if", ("field", "flag"), ("field", "text"), ("upper", ("field", "text")))
    assert lazy in trees
    assert engine.evaluate(artifact, {"text": "ß" * 602, "flag": True}).applied
    assert engine.evaluate(artifact, {"text": "ß" * 602, "flag": False}).reason == "outside_domain"


def test_intermediate_overflow_is_not_erased_by_multiplying_zero():
    spec = {"inputs": _integers("x", low=0, high=10**12),
            "output_type": "integer", "constants": [0]}
    examples = [_row(0, x=0), _row(0, x=1)]
    artifact, trees = _assert_exact(spec, examples, 3, ["mul"],
                                   [{"x": 2}, {"x": 10**12}])
    bad = ("mul", ("literal", "integer", 0),
           ("mul", ("field", "x"), ("mul", ("field", "x"), ("field", "x"))))
    assert bad in trees and _run(bad, {"x": 10**12}) is _INVALID
    assert engine.partitions(artifact, {"x": 10**12}) is None
    assert engine.evaluate(artifact, {"x": 10**12}).applied is False


def test_refinement_is_exact_filter_of_original_complete_trees_and_immutable():
    spec = {"inputs": _integers("x"), "output_type": "integer"}
    examples = [_row(0, x=0), _row(1, x=1)]
    old, trees = _assert_exact(spec, examples, 4, ["mul"], [{"x": 2}])
    before = copy.deepcopy(old)
    new = engine.refine(old, [_row(8, x=2)])
    retained = [tree for tree in trees if _run(tree, {"x": 2}) == 8]
    assert len(retained) == 2  # (x*x)*x and x*(x*x), both retained.
    assert old == before and new["artifact_sha256"] != old["artifact_sha256"]
    assert engine.candidate_count(new) == len(retained)
    for value in range(-3, 5):
        _assert_partition(new, retained, {"x": value})
    with pytest.raises(ValueError):
        engine.refine(old, [_row(7, x=2)])
    assert old == before


@pytest.mark.parametrize("maximum", [True, False, 0, 5, 2.0, "2", None])
def test_operation_bound_is_strict_integer(maximum):
    with pytest.raises(ValueError):
        engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                          [_row(0, x=0), _row(1, x=1)], max_operations=maximum)


@pytest.mark.parametrize("operators", [["eval"], ["concat"], "mul", [1], {"mul": True}])
def test_operator_whitelist_rejects_unsupported_or_untyped_values(operators):
    with pytest.raises(ValueError):
        engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                          [_row(0, x=0), _row(1, x=1)], operators=operators)


@pytest.mark.parametrize("value", [True, False, 1.0, "1", None, [], {}, 10**12 + 1])
def test_runtime_never_coerces_integer_type_or_declared_bound(value):
    artifact = engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                                 [_row(0, x=0), _row(1, x=1)], max_operations=1, operators=["mul"])
    assert engine.partitions(artifact, {"x": value}) is None
    assert engine.evaluate(artifact, {"x": value}).reason == "outside_domain"


def test_boolean_and_integer_training_labels_are_not_interchangeable():
    with pytest.raises(ValueError):
        engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                          [_row(False, x=0), _row(True, x=1)], operators=["mul"])


def test_training_order_and_exact_duplicate_demonstrations_do_not_change_artifact():
    spec = {"inputs": _integers("x"), "output_type": "integer"}
    examples = [_row(0, x=0), _row(1, x=1)]
    first = engine.synthesize(spec, examples, max_operations=2, operators=["mul", "add"])
    again = engine.synthesize(spec, [examples[1], examples[0], examples[1]],
                              max_operations=2, operators=["add", "mul"])
    assert first == again
    with pytest.raises(ValueError):
        engine.refine(first, [_row(2, x=1)])


def _rehash(artifact):
    payload = {key: value for key, value in artifact.items() if key != "artifact_sha256"}
    artifact["artifact_sha256"] = hashlib.sha256(_key(payload).encode("utf-8")).hexdigest()
    return artifact


@pytest.mark.parametrize("mutation", ["schema", "examples", "unknown_key", "operators", "budget"])
def test_rehash_cannot_make_inconsistent_artifact_valid(mutation):
    artifact = engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                                 [_row(0, x=0), _row(1, x=1)], max_operations=2, operators=["mul"])
    changed = copy.deepcopy(artifact)
    if mutation == "schema":
        changed["schema"] = "lightwork.composed-operator.v99"
    elif mutation == "examples":
        changed["examples"][0]["output"] = 99
    elif mutation == "unknown_key":
        changed["unverified_program"] = ["literal", 99]
    elif mutation == "operators":
        changed["grammar"]["operators"] = ["add"]
    else:
        changed["grammar"]["max_operations"] = 1
    _rehash(changed)
    with pytest.raises(ValueError):
        engine.validate_artifact(changed)
    assert engine.evaluate(changed, {"x": 2}).reason == "invalid_artifact"
    assert engine.candidate_count(artifact) == 4


@pytest.mark.parametrize("mutation", ["count", "boolean_count", "state_count", "kind", "cost",
                                      "missing_alternative", "extra_alternative", "cycle",
                                      "duplicate_root", "examples_digest"])
def test_rehashed_packed_graph_tampering_is_reconstructed_and_rejected(mutation):
    artifact = engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                                 [_row(0, x=0), _row(1, x=1)], max_operations=3, operators=["mul"])
    # Warm validation first: caches must bind canonical content, not object identity.
    engine.validate_artifact(artifact)
    before = copy.deepcopy(artifact)
    if mutation == "count":
        artifact["candidate_count"] -= 1
    elif mutation == "boolean_count":
        artifact["candidate_count"] = True
    elif mutation == "state_count":
        artifact["states"][-1]["count"] -= 1
    elif mutation == "kind":
        artifact["states"][-1]["kind"] = "boolean"
    elif mutation == "cost":
        artifact["states"][-1]["cost"] = 0
    elif mutation == "missing_alternative":
        artifact["states"][-1]["alternatives"].pop()
    elif mutation == "extra_alternative":
        artifact["states"][-1]["alternatives"].append(["literal", 99])
    elif mutation == "cycle":
        artifact["states"][0]["alternatives"] = [["mul", 0, 0]]
    elif mutation == "duplicate_root":
        artifact["roots"].append(artifact["roots"][0])
    else:
        artifact["examples_sha256"] = "0" * 64
    _rehash(artifact)
    with pytest.raises(ValueError):
        engine.validate_artifact(artifact)
    assert engine.evaluate(artifact, {"x": 2}).reason == "invalid_artifact"
    assert engine.candidate_count(before) == 9


def test_artifact_and_cached_validation_results_are_caller_immutable():
    spec = {"inputs": _integers("x"), "output_type": "integer"}
    examples = [_row(0, x=0), _row(1, x=1)]
    artifact = engine.synthesize(spec, examples, max_operations=2, operators=["mul"])
    before = copy.deepcopy(artifact)
    engine.validate_artifact(artifact)
    result = engine.partitions(artifact, {"x": 2})
    assert result and len(result) > 1
    result[0]["candidate_count"] = 10**9
    result[0]["output"] = 99
    assert engine.partitions(artifact, {"x": 2}) != result
    spec["inputs"]["x"]["min"] = 2
    examples[0]["output"] = 99
    assert artifact == before
    assert engine.synthesize(before["spec"], before["examples"],
                             max_operations=2, operators=["mul"]) == before


@pytest.mark.parametrize("bad", [None, [], "{}", {"schema": engine.SCHEMA}])
def test_malformed_artifacts_abstain_without_running_any_tree(bad):
    with pytest.raises(ValueError):
        engine.validate_artifact(bad)
    assert engine.evaluate(bad, {"x": 2}).reason == "invalid_artifact"


@pytest.mark.parametrize("limit", ["MAX_PRODUCTIONS", "MAX_STATES", "MAX_TRAINING_EVALUATIONS"])
def test_synthesis_resource_exhaustion_never_returns_partial_version_space(monkeypatch, limit):
    monkeypatch.setattr(engine, limit, 1)
    with pytest.raises(engine.SynthesisLimit):
        engine.synthesize({"inputs": _integers("x", "y"), "output_type": "integer"},
                          [_row(0, x=0, y=0), _row(1, x=1, y=1)],
                          max_operations=2, operators=["mul"])


@pytest.mark.parametrize("limit,value", [("MAX_PREDICTION_EVALUATIONS", 0),
                                         ("MAX_PREDICTION_EVALUATIONS", 2),
                                         ("MAX_PREDICTION_VALUES", 2)])
def test_runtime_limits_abstain_even_if_already_visited_trees_agree(monkeypatch, limit, value):
    artifact = engine.synthesize({"inputs": _integers("x"), "output_type": "integer"},
                                 [_row(0, x=0), _row(1, x=1)], max_operations=4, operators=["mul"])
    engine.validate_artifact(artifact)
    before = copy.deepcopy(artifact)
    monkeypatch.setattr(engine, limit, 1)
    assert engine.partitions(artifact, {"x": value}) is None
    result = engine.evaluate(artifact, {"x": value})
    assert result.applied is False and result.reason == "evaluation_limit"
    assert result.candidate_count == 23 and result.artifact_digest == artifact["artifact_sha256"]
    assert artifact == before


def test_evaluation_cost_bounds_actual_distribution_work_without_mocking_evaluation(monkeypatch):
    spec = {"inputs": {**_integers("x", "y"), "flag": {"type": "boolean"}},
            "output_type": "integer", "constants": [0, False]}
    examples = [_row(0, x=0, y=0, flag=False), _row(1, x=1, y=1, flag=True)]
    artifact = engine.synthesize(spec, examples, max_operations=2, operators=["mul", "if", "not"])
    engine.validate_artifact(artifact)
    original = engine._Distribution.add
    observed = []

    def counting_add(self, destination, value, count):
        observed.append(1)
        return original(self, destination, value, count)

    monkeypatch.setattr(engine._Distribution, "add", counting_add)
    bound = engine.evaluation_cost(artifact)
    trees = _consistent(spec, examples, 2, ["mul", "if", "not"])
    for x, y, flag in itertools.product((-2, 0, 3), (-1, 0, 2), (False, True)):
        observed.clear()
        inputs = {"x": x, "y": y, "flag": flag}
        assert engine.partitions(artifact, inputs) == _partitions(trees, inputs)
        assert 0 < len(observed) <= bound


def test_unicode_and_cyclic_json_are_rejected_without_execution():
    spec = {"inputs": {"text": {"type": "string", "max_length": 10}}, "output_type": "string"}
    artifact = engine.synthesize(spec, [_row("A", text="a"), _row("B", text="b")],
                                 max_operations=2, operators=["upper"])
    assert engine.evaluate(artifact, {"text": "\ud800"}).reason == "outside_domain"
    changed = copy.deepcopy(artifact)
    changed["examples"][0]["output"] = "\ud800"
    assert engine.evaluate(changed, {"text": "a"}).reason == "invalid_artifact"
    cyclic = {"schema": engine.SCHEMA}
    cyclic["states"] = cyclic
    assert engine.evaluate(cyclic, {"text": "a"}).reason == "invalid_artifact"
