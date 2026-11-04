"""Check recipe projections against the independent uncompressed tree oracle.

The reference is the existing test-only complete typed-tree enumerator. It does
not use the production compiler, training-vector packing, catalog or evaluator.
"""
from __future__ import annotations

import copy
import importlib.util
import itertools
import json
from pathlib import Path

import pytest
from maverick.flow import action_recipe, action_recipe_transforms, composed_operator

_reference_spec = importlib.util.spec_from_file_location(
    "action_transforms_independent_reference", Path(__file__).with_name("test_flow_composed_operator_review.py"))
_reference = importlib.util.module_from_spec(_reference_spec)
_reference_spec.loader.exec_module(_reference)


def _obj(**properties):
    return {"type": "object", "properties": properties, "required": sorted(properties),
            "additionalProperties": False}


def _scalar(kind):
    if kind == "integer":
        return {"type": kind, "minimum": -10**12, "maximum": 10**12}
    if kind == "string":
        return {"type": kind, "maxLength": 1024}
    return {"type": kind}


def _example(index, kind):
    value = {"integer": index, "boolean": bool(index), "string": ("a", "B")[index]}[kind]
    return {"id": str(index),
            "inputs": {"a.b": [index], "a": {"b": index}, "flag": bool(index), "text": ("a", "B")[index]},
            "steps": [{"tool": "observe", "arguments": {"out": value}, "result": {"other": value}},
                      {"tool": "act", "arguments": {"out": value}, "result": {"done": True}}]}


def _domain(kind):
    return {"inputs": _obj(**{
        "a": _obj(b=_scalar("integer")),
        "a.b": {"type": "array", "items": _scalar("integer"), "minItems": 1, "maxItems": 1},
        "flag": _scalar("boolean"), "text": _scalar("string"),
    }), "steps": [
        {"arguments": _obj(out=_scalar(kind)), "result": _obj(other=_scalar(kind))},
        {"arguments": _obj(out=_scalar(kind)), "result": _obj(done=_scalar("boolean"))},
    ]}


@pytest.mark.parametrize("kind", ["integer", "boolean", "string"])
def test_every_two_operation_tree_survives_catalog_projection_and_matches_partitions(kind):
    examples = [_example(index, kind) for index in range(2)]
    artifact = action_recipe_transforms.synthesize_transformed(
        examples, allowed_tools=["observe", "act"], domain=_domain(kind), max_operations=2,
        constants=[0, False, ""])
    action_recipe.validate_artifact(artifact)
    expected_catalog = [
        {"name": "v000", "source": "input", "path": ["a", "b"]},
        {"name": "v001", "source": "input", "path": ["a.b", 0]},
        {"name": "v002", "source": "input", "path": ["flag"]},
        {"name": "v003", "source": "input", "path": ["text"]},
    ]
    total_count = 0
    for index, step in enumerate(artifact["steps"]):
        catalog = expected_catalog + ([{"name": "v004", "source": "result", "step": 0,
                                       "path": ["other"]}] if index else [])
        assert step["catalog"] == catalog
        declaration = {"v000": {"type": "integer", "min": -10**12, "max": 10**12},
                       "v001": {"type": "integer", "min": -10**12, "max": 10**12},
                       "v002": {"type": "boolean"}, "v003": {"type": "string", "max_length": 1024}}
        if index:
            declaration["v004"] = {"integer": declaration["v000"], "boolean": declaration["v002"],
                                   "string": declaration["v003"]}[kind]
        spec = {"inputs": declaration, "output_type": kind, "constants": ["", 0, False]}
        rows = []
        for number, example in enumerate(examples):
            values = {"v000": number, "v001": number, "v002": bool(number), "v003": ("a", "B")[number]}
            if index:
                values["v004"] = example["steps"][0]["result"]["other"]
            rows.append({"inputs": values, "output": example["steps"][index]["arguments"]["out"]})
        binding = step["bindings"][0]
        child = binding["artifact"]
        assert binding["kind"] == "composed" and binding["path"] == ["out"]
        assert child["spec"] == spec
        assert sorted(child["examples"], key=lambda row: row["inputs"]["v000"]) == rows
        trees = _reference._consistent(spec, rows, 2, _reference._ALL_OPERATORS)
        assert binding["candidate_count"] == child["candidate_count"] == len(trees)
        assert len(trees) > 1
        total_count += len(trees)
        for number, flag, text in itertools.product((-2, 0, 3), (False, True), (" X ", "ß")):
            other = {"integer": number + 1, "boolean": not flag, "string": "Different"}[kind]
            values = {"v000": number, "v001": number + 1, "v002": flag, "v003": text}
            if index:
                values["v004"] = other
            reference = _reference._partitions(trees, values)
            assert composed_operator.partitions(child, values) == reference
            inputs = {"a": {"b": number}, "a.b": [number + 1], "flag": flag, "text": text}
            decision = action_recipe.resolve_step(artifact, index, inputs, [{"other": other}] if index else [])
            assert decision.candidate_binding_count == artifact["candidate_binding_count"]
            if reference is not None and len(reference) == 1:
                assert decision.applied is True and decision.arguments == {"out": reference[0]["output"]}
            else:
                assert decision.applied is False
                assert decision.reason == ("outside_domain" if reference is None else "ambiguity")
    assert artifact["candidate_binding_count"] == total_count
    reordered = copy.deepcopy(examples)
    for example in reordered:
        example["inputs"] = dict(reversed(list(example["inputs"].items())))
    rebuilt = action_recipe_transforms.synthesize_transformed(
        reordered[::-1], allowed_tools=["act", "observe"], domain=_domain(kind),
        max_operations=2, constants=[False, "", 0])
    assert rebuilt == artifact


def test_lazy_invalid_branch_remains_a_candidate_and_can_prevent_later_agreement():
    text = _scalar("string")
    domain = {"inputs": _obj(flag=_scalar("boolean"), text=text), "steps": [
        {"arguments": _obj(text=text), "result": _obj()},
        {"arguments": _obj(text=text), "result": _obj()},
    ]}
    episodes = [{"id": str(index), "inputs": {"flag": True, "text": "ß" * (600 + index)},
                 "steps": [{"tool": tool, "arguments": {"text": "ß" * (600 + index)}, "result": {}}
                           for tool in ("observe", "act")]} for index in range(2)]
    artifact = action_recipe_transforms.synthesize_transformed(
        episodes, allowed_tools=["observe", "act"], domain=domain, max_operations=2,
        operators=["upper", "if"])
    child = artifact["steps"][0]["bindings"][0]["artifact"]
    spec = {"inputs": {"v000": {"type": "boolean"}, "v001": {"type": "string", "max_length": 1024}},
            "output_type": "string", "constants": []}
    rows = [{"inputs": {"v000": True, "v001": "ß" * size}, "output": "ß" * size} for size in (600, 601)]
    trees = _reference._consistent(spec, rows, 2, ["upper", "if"])
    witness = ("if", ("field", "v000"), ("field", "v001"), ("upper", ("field", "v001")))
    assert witness in trees and len(trees) == child["candidate_count"]
    assert action_recipe.resolve_step(artifact, 0, {"flag": True, "text": "ß" * 602}, []).applied
    blocked = action_recipe.resolve_step(artifact, 0, {"flag": False, "text": "ß" * 602}, [])
    assert blocked.applied is False and blocked.reason == "outside_domain"


def test_recipe_artifact_size_counts_all_children_together(monkeypatch):
    # Compile normally first; a deliberately smaller transport bound must reject
    # the entire artifact even though its children each fit independently.
    episodes, domain = [_example(i, "integer") for i in range(2)], _domain("integer")
    kwargs = {"allowed_tools": ["observe", "act"], "domain": domain, "max_operations": 1,
              "operators": ["add"]}
    artifact = action_recipe_transforms.synthesize_transformed(episodes, **kwargs)
    child_size = max(len(json.dumps(binding["artifact"], separators=(",", ":")).encode())
                     for step in artifact["steps"] for binding in step["bindings"])
    monkeypatch.setattr(action_recipe_transforms, "MAX_ARTIFACT_BYTES", child_size + 32)
    with pytest.raises(ValueError):
        action_recipe_transforms.synthesize_transformed(episodes, **kwargs)


def test_refinement_is_exact_filter_of_prior_syntax_trees_including_seed_literals():
    integer = _scalar("integer")
    domain = {"inputs": _obj(x=integer), "steps": [
        {"arguments": _obj(out=integer), "result": _obj()},
        {"arguments": _obj(out=integer), "result": _obj()},
    ]}

    def episode(identity, value, target):
        return {"id": identity, "inputs": {"x": value}, "steps": [
            {"tool": tool, "arguments": {"out": target}, "result": {}} for tool in ("observe", "act")]}

    old = action_recipe_transforms.synthesize_transformed(
        [episode("a", -1, 1), episode("b", 0, 1)], allowed_tools=["observe", "act"],
        domain=domain, max_operations=2, operators=["max", "min", "add"])
    before = copy.deepcopy(old)
    new = action_recipe.refine(old, [episode("c", 2, 2)])
    assert old == before and new["grammar"] == old["grammar"] and new["domain"] == old["domain"]
    for index in range(2):
        old_child, new_child = (artifact["steps"][index]["bindings"][0]["artifact"] for artifact in (old, new))
        assert old_child["spec"] == new_child["spec"]
        trees = _reference._consistent(old_child["spec"], old_child["examples"], 2, ["max", "min", "add"])
        retained = [tree for tree in trees if _reference._run(tree, {"v000": 2}) == 2]
        assert ("max", ("field", "v000"), ("literal", "integer", 1)) in retained
        assert len(retained) == new_child["candidate_count"]
        for value in (-3, 0, 1, 2, 4):
            expected = _reference._partitions(retained, {"v000": value})
            assert composed_operator.partitions(new_child, {"v000": value}) == expected
            decision = action_recipe.resolve_step(new, index, {"x": value}, [{}] if index else [])
            if expected is not None and len(expected) == 1:
                assert decision.applied and decision.arguments == {"out": expected[0]["output"]}
            else:
                assert not decision.applied
