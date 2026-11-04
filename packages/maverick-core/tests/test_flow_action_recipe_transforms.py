"""Pure complete transformed dataflow, admission boundaries and immutable evidence."""
from __future__ import annotations

import copy
import json

import pytest
from maverick.flow import action_recipe as recipe
from maverick.flow import action_recipe_transforms as transforms
from maverick.flow import composed_operator as composed


def schema(value):
    if type(value) is dict:
        return {"type": "object", "properties": {key: schema(item) for key, item in value.items()},
                "required": list(value), "additionalProperties": False}
    if type(value) is list:
        return {"type": "array", "items": schema(value[0]), "minItems": len(value), "maxItems": len(value)}
    if type(value) is int:
        return {"type": "integer", "minimum": -100, "maximum": 100}
    if type(value) is float:
        return {"type": "number", "minimum": -100.0, "maximum": 100.0}
    if type(value) is str:
        return {"type": "string", "maxLength": 64}
    return {"type": "boolean" if type(value) is bool else "null"}


def domain(episode):
    return {"inputs": schema(episode["inputs"]), "steps": [
        {"arguments": schema(step["arguments"]), "result": schema(step["result"])} for step in episode["steps"]]}


def episode(identity, a, b):
    return {"id": identity, "inputs": {"a": a, "b": b}, "steps": [
        {"tool": "lookup", "arguments": {"x": a}, "result": {"id": identity}},
        {"tool": "save", "arguments": {"x": a + b, "id": identity}, "result": {"ok": True}},
    ]}


def learn(episodes=None, **kwargs):
    episodes = episodes or [episode("first", 2, 2), episode("second", 3, 3)]
    options = {"allowed_tools": ["lookup", "save"], "domain": domain(episodes[0]),
               "max_operations": 1, "operators": ["add", "sub"]}
    options.update(kwargs)
    return transforms.synthesize_transformed(episodes, **options)


def rehash(artifact):
    artifact.pop("artifact_sha256")
    artifact["artifact_sha256"] = transforms._digest(artifact)
    return artifact


def test_all_coincident_paths_and_directed_expression_trees_survive():
    artifact = learn()
    assert artifact["schema"] == transforms.SCHEMA
    assert artifact["steps"][0]["catalog"] == [
        {"name": "v000", "source": "input", "path": ["a"]},
        {"name": "v001", "source": "input", "path": ["b"]},
    ]
    counts = [[binding["candidate_count"] for binding in step["bindings"]] for step in artifact["steps"]]
    assert counts == [[2], [1, 4]]
    assert artifact["candidate_binding_count"] == 7  # Sum, not Cartesian-product size.
    child = artifact["steps"][1]["bindings"][1]["artifact"]
    assert composed.partitions(child, {"v000": 2, "v001": 4, "v002": "fresh"}) == [
        {"output": 4, "candidate_count": 1}, {"output": 6, "candidate_count": 2},
        {"output": 8, "candidate_count": 1},
    ]
    assert transforms.resolve_step(artifact, 0, {"a": 2, "b": 4}, []).reason == "ambiguity"
    assert transforms.resolve_step(artifact, 1, {"a": 2, "b": 4}, [{"id": "fresh"}]).reason == "ambiguity"


def test_counterexample_refines_all_leaves_and_keeps_fresh_result_identity():
    artifact = learn()
    before = copy.deepcopy(artifact)
    refined = transforms.refine(artifact, [episode("counterexample", 2, 4)])
    assert artifact == before and refined["artifact_sha256"] != artifact["artifact_sha256"]
    assert refined["grammar"] == artifact["grammar"] and refined["domain"] == artifact["domain"]
    assert refined["candidate_binding_count"] == 4
    for a in range(1, 5):
        for b in range(1, 5):
            decision = transforms.resolve_step(refined, 1, {"a": a, "b": b}, [{"id": "newly-generated"}])
            assert decision.applied and decision.arguments == {"id": "newly-generated", "x": a + b}


def test_nested_array_paths_and_text_composition_without_a_mapping():
    rows = [{"id": str(index), "inputs": {"p": [{"raw": raw}]}, "steps": [
        {"tool": "lookup", "arguments": {"normalized": raw.strip().lower()}, "result": {"ref": f"r-{index}"}},
        {"tool": "save", "arguments": {"ref": f"r-{index}"}, "result": None},
    ]} for index, raw in enumerate((" Hello ", " WORLD "))]
    artifact = learn(rows, max_operations=2, operators=["strip", "lower", "upper"])
    assert artifact["steps"][0]["catalog"][0]["path"] == ["p", 0, "raw"]
    decision = transforms.resolve_step(artifact, 0, {"p": [{"raw": " NEW Customer "}]}, [])
    assert decision.applied and decision.arguments == {"normalized": "new customer"}
    assert transforms.resolve_step(artifact, 1, {"p": [{"raw": " different "}]}, [{"ref": "r-fresh"}]).arguments == {
        "ref": "r-fresh"}


def test_constant_and_copy_both_survive_even_with_distinct_other_inputs():
    rows = [episode("one", 2, 3), episode("two", 2, 4)]
    artifact = learn(rows, operators=["add", "mul"])
    binding = artifact["steps"][0]["bindings"][0]
    assert binding["candidate_count"] == 2
    assert binding["artifact"]["spec"]["constants"] == [2]
    assert transforms.resolve_step(artifact, 0, {"a": 9, "b": 4}, []).reason == "ambiguity"


def test_float_and_null_are_copy_only_with_strict_type_agreement():
    rows = [{"id": str(index), "inputs": {"n": index, "price": float(index), "absent": None}, "steps": [
        {"tool": "lookup", "arguments": {"price": float(index), "absent": None}, "result": {"price": float(index)}},
        {"tool": "save", "arguments": {"price": float(index)}, "result": None},
    ]} for index in (1, 2)]
    artifact = learn(rows, operators=["add"])
    assert [entry["path"] for entry in artifact["steps"][1]["catalog"]] == [["n"]]
    assert all(binding["kind"] == "copy" for step in artifact["steps"] for binding in step["bindings"])
    assert transforms.resolve_step(artifact, 0, {"n": 4, "price": 4.0, "absent": None}, []).arguments == {
        "price": 4.0, "absent": None}
    assert transforms.resolve_step(artifact, 1, {"n": 4, "price": 4.0, "absent": None}, [{"price": 5.0}]).reason == "ambiguity"
    assert transforms.resolve_step(artifact, 0, {"n": 4, "price": 4, "absent": None}, []).reason == "outside_domain"


@pytest.mark.parametrize("change", [
    lambda a: a["steps"][0]["catalog"].pop(),
    lambda a: a["steps"][0]["catalog"][0].update(source="result", step=0),
    lambda a: a["steps"][1]["catalog"][2].update(step=1),
    lambda a: a["steps"][0]["bindings"][0].update(candidate_count=1),
    lambda a: a["steps"][0]["bindings"][0]["artifact"]["states"][0]["alternatives"].pop(),
    lambda a: a["domain"]["inputs"].update(required=[]),
    lambda a: a["grammar"].update(unsupported_types="coerce"),
    lambda a: a["grammar"].update(seed_episode_ids=[]),
    lambda a: a["grammar"].update(seed_episode_ids=["first", "absent"]),
    lambda a: a["grammar"].update(seed_episode_ids=["first", "first"]),
    lambda a: a["grammar"].update(seed_episode_ids=["first", True]),
    lambda a: a.update(candidate_binding_count=1),
])
def test_rehashing_does_not_authenticate_pruned_or_remapped_alternatives(change):
    artifact = learn()
    change(artifact)
    rehash(artifact)
    with pytest.raises(ValueError):
        transforms.validate_artifact(artifact)
    assert transforms.resolve_step(artifact, 0, {"a": 2, "b": 2}, []).reason == "invalid_artifact"


def test_cached_validation_and_resolution_do_not_share_mutable_arguments():
    artifact = learn()
    transforms.validate_artifact(artifact)
    first = transforms.resolve_step(artifact, 1, {"a": 2, "b": 2}, [{"id": "new"}])
    first.arguments["id"] = "mutated"
    assert transforms.resolve_step(artifact, 1, {"a": 2, "b": 2}, [{"id": "new"}]).arguments["id"] == "new"
    artifact["steps"][0]["catalog"][0]["path"] = ["b"]
    assert transforms.resolve_step(artifact, 0, {"a": 2, "b": 2}, []).reason == "invalid_artifact"


@pytest.mark.parametrize("inputs,prior", [
    ({"a": True, "b": 2}, [{"id": "new"}]),
    ({"a": 101, "b": 2}, [{"id": "new"}]),
    ({"a": 2, "b": 2, "extra": 1}, [{"id": "new"}]),
    ({"a": 2, "b": 2}, [{"id": "x" * 65}]),
    ({"a": 2, "b": 2}, [{"id": "new", "extra": False}]),
    ({"a": 2, "b": 2}, []),
    ({"a": 2, "b": 2}, [{"id": "new"}, {"ok": True}]),
])
def test_all_supplied_input_and_prior_fields_must_be_in_domain(inputs, prior):
    assert transforms.resolve_step(learn(), 1, inputs, prior).reason == "outside_domain"


def test_argument_domain_is_checked_after_prediction():
    artifact = learn()
    assert transforms.resolve_step(artifact, 1, {"a": 60, "b": 60}, [{"id": "new"}]).reason == "outside_domain"


def test_last_result_and_reserved_completeness_markers_are_checked():
    rows = [episode("first", 2, 2), episode("second", 3, 3)]
    for row in rows:
        row["steps"][1]["result"] = {"total": 4, "pending": False}
    artifact = learn(rows)
    transforms.validate_result(artifact, 1, {"total": 5, "pending": False})
    for result in ({"total": 101, "pending": False}, {"total": True, "pending": False}, {"total": 5, "pending": True}):
        with pytest.raises(ValueError):
            transforms.validate_result(artifact, 1, result)


def test_seventh_source_is_rejected_instead_of_choosing_six():
    rows = [episode("first", 2, 2), episode("second", 3, 3)]
    for row in rows:
        row["inputs"].update({f"extra{index}": index for index in range(5)})
    with pytest.raises(ValueError, match="six eligible"):
        learn(rows)


def test_ninth_argument_leaf_refuses_before_any_child_synthesis(monkeypatch):
    rows = [episode("first", 2, 2), episode("second", 3, 3)]
    for row in rows:
        row["steps"][0]["arguments"] = {f"field{index}": row["inputs"]["a"] for index in range(8)}
    monkeypatch.setattr(composed, "synthesize", lambda *a, **k: pytest.fail("must count leaves before compilation"))
    with pytest.raises(ValueError, match="eight total"):
        learn(rows)


@pytest.mark.parametrize("change", [
    lambda d: d["inputs"]["properties"]["a"].update(minimum=-10**12-1),
    lambda d: d["inputs"]["properties"]["a"].update(maximum=10**12+1),
    lambda d: d["inputs"]["properties"]["a"].update(minimum=False),
    lambda d: d["inputs"]["properties"]["a"].update(type=["integer"]),
    lambda d: d["inputs"].update(additionalProperties=True),
    lambda d: d["inputs"].update(required=[]),
    lambda d: d["inputs"].update(**{"$ref": "https://not-fetched.invalid"}),
    lambda d: d["steps"][0]["result"]["properties"]["id"].update(pattern="(a+)+"),
    lambda d: d["steps"][0]["result"]["properties"]["id"].update(maxLength=1025),
    lambda d: d["steps"].pop(),
])
def test_complete_domains_are_closed_and_never_silently_clamped(change):
    declaration = domain(episode("first", 2, 2))
    change(declaration)
    with pytest.raises(ValueError):
        learn(domain=declaration)


def test_duplicate_projected_inputs_are_not_fabricated_into_evidence():
    with pytest.raises(ValueError, match="distinct input"):
        learn([episode("first", 2, 2), episode("second", 2, 2)])


@pytest.mark.parametrize("constants", [[0.5], [None], [10**12 + 1], list(range(9))])
def test_unsupported_explicit_constants_are_rejected(constants):
    with pytest.raises(ValueError):
        learn(constants=constants)


def test_stable_target_literal_is_not_dropped_when_it_overflows_pool():
    rows = [episode("first", 2, 3), episode("second", 2, 4)]
    with pytest.raises(ValueError, match="eight constants"):
        learn(rows, constants=[10, 11, 12, 13, 14, 15, 16, 17])


def test_synthesis_limit_never_returns_a_partial_artifact(monkeypatch):
    monkeypatch.setattr(composed, "MAX_PRODUCTIONS", 1)
    with pytest.raises(composed.SynthesisLimit):
        learn()


def test_per_step_prediction_budget_abstains_before_evaluating_any_leaf(monkeypatch):
    artifact = learn()
    transforms.validate_artifact(artifact)
    monkeypatch.setattr(composed, "evaluation_cost", lambda artifact: 60_000)
    monkeypatch.setattr(composed, "evaluate", lambda *a: pytest.fail("budget must be checked first"))
    decision = transforms.resolve_step(artifact, 1, {"a": 2, "b": 2}, [{"id": "new"}])
    assert not decision.applied and decision.arguments is None and decision.reason == "evaluation_limit"


def test_child_evaluation_limit_is_not_partial_agreement(monkeypatch):
    artifact = learn()
    transforms.validate_artifact(artifact)
    monkeypatch.setattr(composed, "MAX_PREDICTION_EVALUATIONS", 1)
    assert transforms.resolve_step(artifact, 1, {"a": 2, "b": 2}, [{"id": "new"}]).reason == "evaluation_limit"


def test_metadata_depth_is_separate_from_eight_level_business_domain():
    rows = [episode("first", 2, 2), episode("second", 3, 3)]
    for row in rows:
        value = row["inputs"]["a"]
        for _ in range(7):
            value = {"nested": value}
        row["inputs"] = {"a": value}
        row["steps"][1]["arguments"]["x"] = row["steps"][0]["arguments"]["x"]
    artifact = learn(rows, operators=["sub"])
    transforms.validate_artifact(artifact)
    assert len(artifact["steps"][0]["catalog"][0]["path"]) == 8
    assert transforms.resolve_step(artifact, 0, rows[0]["inputs"], []).applied
    for row in rows:
        row["inputs"] = {"too_deep": row["inputs"]}
    with pytest.raises(ValueError, match="depth limit"):
        learn(rows)


def test_whole_artifact_limit_applies_even_when_child_is_individually_valid(monkeypatch):
    baseline = learn()
    raw_size = len(transforms._canonical(baseline).encode())
    assert all(len(json.dumps(binding["artifact"]).encode()) < raw_size
               for step in baseline["steps"] for binding in step["bindings"])
    monkeypatch.setattr(transforms, "MAX_ARTIFACT_BYTES", raw_size - 1)
    with pytest.raises(ValueError, match="size|byte"):
        learn()


def test_v1_remains_copy_only_and_unchanged_by_importing_v2():
    rows = [episode("first", 2, 2), episode("second", 3, 3)]
    with pytest.raises(ValueError, match="no consistent"):
        recipe.synthesize(rows, allowed_tools=["lookup", "save"])
    assert learn()["schema"] == transforms.SCHEMA


def test_refinement_retains_seed_literal_when_target_stops_being_constant():
    def demonstration(identity, value, target):
        return {"id": identity, "inputs": {"x": value}, "steps": [
            {"tool": "lookup", "arguments": {"x": target}, "result": None},
            {"tool": "save", "arguments": {"x": value}, "result": None},
        ]}

    artifact = learn([demonstration("a", -1, 1), demonstration("b", 0, 1)], operators=["max"])
    assert artifact["steps"][0]["bindings"][0]["artifact"]["spec"]["constants"] == [1]
    refined = transforms.refine(artifact, [demonstration("c", 2, 2)])
    assert refined["grammar"] == artifact["grammar"]
    assert refined["steps"][0]["bindings"][0]["artifact"]["spec"]["constants"] == [1]
    assert refined["steps"][0]["bindings"][0]["candidate_count"] == 2
    decision = transforms.resolve_step(refined, 0, {"x": 3}, [])
    assert decision.applied and decision.arguments == {"x": 3}
