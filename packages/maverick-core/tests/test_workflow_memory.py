"""Independent pure-oracle qualification of bounded learned history programs.

These supplied traces claim no native execution. Native signed fixture coverage
is separate; no model/provider or business connector is invoked here.
"""
from __future__ import annotations

import copy
import itertools
from collections import Counter

import pytest
from maverick.flow import composed_operator as composed
from maverick.flow import workflow_memory as memory
from maverick.flow import workflow_transducer as ordinary


def obj(**properties):
    return {"type": "object", "properties": properties, "required": sorted(properties),
            "additionalProperties": False}


INT = {"type": "integer", "minimum": 0, "maximum": 100}
DOMAIN = {"inputs": obj(target=INT), "tools": {
    "receipt": {"arguments": obj(target=INT), "result": obj(quantity=INT)},
}}


def episode(identity, target, quantities):
    return {"id": identity, "inputs": {"target": target}, "steps": [
        {"tool": "receipt", "arguments": {"target": target}, "result": {"quantity": value}}
        for value in quantities]}


SEEDS = [(5, [2, 3]), (5, [1, 3, 1]), (5, [3, 1, 1]), (5, [1, 1, 3]), (5, [4, 2]),
         (4, [1, 3]), (6, [2, 1, 4]), (6, [1, 2, 2, 1]), (7, [3, 3, 1]), (8, [3, 1, 4])]


def learn(examples, **kwargs):
    return memory.synthesize(examples, allowed_tools=["receipt"], domain=DOMAIN,
                             max_operations=2, operators=["if", "le", "lt"], constants=[0], **kwargs)


@pytest.fixture(scope="module")
def cumulative():
    return learn([episode(str(index), target, values) for index, (target, values) in enumerate(SEEDS)])


def assert_trace(artifact, observed):
    prefix = []
    for step in observed["steps"]:
        decision = memory.resolve_next(artifact, observed["inputs"], prefix)
        assert decision.applied and decision.kind == "action", decision
        assert decision.tool == step["tool"] and decision.arguments == step["arguments"]
        memory.validate_observation(artifact, step["tool"], step["result"])
        prefix.append(step)
    decision = memory.resolve_next(artifact, observed["inputs"], prefix)
    assert decision.applied and decision.kind == "complete", decision


def test_real_history_collision_is_not_repaired_by_latest_only_features(cumulative):
    examples = [episode(str(index), target, values) for index, (target, values) in enumerate(SEEDS)]
    with pytest.raises(ValueError, match="no composed program"):
        ordinary.synthesize(examples, allowed_tools=["receipt"], domain=DOMAIN,
                            max_operations=2, operators=["if", "le", "lt"], constants=[0])
    assert cumulative["enumerated_model_count"] == 13
    assert 0 < cumulative["model_count"] < 13
    assert all(model["summary"]["kind"] != "none" for model in cumulative["models"])
    complete = episode("complete", 5, [2, 3])
    continue_ = episode("continue", 5, [1, 3])
    assert complete["inputs"] == continue_["inputs"]
    assert complete["steps"][-1] == continue_["steps"][-1]
    assert memory.resolve_next(cumulative, complete["inputs"], complete["steps"]).kind == "complete"
    assert memory.resolve_next(cumulative, continue_["inputs"], continue_["steps"]).kind == "action"


@pytest.mark.parametrize("target,values", [(5, [1, 1, 1, 1, 1]), (6, [1, 1, 1, 1, 1, 1]),
                                          (7, [2, 2, 2, 1]), (8, [2, 2, 2, 3])])
def test_unseen_lengths_and_quantities_use_one_fixed_memory_program(cumulative, target, values):
    assert_trace(cumulative, episode("fresh", target, values))


def test_unseen_zero_receipt_keeps_ambiguity_until_actual_counterexample(cumulative):
    observed = episode("zeros", 5, [0, 0, 2, 3])
    assert memory.resolve_next(cumulative, observed["inputs"], observed["steps"][:1]).reason == "ambiguity"
    refined = memory.refine(cumulative, [observed])
    assert_trace(refined, observed)


def test_returned_artifact_and_arguments_cannot_mutate_validation_cache(cumulative):
    memory.validate_artifact(cumulative)
    changed = copy.deepcopy(cumulative)
    changed["models"][0]["summary"] = {"kind": "none"}
    assert not memory.resolve_next(changed, {"target": 5}, []).applied
    decision = memory.resolve_next(cumulative, {"target": 5}, [])
    decision.arguments["target"] = 90
    assert memory.resolve_next(cumulative, {"target": 5}, []).arguments == {"target": 5}


@pytest.mark.parametrize("change", ["drop_model", "alter_summary", "drop_expression", "grammar", "count"])
def test_rehashing_cannot_hide_missing_models_or_expressions(cumulative, change):
    altered = copy.deepcopy(cumulative)
    if change == "drop_model":
        altered["models"].pop()
        altered["model_count"] -= 1
    elif change == "alter_summary":
        altered["models"][0]["summary"]["initial"] = {"source": "zero"}
        altered["models"][0]["summary"]["update"] = None
    elif change == "drop_expression":
        child = altered["models"][0]["states"][0]["guard"]
        child["states"][child["roots"][0]]["alternatives"].pop()
    elif change == "grammar":
        altered["grammar"]["memory_family"] = "caller-selected-summary"
    else:
        altered["enumerated_model_count"] += 1
    altered["artifact_sha256"] = memory._digest({key: value for key, value in altered.items()
                                               if key != "artifact_sha256"})
    with pytest.raises(ValueError, match="paired alternatives"):
        memory.validate_artifact(altered)


@pytest.mark.parametrize("bad", [None, True, 1.0, "5", float("nan"), 10**30])
def test_inputs_keep_exact_types_and_declared_bounds(cumulative, bad):
    assert not memory.resolve_next(cumulative, {"target": bad}, []).applied


def test_malformed_history_and_untrusted_checkpoint_refuse(cumulative):
    valid = episode("a", 5, [2, 3])
    wrong = copy.deepcopy(valid["steps"])
    wrong[0]["arguments"]["target"] = True
    assert memory.resolve_next(cumulative, valid["inputs"], wrong).reason == "invalid_history"
    wrong = copy.deepcopy(valid["steps"])
    wrong[0]["memory"] = 99
    assert memory.resolve_next(cumulative, valid["inputs"], wrong).reason == "invalid_history"
    assert memory.resolve_next(cumulative, valid["inputs"], {"memory": 5}).reason == "invalid_history"
    cyclic = []
    cyclic.append(cyclic)
    assert not memory.resolve_next(cumulative, valid["inputs"], cyclic).applied
    assert not memory.resolve_next(cumulative, {"target": 5, "x": "\ud800"}, []).applied


@pytest.mark.parametrize("cap", ["MAX_SUMMARY_MODELS", "MAX_PRODUCTIONS", "MAX_TRAINING_EVALUATIONS", "MAX_PACKED_STATES"])
def test_any_family_resource_failure_produces_no_partial_artifact(monkeypatch, cap):
    monkeypatch.setattr(memory, cap, 1)
    with pytest.raises(composed.SynthesisLimit):
        learn([episode("a", 5, [2, 3]), episode("b", 5, [1, 3, 1])])


def test_unrelated_builder_error_is_not_treated_as_an_inconsistent_model(monkeypatch):
    def broken(*args, **kwargs):
        raise ValueError("unrelated builder defect")

    monkeypatch.setattr(memory._Builder, "build", broken)
    with pytest.raises(ValueError, match="unrelated builder defect"):
        learn([episode("a", 5, [2, 3]), episode("b", 5, [1, 3, 1])])


def test_whole_runtime_budget_never_licenses_subset_consensus(cumulative, monkeypatch):
    monkeypatch.setattr(memory, "MAX_RESOLVE_EVALUATIONS", 1)
    assert memory.resolve_next(cumulative, {"target": 5}, []).reason == "evaluation_limit"


def test_refinement_retains_fixed_family_earlier_evidence_and_original(cumulative):
    before = memory._canonical(cumulative)
    refined = memory.refine(cumulative, [episode("new", 9, [2, 2, 2, 3])])
    assert refined["grammar"] == cumulative["grammar"]
    assert refined["enumerated_model_count"] == cumulative["enumerated_model_count"]
    assert refined["episode_count"] == cumulative["episode_count"] + 1
    assert {item["id"] for item in cumulative["episodes"]} < {item["id"] for item in refined["episodes"]}
    assert memory._canonical(cumulative) == before
    assert {memory._canonical(model["summary"]) for model in refined["models"]} <= {
        memory._canonical(model["summary"]) for model in cumulative["models"]}
    assert refined["guard_candidate_count"] <= cumulative["guard_candidate_count"]
    assert refined["candidate_binding_count"] <= cumulative["candidate_binding_count"]
    assert_trace(refined, episode("fresh", 9, [3, 2, 2, 2]))


def test_no_integer_sources_still_keeps_baseline_and_zero_initializer():
    domain = {"inputs": obj(), "tools": {"touch": {"arguments": obj(), "result": obj()}}}
    examples = [{"id": key, "inputs": {}, "steps": [{"tool": "touch", "arguments": {}, "result": {}}]}
                for key in ("a", "b")]
    artifact = memory.synthesize(examples, allowed_tools=["touch"], domain=domain, operators=["if"])
    assert artifact["enumerated_model_count"] == artifact["model_count"] == 2
    assert_trace(artifact, examples[0])


def oracle_summaries():
    """Independently spell out this fixture's entire thirteen-program family."""
    yield {"kind": "none"}
    for initial in ({"source": "zero"}, {"source": "input", "path": ["target"]}):
        yield {"kind": "integer", "initial": initial, "update": None}
        for operation in ("replace", "add", "subtract", "min", "max"):
            yield {"kind": "integer", "initial": initial,
                   "update": {"tool": "receipt", "path": ["quantity"], "op": operation}}


def oracle_cell(summary, target, quantities):
    if summary["kind"] == "none":
        return None
    value = 0 if summary["initial"]["source"] == "zero" else target
    update = summary["update"]
    for quantity in quantities:
        if update is None:
            continue
        value = {"replace": quantity, "add": value + quantity, "subtract": value - quantity,
                 "min": min(value, quantity), "max": max(value, quantity)}[update["op"]]
    return value


def oracle_trees(names, labels, kind):
    """Unpruned directed trees for the explicitly selected if/le, cost <= 2.

    There are no boolean leaves. Therefore every conditional is exactly one
    le comparison plus one if, with field/literal arms. This enumeration uses
    no production engine, packed states, equivalence grouping or core helpers.
    """
    integers = [("field", name) for name in names] + [("literal", 0)]
    atoms = integers if kind == "integer" else [("literal", label) for label in labels]
    yield from atoms
    for left, right, yes, no in itertools.product(integers, integers, atoms, atoms):
        yield ("if", ("le", left, right), yes, no)


def oracle_eval(tree, values):
    op = tree[0]
    if op == "field":
        return values[tree[1]]
    if op == "literal":
        return tree[1]
    if op == "le":
        return oracle_eval(tree[1], values) <= oracle_eval(tree[2], values)
    assert op == "if"
    return oracle_eval(tree[2] if oracle_eval(tree[1], values) else tree[3], values)


def oracle_values(summary, target, quantities):
    result = {"target": target}
    if quantities:
        result["quantity"] = quantities[-1]
    if summary["kind"] != "none":
        result["cell"] = oracle_cell(summary, target, quantities)
    return result


def oracle_family(examples):
    survivors = []
    for summary in oracle_summaries():
        states = {}
        for after_receipt in (False, True):
            rows = []
            for example in examples:
                quantities = [step["result"]["quantity"] for step in example["steps"]]
                for index in range(len(quantities) + 1):
                    if bool(index) == after_receipt:
                        values = oracle_values(summary, example["inputs"]["target"], quantities[:index])
                        rows.append((values, "complete" if index == len(quantities) else "action:receipt"))
            names = list(rows[0][0])
            guards = [tree for tree in oracle_trees(names, ["complete", "action:receipt"], "string")
                      if all(oracle_eval(tree, values) == label for values, label in rows)]
            args = [tree for tree in oracle_trees(names, [], "integer")
                    if all(oracle_eval(tree, values) == values["target"]
                           for values, label in rows if label != "complete")]
            if not guards or not args:
                break
            states[after_receipt] = {"guard": guards, "argument": args}
        if len(states) == 2:
            survivors.append((summary, states))
    return survivors


def unpack_trees(child, catalog):
    names = {source["name"]: ("cell" if source["source"] == "memory" else source["path"][0])
             for source in catalog}
    cache = {}

    def expand(index):
        if index not in cache:
            result = []
            for production in child["states"][index]["alternatives"]:
                op = production[0]
                if op == "field":
                    result.append((op, names[production[1]]))
                elif op == "literal":
                    result.append((op, production[1]))
                else:
                    result.extend((op, *combination) for combination in
                                  itertools.product(*(expand(part) for part in production[1:])))
            assert len(result) == child["states"][index]["count"]
            cache[index] = result
        return cache[index]

    result = [tree for root in child["roots"] for tree in expand(root)]
    assert len(result) == len(set(result)) == child["candidate_count"]
    return result


def oracle_decision(survivors, target, quantities):
    outputs = set()
    for summary, states in survivors:
        values = oracle_values(summary, target, quantities)
        state = states[bool(quantities)]
        labels = {oracle_eval(tree, values) for tree in state["guard"]}
        if len(labels) != 1:
            return None
        label = next(iter(labels))
        if label == "complete":
            outputs.add(("complete", None))
        else:
            args = {oracle_eval(tree, values) for tree in state["argument"]}
            if len(args) != 1:
                return None
            outputs.add(("action", next(iter(args))))
    return next(iter(outputs)) if len(outputs) == 1 else None


def test_independent_unpruned_oracle_matches_entire_family_trees_weights_and_consensus():
    examples = [episode(str(index), target, values) for index, (target, values) in enumerate(SEEDS)]
    artifact = memory.synthesize(examples, allowed_tools=["receipt"], domain=DOMAIN,
                                 max_operations=2, operators=["if", "le"], constants=[0])
    expected = oracle_family(examples)
    assert len(expected) == artifact["model_count"] > 0
    for model, (summary, states) in zip(artifact["models"], expected, strict=True):
        assert model["summary"] == summary
        for state in model["states"]:
            oracle = states[state["last_tool"] is not None]
            binding = state["branches"][0]["bindings"][0]["artifact"]
            for child, key in ((state["guard"], "guard"), (binding, "argument")):
                actual = unpack_trees(child, state["catalog"])
                assert set(actual) == set(oracle[key])
                # An independently counted full weighted partition on new data.
                for target, quantities in ((1, []), (4, [2]), (6, [2, 1]), (5, [0, 2, 3])):
                    if bool(quantities) != (state["last_tool"] is not None):
                        continue
                    values = oracle_values(summary, target, quantities)
                    assert Counter(oracle_eval(tree, values) for tree in actual) == Counter(
                        oracle_eval(tree, values) for tree in oracle[key])
    checked = 0
    for target in range(1, 5):
        for size in range(4):
            for quantities in itertools.product(range(3), repeat=size):
                # A supplied history must itself have been consensus-authorized.
                if any(oracle_decision(expected, target, quantities[:index]) != ("action", target)
                       for index in range(size)):
                    continue
                predicted = oracle_decision(expected, target, quantities)
                actual = memory.resolve_next(artifact, {"target": target},
                                             episode("held-out", target, quantities)["steps"])
                assert actual.applied == (predicted is not None)
                if predicted is not None:
                    assert actual.kind == predicted[0]
                    assert actual.arguments == ({"target": predicted[1]} if actual.kind == "action" else None)
                checked += 1
    assert checked > 20


def overflow_fixture(input_value, result_value):
    wide = {"type": "integer", "minimum": 0, "maximum": 10**24}
    domain = {"inputs": obj(target=wide), "tools": {
        "a": {"arguments": obj(), "result": obj(quantity=wide)},
        "b": {"arguments": obj(), "result": obj()},
    }}
    episodes = [{"id": key, "inputs": {"target": input_value}, "steps": [
        {"tool": "a", "arguments": {}, "result": {"quantity": result_value}},
        {"tool": "b", "arguments": {}, "result": {}},
    ]} for key in ("a", "b")]
    return domain, episodes


def test_training_overflow_is_proven_inconsistency_but_runtime_cannot_drop_a_survivor():
    domain, examples = overflow_fixture(1, 1)
    artifact = memory.synthesize(examples, allowed_tools=["a", "b"], domain=domain, operators=["if"])
    assert artifact["model_count"] == artifact["enumerated_model_count"] == 13
    _, overflow = overflow_fixture(10**24, 10**24)
    assert memory.resolve_next(artifact, overflow[0]["inputs"], []).applied
    stopped = memory.resolve_next(artifact, overflow[0]["inputs"], overflow[0]["steps"][:1])
    assert not stopped.applied and stopped.reason == "memory_overflow"
    for observed in overflow:
        observed["id"] = "overflow-" + observed["id"]
    corrected = memory.refine(artifact, overflow)
    assert corrected["model_count"] == 12
    assert corrected["enumerated_model_count"] == 13
    assert_trace(corrected, overflow[0])


def test_artifact_byte_cap_fails_whole_build_instead_of_returning_a_subset(monkeypatch):
    monkeypatch.setattr(memory, "MAX_ARTIFACT_BYTES", 1500)
    with pytest.raises(ValueError, match="limit"):
        learn([episode("a", 5, [2, 3]), episode("b", 5, [1, 3, 1])])


def test_family_cardinality_is_checked_before_search_not_truncated(monkeypatch):
    domain, examples = overflow_fixture(1, 1)
    monkeypatch.setattr(memory, "MAX_SUMMARY_MODELS", 12)
    with pytest.raises(composed.SynthesisLimit, match="model cap"):
        memory.synthesize(examples, allowed_tools=["a", "b"], domain=domain, operators=["if"])


def test_extra_sources_are_rejected_without_omitting_a_decision_input():
    domain = {"inputs": obj(**{f"v{i}": {"type": "boolean"} for i in range(13)}), "tools": {
        "touch": {"arguments": obj(), "result": obj()},
    }}
    examples = [{"id": key, "inputs": {f"v{i}": False for i in range(13)}, "steps": [
        {"tool": "touch", "arguments": {}, "result": {}}]} for key in ("a", "b")]
    with pytest.raises(ValueError, match="twelve sources"):
        memory.synthesize(examples, allowed_tools=["touch"], domain=domain, operators=["if"])


def test_observationally_identical_zero_histories_cannot_invent_a_counter():
    with pytest.raises(ValueError, match="no memory model in the complete declared family"):
        learn([episode("a", 0, [0, 0]), episode("b", 0, [0, 0, 0])])


def test_bounded_unseen_history_cannot_request_a_ninth_action(cumulative):
    decision = memory.resolve_next(cumulative, {"target": 9}, episode("bound", 9, [1] * 8)["steps"])
    assert not decision.applied and decision.reason == "step_limit"


@pytest.mark.parametrize("value", [0, 3, True, 1.0])
def test_unsupported_or_inexact_expression_budget_is_rejected(value):
    with pytest.raises(ValueError, match="one or two operations"):
        memory.synthesize([episode("a", 5, [2, 3]), episode("b", 5, [1, 3, 1])],
                          allowed_tools=["receipt"], domain=DOMAIN, max_operations=value)
