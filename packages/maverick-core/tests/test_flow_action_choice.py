"""Pure inferred continuation selection; no connector or generated guard inputs."""
from __future__ import annotations

import copy

import pytest
from maverick.flow import action_choice as choice
from maverick.flow import action_recipe as recipe
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


def episode(identity, amount, limit, *, legacy=None, terminal=None):
    queued = amount > limit
    tool = terminal or ("queue_review" if queued else "approve_case")
    field = "review_amount" if tool == "queue_review" else "total"
    return {"id": identity, "inputs": {"amount": amount, "limit": limit, "customer": f"customer-{identity}"}, "steps": [
        {"tool": "open_case", "arguments": {"customer": f"customer-{identity}"},
         "result": {"case_id": f"case-{identity}", "legacy": queued if legacy is None else legacy}},
        {"tool": tool, "arguments": {"case_id": f"case-{identity}", field: amount},
         "result": {"queued": True, "ticket": f"ticket-{identity}"} if tool == "queue_review" else {"approved": True}},
    ]}


def examples():
    return [episode("a", 1, 2), episode("b", 2, 2), episode("c", 3, 2), episode("d", 4, 2)]


def domain(rows):
    first = rows[0]
    return {"inputs": schema(first["inputs"]), "prefix": {key: schema(first["steps"][0][key]) for key in ("arguments", "result")},
            "branches": {row["steps"][1]["tool"]: {key: schema(row["steps"][1][key]) for key in ("arguments", "result")}
                         for row in rows}}


def learn(rows=None, **changes):
    rows = rows if rows is not None else examples()
    declaration = changes["domain"] if "domain" in changes else domain(rows)
    kwargs = {"allowed_tools": ["open_case", "approve_case", "queue_review"], "domain": declaration,
              "max_operations": 2, "operators": ["eq", "le", "lt", "not"]}
    kwargs.update(changes)
    return choice.synthesize_choice(rows, **kwargs)


def runtime(amount, limit, legacy):
    return {"amount": amount, "limit": limit, "customer": "new-customer"}, [{"case_id": "fresh-generated", "legacy": legacy}]


def test_labels_and_complete_catalog_come_only_from_observed_continuations():
    artifact = learn()
    assert artifact["schema"] == recipe.CHOICE_SCHEMA
    assert len(artifact["steps"]) == 1 and artifact["steps"][0]["tool"] == "open_case"
    assert [(branch["route"], branch["tool"]) for branch in artifact["branches"]] == [
        ("0", "approve_case"), ("1", "queue_review")]
    assert artifact["guard"]["catalog"] == [
        {"name": "v000", "source": "input", "path": ["amount"]},
        {"name": "v001", "source": "input", "path": ["customer"]},
        {"name": "v002", "source": "input", "path": ["limit"]},
        {"name": "v003", "source": "result", "step": 0, "path": ["case_id"]},
        {"name": "v004", "source": "result", "step": 0, "path": ["legacy"]},
    ]
    assert artifact["guard_candidate_count"] > 1
    assert artifact["candidate_binding_count"] == 5
    assert learn(list(reversed(examples())), allowed_tools=["queue_review", "open_case", "approve_case"]) == artifact


def test_prefix_is_inferred_from_all_episodes_and_exposes_actual_tool_identity():
    artifact = learn()
    inputs, _prior = runtime(1, 2, False)
    decision = recipe.resolve_step(artifact, 0, inputs, [])
    assert decision.applied and decision.tool == "open_case" and decision.arguments == {"customer": "new-customer"}
    assert choice.resolve_choice(artifact, inputs, []).reason == "outside_domain"
    assert len(artifact["steps"][0]["bindings"][0]["artifact"]["examples"]) == 4


def test_stale_coincident_guard_blocks_both_selection_and_arguments():
    artifact = learn()
    inputs, prior = runtime(5, 2, False)
    selected = choice.resolve_choice(artifact, inputs, prior)
    assert not selected.applied and selected.tool is None and selected.route is None and selected.reason == "ambiguity"
    decision = recipe.resolve_step(artifact, 1, inputs, prior)
    assert not decision.applied and decision.arguments is None and decision.reason == "ambiguity"


def test_counterexamples_filter_guard_and_preserve_generated_id_for_each_actual_route():
    original = learn()
    before = copy.deepcopy(original)
    refined = recipe.refine(original, [episode("e", 0, 1, legacy=True), episode("f", 5, 4, legacy=False)])
    assert original == before and refined["grammar"] == original["grammar"]
    for amount in range(-1, 5):
        for limit in range(1, 4):
            for legacy in (False, True):
                inputs, prior = runtime(amount, limit, legacy)
                selected = choice.resolve_choice(refined, inputs, prior)
                queued = amount > limit
                assert selected.applied and selected.route == str(int(queued))
                assert selected.tool == ("queue_review" if queued else "approve_case")
                resolved = recipe.resolve_step(refined, 1, inputs, prior)
                assert resolved.applied and resolved.tool == selected.tool
                assert resolved.arguments == {"case_id": "fresh-generated", "review_amount" if queued else "total": amount}


def test_route_argument_ambiguity_cannot_borrow_evidence_from_other_route():
    rows = examples()
    for row in rows[:2]:
        row["inputs"]["amount"] = 1
        row["steps"][1]["arguments"]["total"] = 1
    artifact = learn(rows)
    inputs, prior = runtime(2, 3, False)
    assert choice.resolve_choice(artifact, inputs, prior).applied
    decision = choice.resolve_step(artifact, 1, inputs, prior)
    assert not decision.applied and decision.reason == "ambiguity"


def test_terminal_result_requires_exact_actual_tool_and_its_distinct_schema():
    artifact = learn()
    recipe.validate_result(artifact, 0, {"case_id": "fresh", "legacy": True}, tool="open_case")
    recipe.validate_result(artifact, 1, {"approved": True}, tool="approve_case")
    recipe.validate_result(artifact, 1, {"queued": True, "ticket": "fresh"}, tool="queue_review")
    for tool in (None, "other", "open_case", True):
        with pytest.raises(ValueError):
            recipe.validate_result(artifact, 1, {"approved": True}, tool=tool)
    with pytest.raises(ValueError):
        recipe.validate_result(artifact, 1, {"approved": True}, tool="queue_review")
    with pytest.raises(ValueError):
        recipe.validate_result(artifact, 0, {"case_id": "fresh", "legacy": True}, tool="queue_review")


@pytest.mark.parametrize("change", [
    lambda a: a["guard"]["catalog"].pop(),
    lambda a: a["guard"]["catalog"][0].update(source="result", step=1),
    lambda a: a["guard"]["artifact"]["roots"].pop(),
    lambda a: a["branches"].reverse(),
    lambda a: a["branches"][0].update(route="1"),
    lambda a: a["branches"][0].update(tool="queue_review"),
    lambda a: a["branches"][0]["bindings"].pop(),
    lambda a: a.update(guard_candidate_count=1),
    lambda a: a["grammar"].update(seed_episode_ids=["a", "c", "d"]),
])
def test_rehashing_cannot_prune_guards_arguments_or_remap_routes(change):
    artifact = learn()
    change(artifact)
    artifact.pop("artifact_sha256")
    artifact["artifact_sha256"] = choice.transforms._digest(artifact)
    with pytest.raises(ValueError):
        recipe.validate_artifact(artifact)
    inputs, prior = runtime(1, 2, False)
    assert choice.resolve_choice(artifact, inputs, prior).reason == "invalid_artifact"


@pytest.mark.parametrize("change", [
    lambda rows: rows.pop(),
    lambda rows: rows[0]["steps"].pop(),
    lambda rows: rows[0].update(id=rows[1]["id"]),
    lambda rows: rows[0]["steps"][0].update(tool="other_prefix"),
    lambda rows: rows[0]["steps"][0]["result"].update(extra=1),
    lambda rows: rows[0]["inputs"].update(amount=True),
    lambda rows: rows[0]["steps"][1].update(tool="third_tool"),
    lambda rows: rows[0]["steps"][0]["result"].update(pending=True),
])
def test_admission_refuses_unsupported_or_inconsistent_observations(change):
    rows = examples()
    declaration = domain(rows)
    change(rows)
    with pytest.raises(ValueError):
        learn(rows, domain=declaration)


def test_missing_second_distinct_fork_observation_is_not_fabricated():
    rows = examples()
    rows[1] = copy.deepcopy(rows[0])
    rows[1]["id"] = "b"
    with pytest.raises(ValueError, match="distinct observable"):
        learn(rows)


def test_conflicting_observed_routes_for_same_complete_observable_fork_are_rejected():
    rows = examples()
    rows[2]["inputs"] = copy.deepcopy(rows[0]["inputs"])
    rows[2]["steps"][0] = copy.deepcopy(rows[0]["steps"][0])
    with pytest.raises(ValueError, match="conflicting outputs"):
        learn(rows)


def test_no_caller_guard_or_mapping_is_admitted():
    with pytest.raises(TypeError):
        learn(guard={"field": "legacy"})
    declaration = domain(examples())
    declaration["guard"] = {"desired": "amount>limit"}
    with pytest.raises(ValueError):
        learn(domain=declaration)


@pytest.mark.parametrize("inputs,prior", [
    ({"amount": True, "limit": 2, "customer": "new"}, [{"case_id": "fresh", "legacy": False}]),
    ({"amount": 101, "limit": 2, "customer": "new"}, [{"case_id": "fresh", "legacy": False}]),
    ({"amount": 1, "limit": 2, "customer": "new", "route": "0"}, [{"case_id": "fresh", "legacy": False}]),
    ({"amount": 1, "limit": 2, "customer": "new"}, [{"case_id": "fresh", "legacy": False, "extra": None}]),
    ({"amount": 1, "limit": 2, "customer": "new"}, [{"case_id": "fresh", "legacy": 0}]),
    ({"amount": 1, "limit": 2, "customer": "new"}, []),
    ({"amount": 1, "limit": 2, "customer": "new"}, [{"case_id": "fresh", "legacy": False}, {"approved": True}]),
])
def test_runtime_checks_all_original_fields_and_exact_completed_prefix(inputs, prior):
    artifact = learn()
    assert choice.resolve_choice(artifact, inputs, prior).reason == "outside_domain"
    assert choice.resolve_step(artifact, 1, inputs, prior).reason == "outside_domain"


def test_seventh_fork_source_is_rejected_instead_of_selecting_a_subset():
    rows = examples()
    for row in rows:
        row["steps"][0]["result"].update(unused1=False, unused2="unused")
    with pytest.raises(ValueError, match="six eligible"):
        learn(rows)


def test_all_branches_count_toward_total_argument_bound(monkeypatch):
    rows = examples()
    for row in rows:
        row["steps"][1]["arguments"].update(a=1, b=2)
    monkeypatch.setattr(composed, "synthesize", lambda *args, **kwargs: pytest.fail("must bound before compilation"))
    with pytest.raises(ValueError, match="eight total"):
        learn(rows)


def test_combined_guard_and_selected_argument_cost_stops_before_arguments(monkeypatch):
    artifact = learn()
    choice.validate_artifact(artifact)
    original = composed.evaluation_cost

    def cost(child):
        return original(child) if child["spec"]["output_type"] == "boolean" else 60_000

    monkeypatch.setattr(composed, "evaluation_cost", cost)
    monkeypatch.setattr(choice, "_arguments", lambda *args: pytest.fail("overbudget arguments must not be assembled"))
    inputs, prior = runtime(1, 2, False)
    assert choice.resolve_step(artifact, 1, inputs, prior).reason == "evaluation_limit"


def test_synthesis_and_prediction_exhaustion_never_produce_partial_agreement(monkeypatch):
    artifact = learn()
    choice.validate_artifact(artifact)
    inputs, prior = runtime(1, 2, False)
    with monkeypatch.context() as limited:
        limited.setattr(composed, "MAX_PREDICTION_EVALUATIONS", 1)
        assert choice.resolve_choice(artifact, inputs, prior).reason == "evaluation_limit"
    with monkeypatch.context() as limited:
        limited.setattr(composed, "MAX_PRODUCTIONS", 1)
        with pytest.raises(composed.SynthesisLimit):
            learn()


def test_refinement_keeps_branch_seed_literals_when_its_output_stops_being_constant():
    rows = [episode("a", -2, 0, legacy=False), episode("b", -1, 0, legacy=False),
            episode("c", 2, 0, legacy=True), episode("d", 3, 0, legacy=True)]
    for row in rows[:2]:
        row["steps"][1]["arguments"]["total"] = 1
    original = learn(rows, max_operations=1, operators=["max"])
    new = episode("e", 2, 0, legacy=False, terminal="approve_case")
    new["steps"][1]["arguments"]["total"] = 2
    refined = recipe.refine(original, [new])
    before = original["branches"][0]["bindings"][1]["artifact"]
    after = refined["branches"][0]["bindings"][1]["artifact"]
    assert before["spec"] == after["spec"] and after["spec"]["constants"] == [1]
    assert original["grammar"] == refined["grammar"]
    inputs, prior = runtime(3, 0, False)
    resolved = recipe.resolve_step(refined, 1, inputs, prior)
    assert resolved.applied and resolved.arguments["total"] == 3


def test_input_and_returned_argument_mutation_cannot_change_cached_artifact():
    rows = examples()
    artifact = learn(rows)
    before = copy.deepcopy(artifact)
    rows[0]["steps"][0]["result"]["case_id"] = "rewritten"
    inputs, prior = runtime(1, 2, False)
    result = choice.resolve_step(artifact, 1, inputs, prior)
    result.arguments["case_id"] = "rewritten"
    assert artifact == before
    assert choice.resolve_step(artifact, 1, inputs, prior).arguments["case_id"] == "fresh-generated"


def test_whole_choice_artifact_cap_covers_guard_and_both_continuations(monkeypatch):
    artifact = learn()
    size = len(choice._canonical(artifact).encode())
    monkeypatch.setattr(choice, "MAX_ARTIFACT_BYTES", size - 1)
    with pytest.raises(ValueError, match="whole-artifact"):
        learn()
