"""Complete typed action bindings, changing result IDs and strict JSON boundaries."""
from __future__ import annotations

import copy
import hashlib
import json
import math

import pytest
from maverick.flow import action_recipe as recipe

TOOLS = ["lookup_customer", "create_invoice"]
OPAQUE = "{{secret('must-not-render')}}"


def episode(identity, email, amount, memo, customer_id, invoice_id):
    return {"id": identity, "inputs": {"email": email, "amount": amount, "memo": memo}, "steps": [
        {"tool": "lookup_customer", "arguments": {"query": email},
         "result": {"records": [{"id": customer_id}]}},
        {"tool": "create_invoice", "arguments": {
            "customer": {"id": customer_id}, "lines": [{"amount": amount, "memo": memo}],
            "dry_run": False, "description": OPAQUE,
        }, "result": {"invoice_id": invoice_id, "accepted": True}},
    ]}


def episodes():
    return [episode("one", "a@example.test", 120, "Alpha", "customer-a", "invoice-a"),
            episode("two", "b@example.test", 250, "Beta", "customer-b", "invoice-b")]


@pytest.fixture
def artifact():
    return recipe.synthesize(episodes(), allowed_tools=TOOLS)


def _resign(artifact):
    payload = {key: value for key, value in artifact.items() if key != "artifact_sha256"}
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    artifact["artifact_sha256"] = hashlib.sha256(raw.encode()).hexdigest()
    return artifact


def test_learns_two_step_dataflow_and_uses_new_prior_result_identity(artifact):
    recipe.validate_artifact(artifact)
    assert artifact["schema"] == recipe.SCHEMA and artifact["episode_count"] == 2
    assert artifact["candidate_binding_count"] == 6
    inputs = {"email": "c@example.test", "amount": 390, "memo": "Gamma"}
    first = recipe.resolve_step(artifact, 0, inputs, [])
    assert first.applied and first.arguments == {"query": "c@example.test"}
    prior = {"records": [{"id": "new-runtime-customer"}]}
    second = recipe.resolve_step(artifact, 1, inputs, [prior])
    assert second.applied and second.reason == "agreement"
    assert second.arguments == {"customer": {"id": "new-runtime-customer"},
        "lines": [{"amount": 390, "memo": "Gamma"}], "dry_run": False, "description": OPAQUE}
    assert type(second.arguments["lines"][0]["amount"]) is int
    assert second.arguments["dry_run"] is False
    assert second.artifact_digest == artifact["artifact_sha256"]
    assert second.candidate_binding_count == 6
    customer = next(binding for binding in artifact["steps"][1]["bindings"]
                    if binding["path"] == ["customer", "id"])
    assert customer["choices"] == [{"source": "result", "step": 0, "path": ["records", 0, "id"]}]


def test_synthesis_and_runtime_do_not_mutate_or_share_evidence(artifact):
    original = copy.deepcopy(artifact)
    inputs = {"email": "c@example.test", "amount": 390, "memo": "Gamma"}
    prior = [{"records": [{"id": "runtime"}]}]
    resolved = recipe.resolve_step(artifact, 1, inputs, prior)
    resolved.arguments["customer"]["id"] = "caller-change"
    assert artifact == original and prior[0]["records"][0]["id"] == "runtime"
    assert recipe.resolve_step(artifact, 1, inputs, prior).arguments["customer"]["id"] == "runtime"
    source = episodes()
    learned = recipe.synthesize(source, allowed_tools=TOOLS)
    source[0]["steps"][0]["result"]["records"][0]["id"] = "mutated"
    assert learned == original


def ambiguous_episodes():
    source = episodes()
    for item in source:
        item["inputs"]["alternate_email"] = item["inputs"]["email"]
    return source


def test_coincident_input_bindings_are_all_retained_and_unseen_disagreement_abstains():
    artifact = recipe.synthesize(ambiguous_episodes(), allowed_tools=TOOLS)
    query = artifact["steps"][0]["bindings"][0]
    assert query["choices"] == [{"source": "input", "path": ["alternate_email"]},
                                 {"source": "input", "path": ["email"]}]
    inputs = {"email": "intended@example.test", "alternate_email": "different@example.test",
              "amount": 50, "memo": "New"}
    result = recipe.resolve_step(artifact, 0, inputs, [])
    assert not result.applied and result.arguments is None and result.reason == "ambiguity"


def test_counterexample_refinement_removes_only_inconsistent_binding():
    old = recipe.synthesize(ambiguous_episodes(), allowed_tools=TOOLS)
    snapshot = copy.deepcopy(old)
    next_episode = episode("three", "c@example.test", 360, "Gamma", "customer-c", "invoice-c")
    next_episode["inputs"]["alternate_email"] = "not-the-lookup@example.test"
    refined = recipe.refine(old, [next_episode])
    assert old == snapshot and refined["episode_count"] == 3
    assert refined["candidate_binding_count"] == old["candidate_binding_count"] - 1
    assert refined["artifact_sha256"] != old["artifact_sha256"]
    result = recipe.resolve_step(refined, 0, next_episode["inputs"], [])
    assert result.applied and result.arguments == {"query": "c@example.test"}


def test_matching_constants_do_not_override_coincident_input_bindings():
    source = episodes()
    for item in source:
        item["inputs"]["dry_run"] = False
    artifact = recipe.synthesize(source, allowed_tools=TOOLS)
    binding = next(b for b in artifact["steps"][1]["bindings"] if b["path"] == ["dry_run"])
    assert binding["choices"] == [{"source": "input", "path": ["dry_run"]},
                                   {"source": "constant", "value": False}]
    inputs = {**source[0]["inputs"], "dry_run": True}
    decision = recipe.resolve_step(artifact, 1, inputs, [source[0]["steps"][0]["result"]])
    assert decision.reason == "ambiguity" and decision.arguments is None


def test_result_binding_coincidence_is_preserved_until_runtime_disambiguates():
    source = episodes()
    for item in source:
        result = item["steps"][0]["result"]
        result["alternate"] = result["records"][0]["id"]
    artifact = recipe.synthesize(source, allowed_tools=TOOLS)
    prior = {"records": [{"id": "actual"}], "alternate": "other"}
    decision = recipe.resolve_step(artifact, 1, source[0]["inputs"], [prior])
    assert not decision.applied and decision.reason == "ambiguity"


@pytest.mark.parametrize("mutation", [
    lambda a: a["steps"][0]["bindings"][0]["choices"].pop(),
    lambda a: a["steps"][0]["bindings"][0].update(choices=[{"source": "result", "step": 0, "path": []}]),
    lambda a: a["steps"][0]["bindings"][0].update(choices=[{"source": "result", "step": 1, "path": []}]),
    lambda a: a["steps"][0].update(tool="unapproved_tool"),
    lambda a: a.update(candidate_binding_count=1),
    lambda a: a.update(episode_count=True),
])
def test_delete_rehash_metadata_and_future_references_cannot_forge_certainty(mutation):
    artifact = recipe.synthesize(ambiguous_episodes(), allowed_tools=TOOLS)
    recipe.validate_artifact(artifact)
    mutation(artifact)
    _resign(artifact)
    with pytest.raises(ValueError, match="complete learned bindings"):
        recipe.validate_artifact(artifact)
    assert recipe.resolve_step(artifact, 0, {}, []).reason == "invalid_artifact"


@pytest.mark.parametrize("location", ["current", "future"])
def test_inference_cannot_depend_on_current_or_future_result(location):
    source = episodes()
    for item in source:
        if location == "current":
            item["steps"][0]["arguments"]["query"] = item["steps"][0]["result"]["records"][0]["id"]
        else:
            item["steps"][0]["arguments"]["query"] = item["steps"][1]["result"]["invoice_id"]
    with pytest.raises(ValueError, match="no consistent"):
        recipe.synthesize(source, allowed_tools=TOOLS)


@pytest.mark.parametrize("inputs", [
    {"email": "x", "amount": 1},
    {"email": "x", "amount": 1, "memo": "m", "extra": True},
    {"email": "x", "amount": True, "memo": "m"},
    {"email": "x", "amount": 1.0, "memo": "m"},
    {"email": None, "amount": 1, "memo": "m"},
])
def test_runtime_requires_complete_exact_input_shape(artifact, inputs):
    result = recipe.resolve_step(artifact, 0, inputs, [])
    assert result.reason == "outside_domain" and result.arguments is None


@pytest.mark.parametrize("prior", [
    [], [{"records": []}], [{"records": [{"id": "x"}, {"id": "y"}]}],
    [{"records": [{"id": "x", "extra": "y"}]}], [{"records": [{"id": 1}]}],
    [{"records": [{"id": "x"}]}] * 2,
])
def test_runtime_requires_exact_prior_count_and_full_prior_shape(artifact, prior):
    result = recipe.resolve_step(artifact, 1, episodes()[0]["inputs"], prior)
    assert result.reason == "outside_domain" and result.arguments is None


@pytest.mark.parametrize("index", [-1, 2, True, 0.0, "0"])
def test_step_indices_are_strict_and_bounded(artifact, index):
    assert recipe.resolve_step(artifact, index, episodes()[0]["inputs"], []).reason == "outside_domain"
    with pytest.raises(ValueError, match="index"):
        recipe.validate_result(artifact, index, {})


def test_last_result_is_validated_without_requiring_a_following_step(artifact):
    recipe.validate_result(artifact, 1, {"invoice_id": "fresh", "accepted": False})
    for value in ({"invoice_id": "fresh"}, {"invoice_id": "fresh", "accepted": 1},
                  {"invoice_id": "fresh", "accepted": True, "new": 0}):
        with pytest.raises(ValueError, match="typed shape"):
            recipe.validate_result(artifact, 1, value)


@pytest.mark.parametrize("raw,expected", [
    ('{"id":"fresh"}', {"id": "fresh"}), ('"scalar-id"', "scalar-id"),
    ('""', ""), ("null", None), ("false", False), ("123", 123), ("1.5", 1.5),
    ([], []), ({"a": [1, True, None]}, {"a": [1, True, None]}),
])
def test_parse_result_distinguishes_raw_json_text_and_typed_values(raw, expected):
    parsed = recipe.parse_result(raw)
    assert parsed == expected and type(parsed) is type(expected)
    if isinstance(raw, (dict, list)):
        assert parsed is not raw


@pytest.mark.parametrize("raw", ["", "  ", "unquoted-id", '{"x":1,"x":2}',
                                 '{"a":{"x":1,"x":2}}', "NaN", "Infinity", "-Infinity",
                                 "1e999", math.inf, math.nan, {"x": math.inf}, (1, 2), {1: "x"}])
def test_parse_result_rejects_ambiguous_nonfinite_or_non_json_values(raw):
    with pytest.raises((ValueError, TypeError)):
        recipe.parse_result(raw)


def test_scalar_string_results_are_not_double_parsed():
    source = episodes()
    for item in source:
        identity = item["steps"][0]["result"]["records"][0]["id"]
        item["steps"][0]["result"] = identity
    artifact = recipe.synthesize(source, allowed_tools=TOOLS)
    parsed = recipe.parse_result('"new-scalar-id"')
    recipe.validate_result(artifact, 0, parsed)
    result = recipe.resolve_step(artifact, 1, source[0]["inputs"], [parsed])
    assert result.applied and result.arguments["customer"]["id"] == "new-scalar-id"


def test_strict_boolean_integer_and_float_bindings_do_not_coincide():
    source = episodes()
    for offset, item in enumerate(source):
        item["inputs"].update(flag=bool(offset), number=offset, fractional=float(offset), empty=None)
        item["steps"][0]["arguments"].update(flag=bool(offset), fraction=float(offset), empty=None)
    artifact = recipe.synthesize(source, allowed_tools=TOOLS)
    bindings = {tuple(b["path"]): b["choices"] for b in artifact["steps"][0]["bindings"]}
    assert bindings[("flag",)] == [{"source": "input", "path": ["flag"]}]
    assert bindings[("fraction",)] == [{"source": "input", "path": ["fractional"]}]
    assert bindings[("empty",)] == [{"source": "input", "path": ["empty"]},
                                    {"source": "constant", "value": None}]


@pytest.mark.parametrize("change", [
    lambda es: es[1].update(id=es[0]["id"]),
    lambda es: es[1]["steps"][0].update(tool="create_invoice"),
    lambda es: es[1]["inputs"].update(extra="x"),
    lambda es: es[1]["steps"][0]["arguments"].update(extra="x"),
    lambda es: es[1]["steps"][0]["result"]["records"].append({"id": "x"}),
    lambda es: es[1]["steps"][1]["result"].update(accepted=1),
    lambda es: es[1].update(reviewer="claimed-identity"),
])
def test_episodes_reject_shape_sequence_identity_or_extra_field_changes(change):
    source = episodes()
    change(source)
    with pytest.raises(ValueError):
        recipe.synthesize(source, allowed_tools=TOOLS)


@pytest.mark.parametrize("tools", [None, [], ["lookup_customer"], TOOLS + ["lookup_customer"], [True]])
def test_allowed_tools_are_explicit_strict_and_complete(tools):
    with pytest.raises(ValueError):
        recipe.synthesize(episodes(), allowed_tools=tools)


def test_episode_order_and_tool_allowlist_order_do_not_change_artifact(artifact):
    assert recipe.synthesize(list(reversed(episodes())), allowed_tools=list(reversed(TOOLS))) == artifact


def test_search_limit_fails_whole_synthesis(monkeypatch):
    monkeypatch.setattr(recipe, "MAX_MATCH_EVALUATIONS", 1)
    with pytest.raises(recipe.SynthesisLimit, match="evaluation limit"):
        recipe.synthesize(episodes(), allowed_tools=TOOLS)


def test_json_tree_resource_limits_are_enforced():
    for raw in ([0] * 513, "[" * 14 + "0" + "]" * 14, '"' + "x" * 1025 + '"',
                " " * (recipe.MAX_ARTIFACT_BYTES + 1)):
        with pytest.raises(ValueError):
            recipe.parse_result(raw)
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError, match="cycles"):
        recipe.parse_result(cyclic)


def test_empty_argument_containers_are_preserved():
    source = [{"id": str(i), "inputs": {}, "steps": [
        {"tool": "lookup_customer", "arguments": {"empty": [], "object": {}}, "result": None},
        {"tool": "create_invoice", "arguments": {}, "result": {}}]} for i in range(2)]
    artifact = recipe.synthesize(source, allowed_tools=TOOLS)
    assert artifact["candidate_binding_count"] == 0
    assert recipe.resolve_step(artifact, 0, {}, []).arguments == {"empty": [], "object": {}}
    assert recipe.resolve_step(artifact, 1, {}, [None]).arguments == {}


def test_refinement_rejects_duplicate_episode_and_impossible_new_binding(artifact):
    with pytest.raises(ValueError, match="unique"):
        recipe.refine(artifact, [episodes()[0]])
    unsupported = episode("three", "c@example.test", 50, "Gamma", "customer-c", "invoice-c")
    unsupported["steps"][0]["arguments"]["query"] = "cannot-be-derived"
    with pytest.raises(ValueError, match="no consistent"):
        recipe.refine(artifact, [unsupported])


@pytest.mark.parametrize("count", [0, 1, 33])
def test_episode_count_limits(count):
    source = [episode(str(i), f"person-{i}@example.test", i, str(i), f"customer-{i}", f"invoice-{i}")
              for i in range(count)]
    with pytest.raises(ValueError, match="two to 32"):
        recipe.synthesize(source, allowed_tools=TOOLS)


@pytest.mark.parametrize("count", [0, 1, 9])
def test_step_count_limits(count):
    source = episodes()
    for item in source:
        item["steps"] = [copy.deepcopy(item["steps"][0]) for _ in range(count)]
    with pytest.raises(ValueError, match="two to eight"):
        recipe.synthesize(source, allowed_tools=TOOLS)


def test_maximum_episode_and_step_counts_accept_bounded_empty_actions():
    source = [{"id": str(i), "inputs": {}, "steps": [
        {"tool": "lookup_customer", "arguments": {}, "result": None} for _ in range(8)
    ]} for i in range(32)]
    artifact = recipe.synthesize(source, allowed_tools=["lookup_customer"])
    recipe.validate_artifact(artifact)
    assert artifact["episode_count"] == 32 and len(artifact["steps"]) == 8
    result = recipe.resolve_step(artifact, 7, {}, [None] * 7)
    assert result.applied and result.arguments == {}


@pytest.mark.parametrize("marker,normal,incomplete", [
    ("pending", False, True), ("truncated", False, True),
    ("complete", True, False), ("dry_run", False, True),
])
def test_all_result_boundaries_refuse_reserved_incomplete_markers(marker, normal, incomplete):
    source = episodes()
    for item in source:
        item["steps"][0]["result"]["envelope"] = [{marker: normal}]
    artifact = recipe.synthesize(source, allowed_tools=TOOLS)
    bad = copy.deepcopy(source[0]["steps"][0]["result"])
    bad["envelope"][0][marker] = incomplete
    for operation in (recipe.require_complete_result, recipe.parse_result,
                      lambda value: recipe.parse_result(json.dumps(value)),
                      lambda value: recipe.validate_result(artifact, 0, value)):
        with pytest.raises(ValueError, match="incomplete or preview"):
            operation(bad)
    resolved = recipe.resolve_step(artifact, 1, source[0]["inputs"], [bad])
    assert resolved.reason == "outside_domain" and resolved.arguments is None
    source[0]["steps"][0]["result"] = bad
    with pytest.raises(ValueError, match="incomplete or preview"):
        recipe.synthesize(source, allowed_tools=TOOLS)


@pytest.mark.parametrize("value", [
    {"accepted": False}, {"status": "pending"}, {"error": "business text"},
    {"pending": False, "truncated": False, "complete": True, "dry_run": False},
    {"pending": 1, "truncated": "true", "complete": 0, "dry_run": "true"},
])
def test_completeness_guard_does_not_infer_custom_business_semantics(value):
    recipe.require_complete_result(value)
    assert recipe.parse_result(json.dumps(value)) == value


def test_completeness_helper_is_itself_bounded_and_strict():
    for value in ([0] * 513, {"text": "x" * 1025}, {"x": math.inf}, (1, 2)):
        with pytest.raises(ValueError):
            recipe.require_complete_result(value)
