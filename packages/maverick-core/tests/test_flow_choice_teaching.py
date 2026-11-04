"""Pure teaching questions bind actual supplied observations, never invented args."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from maverick.flow import action_choice as choice
from maverick.flow import choice_teaching as teaching
from maverick.flow import composed_operator as composed

_spec = importlib.util.spec_from_file_location("choice_teaching_examples", Path(__file__).with_name("test_flow_action_choice.py"))
_examples = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_examples)


def observation():
    inputs, prior = _examples.runtime(5, 2, False)
    return inputs, prior[0]


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")).hexdigest()


def question():
    artifact = _examples.learn()
    inputs, prefix = observation()
    return artifact, teaching.propose(artifact, inputs, prefix), inputs, prefix


def test_true_guard_disagreement_offers_exact_tools_and_unanimous_actual_arguments():
    artifact, offered, inputs, prefix = question()
    assert not choice.resolve_choice(artifact, inputs, [prefix]).applied
    assert teaching.TEACHING_SCHEMA == "lightwork.action-choice-teaching.v1"
    assert offered["schema"] == teaching.QUESTION_SCHEMA
    assert offered["options"] == [
        {"route": "0", "tool": "approve_case", "arguments": {"case_id": "fresh-generated", "total": 5},
         "arguments_sha256": digest({"case_id": "fresh-generated", "total": 5})},
        {"route": "1", "tool": "queue_review", "arguments": {"case_id": "fresh-generated", "review_amount": 5},
         "arguments_sha256": digest({"case_id": "fresh-generated", "review_amount": 5})}]
    assert {row["output"] for row in offered["guard_partitions"]} == {False, True}
    assert all(type(row["output"]) is bool and type(row["candidate_count"]) is int
               and row["candidate_count"] > 0 for row in offered["guard_partitions"])
    assert sum(row["candidate_count"] for row in offered["guard_partitions"]) == artifact["guard_candidate_count"]
    assert offered["artifact_sha256"] == artifact["artifact_sha256"]
    assert offered["guard_artifact_sha256"] == artifact["guard"]["artifact"]["artifact_sha256"]
    assert offered["input_sha256"] == digest(inputs)
    assert offered["prefix_sha256"] == digest({"input": inputs, "prior_results": [prefix]})
    assert offered["question_sha256"] == digest({key: value for key, value in offered.items() if key != "question_sha256"})
    teaching.validate_question(artifact, offered)


@pytest.mark.parametrize("route,tool", [("0", "approve_case"), ("1", "queue_review")])
def test_selection_is_an_exact_offered_route_not_guard_agreement_or_automatic_learning(monkeypatch, route, tool):
    artifact, offered, inputs, prefix = question()
    before = copy.deepcopy(artifact)
    monkeypatch.setattr(choice, "refine", lambda *args, **kwargs: pytest.fail("selection must never teach a label"))
    chosen = teaching.select(artifact, offered, route, inputs, prefix)
    assert chosen.applied and chosen.tool == tool and chosen.reason == "teaching_selection"
    assert chosen.arguments == offered["options"][int(route)]["arguments"]
    assert artifact == before
    assert not choice.resolve_choice(artifact, inputs, [prefix]).applied
    binding = teaching.selection_binding(artifact, offered, route)
    assert binding == {key: offered[key] for key in ("artifact_sha256", "guard_artifact_sha256", "question_sha256",
                                                   "input_sha256", "prefix_sha256")} | {
        "route": route, "tool": tool, "arguments_sha256": digest(chosen.arguments)}
    assert "human" not in binding and "authenticated" not in binding
    assert "observation" not in binding and "arguments" not in binding


def test_guard_agreement_requires_no_teaching_question():
    artifact = _examples.learn()
    inputs, prior = _examples.runtime(1, 2, False)
    assert choice.resolve_choice(artifact, inputs, prior).applied
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prior[0])
    assert raised.value.reason == "guard_agreement"


def test_one_branch_argument_ambiguity_refuses_the_entire_question():
    rows = _examples.examples()
    for row in rows[:2]:
        row["inputs"]["amount"] = 1
        row["steps"][1]["arguments"]["total"] = 1
    artifact = _examples.learn(rows)
    inputs, prefix = observation()
    assert choice.resolve_choice(artifact, inputs, [prefix]).reason == "ambiguity"
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "argument_ambiguity"


def test_out_of_domain_argument_is_not_offered_even_when_all_trees_agree():
    rows = _examples.examples()
    declared = _examples.domain(rows)
    declared["branches"]["approve_case"]["arguments"]["properties"]["total"]["maximum"] = 2
    artifact = _examples.learn(rows, domain=declared)
    inputs, prefix = observation()
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "argument_outside_domain"


@pytest.mark.parametrize("route", [0, 1, False, True, None, "2", "approve_case", [], {}])
def test_route_must_be_the_exact_offered_string(route):
    artifact, offered, inputs, prefix = question()
    chosen = teaching.select(artifact, offered, route, inputs, prefix)
    assert not chosen.applied and chosen.tool is None and chosen.arguments is None and chosen.reason == "invalid_route"
    with pytest.raises(ValueError):
        teaching.selection_binding(artifact, offered, route)


@pytest.mark.parametrize("mutate", [
    lambda q: q["options"].pop(),
    lambda q: q["options"].reverse(),
    lambda q: q["options"][0].update(tool="unobserved_tool"),
    lambda q: q["options"][0].update(route="1"),
    lambda q: q["options"][0]["arguments"].update(total=7),
    lambda q: q["guard_partitions"].pop(),
    lambda q: q["guard_partitions"][0].update(candidate_count=1),
    lambda q: q["observation"]["prefix_result"].update(case_id="substituted"),
    lambda q: q.update(input_sha256="0" * 64),
    lambda q: q.update(guard_artifact_sha256="0" * 64),
    lambda q: q.update(authenticated=True),
])
def test_rehashing_does_not_make_edited_alternatives_or_observation_valid(mutate):
    artifact, offered, inputs, prefix = question()
    mutate(offered)
    offered["question_sha256"] = digest({key: value for key, value in offered.items() if key != "question_sha256"})
    with pytest.raises(ValueError):
        teaching.validate_question(artifact, offered)
    chosen = teaching.select(artifact, offered, "0", inputs, prefix)
    assert not chosen.applied and chosen.reason == "invalid_question"


@pytest.mark.parametrize("target", ["input", "prefix"])
def test_valid_question_for_other_actual_values_cannot_select_current_observation(target):
    artifact, offered, inputs, prefix = question()
    if target == "input":
        inputs["amount"] = 6
    else:
        prefix["case_id"] = "another-generated-id"
    assert teaching.select(artifact, offered, "0", inputs, prefix).reason == "observation_changed"


@pytest.mark.parametrize("inputs,prefix", [
    ({"amount": True, "limit": 2, "customer": "new"}, {"case_id": "actual", "legacy": False}),
    ({"amount": 101, "limit": 2, "customer": "new"}, {"case_id": "actual", "legacy": False}),
    ({"amount": 5, "limit": 2, "customer": "new"}, {"case_id": "actual", "legacy": False, "pending": True}),
    ({"amount": 5, "limit": 2, "customer": "new"}, {"case_id": "actual", "legacy": 0}),
    ({"amount": 5, "limit": 2, "customer": "new", "route": "0"}, {"case_id": "actual", "legacy": False}),
])
def test_current_values_require_original_exact_typed_domain_and_complete_prefix(inputs, prefix):
    artifact, offered, _inputs, _prefix = question()
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "outside_domain"
    assert teaching.select(artifact, offered, "0", inputs, prefix).reason == "outside_domain"


def test_same_shape_pending_result_cannot_be_presented_as_a_confirmed_prefix():
    rows = _examples.examples()
    for row in rows:
        row["steps"][0]["result"]["pending"] = False
    artifact = _examples.learn(rows)
    inputs, prefix = observation()
    prefix["pending"] = True
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "outside_domain"


def test_invalid_artifact_has_no_offered_or_selected_action():
    artifact, offered, inputs, prefix = question()
    artifact["guard"]["artifact"]["roots"].clear()
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "invalid_artifact"
    selected = teaching.select(artifact, offered, "0", inputs, prefix)
    assert not selected.applied and selected.arguments is None and selected.tool is None
    assert selected.reason == "invalid_artifact"


def test_shared_guard_plus_both_branches_cost_refuses_before_branch_evaluation(monkeypatch):
    artifact, _offered, inputs, prefix = question()
    monkeypatch.setattr(composed, "evaluation_cost", lambda _artifact: 40_000)
    monkeypatch.setattr(choice, "_arguments", lambda *args: pytest.fail("total cost must precede arguments"))
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "evaluation_limit"


def test_incomplete_guard_distribution_never_offers_partial_options(monkeypatch):
    artifact, _offered, inputs, prefix = question()
    monkeypatch.setattr(composed, "partitions", lambda *args: None)
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "predictions_unavailable"


def test_whole_question_limit_refuses_without_truncating_options(monkeypatch):
    artifact, offered, inputs, prefix = question()
    monkeypatch.setattr(teaching, "MAX_QUESTION_BYTES", len(teaching._canonical(offered).encode("utf-8")) - 1)
    with pytest.raises(teaching.TeachingUnavailable) as raised:
        teaching.propose(artifact, inputs, prefix)
    assert raised.value.reason == "question_limit"


def test_snapshots_unicode_and_opaque_template_text_survive_without_aliases():
    artifact = _examples.learn()
    inputs, prefix = observation()
    inputs["customer"] = "客户"
    prefix["case_id"] = "{{secret('opaque')}}"
    offered = teaching.propose(artifact, inputs, prefix)
    saved = copy.deepcopy(offered)
    inputs["customer"] = "changed"
    prefix["case_id"] = "changed"
    assert offered == saved
    observed = offered["observation"]
    chosen = teaching.select(artifact, offered, "0", observed["inputs"], observed["prefix_result"])
    assert chosen.arguments["case_id"] == "{{secret('opaque')}}"
    chosen.arguments["case_id"] = "mutated-return"
    assert offered == saved
    assert teaching.propose(artifact, observed["inputs"], observed["prefix_result"]) == saved


def test_stale_question_cannot_override_newly_refined_guard():
    artifact, offered, inputs, prefix = question()
    refined = choice.refine(artifact, [_examples.episode("e", 0, 1, legacy=True),
                                       _examples.episode("f", 5, 4, legacy=False)])
    assert choice.resolve_choice(refined, inputs, [prefix]).applied
    assert teaching.select(refined, offered, "0", inputs, prefix).reason == "invalid_question"
