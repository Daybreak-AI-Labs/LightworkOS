"""Pure transducer qualification; these traces assert no native execution."""
from __future__ import annotations

import copy
import itertools

import pytest
from maverick.flow import action_recipe_transforms as transforms
from maverick.flow import composed_operator
from maverick.flow import workflow_transducer as workflow


def obj(**properties):
    return {"type": "object", "properties": properties, "required": sorted(properties),
            "additionalProperties": False}


TEXT = {"type": "string", "maxLength": 64}
BOOL = {"type": "boolean"}


def step(tool, arguments, result):
    return {"tool": tool, "arguments": arguments, "result": result}


def conditional_episode(identity, needed, alias):
    case = f"case-{identity}"
    steps = [step("lookup", {"id": identity}, {"case_id": case})]
    if needed:
        steps.append(step("read_detail", {"case_id": case}, {"verified": True}))
    steps.append(step("finish", {"case_id": case}, {"ok": True}))
    return {"id": identity, "inputs": {"id": identity, "needed": needed, "alias": alias}, "steps": steps}


CONDITIONAL_DOMAIN = {"inputs": obj(id=TEXT, needed=BOOL, alias=BOOL), "tools": {
    "lookup": {"arguments": obj(id=TEXT), "result": obj(case_id=TEXT)},
    "read_detail": {"arguments": obj(case_id=TEXT), "result": obj(verified=BOOL)},
    "finish": {"arguments": obj(case_id=TEXT), "result": obj(ok=BOOL)},
}}


@pytest.fixture(scope="module")
def conditional():
    episodes = [conditional_episode(f"seed-{i}", needed, alias)
                for i, (needed, alias) in enumerate([(False, False), (True, True), (False, True), (True, False)])]
    return workflow.synthesize(episodes, allowed_tools=list(CONDITIONAL_DOMAIN["tools"]),
        domain=CONDITIONAL_DOMAIN, max_operations=1, operators=["if"])


def assert_trace(artifact, episode):
    prefix = []
    for observed in episode["steps"]:
        decision = workflow.resolve_next(artifact, episode["inputs"], prefix)
        assert decision.applied and decision.kind == "action", decision
        assert (decision.tool, decision.arguments) == (observed["tool"], observed["arguments"])
        workflow.validate_observation(artifact, observed["tool"], observed["result"])
        prefix.append(copy.deepcopy(observed))
    final = workflow.resolve_next(artifact, episode["inputs"], prefix)
    assert final.applied and final.kind == "complete" and final.tool is None and final.arguments is None


@pytest.mark.parametrize("needed,alias", [(False, False), (True, True), (False, True), (True, False)])
def test_variable_length_conditional_read_and_fresh_result_binding(conditional, needed, alias):
    episode = conditional_episode(f"unseen-{needed}-{alias}", needed, alias)
    assert len(episode["steps"]) == 2 + int(needed)
    assert_trace(conditional, episode)


LOOP_DOMAIN = {"inputs": obj(id=TEXT), "tools": {
    "begin": {"arguments": obj(id=TEXT), "result": obj(task_id=TEXT)},
    "observe": {"arguments": obj(task_id=TEXT), "result": obj(receipt_id=TEXT, done=BOOL, alias=BOOL)},
}}


def loop_episode(identity, flags):
    task = f"task-{identity}"
    return {"id": identity, "inputs": {"id": identity}, "steps": [
        step("begin", {"id": identity}, {"task_id": task}),
        *(step("observe", {"task_id": task}, {"receipt_id": f"receipt-{identity}-{index}",
           "done": done, "alias": alias}) for index, (done, alias) in enumerate(flags))]}


@pytest.fixture(scope="module")
def looping():
    return workflow.synthesize([
        loop_episode("seed-a", [(False, False), (True, True)]),
        loop_episode("seed-b", [(False, False), (False, False), (True, True)]),
    ], allowed_tools=list(LOOP_DOMAIN["tools"]), domain=LOOP_DOMAIN, operators=["if"], max_steps=5)


def test_learned_stop_disagreement_preserved_then_refined_from_whole_traces(looping):
    changed = loop_episode("new-crossed", [(True, False)])
    decision = workflow.resolve_next(looping, changed["inputs"], changed["steps"])
    assert not decision.applied and decision.kind == "refused" and decision.reason == "ambiguity"
    corrected = workflow.refine(looping, [
        loop_episode("counter-a", [(True, False)]),
        loop_episode("counter-b", [(False, True), (True, False)]),
    ])
    assert corrected["grammar"] == looping["grammar"] and corrected["max_steps"] == 5
    assert corrected["episode_count"] == 4
    # Five calls, longer than any demonstration. All observed IDs are fresh;
    # each repeat uses the retained begin result, not the latest receipt ID.
    unseen = loop_episode("heldout-long", [(False, True), (False, False), (False, True), (True, False)])
    assert_trace(corrected, unseen)
    assert len({step["result"].get("receipt_id") for step in unseen["steps"][1:]}) == 4
    unfinished = loop_episode("heldout-cap", [(False, False)] * 4)
    at_cap = workflow.resolve_next(corrected, unfinished["inputs"], unfinished["steps"])
    assert not at_cap.applied and at_cap.reason == "step_limit"


def test_repetition_binds_the_latest_result_not_a_fixed_earlier_step():
    domain = {"inputs": obj(id=TEXT), "tools": {
        "open": {"arguments": obj(id=TEXT), "result": obj(token=TEXT)},
        "advance": {"arguments": obj(token=TEXT), "result": obj(token=TEXT, done=BOOL)},
    }}

    def episode(identity, count):
        token = f"{identity}-token-0"
        steps = [step("open", {"id": identity}, {"token": token})]
        for index in range(1, count + 1):
            previous, token = token, f"{identity}-token-{index}"
            steps.append(step("advance", {"token": previous}, {"token": token, "done": index == count}))
        return {"id": identity, "inputs": {"id": identity}, "steps": steps}

    artifact = workflow.synthesize([episode("teacher-a", 2), episode("teacher-b", 3)],
        allowed_tools=list(domain["tools"]), domain=domain, operators=["if"], max_steps=6)
    fresh = episode("unseen-chain", 4)
    assert_trace(artifact, fresh)
    fresh["steps"][3]["arguments"]["token"] = fresh["steps"][0]["result"]["token"]
    assert workflow.resolve_next(artifact, fresh["inputs"], fresh["steps"]).reason == "invalid_history"


def test_tool_order_is_inferred_from_examples_without_an_authored_graph():
    domain = {"inputs": obj(reverse=BOOL), "tools": {
        "fetch_a": {"arguments": obj(), "result": obj(a=TEXT)},
        "fetch_b": {"arguments": obj(), "result": obj(b=TEXT)},
        "join": {"arguments": obj(a=TEXT, b=TEXT), "result": obj(ok=BOOL)},
    }}

    def episode(identity, reverse):
        a, b = f"A-{identity}", f"B-{identity}"
        reads = [step("fetch_a", {}, {"a": a}), step("fetch_b", {}, {"b": b})]
        return {"id": identity, "inputs": {"reverse": reverse},
                "steps": [*(reversed(reads) if reverse else reads), step("join", {"a": a, "b": b}, {"ok": True})]}

    artifact = workflow.synthesize([episode("normal", False), episode("reverse", True)],
        allowed_tools=list(domain["tools"]), domain=domain, operators=["if"])
    assert_trace(artifact, episode("unseen-normal", False))
    assert_trace(artifact, episode("unseen-reverse", True))


def test_independent_one_operation_guard_enumerator_matches_all_retained_counts(conditional):
    """Enumerate syntax trees independently, rather than reuse packed states."""
    labels = ["complete", *("action:" + tool for tool in conditional["allowed_tools"])]
    for state in conditional["states"]:
        rows = []
        for episode in conditional["episodes"]:
            for index in range(len(episode["steps"]) + 1):
                prefix = episode["steps"][:index]
                if ((prefix[-1]["tool"] if prefix else None) != state["last_tool"]
                        or sorted({item["tool"] for item in prefix}) != state["available_results"]):
                    continue
                latest = {item["tool"]: item["result"] for item in prefix}
                values = {}
                for source in state["catalog"]:
                    value = episode["inputs"] if source["source"] == "input" else latest[source["tool"]]
                    for part in source["path"]:
                        value = value[part]
                    values[source["name"]] = value
                target = "complete" if index == len(episode["steps"]) else "action:" + episode["steps"][index]["tool"]
                rows.append((values, target))
        string_atoms = [("field", item["name"]) for item in state["catalog"] if item["type"] == "string"]
        string_atoms += [("literal", label) for label in labels]
        predicates = [item["name"] for item in state["catalog"] if item["type"] == "boolean"]

        def atom_value(atom, values):
            return atom[1] if atom[0] == "literal" else values[atom[1]]

        candidates = sum(all(atom_value(atom, values) == target for values, target in rows)
                         for atom in string_atoms)
        for predicate, yes, no in itertools.product(predicates, string_atoms, string_atoms):
            candidates += all(atom_value(yes if values[predicate] else no, values) == target
                              for values, target in rows)
        assert candidates == state["guard"]["candidate_count"]


def test_argument_aliases_are_preserved_when_training_values_coincide():
    episodes = [conditional_episode("alias-a", False, False), conditional_episode("alias-b", False, True)]
    for episode in episodes:
        identity = episode["inputs"]["id"]
        episode["steps"][0]["result"]["case_id"] = identity
        episode["steps"][1]["arguments"]["case_id"] = identity
    artifact = workflow.synthesize(episodes, allowed_tools=list(CONDITIONAL_DOMAIN["tools"]),
        domain=CONDITIONAL_DOMAIN, operators=["if"])
    unseen = conditional_episode("alias-unseen", False, True)
    decision = workflow.resolve_next(artifact, unseen["inputs"], unseen["steps"][:1])
    assert not decision.applied and decision.reason == "ambiguity"


@pytest.mark.parametrize("change", [
    lambda episode: episode["steps"].pop(0),
    lambda episode: episode["steps"][1]["arguments"].update(case_id="invented-id"),
    lambda episode: episode["inputs"].update(id="different-original-input"),
    lambda episode: episode["steps"][0]["result"].update(pending=True),
    lambda episode: episode["steps"][0]["arguments"].update(extra="hidden"),
])
def test_historical_tools_arguments_inputs_and_complete_results_are_revalidated(conditional, change):
    episode = conditional_episode("history-new", True, False)
    change(episode)
    decision = workflow.resolve_next(conditional, episode["inputs"], episode["steps"])
    assert not decision.applied and decision.reason == "invalid_history"


def test_no_post_completion_history_is_accepted(conditional):
    episode = conditional_episode("already-done", False, True)
    episode["steps"].append(copy.deepcopy(episode["steps"][-1]))
    assert workflow.resolve_next(conditional, episode["inputs"], episode["steps"]).reason == "invalid_history"


def test_strict_boolean_domains_and_omitted_inputs(conditional):
    inputs = {"id": "typed", "needed": False, "alias": True}
    for changed in ({**inputs, "needed": 0}, {"id": "typed", "needed": False}, {**inputs, "id": "x" * 65}):
        assert workflow.resolve_next(conditional, changed, []).reason == "outside_domain"
    with pytest.raises(ValueError, match="strict domain"):
        workflow.validate_observation(conditional, "finish", {"ok": 1})


def test_rehashed_candidate_omission_cannot_validate(conditional):
    changed = copy.deepcopy(conditional)
    child = changed["states"][0]["guard"]
    child["states"][child["roots"][0]]["alternatives"].pop()
    changed["artifact_sha256"] = transforms._digest({key: value for key, value in changed.items()
                                                    if key != "artifact_sha256"})
    with pytest.raises(ValueError, match="complete inferred"):
        workflow.validate_artifact(changed)
    assert workflow.resolve_next(changed, {"id": "x", "needed": False, "alias": False}, []).reason == "invalid_artifact"


def test_empty_business_objects_need_no_fabricated_source_fields():
    domain = {"inputs": obj(), "tools": {"touch": {"arguments": obj(), "result": obj()}}}
    artifact = workflow.synthesize([{"id": key, "inputs": {}, "steps": [step("touch", {}, {})]}
                                    for key in ("a", "b")], allowed_tools=["touch"], domain=domain,
                                   operators=["if"], max_steps=1)
    assert artifact["states"][0]["catalog"] == []
    assert_trace(artifact, {"inputs": {}, "steps": [step("touch", {}, {})]})


def test_indistinguishable_latest_observations_cannot_learn_a_hidden_repeat_counter():
    domain = {"inputs": obj(), "tools": {"touch": {"arguments": obj(), "result": obj()}}}
    episodes = [{"id": "once", "inputs": {}, "steps": [step("touch", {}, {})]},
                {"id": "twice", "inputs": {}, "steps": [step("touch", {}, {}), step("touch", {}, {})]}]
    with pytest.raises(ValueError, match="no composed program"):
        workflow.synthesize(episodes, allowed_tools=["touch"], domain=domain, operators=["if"])


def test_sources_are_never_silently_truncated():
    domain = copy.deepcopy(CONDITIONAL_DOMAIN)
    domain["inputs"] = obj(**{f"field{i}": BOOL for i in range(13)})
    episodes = [conditional_episode("many-a", False, False), conditional_episode("many-b", False, False)]
    for episode in episodes:
        episode["inputs"] = {f"field{i}": False for i in range(13)}
    with pytest.raises(ValueError, match="no fields were omitted"):
        workflow.synthesize(episodes, allowed_tools=list(domain["tools"]), domain=domain, operators=["if"])


def test_whole_synthesis_limit_never_returns_partial_artifact(monkeypatch):
    monkeypatch.setattr(workflow, "MAX_PRODUCTIONS", 1)
    with pytest.raises(composed_operator.SynthesisLimit, match="whole workflow"):
        workflow.synthesize([conditional_episode("limit-a", False, False), conditional_episode("limit-b", True, True)],
            allowed_tools=list(CONDITIONAL_DOMAIN["tools"]), domain=CONDITIONAL_DOMAIN, operators=["if"])


def test_resolution_budget_is_shared_across_history_and_next_decision(conditional, monkeypatch):
    budgets = []
    original = workflow._ResolveBudget

    class ObservedBudget(original):
        def __init__(self):
            super().__init__()
            budgets.append(self)

    monkeypatch.setattr(workflow, "_ResolveBudget", ObservedBudget)
    episode = conditional_episode("budget-fresh", True, False)
    assert workflow.resolve_next(conditional, episode["inputs"], []).applied
    first_cost = budgets[-1].used
    budgets.clear()
    assert workflow.resolve_next(conditional, episode["inputs"], episode["steps"]).kind == "complete"
    assert len(budgets) == 1 and budgets[0].used > first_cost
    monkeypatch.setattr(workflow, "MAX_RESOLVE_EVALUATIONS", first_cost)
    assert workflow.resolve_next(conditional, episode["inputs"], []).applied
    assert workflow.resolve_next(conditional, episode["inputs"], episode["steps"]).reason == "evaluation_limit"


@pytest.mark.parametrize("kwargs", [{"max_operations": 3}, {"max_operations": True},
    {"max_steps": 9}, {"max_steps": True}, {"operators": ["execute"]}, {"constants": [False] * 9}])
def test_undeclared_or_unbounded_grammar_is_refused(kwargs):
    with pytest.raises(ValueError):
        workflow.synthesize([conditional_episode("grammar-a", False, False), conditional_episode("grammar-b", True, True)],
            allowed_tools=list(CONDITIONAL_DOMAIN["tools"]), domain=CONDITIONAL_DOMAIN, **kwargs)
