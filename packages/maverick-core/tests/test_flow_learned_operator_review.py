"""Independent grammar oracle and hostile-input checks for executable learning."""
from __future__ import annotations

import copy
import hashlib
import itertools
import json

import pytest
from maverick import audit, config, learning_guard
from maverick.audit.errors import AuditRefused
from maverick.budget import BudgetExceeded
from maverick.flow import Flow, FlowNode, evolve, runner, store
from maverick.flow import learned_operator as engine
from maverick.killswitch import Halted


def _key(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _row(output, **inputs):
    return {"inputs": inputs, "output": output}


def _number(**inputs):
    return {name: {"type": "integer", "min": bounds[0], "max": bounds[1]}
            for name, bounds in inputs.items()}


def _resign(artifact):
    payload = {key: value for key, value in artifact.items() if key != "artifact_sha256"}
    artifact["artifact_sha256"] = hashlib.sha256(_key(payload).encode()).hexdigest()
    return artifact


def _reference_run(program, values):
    """Deliberately separate evaluator; no engine private execution helpers."""
    op, *args = program
    if op == "field":
        return values[args[0]]
    if op == "literal":
        return args[0]
    if op == "if":
        return _reference_run(args[1 if _reference_run(args[0], values) else 2], values)
    operands = [_reference_run(arg, values) for arg in args]
    operations = {
        "strip": lambda a: a.strip(), "upper": lambda a: a.upper(), "lower": lambda a: a.lower(),
        "not": lambda a: not a, "add": lambda a, b: a + b, "sub": lambda a, b: a - b,
        "mul": lambda a, b: a * b, "min": min, "max": max,
        "eq": lambda a, b: a == b, "lt": lambda a, b: a < b, "le": lambda a, b: a <= b,
    }
    return operations[op](*operands)


def _reference_grammar(spec):
    """Enumerate declared scalar grammar without training-vector pruning.

    Arithmetic/equality commutative forms use a single canonical order. Field
    comparisons with themselves are atomic comparisons, not constant-only
    syntax. Distinct arms are required, and nesting is otherwise absent.
    """
    atoms = {"integer": [], "boolean": [], "string": []}
    for name, declaration in spec["inputs"].items():
        atoms[declaration["type"]].append(["field", name])
    for constant in spec.get("constants", []):
        kind = {int: "integer", bool: "boolean", str: "string"}[type(constant)]
        atoms[kind].append(["literal", constant])
    output = spec["output_type"]
    programs = list(atoms[output])
    if output == "integer":
        for left, right in itertools.product(atoms[output], repeat=2):
            if left[0] == right[0] == "literal":
                continue
            for op in ["add", "sub", "mul", "min", "max"]:
                operands = [left, right] if op == "sub" else sorted([left, right], key=_key)
                programs.append([op, *operands])
    else:
        for atom in atoms[output]:
            programs.extend([op, atom] for op in (["not"] if output == "boolean"
                                                 else ["strip", "lower", "upper"]))
    predicates = list(atoms["boolean"])
    for kind, group in atoms.items():
        for left, right in itertools.product(group, repeat=2):
            if left[0] == right[0] == "literal":
                continue
            for op in (["eq", "lt", "le"] if kind == "integer" else ["eq"]):
                operands = sorted([left, right], key=_key) if op == "eq" else [left, right]
                predicates.append([op, *operands])
    if output == "boolean":
        programs.extend(predicates)
    programs.extend(["if", predicate, yes, no]
                    for predicate, yes, no in itertools.product(predicates, atoms[output], atoms[output])
                    if _key(yes) != _key(no))
    return {_key(program): program for program in programs}


def test_reflexive_field_comparison_prevents_false_boolean_agreement():
    spec = {"inputs": {"flag": {"type": "boolean"}, **_number(x=(0, 4))},
            "output_type": "boolean"}
    examples = [_row(True, flag=True, x=1), _row(True, flag=True, x=2)]
    artifact = engine.synthesize(spec, examples)
    alternative = ["eq", ["field", "x"], ["field", "x"]]
    assert all(_reference_run(alternative, row["inputs"]) == row["output"] for row in examples)
    assert _reference_run(alternative, {"flag": False, "x": 3}) is True
    decision = engine.evaluate(artifact, {"flag": False, "x": 3})
    assert not decision.applied and decision.reason == "ambiguity", (artifact["candidates"], decision)


@pytest.mark.parametrize("output,examples", [
    ("integer", [_row(0, x=0, y=0, flag=True), _row(1, x=1, y=1, flag=False)]),
    ("boolean", [_row(True, x=0, y=0, flag=True), _row(True, x=1, y=1, flag=False)]),
    ("string", [_row("yes", x=0, y=0, flag=True), _row("no", x=1, y=1, flag=False)]),
])
def test_complete_space_matches_independent_unpruned_enumerator(output, examples):
    spec = {"inputs": {**_number(x=(-1, 2), y=(-1, 2)), "flag": {"type": "boolean"}},
            "output_type": output, "constants": [0, 2, True, False, "yes", "no"]}
    reference = _reference_grammar(spec)
    consistent = {key: program for key, program in reference.items()
                  if all(_key(_reference_run(program, row["inputs"])) == _key(row["output"])
                         for row in examples)}
    artifact = engine.synthesize(spec, examples)
    actual = {_key(program): program for program in artifact["candidates"]}
    assert actual.keys() == consistent.keys()
    for x, y, flag in itertools.product(range(-1, 3), range(-1, 3), [False, True]):
        values = {"x": x, "y": y, "flag": flag}
        answers = {_key(_reference_run(program, values)) for program in consistent.values()}
        decision = engine.evaluate(artifact, values)
        assert decision.applied == (len(answers) == 1)
        if decision.applied:
            assert _key(decision.value) == next(iter(answers))


@pytest.mark.parametrize("text", ["\ud800", "\udfff", "a\ud800b"])
def test_runtime_non_unicode_scalar_abstains_instead_of_raising(text):
    spec = {"inputs": {"text": {"type": "string", "max_length": 8}}, "output_type": "string"}
    artifact = engine.synthesize(spec, [_row("A", text="a"), _row("B", text="b")])
    result = engine.evaluate(artifact, {"text": text})
    assert not result.applied and result.reason == "outside_domain"


def test_unseen_branch_alternatives_are_not_pruned_by_identical_training_vectors():
    spec = {"inputs": {"approved": {"type": "boolean"}, **_number(amount=(0, 100))},
            "output_type": "integer", "constants": [0, 10]}
    artifact = engine.synthesize(spec, [_row(5, approved=True, amount=5),
                                       _row(20, approved=True, amount=20)])
    assert ["if", ["field", "approved"], ["field", "amount"], ["literal", 0]] in artifact["candidates"]
    assert ["if", ["field", "approved"], ["field", "amount"], ["literal", 10]] in artifact["candidates"]
    assert engine.evaluate(artifact, {"approved": False, "amount": 7}).reason == "ambiguity"
    for amount in [5, 20]:
        result = engine.evaluate(artifact, {"approved": True, "amount": amount})
        assert result.applied and result.value == amount


def test_public_artifact_and_example_mutation_cannot_poison_cached_validation():
    spec = {"inputs": _number(x=(-3, 3)), "output_type": "integer", "constants": [2]}
    examples = [_row(2, x=1), _row(6, x=3)]
    artifact = engine.synthesize(spec, examples)
    original = copy.deepcopy(artifact)
    engine.validate_artifact(artifact)
    examples[0]["output"] = -999
    spec["constants"].append(999)
    artifact["candidates"] = [["literal", -999]]
    _resign(artifact)
    assert engine.evaluate(artifact, {"x": 2}).reason == "invalid_artifact"
    decision = engine.evaluate(original, {"x": 2})
    assert decision.applied and decision.value == 4


@pytest.mark.parametrize("damage", [
    lambda item: item["candidates"].append(item["candidates"][0]),
    lambda item: item["candidates"].reverse(),
    lambda item: item.update(example_count=False),
    lambda item: item["spec"].update(extra="claim"),
])
def test_rehashed_noncanonical_artifact_is_rejected(damage):
    artifact = engine.synthesize({"inputs": _number(x=(-2, 3), y=(-2, 3)), "output_type": "integer"},
                                 [_row(0, x=0, y=0), _row(1, x=1, y=1)])
    damage(artifact)
    _resign(artifact)
    assert engine.evaluate(artifact, {"x": 2, "y": 3}).reason == "invalid_artifact"


@pytest.fixture
def flow_review_enabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setattr(config, "get_flows", lambda: {"learned_operators": True})
    monkeypatch.setattr(learning_guard, "check_learning_halt", lambda *args: None)


def _review_flow():
    artifact = engine.synthesize(
        {"inputs": _number(x=(0, 20)), "output_type": "integer", "constants": [2]},
        [_row(2, x=1), _row(6, x=3)],
    )
    original = Flow(id="independent-review", name="Review", start="calculate", nodes={
        "calculate": FlowNode(id="calculate", kind="agent", brief="Calculate {{x}}",
                              output="answer", next="effect", on_error="recover"),
        "effect": FlowNode(id="effect", kind="action", tool="web_search",
                           params={"body": "{{answer}}"}, next="after"),
        "after": FlowNode(id="after", kind="agent", brief="Follow up"),
        "recover": FlowNode(id="recover", kind="agent", brief="Recover"),
    })
    return evolve.attach_learned_operator(original, "calculate", artifact)


@pytest.mark.parametrize("value", [2, 21])
@pytest.mark.parametrize("failure", [False, None, 1.0, AuditRefused("refused"),
                                    OSError("sink"), BudgetExceeded("budget"), Halted("stop", "test")])
def test_selective_decision_refusal_prevents_original_agent_and_all_downstream_work(
        flow_review_enabled, monkeypatch, value, failure):
    """Other event types succeeding cannot bypass the one required receipt."""
    trace = []

    def record(kind, **payload):
        if kind == audit.EventKind.FLOW_LEARNED_OPERATOR_DECISION:
            trace.append(("decision", payload["status"]))
            if isinstance(failure, Exception):
                raise failure
            return failure
        return True

    def executor(*args):
        trace.append(("unexpected-effect", args[0].id))
        return "effect", 1.0

    monkeypatch.setattr(audit, "record", record)
    expected = type(failure) if isinstance(failure, (AuditRefused, BudgetExceeded, Halted)) else AuditRefused
    with pytest.raises(expected):
        runner.run_flow(_review_flow(), data={"x": value}, agent_fn=executor, action_fn=executor)
    assert trace == [("decision", "applied" if value == 2 else "fallback")]


def test_execution_uses_each_pinned_artifact_after_draft_edit_and_export_mutation(
        flow_review_enabled, monkeypatch, tmp_path):
    monkeypatch.setattr("maverick.paths.data_dir", lambda *parts, **kwargs: tmp_path.joinpath(*parts))
    receipts, effects = [], []

    def record(kind, **payload):
        receipts.append(payload)
        return True

    def action(node, params, data):
        effects.append((params, data["answer"]))
        return "sent", 1.0

    monkeypatch.setattr(audit, "record", record)
    first = _review_flow()
    # The action is our local effect observation; there is no network tool call.
    first.nodes["effect"].next = None
    first_digest, _, _ = store.snapshot_flow_bundle(first)
    second = evolve.attach_learned_operator(first, "calculate", engine.synthesize(
        {"inputs": _number(x=(0, 20)), "output_type": "integer"},
        [_row(1, x=1), _row(3, x=3)],
    ))
    second_digest, _, _ = store.snapshot_flow_bundle(second)
    assert first_digest != second_digest
    first.nodes["calculate"].brief = "Changed work"
    second.nodes["calculate"].learned_operator["artifact"]["examples"][0]["output"] = 999
    loaded = store.load_flow_snapshot(first_digest)
    exported = loaded.to_dict()
    exported["nodes"][0]["learned_operator"]["artifact"]["candidates"].clear()
    for digest, answer in [(first_digest, 4), (second_digest, 2)]:
        result = runner.run_flow(
            store.load_flow_snapshot(digest), data={"x": 2, "private": "NOT-IN-RECEIPT"},
            agent_fn=lambda *args: pytest.fail("snapshot should use its retained scalar operator"),
            action_fn=action,
        )
        assert result.status == "completed" and result.data["answer"] == answer
    assert effects == [({"body": "4"}, 4), ({"body": "2"}, 2)]
    assert len(receipts) == 2
    assert receipts[0]["artifact_sha256"] != receipts[1]["artifact_sha256"]
    assert receipts[0]["work_sha256"] == receipts[1]["work_sha256"]
    assert "NOT-IN-RECEIPT" not in json.dumps(receipts)
    assert all(set(receipt) == {"agent", "flow_id", "flow_run_id", "node_id", "status", "reason",
                               "artifact_sha256", "work_sha256", "candidate_count"}
               for receipt in receipts)
