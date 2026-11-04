"""Independent guard oracle and native execution boundaries for learned choices."""
from __future__ import annotations

import copy
import importlib.util
import itertools
import json
from pathlib import Path

import pytest
from maverick import audit, config
from maverick.audit.errors import AuditRefused
from maverick.flow import action_choice, execution, recipe_flow, store
from maverick.tools import Tool, ToolRegistry

_OPEN, _APPROVE, _QUEUE = "choice_lookup", "choice_accept", "choice_review"


def _obj(**fields):
    return {"type": "object", "properties": fields, "required": sorted(fields), "additionalProperties": False}


def _int(high=100):
    return {"type": "integer", "minimum": 0, "maximum": high}


def _episode(identity, amount, limit, review, ticket, tool):
    return {"id": identity, "inputs": {"amount": amount, "limit": limit, "review": review}, "steps": [
        {"tool": _OPEN, "arguments": {"amount": amount}, "result": {"ticket": ticket}},
        {"tool": tool, "arguments": {"ticket": ticket},
         "result": {"accepted": True} if tool == _APPROVE else {"queued": True}},
    ]}


def _artifact(*, operators=None, maximum=1):
    episodes = [_episode(f"seed-{i}", *row) for i, row in enumerate([
        (2, 5, False, 11, _APPROVE), (7, 8, False, 13, _APPROVE),
        (5, 3, True, 17, _QUEUE), (8, 7, True, 19, _QUEUE)])]
    domain = {"inputs": _obj(amount=_int(10), limit=_int(10), review={"type": "boolean"}),
        "prefix": {"arguments": _obj(amount=_int(10)), "result": _obj(ticket=_int())},
        "branches": {
            _APPROVE: {"arguments": _obj(ticket=_int()), "result": _obj(accepted={"type": "boolean"})},
            _QUEUE: {"arguments": _obj(ticket=_int()), "result": _obj(queued={"type": "boolean"})},
        }}
    return action_choice.synthesize_choice(episodes, allowed_tools=[_OPEN, _APPROVE, _QUEUE],
        domain=domain, max_operations=maximum, operators=["lt"] if operators is None else operators)


@pytest.mark.parametrize("operators,maximum", [(["lt"], 1), (["eq", "lt", "le", "not", "if"], 2)])
def test_full_guard_count_and_every_bounded_input_match_independent_tree_oracle(operators, maximum):
    spec = importlib.util.spec_from_file_location("choice_independent_oracle",
        Path(__file__).with_name("test_flow_composed_operator_review.py"))
    oracle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(oracle)
    artifact = _artifact(operators=operators, maximum=maximum)
    declaration = {"inputs": {"v000": {"type": "integer", "min": 0, "max": 10},
        "v001": {"type": "integer", "min": 0, "max": 10}, "v002": {"type": "boolean"},
        "v003": {"type": "integer", "min": 0, "max": 100}}, "output_type": "boolean", "constants": []}
    rows = [{"inputs": dict(zip(("v000", "v001", "v002", "v003"), row[:4], strict=True)),
             "output": row[4]} for row in [(2, 5, False, 11, False), (7, 8, False, 13, False),
                                         (5, 3, True, 17, True), (8, 7, True, 19, True)]]
    assert artifact["guard"]["artifact"]["spec"] == declaration
    trees = oracle._consistent(declaration, rows, maximum, operators)
    assert artifact["guard_candidate_count"] == len(trees) > 1
    if operators == ["lt"]:
        assert len(trees) == 2  # observed flag and limit < amount are both plausible
    for amount, limit, review, ticket in itertools.product(range(11), range(11), (False, True), (0, 23, 100)):
        values = dict(zip(("v000", "v001", "v002", "v003"), (amount, limit, review, ticket), strict=True))
        expected = oracle._partitions(trees, values)
        selected = action_choice.resolve_choice(artifact,
            {"amount": amount, "limit": limit, "review": review}, [{"ticket": ticket}])
        assert selected.applied is (len(expected) == 1)
        if selected.applied:
            assert selected.tool == (_QUEUE if expected[0]["output"] else _APPROVE)
            assert selected.route == str(int(expected[0]["output"]))
        else:
            assert selected.reason == "ambiguity" and selected.tool is None


@pytest.fixture
def native(tmp_path, monkeypatch):
    path = tmp_path / "choice-config.toml"
    path.write_text('[flows]\nenable=true\naction_recipes=true\naction_recipe_transforms=true\n'
                    'action_recipe_choices=true\n[security.tool_risk]\n'
                    'choice_lookup="low"\nchoice_accept="high"\nchoice_review="high"\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    # The receipts these tests verify are signed; pin signing so they hold under
    # the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "0")
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    config.reset_config_cache()
    calls = []
    registry = ToolRegistry(principal="reviewer")

    def call(name, arguments):
        calls.append((name, copy.deepcopy(arguments)))
        return json.dumps({"ticket": 23} if name == _OPEN else
                          {"accepted": True} if name == _APPROVE else {"queued": True})

    for name in (_OPEN, _APPROVE, _QUEUE):
        registry.register(Tool(name=name, description="Owned local choice fixture",
            input_schema=_obj(**{"amount" if name == _OPEN else "ticket": _int()}),
            fn=lambda arguments, tool=name: call(tool, arguments)))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *args, **kwargs: registry)
    return execution.default_action_runner(world=None, user_id="reviewer"), calls


def _flow():
    flow = recipe_flow.make_flow(_artifact(), flow_id="native-choice", name="Native choice")
    flow.owner = "reviewer"
    return flow


def _execute(native, *, flow=None, data=None, approve=None, run_id="native-choice"):
    return execution.execute(flow or _flow(), owner="reviewer", run_id=run_id,
        data={"input": {"amount": 3, "limit": 6, "review": False}} if data is None else data,
        action_runner=native[0], agent_runner=lambda *args: pytest.fail("agent fallback"),
        approve_fn=approve or (lambda *args: "approved"))


@pytest.mark.parametrize("amount,limit,review,tool", [(3, 6, False, _APPROVE), (7, 4, True, _QUEUE)])
def test_native_branch_uses_actual_prefix_and_signed_choice_receipts(native, amount, limit, review, tool):
    flow = _flow()
    flow = type(flow).from_dict(json.loads(json.dumps(flow.to_dict())))
    proposals = []

    def approve(node, data):
        proposals.append((node.id, copy.deepcopy(data["_recipe_next_arguments"])))
        return "approved"

    run = _execute(native, flow=flow, approve=approve,
        data={"input": {"amount": amount, "limit": limit, "review": review},
              "_recipe_choice": {"tool": "untrusted", "route": "untrusted"}})
    assert run.status == "completed", run.error
    assert native[1] == [(_OPEN, {"amount": amount}), (tool, {"ticket": 23})]
    route = "0" if tool == _APPROVE else "1"
    assert proposals == [("approval_0", {"amount": amount}), (f"approval_1_{route}", {"ticket": 23})]
    assert store.load_run(run.run_id).data["_recipe_choice"]["tool"] == tool
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    assert [event["status"] for event in events] == ["selected", "completed", "choice_selected", "selected", "completed"]
    bound = [event for event in events if "recipe_choice" in event]
    assert len(bound) == 3
    assert all(event["recipe_choice"] == run.data["_recipe_choice"] for event in bound)
    assert all(event["sig"] and "arguments" not in event and "episodes" not in event for event in events)


def test_guard_disagreement_preserves_prefix_and_redelivery_never_replays(native):
    run = _execute(native, data={"input": {"amount": 3, "limit": 6, "review": True}})
    assert run.status == "indeterminate" and "ambiguity" in run.error
    assert native[1] == [(_OPEN, {"amount": 3})]
    assert run.data["_recipe_step_0"] == {"ticket": 23}
    assert "_recipe_step_1" not in run.data
    again = _execute(native)
    assert again.status == "indeterminate" and len(native[1]) == 1


@pytest.mark.parametrize("key", ["action_recipes", "action_recipe_transforms", "action_recipe_choices"])
@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_all_three_permissions_require_literal_true(native, monkeypatch, key, value):
    original = config.get_flows
    monkeypatch.setattr(config, "get_flows", lambda: {**original(), key: value})
    run = _execute(native)
    assert run.status == "failed" and "feature_disabled" in run.error
    assert native[1] == []


@pytest.mark.parametrize("value,expected", [(False, False), (True, True), (1, False), ("true", False), (None, False)])
def test_choice_config_is_strict_and_default_off(monkeypatch, value, expected):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_recipe_choices": value}})
    assert config.get_flows()["action_recipe_choices"] is expected
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_flows()["action_recipe_choices"] is False


@pytest.mark.parametrize("ack", [False, 1])
def test_choice_route_requires_durable_receipt_before_next_approval(native, monkeypatch, ack):
    original = audit.record

    def record(kind, **payload):
        if kind == audit.EventKind.FLOW_ACTION_RECIPE_DECISION and payload.get("status") == "choice_selected":
            return ack
        return original(kind, **payload)

    monkeypatch.setattr(audit, "record", record)
    with pytest.raises(AuditRefused):
        _execute(native)
    assert native[1] == [(_OPEN, {"amount": 3})]


def test_gate_withdrawal_during_terminal_approval_stops_without_replaying(native, monkeypatch):
    original = config.get_flows

    def approve(node, data):
        if node.id == "approval_1_0":
            monkeypatch.setattr(config, "get_flows", lambda: {**original(), "action_recipe_choices": False})
        return "approved"

    run = _execute(native, approve=approve)
    assert run.status == "indeterminate" and "feature_disabled" in run.error
    assert native[1] == [(_OPEN, {"amount": 3})]
    assert run.data["_recipe_step_0"] == {"ticket": 23}


@pytest.mark.parametrize("target", ["cases", "condition", "next", "tool", "approval", "retry", "output"])
def test_choice_graph_cannot_be_rewired_before_persistence_or_execution(native, target):
    flow = _flow()
    if target == "cases":
        flow.nodes["choice"].cases[0]["to"] = "action_1_1"
    elif target == "condition":
        flow.nodes["choice"].condition = "input.review"
    elif target == "next":
        flow.nodes["choice"].next = "action_1_0"
    elif target == "tool":
        flow.nodes["action_1_0"].tool = _QUEUE
    elif target == "approval":
        flow.nodes["approval_1_0"].next = "action_1_1"
    elif target == "retry":
        flow.nodes["action_1_0"].retries = 1
    else:
        flow.nodes["action_0"].output = "spoofed"
    with pytest.raises(ValueError, match="recipe"):
        recipe_flow.validate_flow(flow)
    with pytest.raises(ValueError, match="recipe"):
        store.save_flow(flow)
    assert native[1] == []


@pytest.mark.parametrize("inject", ["input", "prefix", "route", "arguments"])
def test_signed_resume_cannot_override_retained_choice_inputs(native, inject):
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    flow = _flow()
    run = _execute(native, flow=flow, approve=lambda node, data: "approved" if node.id == "approval_0" else "pending")
    assert run.status == "paused_approval" and len(native[1]) == 1
    submitted = {"input": {"amount": 9, "limit": 1, "review": True}} if inject == "input" else (
        {"_recipe_step_0": {"ticket": 99}} if inject == "prefix" else
        {"_recipe_choice": {"tool": _QUEUE, "route": "1"}} if inject == "route" else
        {"_recipe_next_arguments": {"ticket": 99}})
    binding = paused_operation_binding(run, inputs=submitted)
    material = flow_decision_attestation_material(run, inputs=submitted, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="system:direct")
    token = issue_flow_decision_attestation(None, material=material,
        expires_at=float(run.human["approval_card"]["expires_at"]))
    resumed = execution.execute(flow, resume_run_id=run.run_id, inputs=submitted, decision="approved",
        decided_by="system:direct", approval_binding_sha256=binding, approval_decision_attestation=token,
        action_runner=native[0], agent_runner=lambda *args: pytest.fail("agent fallback"))
    assert resumed.status == "completed", resumed.error
    assert native[1] == [(_OPEN, {"amount": 3}), (_APPROVE, {"ticket": 23})]
    assert resumed.data["input"] == {"amount": 3, "limit": 6, "review": False}
    assert resumed.data["_recipe_choice"] == run.data["_recipe_choice"]


def test_terminal_result_must_match_the_branch_actually_executed(native):
    original = native[0]

    def action(tool, arguments, data):
        reply, outcome = original(tool, arguments, data)
        return (json.dumps({"queued": True}), outcome) if tool == _APPROVE else (reply, outcome)

    run = _execute((action, native[1]))
    assert run.status == "indeterminate"
    assert native[1] == [(_OPEN, {"amount": 3}), (_APPROVE, {"ticket": 23})]
    assert "_recipe_step_1" not in run.data


@pytest.mark.parametrize("tamper", ["route", "prefix", "guard", "tool", "arguments"])
def test_persisted_choice_mutation_invalidates_already_issued_approval(native, tamper):
    from maverick.approval_cards import ApprovalCardError
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    flow = _flow()
    run = _execute(native, flow=flow, approve=lambda node, data: "approved" if node.id == "approval_0" else "pending")
    assert run.status == "paused_approval"
    binding = paused_operation_binding(run)
    material = flow_decision_attestation_material(run, inputs=None, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="system:direct")
    token = issue_flow_decision_attestation(None, material=material,
        expires_at=float(run.human["approval_card"]["expires_at"]))
    altered = store.load_run(run.run_id)
    if tamper == "prefix":
        altered.data["_recipe_step_0"]["ticket"] = 99
    elif tamper == "arguments":
        altered.data["_recipe_next_arguments"]["ticket"] = 99
    else:
        key, value = {"route": ("route", "1"), "guard": ("guard_artifact_sha256", "0" * 64),
                      "tool": ("tool", _QUEUE)}[tamper]
        altered.data["_recipe_choice"][key] = value
    assert paused_operation_binding(altered) != binding
    store.save_run(altered)
    with pytest.raises(ApprovalCardError, match="no longer describes the durable operation"):
        execution.execute(flow, resume_run_id=run.run_id, decision="approved", decided_by="system:direct",
            approval_binding_sha256=binding, approval_decision_attestation=token,
            action_runner=native[0], agent_runner=lambda *args: pytest.fail("agent fallback"))
    assert native[1] == [(_OPEN, {"amount": 3})]


def test_terminal_native_authority_is_required_after_human_approval(native, monkeypatch):
    from maverick import governance

    original = governance.evaluate

    def evaluate(action, **kwargs):
        if action == _APPROVE:
            return governance.Verdict(decision=governance.Decision.DENY,
                reason="terminal permission revoked", rule="local_choice_review")
        return original(action, **kwargs)

    def approve(node, data):
        if node.id == "approval_1_0":
            monkeypatch.setattr(governance, "evaluate", evaluate)
        return "approved"

    run = _execute(native, approve=approve)
    assert run.status != "completed"
    assert native[1] == [(_OPEN, {"amount": 3})]
    assert run.data["_recipe_step_0"] == {"ticket": 23}
