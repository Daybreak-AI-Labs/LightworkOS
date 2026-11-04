"""Native authority and persistence boundaries for transformed action recipes."""
from __future__ import annotations

import copy
import json

import pytest
from maverick import audit, config
from maverick.audit.errors import AuditRefused
from maverick.flow import action_recipe, action_recipe_transforms, execution, recipe_flow, store
from maverick.tools import Tool, ToolRegistry

_TOOLS = ["transform_lookup", "transform_commit"]


def _obj(**properties):
    return {"type": "object", "properties": properties, "required": sorted(properties),
            "additionalProperties": False}


def _int(low=0, high=100):
    return {"type": "integer", "minimum": low, "maximum": high}


def _artifact():
    episodes = [{"id": f"e{i}", "inputs": {"n": n}, "steps": [
        {"tool": _TOOLS[0], "arguments": {"value": n * 2}, "result": {"offset": offset}},
        {"tool": _TOOLS[1], "arguments": {"value": n + offset}, "result": {"ok": True}},
    ]} for i, (n, offset) in enumerate([(1, 7), (4, 11)])]
    domain = {"inputs": _obj(n=_int()), "steps": [
        {"arguments": _obj(value=_int(0, 200)), "result": _obj(offset=_int())},
        {"arguments": _obj(value=_int(0, 200)), "result": _obj(ok={"type": "boolean"})},
    ]}
    return action_recipe_transforms.synthesize_transformed(
        episodes, allowed_tools=_TOOLS, domain=domain, max_operations=1, operators=["add"])


@pytest.fixture
def native(tmp_path, monkeypatch):
    path = tmp_path / "transform-config.toml"
    path.write_text('[flows]\nenable=true\naction_recipes=true\naction_recipe_transforms=true\n'
                    '[security.tool_risk]\ntransform_lookup="low"\ntransform_commit="high"\n',
                    encoding="utf-8")
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

    def call(name, args):
        calls.append((name, copy.deepcopy(args)))
        return json.dumps({"offset": 13} if name == _TOOLS[0] else {"ok": True})

    for name in _TOOLS:
        registry.register(Tool(name=name, description="Owned local transform fixture",
                               input_schema=_obj(value=_int(0, 200)),
                               fn=lambda args, tool=name: call(tool, args)))
    monkeypatch.setattr("maverick.tools.base_registry", lambda *args, **kwargs: registry)
    return execution.default_action_runner(world=None, user_id="reviewer"), calls, registry


def _flow():
    flow = recipe_flow.make_flow(_artifact(), flow_id="transformed-native", name="Transformed native")
    flow.owner = "reviewer"
    return flow


def _execute(native, *, flow=None, data=None, approve=None, run_id="transform-native"):
    return execution.execute(
        flow or _flow(), owner="reviewer", run_id=run_id,
        data=data if data is not None else {"input": {"n": 6}}, action_runner=native[0],
        agent_runner=lambda *args: pytest.fail("agent fallback"),
        approve_fn=approve or (lambda *args: "approved"))


def test_native_transformed_arguments_roundtrip_and_signed_receipts(native):
    flow = _flow()
    restored = type(flow).from_dict(json.loads(json.dumps(flow.to_dict())))
    assert restored.to_dict() == flow.to_dict()
    run = _execute(native, flow=restored)
    assert run.status == "completed", run.error
    assert native[1] == [(_TOOLS[0], {"value": 12}), (_TOOLS[1], {"value": 19})]
    assert store.load_run(run.run_id).data["_recipe_step_1"] == {"ok": True}
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    assert len(events) == 4
    assert [event["reason"] for event in events] == ["agreement", "result_domain_valid"] * 2
    assert all(event["sig"] and event["flow_run_id"] == run.run_id
               and event["artifact_sha256"] == flow.learned_recipe["artifact_sha256"] for event in events)
    assert all("arguments" not in event and "episodes" not in event for event in events)


@pytest.mark.parametrize("key", ["action_recipes", "action_recipe_transforms"])
@pytest.mark.parametrize("value", [False, 1, "true", None])
def test_both_strict_feature_permissions_required(native, monkeypatch, key, value):
    original = config.get_flows
    monkeypatch.setattr(config, "get_flows", lambda: {**original(), key: value})
    run = _execute(native)
    assert run.status == "failed" and "feature_disabled" in run.error
    assert native[1] == []


@pytest.mark.parametrize("value,expected", [(False, False), (True, True), (1, False), ("true", False),
                                            (None, False)])
def test_transform_config_strict_boolean(monkeypatch, value, expected):
    monkeypatch.setattr(config, "load_config", lambda: {"flows": {"action_recipe_transforms": value}})
    assert config.get_flows()["action_recipe_transforms"] is expected


def test_transform_config_default_is_off(monkeypatch):
    monkeypatch.setattr(config, "load_config", dict)
    assert config.get_flows()["action_recipe_transforms"] is False


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("ack", [False, 1])
def test_literal_true_receipt_required_before_each_effect(native, monkeypatch, index, ack):
    original = audit.record

    def record(kind, **payload):
        if kind == audit.EventKind.FLOW_ACTION_RECIPE_DECISION and payload.get("step_index") == index:
            return ack
        return original(kind, **payload)

    monkeypatch.setattr(audit, "record", record)
    with pytest.raises(AuditRefused):
        _execute(native)
    assert native[1] == ([] if index == 0 else [(_TOOLS[0], {"value": 12})])


def test_revocation_between_actions_preserves_completed_prefix(native, monkeypatch):
    original = config.get_flows

    def approve(node, data):
        if node.id == "approval_1":
            monkeypatch.setattr(config, "get_flows", lambda: {**original(), "action_recipe_transforms": False})
        return "approved"

    run = _execute(native, approve=approve)
    assert run.status == "indeterminate" and "feature_disabled" in run.error
    assert native[1] == [(_TOOLS[0], {"value": 12})]
    assert run.data["_recipe_step_0"] == {"offset": 13}
    again = _execute(native)
    assert again.status == "indeterminate" and len(native[1]) == 1


def test_caller_and_approval_mutation_cannot_change_shown_transforms(native):
    flow, data, proposals = _flow(), {"input": {"n": 6}}, []

    def approve(node, state):
        proposals.append(copy.deepcopy(state["_recipe_next_arguments"]))
        data["input"]["n"] = 99
        state["input"]["n"] = 100
        state["_recipe_step_0"] = {"offset": 100}
        state["_recipe_next_arguments"] = {"value": 199}
        node.next = None
        flow.nodes["action_1"].tool = _TOOLS[0]
        return "approved"

    run = _execute(native, flow=flow, data=data, approve=approve)
    assert run.status == "completed", run.error
    assert proposals == [{"value": 12}, {"value": 19}]
    assert native[1] == [(_TOOLS[0], {"value": 12}), (_TOOLS[1], {"value": 19})]
    assert run.data["input"] == {"n": 6}


def test_out_of_domain_result_stops_even_with_matching_shape(native):
    original = native[0]

    def action(tool, params, data):
        reply, outcome = original(tool, params, data)
        return (json.dumps({"offset": 101}), outcome) if tool == _TOOLS[0] else (reply, outcome)

    run = _execute((action, *native[1:]))
    assert run.status == "indeterminate"
    assert native[1] == [(_TOOLS[0], {"value": 12})]
    assert "_recipe_step_0" not in run.data


@pytest.mark.parametrize("inject", ["input", "prior"])
def test_signed_resume_injection_does_not_change_retained_values(native, inject):
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    flow = _flow()
    run = _execute(native, flow=flow, approve=lambda node, data:
                   "approved" if node.id == "approval_0" else "pending")
    assert run.status == "paused_approval" and len(native[1]) == 1
    submitted = {"input": {"n": 99}} if inject == "input" else {"_recipe_step_0": {"offset": 100}}
    binding = paused_operation_binding(run, inputs=submitted)
    material = flow_decision_attestation_material(
        run, inputs=submitted, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="system:direct")
    token = issue_flow_decision_attestation(
        None, material=material, expires_at=float(run.human["approval_card"]["expires_at"]))
    resumed = execution.execute(
        flow, resume_run_id=run.run_id, inputs=submitted, decision="approved", decided_by="system:direct",
        approval_binding_sha256=binding, approval_decision_attestation=token, action_runner=native[0],
        agent_runner=lambda *args: pytest.fail("agent fallback"))
    assert resumed.status == "completed", resumed.error
    assert native[1] == [(_TOOLS[0], {"value": 12}), (_TOOLS[1], {"value": 19})]
    assert resumed.data["input"] == {"n": 6} and resumed.data["_recipe_step_0"] == {"offset": 13}


def test_native_tool_authority_is_rechecked_after_approval(native, monkeypatch):
    from maverick import governance

    original = governance.evaluate

    def evaluate(action, **kwargs):
        if action == _TOOLS[1]:
            return governance.Verdict(decision=governance.Decision.DENY,
                                      reason="tool permission revoked", rule="local_review_rule")
        return original(action, **kwargs)

    def approve(node, state):
        if node.id == "approval_1":
            monkeypatch.setattr(governance, "evaluate", evaluate)
        return "approved"

    run = _execute(native, approve=approve)
    assert run.status != "completed"
    assert native[1] == [(_TOOLS[0], {"value": 12})]
    assert run.data["_recipe_step_0"] == {"offset": 13}


@pytest.mark.parametrize("ack", [False, 1])
def test_result_receipt_failure_preserves_effect_without_replaying(native, monkeypatch, ack):
    original = audit.record

    def record(kind, **payload):
        if (kind == audit.EventKind.FLOW_ACTION_RECIPE_DECISION and payload.get("step_index") == 1
                and payload.get("status") == "completed"):
            return ack
        return original(kind, **payload)

    monkeypatch.setattr(audit, "record", record)
    with pytest.raises(AuditRefused):
        _execute(native)
    assert native[1] == [(_TOOLS[0], {"value": 12}), (_TOOLS[1], {"value": 19})]
    saved = store.load_run("transform-native")
    assert saved.status == "indeterminate"
    assert _execute(native).status == "indeterminate" and len(native[1]) == 2


def test_v1_dispatch_remains_byte_identical_and_needs_no_transform_flag(native, monkeypatch):
    old = [{"id": str(n), "inputs": {"n": n}, "steps": [
        {"tool": _TOOLS[0], "arguments": {"value": n}, "result": {"offset": n + 10}},
        {"tool": _TOOLS[1], "arguments": {"value": n + 10}, "result": {"ok": True}},
    ]} for n in (1, 4)]
    artifact = action_recipe.synthesize(old, allowed_tools=_TOOLS)
    action_recipe.validate_artifact(artifact)
    assert artifact["schema"] == action_recipe.SCHEMA
    assert action_recipe.resolve_step(artifact, 1, {"n": 6}, [{"offset": 13}]).arguments == {"value": 13}
    assert artifact == action_recipe.synthesize(old, allowed_tools=_TOOLS)
    original = config.get_flows
    monkeypatch.setattr(config, "get_flows", lambda: {**original(), "action_recipe_transforms": False})
    flow = recipe_flow.make_flow(artifact, flow_id="v1-native", name="Original copy recipe")
    flow.owner = "reviewer"
    run = _execute(native, flow=flow)
    assert run.status == "completed", run.error
    assert native[1] == [(_TOOLS[0], {"value": 6}), (_TOOLS[1], {"value": 13})]
