"""Capture and native recipe execution share explicit result-completeness rules.

Only connector bodies are local fixtures. Real ToolRegistry dispatch, tool
authorization, approval gates, durable flow execution and signed audits run.
"""
from __future__ import annotations

import copy
import json

import pytest
from maverick import audit, config, tools
from maverick.flow import action_episodes, action_recipe, execution, recipe_flow, store

TOOLS = ["completeness_lookup", "completeness_followup"]


@pytest.fixture
def native(monkeypatch, tmp_path):
    configuration = tmp_path / "completeness-config.toml"
    configuration.write_text(
        '[flows]\nenable=true\naction_recipes=true\n'
        '[security.tool_risk]\ncompleteness_lookup="low"\ncompleteness_followup="high"\n',
        encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(configuration))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "0")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.delenv("MAVERICK_CONFIG_OVERLAY", raising=False)
    config.reset_config_cache()
    calls, outputs = [], []
    registry = tools.ToolRegistry(principal="completeness-reviewer")

    def dispatch(index, arguments):
        calls.append({"tool": TOOLS[index], "arguments": copy.deepcopy(arguments)})
        return json.dumps(outputs[index])

    for index, name in enumerate(TOOLS):
        key = "query" if index == 0 else "record_id"
        registry.register(tools.Tool(name=name, description="Local completeness regression",
            input_schema={"type": "object", "properties": {key: {"type": "string"}},
                          "required": [key], "additionalProperties": False},
            fn=lambda arguments, index=index: dispatch(index, arguments)))
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: registry)
    return calls, outputs, execution.default_action_runner(None, channel="test", user_id="completeness-reviewer")


def _artifact(marker, normal):
    episodes = []
    for index in (1, 2):
        episodes.append({"id": f"example-{index}", "inputs": {"query": f"query-{index}"}, "steps": [
            {"tool": TOOLS[0], "arguments": {"query": f"query-{index}"},
             "result": {"id": f"record-{index}", marker: normal}},
            {"tool": TOOLS[1], "arguments": {"record_id": f"record-{index}"},
             "result": {"id": f"child-{index}", marker: normal}},
        ]})
    return action_recipe.synthesize(episodes, allowed_tools=TOOLS)


def _run(artifact, native, run_id):
    flow = recipe_flow.make_flow(artifact, flow_id="result-completeness", name="Result completeness")
    flow.owner = "completeness-reviewer"

    def no_agent(*args, **kwargs):
        pytest.fail("action recipes must not restart via an agent")

    return execution.execute(flow, owner=flow.owner, run_id=run_id,
        data={"input": {"query": "fresh-query"}}, agent_runner=no_agent,
        action_runner=native, approve_fn=lambda *_args: "approved")


@pytest.mark.parametrize("marker,normal,incomplete", [
    ("pending", False, True), ("truncated", False, True),
    ("complete", True, False), ("dry_run", False, True),
])
@pytest.mark.parametrize("changed_step", [0, 1])
def test_explicit_incomplete_result_stops_native_recipe_without_followup_or_replay(
    native, marker, normal, incomplete, changed_step,
):
    calls, outputs, action_runner = native
    artifact = _artifact(marker, normal)
    outputs.extend([{"id": "fresh-record", marker: normal}, {"id": "fresh-child", marker: normal}])
    outputs[changed_step][marker] = incomplete
    with pytest.raises(ValueError, match="incomplete or preview"):
        action_episodes._result_object(json.dumps(outputs[changed_step]))
    run = _run(artifact, action_runner, "incomplete-result")
    assert run.status == "indeterminate"
    assert [call["tool"] for call in calls] == TOOLS[:changed_step + 1]
    saved = store.load_run(run.run_id, owner="completeness-reviewer")
    assert saved.status == "indeterminate"
    assert f"_recipe_step_{changed_step}" not in run.data
    rows = list(audit.iter_events(all_days=True, strict=True, verify=True))
    receipts = [row for row in rows if row.get("kind") == "flow_action_recipe_decision"
                and row.get("flow_run_id") == run.run_id]
    assert receipts and all(row["sig"] for row in receipts)
    assert not any(row.get("step_index") == changed_step and row.get("status") == "completed"
                   for row in receipts)
    before = copy.deepcopy(calls)
    repeated = _run(artifact, action_runner, run.run_id)
    assert repeated.status == "indeterminate" and calls == before


@pytest.mark.parametrize("marker,normal,runtime", [
    ("pending", False, False), ("accepted", True, False), ("status", "ready", "pending"),
])
def test_supported_markers_and_custom_business_fields_keep_native_behavior(native, marker, normal, runtime):
    calls, outputs, action_runner = native
    artifact = _artifact(marker, normal)
    outputs.extend([{"id": "fresh-record", marker: runtime}, {"id": "fresh-child", marker: normal}])
    assert action_episodes._result_object(json.dumps(outputs[0])) == outputs[0]
    run = _run(artifact, action_runner, "supported-result")
    assert run.status == "completed" and len(calls) == 2
    assert calls[1]["arguments"] == {"record_id": "fresh-record"}
    assert store.load_run(run.run_id, owner="completeness-reviewer").status == "completed"
