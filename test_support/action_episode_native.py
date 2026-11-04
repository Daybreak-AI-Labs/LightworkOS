"""Persisted native action capture across real approval pauses; no providers."""
from __future__ import annotations

import copy
import importlib
import json
import time
from pathlib import Path
from unittest.mock import patch

import pytest
from maverick import config, tools, world_model
from maverick.flow import Flow, FlowNode, execution, store
from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
from maverick.governed_operations import ServiceContext
from maverick.paths import tenant_scope
from maverick_dashboard.approval_authority import issue_flow_decision_attestation

TENANT = "capture-resume"
INPUTS = {"customer": "ACME", "quantity": 3}
FLAGS = {"enable": True, "action_recipes": False, "action_episode_capture": True}
ALLOWED = ["episode_lookup", "episode_update"]


def _schema(value):
    if type(value) is dict:
        return {"type": "object", "properties": {key: _schema(item) for key, item in value.items()},
                "required": list(value), "additionalProperties": False}
    if type(value) is bool:
        return {"type": "boolean"}
    if type(value) is int:
        return {"type": "integer", "minimum": -100, "maximum": 100}
    return {"type": "string", "maxLength": 64}


TOOL_SCHEMAS = {
    "episode_lookup": {
        "arguments": _schema({"query": "ACME"}),
        "result": _schema({"customer_id": "C42", "active": True}),
    },
    "episode_update": {
        "arguments": _schema({"customer_id": "C42", "quantity": 3}),
        "result": _schema({"updated": True, "revision": 2}),
    },
}


def _registry(journal: Path):
    registry = tools.ToolRegistry(principal="reviewer")

    def perform(name, args):
        with journal.open("a", encoding="utf-8") as output:
            output.write(json.dumps({"tool": name, "arguments": args}) + "\n")
        return json.dumps({"customer_id": "C42", "active": True} if name == "episode_lookup"
                          else {"updated": True, "revision": 2})

    for name in ALLOWED:
        registry.register(tools.Tool(
            name=name, description="Native local pause/resume fixture",
            input_schema=TOOL_SCHEMAS[name]["arguments"],
            fn=lambda args, name=name: perform(name, args),
        ))
    return registry


@pytest.fixture
def native(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    from test_support.audit_child_process import configure_test_audit_signer

    configure_test_audit_signer(monkeypatch)
    # Retained action evidence refuses plaintext; pin encryption at rest so the
    # fixture holds under the suite's ordinary posture as well as the secure one.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setattr(config, "get_flows", lambda: dict(FLAGS))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "native-resume.db")
    risk = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk, "_load_overrides", lambda: {
        "episode_lookup": "low", "episode_update": "high",
    })
    journal = tmp_path / "native-effects.jsonl"
    registry = _registry(journal)
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: registry)
    with tenant_scope(tenant=TENANT):
        yield journal


def _source():
    flow = Flow(id="durable-native-actions", name="Durable native actions", owner="reviewer",
                start="start_review", nodes={
        "start_review": FlowNode(id="start_review", kind="approval", prompt="Review lookup", next="lookup"),
        "lookup": FlowNode(id="lookup", kind="action", tool="episode_lookup",
                           params={"query": "{{input.customer}}"}, output="found", next="update_review"),
        "update_review": FlowNode(id="update_review", kind="approval", prompt="Review exact update", next="update"),
        "update": FlowNode(id="update", kind="action", tool="episode_update",
                           params={"customer_id": "C42", "quantity": 3}, output="updated"),
    })
    store.save_flow(flow)
    return flow


def _no_agent(*args, **kwargs):
    raise AssertionError("native action capture must not invoke an agent")


def _start():
    source = _source()
    run = execution.execute(
        source, owner=source.owner, data={"input": copy.deepcopy(INPUTS)},
        agent_runner=_no_agent, action_runner=execution.default_action_runner(None, user_id="reviewer"),
    )
    assert run.status == "paused_approval" and run.cursor == "start_review"
    return source, run


def _context():
    return ServiceContext(
        tenant=TENANT, actor="reviewer", resource_owner="reviewer", human=True,
        credential_authority="native_capture_no_new_credentials", credential_ref="not_applicable",
        authorization_role="owner", authorization_policy="native_fixture_owner",
        budget_authority="local_no_provider", workspace_authority="native_fixture_tenant",
    )


def _service():
    from maverick.flow.action_episode_review import ActionEpisodeReviewService

    def authorize(ctx, capability, flow_id):
        return ctx == _context() and flow_id == "durable-native-actions"

    return ActionEpisodeReviewService(authorize)


def _enroll(source, run):
    return _service().enroll(
        _context(), source.id, run.run_id,
        expected_pause_binding=paused_operation_binding(store.load_run(run.run_id)),
        allowed_tools=ALLOWED, input_schema=_schema(INPUTS), tool_data_schemas=TOOL_SCHEMAS,
        retain_until=time.time() + 3600,
    )


def _resume(run_id, *, inputs=None, action_runner=None):
    prior = store.load_run(run_id, owner="reviewer", flow_id="durable-native-actions")
    source = store.load_flow_snapshot(prior.definition_digest)
    binding = paused_operation_binding(prior, inputs=inputs)
    material = flow_decision_attestation_material(
        prior, inputs=inputs, operation_binding_sha256=binding,
        authority_binding_sha256="", decision="approved", decided_by="reviewer",
    )
    attestation = issue_flow_decision_attestation(
        None, material=material, expires_at=float(prior.human["approval_card"]["expires_at"]),
    )
    return execution.execute(
        source, owner="reviewer", resume_run_id=run_id, decision="approved", decided_by="reviewer",
        approval_binding_sha256=binding, approval_decision_attestation=attestation, inputs=inputs,
        agent_runner=_no_agent,
        action_runner=action_runner or execution.default_action_runner(None, user_id="reviewer"),
    )


def _calls(journal):
    return [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()] if journal.exists() else []


def _row(source, run):
    return _service().get(_context(), source.id, run.run_id, detail=True)


def _child_resume(run_id, journal, world_path):
    """Spawn entry point: no collector or native Python state crosses processes."""
    risk = importlib.import_module("maverick.safety.tool_risk")
    registry = _registry(Path(journal))
    with (patch.object(config, "get_flows", lambda: dict(FLAGS)),
          patch.object(world_model, "DEFAULT_DB", Path(world_path)),
          patch.object(risk, "_load_overrides", lambda: {"episode_lookup": "low", "episode_update": "high"}),
          patch.object(tools, "base_registry", lambda *args, **kwargs: registry),
          tenant_scope(tenant=TENANT)):
        _resume(run_id)
