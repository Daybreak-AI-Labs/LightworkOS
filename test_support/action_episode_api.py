"""Reusable authenticated API/native-action fixture; OIDC verification is stubbed.

Capture, flow/run storage, approval authority/attestations, record encryption and
audit are native. These helpers resume native execution with authenticated
dashboard attestations. No provider or external connector is used; agent work
is guarded by a failure sentinel.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from maverick import config, tools, world_model
from maverick.flow import Flow, FlowNode, execution, store
from maverick.oidc import VerifiedPrincipal
from maverick.paths import tenant_scope
from maverick_dashboard import auth

TENANT = "episode-api-team"
OWNER = "user:alice"
LOOKUP = "episode_api_lookup"
CREATE = "episode_api_create"
PRIVATE_REF = "private-customer-reference"
RATIONALE = "Private reviewed business evidence for the retained demonstration."


def _object(**properties):
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


def _string():
    return {"type": "string", "maxLength": 128}


@pytest.fixture
def harness(tmp_path, monkeypatch, request):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", TENANT)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TOOL_CACHE", "0")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(
        ("episode-api-audit:" + request.node.nodeid).encode()).hexdigest())
    key = hashlib.sha256(("episode-api-encryption:" + request.node.nodeid).encode()).digest()
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY_DIGEST", "sha256:" + hashlib.sha256(key).hexdigest())
    from maverick import crypto_at_rest

    crypto_at_rest._reset_shared_key_identity_for_testing()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    flags = {"enable": True, "action_episode_capture": True, "action_recipes": False}
    monkeypatch.setattr(config, "get_flows", lambda: dict(flags))
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "is_dashboard_admin", lambda actor: actor == "user:admin")
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kw: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token},
    ))
    from maverick_dashboard import rbac
    from maverick_dashboard.app import app

    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    risk = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(risk, "_load_overrides", lambda: {LOOKUP: "low", CREATE: "high"})
    calls = []
    registry = tools.ToolRegistry(principal=OWNER)

    def perform(name, args):
        calls.append((name, copy.deepcopy(args)))
        value = ({"customer_id": "customer-" + args["query"]} if name == LOOKUP
                 else {"order_id": f"fresh-order-{len(calls)}"})
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    for name in (LOOKUP, CREATE):
        registry.register(tools.Tool(
            name=name, description="Local native retained episode fixture",
            input_schema={"type": "object"},
            fn=lambda args, name=name: perform(name, args),
        ))
    monkeypatch.setattr(tools, "base_registry", lambda *args, **kwargs: registry)
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1",
                                     "Authorization": "Bearer alice"})
    yield SimpleNamespace(client=client, calls=calls, flags=flags, monkeypatch=monkeypatch,
                          native=execution.default_action_runner(None, user_id=OWNER))
    crypto_at_rest._reset_shared_key_identity_for_testing()


def _paused(harness, *, index=0, flow_id="episode-flow", tenant=TENANT):
    # The ordinary author supplies different reviewed static second-step values
    # in each saved draft. The learning engine receives only resulting episodes,
    # not these authored flow parameters or a proposed argument binding.
    ref = f"{PRIVATE_REF}-{index}"
    source = Flow(id=flow_id, name="Reviewed local order", owner=OWNER, start="approve_lookup", nodes={
        "approve_lookup": FlowNode(id="approve_lookup", kind="approval", prompt="Review lookup", next="lookup"),
        "lookup": FlowNode(id="lookup", kind="action", tool=LOOKUP,
                           params={"query": "{{input.ref}}"}, output="customer", next="approve_create"),
        "approve_create": FlowNode(id="approve_create", kind="approval", prompt="Review order", next="create"),
        "create": FlowNode(id="create", kind="action", tool=CREATE,
                           params={"customer_id": "customer-" + ref}, output="order"),
    })
    with tenant_scope(tenant=tenant):
        source = store.save_flow(source)
        run = execution.execute(source, owner=OWNER, data={"input": {"ref": ref}},
                                action_runner=harness.native,
                                agent_runner=lambda *a, **kw: pytest.fail("agent dispatch"))
    assert run.status == "paused_approval", run.error
    return source, run


def _base(run):
    return f"/api/v1/flows/{run.flow_id}/runs/{run.run_id}/episode-capture"


def _enrollment(harness, run):
    prepared = harness.client.get(_base(run) + "/enrollment")
    assert prepared.status_code == 200, prepared.text
    body = {"expected_pause_binding": prepared.json()["expected_pause_binding"],
            "allowed_tools": [LOOKUP, CREATE], "input_schema": _object(ref=_string()),
            "tool_data_schemas": {
                LOOKUP: {"arguments": _object(query=_string()), "result": _object(customer_id=_string())},
                CREATE: {"arguments": _object(customer_id=_string()), "result": _object(order_id=_string())},
            }, "retain_until": time.time() + 3600}
    assert PRIVATE_REF not in prepared.text
    return body


def _enroll(harness, run):
    response = harness.client.post(_base(run), json=_enrollment(harness, run))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "enrolled"
    return response.json()


def _resume(harness, source, run):
    from maverick.flow.approvals import flow_decision_attestation_material, paused_operation_binding
    from maverick_dashboard.approval_authority import (
        issue_flow_decision_attestation,
        require_approval_authority,
    )

    with tenant_scope(tenant=TENANT):
        current = store.load_run(run.run_id)
        binding = paused_operation_binding(current, inputs={})
        material = flow_decision_attestation_material(
            current, inputs={}, operation_binding_sha256=binding,
            authority_binding_sha256="", decision="approved", decided_by=OWNER)
        request = SimpleNamespace(state=SimpleNamespace(principal=SimpleNamespace(principal=OWNER)))
        authority = require_approval_authority(request, action="flow.approval.decide", resource=run.run_id)
        attestation = issue_flow_decision_attestation(
            authority, material=material, expires_at=float(current.human["approval_card"]["expires_at"]))
        return execution.execute(
            source, resume_run_id=run.run_id, inputs={}, decision="approved", decided_by=OWNER,
            approval_binding_sha256=binding, approval_decision_attestation=attestation,
            action_runner=harness.native, agent_runner=lambda *a, **kw: pytest.fail("agent dispatch"))


def _awaiting_review(harness, *, index=0, flow_id="episode-flow"):
    source, run = _paused(harness, index=index, flow_id=flow_id)
    _enroll(harness, run)
    middle = _resume(harness, source, run)
    assert middle.status == "paused_approval" and middle.cursor == "approve_create", middle.error
    status = harness.client.get(_base(run))
    assert status.status_code == 200, status.text
    assert status.json()["status"] == "paused", status.text
    final = _resume(harness, source, middle)
    assert final.status == "completed", final.error
    response = harness.client.get(_base(run))
    assert response.status_code == 200, response.text
    record = response.json()
    assert record["status"] == "awaiting_review", response.text
    assert PRIVATE_REF not in response.text
    return source, final, record


def _review(record, **changes):
    return {"expected_revision": record["revision"],
            "expected_episode_sha256": record["episode_sha256"],
            "reviewed": True, "accepted": True, "rationale": RATIONALE, **changes}


def _accepted(harness):
    source, run, record = _awaiting_review(harness)
    response = harness.client.post(_base(run) + "/review", json=_review(record))
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "accepted"
    return source, run, record
