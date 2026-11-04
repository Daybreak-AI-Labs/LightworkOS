"""Authenticated API + local native actions; OIDC signature verification is stubbed.

Capture, flow/run storage, approval authority/attestations, record encryption and
audit are native. One case drives HTTP run/resume through the real queue Worker;
other cases call native execution directly. No provider or external connector
is used. The queue case suppresses notifications and guards unused agent work.
"""
from __future__ import annotations

import copy
import hashlib
import importlib
import json
import time
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick import audit, config, tools, world_model
from maverick.flow import Flow, FlowNode, action_recipe, execution, store
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


def test_http_enrollment_native_approval_segments_review_export_and_recipe_learning(harness):
    episodes = []
    for index in range(2):
        _source, run, record = _awaiting_review(harness, index=index)
        assert harness.client.get(_base(run) + "/export").status_code == 409
        detail = harness.client.get(_base(run) + "/detail")
        assert detail.status_code == 200, detail.text
        assert PRIVATE_REF in detail.text
        reviewed = harness.client.post(_base(run) + "/review", json=_review(record))
        assert reviewed.status_code == 200, reviewed.text
        exported = harness.client.get(_base(run) + "/export")
        assert exported.status_code == 200, exported.text
        assert exported.headers["Cache-Control"] == "no-store"
        bundle = exported.json()
        assert bundle["review"]["authenticated"] is True
        assert bundle["review"]["reviewer"] == OWNER
        assert bundle["review"]["accepted"] is True
        assert bundle["provenance"]["run_id"] == run.run_id
        assert bundle["episode"]["steps"][1]["arguments"] == {
            "customer_id": "customer-" + bundle["episode"]["inputs"]["ref"]}
        episodes.append(bundle["episode"])
    assert len(harness.calls) == 4
    artifact = action_recipe.synthesize(episodes, allowed_tools=[LOOKUP, CREATE])
    first = action_recipe.resolve_step(artifact, 0, {"ref": "new-ref"}, [])
    second = action_recipe.resolve_step(artifact, 1, {"ref": "new-ref"}, [{"customer_id": "new-native-id"}])
    assert first.applied and first.arguments == {"query": "new-ref"}
    assert second.applied and second.arguments == {"customer_id": "new-native-id"}
    with tenant_scope(tenant=TENANT):
        events = list(audit.iter_events(all_days=True, strict=True, verify=True))
    assert all(event.get("sig") for event in events)
    assert sum(event["kind"] == "tool_result" for event in events) == 4
    learning_events = [event for event in events if "flow_action_episode" in json.dumps(event)]
    assert learning_events
    assert PRIVATE_REF not in json.dumps(learning_events) and RATIONALE not in json.dumps(learning_events)


@pytest.mark.parametrize("capture", [False, None, 1, "true"])
def test_capture_flag_is_literal_true_and_independent_of_recipe_execution(harness, capture):
    _source, run = _paused(harness)
    body = _enrollment(harness, run)
    harness.flags.update(action_episode_capture=capture, action_recipes=True)
    assert harness.client.post(_base(run), json=body).status_code == 403
    assert harness.calls == []


@pytest.mark.parametrize("patch", [{"actor": "user:admin"}, {"tenant": "other"},
                                    {"owner": "user:admin"}, {"human": True}])
def test_enrollment_body_cannot_supply_service_authority(harness, patch):
    _source, run = _paused(harness)
    response = harness.client.post(_base(run), json={**_enrollment(harness, run), **patch})
    assert response.status_code == 422
    assert harness.client.get(_base(run)).status_code == 404
    assert harness.calls == []


@pytest.mark.parametrize("patch", [{"reviewer": "user:admin"}, {"tenant": "other"},
                                    {"accepted": "true"}, {"reviewed": 1}, {"expected_revision": True}])
def test_review_body_rejects_identity_and_type_coercion(harness, patch):
    _source, run, record = _awaiting_review(harness)
    response = harness.client.post(_base(run) + "/review", json=_review(record, **patch))
    assert response.status_code == 422
    assert harness.client.get(_base(run)).json()["status"] == "awaiting_review"


def test_review_requires_explicit_attestation_and_reject_verdict_is_not_exportable(harness):
    _source, run, record = _awaiting_review(harness)
    assert harness.client.post(_base(run) + "/review", json=_review(record, reviewed=False)).status_code == 400
    response = harness.client.post(_base(run) + "/review", json=_review(record, accepted=False))
    assert response.status_code == 200 and response.json()["status"] == "rejected", response.text
    assert harness.client.get(_base(run) + "/export").status_code == 409


def test_current_owner_role_and_tenant_apply_to_all_read_and_review_routes(harness):
    _source, run, record = _accepted(harness)
    for suffix in ("", "/detail", "/export", "/enrollment"):
        assert harness.client.get(_base(run) + suffix, headers={"Authorization": "Bearer bob"}).status_code == 404
    assert harness.client.post(_base(run) + "/review", json=_review(record),
                               headers={"Authorization": "Bearer bob"}).status_code == 404
    from maverick_dashboard import rbac

    harness.monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
    assert harness.client.get(_base(run) + "/export").status_code == 403
    assert harness.client.post(_base(run) + "/review", json=_review(record)).status_code == 403
    harness.monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    _paused(harness, flow_id=run.flow_id, tenant="other-team")
    harness.monkeypatch.setenv("MAVERICK_TENANT", "other-team")
    assert harness.client.get(_base(run) + "/export").status_code == 404


def test_static_bearer_does_not_authenticate_a_human_reviewer(harness):
    _source, run = _paused(harness)
    body = _enrollment(harness, run)
    harness.monkeypatch.setattr(auth, "oidc_enabled", lambda: False)
    harness.monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "shared-local-test-bearer")
    harness.client.headers["Authorization"] = "Bearer shared-local-test-bearer"
    assert harness.client.post(_base(run), json=body).status_code == 401


def test_enrollment_stale_binding_and_review_stale_revision_conflict(harness):
    _source, run = _paused(harness)
    body = _enrollment(harness, run)
    body["expected_pause_binding"] = "0" * 64
    assert harness.client.post(_base(run), json=body).status_code == 409
    _source, run, record = _awaiting_review(harness, flow_id="second-flow")
    for patch in ({"expected_revision": record["revision"] + 1}, {"expected_episode_sha256": "0" * 64}):
        assert harness.client.post(_base(run) + "/review", json=_review(record, **patch)).status_code == 409
    assert harness.client.get(_base(run)).json()["status"] == "awaiting_review"


@pytest.mark.parametrize("receipt", [False, 1])
def test_committed_review_pending_hides_evidence_and_recovers_without_business_replay(harness, receipt):
    _source, run, record = _awaiting_review(harness)
    original = audit.record
    harness.monkeypatch.setattr(audit, "record", lambda *a, **kw: receipt)
    response = harness.client.post(_base(run) + "/review", json=_review(record))
    assert response.status_code == 503, response.text
    pending = response.json()
    assert pending["status"] == "audit_pending" and pending["committed_status"] == "accepted"
    for suffix in ("", "/detail", "/export"):
        held = harness.client.get(_base(run) + suffix)
        assert held.status_code == 503, held.text
        assert PRIVATE_REF not in held.text and RATIONALE not in held.text
        assert "envelope" not in held.text and "arguments" not in held.text
    harness.monkeypatch.setattr(audit, "record", original)
    recovered = harness.client.get(_base(run))
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["revision"] == pending["revision"]
    assert recovered.json()["audit_status"] == "delivered"
    assert harness.client.get(_base(run) + "/export").status_code == 200
    assert len(harness.calls) == 2


@pytest.mark.parametrize("change", ["membership", "selection_generation", "suspension", "role", "owner"])
@pytest.mark.parametrize("operation", ["review", "export"])
def test_service_rechecks_current_dashboard_authority_not_just_context_creation(harness, change, operation):
    from maverick.tenant import registry
    from maverick_dashboard import api_flow_action_episodes as routes
    from maverick_dashboard import rbac, workspace_tenants

    # Provision before saved flows reserve this namespace. Existing retained
    # work must never be silently adopted by a new workspace registry entry.
    registry.create_tenant(TENANT)
    source, run, record = _accepted(harness) if operation == "export" else _awaiting_review(harness)
    rbac.set_tenant_role(TENANT, OWNER, "operator")
    workspace_tenants.set_selection(OWNER, TENANT)
    request = SimpleNamespace(state=SimpleNamespace(
        principal=SimpleNamespace(principal=OWNER), workspace_tenant_source="principal_selection"))
    with tenant_scope(tenant=TENANT):
        service, ctx = routes._service(request, source.id, human=operation == "review")
        if change == "membership":
            rbac.remove_tenant_role(TENANT, OWNER)
        elif change == "selection_generation":
            workspace_tenants.set_selection(OWNER, None)
            workspace_tenants.set_selection(OWNER, TENANT)
        elif change == "suspension":
            registry.suspend_tenant(TENANT)
        elif change == "role":
            rbac.set_tenant_role(TENANT, OWNER, "viewer")
        else:
            source.owner = "user:bob"
            store.save_flow(source, expected_version=source.version, expected_revision=source.revision)
        with pytest.raises(HTTPException) as rejected:
            if operation == "export":
                service.export(ctx, source.id, run.run_id)
            else:
                service.review(ctx, source.id, run.run_id, expected_revision=record["revision"],
                               expected_episode_sha256=record["episode_sha256"], accepted=True,
                               rationale=RATIONALE)
        assert rejected.value.status_code in {403, 404, 409}
    assert len(harness.calls) == 2


def test_initial_record_is_encrypted_and_cross_run_ciphertext_swap_cannot_be_reviewed(harness):
    from maverick import crypto_at_rest
    from maverick.flow import action_episode_review

    _source, first = _paused(harness)
    row1 = _enroll(harness, first)
    _source, second = _paused(harness, index=1)
    row2 = _enroll(harness, second)
    with tenant_scope(tenant=TENANT):
        backend = action_episode_review._RECORDS._local_backend._store
        path1, path2 = backend._path(row1["id"]), backend._path(row2["id"])
        raw1, raw2 = path1.read_text(encoding="utf-8"), path2.read_text(encoding="utf-8")
        assert PRIVATE_REF not in raw1 and PRIVATE_REF not in raw2
        saved1, saved2 = json.loads(raw1), json.loads(raw2)
        assert crypto_at_rest.is_sealed_str(saved1["sensitive_envelope"])
        assert crypto_at_rest.is_sealed_str(saved2["sensitive_envelope"])
        saved1["sensitive_envelope"] = saved2["sensitive_envelope"]
        # Fault injection into the retained local row, preserving all outer
        # metadata/revisions. Authenticated decryption alone must not accept it.
        path1.write_text(json.dumps(saved1), encoding="utf-8")
    for suffix in ("", "/detail", "/export"):
        response = harness.client.get(_base(first) + suffix)
        assert response.status_code == 400, response.text
        assert PRIVATE_REF not in response.text and "envelope" not in response.text
    assert harness.client.get(_base(second) + "/detail").status_code == 200
    assert harness.calls == []


def test_http_start_and_approval_resume_worker_uses_native_capture_without_queue_grants(harness):
    from maverick.worker import Worker
    from maverick_dashboard import automation_queue as aq

    harness.monkeypatch.setattr(aq, "_queue", None)
    harness.monkeypatch.setattr(aq, "_worker", None)
    harness.monkeypatch.setattr(aq, "_worker_threads", [])
    # Notifications are unrelated outbound work, and the admitted plan has no
    # agent node. Native worker/authorization/action execution stays unchanged.
    harness.monkeypatch.setattr(aq, "_notify_flow", lambda *args: None)
    harness.monkeypatch.setattr(execution, "default_agent_runner", lambda *a, **kw:
                               lambda *a, **kw: pytest.fail("agent dispatch"))
    source, _unused = _paused(harness)
    published = harness.client.post(f"/api/v1/flows/{source.id}/publish", json={
        "version": source.version, "revision": source.revision,
    })
    assert published.status_code == 200, published.text
    started = harness.client.post(f"/api/v1/flows/{source.id}/run", json={
        "data": {"input": {"ref": PRIVATE_REF + "-0"}},
    })
    assert started.status_code == 200, started.text
    run_id = started.json()["run_id"]
    worker = Worker(queue=aq.queue())
    worker.register(aq.FLOW_RUN_KIND, aq._handle_flow_run)
    worker.register(aq.FLOW_RESUME_KIND, aq._handle_flow_resume)
    worker.drain()
    with tenant_scope(tenant=TENANT):
        run = store.load_run(run_id)
    assert run.status == "paused_approval", run.error
    _enroll(harness, run)
    for expected in ("paused_approval", "completed"):
        visible = harness.client.get(f"/api/v1/flows/runs/{run_id}")
        assert visible.status_code == 200, visible.text
        resumed = harness.client.post(f"/api/v1/flows/runs/{run_id}/resume", json={
            "decision": "approved", "approval_binding_sha256": visible.json()["approval_binding_sha256"],
        })
        assert resumed.status_code == 200, resumed.text
        jobs = [job for job in aq._pending(aq.FLOW_RESUME_KIND) if job.payload.get("run_id") == run_id]
        assert len(jobs) == 1
        assert not any("episode" in key or "capture" in key for key in jobs[0].payload)
        worker.drain()
        with tenant_scope(tenant=TENANT):
            persisted = store.load_run(run_id)
        assert persisted.status == expected, persisted.error
    record = harness.client.get(_base(run)).json()
    assert record["status"] == "awaiting_review", record
    reviewed = harness.client.post(_base(run) + "/review", json=_review(record))
    assert reviewed.status_code == 200, reviewed.text
    exported = harness.client.get(_base(run) + "/export")
    assert exported.status_code == 200, exported.text
    assert len(exported.json()["episode"]["steps"]) == 2
    assert exported.json()["review"]["reviewer"] == OWNER
    assert len(harness.calls) == 2
    # Native queue redelivery of the already consumed approval is a no-op.
    aq._handle_flow_resume(jobs[0])
    assert len(harness.calls) == 2
