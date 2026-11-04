"""From a fresh run to a learned flow, entirely through the dashboard's routes.

Two fresh runs of a flow are each kept as a learning example (suggested data
description, enrollment at the first approval), approved step by step, then
reviewed, accepted and allowed for learning. The flow's teach page then
learns a new flow from them, and from their signed copies (checked, learned,
approved for governed use and drafted). Capture, encryption, signing, audit,
approval attestations and learning are all native; only the two connector
tools are local stand-ins and the sign-in check is stubbed (the harness of
test_flow_action_episodes_api).
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
from maverick.flow import Flow, FlowNode, action_recipe, execution, recipe_flow, store
from maverick.oidc import VerifiedPrincipal
from maverick.paths import tenant_scope
from maverick_dashboard import auth

TENANT = "episode-api-team"
OWNER = "user:alice"
LOOKUP = "episode_api_lookup"
CREATE = "episode_api_create"
PRIVATE_REF = "private-customer-reference"


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



REASON = "Reviewed this run's actual inputs, actions and results."


def _lineage_flags(harness):
    harness.flags.update({"action_recipes": True, "action_recipe_transforms": True, "action_recipe_lineage": True,
                          "require_action_recipe_lineage": False, "action_evidence_issuer": "capture-e2e",
                          "action_evidence_revoked_keys": []})


def _keep_as_example(harness, index, *, allow_learning=True, grant_seconds=5 * 86400):
    source, run = _paused(harness, index=index)
    suggestion = harness.client.get(_base(run) + "/suggestion")
    assert suggestion.status_code == 200, suggestion.text
    prepared = suggestion.json()
    contract = prepared["suggestion"]
    assert contract["input_schema"]["properties"]["ref"]["type"] == "string"
    assert set(contract["tool_data_schemas"]) == {LOOKUP, CREATE}
    if index == 0:
        # Nothing has shown what the tools give back yet: the person adds those
        # details on the page (here, as the page would send them).
        assert contract["unknown_results"] == sorted([LOOKUP, CREATE])
        for tool, field in ((LOOKUP, "customer_id"), (CREATE, "order_id")):
            contract["tool_data_schemas"][tool]["result"] = {
                "type": "object", "properties": {field: {"type": "string", "maxLength": 1024}},
                "required": [field], "additionalProperties": False}
    else:
        assert contract["unknown_results"] == [], "the earlier example's description is reused"
    enrolled = harness.client.post(_base(run), json={
        "expected_pause_binding": prepared["expected_pause_binding"], "allowed_tools": prepared["allowed_tools"],
        "input_schema": contract["input_schema"], "tool_data_schemas": contract["tool_data_schemas"],
        "retain_until": time.time() + 6 * 86400})
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["status"] == "enrolled"
    middle = _resume(harness, source, run)
    assert middle.status == "paused_approval", middle.error
    final = _resume(harness, source, middle)
    assert final.status == "completed", final.error
    record = harness.client.get(_base(run)).json()
    assert record["status"] == "awaiting_review", record
    detail = harness.client.get(_base(run) + "/detail").json()
    assert [slot["tool"] for slot in detail["evidence"]["slots"]] == [LOOKUP, CREATE]
    reviewed = harness.client.post(_base(run) + "/review", json={
        "expected_revision": record["revision"], "expected_episode_sha256": record["episode_sha256"],
        "reviewed": True, "accepted": True, "rationale": REASON})
    assert reviewed.status_code == 200 and reviewed.json()["status"] == "accepted", reviewed.text
    accepted = reviewed.json()
    if not allow_learning:
        return run
    granted = harness.client.post(_base(run) + "/training-grant", json={
        "expected_revision": accepted["revision"], "expected_episode_sha256": accepted["episode_sha256"],
        "use_until": time.time() + grant_seconds, "retain_derived_copies": True, "rationale": REASON})
    assert granted.status_code == 200, granted.text
    assert granted.json()["grant_sha256"]
    return run


def test_fresh_runs_are_captured_reviewed_granted_and_learned_from(harness):
    _lineage_flags(harness)
    runs = [_keep_as_example(harness, index) for index in range(2)]
    flow_id = runs[0].flow_id
    examples = harness.client.get(f"/api/v1/flows/{flow_id}/teach/examples").json()
    listed = {row["run_id"]: row for row in examples["runs"]}
    assert all(listed[run.run_id]["can_learn"] and listed[run.run_id]["can_sign"] for run in runs)

    # The ordinary reviewed-runs route signs each granted run and keeps the
    # same live lineage checks as the explicit signed-copies route.
    learned = harness.client.post(f"/api/v1/flows/{flow_id}/teach/recipe/learn",
                                  json={"run_ids": [run.run_id for run in runs], "tools": [LOOKUP, CREATE]})
    assert learned.status_code == 200, learned.text
    assert learned.json()["summary"]["runs"] == 2 and learned.json()["summary"]["actions"] == [LOOKUP, CREATE]
    assert learned.json()["package"]["bundles"]
    draft = harness.client.post(f"/api/v1/flows/{flow_id}/teach/recipe/draft",
                                json={"package": learned.json()["package"], "name": "Learned order"})
    assert draft.status_code == 200 and draft.json()["saved"] is False, draft.text
    assert draft.json()["draft"]["recipe_lineage"]

    # And from their signed copies, through governed approval.
    bundles = []
    for run in runs:
        row = listed[run.run_id]
        signed = harness.client.post(_base(run) + "/signed-export", json={
            "expected_revision": row["revision"], "expected_episode_sha256": row["episode"],
            "expected_grant_sha256": row["grant"]})
        assert signed.status_code == 200, signed.text
        check = harness.client.post("/api/v1/flow-teach/signed-copy/check", json={"bundle": signed.json()})
        assert check.json()["genuine"] is True, check.text
        bundles.append(signed.json())
    transformed = harness.client.post("/api/v1/flow-teach/signed/learn", json={
        "bundles": bundles, "tools": [LOOKUP, CREATE], "style": "transforms", "max_operations": 1})
    assert transformed.status_code == 200, transformed.text
    assert transformed.json()["package"]["artifact"]["schema"] == "lightwork.action-recipe.v2"
    package = harness.client.post("/api/v1/flow-teach/signed/learn",
                                  json={"bundles": bundles, "tools": [LOOKUP, CREATE]})
    assert package.status_code == 200, package.text
    assert package.json()["approved"] is False
    admitted = harness.client.post("/api/v1/flows/recipe-lineage", json={"package": package.json()["package"]})
    assert admitted.status_code == 200, admitted.text
    record_id = admitted.json()["id"]
    approved = harness.client.get("/api/v1/flow-teach/approved").json()["recipes"]
    assert [row["id"] for row in approved] == [record_id]
    governed = harness.client.post(f"/api/v1/flows/recipe-lineage/{record_id}/draft",
                                   json={"flow_id": "learned-governed-order", "name": "Learned governed order"})
    assert governed.status_code == 200, governed.text
    assert governed.json()["recipe_lineage"]

    # A third, newly granted run refines the exact signed package; the older
    # signed examples and their lineage remain in the derivation.
    third = _keep_as_example(harness, 2)
    refined = harness.client.post(f"/api/v1/flows/{flow_id}/teach/recipe/refine", json={
        "package": learned.json()["package"], "run_ids": [third.run_id]})
    assert refined.status_code == 200 and refined.json()["summary"]["runs"] == 3, refined.text
    assert len(refined.json()["package"]["manifest"]) == 3
    refined_draft = harness.client.post(f"/api/v1/flows/{flow_id}/teach/recipe/draft", json={
        "package": refined.json()["package"], "name": "Improved order"})
    assert refined_draft.status_code == 200 and refined_draft.json()["draft"]["recipe_lineage"], refined_draft.text


def test_review_without_training_permission_cannot_be_learned_or_signed(harness):
    _lineage_flags(harness)
    # A learning decision needs the run's procedure to still be current, so
    # the run granted later is the one saved under the current procedure.
    other = _keep_as_example(harness, 0)
    run = _keep_as_example(harness, 1, allow_learning=False)
    path = f"/api/v1/flows/{run.flow_id}/teach"
    listed = {row["run_id"]: row for row in harness.client.get(path + "/examples").json()["runs"]}
    assert listed[run.run_id]["status"] == "accepted"
    assert listed[run.run_id]["can_learn"] is False and listed[run.run_id]["can_sign"] is False
    refused = harness.client.post(path + "/recipe/learn", json={
        "run_ids": [run.run_id, other.run_id], "tools": [LOOKUP, CREATE]})
    assert refused.status_code == 409 and "not currently allowed" in refused.json()["detail"]
    assert len(harness.calls) == 4, "denial must not repeat either business run"
    # The older raw export is still useful outside the Teach route. It cannot
    # be synthesized into a runnable customer flow while capture is enabled.
    raw = [harness.client.get(_base(item) + "/export") for item in (run, other)]
    assert all(result.status_code == 200 for result in raw)
    artifact = action_recipe.synthesize([result.json()["episode"] for result in raw],
                                        allowed_tools=[LOOKUP, CREATE])
    unsigned = recipe_flow.make_flow(artifact, flow_id="unsigned-bypass", name="Unsigned bypass")
    denied_save = harness.client.post("/api/v1/flows", json={"flow": unsigned.to_dict()})
    assert denied_save.status_code == 409 and "signed examples" in denied_save.json()["detail"]
    with tenant_scope(tenant=TENANT):
        assert store.load_flow("unsigned-bypass") is None
        nested = Flow(id="nested-bypass", name="Nested bypass", start="scope", owner=OWNER,
                      nodes={"scope": FlowNode(id="scope", kind="scope", body=unsigned)})
        with pytest.raises(ValueError, match="admitted signed evidence"):
            store.save_flow(nested)
        # A release made before this installation enabled capture must stop at
        # the next customer entrance once the signed-example rule takes effect.
        harness.flags.update(action_episode_capture=False, action_recipe_lineage=False)
        try:
            unsigned.owner = OWNER
            legacy = store.save_flow(unsigned)
            store.publish_flow(legacy.id, expected_version=legacy.version,
                               expected_revision=legacy.revision)
        finally:
            harness.flags.update(action_episode_capture=True, action_recipe_lineage=True)
    for endpoint, body in (("/api/v1/flows/unsigned-bypass/run", {"data": {"input": {"ref": "new"}}}),
                           ("/api/v1/flows/unsigned-bypass/publish",
                            {"version": legacy.version, "revision": legacy.revision})):
        blocked = harness.client.post(endpoint, json=body)
        assert blocked.status_code == 409 and "signed examples" in blocked.json()["detail"]
    assert len(harness.calls) == 4
    current = harness.client.get(_base(run)).json()
    grant = harness.client.post(_base(run) + "/training-grant", json={
        "expected_revision": current["revision"], "expected_episode_sha256": current["episode_sha256"],
        "use_until": time.time() + 3600, "retain_derived_copies": True, "rationale": REASON})
    assert grant.status_code == 200 and grant.json()["training_available"] is True, grant.text
    learned = harness.client.post(path + "/recipe/learn", json={
        "run_ids": [run.run_id, other.run_id], "tools": [LOOKUP, CREATE]})
    assert learned.status_code == 200 and learned.json()["package"]["manifest"], learned.text
    assert len(harness.calls) == 4


def test_expired_training_permission_is_not_offered_or_accepted(harness):
    _lineage_flags(harness)
    run = _keep_as_example(harness, 0, grant_seconds=1)
    other = _keep_as_example(harness, 1)
    time.sleep(1.05)
    path = f"/api/v1/flows/{run.flow_id}/teach"
    listed = {row["run_id"]: row for row in harness.client.get(path + "/examples").json()["runs"]}
    assert listed[run.run_id]["grant"] and listed[run.run_id]["can_learn"] is False
    assert listed[run.run_id]["can_sign"] is False and listed[other.run_id]["can_learn"] is True
    refused = harness.client.post(path + "/recipe/learn", json={
        "run_ids": [run.run_id, other.run_id], "tools": [LOOKUP, CREATE]})
    assert refused.status_code == 409 and len(harness.calls) == 4


def test_withdrawn_source_blocks_admission_and_runtime_of_reviewed_runs_recipe(harness):
    from maverick.flow import recipe_flow
    from maverick.flow.action_episode_review import ActionEpisodeConflict

    _lineage_flags(harness)
    runs = [_keep_as_example(harness, index) for index in range(2)]
    path = f"/api/v1/flows/{runs[0].flow_id}/teach"
    learned = harness.client.post(path + "/recipe/learn", json={
        "run_ids": [run.run_id for run in runs], "tools": [LOOKUP, CREATE]})
    assert learned.status_code == 200, learned.text
    package = learned.json()["package"]
    prepared = harness.client.post(path + "/recipe/draft", json={"package": package, "name": "Bound flow"})
    assert prepared.status_code == 200, prepared.text
    draft = prepared.json()["draft"]
    with tenant_scope(tenant=TENANT):
        assert recipe_flow.check_lineage(draft["learned_recipe"], draft["recipe_lineage"], owner=OWNER)
    current = harness.client.get(_base(runs[0])).json()
    withdrawn = harness.client.post(_base(runs[0]) + "/withdraw", json={
        "expected_revision": current["revision"], "expected_episode_sha256": current["episode_sha256"],
        "expected_review_sha256": current["review_sha256"], "withdraw": True, "rationale": "Stop future reuse."})
    assert withdrawn.status_code == 200 and withdrawn.json()["status"] == "withdrawn", withdrawn.text
    with tenant_scope(tenant=TENANT), pytest.raises(ActionEpisodeConflict):
        recipe_flow.check_lineage(draft["learned_recipe"], draft["recipe_lineage"], owner=OWNER)
    retry = harness.client.post(path + "/recipe/draft", json={"package": package, "name": "Bound flow"})
    assert retry.status_code in {403, 409} and len(harness.calls) == 4


def test_suggestion_refuses_runs_past_their_first_approval_and_other_people(harness):
    source, run = _paused(harness)
    middle = _resume(harness, source, run)
    assert middle.status == "paused_approval"
    assert harness.client.get(_base(run) + "/suggestion").status_code == 409
    _, fresh = _paused(harness, index=1)
    other = harness.client.get(_base(fresh) + "/suggestion", headers={"Authorization": "Bearer mallory"})
    assert other.status_code == 404


def test_run_page_offers_the_example_controls(harness):
    _, run = _paused(harness)
    page = harness.client.get(f"/flows/{run.flow_id}/runs/{run.run_id}")
    assert page.status_code == 200, page.text[:300]
    for needle in ("lx-card", "lx-enroll-go", "lx-accept", "lx-grant-go", "lightwork-learning-capture.js"):
        assert needle in page.text
    assert harness.client.get("/static/lightwork-learning-capture.js").status_code == 200
    assert harness.client.get("/static/lightwork-learning-example.js").status_code == 200
