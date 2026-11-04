"""Real native API/builder boundaries with synthetic audit and identity inputs."""
from __future__ import annotations

import hashlib
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient
from maverick import audit, config, world_model
from maverick.flow import store
from maverick.intent_value import opportunities, service
from maverick.oidc import VerifiedPrincipal
from maverick_dashboard import api, auth
from maverick_dashboard import app as app_module

BASE = "/api/v1/intent-value"


def headers(user="alice"):
    return {"Authorization": "Bearer " + user, "Origin": "http://127.0.0.1"}


@pytest.fixture
def context(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text('[value]\nhourly_rate=60.0\n[flows]\nenable=true\n[audit]\nsign=false\n[dashboard]\nadmins=["user:root"]\n', encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_ADMINS", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    api._world_cache.clear()
    app_module._world_cache.clear()
    config.reset_config_cache()
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kwargs: VerifiedPrincipal(
        sub=token, issuer="https://issuer.test", audience="maverick", claims={"sub": token}))
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")
    rbac.set_role("user:bob", "operator")
    with world_model.WorldModel(tmp_path / "world.db") as world:
        yield TestClient(app_module.app, base_url="http://127.0.0.1"), world
    config.reset_config_cache()


def seed(world, *, owner="user:alice", count=1, performed=True):
    ids = []
    for _ in range(count):
        gid = world.create_goal("Draft an RFP with CONFIDENTIAL-EMPLOYEE-MATERIAL", owner=owner)
        eid = world.start_episode(gid)
        world.end_episode(eid, "PRIVATE-RESULT", "success" if performed else "failed", cost_dollars=2)
        if performed:
            world.set_goal_status(gid, "done")
            audit.audit_event("goal_start", goal_id=gid, agent="orchestrator",
                              title=world.get_goal(gid).title, description="PRIVATE-REQUEST-CONTEXT")
            audit.audit_event("goal_end", goal_id=gid, agent="orchestrator", status="succeeded")
        ids.append(gid)
    return ids


def get(client, path="", user="alice"):
    # Reads never record work; the page records it first through the explicit sync.
    synced = client.post(BASE + "/sync", headers=headers(user))
    assert synced.status_code == 200, synced.text
    response = client.get(BASE + path, headers=headers(user))
    assert response.status_code == 200, response.text
    return response.json()


# A first render of a fresh home may create these, and nothing else: the empty
# authority fence that the shared navigation takes, and the template bytecode cache.
FIRST_RENDER_FILES = {"home/authority-effects.lock"}


def tree(root):
    """Content digests of every file under ``root``, lock files and caches included."""
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def stable(payload):
    """A report without its read-time stamps (the check time and the default period end)."""
    return {key: value for key, value in payload.items() if key not in {"checked_at", "end"}}


def test_native_completed_task_rename_preserves_report_and_copilot_value(context):
    client, world = context
    identifier = seed(world)[0]
    before = get(client)
    response = client.post(f"/api/v1/goals/{identifier}/retitle", headers=headers(),
        json={"title": "Review an invoice", "expected_updated_at": world.get_goal(identifier).updated_at,
              "operation_id": "intent-value-retitle-check"})
    assert response.status_code == 204, response.text
    after = get(client)
    assert after["totals"] == before["totals"]
    assert after["rows"][0]["intents"] == ["rfp.draft"]
    response = client.post("/api/v1/copilot", headers=headers(),
        json={"message": "What value delivered this month?", "page": "/work-value"})
    assert response.status_code == 200, response.text
    assert response.json()["metrics"]["totals"] == after["totals"]
    detail = get(client, "/work/" + after["rows"][0]["id"])
    assert "PRIVATE-REQUEST-CONTEXT" not in str(detail)
    assert "CONFIDENTIAL-EMPLOYEE-MATERIAL" not in str(detail)


def test_company_metadata_has_no_employee_content_or_mutation_authority(context):
    client, world = context
    seed(world)
    own = get(client)
    assert own["totals"]["performed_work"] == 1
    identifier = own["rows"][0]["id"]
    assert get(client, user="bob")["totals"]["performed_work"] == 0
    assert client.get(BASE + "/work/" + identifier, headers=headers("bob")).status_code == 404
    company = get(client, "?scope=company", user="root")
    detail = get(client, "/work/" + identifier + "?scope=company", user="root")
    assert company["totals"] == own["totals"]
    assert not detail["can_correct"] and not detail["sources"]
    assert "CONFIDENTIAL" not in str(company) + str(detail)
    assert "PRIVATE-RESULT" not in str(company) + str(detail)
    denied = client.post(BASE + "/work/" + identifier + "/correct", headers=headers("root"),
        json={"revision": detail["revision"], "intents": ["rfp.review"], "reason": "not my work"})
    assert denied.status_code == 404


def test_correction_cost_explanation_and_default_confirmation(context):
    client, world = context
    seed(world)
    row = get(client)["rows"][0]
    detail = get(client, "/work/" + row["id"])
    assert not detail["confirmation_enabled"]
    assert len(detail["evidence"]) == 1 and detail["costs"][0]["amount"] == 2
    result = client.post(BASE + "/work/" + row["id"] + "/correct", headers=headers(),
        json={"revision": detail["revision"], "intents": ["rfp.review"], "size": "standard", "reason": "Existing RFP review"})
    assert result.status_code == 200, result.text
    updated = get(client)["rows"][0]
    assert updated["gross"] < row["gross"]
    assert len(get(client, "/work/" + row["id"])["estimates"]) == 2
    assert client.post(BASE + "/work/" + row["id"] + "/confirm", headers=headers(), json={"revision": updated["revision"]}).status_code == 422


def test_deliverable_correction_preserves_evidence_and_previous_quantity(context):
    client, world = context
    seed(world)
    row = get(client)["rows"][0]
    original = get(client, "/work/" + row["id"])
    response = client.post(BASE + "/work/" + row["id"] + "/correct", headers=headers(), json={
        "revision": row["revision"], "intents": ["rfp.draft", "rfp.review"], "units": {"rfp": 2},
        "reason": "Two independent RFP deliverables, each drafted and reviewed."})
    assert response.status_code == 200, response.text
    changed = get(client, "/work/" + row["id"])
    assert changed["evidence"] == original["evidence"]
    assert changed["estimates"][0] == original["estimates"][0]
    assert changed["estimates"][-1]["gross"] == 2 * original["estimates"][-1]["gross"]
    assert get(client)["totals"]["performed_work"] == 1
    rejected = client.post(BASE + "/work/" + row["id"] + "/correct", headers=headers(), json={
        "revision": changed["revision"], "intents": ["rfp.draft"], "units": {"invoice": 50}, "reason": "Wrong object"})
    assert rejected.status_code == 422


def test_pending_audit_cannot_release_detail_or_accept_correction(context, monkeypatch):
    client, world = context
    seed(world)
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    report = get(client)
    assert report["incomplete"] and report["rows"] == []
    row = service.WORKS.list(limit=10)[0]
    assert client.get(BASE + "/work/" + row["id"], headers=headers()).status_code == 503
    response = client.post(BASE + "/work/" + row["id"] + "/correct", headers=headers(), json={
        "revision": row["revision"], "intents": ["rfp.review"], "reason": "Cannot outrun pending audit"})
    assert response.status_code == 503


def test_copilot_honors_dashboard_filters_and_ambiguity(context):
    client, world = context
    seed(world)
    answer = client.post("/api/v1/copilot", headers=headers(), json={
        "message": "What is the net benefit?", "page": "/work-value?intent=rfp.review&scope=own"})
    assert answer.status_code == 200, answer.text
    assert answer.json()["metrics"]["totals"] == get(client, "?intent=rfp.review")["totals"]
    save_existing_process(client)
    response = client.post("/api/v1/flows", headers=headers(), json={"flow": {
        "id": "other-proposal", "name": "Bid preparation", "start": "prepare",
        "nodes": [{"id": "prepare", "kind": "agent", "brief": "Draft an RFP"}]}})
    assert response.status_code == 201, response.text
    ambiguous = client.post("/api/v1/copilot", headers=headers(), json={
        "message": "What did process Bid preparation cost?", "page": "/work-value"})
    assert ambiguous.status_code == 200
    assert "Which process" in ambiguous.json()["reply"] and "metrics" not in ambiguous.json()


def test_metric_copilot_matches_dashboard_and_retains_followup_scope(context):
    client, world = context
    seed(world)
    expected = get(client)["totals"]
    response = client.post("/api/v1/copilot", headers=headers(), json={"message": "What is Lightwork delivering across our company?", "page": "/work-value"})
    assert response.status_code == 200, response.text
    answer = response.json()
    assert answer["metrics"]["totals"] == expected
    assert "benchmark" in answer["reply"].lower()
    explanation = client.post("/api/v1/copilot", headers=headers(), json={"message": "Why did that number fall?", "page": "/work-value", "conversation_token": answer["conversation_token"]})
    assert explanation.status_code == 200, explanation.text
    explained = explanation.json()
    assert explained["metrics"]["totals"] == expected
    assert explained["metrics"]["comparison_detail"]["cost_changes"] == {"USD": 2}
    assert explained["metrics"]["comparison_detail"]["intent_changes"][0]["id"] == "rfp.draft"
    assert "known execution costs" in explained["reply"] and "change USD 2.00" in explained["reply"]
    assert "does not establish a causal reason" in explained["reply"]
    next_response = client.post("/api/v1/copilot", headers=headers(), json={"message": "What about last month?", "page": "/work-value", "conversation_token": answer["conversation_token"]})
    assert next_response.status_code == 200, next_response.text
    assert next_response.json()["metrics"]["scope"] == "company"
    assert next_response.json()["metrics"]["totals"]["performed_work"] == 0
    replay = client.post("/api/v1/copilot", headers=headers("bob"), json={"message": "Why?", "page": "/work-value", "conversation_token": answer["conversation_token"]})
    assert replay.status_code == 409


def test_build_is_native_idempotent_draft_with_retained_manual_steps(context):
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    assert proposal["current_evidence"]["draft_supported"]
    choice = client.post(BASE + "/opportunities/" + proposal["id"] + "/decision", headers=headers(),
        json={"revision": proposal["revision"], "decision": "adjust", "manual_steps": ["inputs", "prepare", "review"]})
    assert choice.status_code == 200, choice.text
    body = {"revision": choice.json()["revision"]}
    first = client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers(), json=body)
    assert first.status_code == 200, first.text
    second = client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers(), json=body)
    assert second.status_code == 200, second.text
    assert first.json()["draft_id"] == second.json()["draft_id"]
    flow = store.load_flow(first.json()["draft_id"])
    assert flow.owner == "user:alice" and not flow.schedule
    assert all(node.kind == "approval" for node in flow.nodes.values())
    assert store.load_published_bundle(flow.id) is None
    assert list(store.iter_run_metadata()) == []
    assert len(store.list_flows()) == 1
    assert get(client)["totals"]["performed_work"] == 3


def test_interrupted_native_save_resumes_same_reserved_draft(context, monkeypatch):
    from maverick_dashboard import flows_api
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    real = flows_api._save_flow_definition
    calls = []
    def interrupted(*args, **kwargs):
        saved = real(*args, **kwargs)
        calls.append(saved)
        raise OSError("simulated interruption after native save")
    monkeypatch.setattr(flows_api, "_save_flow_definition", interrupted)
    path = BASE + "/opportunities/" + proposal["id"] + "/build"
    assert client.post(path, headers=headers(), json={"revision": proposal["revision"]}).status_code == 503
    monkeypatch.setattr(flows_api, "_save_flow_definition", real)
    retry = client.post(path, headers=headers(), json={"revision": proposal["revision"]})
    assert retry.status_code == 200, retry.text
    assert len(calls) == len(store.list_flows()) == 1


def test_decline_suppresses_unchanged_proposal_and_cross_owner_build(context):
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/decision", headers=headers(),
        json={"revision": proposal["revision"], "decision": "decline"})
    assert response.status_code == 200
    assert get(client, "/opportunities")["opportunities"] == []
    assert get(client, "/opportunities?include_decided=true")["opportunities"][0]["status"] == "declined"
    assert client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers("bob"),
        json={"revision": proposal["revision"]}).status_code == 404


def test_unsupported_or_deleted_evidence_cannot_build(context):
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    with world._writing() as conn:
        conn.execute("DELETE FROM episodes")
        conn.execute("DELETE FROM goals")
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 409
    assert get(client)["totals"]["performed_work"] == 0


def test_native_outcome_requires_work_receipt_and_preserves_forecast(context):
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 200, response.text
    current = opportunities.RECOMMENDATIONS.get(proposal["id"])
    flow = store.load_flow(current["draft_id"])
    publish = client.post("/api/v1/flows/" + flow.id + "/publish", headers=headers(),
        json={"version": flow.version, "revision": flow.revision})
    assert publish.status_code == 200, publish.text
    assert opportunities.outcome(current, service.refresh(world))["state"] == "adopted"
    from maverick.flow.store import FlowRun
    release = store.load_published_bundle(flow.id)[1]
    run = FlowRun(run_id="value-outcome", flow_id=flow.id, owner=flow.owner,
        status="completed", created=time.time(), updated=time.time(), definition_revision=flow.revision,
        definition_digest=release["definition_digest"], release_id=release["release_id"], subflow_digests=release["subflow_digests"])
    store.save_run(run)
    assert opportunities.outcome(current, service.refresh(world))["observed_runs"] == 0
    audit.audit_event("control_plane_action", agent="flow", action="intent_value.flow_state", run_id=run.run_id,
        status="completed", definition_revision=flow.revision, release_id=run.release_id, performed_work_nodes=1)
    outcome = opportunities.outcome(current, service.refresh(world))
    assert outcome["observed_runs"] == 1
    assert opportunities.RECOMMENDATIONS.get(proposal["id"])["forecast"] == proposal["forecast"]
    assert get(client)["totals"]["performed_work"] == 4


def test_cross_tenant_metric_evidence_and_recommendation_boundaries(context, monkeypatch):
    from maverick.paths import tenant_scope
    client, _world = context
    monkeypatch.setenv("MAVERICK_TENANT_BY_USER", "1")
    with tenant_scope(tenant="api:user:alice"):
        seed(api._world(), count=3)
    alice = get(client)
    assert alice["totals"]["performed_work"] == 3
    proposal = get(client, "/opportunities")["opportunities"][0]
    assert get(client, "?scope=company", user="bob")["totals"]["performed_work"] == 0
    work_id = alice["rows"][0]["id"]
    assert client.get(BASE + "/work/" + work_id + "?scope=company", headers=headers("bob")).status_code == 404
    assert client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers("bob"),
        json={"revision": proposal["revision"]}).status_code == 404
    answer = client.post("/api/v1/copilot", headers=headers("bob"), json={"message": "What is Lightwork delivering across our company?", "page": "/work-value"})
    assert answer.status_code == 200, answer.text
    assert answer.json()["metrics"]["totals"]["performed_work"] == 0


def test_source_failure_is_unavailable_not_zero(context, monkeypatch):
    from maverick.intent_value import sources
    client, world = context
    seed(world)
    get(client)
    def unavailable():
        raise OSError("synthetic unreadable audit history")
    monkeypatch.setattr(sources, "audit_population", unavailable)
    # Reads report the recorded ledger; the sync that records new work is where an unreadable source surfaces.
    response = client.post(BASE + "/sync", headers=headers())
    assert response.status_code == 503 and "not zero" in response.text
    response = client.get(BASE, headers=headers())
    assert response.status_code == 200 and response.json()["totals"]["performed_work"] == 1
    response = client.post("/api/v1/copilot", headers=headers(), json={"message": "What value delivered this month?", "page": "/work-value"})
    assert response.status_code == 503


def test_existing_chat_handoff_links_execution_and_converts_potential_once(context):
    from maverick_dashboard import intent_value_handoff
    from starlette.requests import Request
    client, world = context
    seed(world, performed=False)
    before = get(client)
    proposal = get(client, "/opportunities")["opportunities"][0]
    selected = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert selected.status_code == 200, selected.text
    assert "value_opportunity=" in selected.json()["href"]
    assert get(client)["totals"]["performed_work"] == 0
    request = Request({"type": "http", "method": "POST", "headers": [(b"authorization", b"Bearer alice")],
                       "path": "/chat/send", "query_string": b""})
    request.state.principal = VerifiedPrincipal(sub="alice", issuer="https://issuer.test", audience="maverick", claims={"sub": "alice"})
    gid = seed(world)[0]
    intent_value_handoff.bind(request, proposal["id"], world, gid)
    intent_value_handoff.bind(request, proposal["id"], world, gid)
    result = get(client)
    assert result["totals"]["performed_work"] == 1
    assert result["totals"]["opportunity_value"] == 0 < before["totals"]["opportunity_value"]
    converted = next(row for row in result["rows"] if row["converted_to"])
    explanation = get(client, "/work/" + converted["id"])
    assert explanation["converted_to"] == converted["converted_to"]
    assert opportunities.RECOMMENDATIONS.get(proposal["id"])["linked_goal_ids"] == [gid]
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["observed_runs"] == 1
    assert current["next_review_reference"]["sample_count"] == 1


def save_existing_process(client):
    response = client.post("/api/v1/flows", headers=headers(), json={"flow": {
        "id": "proposal-process", "name": "Bid preparation", "start": "prepare", "nodes": [
            {"id": "prepare", "kind": "agent", "brief": "Draft an RFP", "output": "result"}]}})
    assert response.status_code == 201, response.text
    return store.load_flow("proposal-process")


def disable_recommendations(monkeypatch):
    from maverick.intent_value import settings
    monkeypatch.setattr(settings, "policy", lambda: {
        "enabled": True, "recommendations": False, "completion_confirmation": False})
    monkeypatch.setattr(opportunities, "policy", settings.policy)


def test_disabled_recommendations_neither_offer_nor_persist_reuse(context, monkeypatch):
    from maverick_dashboard import intent_value_api
    client, world = context
    seed(world, count=3)
    save_existing_process(client)
    disable_recommendations(monkeypatch)
    monkeypatch.setattr(intent_value_api, "capabilities", lambda request: pytest.fail("Disabled suggestions must not enumerate capabilities"))
    assert get(client, "/opportunities")["opportunities"] == []
    assert opportunities.RECOMMENDATIONS.list(limit=10) == []
    assert get(client)["totals"]["performed_work"] == 3


def test_disabled_recommendations_skip_external_discovery_and_recover(context, monkeypatch):
    from maverick_dashboard import intent_value_discovery

    client, world = context
    seed(world)
    calls = []
    external = {"state": "available", "patterns": [{"id": "external-pattern", "href": "/ekko?device_id=desk"}],
                "notice": "Consented external observations"}

    def discover(request, device_id):
        calls.append(device_id)
        return external

    monkeypatch.setattr(intent_value_discovery, "read", discover)
    assert get(client, "/opportunities?device_id=desk")["external_observations"] == external
    before = get(client)["totals"]
    with monkeypatch.context() as disabled:
        disable_recommendations(disabled)
        suggestions = get(client, "/opportunities?device_id=desk")
        assert not suggestions["recommendations_enabled"]
        assert suggestions["external_observations"]["patterns"] == []
        assert "turned off" in suggestions["external_observations"]["notice"]
        assert calls == ["desk"]
        answer = client.post("/api/v1/copilot", headers=headers(), json={
            "message": "How can I save more?", "page": "/work-value"})
        assert answer.status_code == 200, answer.text
        assert "turned off" in answer.json()["reply"]
        assert answer.json()["metrics"]["totals"] == before
        assert calls == ["desk"]
    assert get(client, "/opportunities?device_id=desk")["external_observations"] == external
    assert calls == ["desk", "desk"]


def test_external_discovery_cannot_release_patterns_after_policy_revocation(context, monkeypatch):
    from maverick_dashboard import intent_value_discovery

    client, _world = context

    def revoke_during_discovery(request, device_id):
        disable_recommendations(monkeypatch)
        return {"state": "available", "patterns": [{"id": "stale-pattern", "href": "/ekko"}], "notice": "External work"}

    monkeypatch.setattr(intent_value_discovery, "read", revoke_during_discovery)
    suggestions = get(client, "/opportunities")
    assert not suggestions["recommendations_enabled"]
    assert suggestions["opportunities"] == []
    assert suggestions["external_observations"]["patterns"] == []


def test_disabled_recommendations_block_stale_actions_and_chat_handoff(context, monkeypatch):
    from fastapi import HTTPException
    from maverick_dashboard import intent_value_handoff
    from starlette.requests import Request

    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    path = BASE + "/opportunities/" + proposal["id"]
    built = client.post(path + "/build", headers=headers(), json={"revision": proposal["revision"]})
    assert built.status_code == 200, built.text
    prior = opportunities.RECOMMENDATIONS.get(proposal["id"])
    disable_recommendations(monkeypatch)
    for suffix, body in (("/use", {}), ("/build", {}), ("/decision", {"decision": "reopen"})):
        response = client.post(path + suffix, headers=headers(), json={"revision": prior["revision"], **body})
        assert response.status_code == 403, response.text
    request = Request({"type": "http", "method": "POST", "headers": [], "path": "/chat/send", "query_string": b""})
    request.state.principal = VerifiedPrincipal(sub="alice", issuer="https://issuer.test", audience="maverick", claims={"sub": "alice"})
    with pytest.raises(HTTPException) as error:
        intent_value_handoff.bind(request, proposal["id"], world, seed(world)[0])
    assert error.value.status_code == 403
    assert opportunities.RECOMMENDATIONS.get(proposal["id"]) == prior
    assert len(store.list_flows()) == 1


def publish_process(client, flow):
    response = client.post("/api/v1/flows/" + flow.id + "/publish", headers=headers(),
        json={"version": flow.version, "revision": flow.revision})
    assert response.status_code == 200, response.text
    return store.load_published_bundle(flow.id)[1]


def completed_process_run(flow, release, *, run_id="bound-run", origin=""):
    run = store.FlowRun(run_id=run_id, flow_id=flow.id, owner=flow.owner,
        status="completed", created=time.time(), updated=time.time(), cost_dollars=1,
        definition_revision=flow.revision, definition_digest=release["definition_digest"],
        release_id=release["release_id"], subflow_digests=release["subflow_digests"], origin=origin)
    store.save_run(run)
    audit.audit_event("control_plane_action", agent="flow", action="intent_value.flow_state", run_id=run.run_id,
        status="completed", definition_revision=flow.revision, release_id=run.release_id, performed_work_nodes=1)
    return run


def test_reused_workflow_cannot_adopt_or_credit_an_older_published_definition(context):
    client, world = context
    seed(world, count=3)
    old = save_existing_process(client)
    old_release = publish_process(client, old)
    payload = old.to_dict()
    payload["name"] = "Updated bid preparation"
    response = client.post("/api/v1/flows", headers=headers(), json={"flow": payload})
    assert response.status_code == 201, response.text
    current_flow = store.load_flow(old.id)
    assert current_flow.revision == old.revision and current_flow.version > old.version
    proposal = get(client, "/opportunities")["opportunities"][0]
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 200, response.text
    completed_process_run(old, old_release, run_id="old-release-run")
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["state"] == "draft"
    assert current["outcome"]["observed_runs"] == 0
    release = publish_process(client, current_flow)
    completed_process_run(current_flow, release, run_id="selected-release-run")
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["observed_runs"] == 1
    assert current["outcome"]["attempt_count"] == 1
    assert get(client)["totals"]["performed_work"] == 5


def test_policy_revocation_at_selection_effect_leaves_recommendation_unchanged(context, monkeypatch):
    client, world = context
    seed(world, count=3)
    save_existing_process(client)
    proposal = get(client, "/opportunities")["opportunities"][0]
    prior = opportunities.RECOMMENDATIONS.get(proposal["id"])
    original = opportunities.RECOMMENDATIONS.update

    def revoke_before_effect(*args, **kwargs):
        if kwargs["action"] == "intent_value.capability_selected":
            disable_recommendations(monkeypatch)
        return original(*args, **kwargs)

    monkeypatch.setattr(opportunities.RECOMMENDATIONS, "update", revoke_before_effect)
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 403, response.text
    assert opportunities.RECOMMENDATIONS.get(proposal["id"]) == prior


def test_policy_revocation_at_native_draft_save_does_not_create_workflow(context, monkeypatch):
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    original = store.save_flow

    def revoke_before_effect(*args, **kwargs):
        disable_recommendations(monkeypatch)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "save_flow", revoke_before_effect)
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 403, response.text
    assert store.list_flows() == []
    assert opportunities.RECOMMENDATIONS.get(proposal["id"])["status"] == "building"


def test_workflow_edit_at_selection_effect_requires_fresh_review(context, monkeypatch):
    client, world = context
    seed(world, count=3)
    flow = save_existing_process(client)
    proposal = get(client, "/opportunities")["opportunities"][0]
    prior = opportunities.RECOMMENDATIONS.get(proposal["id"])
    original = opportunities.RECOMMENDATIONS.update

    def edit_before_effect(*args, **kwargs):
        if kwargs["action"] == "intent_value.capability_selected":
            flow.name = "Changed after selection"
            store.save_flow(flow, expected_version=flow.version, expected_revision=flow.revision)
        return original(*args, **kwargs)

    monkeypatch.setattr(opportunities.RECOMMENDATIONS, "update", edit_before_effect)
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 409, response.text
    assert opportunities.RECOMMENDATIONS.get(proposal["id"]) == prior


def test_exact_publication_survives_republish_and_rejects_mixed_retry_credit(context):
    client, world = context
    seed(world, count=3)
    flow = save_existing_process(client)
    selected_release = publish_process(client, flow)
    proposal = get(client, "/opportunities")["opportunities"][0]
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 200, response.text
    later_release = publish_process(client, flow)
    assert later_release["release_digest"] == selected_release["release_digest"]
    assert later_release["release_id"] != selected_release["release_id"]
    completed_process_run(flow, later_release, run_id="other-publication")
    completed_process_run(flow, selected_release, run_id="selected-publication")
    old = completed_process_run(flow, later_release, run_id="mixed-root")
    completed_process_run(flow, selected_release, run_id="mixed-retry", origin="retry:" + old.run_id)
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["observed_runs"] == 1
    assert current["outcome"]["attempt_count"] == 1
    assert get(client)["totals"]["performed_work"] == 6  # Three originals and three deduplicated flow work items.


def test_edited_draft_adopts_explicit_publication_and_retains_that_binding(context):
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/build", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 200, response.text
    flow = store.load_flow(response.json()["draft_id"])
    flow.nodes["prepare"].brief += " Make the result concise."
    store.save_flow(flow, expected_version=flow.version, expected_revision=flow.revision)
    adopted = publish_process(client, flow)
    completed_process_run(flow, adopted, run_id="edited-draft-run")
    # The first read is only metrics, not the recommendation page. It must
    # retain its publication before a later publish can replace the pointer.
    assert get(client)["totals"]["performed_work"] == 4
    assert opportunities.RECOMMENDATIONS.get(proposal["id"])["workflow_release"]["release_id"] == adopted["release_id"]
    later = publish_process(client, flow)
    completed_process_run(flow, later, run_id="later-draft-run")
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["observed_runs"] == 1
    assert current["outcome"]["release_binding"]["release_id"] == adopted["release_id"]


def test_exact_partial_failed_attempt_retains_cost_without_completed_work_credit(context):
    client, world = context
    seed(world, count=3)
    flow = save_existing_process(client)
    release = publish_process(client, flow)
    proposal = get(client, "/opportunities")["opportunities"][0]
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 200, response.text
    failed = store.FlowRun(run_id="partial-failed", flow_id=flow.id, owner=flow.owner,
        status="failed", created=time.time(), cost_dollars=3,
        definition_revision=flow.revision, definition_digest=release["definition_digest"],
        release_id=release["release_id"], subflow_digests=release["subflow_digests"])
    store.save_run(failed)
    audit.audit_event("control_plane_action", agent="flow", action="intent_value.flow_state", run_id=failed.run_id,
        status="failed", definition_revision=flow.revision, release_id=failed.release_id, performed_work_nodes=1)
    incomplete = get(client, "/opportunities")["opportunities"][0]
    assert incomplete["outcome"]["observed_runs"] == 0
    assert incomplete["outcome"]["attempt_count"] == 1
    assert incomplete["outcome"]["runs"][0]["performed"] is False
    completed_process_run(flow, release, run_id="completed-after-failure")
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["observed_runs"] == 1
    assert current["outcome"]["attempt_count"] == 2
    assert current["outcome"]["after_known_cost_per_run"] == 4


def test_legacy_generation_only_selection_preserves_work_without_invented_attribution(context):
    client, world = context
    seed(world, count=3)
    flow = save_existing_process(client)
    release = publish_process(client, flow)
    proposal = get(client, "/opportunities")["opportunities"][0]
    opportunities.RECOMMENDATIONS.update(proposal["id"], lambda row: row.update(
        adopted_capability={"kind": "process", "id": flow.id, "revision": flow.revision}, adopted_at=time.time()),
        expected_revision=proposal["revision"], action="test.legacy_selection", actor="test")
    completed_process_run(flow, release)
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["state"] == "source_unavailable"
    assert current["outcome"]["runs"] == []
    assert "select the workflow again" in current["outcome"]["message"]
    assert get(client)["totals"]["performed_work"] == 4


def test_prepared_copilot_use_cannot_outlive_recommendation_policy(context, monkeypatch):
    from maverick_dashboard import product_operations as operations
    client, world = context
    seed(world, count=3)
    proposal = get(client, "/opportunities")["opportunities"][0]
    prior = opportunities.RECOMMENDATIONS.get(proposal["id"])
    monkeypatch.setattr(operations, "_gate", lambda request: auth.require_permission(request, "operate"))
    base, scope = "/api/v1/copilot/product-operations", {"page": "/work-value", "selection": {}}
    catalog = client.post(base + "/catalog", headers=headers(), json=scope).json()
    action = next(row for row in catalog["operations"] if row["id"] == "learning.work_value_use")
    response = client.post(base + "/prepare", headers=headers(), json={**scope, "context": catalog["context"],
        "operation": action["id"], "revision": action["revision"], "arguments": {"identifier": proposal["id"]}})
    assert response.status_code == 200, response.text
    disable_recommendations(monkeypatch)
    execution = client.post(base + "/execute", headers=headers(), json={"token": response.json()["token"], "confirmed": True})
    assert execution.status_code in {403, 409}, execution.text
    assert opportunities.RECOMMENDATIONS.get(proposal["id"]) == prior


def test_existing_process_adoption_outcomes_remain_readable(context):
    client, world = context
    seed(world, count=3)
    flow = save_existing_process(client)
    release = publish_process(client, flow)
    proposal = get(client, "/opportunities")["opportunities"][0]
    assert proposal["current_evidence"]["capability"]["id"] == flow.id
    response = client.post(BASE + "/opportunities/" + proposal["id"] + "/use", headers=headers(), json={"revision": proposal["revision"]})
    assert response.status_code == 200, response.text
    completed_process_run(flow, release, run_id="reused-value-run")
    current = get(client, "/opportunities")["opportunities"][0]
    assert current["outcome"]["observed_runs"] == 1
    assert get(client)["totals"]["performed_work"] == 4


def test_copilot_resolves_entity_clarification_by_business_name(context):
    client, _world = context
    flow = save_existing_process(client)
    response = client.post("/api/v1/copilot", headers=headers(), json={"message": "What ROI has this process delivered?", "page": "/work-value"})
    assert response.status_code == 200, response.text
    answer = response.json()
    assert "Which process" in answer["reply"]
    assert answer.get("conversation_token")
    followup = client.post("/api/v1/copilot", headers=headers(), json={"message": "Bid preparation", "page": "/work-value", "conversation_token": answer["conversation_token"]})
    assert followup.status_code == 200, followup.text
    expected = get(client, "?entity_kind=processes&entity_id=" + flow.id)
    assert followup.json()["metrics"]["totals"] == expected["totals"]
    assert "Bid preparation" in followup.json()["reply"]


def test_copilot_native_read_and_reviewed_correction(context, monkeypatch):
    from maverick_dashboard import product_operations as operations
    client, world = context
    seed(world)
    monkeypatch.setattr(operations, "_gate", lambda request: auth.require_permission(request, "operate"))
    base = "/api/v1/copilot/product-operations"
    context_body = {"page": "/work-value", "selection": {}}
    response = client.post(base + "/catalog", headers=headers(), json=context_body)
    assert response.status_code == 200, response.text
    catalog = response.json()
    correction = next(row for row in catalog["operations"] if row["id"] == "learning.work_value_correct")
    row = get(client)["rows"][0]
    response = client.post(base + "/prepare", headers=headers(), json={**context_body,
        "context": catalog["context"], "operation": correction["id"], "revision": correction["revision"],
        "arguments": {"identifier": row["id"], "intents": "rfp.review", "size": "standard", "reason": "Actual requested review"}})
    assert response.status_code == 200, response.text
    prepared = response.json()
    assert get(client)["rows"][0]["intents"] == ["rfp.draft"]
    response = client.post(base + "/execute", headers=headers(), json={"token": prepared["token"], "confirmed": True})
    assert response.status_code == 200, response.text
    assert get(client)["rows"][0]["intents"] == ["rfp.review"]


@pytest.mark.parametrize(("kind", "arguments", "path"), [
    ("settings", {"hourly_rate": 48, "currency": "USD", "completion_confirmation": True}, "/settings"),
    ("benchmark", {"identifier": "rfp.draft", "minutes": 100, "low_minutes": 50, "high_minutes": 150,
                   "attributable_share": 0.5, "review_minutes": 20, "reason": "Company timing study"}, "/benchmarks"),
])
def test_copilot_admin_assumptions_require_review_preserve_history_and_deduplicate(context, monkeypatch, kind, arguments, path):
    from maverick_dashboard import product_operations as operations

    client, world = context
    seed(world)
    original = get(client)["totals"]
    monkeypatch.setattr(operations, "_gate", lambda request: auth.require_permission(request, "operate"))
    base, scope = "/api/v1/copilot/product-operations", {"page": "/work-value", "selection": {}}
    catalogue = client.post(base + "/catalog", headers=headers("root"), json=scope).json()
    action = next(row for row in catalogue["operations"] if row["id"] == "learning.work_value_" + kind)
    prior = get(client, path, user="root")
    response = client.post(base + "/prepare", headers=headers("root"), json={**scope, "context": catalogue["context"],
        "operation": action["id"], "revision": action["revision"], "arguments": arguments})
    assert response.status_code == 200, response.text
    assert get(client, path, user="root") == prior
    token = response.json()["token"]
    executed = client.post(base + "/execute", headers=headers("root"), json={"token": token, "confirmed": True})
    assert executed.status_code == 200, executed.text
    current = get(client, path, user="root")
    replay = client.post(base + "/execute", headers=headers("root"), json={"token": token, "confirmed": True})
    assert replay.status_code == 409  # Native reviewed-operation tokens become stale after the change.
    assert get(client, path, user="root") == current and current != prior
    assert get(client)["totals"] == original
    ordinary = client.post(base + "/catalog", headers=headers(), json=scope).json()
    assert action["id"] not in {row["id"] for row in ordinary["operations"]}


def test_reads_leave_stores_unchanged_until_the_page_syncs(context, tmp_path):
    client, world = context
    seed(world, count=3)
    empty = tree(tmp_path)
    assert client.get("/work-value", headers=headers()).status_code == 200
    created = set(tree(tmp_path)) - set(empty)
    assert all(path in FIRST_RENDER_FILES or path.startswith("home/cache/templates/") for path in created), created
    before = tree(tmp_path)
    unrecorded = client.get(BASE, headers=headers())
    assert unrecorded.status_code == 200 and unrecorded.json()["totals"]["performed_work"] == 0
    for path in ("/opportunities", "/settings", "/benchmarks"):
        assert client.get(BASE + path, headers=headers()).status_code == 200
    assert tree(tmp_path) == before
    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    recorded = tree(tmp_path)
    assert recorded != before
    first = client.get(BASE, headers=headers()).json()
    assert first["totals"]["performed_work"] == 3
    assert client.get(BASE + "/work/" + first["rows"][0]["id"], headers=headers()).status_code == 200
    assert tree(tmp_path) == recorded
    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    assert tree(tmp_path) == recorded
    assert stable(client.get(BASE, headers=headers()).json()) == stable(first)


def test_saved_rate_change_does_not_reprice_work_seen_before_it(context):
    client, world = context
    seed(world)
    settings = client.get(BASE + "/settings", headers=headers("root")).json()
    response = client.put(BASE + "/settings", headers=headers("root"), json={
        "revision": settings["revision"], "hourly_rate": 120, "currency": "USD", "completion_confirmation": False})
    assert response.status_code == 200, response.text
    row = get(client)["rows"][0]
    estimate = get(client, "/work/" + row["id"])["estimates"][0]
    assert estimate["assumptions"]["hourly_rate"] == 60.0
    assert get(client)["rows"][0]["revision"] == row["revision"]


def test_catalogue_listing_reads_the_callers_grants_once(context, monkeypatch):
    client, world = context
    seed(world, count=2)
    get(client)
    reads = []
    original = auth.caller_suites
    monkeypatch.setattr(auth, "caller_suites", lambda request: reads.append(1) or original(request))
    response = client.get(BASE + "/opportunities", headers=headers())
    assert response.status_code == 200, response.text
    assert len(reads) <= 1


def test_domain_suites_checker_matches_each_pack_check(monkeypatch):
    from fastapi import HTTPException
    from maverick.domain import available_domains, suites_for_domain
    names = sorted(available_domains())
    suites = sorted({suite for name in names for suite in suites_for_domain(name) if suite})
    assert suites
    grants = {"unrestricted": None, "none": frozenset(), "half": frozenset(suites[::2]), "all": frozenset(suites)}
    request = object()
    reads = []
    for label, granted in grants.items():
        monkeypatch.setattr(auth, "caller_suites", lambda request, granted=granted: reads.append(1) or granted)
        expected = {name: auth.domain_suites_allowed(request, name) for name in names}
        reads.clear()
        check = auth.domain_suites_checker(request)
        assert {name: check(name) for name in names} == expected, label
        assert len(reads) <= 1, label

    def broken(request):
        raise RuntimeError("grant store unavailable")
    monkeypatch.setattr(auth, "caller_suites", broken)
    with pytest.raises(HTTPException) as direct:
        auth.domain_suites_allowed(request, next(name for name in names if suites_for_domain(name)))
    with pytest.raises(HTTPException) as checked:
        auth.domain_suites_checker(request)(next(name for name in names if suites_for_domain(name)))
    assert checked.value.status_code == direct.value.status_code == 503


def test_opportunities_read_with_ekko_enabled_leaves_expired_events_in_place(context, monkeypatch, tmp_path):
    from maverick.work_discovery import CapturePolicy, WorkEvent
    from maverick.work_discovery_store import WorkDiscoveryStore
    from maverick_dashboard import ekko_routes, intent_value_discovery

    client, world = context
    seed(world)
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    monkeypatch.setattr(intent_value_discovery, "get_ekko", lambda: {"enable": True})
    now = 1_800_000_000.0
    path = tmp_path / "ekko.sqlite3"
    policy = CapturePolicy(
        enabled=True, capture_level="guided", allowed_apps=frozenset({"chrome"}),
        allowed_actions=frozenset({"download"}), allowed_object_types=frozenset({"report"}),
        retention_days=14, min_occurrences=2, min_distinct_days=2, poll_interval_seconds=1,
        provider_egress=False,
    )

    def ekko(clock):
        return WorkDiscoveryStore("user:alice", "local-device", tenant="acme", path=path,
                                  clock=lambda: clock, authority_check=lambda _policy: None)

    writer = ekko(now)
    writer.enroll(policy)
    writer.create_session(policy=policy, session_id="expired-session")
    writer.claim_collector("expired-session", "collector-test-capability", policy=policy, ttl_seconds=30)
    writer.append_event(WorkEvent(event_id="event-1", session_id="expired-session", sequence=1, occurred_at=now,
                                  app="chrome", action="download", object_type="report", duration_seconds=8),
                        policy=policy, collector_id="collector-test-capability")
    with sqlite3.connect(path) as conn:
        stored = conn.execute("SELECT event_id,event_digest,ingested_at,expires_at,payload FROM ekko_events").fetchall()
    assert len(stored) == 1
    monkeypatch.setattr(ekko_routes, "_store", lambda request, device_id: ekko(now + 15 * 86_400.0))

    response = client.get(BASE + "/opportunities", headers=headers())
    assert response.status_code == 200, response.text
    assert response.json()["external_observations"]["state"] == "available"
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT event_id,event_digest,ingested_at,expires_at,payload FROM ekko_events").fetchall() == stored


def test_pending_audit_receipts_are_retried_only_by_the_explicit_sync(context, monkeypatch, tmp_path):
    from maverick import audit

    client, world = context
    seed(world)
    settings_before = client.get(BASE + "/settings", headers=headers("root")).json()
    item = client.get(BASE + "/benchmarks", headers=headers("root")).json()["benchmarks"][0]
    real_record = audit.record
    # The audit receipt cannot be written yet: both rows keep their pending receipts.
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: None)
    saved = client.put(BASE + "/settings", headers=headers("root"), json={
        "revision": settings_before["revision"], "hourly_rate": 90, "currency": "USD", "completion_confirmation": False})
    assert saved.status_code == 200 and saved.json()["state"] == "audit_pending", saved.text
    benchmark = client.put(BASE + "/benchmarks/" + item["id"], headers=headers("root"), json={
        "revision": item["revision"], "minutes": 10, "low_minutes": 5, "high_minutes": 15,
        "attributable_share": 0.5, "review_minutes": 1, "reason": "Company time study"})
    assert benchmark.status_code == 200 and benchmark.json()["state"] == "audit_pending", benchmark.text
    pending = tree(tmp_path)

    # Reads report the pending state; they neither retry the receipt nor write it.
    assert client.get(BASE + "/settings", headers=headers("root")).status_code == 503
    assert client.get(BASE + "/benchmarks", headers=headers("root")).status_code == 503
    assert tree(tmp_path) == pending
    monkeypatch.setattr(audit, "record", real_record)
    assert client.get(BASE + "/settings", headers=headers("root")).status_code == 503
    assert client.get(BASE + "/benchmarks", headers=headers("root")).status_code == 503
    assert tree(tmp_path) == pending

    # The explicit sync is the one read-path-adjacent write that retries receipts.
    assert client.post(BASE + "/sync", headers=headers("root")).status_code == 200
    settings_after = client.get(BASE + "/settings", headers=headers("root"))
    assert settings_after.status_code == 200 and settings_after.json()["hourly_rate"] == 90
    benchmarks_after = client.get(BASE + "/benchmarks", headers=headers("root"))
    assert benchmarks_after.status_code == 200
    assert next(row for row in benchmarks_after.json()["benchmarks"] if row["id"] == item["id"])["benchmark"]["minutes"] == 10


def test_deleted_flow_run_is_withheld_from_reads_until_the_sync(context):
    from maverick.flow.store import FlowRun

    client, _world = context
    now = time.time()
    store.save_run(FlowRun(run_id="probe-run", flow_id="probe-flow", owner="user:alice", status="completed",
                           created=now, updated=now, definition_revision=1))
    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    identifier = next(row["id"] for row in service.WORKS.list(limit=100)
                      if any(source.get("id") == "probe-run" for source in row["source"]["sources"]))
    assert client.get(BASE + "/work/" + identifier, headers=headers()).status_code == 200

    # The run is deleted, but no sync has run: reads must not release its cost or evidence.
    assert store.delete_run("probe-run")
    assert client.get(BASE + "/work/" + identifier, headers=headers()).status_code == 404
    report = client.get(BASE, headers=headers()).json()
    assert identifier not in {row["id"] for row in report["rows"]}
    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    assert client.get(BASE + "/work/" + identifier, headers=headers()).status_code == 404


def test_report_states_when_its_recorded_work_last_changed_not_the_read_time(context):
    client, world = context
    seed(world, count=2)
    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    report = client.get(BASE, headers=headers()).json()
    newest = max(row["updated_at"] for row in service.WORKS.list(limit=100))
    assert report["recorded_as_of"] == newest
    # The deprecated checked_at is kept for existing clients, with the same value.
    assert report["checked_at"] == newest
    assert client.get(BASE, headers=headers()).json()["recorded_as_of"] == newest
    empty = client.get(BASE, headers=headers("bob")).json()
    assert empty["recorded_as_of"] is None
    assert empty["checked_at"] is None


def test_saving_assumptions_fails_closed_when_work_cannot_be_read(context, monkeypatch):
    # An edit first records observed work. If that cannot be read completely, the
    # edit is refused, so unrecorded work can never be priced under the new rate.
    from maverick.intent_value import sources

    client, world = context
    seed(world)
    before = client.get(BASE + "/settings", headers=headers("root")).json()
    readable = sources.audit_population

    def unreadable():
        raise OSError("synthetic unreadable audit history")
    monkeypatch.setattr(sources, "audit_population", unreadable)
    refused = client.put(BASE + "/settings", headers=headers("root"), json={
        "revision": before["revision"], "hourly_rate": 90, "currency": "USD", "completion_confirmation": False})
    assert refused.status_code == 503 and "not zero" in refused.text, refused.text
    assert client.get(BASE + "/settings", headers=headers("root")).json()["revision"] == before["revision"]
    monkeypatch.setattr(sources, "audit_population", readable)
    saved = client.put(BASE + "/settings", headers=headers("root"), json={
        "revision": before["revision"], "hourly_rate": 90, "currency": "USD", "completion_confirmation": False})
    assert saved.status_code == 200, saved.text
    assert client.get(BASE + "/settings", headers=headers("root")).json()["hourly_rate"] == 90


def test_report_and_suggestions_read_source_goals_in_one_batch_with_identical_output(context, monkeypatch):
    from maverick.world_model import WorldModel

    client, world = context
    seed(world, count=4)
    get(client)
    single = []
    per_goal = WorldModel.get_goal

    def counting(self, goal_id):
        single.append(goal_id)
        return per_goal(self, goal_id)
    monkeypatch.setattr(WorldModel, "get_goal", counting)
    batched = {path: client.get(BASE + path, headers=headers()) for path in ("", "/opportunities")}
    assert all(response.status_code == 200 for response in batched.values())
    assert single == []  # Source access checks read each row's goals in one batch, not one read per goal.

    # The batch must answer exactly as one read per goal does.
    monkeypatch.setattr(WorldModel, "get_goals", lambda self, goal_ids: {
        goal_id: goal for goal_id in goal_ids if (goal := per_goal(self, goal_id)) is not None})
    for path, response in batched.items():
        # The report's default period end is the read time, so compare without it.
        assert stable(client.get(BASE + path, headers=headers()).json()) == stable(response.json()), path


def test_specialist_intents_are_memoised_without_changing_the_classification():
    from maverick.domain import available_domains
    from maverick.intent_value import taxonomy
    from maverick_dashboard import intent_value_api

    domains = available_domains()
    assert len(domains) > 100
    for profile in domains.values():
        direct = taxonomy.classify(profile.description)["intents"]
        assert list(intent_value_api._domain_intents(profile.description)) == direct
        assert list(intent_value_api._domain_intents(profile.description)) == direct


def _ekko_with_an_expired_event(monkeypatch, tmp_path):
    """An enrolled device whose only observation is 15 days old: past its 14-day retention."""
    from maverick.work_discovery import CapturePolicy, WorkEvent
    from maverick.work_discovery_store import WorkDiscoveryStore
    from maverick_dashboard import ekko_routes, intent_value_discovery

    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    monkeypatch.setattr(intent_value_discovery, "get_ekko", lambda: {"enable": True})
    now = 1_800_000_000.0
    path = tmp_path / "ekko.sqlite3"
    policy = CapturePolicy(
        enabled=True, capture_level="guided", allowed_apps=frozenset({"chrome"}),
        allowed_actions=frozenset({"download"}), allowed_object_types=frozenset({"report"}),
        retention_days=14, min_occurrences=2, min_distinct_days=2, poll_interval_seconds=1,
        provider_egress=False,
    )

    def ekko(clock, device="local-device"):
        return WorkDiscoveryStore("user:alice", device, tenant="acme", path=path,
                                  clock=lambda: clock, authority_check=lambda _policy: None)

    writer = ekko(now)
    writer.enroll(policy)
    writer.create_session(policy=policy, session_id="expired-session")
    writer.claim_collector("expired-session", "collector-test-capability", policy=policy, ttl_seconds=30)
    writer.append_event(WorkEvent(event_id="event-1", session_id="expired-session", sequence=1, occurred_at=now,
                                  app="chrome", action="download", object_type="report", duration_seconds=8),
                        policy=policy, collector_id="collector-test-capability")
    def store(request, device_id):
        # The real route checks the device name before it opens a store.
        return ekko(now + 15 * 86_400.0, ekko_routes._device_id(device_id))

    monkeypatch.setattr(ekko_routes, "_store", store)
    return path


def _ekko_event_ids(path):
    with sqlite3.connect(path) as conn:
        return [row[0] for row in conn.execute("SELECT event_id FROM ekko_events").fetchall()]


def test_the_sync_deletes_expired_ekko_events_for_the_device_it_is_called_for(context, monkeypatch, tmp_path):
    client, world = context
    seed(world)
    path = _ekko_with_an_expired_event(monkeypatch, tmp_path)

    # The read leaves expired ciphertext in place; the explicit sync of another device leaves it too.
    assert client.get(BASE + "/opportunities", headers=headers()).status_code == 200
    assert _ekko_event_ids(path) == ["event-1"]
    assert client.post(BASE + "/sync?device_id=laptop-2", headers=headers()).status_code == 200
    assert _ekko_event_ids(path) == ["event-1"]

    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    assert _ekko_event_ids(path) == []


def test_a_sync_naming_an_invalid_device_still_records_and_deletes_no_ekko_events(context, monkeypatch, tmp_path):
    client, world = context
    seed(world)
    path = _ekko_with_an_expired_event(monkeypatch, tmp_path)

    response = client.post(BASE + "/sync?device_id=not%20a%20device", headers=headers())
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "recorded"
    assert _ekko_event_ids(path) == ["event-1"]


def test_a_viewer_sync_does_not_delete_expired_ekko_events(context, monkeypatch, tmp_path):
    from maverick_dashboard import auth

    client, world = context
    seed(world)
    path = _ekko_with_an_expired_event(monkeypatch, tmp_path)
    real = auth.has_permission
    monkeypatch.setattr(auth, "has_permission", lambda request, permission, **kwargs: permission != "operate" and real(request, permission, **kwargs))

    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    assert _ekko_event_ids(path) == ["event-1"]


def test_pausing_watching_deletes_expired_ekko_events(context, monkeypatch, tmp_path):
    client, world = context
    seed(world)
    path = _ekko_with_an_expired_event(monkeypatch, tmp_path)

    response = client.post("/api/v1/ekko/sessions/expired-session/pause", json={"device_id": "local-device"}, headers=headers())
    assert response.status_code == 200, response.text
    assert _ekko_event_ids(path) == []


def test_starting_watching_deletes_expired_ekko_events(context, monkeypatch, tmp_path):
    from maverick import config
    from maverick.work_discovery import SessionState

    client, world = context
    seed(world)
    path = _ekko_with_an_expired_event(monkeypatch, tmp_path)
    # The earlier session is stopped first, so the device may be watched again.
    monkeypatch.setattr(config, "get_ekko", lambda: {"enable": True, "allowed_apps": ["chrome"]})
    monkeypatch.setattr(config, "validate_ekko_policy_ceiling", lambda policy: None)
    from maverick_dashboard import ekko_routes
    store = ekko_routes._store(None, "local-device")
    store.transition_session("expired-session", SessionState.STOPPED)

    response = client.post("/api/v1/ekko/sessions", json={"device_id": "local-device", "acknowledge_capture_scope": True},
                           headers=headers())
    assert response.status_code == 201, response.text
    assert _ekko_event_ids(path) == []


def test_pausing_watching_still_pauses_when_its_retention_record_cannot_be_queued(context, monkeypatch, tmp_path):
    from maverick import work_discovery_store

    client, world = context
    seed(world)
    path = _ekko_with_an_expired_event(monkeypatch, tmp_path)
    monkeypatch.setattr(work_discovery_store, "MAX_AUDIT_OUTBOX", 0)

    response = client.post("/api/v1/ekko/sessions/expired-session/pause", json={"device_id": "local-device"}, headers=headers())
    # The pause is the safety action and stands; nothing is deleted without its record.
    assert response.status_code == 200, response.text
    assert response.json()["session"]["state"] == "paused"
    assert _ekko_event_ids(path) == ["event-1"]

    monkeypatch.setattr(work_discovery_store, "MAX_AUDIT_OUTBOX", 2_000)
    assert client.post(BASE + "/sync", headers=headers()).status_code == 200
    assert _ekko_event_ids(path) == []


def test_a_pause_delivers_the_retention_record_with_the_number_removed(context, monkeypatch, tmp_path):
    client, world = context
    seed(world)
    _ekko_with_an_expired_event(monkeypatch, tmp_path)
    delivered = []
    monkeypatch.setattr(audit, "record", lambda kind, **payload: delivered.append((kind, payload)) or True)

    response = client.post("/api/v1/ekko/sessions/expired-session/pause", json={"device_id": "local-device"}, headers=headers())
    assert response.status_code == 200, response.text
    purges = [payload["lifecycle"] for kind, payload in delivered if kind == "ekko_retention_purge"]
    assert purges == [{"state": "expired_removed", "removed": 1}]


def test_ekko_factory_finds_owned_work_and_respects_customer_decisions(context):
    import os
    from pathlib import Path

    client, world = context
    path = Path(os.environ["MAVERICK_CONFIG"])
    path.write_text(path.read_text() + '\n[ekko]\nenable=true\nbuild_enabled=true\n')
    config.reset_config_cache()
    seed(world, owner="user:alice", count=3)
    seed(world, owner="user:bob", count=4)
    options = client.get("/api/v1/ekko/build/options", headers=headers())
    assert options.status_code == 200, options.text
    body = {"context": options.json()["context"], "device_id": "local-device", "brief": ""}

    def scan():
        response = client.post("/api/v1/ekko/build/scan", headers=headers(), json=body)
        assert response.status_code == 200, response.text
        assert "CONFIDENTIAL" not in response.text and "PRIVATE-RESULT" not in response.text
        return response.json()

    found = scan()
    assert found["ready"] == 1
    assert found["proposals"][0]["source"] == "3 distinct requests in Lightwork"
    recommendation = get(client, "/opportunities")["opportunities"][0]
    decision_path = BASE + "/opportunities/" + recommendation["id"] + "/decision"
    refused = client.post(decision_path, headers=headers(), json={"revision": recommendation["revision"],
        "decision": "decline", "manual_steps": ["inputs", "review"]})
    assert refused.status_code == 200, refused.text
    assert scan()["ready"] == 0
    current = opportunities.RECOMMENDATIONS.get(recommendation["id"])
    reopened = client.post(decision_path, headers=headers(), json={"revision": current["revision"],
        "decision": "reopen", "manual_steps": ["inputs", "prepare", "review"]})
    assert reopened.status_code == 200, reopened.text
    assert scan()["ready"] == 0
