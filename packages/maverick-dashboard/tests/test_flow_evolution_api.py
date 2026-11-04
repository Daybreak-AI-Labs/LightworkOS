"""Dashboard endpoints for the flow self-learning loop: apply a rewrite proposal,
walk version history + roll back, and read the before/after impact of an applied
change. Flow engine gated (enabled in the fixture)."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _save(c, fid="f"):
    return c.post("/api/v1/flows", json={"flow": {
        "id": fid, "name": "F", "start": "a",
        "nodes": [{"id": "a", "kind": "agent", "brief": "summarize {{x}}"}]}})


def _apply(c, body: dict, fid="f"):
    current = c.get(f"/api/v1/flows/{fid}").json()
    submitted = dict(body)
    if submitted.get("to_kind") == "action" and "params" not in submitted:
        # Test helpers model a human-reviewed no-argument binding explicitly.
        submitted["params"] = {}
    return c.post(f"/api/v1/flows/{fid}/apply", json={
        **submitted,
        "version": current["version"],
        "revision": current["revision"],
    })


def _rollback(c, body: dict, fid="f"):
    current = c.get(f"/api/v1/flows/{fid}").json()
    return c.post(f"/api/v1/flows/{fid}/rollback", json={
        **body,
        "current_version": current["version"],
        "revision": current["revision"],
    })


def test_auto_apply_leaves_a_failing_action_for_complete_review(monkeypatch, tmp_path):
    # Failure measurements do not supply complete replacement instructions.
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    monkeypatch.setattr("maverick.config.get_flows",
                        lambda: {"auto_evolve": True, "auto_apply": True})
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    store.save_flow(Flow(id="fa", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="action", tool="t", brief="do it")}))
    for _ in range(12):
        node_outcomes.record("fa", "a", "action", 0.0)      # it keeps failing
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    aq._handle_flow_evolve()
    assert store.load_flow("fa").nodes["a"].kind == "action"
    from maverick.flow import evolution_log, evolve
    assert evolution_log.last_apply("fa", "a") is None
    assert evolve.maybe_propose(store.load_flow("fa"))[0].to_kind == "agent"


def test_auto_apply_preserves_the_exact_active_release(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    monkeypatch.setattr(
        "maverick.config.get_flows",
        lambda: {"auto_evolve": True, "auto_apply": True},
    )
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    saved = store.save_flow(Flow(
        id="active-auto-apply",
        name="F",
        start="a",
        nodes={"a": FlowNode(id="a", kind="action", tool="web_search", brief="do it")},
    ))
    before = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    for _ in range(12):
        node_outcomes.record(saved.id, "a", "action", 0.0)

    aq._handle_flow_evolve()

    draft = store.load_flow(saved.id)
    active, after = store.load_published_bundle(saved.id)
    assert draft.nodes["a"].kind == "action"
    assert active.nodes["a"].kind == "action"
    assert after["release_id"] == before["release_id"]
    assert after["release_digest"] == before["release_digest"]


def test_auto_apply_skips_a_published_flow_with_diverged_human_draft(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    monkeypatch.setattr(
        "maverick.config.get_flows",
        lambda: {"auto_evolve": True, "auto_apply": True},
    )
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    saved = store.save_flow(Flow(
        id="diverged-auto-apply",
        name="Published",
        start="a",
        nodes={"a": FlowNode(id="a", kind="action", tool="web_search", brief="do it")},
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    saved.name = "Human draft"
    diverged = store.save_flow(
        saved,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    for _ in range(12):
        node_outcomes.record(saved.id, "a", "action", 0.0)

    aq._handle_flow_evolve()

    draft = store.load_flow(saved.id)
    active, still_live = store.load_published_bundle(saved.id)
    assert draft.version == diverged.version
    assert draft.name == "Human draft" and draft.nodes["a"].kind == "action"
    assert active.name == "Published" and active.nodes["a"].kind == "action"
    assert still_live["release_id"] == release["release_id"]


def test_auto_apply_leaves_reliable_one_tool_agent_for_human_review(monkeypatch, tmp_path):
    # HARDEN proposals are model-influenced because their tool comes from captured
    # agent behavior, so auto-apply must leave them for human review even when a
    # single tool was inferred confidently.
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    monkeypatch.setattr("maverick.config.get_flows",
                        lambda: {"auto_evolve": True, "auto_apply": True})
    from maverick.flow import node_outcomes, node_tools, store
    from maverick.flow.ir import Flow, FlowNode
    store.save_flow(Flow(id="fh", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="agent", brief="summarize it")}))
    for _ in range(20):
        node_outcomes.record("fh", "a", "agent", 1.0)     # reliably succeeds
    for _ in range(6):
        node_tools.record("fh", "a", ["summarize_tool"])  # always the same one tool
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    aq._handle_flow_evolve()
    hardened = store.load_flow("fh").nodes["a"]
    assert hardened.kind == "agent" and not hardened.tool


def test_auto_apply_leaves_a_reliable_agent_alone_without_an_inferred_tool(monkeypatch, tmp_path):
    # No captured tool -> hardening still needs a human to pick one; the loop must
    # NOT guess, so a reliable agent node with no tool signal is left untouched.
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    monkeypatch.setattr("maverick.config.get_flows",
                        lambda: {"auto_evolve": True, "auto_apply": True})
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    store.save_flow(Flow(id="fn", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="agent", brief="summarize it")}))
    for _ in range(20):
        node_outcomes.record("fn", "a", "agent", 1.0)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    aq._handle_flow_evolve()
    assert store.load_flow("fn").nodes["a"].kind == "agent"   # untouched


def test_auto_apply_off_by_default_leaves_the_flow_alone(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")           # auto_evolve on, auto_apply OFF
    monkeypatch.setattr("maverick.config.get_flows", lambda: {"auto_evolve": True})
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    store.save_flow(Flow(id="fb", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="action", tool="t", brief="do it")}))
    for _ in range(12):
        node_outcomes.record("fb", "a", "action", 0.0)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    aq._handle_flow_evolve()
    assert store.load_flow("fb").nodes["a"].kind == "action"  # untouched


def test_apply_hardens_agent_to_action_and_bumps_version(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    assert _save(c).status_code == 201
    r = _apply(c, {"node_id": "a", "to_kind": "action", "tool": "web_search"})
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == 2 and body["from_kind"] == "agent" and body["to_kind"] == "action"
    node_a = next(n for n in c.get("/api/v1/flows/f").json()["nodes"] if n["id"] == "a")
    assert node_a["kind"] == "action" and node_a["tool"] == "web_search"


def test_hardening_review_uses_live_action_contract_and_current_flow_inputs(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import evolve, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import api

    saved = store.save_flow(Flow(
        id="review", name="Customer lookup", start="agent",
        inputs=[{"key": "customer", "label": "Customer name", "type": "text"}],
        nodes={"agent": FlowNode(id="agent", kind="agent", brief="Look up a customer",
                                 label="Look up customer")},
    ))
    monkeypatch.setattr(evolve, "maybe_propose", lambda _flow: [evolve.NodeProposal(
        "agent", "agent", "action", "Past successful runs used one action", 12, 1.0,
        inferred_tool="web_search", applicable=False,
        blocking_reason="parameters need review",
    )])
    monkeypatch.setattr(api, "_TOOL_INDEX_CACHE", [
        {"name": "web_search", "description": "Search public pages", "params": ["query"]},
    ])
    monkeypatch.setattr(api, "_TOOL_SCHEMA_CACHE", {
        "web_search": {"type": "object", "properties": {
            "query": {"type": "string", "description": "What to search for"},
        }, "required": ["query"]},
    })
    client = _client()
    response = client.get("/api/v1/flows/review/apply-review?node_id=agent")
    assert response.status_code == 200, response.text
    review = response.json()
    assert (review["version"], review["revision"]) == (saved.version, saved.revision)
    assert review["tool"] == "web_search"
    assert review["fields"] == [{"name": "query", "label": "Query", "type": "string",
                                 "required": True, "description": "What to search for"}]
    assert review["sources"] == [{"key": "customer", "label": "Customer name", "origin": "input"}]
    assert store.load_flow("review").version == saved.version
    monkeypatch.setattr(api, "_TOOL_INDEX_CACHE", [])
    unavailable = client.get("/api/v1/flows/review/apply-review?node_id=agent")
    assert unavailable.status_code == 200 and unavailable.json()["tool"] == ""
    unavailable_choice = client.get(
        "/api/v1/flows/review/apply-review?node_id=agent&tool=web_search",
    )
    assert unavailable_choice.status_code == 409
    assert store.load_flow("review").nodes["agent"].kind == "agent"


def test_apply_refuses_action_to_agent_without_replacement_review(monkeypatch, tmp_path):
    # A node label is not evidence for the replacement work instructions.
    _isolate(monkeypatch, tmp_path)
    c = _client()
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    store.save_flow(Flow(id="f", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="action", tool="t",
                                              label="reconcile the ledger")}))
    r = _apply(c, {"node_id": "a", "to_kind": "agent"})
    assert r.status_code == 409
    node_a = next(n for n in c.get("/api/v1/flows/f").json()["nodes"] if n["id"] == "a")
    assert node_a["kind"] == "action" and node_a["tool"] == "t"
    assert not node_a.get("brief")


def test_apply_without_tool_is_400(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    assert _apply(c, {"node_id": "a", "to_kind": "action"}).status_code == 400


def test_apply_tool_name_without_parameter_binding_is_400(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    current = c.get("/api/v1/flows/f").json()
    response = c.post("/api/v1/flows/f/apply", json={
        "node_id": "a",
        "to_kind": "action",
        "tool": "web_search",
        "version": current["version"],
        "revision": current["revision"],
    })
    assert response.status_code == 400
    assert "parameter bindings" in response.json()["detail"]


def test_apply_noop_same_kind_is_400(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    assert _apply(c, {"node_id": "a", "to_kind": "agent"}).status_code == 400


def test_apply_unknown_node_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    assert _apply(c, {"node_id": "zzz", "to_kind": "action", "tool": "t"}).status_code == 404


def test_apply_unknown_flow_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    assert _client().post("/api/v1/flows/ghost/apply",
                          json={"node_id": "a", "to_kind": "action", "tool": "t"}).status_code == 404


def test_versions_and_rollback(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)                                                          # v1 (agent)
    _apply(c, {"node_id": "a", "to_kind": "action", "tool": "web_search"})  # v2 (action)
    versions = c.get("/api/v1/flows/f/versions").json()["versions"]
    assert [v["version"] for v in versions] == [2, 1]                 # newest first
    rb = _rollback(c, {})                                             # -> v3, agent again
    assert rb.status_code == 200 and rb.json()["version"] == 3
    node_a = next(n for n in c.get("/api/v1/flows/f").json()["nodes"] if n["id"] == "a")
    assert node_a["kind"] == "agent"


def test_rollback_unknown_version_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    assert _rollback(c, {"version": 99}).status_code == 404


def test_apply_and_rollback_reject_stale_editor_tokens(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    created = c.post("/api/v1/flows", json={"flow": {
        "id": "f", "name": "F", "start": "a",
        "nodes": [{"id": "a", "kind": "action", "tool": "web_search"}],
    }})
    assert created.status_code == 201
    stale = c.get("/api/v1/flows/f").json()
    winner = {**stale, "name": "human edit"}
    assert c.post("/api/v1/flows", json={"flow": winner}).status_code == 201

    apply = c.post("/api/v1/flows/f/apply", json={
        "node_id": "a", "to_kind": "agent", "brief": "read it",
        "version": stale["version"], "revision": stale["revision"],
    })
    rollback = c.post("/api/v1/flows/f/rollback", json={
        "version": 1,
        "current_version": stale["version"],
        "revision": stale["revision"],
    })
    assert apply.status_code == 409
    assert rollback.status_code == 409
    assert c.get("/api/v1/flows/f").json()["name"] == "human edit"


def test_impact_reports_before_after_once_applied(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    from maverick.flow import node_outcomes
    node_outcomes.record("f", "a", "agent", 0.4)             # before the change
    node_outcomes.record("f", "a", "agent", 0.5)
    assert _apply(c, {
        "node_id": "a", "to_kind": "action", "tool": "web_search",
    }).status_code == 200
    node_outcomes.record("f", "a", "action", 1.0)            # after the change
    body = c.get("/api/v1/flows/f/nodes/a/impact").json()
    assert body["changed"] is True and body["applied"]["to_kind"] == "action"
    imp = body["impact"]
    assert imp["before"]["n"] + imp["after"]["n"] == 3       # all outcomes accounted for


def test_signals_surfaces_approval_and_trigger_stats(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    c.post("/api/v1/flows", json={"flow": {
        "id": "s", "name": "S", "start": "g",
        "nodes": [{"id": "g", "kind": "approval", "prompt": "ok?", "label": "gate"}]}})
    from maverick.flow import execution, node_outcomes
    node_outcomes.record("s", "g", "approval", 1.0)          # approved
    node_outcomes.record("s", "g", "approval", 0.0)          # rejected
    node_outcomes.record("s", execution.TRIGGER_NODE, "trigger", 1.0)
    node_outcomes.record("s", execution.TRIGGER_NODE, "trigger", 1.0)
    body = c.get("/api/v1/flows/s/signals").json()
    assert body["nodes"]["g"]["mean"] == 0.5 and body["nodes"]["g"]["kind"] == "approval"
    assert body["nodes"]["g"]["label"] == "gate"
    assert body["trigger"]["n"] == 2 and body["trigger"]["mean"] == 1.0
    # the reserved trigger node is not listed among the flow's own nodes
    assert execution.TRIGGER_NODE not in body["nodes"]


def test_signals_unknown_flow_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    assert _client().get("/api/v1/flows/ghost/signals").status_code == 404


def test_signals_are_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import api as api_mod

    store.save_flow(Flow(
        id="alice-flow", name="Alice", start="g", owner="user:alice",
        nodes={"g": FlowNode(id="g", kind="approval", prompt="ok?", label="gate")},
    ))
    node_outcomes.record("alice-flow", "g", "approval", 1.0)
    monkeypatch.setattr(api_mod, "caller_principal", lambda request: "user:bob")
    monkeypatch.setattr(api_mod, "is_dashboard_admin", lambda principal: False)
    monkeypatch.setattr(api_mod, "require_permission", lambda request, permission: None)

    assert _client().get("/api/v1/flows/alice-flow/signals").status_code == 404


def test_all_learning_and_history_surfaces_are_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import api as api_mod

    saved = store.save_flow(Flow(
        id="alice-private", name="private", start="a", owner="user:alice",
        nodes={"a": FlowNode(id="a", kind="agent", brief="private work")},
    ))
    monkeypatch.setattr(api_mod, "caller_principal", lambda request: "user:bob")
    monkeypatch.setattr(api_mod, "is_dashboard_admin", lambda principal: False)
    monkeypatch.setattr(api_mod, "require_permission", lambda request, permission: None)
    c = _client()

    assert c.get("/api/v1/flows/alice-private/proposals").status_code == 404
    assert c.get("/api/v1/flows/alice-private/versions").status_code == 404
    assert c.get("/api/v1/flows/alice-private/nodes/a/impact").status_code == 404
    assert c.post("/api/v1/flows/alice-private/apply", json={
        "node_id": "a", "to_kind": "action", "tool": "read_file",
        "version": saved.version, "revision": saved.revision,
    }).status_code == 404
    assert c.post("/api/v1/flows/alice-private/rollback", json={
        "current_version": saved.version, "revision": saved.revision,
    }).status_code == 404
    assert all(
        item["flow_id"] != "alice-private"
        for item in c.get("/api/v1/flows/insights").json()["flows"]
    )


def test_impact_unchanged_node(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    r = c.get("/api/v1/flows/f/nodes/a/impact")
    assert r.status_code == 200 and r.json()["changed"] is False


def test_insights_surfaces_applied_changes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    _save(c)
    assert _apply(c, {
        "node_id": "a", "to_kind": "action", "tool": "web_search",
    }).status_code == 200
    body = c.get("/api/v1/flows/insights").json()
    flow = next(fl for fl in body["flows"] if fl["flow_id"] == "f")
    assert flow["changes"] and flow["changes"][0]["to_kind"] == "action"


def _build_regressed_scenario():
    # A hardened (agent->action) node whose grounded outcomes then regressed.
    from maverick.flow import Flow, FlowNode, evolution_log, evolve, node_outcomes, store
    store.save_flow(Flow(id="f", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="agent", brief="summarize")}))
    for _ in range(4):
        node_outcomes.record("f", "a", "agent", 0.9)        # worked well as an agent
    saved = store.save_flow(evolve.apply_proposal(
        store.load_flow("f"), "a", "action", tool="web_search", params={}))
    evolution_log.record_apply("f", "a", "agent", "action", saved.version, source="manual")
    for _ in range(6):
        node_outcomes.record("f", "a", "action", 0.2)        # regressed as an action


def test_evolve_pass_reverts_a_regression_when_enabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    from maverick.flow import evolution_log, store
    from maverick_dashboard import automation_queue as aq
    _build_regressed_scenario()
    aq._handle_flow_evolve()
    assert store.load_flow("f").nodes["a"].kind == "agent"          # undone
    assert evolution_log.last_apply("f", "a")["source"] == "auto-revert"


def test_auto_revert_replaces_the_exact_active_release(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _build_regressed_scenario()
    current = store.load_flow("f")
    before = store.publish_flow(
        current.id,
        expected_version=current.version,
        expected_revision=current.revision,
    )

    aq._handle_flow_evolve()

    draft = store.load_flow("f")
    active, after = store.load_published_bundle("f")
    assert draft.nodes["a"].kind == "agent"
    assert active.nodes["a"].kind == "agent"
    assert after["release_id"] != before["release_id"]
    assert after["release_digest"] != before["release_digest"]


def test_autonomous_publish_cas_refuses_a_rearmed_activation(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import evolve, store
    from maverick.flow.ir import Flow, FlowNode

    saved = store.save_flow(Flow(
        id="evolve-activation-race",
        name="F",
        start="a",
        nodes={"a": FlowNode(id="a", kind="action", tool="web_search", brief="do it")},
    ))
    old = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    assert store.unpublish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    replacement = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    candidate = evolve.apply_proposal(saved, "a", "agent", brief="do it")

    import pytest

    with pytest.raises(store.FlowSnapshotError, match="activation"):
        store.save_and_publish_flow(
            candidate,
            expected_version=saved.version,
            expected_revision=saved.revision,
            expected_release_id=old["release_id"],
        )
    assert store.load_flow(saved.id).nodes["a"].kind == "action"
    assert store.load_published_bundle(saved.id)[1]["release_id"] == replacement["release_id"]


def test_evolve_pass_visits_two_tenants_without_crossing_namespaces(
    monkeypatch, tmp_path,
):
    from types import SimpleNamespace

    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    monkeypatch.setattr("maverick.config.get_flows", lambda: {"auto_apply": True})
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    tenants = [
        SimpleNamespace(id="acme", active=True),
        SimpleNamespace(id="globex", active=True),
    ]
    monkeypatch.setattr("maverick.tenant.registry.list_tenants", lambda: tenants)
    monkeypatch.setattr("maverick.tenant.registry.assert_tenant_active", lambda _t: None)

    from maverick.flow import evolution_log, store
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick_dashboard import automation_queue as aq

    auto_apply_scopes = []
    monkeypatch.setattr(
        aq, "_auto_apply_proposals",
        lambda: auto_apply_scopes.append(current_tenant_id() or ""),
    )

    # Deliberately reuse the same flow/node ids: each tenant's definition,
    # outcomes and evolution log must resolve only inside its pinned namespace.
    for tenant in ("acme", "globex"):
        token = set_tenant(tenant)
        try:
            _build_regressed_scenario()
        finally:
            reset_tenant(token)

    ambient = set_tenant("ambient-poison")
    try:
        aq._handle_flow_evolve()
        assert current_tenant_id() == "ambient-poison"
    finally:
        reset_tenant(ambient)

    assert store.load_flow("f") is None  # shared namespace was not contaminated
    assert auto_apply_scopes == ["", "acme", "globex"]
    for tenant in ("acme", "globex"):
        token = set_tenant(tenant)
        try:
            assert store.load_flow("f").nodes["a"].kind == "agent"
            assert evolution_log.last_apply("f", "a")["source"] == "auto-revert"
        finally:
            reset_tenant(token)


def test_evolve_pass_skips_stale_apply_after_manual_save(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    from maverick.flow import evolve, store
    from maverick_dashboard import automation_queue as aq
    _build_regressed_scenario()
    edited = evolve.apply_proposal(
        store.load_flow("f"), "a", "action", tool="safe_tool", params={},
    )
    store.save_flow(edited)
    aq._handle_flow_evolve()
    node = store.load_flow("f").nodes["a"]
    assert node.kind == "action"
    assert node.tool == "safe_tool"


def test_evolve_pass_reverts_regression_across_later_unrelated_save(
    monkeypatch, tmp_path,
):
    """The apply's explicit cohorts survive a later metadata-only draft save."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_FLOWS_AUTO", "1")
    from maverick.flow import evolution_log, store
    from maverick_dashboard import automation_queue as aq

    _build_regressed_scenario()  # v2 is the regressed agent -> action apply
    later = store.load_flow("f")
    later.name = "human renamed this after the apply"
    store.save_flow(
        later,
        expected_version=later.version,
        expected_revision=later.revision,
    )  # v3 keeps the applied work definition

    aq._handle_flow_evolve()

    current = store.load_flow("f")
    assert current.version == 4
    assert current.name == "human renamed this after the apply"
    assert current.nodes["a"].kind == "agent"
    last = evolution_log.last_apply("f", "a")
    assert last["source"] == "auto-revert"
    assert last["before_revision"].endswith(":v3")
    assert last["after_revision"].endswith(":v4")


def test_evolve_pass_is_a_noop_when_disabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_FLOWS_AUTO", raising=False)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _build_regressed_scenario()
    aq._handle_flow_evolve()
    assert store.load_flow("f").nodes["a"].kind == "action"         # left alone


def test_notify_flow_pushes_when_enabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow
    from maverick.flow.store import FlowRun
    from maverick_dashboard import automation_queue as aq
    sent = []
    monkeypatch.setattr("maverick.notifications.notify",
                        lambda body, **k: (sent.append((body, k.get("priority"))), 1)[1])
    flow = Flow(id="f", name="Payout", start="a", nodes={}, notify=True)
    aq._notify_flow(flow, FlowRun(run_id="r", flow_id="f", status="paused_approval", prompt="ok?"))
    assert sent and "Payout" in sent[0][0] and sent[0][1] == "high"


def test_notify_flow_silent_when_disabled(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow
    from maverick.flow.store import FlowRun
    from maverick_dashboard import automation_queue as aq
    sent = []
    monkeypatch.setattr("maverick.notifications.notify", lambda body, **k: sent.append(body) or 1)
    aq._notify_flow(Flow(id="f", name="X", start="a", nodes={}, notify=False),
                    FlowRun(run_id="r", flow_id="f", status="completed"))
    assert sent == []                                       # opt-in: no notify by default


def test_dry_run_handler_completes_without_grounding(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow, FlowNode, node_outcomes, store
    from maverick_dashboard import automation_queue as aq
    store.save_flow(Flow(id="f", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="agent", brief="x")}))
    rid = store.new_run_id()
    digest, version, subflows = store.snapshot_current_flow_bundle("f")
    store.save_run(store.FlowRun(
        run_id=rid, flow_id="f", status="queued", dry_run=True,
        definition_digest=digest, definition_version=version,
        subflow_digests=subflows))

    class _Job:
        # Delivery payload lies; the durable reservation remains authoritative.
        payload = {"flow_id": "f", "run_id": rid, "data": {}, "dry_run": False}
    aq._handle_flow_run(_Job())
    assert store.load_run(rid).status == "completed"
    assert store.load_run(rid).dry_run is True
    assert node_outcomes.stats("f") == {}              # dry run grounded nothing


def test_dry_run_resume_never_upgrades_to_real_executors(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow, FlowNode, execution, node_outcomes, store
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import rbac

    rbac.set_role("user:alice", "operator")

    flow = Flow(id="dry-pause", name="dry", start="gate", nodes={
        "gate": FlowNode(id="gate", kind="approval", prompt="continue?", next="read"),
        "read": FlowNode(id="read", kind="action", tool="web_search"),
    })
    store.save_flow(flow)
    rid = store.new_run_id()
    digest, version, subflows = store.snapshot_current_flow_bundle(flow.id)
    store.save_run(store.FlowRun(
        run_id=rid, flow_id=flow.id, status="queued", dry_run=True,
        owner="user:alice", input_data={"path": "sample.txt"},
        definition_digest=digest, definition_version=version,
        subflow_digests=subflows,
    ))
    sandbox_calls = []

    def _sandbox():
        return (
            lambda brief, data: ("mock-agent", 1.0),
            lambda tool, params, data: (sandbox_calls.append(tool) or "mock", 1.0),
        )

    monkeypatch.setattr(execution, "sandbox_runners", _sandbox)
    monkeypatch.setattr(
        aq, "_flow_runners",
        lambda owner: (_ for _ in ()).throw(AssertionError("real runner selected")),
    )

    class _Job:
        def __init__(self, payload):
            self.payload = payload

    aq._handle_flow_run(_Job({
        "flow_id": flow.id, "run_id": rid, "dry_run": False,
        "owner": "user:attacker", "data": {"path": "production.txt"},
    }))
    paused = store.load_run(rid)
    assert paused.status == "paused_approval"

    # A resume is only honoured when it answers this exact pause with an
    # authenticated decision; the attacker's payload still asks for a real run.
    from maverick.flow.approvals import (
        flow_decision_attestation_material,
        paused_operation_binding,
    )
    from maverick_dashboard.approval_authority import issue_flow_decision_attestation

    authority_binding = aq.flow_approval_binding(paused)
    material = flow_decision_attestation_material(
        paused,
        inputs={},
        operation_binding_sha256=paused_operation_binding(paused, inputs={}),
        authority_binding_sha256=authority_binding,
        decision="approved",
        decided_by="system:test",
    )
    attestation = issue_flow_decision_attestation(
        None,
        material=material,
        expires_at=float(paused.human["approval_card"]["expires_at"]),
    )
    aq._handle_flow_resume(_Job({
        "flow_id": flow.id, "run_id": rid, "decision": "approved",
        "decided_by": "system:test",
        "approval_binding_sha256": authority_binding,
        "approval_decision_attestation": attestation,
        "dry_run": False, "owner": "user:attacker",
    }))
    done = store.load_run(rid)
    assert done.status == "completed" and done.dry_run is True
    assert sandbox_calls == ["web_search"]
    assert node_outcomes.stats(flow.id) == {}


def test_run_api_redacts_secrets_in_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    rid = store.new_run_id()
    secret = "ghp_" + "R" * 36  # pragma: allowlist secret
    store.save_run(store.FlowRun(run_id=rid, flow_id="f", status="completed",
                                 data={"api_key": "sk-secret", "user": "ada",  # pragma: allowlist secret
                                       "result": f"Bearer {secret}"}))  # pragma: allowlist secret
    got = _client().get("/api/v1/flows/runs/" + rid).json()
    assert got["data"]["api_key"] == "***redacted***" and got["data"]["user"] == "ada"
    assert secret not in got["data"]["result"]


def test_run_api_redacts_secrets_in_input_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    rid = store.new_run_id()
    store.save_run(store.FlowRun(run_id=rid, flow_id="f", status="completed",
                                 data={"ok": True},
                                 input_data={
                                     "access_token": "tok_INPUT_SECRET_123",
                                     "Authorization": "Bearer INPUT_AUTH_SECRET",
                                     "user": "ada",
                                 }))  # pragma: allowlist secret
    got = _client().get("/api/v1/flows/runs/" + rid).json()
    assert got["input_data"]["access_token"] == "***redacted***"
    assert got["input_data"]["Authorization"] == "***redacted***"
    assert got["input_data"]["user"] == "ada"


def test_enqueue_flow_run_dedups_on_idem_key(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow, FlowNode, store
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    store.save_flow(Flow(id="f", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="agent", brief="x")}))
    r1 = aq.enqueue_flow_run("f", {"k": 1}, "", "evt:1")
    r2 = aq.enqueue_flow_run("f", {"k": 1}, "", "evt:1")     # same event -> dedup to r1
    r3 = aq.enqueue_flow_run("f", {"k": 1}, "", "evt:2")     # different event -> new run
    assert r1 == r2 and r3 != r1


def test_retry_reruns_from_original_inputs(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow, FlowNode, store
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    saved = store.save_flow(Flow(
        id="f",
        name="F",
        start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="x")},
    ))
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    rid = store.new_run_id()
    store.save_run(store.FlowRun(run_id=rid, flow_id="f", status="failed",
                                 input_data={"order": "A1"}, data={"order": "A1", "junk": "z"}))
    r = _client().post("/api/v1/flows/runs/" + rid + "/retry")
    assert r.status_code == 200 and r.json()["retried_from"] == rid
    new = store.load_run(r.json()["run_id"])
    assert new.run_id != rid and new.input_data == {"order": "A1"}   # original inputs, not mutated data
    assert new.definition_digest and new.definition_revision


def test_retry_rejects_a_partially_pinned_legacy_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow, FlowNode, store
    from maverick_dashboard import automation_queue as aq

    monkeypatch.setattr(aq, "_queue", None)
    store.save_flow(Flow(id="f", name="F", start="a",
                         nodes={"a": FlowNode(id="a", kind="agent", brief="x")}))
    rid = store.new_run_id()
    store.save_run(store.FlowRun(
        run_id=rid,
        flow_id="f",
        status="failed",
        input_data={"order": "A1"},
        definition_digest="0" * 64,
    ))

    r = _client().post("/api/v1/flows/runs/" + rid + "/retry")

    assert r.status_code == 409
    assert "definition has changed" in r.json()["detail"]


def test_retry_of_active_run_is_409(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    rid = store.new_run_id()
    store.save_run(store.FlowRun(run_id=rid, flow_id="f", status="paused_approval"))
    assert _client().post("/api/v1/flows/runs/" + rid + "/retry").status_code == 409


def test_tools_catalog_lists_connectors_with_metadata(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/api/v1/flows/tools")
    assert r.status_code == 200
    tools = r.json()["tools"]
    names = [t["name"] for t in tools]
    assert "slack_bot" in names and "github_issues" in names
    for t in tools:                       # every entry carries the picker's fields
        assert "description" in t and isinstance(t.get("params"), list)
