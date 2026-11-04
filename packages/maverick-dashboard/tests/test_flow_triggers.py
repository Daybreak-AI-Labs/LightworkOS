"""Flows as first-class trigger targets: an event trigger can fire a FLOW (not
just a template->goal), with the polled event's fields as the flow run's data."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "1")
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")


def _reset_aq(monkeypatch, aq):
    monkeypatch.setattr(aq, "_queue", None)
    monkeypatch.setattr(aq, "_worker", None)
    monkeypatch.setattr(aq, "_worker_threads", [])


def _save_flow(fid="onboard"):
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    saved = store.save_flow(Flow(
        id=fid,
        name="Onboard",
        start="a",
        nodes={
            "a": FlowNode(
                id="a",
                kind="agent",
                brief="welcome {{email}}",
            )
        },
    ))
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    return saved


def test_create_flow_target_trigger(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_flow()
    r = _client().post("/api/v1/event-triggers", json={
        "flow": "onboard", "source": "http_json", "config": {"url": "https://x"}})
    assert r.status_code == 201
    body = r.json()
    assert body["flow"] == "onboard" and body["template"] == ""


def test_exactly_one_target_required(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    # neither
    assert c.post("/api/v1/event-triggers", json={"source": "http_json"}).status_code == 400
    # both
    _save_flow()
    r = c.post("/api/v1/event-triggers", json={
        "template": "t", "flow": "onboard", "source": "http_json"})
    assert r.status_code == 400


def test_unknown_flow_is_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().post("/api/v1/event-triggers", json={
        "flow": "ghost", "source": "http_json", "config": {"url": "https://x"}})
    assert r.status_code == 404


def test_poll_fires_a_flow_run_with_event_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_flow()
    import maverick.automation_events as ev
    from maverick.flow import store as flow_store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    box = [{"items": [{"id": "1", "email": "a@b.com"}]}]
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: box[0])
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "flow": "onboard", "source": "http_json",
        "config": {"url": "https://x", "items_path": "items", "id_field": "id"}})
    c.post("/api/v1/event-triggers/poll")                       # baseline: nothing new
    draft = flow_store.load_flow("onboard")
    draft.nodes["a"].brief = "unpublished {{email}}"
    flow_store.save_flow(draft, expected_version=draft.version)
    box[0] = {"items": [{"id": "2", "email": "new@b.com"}, {"id": "1", "email": "a@b.com"}]}
    out = c.post("/api/v1/event-triggers/poll").json()
    # a flow run was queued for the new event
    fired = out["triggers"][0].get("fired_flows")
    assert fired and len(fired) == 1
    run = flow_store.load_run(fired[0])
    assert run.flow_id == "onboard"
    assert run.data.get("email") == "new@b.com"                # event field became flow data
    snapshot = flow_store.load_flow_snapshot(run.definition_digest)
    assert run.definition_version == 1
    assert snapshot.nodes["a"].brief == "welcome {{email}}"


def test_rss_source_published_flow_catalog_create_and_poll(monkeypatch, tmp_path):
    """The guided RSS-to-published-flow journey reaches the real event worker."""
    _isolate(monkeypatch, tmp_path)
    _save_flow()
    import maverick.automation_events as ev
    from maverick.flow import store as flow_store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    feed = ["<rss><channel><item><guid>one</guid><title>First</title></item></channel></rss>"]
    monkeypatch.setattr(ev, "_http_get_text", lambda *args, **kwargs: feed[0])
    c = _client()
    listed = c.get("/api/v1/flows")
    assert listed.status_code == 200, listed.text
    assert any(item["id"] == "onboard" and item["published"] for item in listed.json()["flows"])

    created = c.post("/api/v1/event-triggers", json={
        "name": "New posts", "flow": "onboard", "source": "rss",
        "config": {"url": "https://example.org/feed.xml"},
    })
    assert created.status_code == 201, created.text
    assert created.json()["flow"] == "onboard"
    first = c.post("/api/v1/event-triggers/poll").json()["triggers"][0]
    assert first["new_events"] == 0  # Initial check safely establishes a baseline.

    feed[0] = ("<rss><channel><item><guid>two</guid><title>Second</title></item>"
               "<item><guid>one</guid><title>First</title></item></channel></rss>")
    second = c.post("/api/v1/event-triggers/poll").json()["triggers"][0]
    assert second["new_events"] == 1
    assert len(second["fired_flows"]) == 1
    run = flow_store.load_run(second["fired_flows"][0])
    assert run.flow_id == "onboard"
    assert run.data["title"] == "Second"


def test_flow_fire_is_logged_in_history_with_run_ids(monkeypatch, tmp_path):
    # A flow fire records a FIRED history row carrying the flow run ids (not an
    # empty goal-id list), so the automations UI can show it fired.
    _isolate(monkeypatch, tmp_path)
    _save_flow()
    import maverick.automation_events as ev
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    box = [{"items": [{"id": "1", "email": "a@b.com"}]}]
    monkeypatch.setattr(ev, "_http_get_json", lambda url, headers=None, timeout=15.0: box[0])
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "flow": "onboard", "source": "http_json",
        "config": {"url": "https://x", "items_path": "items", "id_field": "id"}})
    c.post("/api/v1/event-triggers/poll")                       # baseline: item 1 seen
    box[0] = {"items": [{"id": "7", "email": "x@y.com"}, {"id": "1", "email": "a@b.com"}]}
    out = c.post("/api/v1/event-triggers/poll").json()
    run_ids = out["triggers"][0]["fired_flows"]
    assert len(run_ids) == 1
    hist = c.get("/api/v1/event-triggers/history").json()["history"]
    fired = [r for r in hist if r["kind"] == "fired"]
    assert fired and fired[0]["fired_flows"] == run_ids and fired[0]["fired"] == []


def test_deleted_flow_advances_cursor_not_wedged(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_flow()
    import maverick.automation_events as ev
    from maverick.flow import store as flow_store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(ev, "_http_get_json",
                        lambda url, headers=None, timeout=15.0: {"items": [{"id": "9"}]})
    c = _client()
    c.post("/api/v1/event-triggers", json={
        "flow": "onboard", "source": "http_json",
        "config": {"url": "https://x", "items_path": "items", "id_field": "id"}})
    flow_store.delete_flow("onboard")                          # target vanishes
    out = c.post("/api/v1/event-triggers/poll").json()
    assert out["triggers"][0]["fired_flows"] == []
    assert any("flow unavailable" in n for n in out["triggers"][0]["notes"])


def test_event_trigger_rejects_deleted_recreated_flow_binding(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _save_flow()
    import maverick.automation_events as ev
    from maverick.flow import store as flow_store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import event_triggers_store

    _reset_aq(monkeypatch, aq)
    box = [{"items": [{"id": "1", "email": "old@example.com"}]}]
    monkeypatch.setattr(
        ev, "_http_get_json", lambda *a, **k: box[0]
    )
    client = _client()
    assert client.post(
        "/api/v1/event-triggers",
        json={
            "name": "bound",
            "flow": "onboard",
            "source": "http_json",
            "config": {
                "url": "https://x",
                "items_path": "items",
                "id_field": "id",
            },
        },
    ).status_code == 201
    binding = event_triggers_store.get_trigger("bound")
    _published, release = flow_store.load_published_bundle("onboard")
    assert binding["flow_revision"] == release["release_id"]
    client.post("/api/v1/event-triggers/poll")  # establish cursor

    assert flow_store.delete_flow("onboard") is True
    replacement = flow_store.save_flow(Flow(
        id="onboard",
        name="Replacement",
        owner="user:bob",
        start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="replacement")},
    ))
    flow_store.publish_flow(
        replacement.id,
        expected_version=replacement.version,
        expected_revision=replacement.revision,
    )
    box[0] = {
        "items": [
            {"id": "2", "email": "new@example.com"},
            {"id": "1", "email": "old@example.com"},
        ]
    }

    result = client.post("/api/v1/event-triggers/poll").json()["triggers"][0]
    assert result["fired_flows"] == []
    assert result["notes"] == ["flow unavailable: binding is stale"]
    assert not [
        job for job in aq.queue().list(status="pending")
        if job.kind == aq.FLOW_RUN_KIND
    ]


def test_event_flow_queue_restores_trigger_tenant(monkeypatch, tmp_path):
    # A flow_run job enqueued under a tenant must load/execute/persist under
    # THAT tenant when the worker drains it later -- not whatever tenant the
    # worker thread happens to be scoped to (or the shared/no-tenant namespace).
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import rbac

    rbac.set_role("alice", "operator")
    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)

    observed = []

    def _fake_agent(world, **k):
        return lambda brief, d: (observed.append(brief) or brief, 1.0)

    monkeypatch.setattr(execution, "default_agent_runner", _fake_agent)
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs: (
                            lambda t, p, d: ("ok", 1.0)))

    shared = Flow(id="same", name="Shared", start="a",
                  nodes={"a": FlowNode(id="a", kind="agent", brief="shared {{secret}}")})
    tenant = Flow(id="same", name="Tenant", start="a",
                  nodes={"a": FlowNode(id="a", kind="agent", brief="tenant {{secret}}")})
    store.save_flow(shared)
    tok = set_tenant("tenant-a")
    try:
        saved_tenant = store.save_flow(tenant)
        store.publish_flow(
            saved_tenant.id,
            expected_version=saved_tenant.version,
            expected_revision=saved_tenant.revision,
        )
        run_id = aq.enqueue_flow_run("same", {"secret": "TENANT_DATA"}, owner="alice")
        jobs = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLOW_RUN_KIND]
        assert jobs[-1].payload["tenant"] == "tenant-a"
    finally:
        reset_tenant(tok)

    aq._handle_flow_run(jobs[-1])   # drained OUTSIDE tenant-a -- must restore it itself

    # Runtime prompts are now redacted before reaching the model-facing runner;
    # the tenant-specific definition still proves which namespace was loaded.
    assert observed == ["tenant ***redacted***"]
    assert store.load_run(run_id) is None   # not visible from the shared namespace
    tok = set_tenant("tenant-a")
    try:
        run = store.load_run(run_id)
        assert run is not None
        assert run.status == "completed"
        assert run.data["secret"] == "***redacted***"
    finally:
        reset_tenant(tok)
