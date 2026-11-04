"""Signed approval links bind a pause token to an authenticated approver."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    # follow_redirects off so we assert on each page directly
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.setenv("MAVERICK_FLOW_APPROVAL_SECRET", "link-secret")  # pragma: allowlist secret
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    from maverick_dashboard import rbac
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    rbac.set_role("user:alice", "operator")


def _as_actor(monkeypatch, principal="user:alice"):
    import importlib

    app_module = importlib.import_module("maverick_dashboard.app")
    auth_module = importlib.import_module("maverick_dashboard.auth")
    monkeypatch.setattr(app_module, "caller_principal", lambda _request: principal)
    monkeypatch.setattr(auth_module, "caller_principal", lambda _request: principal)


def _paused_run(rid="r1", fid="f1", *, owner="user:alice", assignee="@alice"):
    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    saved = store.save_flow(Flow(
        id=fid,
        name="F",
        start="a",
        owner=owner,
        nodes={"a": FlowNode(
            id="a", kind="approval", prompt="ok?", assignee=assignee,
        )},
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    store.save_run(store.FlowRun(
        run_id=rid,
        flow_id=fid,
        status="queued",
        owner=owner,
        input_data={},
        definition_digest=release["definition_digest"],
        release_digest=release["release_digest"],
        release_id=release["release_id"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))
    paused = execution.execute(
        saved,
        agent_runner=lambda *args: ("unused", 1.0),
        action_runner=lambda *args: ("unused", 1.0),
        run_id=rid,
        owner=owner,
        record_outcomes=True,
    )
    assert paused.status == "paused_approval"
    return rid, fid


def _tok(rid, decision):
    from maverick.flow import store
    from maverick.flow.approvals import mint_token
    from maverick_dashboard import automation_queue as aq
    run = store.load_run(rid)
    return mint_token(rid, decision, cursor=run.cursor, prompt=run.prompt,
                      updated=run.updated,
                      assignee=str((run.human or {}).get("assignee") or ""),
                      owner=run.owner,
                      binding_sha256=aq.flow_approval_binding(run))


def test_get_shows_confirm_page_without_resuming(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    _as_actor(monkeypatch)
    rid, _ = _paused_run()
    r = _client().get("/flow/approve", params={"token": _tok(rid, "approved")})
    assert r.status_code == 200
    assert "Confirm exact operation" in r.text
    assert "Known effects" in r.text
    assert "Unresolved assumptions" in r.text
    assert "prediction does not grant authority" in r.text
    # the GET must NOT have enqueued a resume (defeats link prefetchers)
    from maverick.flow import store
    assert store.load_run(rid).status == "paused_approval"


def test_post_resumes_the_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    _as_actor(monkeypatch)
    rid, fid = _paused_run()
    tok = _tok(rid, "approved")
    r = _client().post("/flow/approve", data={"token": tok})
    assert r.status_code == 200 and "recorded" in r.text.lower()
    # a resume job was enqueued carrying the decision
    jobs = [j for j in aq.queue().list(status="pending", limit=100)
            if j.kind == aq.FLOW_RESUME_KIND]
    assert len(jobs) == 1
    assert jobs[0].payload["run_id"] == rid and jobs[0].payload["decision"] == "approved"
    assert jobs[0].payload["decided_by"] == "user:alice"

    aq._handle_flow_resume(jobs[0])
    from maverick.flow import store
    assert store.load_run(rid).decided_by == "user:alice"


def test_invalid_token_is_rejected(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/flow/approve", params={"token": "bogus.deadbeef"})
    assert r.status_code == 410
    assert "invalid or has expired" in r.text


def test_post_on_already_resolved_run_is_noop(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    _as_actor(monkeypatch)
    rid, fid = _paused_run()
    from maverick.flow import store
    run = store.load_run(rid)
    run.status = "completed"
    store.save_run(run)
    r = _client().post("/flow/approve", data={"token": _tok(rid, "approved")})
    assert r.status_code == 410 and "no longer awaiting approval" in r.text
    jobs = [j for j in aq.queue().list(status="pending", limit=100)
            if j.kind == aq.FLOW_RESUME_KIND]
    assert jobs == []


def test_old_link_cannot_resolve_later_approval(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    _as_actor(monkeypatch)
    rid, _ = _paused_run()
    old = _tok(rid, "approved")
    from maverick.flow import store
    run = store.load_run(rid)
    run.cursor = "b"
    run.prompt = "second approval?"
    store.save_run(run)
    r = _client().post("/flow/approve", data={"token": old})
    assert r.status_code == 410 and "older approval step" in r.text
    jobs = [j for j in aq.queue().list(status="pending", limit=100)
            if j.kind == aq.FLOW_RESUME_KIND]
    assert jobs == []


def test_anonymous_bearer_link_cannot_decide(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    rid, _ = _paused_run()

    response = _client().post(
        "/flow/approve", data={"token": _tok(rid, "approved")},
    )

    assert response.status_code == 403
    assert aq.queue().list(status="pending", limit=100) == []


def test_forwarded_link_is_refused_for_the_wrong_assignee(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq
    monkeypatch.setattr(aq, "_queue", None)
    from maverick_dashboard import rbac
    rbac.set_role("user:bob", "operator")
    _as_actor(monkeypatch, "user:bob")
    rid, _ = _paused_run()

    response = _client().post(
        "/flow/approve", data={"token": _tok(rid, "approved")},
    )

    assert response.status_code == 403
    assert "assigned" in response.text
    assert aq.queue().list(status="pending", limit=100) == []
