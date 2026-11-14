"""Dashboard flow surface: CRUD + validation, the durable run/resume path through
the automation queue, owner-scoped runs, and self-rewrite proposals. Flow engine
gated (off by default)."""
from __future__ import annotations

import time

import pytest
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


def _reset_aq(monkeypatch, aq):
    monkeypatch.setattr(aq, "_queue", None)
    monkeypatch.setattr(aq, "_worker", None)
    monkeypatch.setattr(aq, "_worker_threads", [])


def _drain(aq):
    # A worker with the flow handlers registered (as automation_queue.start would).
    from maverick.worker import Worker
    w = Worker(queue=aq.queue())
    w.register(aq.FLOW_RUN_KIND, aq._handle_flow_run)
    w.register(aq.FLOW_RESUME_KIND, aq._handle_flow_resume)
    w.drain()


def _publish(client, flow_id: str) -> dict:
    current = client.get(f"/api/v1/flows/{flow_id}")
    assert current.status_code == 200, current.text
    body = current.json()
    response = client.post(f"/api/v1/flows/{flow_id}/publish", json={
        "version": body["version"],
        "revision": body["revision"],
    })
    assert response.status_code == 200, response.text
    return response.json()


def _attach_test_approval_card(run_id: str) -> str:
    """Modernize a hand-built paused-run fixture and return its review binding."""
    from maverick.approval_cards import build_approval_card, digest
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    run = store.load_run(run_id)
    assert run is not None and run.status == "paused_approval"
    flow = store.load_flow_snapshot(run.definition_digest)
    paused = flow.node(run.cursor)
    assert paused is not None and paused.kind == "approval"
    next_node = flow.node(paused.next) if paused.next else None
    continuation = (
        next_node.to_dict()
        if next_node is not None
        else {"kind": "complete", "id": "end"}
    )
    human = dict(run.human or {})
    human.setdefault("choices", [])
    human.setdefault("assignee", "")
    human.setdefault("form", [])
    human["approval_card"] = build_approval_card(
        action="flow.resume",
        summary=run.prompt or f"Resume {run.flow_id}",
        target_label=f"continue flow {run.flow_id}",
        target={
            "flow_id": run.flow_id,
            "pause_node": paused.id,
            "continuation": continuation,
        },
        parameters={"data": run.data or {}, "continuation": continuation},
        parameter_summary=[f"Continue after {run.cursor or 'the current pause'}"],
        actor=run.owner or "local:dashboard",
        workspace="local",
        role="flow-execution-owner",
        authority_versions={
            "definition_digest": run.definition_digest,
            "release_digest": run.release_digest,
            "release_id": run.release_id,
            "execution_principal_sha256": digest(
                run.execution_user_id or run.owner or "local:operator"
            ),
            "allowed_suites_sha256": digest(run.allowed_suites),
        },
        input_versions={
            "run_data_sha256": digest(run.data or {}),
            "definition_revision": run.definition_revision,
        },
        credential_versions={"resolution": "worker-dispatch"},
        budget={"currency": "USD", "maximum": "configured runtime limit"},
        expires_at=(
            float(run.resume_at) if run.resume_at is not None else time.time() + 300
        ),
        known_effects=["Runs the reviewed immutable continuation once."],
        unresolved_assumptions=["Current connector authority remains valid."],
        before="The run remains paused.",
        after="The reviewed continuation may execute once.",
        irreversible=True,
    )
    run.human = human
    store.save_run(run)
    return aq.flow_approval_binding(store.load_run(run_id))


def _approval_resume_body(client, run_id: str, decision: str, **extra) -> dict:
    current = client.get(f"/api/v1/flows/runs/{run_id}")
    assert current.status_code == 200, current.text
    inputs = dict(extra.get("inputs") or {})
    if inputs:
        preview = client.post(
            f"/api/v1/flows/runs/{run_id}/approval-preview",
            json={"inputs": inputs},
        )
        assert preview.status_code == 200, preview.text
        binding = preview.json().get("approval_binding_sha256")
    else:
        binding = current.json().get("approval_binding_sha256")
    assert isinstance(binding, str) and len(binding) == 64
    return {"decision": decision, "approval_binding_sha256": binding, **extra}


def _store_published_pin(flow_id: str = "demo") -> dict:
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode

    saved = store.save_flow(Flow(
        id=flow_id,
        name="Pinned",
        start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="work")},
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    return {
        "definition_digest": release["definition_digest"],
        "release_id": release["release_id"],
        "definition_version": release["definition_version"],
        "definition_revision": release["definition_revision"],
        "subflow_digests": dict(release.get("subflow_digests") or {}),
    }


def _store_published_approval_pin(flow_id: str = "approval-expiry") -> dict:
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode

    saved = store.save_flow(Flow(
        id=flow_id,
        name="Expiring approval",
        start="approve",
        nodes={
            "approve": FlowNode(
                id="approve", kind="approval", prompt="approve?", expires_after=1,
            ),
        },
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    return {
        "definition_digest": release["definition_digest"],
        "release_id": release["release_id"],
        "release_digest": release["release_digest"],
        "definition_version": release["definition_version"],
        "definition_revision": release["definition_revision"],
        "subflow_digests": dict(release.get("subflow_digests") or {}),
    }


def test_disconnected_step_stays_in_draft_but_blocks_live_publication(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    client = _client()
    flow = {"id": "disconnected", "name": "Payment review", "start": "check", "nodes": [
        {"id": "check", "kind": "agent", "brief": "Check payment"},
        {"id": "approve", "kind": "approval", "label": "Approve payment", "prompt": "Approve?"},
    ]}
    created = client.post("/api/v1/flows", json={"flow": flow})
    assert created.status_code == 201, created.text
    saved = created.json()
    blocked = client.post("/api/v1/flows/disconnected/publish", json={
        "version": saved["version"], "revision": saved["revision"],
    })
    assert blocked.status_code == 409
    assert "Approve payment" in blocked.json()["detail"]
    assert "can never run" in blocked.json()["detail"]
    draft = client.get("/api/v1/flows/disconnected").json()
    draft["nodes"][0]["next"] = "approve"
    connected = client.post("/api/v1/flows", json={"flow": draft})
    assert connected.status_code == 201, connected.text
    assert _publish(client, "disconnected")["published"] is True


_FLOW = {
    "id": "demo", "name": "Demo", "start": "a",
    "nodes": [
        {"id": "a", "kind": "agent", "brief": "assess {{order}}", "next": "b", "output": "r"},
        {"id": "b", "kind": "approval", "prompt": "ship it?", "next": "c"},
        {"id": "c", "kind": "action", "tool": "notify", "params": {"m": "{{r}}"}},
    ],
}


def test_flows_gated_off_by_default(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_FLOWS", raising=False)
    monkeypatch.setattr("maverick.config.get_flows", lambda: {"enable": False})
    assert _client().get("/api/v1/flows").status_code == 403


def test_flow_designer_explains_credential_migration_and_links_native_accounts(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    response = _client().get("/flows/designer")
    assert response.status_code == 200, response.text
    assert "Connector credentials belong in Connections." in response.text
    assert "saved definitions and grants are not changed automatically" in response.text
    assert 'href="/connections"' in response.text


_INPUT_FLOW = {
    "id": "typed", "name": "Typed", "start": "a",
    "nodes": [{"id": "a", "kind": "agent", "brief": "process {{amount}}"}],
    "inputs": [{"key": "amount", "type": "number", "required": True}],
}


def test_dry_run_executes_unsaved_snapshot_without_saving_or_arming_schedule(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    draft = {
        "id": "unsaved-draft",
        "name": "Unsaved",
        "start": "a",
        "schedule": "* * * * *",
        "nodes": [{"id": "a", "kind": "agent", "brief": "new canvas behavior"}],
    }
    response = _client().post(
        "/api/v1/flows/dry-run",
        json={"flow": draft, "data": {"sample": 1}},
    )

    assert response.status_code == 200, response.text
    assert response.json()["dry_run"] is True
    assert store.load_flow("unsaved-draft") is None
    assert store.load_published_bundle("unsaved-draft") is None
    aq._reconcile_flow_crons()
    assert aq._pending(aq.FLOW_CRON_KIND) == []

    run = store.load_run(response.json()["run_id"])
    assert run is not None and run.dry_run is True
    assert run.definition_digest
    snapshotted = store.load_flow_snapshot(run.definition_digest)
    assert snapshotted.nodes["a"].brief == "new canvas behavior"
    assert snapshotted.schedule == "* * * * *"


def test_dry_run_does_not_mutate_an_existing_saved_draft(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store

    client = _client()
    saved = client.post("/api/v1/flows", json={"flow": {
        "id": "existing",
        "name": "Existing",
        "start": "a",
        "nodes": [{"id": "a", "kind": "agent", "brief": "saved behavior"}],
    }}).json()
    candidate = {
        "id": "existing",
        "name": "Existing candidate",
        "start": "a",
        "version": saved["version"],
        "revision": saved["revision"],
        "schedule": "0 9 * * *",
        "nodes": [{"id": "a", "kind": "agent", "brief": "unsaved behavior"}],
    }
    response = client.post(
        "/api/v1/flows/dry-run", json={"flow": candidate, "data": {}},
    )
    assert response.status_code == 200, response.text

    current = store.load_flow("existing")
    assert current is not None
    assert current.version == 1
    assert current.name == "Existing"
    assert current.nodes["a"].brief == "saved behavior"
    run = store.load_run(response.json()["run_id"])
    snapshot = store.load_flow_snapshot(run.definition_digest)
    assert snapshot.version == 2
    assert snapshot.nodes["a"].brief == "unsaved behavior"


def test_saving_is_not_activation_and_publish_pins_the_exact_revision(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    created = client.post("/api/v1/flows", json={"flow": {
        "id": "scheduled",
        "name": "Scheduled",
        "start": "a",
        "schedule": "0 9 * * *",
        "nodes": [{"id": "a", "kind": "agent", "brief": "published behavior"}],
    }})
    assert created.status_code == 201
    draft = created.json()
    aq._reconcile_flow_crons()
    assert aq._pending(aq.FLOW_CRON_KIND) == []

    activated = client.post("/api/v1/flows/scheduled/publish", json={
        "version": draft["version"], "revision": draft["revision"],
    })
    assert activated.status_code == 200, activated.text
    assert activated.json()["published_version"] == 1
    assert len(activated.json()["published_revision"]) == 64
    crons = aq._pending(aq.FLOW_CRON_KIND)
    assert len(crons) == 1
    assert crons[0].payload["__flow_revision__"] == activated.json()["published_revision"]

    current = client.get("/api/v1/flows/scheduled").json()
    edited = dict(current)
    edited["name"] = "Unpublished edit"
    edited["schedule"] = "0 17 * * *"
    saved = client.post("/api/v1/flows", json={"flow": edited})
    assert saved.status_code == 201
    published_flow, release = store.load_published_bundle("scheduled")
    assert published_flow.name == "Scheduled"
    assert published_flow.schedule == "0 9 * * *"
    assert release["release_id"] == activated.json()["published_revision"]
    aq._reconcile_flow_crons()
    assert aq._pending(aq.FLOW_CRON_KIND)[0].payload["__cron__"] == "0 9 * * *"


def test_saved_but_unpublished_flow_cannot_start_a_live_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201

    response = client.post("/api/v1/flows/demo/run", json={"data": {"order": "X"}})

    assert response.status_code == 409
    assert "not published" in response.json()["detail"]
    assert aq._pending(aq.FLOW_RUN_KIND) == []


def test_manual_live_run_pins_release_not_a_later_unpublished_draft(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    created = client.post("/api/v1/flows", json={"flow": _FLOW})
    assert created.status_code == 201
    release = _publish(client, "demo")

    draft = client.get("/api/v1/flows/demo").json()
    draft["nodes"][0]["brief"] = "unpublished replacement {{order}}"
    updated = client.post("/api/v1/flows", json={"flow": draft})
    assert updated.status_code == 201

    response = client.post(
        "/api/v1/flows/demo/run", json={"data": {"order": "X"}},
    )
    assert response.status_code == 200, response.text
    run = store.load_run(response.json()["run_id"])
    pinned = store.load_flow_snapshot(run.definition_digest)
    assert run.release_id == release["published_revision"]
    assert run.definition_version == 1
    assert pinned.nodes["a"].brief == "assess {{order}}"


def test_plain_live_retry_also_pins_the_published_release(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    release = _publish(client, "demo")
    started = client.post(
        "/api/v1/flows/demo/run", json={"data": {"order": "original"}},
    )
    original = store.load_run(started.json()["run_id"])
    original.status = "completed"
    store.save_run(original)

    draft = client.get("/api/v1/flows/demo").json()
    draft["nodes"][0]["brief"] = "unpublished retry behavior"
    assert client.post("/api/v1/flows", json={"flow": draft}).status_code == 201

    response = client.post(f"/api/v1/flows/runs/{original.run_id}/retry")
    assert response.status_code == 200, response.text
    retried = store.load_run(response.json()["run_id"])
    assert retried.release_id == release["published_revision"]
    assert store.load_flow_snapshot(retried.definition_digest).version == 1


def test_unpublish_refuses_paused_live_resume(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    from maverick_dashboard import rbac

    rbac.set_role("operator", "operator")

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    published, release = store.load_published_bundle("demo")
    store.save_run(store.FlowRun(
        run_id="paused-live",
        flow_id="demo",
        status="paused_approval",
        owner="operator",
        cursor="b",
        definition_digest=release["definition_digest"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))
    approval_binding = _attach_test_approval_card("paused-live")
    assert store.unpublish_flow(
        "demo",
        expected_version=published.version,
        expected_revision=published.revision,
    ) is True

    response = client.post(
        "/api/v1/flows/runs/paused-live/resume",
        json={
            "decision": "approved",
            "approval_binding_sha256": approval_binding,
        },
    )
    assert response.status_code == 409
    assert "no longer active" in response.json()["detail"]
    assert aq._pending(aq.FLOW_RESUME_KIND) == []


def test_republish_refuses_retry_from_failure_of_old_release(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    _published, v1 = store.load_published_bundle("demo")
    store.save_run(store.FlowRun(
        run_id="failed-v1",
        flow_id="demo",
        status="failed",
        owner="operator",
        cursor="a",
        definition_digest=v1["definition_digest"],
        definition_version=v1["definition_version"],
        definition_revision=v1["definition_revision"],
        subflow_digests=v1["subflow_digests"],
    ))
    draft = client.get("/api/v1/flows/demo").json()
    draft["name"] = "replacement release"
    assert client.post("/api/v1/flows", json={"flow": draft}).status_code == 201
    _publish(client, "demo")

    response = client.post("/api/v1/flows/runs/failed-v1/retry?from_failure=1")
    assert response.status_code == 409
    assert "no longer active" in response.json()["detail"]
    assert aq._pending(aq.FLOW_RESUME_KIND) == []


def test_publish_requires_exact_cas_and_live_run_rejects_corrupt_release(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    first = client.post("/api/v1/flows", json={"flow": _FLOW}).json()
    current = client.get("/api/v1/flows/demo").json()
    current["name"] = "v2 draft"
    second = client.post("/api/v1/flows", json={"flow": current}).json()

    stale = client.post("/api/v1/flows/demo/publish", json={
        "version": first["version"], "revision": first["revision"],
    })
    assert stale.status_code == 409
    wrong_generation = client.post("/api/v1/flows/demo/publish", json={
        "version": second["version"], "revision": "attacker-selected",
    })
    assert wrong_generation.status_code == 409

    _publish(client, "demo")
    _published, metadata = store.load_published_bundle("demo")
    snapshot = store._objects_dir() / f"{metadata['definition_digest']}.json"
    snapshot.write_text('{"id":"tampered"}', encoding="utf-8")

    rejected = client.post(
        "/api/v1/flows/demo/run", json={"data": {"order": "X"}},
    )
    assert rejected.status_code == 409
    assert "integrity" in rejected.json()["detail"]
    assert aq._pending(aq.FLOW_RUN_KIND) == []


def test_live_reservation_rechecks_publication_after_optimistic_load(
    monkeypatch, tmp_path,
):
    """Unpublish winning after the first read prevents any durable live run."""
    _isolate(monkeypatch, tmp_path)
    import threading

    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    current = store.load_flow("demo")
    initial_loaded = threading.Event()
    resume_enqueue = threading.Event()
    real_load = store.load_published_bundle
    first = [True]

    def _pause_after_first_load(flow_id):
        published = real_load(flow_id)
        if first[0]:
            first[0] = False
            initial_loaded.set()
            assert resume_enqueue.wait(timeout=5)
        return published

    monkeypatch.setattr(store, "load_published_bundle", _pause_after_first_load)
    result: dict = {}

    def _enqueue():
        try:
            result["run"] = aq.enqueue_published_flow_run_once(
                "demo", {}, owner="user:alice",
            )
        except Exception as exc:  # expected fail-closed result from the worker
            result["error"] = exc

    thread = threading.Thread(target=_enqueue)
    thread.start()
    assert initial_loaded.wait(timeout=5)
    assert store.unpublish_flow(
        "demo",
        expected_version=current.version,
        expected_revision=current.revision,
    ) is True
    resume_enqueue.set()
    thread.join(timeout=5)

    assert not thread.is_alive()
    assert isinstance(result.get("error"), store.FlowSnapshotError)
    assert "run" not in result
    assert store.list_runs(flow_id="demo", limit=None) == []
    assert aq._pending(aq.FLOW_RUN_KIND) == []


def test_bound_release_is_refused_after_republication(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    v1 = _publish(client, "demo")
    draft = client.get("/api/v1/flows/demo").json()
    draft["name"] = "v2"
    assert client.post("/api/v1/flows", json={"flow": draft}).status_code == 201
    _publish(client, "demo")

    with pytest.raises(store.FlowSnapshotError, match="no longer matches"):
        aq.enqueue_published_flow_run_once(
            "demo", {}, expected_revision=v1["published_revision"],
        )
    assert store.list_runs(flow_id="demo", limit=None) == []
    assert aq._pending(aq.FLOW_RUN_KIND) == []


@pytest.mark.parametrize("mutation", ["unpublish", "replace"])
def test_queued_live_dispatch_revalidates_release_before_building_executors(
    monkeypatch, tmp_path, mutation,
):
    """A reservation made while live cannot outlive later release revocation."""
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    run_id = aq.enqueue_published_flow_run("demo", {"order": "queued"})
    job = next(
        j for j in aq._pending(aq.FLOW_RUN_KIND)
        if j.payload.get("run_id") == run_id
    )
    current = store.load_flow("demo")
    if mutation == "unpublish":
        assert store.unpublish_flow(
            current.id,
            expected_version=current.version,
            expected_revision=current.revision,
        )
    else:
        current.name = "replacement"
        saved = store.save_flow(
            current,
            expected_version=current.version,
            expected_revision=current.revision,
        )
        store.publish_flow(
            saved.id,
            expected_version=saved.version,
            expected_revision=saved.revision,
        )
    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("revoked run built live executors"),
    )

    aq._handle_flow_run(SimpleNamespace(payload=job.payload))

    revoked = store.load_run(run_id)
    assert revoked.status == "failed"
    assert "revoked before dispatch" in revoked.error


def test_release_revocation_does_not_hold_a_lock_through_long_execution(
    monkeypatch, tmp_path,
):
    """Dispatch wins once; unpublish returns without waiting for its executor."""
    _isolate(monkeypatch, tmp_path)
    import threading
    from types import SimpleNamespace

    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    saved = store.save_flow(Flow(
        id="long-dispatch",
        name="Long dispatch",
        start="agent",
        nodes={"agent": FlowNode(id="agent", kind="agent", brief="work")},
    ))
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    run_id = aq.enqueue_published_flow_run(saved.id, {})
    job = next(
        j for j in aq._pending(aq.FLOW_RUN_KIND)
        if j.payload.get("run_id") == run_id
    )
    executor_started = threading.Event()
    finish_executor = threading.Event()
    unpublished = threading.Event()

    def _agent(_brief, _data):
        executor_started.set()
        # Generous ceiling: must stay well ABOVE the unpublished.wait below,
        # or a lock-blocked unpublish could ride out this timeout and pass.
        assert finish_executor.wait(timeout=30)
        return "done", 1.0

    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda _run: (_agent, lambda *_args: ("", None)),
    )
    worker = threading.Thread(
        target=aq._handle_flow_run,
        args=(SimpleNamespace(payload=job.payload),),
    )
    worker.start()
    assert executor_started.wait(timeout=5)

    def _unpublish():
        assert store.unpublish_flow(
            saved.id,
            expected_version=saved.version,
            expected_revision=saved.revision,
        )
        unpublished.set()

    revoker = threading.Thread(target=_unpublish)
    revoker.start()
    # The per-flow activation lock covers only execution-start linearization,
    # not minutes/hours of agent work. A correct unpublish returns in
    # milliseconds; a lock-blocked one cannot fire before the executor's 30s
    # ceiling, so 10s discriminates the two even on a starved CI runner
    # (2s flaked there while the code was correct).
    assert unpublished.wait(timeout=10)
    assert worker.is_alive()
    finish_executor.set()
    worker.join(timeout=10)
    revoker.join(timeout=10)

    assert not worker.is_alive() and not revoker.is_alive()
    assert store.load_run(run_id).status == "completed"
    assert store.load_published_bundle(saved.id) is None


def test_stale_queue_redelivery_never_rewrites_a_terminal_run(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    run_id = aq.enqueue_published_flow_run("demo", {"order": "once"})
    job = next(
        j for j in aq._pending(aq.FLOW_RUN_KIND)
        if j.payload.get("run_id") == run_id
    )
    terminal = store.load_run(run_id)
    terminal.status = "completed"
    store.save_run(terminal)
    current = store.load_flow("demo")
    current.name = "new release"
    saved = store.save_flow(
        current,
        expected_version=current.version,
        expected_revision=current.revision,
    )
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("terminal redelivery built executors"),
    )

    aq._handle_flow_run(SimpleNamespace(payload=job.payload))
    aq._handle_flow_resume(SimpleNamespace(payload={
        "flow_id": "demo", "run_id": run_id,
    }))

    assert store.load_run(run_id).status == "completed"


@pytest.mark.parametrize(
    ("status", "node_kind"),
    [("paused_approval", "approval"), ("paused_delay", "delay")],
)
@pytest.mark.parametrize("mutation", ["unpublish", "replace"])
def test_queued_live_resume_revalidates_release_at_delivery(
    monkeypatch, tmp_path, status, node_kind, mutation,
):
    """Approval and delayed jobs cannot resume after their release is revoked."""
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    gate = FlowNode(id="gate", kind=node_kind, next="effect")
    if node_kind == "approval":
        gate.prompt = "continue?"
    else:
        gate.seconds = 1
    saved = store.save_flow(Flow(
        id="resume-boundary",
        name="Resume boundary",
        start="gate",
        nodes={
            "gate": gate,
            "effect": FlowNode(
                id="effect", kind="agent", brief="perform live work",
            ),
        },
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    store.save_run(store.FlowRun(
        run_id="paused-boundary",
        flow_id=saved.id,
        status=status,
        cursor="gate",
        definition_digest=release["definition_digest"],
        release_id=release["release_id"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))
    approval_binding = (
        _attach_test_approval_card("paused-boundary")
        if status == "paused_approval"
        else ""
    )
    aq.enqueue_flow_resume(
        saved.id,
        "paused-boundary",
        decision="approved" if status == "paused_approval" else "",
        decided_by="system:test" if status == "paused_approval" else "",
        approval_binding_sha256=approval_binding,
    )
    job = next(
        j for j in aq._pending(aq.FLOW_RESUME_KIND)
        if j.payload.get("run_id") == "paused-boundary"
    )
    if mutation == "unpublish":
        assert store.unpublish_flow(
            saved.id,
            expected_version=saved.version,
            expected_revision=saved.revision,
        )
    else:
        saved.name = "replacement"
        replacement = store.save_flow(
            saved,
            expected_version=saved.version,
            expected_revision=saved.revision,
        )
        store.publish_flow(
            replacement.id,
            expected_version=replacement.version,
            expected_revision=replacement.revision,
        )
    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("revoked resume built live executors"),
    )

    aq._handle_flow_resume(SimpleNamespace(payload=job.payload))

    revoked = store.load_run("paused-boundary")
    assert revoked.status == "failed"
    assert "revoked before resume" in revoked.error


def test_malformed_publication_pointer_fails_integrity_checks(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store

    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    pointer = store._published_dir() / "demo.json"
    pointer.write_text("{", encoding="utf-8")

    with pytest.raises(store.FlowSnapshotError, match="pointer"):
        store.load_published_bundle("demo")
    response = client.post("/api/v1/flows/demo/run", json={"data": {}})
    assert response.status_code == 409
    assert "integrity" in response.json()["detail"]


def test_release_pointer_derives_legacy_identity_but_rejects_mismatch(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    import json

    from maverick.flow import store

    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    pointer = store._published_dir() / "demo.json"
    raw = json.loads(pointer.read_text(encoding="utf-8"))
    content_digest = raw.pop("release_digest")
    raw["release_id"] = content_digest  # pre-activation-epoch pointer format
    pointer.write_text(json.dumps(raw), encoding="utf-8")

    _flow, derived = store.load_published_bundle("demo")
    assert derived["release_id"] == content_digest
    assert derived["release_digest"] == content_digest

    raw["release_digest"] = "0" * 64
    pointer.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(store.FlowSnapshotError, match="release content"):
        store.load_published_bundle("demo")


def test_run_rejects_a_missing_required_input(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    c.post("/api/v1/flows", json={"flow": _INPUT_FLOW})
    _publish(c, "typed")
    r = c.post("/api/v1/flows/typed/run", json={"data": {}})
    assert r.status_code == 400 and "amount" in r.json()["detail"]


def test_run_coerces_a_typed_input(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    c.post("/api/v1/flows", json={"flow": _INPUT_FLOW})
    _publish(c, "typed")
    r = c.post("/api/v1/flows/typed/run", json={"data": {"amount": "42"}})
    assert r.status_code == 200
    from maverick.flow import store
    assert store.load_run(r.json()["run_id"]).data["amount"] == 42.0   # coerced to number


def test_run_idempotency_key_dedups_a_repeat_submit(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    c.post("/api/v1/flows", json={"flow": _FLOW})
    _publish(c, "demo")
    a = c.post("/api/v1/flows/demo/run", json={"data": {"order": "X"}, "idempotency_key": "k1"}).json()
    b = c.post("/api/v1/flows/demo/run", json={"data": {"order": "X"}, "idempotency_key": "k1"}).json()
    assert a["run_id"] == b["run_id"] and b.get("deduplicated") is True


def test_idempotency_key_is_scoped_to_exact_published_release(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    v1_release = _publish(client, "demo")
    v1 = client.post("/api/v1/flows/demo/run", json={
        "data": {"order": "v1"}, "idempotency_key": "business-key",
    }).json()

    draft = client.get("/api/v1/flows/demo").json()
    draft["nodes"][0]["brief"] = "v2 {{order}}"
    assert client.post("/api/v1/flows", json={"flow": draft}).status_code == 201
    v2_release = _publish(client, "demo")
    v2 = client.post("/api/v1/flows/demo/run", json={
        "data": {"order": "v2"}, "idempotency_key": "business-key",
    }).json()
    v2_repeat = client.post("/api/v1/flows/demo/run", json={
        "data": {"order": "v2"}, "idempotency_key": "business-key",
    }).json()

    assert v2["run_id"] != v1["run_id"]
    assert v2_repeat["run_id"] == v2["run_id"]
    assert v2_repeat["deduplicated"] is True
    assert store.load_run(v1["run_id"]).release_id == (
        v1_release["published_revision"]
    )
    assert store.load_run(v2["run_id"]).release_id == (
        v2_release["published_revision"]
    )


def test_release_identity_binds_unchanged_parent_to_exact_child_manifest(
    monkeypatch, tmp_path,
):
    """A child-only change is a new release, guard, and idempotency cohort."""
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    child = store.save_flow(Flow(
        id="child",
        name="Child",
        start="c",
        nodes={"c": FlowNode(id="c", kind="agent", brief="child-v1")},
    ))
    parent = store.save_flow(Flow(
        id="parent",
        name="Parent",
        start="s",
        nodes={"s": FlowNode(id="s", kind="subflow", flow_ref="child")},
    ))
    release_v1 = store.publish_flow(
        parent.id,
        expected_version=parent.version,
        expected_revision=parent.revision,
    )
    run_v1, dedup_v1 = aq.enqueue_published_flow_run_once(
        parent.id,
        {},
        idem_key="same-business-event",
        expected_revision=release_v1["release_id"],
    )
    assert dedup_v1 is False

    child.nodes["c"].brief = "child-v2"
    store.save_flow(
        child,
        expected_version=child.version,
        expected_revision=child.revision,
    )
    release_v2 = store.publish_flow(
        parent.id,
        expected_version=parent.version,
        expected_revision=parent.revision,
    )

    assert release_v2["definition_digest"] == release_v1["definition_digest"]
    assert release_v2["release_id"] != release_v1["release_id"]
    with pytest.raises(store.FlowSnapshotError, match="bound revision"):
        aq.enqueue_published_flow_run_once(
            parent.id, {}, expected_revision=release_v1["release_id"],
        )

    run_v2, dedup_v2 = aq.enqueue_published_flow_run_once(
        parent.id,
        {},
        idem_key="same-business-event",
        expected_revision=release_v2["release_id"],
    )
    assert dedup_v2 is False and run_v2 != run_v1
    pinned_v1 = store.load_run(run_v1)
    pinned_v2 = store.load_run(run_v2)
    assert pinned_v1.release_id == release_v1["release_id"]
    assert pinned_v2.release_id == release_v2["release_id"]
    assert pinned_v1.subflow_digests["child"] != pinned_v2.subflow_digests["child"]
    assert store.load_flow_snapshot(
        pinned_v1.subflow_digests["child"],
    ).nodes["c"].brief == "child-v1"
    assert store.load_flow_snapshot(
        pinned_v2.subflow_digests["child"],
    ).nodes["c"].brief == "child-v2"


def test_identical_republish_creates_a_new_activation_and_refuses_old_work(
    monkeypatch, tmp_path,
):
    """Revoke+republish cannot re-arm queued work from an older activation."""
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    saved = store.save_flow(Flow(
        id="activation-aba",
        name="Activation ABA",
        start="a",
        nodes={"a": FlowNode(id="a", kind="approval", prompt="same content")},
    ))
    v1 = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    old_initial, duplicate = aq.enqueue_published_flow_run_once(
        saved.id, {}, idem_key="same-event",
    )
    assert duplicate is False
    store.save_run(store.FlowRun(
        run_id="old-paused",
        flow_id=saved.id,
        status="paused_approval",
        cursor="a",
        human={"choices": [], "assignee": "", "form": []},
        definition_digest=v1["definition_digest"],
        release_digest=v1["release_digest"],
        release_id=v1["release_id"],
        definition_version=v1["definition_version"],
        definition_revision=v1["definition_revision"],
        subflow_digests=v1["subflow_digests"],
    ))
    approval_binding = _attach_test_approval_card("old-paused")
    aq.enqueue_flow_resume(
        saved.id,
        "old-paused",
        decision="approved",
        decided_by="system:test",
        approval_binding_sha256=approval_binding,
    )

    assert store.unpublish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    v2 = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    assert v2["release_digest"] == v1["release_digest"]
    assert v2["release_id"] != v1["release_id"]
    with pytest.raises(store.FlowSnapshotError, match="bound revision"):
        aq.enqueue_published_flow_run_once(
            saved.id, {}, expected_revision=v1["release_id"],
        )
    current, duplicate = aq.enqueue_published_flow_run_once(
        saved.id, {}, idem_key="same-event",
    )
    assert duplicate is False and current != old_initial

    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("old activation built executors"),
    )
    pending = aq.queue().list(status="pending", limit=100)
    initial_job = next(j for j in pending if j.kind == aq.FLOW_RUN_KIND
                       and j.payload.get("run_id") == old_initial)
    resume_job = next(j for j in pending if j.kind == aq.FLOW_RESUME_KIND
                      and j.payload.get("run_id") == "old-paused")
    aq._handle_flow_run(initial_job)
    aq._handle_flow_resume(resume_job)
    assert store.load_run(old_initial).status == "failed"
    assert store.load_run("old-paused").status == "failed"


def test_idempotency_key_is_scoped_to_execution_owner(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")

    alice, alice_dedup = aq.enqueue_published_flow_run_once(
        "demo", {}, owner="user:alice", idem_key="shared-key",
    )
    bob, bob_dedup = aq.enqueue_published_flow_run_once(
        "demo", {}, owner="user:bob", idem_key="shared-key",
    )
    alice_repeat, alice_repeat_dedup = aq.enqueue_published_flow_run_once(
        "demo", {}, owner="user:alice", idem_key="shared-key",
    )
    bob_repeat, bob_repeat_dedup = aq.enqueue_published_flow_run_once(
        "demo", {}, owner="user:bob", idem_key="shared-key",
    )

    assert alice != bob
    assert alice_dedup is bob_dedup is False
    assert alice_repeat == alice and alice_repeat_dedup is True
    assert bob_repeat == bob and bob_repeat_dedup is True


def test_idempotency_key_does_not_alias_a_recreated_flow_generation(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    first, duplicate = aq.enqueue_flow_run_once(
        "demo", {}, idem_key="same-event")
    assert duplicate is False
    old = store.load_flow("demo")
    assert old is not None
    assert store.delete_flow(
        "demo", expected_version=old.version, expected_revision=old.revision)
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201

    second, duplicate = aq.enqueue_flow_run_once(
        "demo", {}, idem_key="same-event")

    assert duplicate is False
    assert second != first
    assert store.load_run(second).definition_revision != store.load_run(first).definition_revision


def test_save_validate_get_delete(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    assert c.get("/api/v1/flows").json()["flows"][0]["id"] == "demo"
    assert len(c.get("/api/v1/flows/demo").json()["nodes"]) == 3
    assert c.delete("/api/v1/flows/demo").status_code == 204
    assert c.get("/api/v1/flows/demo").status_code == 404


def test_delete_keeps_draft_and_live_pointer_when_revocation_fails(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store

    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(c, "demo")

    def _fail_revoke(_flow_id):
        raise store.FlowSnapshotError("simulated pointer failure")

    monkeypatch.setattr(store, "_revoke_published_pointer_locked", _fail_revoke)
    response = c.delete("/api/v1/flows/demo")
    assert response.status_code == 409
    assert store.load_flow("demo") is not None
    assert store.load_published_bundle("demo") is not None


def test_delete_is_retryable_after_revocation_wins_but_draft_unlink_fails(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from pathlib import Path

    from maverick.flow import store

    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(c, "demo")
    current = store.load_flow("demo")
    draft_path = store._flows_dir() / "demo.json"
    original_unlink = Path.unlink

    def _fail_draft_unlink(path, *args, **kwargs):
        if path == draft_path:
            raise PermissionError("simulated draft unlink failure")
        return original_unlink(path, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "unlink", _fail_draft_unlink)
        with pytest.raises(store.FlowSnapshotError, match="revoked"):
            store.delete_flow(
                "demo",
                expected_version=current.version,
                expected_revision=current.revision,
            )

    assert store.load_flow("demo") is not None
    assert store.load_published_bundle("demo") is None
    assert store._revoked_pointer_path("demo").exists()
    assert store.delete_flow(
        "demo",
        expected_version=current.version,
        expected_revision=current.revision,
    )
    assert store.load_flow("demo") is None


def test_save_uses_client_cas_and_rejects_a_stale_editor(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    created = c.post("/api/v1/flows", json={"flow": _FLOW})
    assert created.status_code == 201
    first = c.get("/api/v1/flows/demo").json()

    winner = {**first, "name": "winner"}
    saved = c.post("/api/v1/flows", json={"flow": winner})
    assert saved.status_code == 201 and saved.json()["version"] == 2

    stale = {**first, "name": "stale overwrite"}
    rejected = c.post("/api/v1/flows", json={"flow": stale})
    assert rejected.status_code == 409
    assert c.get("/api/v1/flows/demo").json()["name"] == "winner"


def test_save_generation_token_closes_delete_recreate_aba(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    stale = c.get("/api/v1/flows/demo").json()
    assert c.delete("/api/v1/flows/demo").status_code == 204
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201

    stale["name"] = "ABA overwrite"
    assert c.post("/api/v1/flows", json={"flow": stale}).status_code == 409
    assert c.get("/api/v1/flows/demo").json()["name"] == "Demo"


def test_new_flow_version_is_store_owned(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    hostile = {**_FLOW, "version": -99, "revision": "attacker-selected"}
    r = _client().post("/api/v1/flows", json={"flow": hostile})
    assert r.status_code == 201
    saved = _client().get("/api/v1/flows/demo").json()
    assert saved["version"] == 1
    assert saved["revision"] and saved["revision"] != "attacker-selected"


def test_invalid_flow_rejected(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    bad = {"id": "b", "name": "x", "start": "z", "nodes": [{"id": "a", "kind": "agent"}]}
    r = _client().post("/api/v1/flows", json={"flow": bad})
    assert r.status_code == 400 and "invalid flow" in r.json()["detail"]


def test_run_drains_through_queue_and_pauses_on_approval(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    # fake live runners so no LLM/tool is needed
    def _fake_agent(world, **k):
        return lambda brief, d: (f"ran:{brief}", 1.0)

    def _fake_action(world, sandbox=None, **kwargs):
        return lambda t, p, d: ("sent", 1.0)

    monkeypatch.setattr(execution, "default_agent_runner", _fake_agent)
    monkeypatch.setattr(execution, "default_action_runner", _fake_action)
    c = _client()
    c.post("/api/v1/flows", json={"flow": _FLOW})
    _publish(c, "demo")
    started = c.post("/api/v1/flows/demo/run", json={"data": {"order": "X-9"}}).json()
    run_id = started["run_id"]
    assert started["status"] == "queued"
    from maverick.flow import store
    assert store.load_run(run_id).owner == ""
    assert run_id in {item["run_id"] for item in c.get("/api/v1/flows/runs").json()["runs"]}
    # drain the queued flow_run job
    _drain(aq)
    run = c.get(f"/api/v1/flows/runs/{run_id}").json()
    assert run["status"] == "paused_approval" and run["cursor"] == "b"
    assert run["data"]["r"] == "ran:assess X-9"     # agent output threaded through
    # resume approved -> drains to completion, action fires
    c.post(
        f"/api/v1/flows/runs/{run_id}/resume",
        json=_approval_resume_body(c, run_id, "approved"),
    )
    _drain(aq)
    done = c.get(f"/api/v1/flows/runs/{run_id}").json()
    assert done["status"] == "completed"
    assert done["decided_by"] == "local:dashboard"


def _expired_open_review(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.approval_cards import digest
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    client = _client()
    flow = {"id": "review-recovery", "name": "Invoice review", "start": "prepare", "nodes": [
        {"id": "prepare", "kind": "setvar", "assignments": {"vendor": "Acme", "amount": 5000}, "next": "gate"},
        {"id": "gate", "kind": "approval", "prompt": "Approve paying {{vendor}} {{amount}}?", "next": "finish"},
        {"id": "finish", "kind": "setvar", "assignments": {"finished": True}},
    ]}
    assert client.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    _publish(client, flow["id"])
    started = client.post(f"/api/v1/flows/{flow['id']}/run", json={"data": {}})
    assert started.status_code == 200, started.text
    run_id = started.json()["run_id"]
    _drain(aq)
    run = store.load_run(run_id)
    assert run.status == "paused_approval" and run.resume_at is None
    old_decision = client.get(f"/api/v1/flows/runs/{run_id}").json()["approval_binding_sha256"]
    card = dict(run.human["approval_card"])
    card.pop("binding_sha256")
    card["expires_at"] = time.time() - 1
    card["binding_sha256"] = digest(card)
    run.human["approval_card"] = card
    store.save_run(run)
    return client, run_id, old_decision


def test_expired_open_approval_can_be_refreshed_then_decided_without_repeating_work(monkeypatch, tmp_path):
    client, run_id, old_decision = _expired_open_review(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    before = store.load_run(run_id)
    url = f"/api/v1/flows/runs/{run_id}/approval-refresh"
    preview = client.get(url)
    assert preview.status_code == 200, preview.text
    review = preview.json()
    body = {"binding": review["binding"], "confirmed": True}
    assert client.post(url, json={**body, "confirmed": False}).status_code == 422
    result = client.post(url, json=body)
    assert result.status_code == 200, result.text
    renewed = store.load_run(run_id)
    assert renewed.status == before.status and renewed.cursor == before.cursor
    assert renewed.data == before.data and renewed.nodes == before.nodes
    assert renewed.human["approval_card"]["expires_at"] > time.time() + 6 * 86400
    assert client.post(url, json=body).status_code == 200  # same request is a receipt replay
    assert client.post(f"/api/v1/flows/runs/{run_id}/resume", json={
        "decision": "approved", "approval_binding_sha256": old_decision,
    }).status_code == 409
    assert client.post(f"/api/v1/flows/runs/{run_id}/resume",
                       json=_approval_resume_body(client, run_id, "approved")).status_code == 200
    _drain(aq)
    assert store.load_run(run_id).status == "completed"
    assert store.load_run(run_id).data["finished"] is True


@pytest.mark.parametrize("change", ["credentials", "checkpoint", "timed", "audit", "publication", "owner"])
def test_approval_refresh_refuses_changed_authority_data_or_deadline(monkeypatch, tmp_path, change):
    client, run_id, _old_decision = _expired_open_review(monkeypatch, tmp_path)
    from maverick import audit
    from maverick.flow import store

    url = f"/api/v1/flows/runs/{run_id}/approval-refresh"
    review = client.get(url).json()
    if change == "credentials":
        monkeypatch.setenv("SYNTHETIC_API_KEY", "new-credential-generation")
    elif change in {"checkpoint", "timed"}:
        run = store.load_run(run_id)
        if change == "checkpoint":
            run.data["amount"] = 9000
        else:
            run.resume_at = time.time() - 1
        store.save_run(run)
    elif change == "publication":
        flow = store.load_flow("review-recovery")
        store.unpublish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)
    elif change == "owner":
        from maverick_dashboard import api as native
        monkeypatch.setattr(native, "goal_owner_filter", lambda _request: "user:someone-else")
    else:
        monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: False)
    before = store.load_run(run_id)
    result = client.post(url, json={"binding": review["binding"], "confirmed": True})
    assert result.status_code == (503 if change == "audit" else 404 if change == "owner" else 409), result.text
    assert store.load_run(run_id).human == before.human
    assert store.load_run(run_id).status == "paused_approval"


def test_copilot_refresh_uses_native_approval_checks_and_recovers_its_exact_receipt(monkeypatch, tmp_path):
    client, run_id, _old_decision = _expired_open_review(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import product_operations as ops
    from maverick_dashboard import product_operations_flow_approval_recovery as adapter

    # Enable only the new adapter; its native ownership, authority, release,
    # current-state and audit boundaries remain real.
    monkeypatch.setattr(ops, "_gate", lambda _request: None)
    monkeypatch.setattr(ops, "enabled_families", lambda: {"learning"})
    monkeypatch.setattr(ops, "adapters", lambda: {entry.id: entry for entry in adapter.entries()})
    base = "/api/v1/copilot/product-operations"
    context = {"page": f"/flows/review-recovery/runs/{run_id}",
               "selection": {"kind": "flow_run", "id": run_id, "flow_id": "review-recovery"}}
    catalog = client.post(base + "/catalog", json=context)
    assert catalog.status_code == 200, catalog.text
    value = catalog.json()
    entry = value["operations"][0]
    assert entry["available"] is True
    prepared = client.post(base + "/prepare", json={**context, "operation": entry["id"],
        "context": value["context"], "revision": entry["revision"], "arguments": {}})
    assert prepared.status_code == 200, prepared.text
    body = {"token": prepared.json()["token"], "confirmed": True}
    applied = client.post(base + "/execute", json=body)
    assert applied.status_code == 200, applied.text
    assert applied.json()["status"] == "confirmed"
    assert client.post(base + "/execute", json=body).status_code == 200
    assert store.load_run(run_id).status == "paused_approval"
    assert store.load_run(run_id).data == {"vendor": "Acme", "amount": 5000}


def test_restored_resume_rechecks_credential_revision_before_live_executors(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("SYNTHETIC_API_KEY", "credential-generation-one")
    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda world, **kwargs: lambda brief, data: ("reviewed", 1.0),
    )
    monkeypatch.setattr(
        execution,
        "default_action_runner",
        lambda world, sandbox=None, **kwargs: lambda tool, params, data: ("ok", 1.0),
    )
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    run_id = client.post("/api/v1/flows/demo/run", json={"data": {}}).json()["run_id"]
    _drain(aq)
    reviewed = client.get(f"/api/v1/flows/runs/{run_id}").json()
    old_binding = reviewed["approval_binding_sha256"]
    queued = client.post(
        f"/api/v1/flows/runs/{run_id}/resume",
        json={
            "decision": "approved",
            "approval_binding_sha256": old_binding,
        },
    )
    assert queued.status_code == 200, queued.text
    job = next(
        item for item in aq._pending(aq.FLOW_RESUME_KIND)
        if item.payload.get("run_id") == run_id
    )
    monkeypatch.setenv("SYNTHETIC_API_KEY", "credential-generation-two")
    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("stale approval built live executors"),
    )

    aq._handle_flow_resume(job)

    refused = store.load_run(run_id)
    assert refused.status == "paused_approval"
    assert "Review the current operation again" in refused.error
    refreshed = client.get(f"/api/v1/flows/runs/{run_id}").json()
    assert refreshed["approval_card_status"] == "current"
    assert refreshed["approval_binding_sha256"] != old_binding
    assert refreshed["approval_authority"]["credential_inventory_sha256"] != (
        reviewed["approval_authority"]["credential_inventory_sha256"]
    )


@pytest.mark.parametrize("tamper", ["inputs", "durable_data", "missing_binding"])
def test_direct_worker_refuses_unreviewed_or_changed_resume_payload(
    monkeypatch, tmp_path, tamper,
):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda world, **kwargs: lambda brief, data: ("reviewed", 1.0),
    )
    monkeypatch.setattr(
        execution,
        "default_action_runner",
        lambda world, sandbox=None, **kwargs: lambda tool, params, data: ("ok", 1.0),
    )
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    run_id = client.post(
        "/api/v1/flows/demo/run", json={"data": {"reviewed": "v1"}},
    ).json()["run_id"]
    _drain(aq)
    body = _approval_resume_body(
        client, run_id, "approved", inputs={"review_note": "approved-value"},
    )
    response = client.post(f"/api/v1/flows/runs/{run_id}/resume", json=body)
    assert response.status_code == 200, response.text
    queued = next(
        item for item in aq._pending(aq.FLOW_RESUME_KIND)
        if item.payload.get("run_id") == run_id
    )
    payload = dict(queued.payload)
    if tamper == "inputs":
        payload["inputs"] = {"review_note": "changed-after-approval"}
    elif tamper == "durable_data":
        run = store.load_run(run_id)
        run.data["reviewed"] = "changed-after-approval"
        store.save_run(run)
    else:
        payload.pop("approval_binding_sha256", None)
    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("unreviewed resume built live executors"),
    )

    aq._handle_flow_resume(SimpleNamespace(payload=payload))

    refused = store.load_run(run_id)
    assert refused.status == "paused_approval"
    assert "Review the current operation again" in refused.error


def test_resume_api_rejects_form_values_changed_after_exact_preview(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda world, **kwargs: lambda brief, data: ("reviewed", 1.0),
    )
    monkeypatch.setattr(
        execution,
        "default_action_runner",
        lambda world, sandbox=None, **kwargs: lambda tool, params, data: ("ok", 0.0),
    )
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    run_id = client.post(
        "/api/v1/flows/demo/run", json={"data": {"reviewed": "v1"}},
    ).json()["run_id"]
    _drain(aq)
    preview = client.post(
        f"/api/v1/flows/runs/{run_id}/approval-preview",
        json={"inputs": {"review_note": "approved value"}},
    )
    assert preview.status_code == 200, preview.text

    response = client.post(
        f"/api/v1/flows/runs/{run_id}/resume",
        json={
            "decision": "approved",
            "inputs": {"review_note": "substituted value"},
            "approval_binding_sha256": preview.json()["approval_binding_sha256"],
        },
    )

    assert response.status_code == 409
    assert aq._pending(aq.FLOW_RESUME_KIND) == []
    assert store.load_run(run_id).status == "paused_approval"


@pytest.mark.parametrize("tamper", ["before_due", "missing_expiry_binding"])
def test_direct_worker_cannot_forge_approval_expiry(
    monkeypatch, tmp_path, tamper,
):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda world, **kwargs: lambda brief, data: ("reviewed", 1.0),
    )
    monkeypatch.setattr(
        execution,
        "default_action_runner",
        lambda world, sandbox=None, **kwargs: lambda tool, params, data: ("ok", 0.0),
    )
    flow = {
        **_FLOW,
        "id": "expiring-approval",
        "nodes": [
            dict(node, expires_after=3600)
            if node["id"] == "b" else dict(node)
            for node in _FLOW["nodes"]
        ],
    }
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    _publish(client, flow["id"])
    run_id = client.post(
        f"/api/v1/flows/{flow['id']}/run", json={"data": {}},
    ).json()["run_id"]
    _drain(aq)
    run = store.load_run(run_id)
    assert run.status == "paused_approval" and run.resume_at is not None
    scheduled = next(
        job for job in aq._pending(aq.FLOW_RESUME_KIND)
        if job.payload.get("run_id") == run_id and job.payload.get("expired")
    )
    forged = dict(scheduled.payload)
    if tamper == "missing_expiry_binding":
        forged.pop("approval_expiry_binding_sha256", None)
        monkeypatch.setattr(aq.time, "time", lambda: float(run.resume_at) + 1.0)
    else:
        monkeypatch.setattr(aq.time, "time", lambda: float(run.resume_at) - 1.0)
    monkeypatch.setattr(
        aq,
        "_flow_runners",
        lambda *_args, **_kwargs: pytest.fail("forged expiry built live executors"),
    )

    aq._handle_flow_resume(SimpleNamespace(payload=forged))

    refused = store.load_run(run_id)
    assert refused.status == "paused_approval"
    assert "Review the current operation again" in refused.error


def test_view_only_flow_approval_is_audited_and_remains_paused(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick import audit
    from maverick.flow import execution, store
    from maverick_dashboard import api as api_module
    from maverick_dashboard import auth
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda world, **kwargs: lambda brief, data: ("reviewed", 1.0),
    )
    monkeypatch.setattr(
        execution,
        "default_action_runner",
        lambda world, sandbox=None, **kwargs: lambda tool, params, data: ("ok", 1.0),
    )
    client = _client()
    assert client.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    _publish(client, "demo")
    run_id = client.post("/api/v1/flows/demo/run", json={"data": {}}).json()["run_id"]
    _drain(aq)
    recorded = []
    monkeypatch.setattr(auth, "has_permission", lambda _request, _permission: False)
    monkeypatch.setattr(auth, "caller_principal", lambda _request: "user:viewer")
    monkeypatch.setattr(api_module, "goal_owner_filter", lambda _request: None)
    monkeypatch.setattr(
        audit,
        "audit_event",
        lambda kind, **payload: recorded.append((kind, payload)) or True,
    )

    response = client.post(
        f"/api/v1/flows/runs/{run_id}/resume",
        json={"decision": "approved", "approval_binding_sha256": "a" * 64},
    )

    assert response.status_code == 403
    assert store.load_run(run_id).status == "paused_approval"
    assert aq._pending(aq.FLOW_RESUME_KIND) == []
    assert len(recorded) == 1
    assert recorded[0][0] == audit.EventKind.CAPABILITY_DENIED
    assert recorded[0][1]["principal"] == "user:viewer"
    assert len(recorded[0][1]["resource_sha256"]) == 64
    assert run_id not in str(recorded[0][1])


def test_approval_resume_never_defaults_an_empty_body_to_approved(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    saved = store.save_flow(Flow(
        id="explicit-decision",
        name="Explicit decision",
        start="gate",
        nodes={"gate": FlowNode(id="gate", kind="approval", prompt="ok?")},
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    store.save_run(store.FlowRun(
        run_id="explicit-decision-run",
        flow_id=saved.id,
        status="paused_approval",
        cursor="gate",
        human={"choices": [], "assignee": "", "form": []},
        definition_digest=release["definition_digest"],
        release_digest=release["release_digest"],
        release_id=release["release_id"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))
    response = _client().post(
        "/api/v1/flows/runs/explicit-decision-run/resume", json={},
    )

    assert response.status_code == 400
    assert store.load_run("explicit-decision-run").status == "paused_approval"
    assert aq.queue().list(status="pending", limit=100) == []


def test_approval_resume_refuses_an_authenticated_wrong_assignee(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import api as api_module
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(api_module, "caller_principal", lambda _request: "user:bob")
    saved = store.save_flow(Flow(
        id="assigned-approval",
        name="Assigned",
        start="gate",
        nodes={"gate": FlowNode(
            id="gate", kind="approval", prompt="ok?", assignee="@alice",
        )},
    ))
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    store.save_run(store.FlowRun(
        run_id="assigned-approval-run",
        flow_id=saved.id,
        status="paused_approval",
        cursor="gate",
        human={"choices": [], "assignee": "@alice", "form": []},
        definition_digest=release["definition_digest"],
        release_digest=release["release_digest"],
        release_id=release["release_id"],
        definition_version=release["definition_version"],
        definition_revision=release["definition_revision"],
        subflow_digests=release["subflow_digests"],
    ))
    binding = _attach_test_approval_card("assigned-approval-run")

    response = _client().post(
        "/api/v1/flows/runs/assigned-approval-run/resume",
        json={"decision": "approved", "approval_binding_sha256": binding},
    )

    assert response.status_code == 403
    assert store.load_run("assigned-approval-run").status == "paused_approval"
    assert aq.queue().list(status="pending", limit=100) == []


def test_manual_run_and_resume_jobs_capture_the_active_tenant(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)

    token = set_tenant("tenant-a")
    try:
        saved = store.save_flow(Flow(
            id="tenant-manual", name="tenant manual", start="gate", nodes={
                "gate": FlowNode(id="gate", kind="approval", prompt="approve?"),
            }))
        store.publish_flow(
            saved.id,
            expected_version=saved.version,
            expected_revision=saved.revision,
        )
        run_id, deduplicated = aq.enqueue_flow_run_once(
            "tenant-manual", {"value": 1}, origin="manual")
        aq.enqueue_flow_resume("tenant-manual", run_id, "approved")
        pending = aq.queue().list(status="pending")
        run_job = next(j for j in pending if j.kind == aq.FLOW_RUN_KIND)
        resume_job = next(j for j in pending if j.kind == aq.FLOW_RESUME_KIND)
        placeholder = store.load_run(run_id)
    finally:
        reset_tenant(token)

    assert deduplicated is False
    assert run_job.payload["tenant"] == "tenant-a"
    assert resume_job.payload["tenant"] == "tenant-a"
    assert placeholder is not None and placeholder.definition_digest


def test_durable_flow_identity_survives_queueing_and_applies_revocation_floor(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    store.save_flow(Flow(
        id="identity", name="identity", start="a", owner="user:alice",
        nodes={"a": FlowNode(id="a", kind="agent", brief="work")},
    ))
    grants = [frozenset({"finance", "legal"})]
    monkeypatch.setattr(
        "maverick.suite_grants.granted_suites", lambda principal: grants[0])
    run_id = aq.enqueue_flow_run(
        "identity", {}, owner="user:alice", channel="api", user_id="alice")
    run = store.load_run(run_id)
    assert run is not None
    assert run.execution_channel == "api"
    assert run.execution_user_id == "alice"
    assert run.allowed_suites == ["finance", "legal"]

    # A grant narrowed while the job waited. Dispatch intersects current policy
    # with the enqueue-time grant; it never widens from stale queue metadata.
    grants[0] = frozenset({"finance"})
    agent_kwargs = {}
    action_kwargs = {}
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda world, **kwargs: agent_kwargs.update(kwargs) or (lambda *a: ("", 1.0)),
    )
    monkeypatch.setattr(
        execution,
        "default_action_runner",
        lambda world, sandbox=None, **kwargs: (
            action_kwargs.update(kwargs) or (lambda *a: ("", 1.0))
        ),
    )
    aq._flow_runners(run)

    assert agent_kwargs["channel"] == "api"
    assert agent_kwargs["user_id"] == "alice"
    assert agent_kwargs["allowed_suites"] == frozenset({"finance"})
    assert agent_kwargs["concurrency_principal"] == "user:alice"
    assert action_kwargs == {"channel": "api", "user_id": "alice"}


def test_queued_flow_fails_closed_when_operate_role_is_revoked(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    saved = store.save_flow(Flow(
        id="revoked", name="revoked", start="a", owner="user:alice",
        nodes={"a": FlowNode(id="a", kind="agent", brief="must not run")},
    ))
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    run_id = aq.enqueue_flow_run(
        "revoked", {}, owner="user:alice", channel="api", user_id="alice")
    monkeypatch.setattr(
        "maverick_dashboard.auth.role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda *args, **kwargs: pytest.fail("revoked run built a live runner"),
    )
    job = next(
        job for job in aq.queue().list(status="pending")
        if job.kind == aq.FLOW_RUN_KIND and job.payload.get("run_id") == run_id
    )

    aq._handle_flow_run(SimpleNamespace(payload=job.payload))

    run = store.load_run(run_id)
    assert run is not None
    assert run.status == "failed"
    assert "authorization was revoked" in run.error


@pytest.mark.parametrize("policy_failure", ["inactive", "unreadable"])
def test_queued_flow_fails_closed_on_scim_lifecycle_failure(
    monkeypatch, tmp_path, policy_failure,
):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    saved = store.save_flow(Flow(
        id="scim-revoked",
        name="scim-revoked",
        start="a",
        owner="user:alice",
        nodes={"a": FlowNode(id="a", kind="agent", brief="must not run")},
    ))
    store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    run_id = aq.enqueue_flow_run(
        "scim-revoked",
        {},
        owner="user:alice",
        channel="api",
        user_id="alice",
    )
    if policy_failure == "inactive":
        monkeypatch.setattr(
            "maverick_dashboard.scim_groups.active_for_principal", lambda _p: False
        )
    else:
        monkeypatch.setattr(
            "maverick_dashboard.scim_groups.active_for_principal",
            lambda _p: (_ for _ in ()).throw(OSError("policy store unavailable")),
        )
    monkeypatch.setattr(
        execution,
        "default_agent_runner",
        lambda *args, **kwargs: pytest.fail("revoked run built a live runner"),
    )
    job = next(
        job for job in aq.queue().list(status="pending")
        if job.kind == aq.FLOW_RUN_KIND and job.payload.get("run_id") == run_id
    )

    aq._handle_flow_run(SimpleNamespace(payload=job.payload))

    run = store.load_run(run_id)
    assert run is not None and run.status == "failed"
    assert "authorization was revoked" in run.error


def test_queued_run_outbox_repairs_a_missing_job_without_losing_dry_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    assert _client().post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    digest, version, subflows = store.snapshot_current_flow_bundle("demo")
    store.save_run(store.FlowRun(
        run_id="orphan", flow_id="demo", status="queued",
        input_data={"order": "X"}, data={"order": "X"}, dry_run=True,
        definition_digest=digest, definition_version=version,
        subflow_digests=subflows,
    ))

    aq._repair_queued_flow_outbox()
    jobs = [j for j in aq._pending(aq.FLOW_RUN_KIND)
            if j.payload.get("run_id") == "orphan"]
    assert len(jobs) == 1
    assert jobs[0].payload["dry_run"] is True
    # Idempotent startup reconciliation never publishes a duplicate.
    aq._repair_queued_flow_outbox()
    assert len([j for j in aq._pending(aq.FLOW_RUN_KIND)
                if j.payload.get("run_id") == "orphan"]) == 1


def test_legacy_run_without_immutable_plan_fails_closed(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    assert _client().post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    store.save_run(store.FlowRun(
        run_id="legacy-unpinned", flow_id="demo", status="queued",
    ))
    aq._repair_queued_flow_outbox()
    run = store.load_run("legacy-unpinned")
    assert run.status == "failed"
    assert "replacement run" in run.error
    assert not any(
        job.payload.get("run_id") == run.run_id
        for job in aq._pending(aq.FLOW_RUN_KIND)
    )


def test_idempotency_claim_survives_crash_before_queue_publish(monkeypatch, tmp_path):
    """A process death in the JSON-to-SQLite gap repairs, never duplicates."""
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    assert _client().post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    q = aq.queue()
    real_enqueue = q.enqueue

    def _crash(*args, **kwargs):
        raise SystemExit("simulated process death")

    monkeypatch.setattr(q, "enqueue", _crash)
    with pytest.raises(SystemExit):
        aq.enqueue_flow_run_once("demo", {"order": "X"}, idem_key="delivery-1")

    created = store.list_runs(flow_id="demo", limit=None)[0]
    reserved = store.find_run_by_idem(
        "demo",
        "delivery-1",
        within=0,
        release_id=created.release_id,
        owner=created.owner,
    )
    assert reserved is not None and reserved.status == "queued"
    monkeypatch.setattr(q, "enqueue", real_enqueue)

    run_id, deduplicated = aq.enqueue_flow_run_once(
        "demo", {"order": "X"}, idem_key="delivery-1")
    assert deduplicated is True and run_id == reserved.run_id
    jobs = [j for j in aq._pending(aq.FLOW_RUN_KIND)
            if j.payload.get("run_id") == reserved.run_id]
    assert len(jobs) == 1


def test_ambiguous_post_commit_enqueue_error_never_duplicates_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    assert _client().post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    q = aq.queue()
    real_enqueue = q.enqueue

    def _commit_then_raise(*args, **kwargs):
        real_enqueue(*args, **kwargs)
        raise RuntimeError("driver lost acknowledgement after commit")

    monkeypatch.setattr(q, "enqueue", _commit_then_raise)
    with pytest.raises(RuntimeError, match="lost acknowledgement"):
        aq.enqueue_flow_run_once("demo", {}, idem_key="delivery-ambiguous")

    created = store.list_runs(flow_id="demo", limit=None)[0]
    reserved = store.find_run_by_idem(
        "demo",
        "delivery-ambiguous",
        within=0,
        release_id=created.release_id,
        owner=created.owner,
    )
    assert reserved is not None and reserved.status == "queued"
    monkeypatch.setattr(q, "enqueue", real_enqueue)
    run_id, deduplicated = aq.enqueue_flow_run_once(
        "demo", {}, idem_key="delivery-ambiguous")
    assert deduplicated is True and run_id == reserved.run_id
    jobs = [j for j in aq._pending(aq.FLOW_RUN_KIND)
            if j.payload.get("run_id") == reserved.run_id]
    assert len(jobs) == 1


def test_composite_idempotency_lookup_verifies_a_legacy_root_claim(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store

    pin = _store_published_pin("legacy-claim")
    run = store.FlowRun(
        run_id="legacy-indexed",
        flow_id="legacy-claim",
        status="completed",
        idem_key="event-1",
        **pin,
    )
    store.save_run(run)
    store.save_idempotency_claim(
        run.flow_id,
        run.idem_key,
        run.run_id,
        definition_digest=run.definition_digest,
        owner=run.owner,
    )

    found = store.find_run_by_idem(
        run.flow_id,
        run.idem_key,
        within=0,
        definition_digest=run.definition_digest,
        release_id=run.release_id,
        owner=run.owner,
    )
    assert found is not None and found.run_id == run.run_id


class _Job:
    def __init__(self, payload):
        self.payload = payload


def _singleton_flow(mc=1):
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    flow = Flow(id="s", name="S", start="a", max_concurrent=mc,
                nodes={"a": FlowNode(id="a", kind="agent", brief="go")})
    saved = store.save_flow(flow)
    return store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )


def _release_pin(release):
    return {
        "definition_digest": release["definition_digest"],
        "release_digest": release["release_digest"],
        "release_id": release["release_id"],
        "definition_version": release["definition_version"],
        "definition_revision": release["definition_revision"],
        "subflow_digests": release["subflow_digests"],
    }


def test_singleton_defers_a_run_while_another_is_in_flight(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    release = _singleton_flow(mc=1)
    store.save_run(store.FlowRun(
        run_id="r_active", flow_id="s", status="running",
        **_release_pin(release)))
    store.save_run(store.FlowRun(
        run_id="r_new", flow_id="s", status="queued",
        **_release_pin(release)))
    aq._handle_flow_run(_Job({"flow_id": "s", "run_id": "r_new"}))
    # the slot is taken -> the new run is NOT executed, it's left queued (deferred)
    assert store.load_run("r_new").status == "queued"


def test_singleton_defers_while_another_run_waits_for_an_event(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    release = _singleton_flow(mc=1)
    store.save_run(store.FlowRun(
        run_id="r_waiting", flow_id="s", status="paused_event", cursor="wait",
        **_release_pin(release)))
    store.save_run(store.FlowRun(
        run_id="r_new", flow_id="s", status="queued",
        **_release_pin(release)))

    aq._handle_flow_run(_Job({"flow_id": "s", "run_id": "r_new"}))

    # A wait-event run is live work and continues to own the singleton slot.
    assert store.load_run("r_new").status == "queued"


def test_singleton_defers_when_active_run_is_older_than_recent_window(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    release = _singleton_flow(mc=1)
    now = [1_000.0]
    monkeypatch.setattr(store.time, "time", lambda: now[0])
    store.save_run(store.FlowRun(
        run_id="r_active", flow_id="s", status="running",
        **_release_pin(release)))
    now[0] = 2_000.0
    for i in range(201):
        store.save_run(store.FlowRun(run_id=f"r_done_{i}", flow_id="s", status="completed"))
    store.save_run(store.FlowRun(
        run_id="r_new", flow_id="s", status="queued",
        **_release_pin(release)))

    assert all(r.run_id != "r_active" for r in store.list_runs(flow_id="s", limit=200))

    aq._handle_flow_run(_Job({"flow_id": "s", "run_id": "r_new"}))

    # Even if many newer runs push the active run out of the recent list window,
    # the singleton cap still sees it and leaves the new run queued for retry.
    assert store.load_run("r_new").status == "queued"


def test_singleton_runs_when_the_slot_is_free(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(execution, "default_agent_runner",
                        lambda world, **k: (lambda brief, d, **kw: ("ok", 1.0)))
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs: (lambda t, p, d: ("", None)))
    release = _singleton_flow(mc=1)
    store.save_run(store.FlowRun(
        run_id="r_new", flow_id="s", status="queued",
        **_release_pin(release)))
    aq._handle_flow_run(_Job({"flow_id": "s", "run_id": "r_new"}))
    assert store.load_run("r_new").status == "completed"   # no sibling -> claimed + ran


def test_singleton_skips_once_the_defer_budget_is_spent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    release = _singleton_flow(mc=1)
    store.save_run(store.FlowRun(
        run_id="r_active", flow_id="s", status="paused_approval",
        **_release_pin(release)))
    store.save_run(store.FlowRun(
        run_id="r_new", flow_id="s", status="queued",
        **_release_pin(release)))
    # a run that has already been deferred to the limit is dropped, not re-queued forever
    aq._handle_flow_run(_Job({"flow_id": "s", "run_id": "r_new",
                              "_slot_defers": aq._SINGLETON_MAX_DEFERS}))
    assert store.load_run("r_new").status == "skipped_concurrency"


def test_unlimited_flow_ignores_the_slot_guard(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution, store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(execution, "default_agent_runner",
                        lambda world, **k: (lambda brief, d, **kw: ("ok", 1.0)))
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs: (lambda t, p, d: ("", None)))
    flow = Flow(id="u", name="U", start="a", max_concurrent=0,
                nodes={"a": FlowNode(id="a", kind="agent", brief="go")})
    saved = store.save_flow(flow)
    release = store.publish_flow(
        saved.id,
        expected_version=saved.version,
        expected_revision=saved.revision,
    )
    store.save_run(store.FlowRun(
        run_id="ua", flow_id="u", status="running",
        **_release_pin(release)))   # sibling
    store.save_run(store.FlowRun(
        run_id="ub", flow_id="u", status="queued",
        **_release_pin(release)))
    aq._handle_flow_run(_Job({"flow_id": "u", "run_id": "ub"}))
    assert store.load_run("ub").status == "completed"   # 0 = unlimited -> runs anyway


def test_runs_are_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import api
    store.save_run(store.FlowRun(run_id="r1", flow_id="demo", status="completed", owner="user:alice"))
    store.save_run(store.FlowRun(run_id="r2", flow_id="demo", status="completed", owner="user:bob"))
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    ids = {r["run_id"] for r in _client().get("/api/v1/flows/runs").json()["runs"]}
    assert ids == {"r1"}


def test_runs_list_carries_origin_and_cost(monkeypatch, tmp_path):
    # The list endpoint surfaces how each run was triggered and its $ cost so the
    # automations UI can label cron/event/retry runs at a glance (not just manual).
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    store.save_run(store.FlowRun(run_id="r1", flow_id="demo", status="completed",
                                 origin="cron:demo", cost_dollars=0.42))
    row = _client().get("/api/v1/flows/runs").json()["runs"][0]
    assert row["origin"] == "cron:demo" and row["cost_dollars"] == 0.42


def test_resume_of_non_paused_run_is_409(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    store.save_run(store.FlowRun(run_id="rc", flow_id="demo", status="completed"))
    r = _client().post("/api/v1/flows/runs/rc/resume", json={"decision": "approved"})
    assert r.status_code == 409


def test_delay_sweep_reenqueues_only_due_runs(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    pin = _store_published_pin()
    store.save_run(store.FlowRun(run_id="d1", flow_id="demo",
                                 status="paused_delay", resume_at=1.0,
                                 **pin))                                        # due
    store.save_run(store.FlowRun(run_id="d2", flow_id="demo",
                                 status="paused_delay", resume_at=9e18,
                                 **pin))                                         # not yet
    aq._handle_flow_sweep(None)
    jobs = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLOW_RESUME_KIND]
    assert {j.payload["run_id"] for j in jobs} == {"d1"}


def test_sweep_rejects_expired_approvals_but_never_paused_events(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    pin = _store_published_approval_pin()
    store.save_run(store.FlowRun(
        run_id="ap1", flow_id="approval-expiry", status="paused_approval",
        cursor="approve", prompt="approve?", resume_at=1.0, **pin,
    ))                                                                        # expired
    _attach_test_approval_card("ap1")
    store.save_run(store.FlowRun(
        run_id="ap2", flow_id="approval-expiry", status="paused_approval",
        cursor="approve", prompt="approve?", resume_at=9e18, **pin,
    ))                                                                        # still open
    _attach_test_approval_card("ap2")
    store.save_run(store.FlowRun(run_id="ev1", flow_id="approval-expiry",
                                 status="paused_event", resume_at=1.0,
                                 **pin))                                       # event-only
    aq._handle_flow_sweep(None)
    jobs = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLOW_RESUME_KIND]
    assert {j.payload["run_id"] for j in jobs} == {"ap1"}
    # expiry rides the out-of-band flag -> the runner routes on_expire or rejects
    assert jobs[0].payload["expired"] is True and "decision" not in jobs[0].payload


def test_sweep_visits_named_tenants_and_preserves_resume_namespace(
    monkeypatch, tmp_path,
):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr("maverick.client.client_id", lambda: None)
    from maverick.flow import store
    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick.tenant import registry
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    registry.create_tenant("acme")
    shared_pin = _store_published_pin()
    store.save_run(store.FlowRun(
        run_id="shared-delay",
        flow_id="demo",
        status="paused_delay",
        resume_at=1.0,
        **shared_pin,
    ))
    token = set_tenant("acme")
    try:
        private_pin = _store_published_pin()
        private_approval_pin = _store_published_approval_pin()
        store.save_run(store.FlowRun(
            run_id="private-delay",
            flow_id="demo",
            status="paused_delay",
            resume_at=1.0,
            **private_pin,
        ))
        store.save_run(store.FlowRun(
            run_id="private-approval",
            flow_id="approval-expiry",
            status="paused_approval",
            cursor="approve",
            prompt="approve?",
            resume_at=1.0,
            **private_approval_pin,
        ))
        _attach_test_approval_card("private-approval")
    finally:
        reset_tenant(token)

    ambient = set_tenant("ambient-poison")
    try:
        aq._handle_flow_sweep(None)
        assert current_tenant_id() == "ambient-poison"
    finally:
        reset_tenant(ambient)

    jobs = {
        job.payload["run_id"]: job.payload
        for job in aq.queue().list(status="pending")
        if job.kind == aq.FLOW_RESUME_KIND
    }
    assert "tenant" not in jobs["shared-delay"]
    assert jobs["private-delay"]["tenant"] == "acme"
    assert jobs["private-approval"]["tenant"] == "acme"
    assert jobs["private-approval"]["expired"] is True


def test_retry_of_paused_event_run_is_409_not_a_duplicate(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201
    store.save_run(store.FlowRun(run_id="pe", flow_id="demo", status="paused_event",
                                 cursor="w"))
    r = c.post("/api/v1/flows/runs/pe/retry")
    assert r.status_code == 409 and "still active" in r.json()["detail"]
    # no duplicate flow_run job was enqueued
    jobs = [j for j in aq.queue().list(status="pending") if j.kind == aq.FLOW_RUN_KIND]
    assert jobs == []


def test_paused_event_run_resumes_via_api_with_event_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(execution, "default_agent_runner",
                        lambda world, **k: lambda brief, d: (f"ran:{brief}", 1.0))
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs: lambda t, p, d: ("", 1.0))
    c = _client()
    flow = {"id": "fev", "name": "f", "start": "w", "nodes": [
        {"id": "w", "kind": "wait_event", "prompt": "cb", "next": "a"},
        {"id": "a", "kind": "agent", "brief": "handle {{payload}}", "output": "r"},
    ]}
    assert c.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    _publish(c, "fev")
    run_id = c.post("/api/v1/flows/fev/run", json={"data": {}}).json()["run_id"]
    _drain(aq)
    assert c.get(f"/api/v1/flows/runs/{run_id}").json()["status"] == "paused_event"
    r = c.post(f"/api/v1/flows/runs/{run_id}/resume",
               json={"inputs": {"payload": "evt-7"}})
    assert r.status_code == 200
    _drain(aq)
    done = c.get(f"/api/v1/flows/runs/{run_id}").json()
    assert done["status"] == "completed" and done["data"]["r"] == "ran:handle evt-7"


def test_choice_approval_verdict_flows_through_resume(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    monkeypatch.setattr(execution, "default_agent_runner",
                        lambda world, **k: lambda brief, d: (f"ran:{brief}", 1.0))
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs: lambda t, p, d: ("", 1.0))
    c = _client()
    flow = {"id": "fch", "name": "f", "start": "a", "nodes": [
        {"id": "a", "kind": "approval", "prompt": "ship or hold?",
         "choices": ["ship", "hold"], "output": "verdict", "next": "s"},
        {"id": "s", "kind": "switch", "condition": "verdict",
         "cases": [{"value": "ship", "to": "go"}], "next": "no"},
        {"id": "go", "kind": "agent", "brief": "shipping", "output": "r"},
        {"id": "no", "kind": "agent", "brief": "holding", "output": "r"},
    ]}
    assert c.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    _publish(c, "fch")
    run_id = c.post("/api/v1/flows/fch/run", json={"data": {}}).json()["run_id"]
    _drain(aq)
    r = c.post(
        f"/api/v1/flows/runs/{run_id}/resume",
        json=_approval_resume_body(c, run_id, "ship"),
    )
    assert r.status_code == 200, r.text
    _drain(aq)
    done = c.get(f"/api/v1/flows/runs/{run_id}").json()
    assert done["status"] == "completed"
    assert done["data"]["verdict"] == "ship" and done["data"]["r"] == "ran:shipping"


def test_draft_endpoint_returns_a_flow(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    # bypass the provider-key guard + the real LLM
    import maverick.flow.draft as draft_mod
    from maverick.flow.ir import single_agent_flow
    monkeypatch.setattr(
        "maverick_dashboard._shared.require_provider_or_400",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(draft_mod, "draft_flow",
                        lambda desc, **k: (single_agent_flow(k.get("flow_id", ""), "Drafted", desc), ["note"]))
    r = _client().post("/api/v1/flows/draft", json={"description": "email me on new leads"})
    assert r.status_code == 200
    body = r.json()
    assert body["flow"]["nodes"][0]["kind"] == "agent"
    assert body["notes"] == ["note"]


def test_draft_endpoint_ranks_full_live_catalog_and_passes_contracts(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.flow.draft as draft_mod
    from maverick.flow.ir import single_agent_flow
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod

    monkeypatch.setattr(
        "maverick_dashboard._shared.require_provider_or_400",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(api_mod, "_TOOL_INDEX_CACHE", [
        {"name": "slack_bot", "description": "Post a team message",
         "params": ["channel", "text"], "category": "Communication"},
        {"name": "pagerduty_incidents",
         "description": "Create an alert for the on-call engineer",
         "params": ["summary"], "category": "Operations"},
        {"name": "image_resize", "description": "Resize an image",
         "params": ["path"], "category": "Other"},
    ])
    monkeypatch.setattr(api_mod, "_TOOL_SCHEMA_CACHE", {
        "pagerduty_incidents": {
            "type": "object", "properties": {"summary": {"type": "string"}},
            "required": ["summary"],
        },
    })
    rate_sources = []
    monkeypatch.setattr(
        app_mod, "check_goal_rate_limit",
        lambda request, source=None, **kwargs: rate_sources.append(source),
    )
    seen = {}

    def fake_draft(desc, **kwargs):
        seen.update(kwargs)
        return single_agent_flow(kwargs.get("flow_id", ""), "Drafted", desc), []

    monkeypatch.setattr(draft_mod, "draft_flow", fake_draft)
    r = _client().post(
        "/api/v1/flows/draft",
        json={"description": "page the on-call engineer when production breaks"},
    )

    assert r.status_code == 200, r.text
    assert seen["tools"][0] == "pagerduty_incidents"
    assert "image_resize" not in seen["tools"]
    assert seen["tool_schemas"]["pagerduty_incidents"]["required"] == ["summary"]
    assert rate_sources == ["flow-authoring"]


def test_live_authoring_tool_cache_is_tenant_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick.paths import current_tenant_id, reset_tenant, set_tenant
    from maverick_dashboard import api as api_mod

    monkeypatch.setattr(api_mod, "_TOOL_INDEX_CACHE", None)
    monkeypatch.setattr(api_mod, "_TOOL_SCHEMA_CACHE", None)
    monkeypatch.setattr(api_mod, "_TOOL_CATALOG_CACHE", {})
    monkeypatch.setattr("maverick.flow.ir.action_tool_policy_error", lambda name: "")

    class _Registry:
        def all(self):
            tenant = current_tenant_id() or "shared"
            return [SimpleNamespace(
                name=f"{tenant}_private_tool",
                description=f"private to {tenant}",
                input_schema={"type": "object", "properties": {}},
            )]

    monkeypatch.setattr("maverick.tools.base_registry", lambda *args, **kwargs: _Registry())
    token = set_tenant("tenant-a")
    try:
        tenant_a = api_mod._live_tool_index()
    finally:
        reset_tenant(token)
    token = set_tenant("tenant-b")
    try:
        tenant_b = api_mod._live_tool_index()
    finally:
        reset_tenant(token)

    assert [item["name"] for item in tenant_a] == ["tenant-a_private_tool"]
    assert [item["name"] for item in tenant_b] == ["tenant-b_private_tool"]


def test_live_authoring_tool_cache_is_execution_identity_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from types import SimpleNamespace

    from maverick_dashboard import api as api_mod

    monkeypatch.setattr(api_mod, "_TOOL_INDEX_CACHE", None)
    monkeypatch.setattr(api_mod, "_TOOL_SCHEMA_CACHE", None)
    monkeypatch.setattr(api_mod, "_TOOL_CATALOG_CACHE", {})
    monkeypatch.setattr("maverick.flow.ir.action_tool_policy_error", lambda name: "")

    class _Registry:
        def __init__(self, user_id):
            self.user_id = user_id

        def all(self):
            return [SimpleNamespace(
                name=f"{self.user_id}_allowed_tool",
                description=f"private to {self.user_id}",
                input_schema={"type": "object", "properties": {}},
            )]

    seen = []

    def registry(*args, **kwargs):
        seen.append((kwargs.get("channel"), kwargs.get("user_id")))
        return _Registry(kwargs.get("user_id"))

    monkeypatch.setattr("maverick.tools.base_registry", registry)
    alice = api_mod._live_tool_index(channel="api", user_id="alice")
    bob = api_mod._live_tool_index(channel="api", user_id="bob")
    alice_cached = api_mod._live_tool_index(channel="api", user_id="alice")

    assert [item["name"] for item in alice] == ["alice_allowed_tool"]
    assert [item["name"] for item in bob] == ["bob_allowed_tool"]
    assert alice_cached == alice
    assert seen == [("api", "alice"), ("api", "bob")]


@pytest.mark.parametrize(("stop", "words"), [
    ("halted", "kill switch"), ("budget", "budget"),
])
def test_draft_names_a_kill_switch_or_budget_stop(monkeypatch, tmp_path, stop, words):
    _isolate(monkeypatch, tmp_path)
    import maverick.flow.draft as draft_mod
    from maverick.budget import BudgetExceeded
    from maverick.killswitch import Halted

    monkeypatch.setattr(
        "maverick_dashboard._shared.require_provider_or_400",
        lambda **_kwargs: None,
    )

    def stopped(*_args, **_kwargs):
        raise Halted("operator", "file") if stop == "halted" else BudgetExceeded("dollars")

    monkeypatch.setattr(draft_mod, "draft_flow", stopped)
    r = _client().post("/api/v1/flows/draft", json={"description": "x"})
    assert r.status_code == 409, r.text
    assert words in r.json()["detail"]


def test_draft_requires_provider(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from fastapi import HTTPException

    def unavailable(*, role=None):
        raise HTTPException(status_code=400, detail=f"missing {role} route")

    monkeypatch.setattr("maverick_dashboard._shared.require_provider_or_400", unavailable)
    r = _client().post("/api/v1/flows/draft", json={"description": "x"})
    assert r.status_code == 400


def test_chat_endpoint_returns_reply_and_patched_flow(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.flow.chat as chat_mod
    from maverick.flow.chat import FlowChatResult
    from maverick.flow.ir import Flow
    monkeypatch.setattr(
        "maverick_dashboard._shared.require_provider_or_400",
        lambda **_kwargs: None,
    )
    seen = {}

    def fake_chat(message, *, flow=None, history=(), run=None, **k):
        seen.update(message=message, flow=flow, history=list(history), run=run)
        return FlowChatResult(reply="Added it.", flow=flow,
                              applied=["add delay node d1 after a"])
    monkeypatch.setattr(chat_mod, "chat_flow", fake_chat)
    r = _client().post("/api/v1/flows/chat", json={
        "message": "add a 5 minute delay",
        "flow": _FLOW,
        "history": [{"role": "user", "content": "hi"}],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["reply"] == "Added it."
    assert body["flow"]["id"] == "demo" and body["applied"]
    assert isinstance(seen["flow"], Flow) and seen["history"][0]["content"] == "hi"


def test_chat_endpoint_ranks_new_tools_and_keeps_live_existing_binding(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.flow.chat as chat_mod
    from maverick.flow.chat import FlowChatResult
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod

    monkeypatch.setattr(
        "maverick_dashboard._shared.require_provider_or_400",
        lambda **_kwargs: None,
    )
    monkeypatch.setattr(api_mod, "_TOOL_INDEX_CACHE", [
        {"name": "notify", "description": "Send a notification",
         "params": ["m"], "category": "Communication"},
        {"name": "rare_crm_sync", "description": "Sync a customer lead into the CRM",
         "params": ["lead"], "category": "Sales"},
        {"name": "image_resize", "description": "Resize an image",
         "params": ["path"], "category": "Other"},
    ])
    monkeypatch.setattr(api_mod, "_TOOL_SCHEMA_CACHE", {
        "notify": {"type": "object", "properties": {"m": {"type": "string"}}},
        "rare_crm_sync": {
            "type": "object", "properties": {"lead": {"type": "object"}},
            "required": ["lead"],
        },
    })
    rate_sources = []
    monkeypatch.setattr(
        app_mod, "check_goal_rate_limit",
        lambda request, source=None, **kwargs: rate_sources.append(source),
    )
    seen = {}

    def fake_chat(message, **kwargs):
        seen.update(kwargs)
        return FlowChatResult(reply="Ready.")

    monkeypatch.setattr(chat_mod, "chat_flow", fake_chat)
    r = _client().post("/api/v1/flows/chat", json={
        "message": "sync each customer lead into our CRM", "flow": _FLOW,
    })

    assert r.status_code == 200, r.text
    assert "rare_crm_sync" in seen["tools"]
    assert "notify" in seen["tools"]  # current action remains bindable
    assert "image_resize" not in seen["tools"]
    assert seen["tool_schemas"]["rare_crm_sync"]["required"] == ["lead"]
    assert rate_sources == ["flow-authoring"]


def test_chat_grounds_in_an_owned_run(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.flow.chat as chat_mod
    from maverick.flow import store
    from maverick.flow.chat import FlowChatResult
    monkeypatch.setattr(
        "maverick_dashboard._shared.require_provider_or_400",
        lambda **_kwargs: None,
    )
    store.save_run(store.FlowRun(run_id="rf", flow_id="demo", status="failed",
                                 cursor="b", error="node 'b': boom"))
    seen = {}

    def fake_chat(message, *, run=None, **k):
        seen["run"] = run
        return FlowChatResult(reply="b failed: boom")
    monkeypatch.setattr(chat_mod, "chat_flow", fake_chat)
    r = _client().post("/api/v1/flows/chat", json={
        "message": "why did it fail?", "flow": _FLOW, "run_id": "rf"})
    assert r.status_code == 200
    assert seen["run"]["cursor"] == "b" and "boom" in seen["run"]["error"]
    # an unknown run id is a 404, not a silent no-context turn
    assert _client().post("/api/v1/flows/chat", json={
        "message": "x", "flow": _FLOW, "run_id": "nope"}).status_code == 404


def test_chat_requires_provider(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from fastapi import HTTPException

    def unavailable(*, role=None):
        raise HTTPException(status_code=400, detail=f"missing {role} route")

    monkeypatch.setattr("maverick_dashboard._shared.require_provider_or_400", unavailable)
    r = _client().post("/api/v1/flows/chat", json={"message": "x", "flow": _FLOW})
    assert r.status_code == 400


def test_retry_from_failure_resumes_at_failed_node(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    calls = []

    def _fake_agent(world, **k):
        def run(brief, d):
            calls.append(brief)
            return (f"ran:{brief}", 1.0)
        return run
    monkeypatch.setattr(execution, "default_agent_runner", _fake_agent)
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs: lambda t, p, d: ("sent", 1.0))
    c = _client()
    flow = {"id": "fret", "name": "f", "start": "a", "nodes": [
        {"id": "a", "kind": "agent", "brief": "prep", "next": "b", "output": "r1"},
        {"id": "b", "kind": "action", "tool": "web_search", "params": {}, "output": "r2"},
    ]}
    assert c.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    release = _publish(c, "fret")
    published, metadata = store.load_published_bundle("fret")
    digest = metadata["definition_digest"]
    version = published.version
    subflows = metadata["subflow_digests"]
    # a run that failed AT node b, with node a's work already done
    store.save_run(store.FlowRun(run_id="rx", flow_id="fret", status="failed",
                                 cursor="b", data={"r1": "ok"},
                                     nodes={"a": {"status": "done", "outcome": 1.0}},
                                     definition_digest=digest, definition_version=version,
                                     release_id=release["published_revision"],
                                     definition_revision=published.revision,
                                 subflow_digests=subflows))
    r = c.post("/api/v1/flows/runs/rx/retry?from_failure=1")
    assert r.status_code == 200, r.text
    assert r.json() == {"run_id": "rx", "status": "resuming", "from_node": "b"}
    _drain(aq)
    done = c.get("/api/v1/flows/runs/rx").json()
    assert done["status"] == "completed" and done["data"]["r2"] == "sent"
    assert calls == []                        # node a was NOT re-run
    # a completed run can't be resumed from failure
    assert c.post("/api/v1/flows/runs/rx/retry?from_failure=1").status_code == 409
    # a failed run with no recorded failure node can't either
    store.save_run(store.FlowRun(
        run_id="ry", flow_id="fret", status="failed",
        definition_digest=digest, definition_version=version,
        definition_revision=published.revision,
        subflow_digests=subflows))
    assert c.post("/api/v1/flows/runs/ry/retry?from_failure=1").status_code == 409


def test_retry_of_a_failed_gated_action_is_refused_visibly(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution, store
    from maverick_dashboard import automation_queue as aq
    _reset_aq(monkeypatch, aq)
    sent = []
    monkeypatch.setattr(execution, "default_action_runner",
                        lambda world, sandbox=None, **kwargs:
                        lambda t, p, d: sent.append(t) or ("sent", 1.0))
    c = _client()
    flow = {"id": "fgate", "name": "f", "start": "a", "nodes": [
        {"id": "a", "kind": "approval", "prompt": "ok?", "next": "b"},
        {"id": "b", "kind": "action", "tool": "slack_bot", "params": {"text": "x"}},
    ]}
    assert c.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    release = _publish(c, "fgate")
    published, metadata = store.load_published_bundle("fgate")
    store.save_run(store.FlowRun(
        run_id="rg", flow_id="fgate", status="failed", cursor="b", error="refused",
        definition_digest=metadata["definition_digest"], definition_version=published.version,
        release_id=release["published_revision"], definition_revision=published.revision,
        subflow_digests=metadata["subflow_digests"]))
    r = c.post("/api/v1/flows/runs/rg/retry?from_failure=1")
    assert r.status_code == 409 and "without a new review" in r.json()["detail"]
    # A delivery already queued records the reason instead of dropping it.
    aq.enqueue_flow_resume("fgate", "rg", owner="", from_failure=True)
    _drain(aq)
    run = store.load_run("rg")
    assert run.status == "failed" and "without a new review" in run.error
    assert run.error.startswith("refused | ")
    assert sent == []


def test_budget_held_run_requires_explicit_larger_allowance_and_retains_work(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import execution
    from maverick_dashboard import automation_queue as aq

    _reset_aq(monkeypatch, aq)
    calls = []

    def factory(_world, **_kwargs):
        def run(brief, _data):
            calls.append(brief)
            return brief, 1.0
        return run

    monkeypatch.setattr(execution, "default_agent_runner", factory)
    monkeypatch.setattr(execution, "default_action_runner", lambda *_a, **_k: lambda *_: ("", 1))
    c = _client()
    flow = {"id": "allowance", "name": "allowance", "start": "a", "max_dollars": 5, "nodes": [
        {"id": "a", "kind": "agent", "brief": "first", "next": "b", "output": "first"},
        {"id": "b", "kind": "agent", "brief": "second", "output": "second"},
    ]}
    assert c.post("/api/v1/flows", json={"flow": flow}).status_code == 201
    _publish(c, "allowance")
    rid = c.post("/api/v1/flows/allowance/run", json={"data": {}}).json()["run_id"]
    _drain(aq)
    run = c.get(f"/api/v1/flows/runs/{rid}").json()
    assert run["status"] == "budget_limited" and calls == ["first"]
    with c.stream("GET", f"/api/v1/flows/runs/{rid}/events") as stream:
        frames = "".join(stream.iter_text())
    assert "event: terminal" in frames and '"budget_limited"' in frames
    url = f"/api/v1/flows/runs/{rid}/retry?from_failure=1"
    assert c.post(url).status_code == 409
    assert c.post(url + "&budget_limit_dollars=5").status_code == 409
    assert c.post(url + "&budget_limit_dollars=nan").status_code == 422
    assert c.post(url + "&budget_limit_dollars=10").status_code == 200
    _drain(aq)
    run = c.get(f"/api/v1/flows/runs/{rid}").json()
    assert run["status"] == "completed" and calls == ["first", "second"]
    assert run["cost_dollars"] == 10 and run["budget_limit_dollars"] == 10


def test_run_events_stream_ends_with_terminal_snapshot(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    store.save_run(store.FlowRun(run_id="sse1", flow_id="demo", status="completed",
                                 data={"r": "ok"}, nodes={"a": {"status": "done", "outcome": 1.0}}))
    c = _client()
    with c.stream("GET", "/api/v1/flows/runs/sse1/events") as r:
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/event-stream")
        body = ""
        for chunk in r.iter_text():
            body += chunk
            if "event: terminal" in body:
                break
    assert "event: terminal" in body and '"status": "completed"' in body
    # unknown run 404s before a stream slot is held
    assert c.get("/api/v1/flows/runs/nope/events").status_code == 404


def test_indeterminate_run_is_terminal_and_cannot_be_blindly_retried(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store

    store.save_run(store.FlowRun(
        run_id="ambiguous", flow_id="demo", status="indeterminate",
        cursor="charge", error="external acknowledgement was lost",
    ))
    c = _client()
    retry = c.post("/api/v1/flows/runs/ambiguous/retry")
    assert retry.status_code == 409
    assert "reconcile" in retry.json()["detail"].lower()

    with c.stream("GET", "/api/v1/flows/runs/ambiguous/events") as response:
        body = "".join(response.iter_text())
    assert response.status_code == 200
    assert "event: terminal" in body
    assert '"status": "indeterminate"' in body


def test_run_viewer_page_renders(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/flows/demo/runs/abc123")
    assert r.status_code == 200
    assert 'id="fr-steps"' in r.text and "Open the flow" in r.text


def test_designer_page_has_copilot_and_toolbar(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _client().get("/flows/designer")
    assert r.status_code == 200
    for needle in ('id="fd-chat"', 'id="fd-undo"', 'id="fd-redo"', 'id="fd-fit"',
                   'id="fd-triggers"', 'id="fd-export"', 'data-add="switch"',
                   'data-add="while"', 'data-add="wait_event"', 'data-add="scope"',
                   "/api/v1/flows/chat", "upstreamOutputs", "validateFlow"):
        assert needle in r.text, needle
    # A Chat handoff verifies its workspace and fills the ordinary brief.
    for needle in ("lightwork.authoring-handoff", "/api/v1/templates/draft-context",
                   'id="fd-nl"', 'id="fd-draft"'):
        assert needle in r.text, needle


def test_flow_analytics_aggregates_runs(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    for i in range(3):
        store.save_run(store.FlowRun(run_id=f"c{i}", flow_id="demo", status="completed",
                                     nodes={"a": {"status": "done", "outcome": 1.0, "seconds": 2.0 + i}}))
    store.save_run(store.FlowRun(run_id="f1", flow_id="demo", status="failed",
                                 error="node 'b': connector down"))
    store.save_run(store.FlowRun(run_id="p1", flow_id="demo", status="paused_approval"))
    flows = _client().get("/api/v1/flows/analytics").json()["flows"]
    demo = next(f for f in flows if f["flow_id"] == "demo")
    assert demo["runs"] == 5 and demo["completed"] == 3 and demo["failed"] == 1 and demo["paused"] == 1
    assert demo["success_rate"] == 0.75          # 3 completed / 4 finished
    assert demo["p50_seconds"] >= 2.0 and demo["p95_seconds"] >= demo["p50_seconds"]
    assert demo["top_errors"][0]["error"].startswith("node 'b'")


def test_flow_pages_render_under_strict_undefined(monkeypatch, tmp_path):
    # A literal "{{key}}" in template TEXT (a CSS/JS comment, an example string)
    # is a stray Jinja expression: harmless under the default Undefined (renders
    # empty), but a 500 on any instance configured with StrictUndefined -- which
    # is exactly what broke the flow designer in the field. Render the flow
    # pages (and their included JS) under StrictUndefined so a stray "{{ }}"
    # doc-literal fails HERE instead of on a hardened deployment.
    from jinja2 import StrictUndefined
    from maverick_dashboard.app import templates
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setattr(templates.env, "undefined", StrictUndefined)
    c = _client()
    for path in ("/flows/designer", "/flows/designer/demo", "/workflow-builder",
                 "/flows/analytics", "/connections", "/workflows",
                 "/flows/f/runs/r"):
        assert c.get(path).status_code == 200, path


def test_flow_analytics_page_renders(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import flow

    monkeypatch.setattr(flow, "enabled", lambda: False)
    r = _client().get("/flows/analytics")
    assert r.status_code == 200 and 'id="fa-table"' in r.text
    assert "var flowsEnabled = false;" in r.text
    monkeypatch.setattr(flow, "enabled", lambda: True)
    assert "var flowsEnabled = true;" in _client().get("/flows/analytics").text


def test_flow_schema_endpoint_returns_learned_shapes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    store.save_flow(Flow(
        id="demo", name="demo", start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="work")},
    ))
    store.record_flow_schema("demo", {"order": {"type": "object", "keys": ["total"]}})
    r = _client().get("/api/v1/flows/demo/schema")
    assert r.status_code == 200
    assert r.json()["schema"]["order"] == {"type": "object", "keys": ["total"]}
    assert _client().get("/api/v1/flows/nope/schema").status_code == 404


def test_flow_schema_is_owner_scoped(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import api as api_mod

    store.save_flow(Flow(
        id="private-schema", name="private", start="a", owner="user:alice",
        nodes={"a": FlowNode(id="a", kind="agent", brief="work")},
    ))
    store.record_flow_schema("private-schema", {"customer": {"type": "object"}})
    monkeypatch.setattr(api_mod, "caller_principal", lambda request: "user:bob")
    monkeypatch.setattr(api_mod, "is_dashboard_admin", lambda principal: False)
    monkeypatch.setattr(api_mod, "require_permission", lambda request, permission: None)
    assert _client().get("/api/v1/flows/private-schema/schema").status_code == 404


def test_gallery_returns_valid_starter_flows(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import Flow
    flows = _client().get("/api/v1/flows/gallery").json()["flows"]
    assert len(flows) >= 3
    for g in flows:
        f = Flow.from_dict(g)
        f.id = "gallery-check"
        assert f.validate() == [], (g["name"], f.validate())


def test_tools_search_reaches_the_full_registry(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    curated = c.get("/api/v1/flows/tools").json()["tools"]
    assert curated and any(t["name"] == "slack_bot" for t in curated)
    hits = c.get("/api/v1/flows/tools?q=http").json()["tools"]
    assert hits and all("http" in (t["name"] + t["description"]).lower() for t in hits)
    # name-prefix matches rank first
    assert hits[0]["name"].startswith("http")


def test_tools_catalog_carries_categories(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    body = _client().get("/api/v1/flows/tools").json()
    # Every response advertises the category list so the picker can build its filter.
    assert "Communication" in body["categories"] and body["categories"][-1] == "Other"
    # Curated tools each carry a category.
    assert body["tools"] and all("category" in t for t in body["tools"])


def test_tools_category_filter_narrows_the_registry(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    c = _client()
    comms = c.get("/api/v1/flows/tools?category=Communication").json()["tools"]
    assert comms and all(t["category"] == "Communication" for t in comms)
    # A category + query intersect: only Communication tools matching the query.
    both = c.get("/api/v1/flows/tools?q=slack&category=Communication").json()["tools"]
    assert both and all(t["category"] == "Communication" for t in both)
    assert all("slack" in (t["name"] + t["description"]).lower() for t in both)


def test_tools_category_pages_include_starters_and_every_remaining_action(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import api as api_mod

    rows = [{"name": f"app_{i:03}", "description": "Send a message", "params": [],
             "category": "Communication"} for i in range(110)]
    rows.append({"name": "slack_bot", "description": "Send to Slack", "params": ["text"],
                 "category": "Communication"})
    monkeypatch.setattr(api_mod, "_TOOL_INDEX_CACHE", rows)
    client = _client()
    found = []
    offset = 0
    while offset is not None:
        body = client.get(f"/api/v1/flows/tools?category=Communication&offset={offset}").json()
        assert body["total"] == len(rows)
        if not offset:
            assert body["tools"][0]["name"] == "slack_bot"
        found.extend(row["name"] for row in body["tools"])
        offset = body["next_offset"]
    assert len(found) == len(set(found)) == len(rows)
    assert set(found) == {row["name"] for row in rows}
    assert client.get("/api/v1/flows/tools?offset=-1").status_code == 422
    assert client.get("/api/v1/flows/tools?limit=5000").status_code == 422


def test_designer_opens_a_template_as_a_flow(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    import maverick.templates as tpl
    tdir = tmp_path / ".maverick" / "templates"
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tdir)
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / "weekly-digest.md").write_text(
        "---\nowner: local\ntitle: Weekly digest\nparams: []\n---\nWrite the weekly digest.\n",
        encoding="utf-8")
    r = _client().get("/flows/designer?from_template=weekly-digest")
    assert r.status_code == 200
    assert "Write the weekly digest." in r.text          # seeded as an agent brief
    # an unknown template degrades to a blank canvas, not an error
    assert _client().get("/flows/designer?from_template=nope").status_code == 200


def test_proposals_endpoint(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import node_outcomes, store
    from maverick.flow.ir import Flow, FlowNode
    f = Flow(id="fp", name="f", start="a",
             nodes={"a": FlowNode(id="a", kind="agent", brief="b")})
    store.save_flow(f)
    for _ in range(12):
        node_outcomes.record("fp", "a", "agent", 1.0)   # reliable agent
    props = _client().get("/api/v1/flows/fp/proposals").json()["proposals"]
    assert props and props[0]["to_kind"] == "action"


def test_flow_crud_is_owner_scoped_for_authenticated_non_admin(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import api as api_mod

    current = {"principal": "user:alice"}
    monkeypatch.setattr(api_mod, "caller_principal", lambda request: current["principal"])
    monkeypatch.setattr(api_mod, "is_dashboard_admin", lambda principal: False)
    monkeypatch.setattr(api_mod, "require_permission", lambda request, permission: None)

    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201

    current["principal"] = "user:bob"
    assert c.get("/api/v1/flows").json()["flows"] == []
    assert c.get("/api/v1/flows/demo").status_code == 404
    assert c.post("/api/v1/flows/demo/run", json={"data": {}}).status_code == 404
    assert c.delete("/api/v1/flows/demo").status_code == 404

    updated = {**_FLOW, "name": "Bob overwrite", "schedule": "* * * * *"}
    assert c.post("/api/v1/flows", json={"flow": updated}).status_code == 404

    current["principal"] = "user:alice"
    saved = c.get("/api/v1/flows/demo").json()
    assert saved["name"] == "Demo"
    assert saved["owner"] == "user:alice"


def test_flow_crud_admin_cannot_read_or_edit_employee_content(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import api as api_mod

    current = {"principal": "user:alice", "admin": False}
    monkeypatch.setattr(api_mod, "caller_principal", lambda request: current["principal"])
    monkeypatch.setattr(api_mod, "is_dashboard_admin", lambda principal: current["admin"])
    monkeypatch.setattr(api_mod, "require_permission", lambda request, permission: None)

    c = _client()
    assert c.post("/api/v1/flows", json={"flow": _FLOW}).status_code == 201

    current.update(principal="user:admin", admin=True)
    assert c.get("/api/v1/flows/demo").status_code == 404
    updated = {**_FLOW, "name": "Admin edit", "schedule": "* * * * *"}
    assert c.post("/api/v1/flows", json={"flow": updated}).status_code == 404
    assert c.delete("/api/v1/flows/demo").status_code == 404
    current.update(principal="user:alice", admin=False)
    saved = c.get("/api/v1/flows/demo").json()
    assert saved["name"] == _FLOW["name"]
    assert saved["owner"] == "user:alice"


def test_run_viewer_and_results_pages_read_plainly(monkeypatch, tmp_path):
    from test_support.plain_language import developer_terms

    _isolate(monkeypatch, tmp_path)
    run_page = _client().get("/flows/demo/runs/abc123").text
    results = _client().get("/flows/analytics").text
    for text in (run_page, results):
        assert developer_terms(text) == []
    for phrase in ("Approve exact operation", "Target commitment", "Credential revision",
                   "JSON.stringify(card.budget", "No such run (or not yours)"):
        assert phrase not in run_page
    assert "Information in this run" in run_page and "Technical details" in run_page
    assert "Typical time" in results and ">p50<" not in results
