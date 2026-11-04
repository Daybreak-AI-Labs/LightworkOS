"""Published preview tokens bind dashboard input review to native queue admission.

OIDC verification is fixture supplied; tenant routing, permissions, snapshots,
publication epochs and the persistent queue are the production implementations.
No worker, provider or tool is executed.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from maverick import world_model
from maverick.flow import store
from maverick.flow.ir import Flow, FlowNode
from maverick.oidc import VerifiedPrincipal
from maverick.paths import tenant_scope
from maverick_dashboard import auth, rbac
from maverick_dashboard import automation_queue as aq

TENANT = "published-preview-team"
PATH = "/api/v1/flows/preview"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", TENANT)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(auth, "verify_oidc_token", lambda token, **kw: VerifiedPrincipal(
        sub=token, issuer="https://issuer.example", audience="maverick", claims={"sub": token},
    ))
    monkeypatch.setattr(rbac, "default_role", lambda: "operator")
    monkeypatch.setattr(aq, "_queue", None)
    monkeypatch.setattr(aq, "_worker", None)
    monkeypatch.setattr(aq, "_worker_threads", [])
    from maverick_dashboard.app import app

    # Deliberately do not enter app lifespan: no schedulers or workers start.
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1", "Authorization": "Bearer alice"})


def _publish(*, owner="user:alice", tenant=TENANT):
    with tenant_scope(tenant=tenant):
        flow = store.save_flow(Flow(
            id="preview", name="Published inputs", start="work", owner=owner,
            inputs=[{"key": "account", "type": "text", "required": True}],
            nodes={"work": FlowNode(id="work", kind="agent", brief="Published {{account}}")},
        ))
        release = store.publish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)
        return flow, release


def _republish(*, edit=False):
    with tenant_scope(tenant=TENANT):
        flow = store.load_flow("preview")
        if edit:
            flow.inputs = [{"key": "replacement", "type": "number", "required": True}]
            flow = store.save_flow(flow)
        return store.publish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)


def _assert_not_enqueued():
    with tenant_scope(tenant=TENANT):
        assert store.list_runs(flow_id="preview") == []
        assert aq._pending(aq.FLOW_RUN_KIND) == []


def test_preview_returns_exact_published_inputs_not_saved_draft(client):
    published, release = _publish()
    with tenant_scope(tenant=TENANT):
        draft = store.load_flow("preview")
        draft.name = "Unsaved-to-publication edits"
        draft.inputs = [{"key": "replacement", "type": "number", "required": True}]
        draft.nodes["work"].brief = "Draft-only behavior"
        store.save_flow(draft)
    assert client.get(PATH).json()["inputs"] != published.to_dict()["inputs"]
    response = client.get(PATH + "/published")
    assert response.status_code == 200, response.text
    assert response.json() == {
        "flow": published.to_dict(), "release_id": release["release_id"], "published": True,
        "published_version": published.version, "published_revision": release["release_id"],
        "published_at": release["published_at"],
    }
    started = client.post(PATH + "/run", json={
        "data": {"account": "A"}, "expected_release_id": response.json()["release_id"],
    })
    assert started.status_code == 200, started.text
    with tenant_scope(tenant=TENANT):
        run = store.load_run(started.json()["run_id"])
        assert run.release_id == release["release_id"]
        assert store.load_flow_snapshot(run.definition_digest).to_dict() == published.to_dict()


@pytest.mark.parametrize("edit", [False, True], ids=["same-content-new-epoch", "changed-inputs"])
def test_stale_preview_refused_before_coercion_or_enqueue(client, edit):
    _, first = _publish()
    second = _republish(edit=edit)
    assert first["release_id"] != second["release_id"]
    if not edit:
        assert first["definition_digest"] == second["definition_digest"]
    response = client.post(PATH + "/run", json={
        # Deliberately invalid even for the old release: stale review has priority.
        "data": {}, "expected_release_id": first["release_id"],
    })
    assert response.status_code == 409, response.text
    assert "release" in response.json()["detail"].lower()
    _assert_not_enqueued()


def test_stale_preview_cannot_silently_run_same_content_republication(client):
    _, first = _publish()
    _republish()
    response = client.post(PATH + "/run", json={
        "data": {"account": "A"}, "expected_release_id": first["release_id"],
    })
    assert response.status_code == 409, response.text
    _assert_not_enqueued()


def test_revoked_publication_has_no_preview_and_cannot_start(client):
    flow, release = _publish()
    with tenant_scope(tenant=TENANT):
        store.unpublish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)
    assert client.get(PATH + "/published").status_code == 409
    response = client.post(PATH + "/run", json={"data": {"account": "A"}, "expected_release_id": release["release_id"]})
    assert response.status_code == 409
    _assert_not_enqueued()


@pytest.mark.parametrize("which", ["draft", "published", "both"])
def test_preview_checks_both_current_draft_and_published_owners(client, which):
    _publish(owner="user:bob" if which in {"published", "both"} else "user:alice")
    if which != "both":
        with tenant_scope(tenant=TENANT):
            draft = store.load_flow("preview")
            draft.owner = "user:bob" if which == "draft" else "user:alice"
            store.save_flow(draft)
    assert client.get(PATH + "/published").status_code == 404
    assert client.post(PATH + "/run", json={"data": {"account": "A"}}).status_code == 404
    _assert_not_enqueued()


def test_preview_uses_authenticated_tenant_namespace(client, monkeypatch):
    _publish(tenant="other-team")
    assert client.get(PATH + "/published").status_code == 404
    own_flow, own_release = _publish()
    response = client.get(PATH + "/published")
    assert response.status_code == 200, response.text
    assert response.json()["flow"] == own_flow.to_dict()
    assert response.json()["release_id"] == own_release["release_id"]
    monkeypatch.setenv("MAVERICK_TENANT", "third-team")
    assert client.get(PATH + "/published").status_code == 404


def test_preview_requires_authentication_and_operate_role(client, monkeypatch):
    _publish()
    assert client.get(PATH + "/published", headers={"Authorization": ""}).status_code == 401
    monkeypatch.setattr(rbac, "default_role", lambda: "viewer")
    assert client.get(PATH + "/published").status_code == 403


def test_preview_preserves_integrity_failure(client):
    _publish()
    with tenant_scope(tenant=TENANT):
        pointer = store._published_dir() / "preview.json"
        raw = json.loads(pointer.read_text(encoding="utf-8"))
        raw["definition_digest"] = "0" * 64
        pointer.write_text(json.dumps(raw), encoding="utf-8")
    response = client.get(PATH + "/published")
    assert response.status_code == 409
    assert response.json()["detail"] == "published flow release failed integrity checks"


@pytest.mark.parametrize("token", [None, True, 7, [], {}, "a" * 63, "a" * 65, "A" * 64, "g" * 64, " " + "a" * 64])
def test_expected_release_token_is_strict_and_bounded(client, token):
    _publish()
    response = client.post(PATH + "/run", json={"data": {"account": "A"}, "expected_release_id": token})
    assert response.status_code == 422, response.text
    _assert_not_enqueued()


@pytest.mark.parametrize("explicit_empty", [False, True])
def test_legacy_run_without_preview_token_still_pins_current_release(client, explicit_empty):
    _, release = _publish()
    payload = {"data": {"account": "A"}}
    if explicit_empty:
        payload["expected_release_id"] = ""
    response = client.post(PATH + "/run", json=payload)
    assert response.status_code == 200, response.text
    with tenant_scope(tenant=TENANT):
        assert store.load_run(response.json()["run_id"]).release_id == release["release_id"]


@pytest.mark.parametrize("revoke", [False, True], ids=["republish", "unpublish"])
def test_release_race_between_preview_check_and_queue_creates_no_run(client, monkeypatch, revoke):
    _, release = _publish()
    enqueue = aq.enqueue_published_flow_run_once
    observed_tokens = []

    def change_before_enqueue(*args, **kwargs):
        observed_tokens.append(kwargs["expected_revision"])
        if revoke:
            flow = store.load_flow("preview")
            store.unpublish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)
        else:
            _republish()
        return enqueue(*args, **kwargs)

    monkeypatch.setattr(aq, "enqueue_published_flow_run_once", change_before_enqueue)
    response = client.post(PATH + "/run", json={
        "data": {"account": "A"}, "expected_release_id": release["release_id"],
    })
    assert response.status_code == 409, response.text
    assert observed_tokens == [release["release_id"]]
    _assert_not_enqueued()
