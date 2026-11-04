"""A drained public form can get a fresh link without losing old submissions."""
from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _form(monkeypatch, tmp_path, *, owner=""):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", "1")
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    from maverick.flow import store as flow_store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import event_triggers_store

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard_app._goal_times.clear()
    dashboard_app._goal_times_global.clear()
    saved = flow_store.save_flow(Flow(
        id="review-form", name="Review form", start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="Review the submission")},
        inputs=[{"key": "name", "type": "text"}],
    ))
    published = flow_store.publish_flow(
        saved.id, expected_version=saved.version, expected_revision=saved.revision,
    )
    event_triggers_store.set_trigger(
        "intake", "", "form", config={"token": "legacy.link"},
        flow=saved.id, flow_owner=saved.owner,
        flow_revision=published["release_id"], owner=owner, tenant="",
    )
    return _client()


def _listed(client):
    return next(
        row for row in client.get("/api/v1/event-triggers").json()["triggers"]
        if row["name"] == "intake"
    )


def _rotate(client, generation):
    return client.post(
        "/api/v1/event-triggers/intake/rotate-form-link",
        json={"expected_generation": generation},
    )


def test_drained_full_legacy_form_replaces_link_and_preserves_history(monkeypatch, tmp_path):
    client = _form(monkeypatch, tmp_path)
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    monkeypatch.setattr(form_store, "_MAX_LINES", 1)
    assert client.post("/form/legacy.link", json={"name": "accepted"}).status_code == 201
    old_file = form_store._path("legacy.link")
    old_bytes = old_file.read_bytes()
    assert client.post("/api/v1/event-triggers/poll?name=intake").status_code == 200
    before = _listed(client)
    assert before["pending_submissions"] == 0
    assert client.post("/form/legacy.link", json={"name": "blocked"}).status_code == 507

    changed = _rotate(client, before["binding_revision"])
    assert changed.status_code == 200
    assert changed.headers["cache-control"] == "no-store"
    token = changed.json()["config"]["token"]
    assert token.startswith("form-") and token != "legacy.link"
    assert changed.json()["cursor"] == "0"
    assert old_file.read_bytes() == old_bytes
    assert client.get("/form/legacy.link").status_code == 404
    assert client.post("/form/legacy.link", json={"name": "late"}).status_code == 404
    assert client.post(f"/form/{token}", json={"name": "new"}).status_code == 201
    assert form_store._path(token).read_bytes() != old_bytes

    # A lost success response cannot cause a second replacement.
    assert _rotate(client, before["binding_revision"]).status_code == 409
    assert _listed(client)["config"]["token"] == token
    metadata = event_triggers_store.get_trigger("intake", tenant="")["last_form_link_rotation"]
    assert metadata["old_token_sha256"] == hashlib.sha256(b"legacy.link").hexdigest()
    assert metadata["new_token_sha256"] == hashlib.sha256(token.encode()).hexdigest()
    assert "legacy.link" not in str(metadata)
    assert client.post("/api/v1/event-triggers", json={
        "name": "intake", "source": "form", "flow": "review-form", "config": {},
    }).status_code == 201
    assert event_triggers_store.get_trigger("intake", tenant="")["last_form_link_rotation"] == metadata


def test_waiting_or_damaged_history_refuses_link_replacement(monkeypatch, tmp_path):
    client = _form(monkeypatch, tmp_path)
    from maverick import form_store

    before = _listed(client)
    assert client.post("/form/legacy.link", json={"name": "waiting"}).status_code == 201
    waiting = _rotate(client, before["binding_revision"])
    assert waiting.status_code == 409 and "Check now" in waiting.json()["detail"]
    assert _listed(client)["config"]["token"] == "legacy.link"

    file = form_store._path("legacy.link")
    with file.open("a", encoding="utf-8") as stream:
        stream.write("{damaged\n")
    damaged = _rotate(client, before["binding_revision"])
    assert damaged.status_code == 503
    assert file.read_text(encoding="utf-8").endswith("{damaged\n")
    assert _listed(client)["config"]["token"] == "legacy.link"


def test_rotation_enforces_owner_and_tenant_and_skips_old_files(monkeypatch, tmp_path):
    client = _form(monkeypatch, tmp_path, owner="user:alice")
    from maverick import form_store
    from maverick_dashboard import api, event_triggers_store

    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")
    before = _listed(client)
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:bob")
    assert _rotate(client, before["binding_revision"]).status_code == 404
    assert event_triggers_store.rotate_form_link(
        "intake", tenant="elsewhere", expected_generation=before["binding_revision"],
    ) is None
    monkeypatch.setattr(api, "goal_owner_filter", lambda request: "user:alice")

    old_candidate = "form-" + "A" * 32
    old_path = form_store._path(old_candidate)
    old_path.parent.mkdir(parents=True, exist_ok=True)
    old_path.write_text('{"seq":1,"ts":0,"fields":{"old":"saved"}}\n', encoding="utf-8")
    choices = iter(("A" * 32, "B" * 32))
    monkeypatch.setattr(event_triggers_store.secrets, "token_urlsafe", lambda _: next(choices))
    changed = _rotate(client, before["binding_revision"])
    assert changed.status_code == 200
    assert changed.json()["config"]["token"] == "form-" + "B" * 32
    assert old_path.read_text(encoding="utf-8").endswith('"saved"}}\n')
