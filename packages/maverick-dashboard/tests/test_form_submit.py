"""The public POST /form/{token} endpoint that records hosted-form submissions."""
from __future__ import annotations

import hashlib
import json
import os
import re

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient


def _client(host="testclient"):
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}, client=(host, 50000))


def _isolate(monkeypatch, tmp_path, triggers="1"):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_EVENT_TRIGGERS", triggers)
    monkeypatch.setenv("MAVERICK_FLOWS", "1")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    from maverick import world_model
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    dashboard_app._goal_times.clear()
    dashboard_app._goal_times_global.clear()


def _register_form(token: str, *, tenant: str = "", name: str = "", owner: str = "",
                   inputs: list[dict] | None = None) -> None:
    from maverick.flow import store as flow_store
    from maverick.flow.ir import Flow, FlowNode
    from maverick.paths import reset_tenant, set_tenant
    from maverick_dashboard import event_triggers_store

    scope = set_tenant(tenant or None)
    try:
        published = flow_store.load_published_bundle("published-form-flow")
        if published is None:
            # Most intake tests submit a person's name. Declare that public
            # field explicitly; an input-free flow exposes only the message
            # fallback from its public page.
            declared = [{"key": "name", "type": "text"}] if inputs is None else inputs
            saved = flow_store.save_flow(Flow(
                id="published-form-flow", name="Published form", start="a",
                nodes={"a": FlowNode(id="a", kind="agent", brief="Review the submission")},
                inputs=declared,
            ))
            release = flow_store.publish_flow(
                saved.id, expected_version=saved.version, expected_revision=saved.revision,
            )
        else:
            saved, release = published
    finally:
        reset_tenant(scope)
    event_triggers_store.set_trigger(
        name or f"accept-{token}", "", "form", config={"token": token},
        flow=saved.id, flow_owner=saved.owner,
        flow_revision=release["release_id"], tenant=tenant, owner=owner,
    )


def test_new_form_api_mints_a_server_secret_and_returns_the_link(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("old-link", inputs=[])  # Publish the flow used by the new automation.
    client = _client()
    created = client.post("/api/v1/event-triggers", json={
        "name": "new-intake", "source": "form", "flow": "published-form-flow",
        "config": {},
    })
    assert created.status_code == 201
    token = created.json()["config"]["token"]
    assert re.fullmatch(r"form-[A-Za-z0-9_-]{32}", token)
    listed = client.get("/api/v1/event-triggers").json()["triggers"]
    assert next(t for t in listed if t["name"] == "new-intake")["config"]["token"] == token
    assert client.get(f"/form/{token}").status_code == 200
    assert client.post(f"/form/{token}", json={"message": "Hello"}).status_code == 201


def test_static_token_cannot_create_unrunnable_forms_but_can_remove_legacy(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("legacy-link", name="legacy")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-form-operator-token")  # pragma: allowlist secret
    from maverick_dashboard import event_triggers_store

    client = _client()
    auth = {"Authorization": "Bearer static-form-operator-token"}  # pragma: allowlist secret
    refused = client.post("/api/v1/event-triggers", headers=auth, json={
        "name": "new-intake", "source": "form", "flow": "published-form-flow", "config": {},
    })
    assert refused.status_code == 409
    assert "named account" in refused.json()["detail"]
    assert event_triggers_store.get_trigger("new-intake", tenant="") is None
    changed = client.post("/api/v1/event-triggers", headers=auth, json={
        "name": "legacy", "source": "form", "flow": "published-form-flow", "config": {},
    })
    assert changed.status_code == 409
    assert event_triggers_store.get_trigger("legacy", tenant="")["owner"] == ""
    listed = client.get("/api/v1/event-triggers", headers=auth)
    assert listed.status_code == 200
    assert any(row["name"] == "legacy" for row in listed.json()["triggers"])
    assert client.delete("/api/v1/event-triggers/legacy", headers=auth).status_code == 200


def test_local_operator_manages_new_and_legacy_local_forms(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("legacy-link", name="legacy")
    from maverick_dashboard import event_triggers_store

    client = _client()
    auth = {}
    created = client.post("/api/v1/event-triggers", headers=auth, json={
        "name": "new-intake", "source": "form", "flow": "published-form-flow", "config": {},
    })
    assert created.status_code == 201
    original_token = created.json()["config"]["token"]
    assert event_triggers_store.get_trigger("new-intake", tenant="")["owner"] == ""

    listed = client.get("/api/v1/event-triggers", headers=auth)
    assert listed.status_code == 200
    rows = {row["name"]: row for row in listed.json()["triggers"]}
    assert rows["new-intake"]["config"]["token"] == original_token
    assert rows["legacy"]["config"]["token"] == "legacy-link"

    updated = client.post("/api/v1/event-triggers", headers=auth, json={
        "name": "new-intake", "source": "form", "flow": "published-form-flow", "config": {},
    })
    assert updated.status_code == 201
    assert updated.json()["config"]["token"] == original_token
    rotated = client.post(
        "/api/v1/event-triggers/new-intake/rotate-form-link", headers=auth,
        json={"expected_generation": updated.json()["binding_revision"]},
    )
    assert rotated.status_code == 200
    assert rotated.json()["config"]["token"] != original_token
    new_token = rotated.json()["config"]["token"]
    assert client.post(f"/form/{new_token}", json={"name": "Ada"}).status_code == 201
    polled = client.post("/api/v1/event-triggers/poll?name=new-intake", headers=auth)
    assert polled.status_code == 200
    assert polled.json()["polled"] == 1
    history = client.get("/api/v1/event-triggers/history?name=new-intake", headers=auth)
    assert history.status_code == 200
    assert history.json()["history"][0]["owner"] == ""

    legacy_rotated = client.post(
        "/api/v1/event-triggers/legacy/rotate-form-link", headers=auth,
        json={"expected_generation": rows["legacy"]["binding_revision"]},
    )
    assert legacy_rotated.status_code == 200
    legacy_updated = client.post("/api/v1/event-triggers", headers=auth, json={
        "name": "legacy", "source": "form", "flow": "published-form-flow", "config": {},
    })
    assert legacy_updated.status_code == 201
    assert legacy_updated.json()["config"]["token"] == legacy_rotated.json()["config"]["token"]
    assert event_triggers_store.get_trigger("legacy", tenant="")["owner"] == ""
    assert client.delete("/api/v1/event-triggers/new-intake", headers=auth).status_code == 200
    assert client.delete("/api/v1/event-triggers/legacy", headers=auth).status_code == 200


def test_static_token_form_list_denies_missing_and_wrong_bearers(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("private-form-link", name="private")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-form-operator-token")  # pragma: allowlist secret
    client = _client()

    for headers in ({}, {"Authorization": "Bearer incorrect"}):
        denied = client.get("/api/v1/event-triggers", headers=headers)
        assert denied.status_code == 401
        assert "private-form-link" not in denied.text


def test_static_token_does_not_claim_another_named_owner_form(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("legacy-link", name="legacy")
    from maverick_dashboard import event_triggers_store

    prior = event_triggers_store.get_trigger("legacy", tenant="")
    foreign = event_triggers_store.set_trigger(
        "foreign", "", "form", config={"token": "foreign-link"},
        flow=prior["flow"], flow_owner=prior["flow_owner"],
        flow_revision=prior["flow_revision"], owner="user:alice", tenant="",
    )
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "static-form-operator-token")  # pragma: allowlist secret
    client = _client()
    auth = {"Authorization": "Bearer static-form-operator-token"}

    listed = client.get("/api/v1/event-triggers", headers=auth)
    assert listed.status_code == 200
    assert "foreign" not in {row["name"] for row in listed.json()["triggers"]}
    assert client.delete("/api/v1/event-triggers/foreign", headers=auth).status_code == 404
    from maverick_dashboard.event_poll import _trigger_key

    assert client.post(
        "/api/v1/event-triggers/foreign/rotate-form-link", headers=auth,
        json={"expected_generation": _trigger_key(foreign)},
    ).status_code == 404
    assert client.post("/api/v1/event-triggers", headers=auth, json={
        "name": "foreign", "source": "form", "flow": "published-form-flow", "config": {},
    }).status_code == 409
    assert event_triggers_store.get_trigger("foreign", tenant="")["owner"] == "user:alice"


def test_non_form_upsert_checks_expected_owner_under_store_lock(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store

    event_triggers_store.set_trigger("shared", "", "http_json", owner="user:alice")
    with pytest.raises(event_triggers_store.FormTriggerConflict):
        event_triggers_store.set_trigger(
            "shared", "", "http_json", owner="user:local", expected_owner="user:local",
        )
    assert event_triggers_store.get_trigger("shared", tenant="")["owner"] == "user:alice"
    updated = event_triggers_store.set_trigger(
        "shared", "", "http_json", owner="user:alice", expected_owner="user:alice",
    )
    assert updated["owner"] == "user:alice"


def test_new_form_api_rejects_caller_chosen_tokens_even_if_they_look_strong(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("old-link")
    from maverick_dashboard import event_triggers_store

    for token in ("a", "form-" + "a" * 32, "old-link"):
        created = _client().post("/api/v1/event-triggers", json={
            "name": "new-intake", "source": "form", "flow": "published-form-flow",
            "config": {"token": token},
        })
        assert created.status_code == 400
        assert event_triggers_store.get_trigger("new-intake", tenant="") is None


def test_form_api_preserves_exact_legacy_link_on_upsert(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("legacy.link", name="intake")
    client = _client()
    body = {"name": "intake", "source": "form", "flow": "published-form-flow"}
    for config in ({}, {"token": "legacy.link"}):
        updated = client.post("/api/v1/event-triggers", json={**body, "config": config})
        assert updated.status_code == 201
        assert updated.json()["config"]["token"] == "legacy.link"
    changed = client.post("/api/v1/event-triggers", json={
        **body, "config": {"token": "another.link"},
    })
    assert changed.status_code == 409
    assert client.get("/form/legacy.link").status_code == 200


def test_minted_form_link_retries_a_global_tenant_collision(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store

    first = "form-" + "A" * 32
    second = "form-" + "B" * 32
    event_triggers_store.set_trigger(
        "first", "", "form", config={"token": first}, flow="flow-id", tenant="tenant-a",
    )
    choices = iter(("A" * 32, "B" * 32))
    monkeypatch.setattr(event_triggers_store.secrets, "token_urlsafe", lambda _: next(choices))
    saved = event_triggers_store.set_trigger(
        "second", "", "form", config={}, flow="flow-id", tenant="tenant-b",
        mint_public_form_token=True,
    )
    assert saved["config"]["token"] == second


def test_existing_form_link_cannot_be_claimed_by_a_different_owner(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store

    event_triggers_store.set_trigger(
        "intake", "", "form", config={"token": "old-link"},
        flow="flow-id", owner="user:alice",
    )
    with pytest.raises(event_triggers_store.FormTriggerConflict, match="another person"):
        event_triggers_store.set_trigger(
            "intake", "", "form", config={}, flow="flow-id", owner="user:bob",
            mint_public_form_token=True, expected_owner="user:bob",
        )


def test_live_automation_form_page_uses_published_inputs(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("private-link", inputs=[
        {"key": "contact", "type": "text", "label": "Your name", "required": True},
        {"key": "amount", "type": "number", "label": "Order amount", "required": True},
        {"key": "date", "type": "date", "label": "Requested date", "required": False},
        {"key": "urgent", "type": "bool", "label": "Is this urgent?", "required": False},
        {"key": "private_default", "type": "text", "default": "hidden-value"},
    ])
    client = _client()
    page = client.get("/form/private-link")
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["referrer-policy"] == "no-referrer"
    assert "noindex" in page.headers["x-robots-tag"]
    assert "Published form" in page.text
    for name in ("contact", "amount", "date", "urgent", "private_default"):
        assert f'name="{name}"' in page.text
    assert 'type="number"' in page.text and 'type="date"' in page.text
    assert '<option value="false">No</option>' in page.text
    assert "hidden-value" not in page.text
    assert "Submitting does not mean the work is finished." in page.text
    assert client.post("/form/private-link", json={"contact": "Ada", "amount": "12.5"}).status_code == 201


def test_automation_form_without_declared_inputs_still_has_a_useful_field(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("intake", inputs=[])
    page = _client().get("/form/intake")
    assert page.status_code == 200
    assert '<textarea class="textarea" id="af-field-1" name="message"' in page.text
    assert "What would you like to share?" in page.text
    assert _client().post("/form/intake", json={"name": "unlisted"}).status_code == 422
    assert _client().post("/form/intake", json={"message": "Hello"}).status_code == 201


def test_bound_template_form_page_uses_immutable_params_without_exposing_defaults(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import Template
    from maverick_dashboard import event_triggers_store
    from maverick_dashboard.triggers_store import snapshot_from_template

    template = Template(name="contact", title="Contact", body="Review {{name}}", params=["name", "reference"])
    event_triggers_store.set_trigger(
        "contact", "contact", "form", config={"token": "contact-link"},
        params={"reference": "private-default"},
        template_snapshot=snapshot_from_template(template),
    )
    page = _client().get("/form/contact-link")
    assert page.status_code == 200
    assert "Contact" in page.text
    assert 'name="name"' in page.text and 'name="reference"' in page.text
    assert "private-default" not in page.text
    assert _client().post("/form/contact-link", json={"name": "Ada"}).status_code == 201


def test_public_form_get_rejects_unknown_and_non_form_links(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store

    event_triggers_store.set_trigger(
        "other-source", "", "rss", config={"token": "rss-token"}, flow="published-form-flow",
    )
    assert _client().get("/form/unknown").status_code == 404
    assert _client().get("/form/rss-token").status_code == 404


def test_public_form_get_rejects_stale_release_and_revoked_owner(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("stale")
    from maverick.flow import store as flow_store

    flow, _release = flow_store.load_published_bundle("published-form-flow")
    assert flow_store.unpublish_flow(
        flow.id, expected_version=flow.version, expected_revision=flow.revision,
    )
    assert _client().get("/form/stale").status_code == 404
    flow_store.publish_flow(flow.id, expected_version=flow.version, expected_revision=flow.revision)
    assert _client().get("/form/stale").status_code == 404


def test_public_form_get_withholds_revoked_owner_and_unavailable_registry(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("owner-link", owner="user:departed")
    from maverick_dashboard import event_triggers_store, scim_groups

    monkeypatch.setattr(scim_groups, "active_for_principal", lambda _owner: False)
    page = _client().get("/form/owner-link")
    assert page.status_code == 503
    assert "Published form" not in page.text
    monkeypatch.setattr(event_triggers_store, "list_triggers", lambda: (_ for _ in ()).throw(OSError("private path")))
    unavailable = _client().get("/form/owner-link")
    assert unavailable.status_code == 503
    assert "private path" not in unavailable.text


def test_typed_form_refuses_invalid_answers_before_append_and_dispatches_typed_data(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("typed", inputs=[
        {"key": "contact", "type": "text", "required": True},
        {"key": "amount", "type": "number", "required": True},
        {"key": "due", "type": "date", "required": True},
        {"key": "urgent", "type": "bool", "required": True},
    ])
    client = _client()
    for answer in (
        {"amount": "12", "due": "2026-10-01", "urgent": "true"},
        {"contact": "Ada", "amount": "NaN", "due": "2026-10-01", "urgent": "true"},
        {"contact": "Ada", "amount": "12", "due": "2026-02-30", "urgent": "true"},
        {"contact": "Ada", "amount": "12", "due": "2026-10-01", "urgent": "maybe"},
    ):
        assert client.post("/form/typed", json=answer).status_code == 422
    assert not list(tmp_path.rglob("*.ndjson"))
    valid = client.post("/form/typed", json={
        "contact": "Ada", "amount": "12.5", "due": "2026-10-01", "urgent": "true",
    })
    assert valid.status_code == 201
    poll = client.post("/api/v1/event-triggers/poll?name=accept-typed")
    assert poll.status_code == 200
    fired = poll.json()["triggers"][0]["fired_flows"]
    assert len(fired) == 1
    from maverick.flow import store as flow_store

    run = flow_store.load_run(fired[0])
    assert run.input_data["amount"] == 12.5
    assert run.input_data["urgent"] is True
    assert run.input_data["due"] == "2026-10-01"


def test_public_form_cannot_override_an_undeclared_saved_flow_default(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("guarded", inputs=[{"key": "message", "type": "text", "required": True}])
    from maverick.flow import store as flow_store
    from maverick_dashboard import event_triggers_store

    bound_flow, release = flow_store.load_published_bundle("published-form-flow")
    event_triggers_store.set_trigger(
        "accept-guarded", "", "form", config={"token": "guarded"},
        flow=bound_flow.id, flow_owner=bound_flow.owner,
        flow_revision=release["release_id"], params={"recipient": "approved@example.test"},
    )
    client = _client()
    page = client.get("/form/guarded")
    assert page.status_code == 200
    assert 'name="message"' in page.text
    assert 'name="recipient"' not in page.text
    refused = client.post("/form/guarded", json={
        "message": "Review this", "recipient": "outside@example.test",
    })
    assert refused.status_code == 422
    assert "not on the saved form" in refused.text
    assert not list(tmp_path.rglob("*.ndjson"))

    accepted = client.post("/form/guarded", json={"message": "Review this"})
    assert accepted.status_code == 201
    polled = client.post("/api/v1/event-triggers/poll?name=accept-guarded")
    assert polled.status_code == 200
    fired = polled.json()["triggers"][0]["fired_flows"]
    assert len(fired) == 1
    run = flow_store.load_run(fired[0])
    assert run.input_data["recipient"] == "approved@example.test"


def test_legacy_row_with_undeclared_field_stays_pending(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("legacy", inputs=[{"key": "message", "type": "text", "required": True}])
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    assert form_store.append("legacy", {
        "message": "Review this", "recipient": "outside@example.test",
    }) == 1
    polled = _client().post("/api/v1/event-triggers/poll?name=accept-legacy")
    assert polled.status_code == 200
    result = polled.json()["triggers"][0]
    assert result["poll_error"] is True
    assert result["fired_flows"] == []
    assert any("not on the saved form" in note for note in result["notes"])
    trigger = event_triggers_store.get_trigger("accept-legacy", tenant="")
    assert trigger["cursor"] == "0"
    assert event_triggers_store.pending_form_submissions(trigger) == 1


def test_preexisting_invalid_form_row_stays_pending_for_repair(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("typed", inputs=[{"key": "amount", "type": "number", "required": True}])
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    assert form_store.append("typed", {"amount": "not a number"}) == 1
    poll = _client().post("/api/v1/event-triggers/poll?name=accept-typed")
    assert poll.status_code == 200
    result = poll.json()["triggers"][0]
    assert result["poll_error"] is True
    assert result["fired_flows"] == []
    assert any("form submission needs attention" in note for note in result["notes"])
    trigger = event_triggers_store.get_trigger("accept-typed", tenant="")
    assert trigger["cursor"] == "0"
    assert event_triggers_store.pending_form_submissions(trigger) == 1


def test_missing_bound_template_param_is_rejected_before_append(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import Template
    from maverick_dashboard import event_triggers_store
    from maverick_dashboard.triggers_store import snapshot_from_template

    template = Template(name="contact", title="Contact", body="Review {{name}}", params=["name"])
    event_triggers_store.set_trigger(
        "contact", "contact", "form", config={"token": "contact-link"},
        template_snapshot=snapshot_from_template(template),
    )
    client = _client()
    assert client.post("/form/contact-link", json={"other": "Ada"}).status_code == 422
    assert client.post("/form/contact-link", json={"name": "Ada", "other": "x"}).status_code == 422
    assert not list(tmp_path.rglob("*.ndjson"))
    assert client.post("/form/contact-link", json={"name": "Ada"}).status_code == 201


def test_json_submission_is_recorded_and_pollable(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup", inputs=[
        {"key": "email", "type": "text"}, {"key": "plan", "type": "text"},
    ])
    r = _client().post("/form/signup", json={"email": "a@b.com", "plan": "pro"})
    assert r.status_code == 201 and r.json()["seq"] == 1
    # The first poll records the existing submission without replaying it.
    from maverick import automation_events as ev
    base = ev.get_source("form").poll({"token": "signup"}, "")   # baseline
    assert base.events == []
    assert ev._decode_cursor(base.cursor, "form", base.cursor_format) == "1"


def test_form_submission_fires_after_baseline(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("lead")
    c = _client()
    c.post("/form/lead", json={"name": "first"})
    from maverick import automation_events as ev
    base = ev.get_source("form").poll({"token": "lead"}, "")
    c.post("/form/lead", json={"name": "second"})
    out = ev.get_source("form").poll({"token": "lead"}, base.cursor)
    assert [e["name"] for e in out.events] == ["second"]


def test_new_form_delivers_first_submission_before_first_poll(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.flow import store as flow_store
    from maverick.flow.ir import Flow, FlowNode

    saved = flow_store.save_flow(Flow(
        id="first-form-flow", name="First form", start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="Review {{name}}")},
        inputs=[{"key": "name", "type": "text"}],
    ))
    flow_store.publish_flow(
        saved.id, expected_version=saved.version, expected_revision=saved.revision,
    )
    client = _client()
    created = client.post("/api/v1/event-triggers", json={
        "name": "first-form", "source": "form", "flow": saved.id,
        "config": {},
    })
    assert created.status_code == 201
    token = created.json()["config"]["token"]
    from maverick_dashboard import event_triggers_store

    assert event_triggers_store.get_trigger("first-form", tenant="")["cursor"] == "0"
    assert client.post(f"/form/{token}", json={"name": "first"}).status_code == 201
    result = client.post("/api/v1/event-triggers/poll?name=first-form")
    assert result.status_code == 200
    fired = result.json()["triggers"][0]["fired_flows"]
    assert len(fired) == 1
    assert flow_store.load_run(fired[0]).data["name"] == "first"


def test_form_backlog_drains_in_bounded_polls(monkeypatch, tmp_path):
    from collections import deque

    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "100")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "1000")
    _register_form("batch")
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import automation_queue

    monkeypatch.setattr(dashboard_app, "_goal_times", {})
    monkeypatch.setattr(dashboard_app, "_goal_times_global", deque())
    dispatched = []
    enqueue = automation_queue.enqueue_published_flow_run

    def record_run(*args, **kwargs):
        run_id = enqueue(*args, **kwargs)
        dispatched.append(args)
        return run_id

    monkeypatch.setattr(automation_queue, "enqueue_published_flow_run", record_run)
    client = _client()
    for n in range(26):
        response = client.post("/form/batch", json={"name": str(n)})
        assert response.status_code == 201
    first = client.post("/api/v1/event-triggers/poll?name=accept-batch")
    second = client.post("/api/v1/event-triggers/poll?name=accept-batch")
    assert first.status_code == second.status_code == 200
    first_batch = first.json()["triggers"][0]
    second_batch = second.json()["triggers"][0]
    assert first_batch["poll_error"] is second_batch["poll_error"] is False
    assert (first_batch["new_events"], second_batch["new_events"]) == (25, 1)
    assert [args[1]["name"] for args in dispatched] == [str(n) for n in range(26)]


def test_accepted_form_cannot_rebind_or_delete_before_original_flow_is_queued(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("lead", name="intake")
    from maverick.flow import store as flow_store
    from maverick.flow.ir import Flow, FlowNode
    from maverick_dashboard import event_triggers_store

    second = flow_store.save_flow(Flow(
        id="second-flow", name="Second flow", start="a",
        nodes={"a": FlowNode(id="a", kind="agent", brief="Review {{name}}")},
        inputs=[{"key": "name", "type": "text"}],
    ))
    flow_store.publish_flow(
        second.id, expected_version=second.version, expected_revision=second.revision,
    )
    client = _client()
    assert client.post("/form/lead", json={"name": "accepted for A"}).status_code == 201
    listed = client.get("/api/v1/event-triggers").json()["triggers"]
    assert next(t for t in listed if t["name"] == "intake")["pending_submissions"] == 1
    with pytest.raises(ValueError, match="managed automatically"):
        event_triggers_store.set_trigger(
            "intake", "", "form", config={"token": "lead"},
            flow="published-form-flow", cursor="1", tenant="",
        )
    assert not event_triggers_store.set_cursor("intake", "1", tenant="")
    rebind = client.post("/api/v1/event-triggers", json={
        "name": "intake", "source": "form", "flow": second.id,
        "config": {"token": "lead"},
    })
    assert rebind.status_code == 409 and "Check now" in rebind.json()["detail"]
    deletion = client.delete("/api/v1/event-triggers/intake")
    assert deletion.status_code == 409 and "Check now" in deletion.json()["detail"]
    assert event_triggers_store.get_trigger("intake", tenant="")["flow"] == "published-form-flow"

    polled = client.post("/api/v1/event-triggers/poll?name=intake")
    assert polled.status_code == 200
    run_id = polled.json()["triggers"][0]["fired_flows"][0]
    run = flow_store.load_run(run_id)
    assert run.flow_id == "published-form-flow" and run.data["name"] == "accepted for A"
    assert next(t for t in client.get("/api/v1/event-triggers").json()["triggers"]
                if t["name"] == "intake")["pending_submissions"] == 0
    with pytest.raises(ValueError, match="managed automatically"):
        event_triggers_store.set_trigger(
            "intake", "", "form", config={"token": "lead"},
            flow="published-form-flow", cursor="0", tenant="",
        )
    assert client.post("/api/v1/event-triggers", json={
        "name": "intake", "source": "form", "flow": second.id,
        "config": {"token": "lead"},
    }).status_code == 201
    assert client.post("/form/lead", json={"name": "accepted for B"}).status_code == 201
    polled_b = client.post("/api/v1/event-triggers/poll?name=intake")
    run_b = flow_store.load_run(polled_b.json()["triggers"][0]["fired_flows"][0])
    assert run_b.flow_id == "second-flow" and run_b.data["name"] == "accepted for B"
    assert client.delete("/api/v1/event-triggers/intake").status_code == 200


def test_form_template_parameters_cannot_change_while_a_submission_waits(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import Template
    from maverick_dashboard import event_triggers_store
    from maverick_dashboard.triggers_store import snapshot_from_template

    template = Template(name="contact", title="Contact {{name}}", body="Review {{name}}", params=["name"])
    snapshot = snapshot_from_template(template)
    event_triggers_store.set_trigger(
        "contact", "contact", "form", config={"token": "contact"},
        params={"name": "original"}, template_snapshot=snapshot,
    )
    client = _client()
    assert client.post("/form/contact", json={"name": "accepted"}).status_code == 201
    with pytest.raises(event_triggers_store.FormTriggerPending):
        event_triggers_store.set_trigger(
            "contact", "contact", "form", config={"token": "contact"},
            params={"name": "changed"}, template_snapshot=snapshot,
        )
    assert event_triggers_store.get_trigger("contact", tenant="")["params"]["name"] == "original"
    import maverick.runner as runner_mod

    monkeypatch.setattr(runner_mod, "run_goal_in_thread", lambda *a, **k: None)
    polled = client.post("/api/v1/event-triggers/poll?name=contact")
    assert polled.status_code == 200
    goal_id = polled.json()["triggers"][0]["fired"][0]
    from maverick.world_model import WorldModel

    assert WorldModel(tmp_path / "world.db").get_goal(goal_id).title == "Contact accepted"
    assert event_triggers_store.pending_form_submissions(
        event_triggers_store.get_trigger("contact", tenant="")
    ) == 0


def test_unavailable_original_form_flow_keeps_accepted_submission_pending(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("stale", name="intake")
    from maverick.flow import store as flow_store
    from maverick_dashboard import event_triggers_store

    client = _client()
    assert client.post("/form/stale", json={"name": "accepted"}).status_code == 201
    published = flow_store.load_published_bundle("published-form-flow")
    assert published is not None
    flow = published[0]
    assert flow_store.unpublish_flow(
        flow.id, expected_version=flow.version, expected_revision=flow.revision,
    )
    polled = client.post("/api/v1/event-triggers/poll?name=intake")
    assert polled.status_code == 200
    assert polled.json()["triggers"][0]["fired_flows"] == []
    assert event_triggers_store.pending_form_submissions(
        event_triggers_store.get_trigger("intake", tenant="")
    ) == 1
    assert client.delete("/api/v1/event-triggers/intake").status_code == 409


def test_owner_can_record_exact_waiting_form_submission_without_losing_original(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("stale", name="intake")
    from maverick import form_store
    from maverick.flow import store as flow_store
    from maverick_dashboard import event_triggers_store

    client = _client()
    assert client.post("/form/stale", json={"name": "customer answer"}).status_code == 201
    original = form_store._path("stale").read_bytes()
    published = flow_store.load_published_bundle("published-form-flow")
    assert published is not None
    flow = published[0]
    assert flow_store.unpublish_flow(
        flow.id, expected_version=flow.version, expected_revision=flow.revision,
    )
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions")
    assert waiting.status_code == 200
    snapshot = waiting.json()
    assert snapshot["waiting_total"] == 1
    assert snapshot["submissions"][0]["fields"] == {"name": "customer answer"}
    row = snapshot["submissions"][0]
    body = {
        "expected_generation": snapshot["binding_revision"],
        "expected_fields_sha256": row["fields_sha256"],
        "reason": "Handled outside this workflow after direct customer review.",
    }
    assert client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run",
        json={**body, "expected_fields_sha256": "0" * 64},
    ).status_code == 409
    decision = client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run", json=body,
    )
    assert decision.status_code == 200, decision.text
    assert form_store._path("stale").read_bytes() == original
    assert client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run", json=body,
    ).status_code == 409
    listed = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    assert listed["submissions"][0]["do_not_run"] is True
    assert listed["submissions"][0]["reason"] == body["reason"]
    polled = client.post("/api/v1/event-triggers/poll?name=intake")
    result = polled.json()["triggers"][0]
    assert result["poll_error"] is False
    assert result["fired_flows"] == []
    assert result["abandoned_submissions"] == 1
    assert event_triggers_store.pending_form_submissions(
        event_triggers_store.get_trigger("intake", tenant="")
    ) == 0
    receipt = client.get("/api/v1/event-triggers/intake/form-submissions/1/decision-receipt")
    assert receipt.status_code == 200, receipt.text
    assert receipt.json()["binding_revision"] == snapshot["binding_revision"]
    assert receipt.json()["fields_sha256"] == row["fields_sha256"]
    assert receipt.json()["decision_sha256"] == decision.json()["decision_sha256"]
    assert form_store._path("stale").read_bytes() == original


def test_owner_recovers_signed_form_decision_after_interrupted_marker_write(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("interrupted", name="intake")
    from maverick import audit, form_store
    from maverick_dashboard import event_triggers_store, form_recovery

    client = _client()
    assert client.post("/form/interrupted", json={"name": "customer answer"}).status_code == 201
    original = form_store._path("interrupted").read_bytes()
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    row = waiting["submissions"][0]
    body = {"expected_generation": waiting["binding_revision"],
            "expected_fields_sha256": row["fields_sha256"],
            "reason": "Handled outside the workflow after speaking with the customer."}
    decided = client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run", json=body,
    )
    assert decided.status_code == 200
    journal = form_recovery._path("interrupted")
    marker = form_recovery._marker(journal)
    marker.write_bytes(form_recovery._signed_receipt(0, "0" * 64))

    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]
    result = client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]
    assert result["poll_error"] is True
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before
    held = client.get("/api/v1/event-triggers/intake/form-submissions")
    assert held.status_code == 200
    assert held.json()["submissions"] == []
    recovery = held.json()["interrupted_decision"]
    assert recovery["fields"] == {"name": "customer answer"}
    assert recovery["reason"] == body["reason"]
    assert recovery["decision_sha256"] == decided.json()["decision_sha256"]
    endpoint = "/api/v1/event-triggers/intake/form-submissions/1/recover-decision"
    pins = {"expected_generation": waiting["binding_revision"],
            "expected_fields_sha256": row["fields_sha256"],
            "expected_decision_sha256": recovery["decision_sha256"]}
    assert client.post(endpoint, json={**pins, "expected_generation": "0" * 64}).status_code == 409
    assert client.post(endpoint, json={**pins, "expected_decision_sha256": "0" * 64}).status_code == 409
    assert marker.read_bytes() == form_recovery._signed_receipt(0, "0" * 64)

    real_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    assert client.post(endpoint, json=pins).status_code == 503
    assert client.get("/api/v1/event-triggers/intake/form-submissions").json()["interrupted_decision"]
    monkeypatch.setattr(audit, "record", real_record)
    repaired = client.post(endpoint, json=pins)
    assert repaired.status_code == 200, repaired.text
    assert client.post(endpoint, json=pins).status_code == 409
    confirmed = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    assert confirmed["interrupted_decision"] is None
    assert confirmed["submissions"][0]["do_not_run"] is True
    assert form_store._path("interrupted").read_bytes() == original
    result = client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]
    assert result["poll_error"] is False
    assert result["abandoned_submissions"] == 1
    assert result["fired_flows"] == []


@pytest.mark.parametrize("prior_decision", [False, True])
def test_owner_recovers_signed_form_decision_before_journal_append(
    monkeypatch, tmp_path, prior_decision,
):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("pending-append", name="intake")
    from maverick import file_lock, form_store
    from maverick_dashboard import event_triggers_store, form_recovery

    client = _client()
    count = 2 if prior_decision else 1
    for sequence in range(1, count + 1):
        assert client.post("/form/pending-append", json={"name": f"answer {sequence}"}).status_code == 201
    original = form_store._path("pending-append").read_bytes()
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    if prior_decision:
        first = waiting["submissions"][0]
        decided = client.post(
            "/api/v1/event-triggers/intake/form-submissions/1/do-not-run",
            json={"expected_generation": waiting["binding_revision"],
                  "expected_fields_sha256": first["fields_sha256"],
                  "reason": "Handled first answer outside the workflow."},
        )
        assert decided.status_code == 200, decided.text
    row = waiting["submissions"][count - 1]
    endpoint = f"/api/v1/event-triggers/intake/form-submissions/{count}"
    real_append = file_lock.open_private_append

    def fail_before_append(*_args, **_kwargs):
        raise OSError("simulated crash before decision append")

    monkeypatch.setattr(file_lock, "open_private_append", fail_before_append)
    refused = client.post(endpoint + "/do-not-run", json={
        "expected_generation": waiting["binding_revision"],
        "expected_fields_sha256": row["fields_sha256"],
        "reason": "Handled this answer outside the workflow after review.",
    })
    assert refused.status_code == 503
    monkeypatch.setattr(file_lock, "open_private_append", real_append)
    journal = form_recovery._path("pending-append")
    if prior_decision:
        assert len(journal.read_text(encoding="utf-8").splitlines()) == 1
    else:
        assert not journal.exists()
    marker = form_recovery._marker(journal)
    signed_pending = marker.read_bytes()
    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]
    assert client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]["poll_error"]
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before
    held = client.get("/api/v1/event-triggers/intake/form-submissions")
    assert held.status_code == 200, held.text
    recovery = held.json()["interrupted_decision"]
    assert recovery["sequence"] == count
    assert recovery["recovery_phase"] == "journal_pending"
    assert recovery["fields"] == row["fields"]
    pins = {"expected_generation": waiting["binding_revision"],
            "expected_fields_sha256": row["fields_sha256"],
            "expected_decision_sha256": recovery["decision_sha256"]}
    assert client.post(endpoint + "/recover-decision", json={**pins,
        "expected_decision_sha256": "0" * 64}).status_code == 409
    marker.write_bytes(b"{}\n")
    assert client.get("/api/v1/event-triggers/intake/form-submissions").status_code == 503
    assert client.post(endpoint + "/recover-decision", json=pins).status_code == 503
    marker.write_bytes(signed_pending)

    real_write = file_lock.atomic_write_bytes

    def fail_final_marker(target, payload, *args, **kwargs):
        if target == marker:
            raise OSError("simulated crash after decision append")
        return real_write(target, payload, *args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_write_bytes", fail_final_marker)
    assert client.post(endpoint + "/recover-decision", json=pins).status_code == 503
    monkeypatch.setattr(file_lock, "atomic_write_bytes", real_write)
    after_append = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    assert after_append["interrupted_decision"]["recovery_phase"] == "marker_pending"
    repaired = client.post(endpoint + "/recover-decision", json=pins)
    assert repaired.status_code == 200, repaired.text
    assert client.post(endpoint + "/recover-decision", json=pins).status_code == 409
    receipt = client.get(endpoint + "/decision-receipt")
    assert receipt.status_code == 200, receipt.text
    assert receipt.json() == {"sequence": count,
        "binding_revision": waiting["binding_revision"],
        "fields_sha256": row["fields_sha256"],
        "decision_sha256": recovery["decision_sha256"], "do_not_run": True}
    assert form_store._path("pending-append").read_bytes() == original
    polled = client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]
    assert polled["poll_error"] is False
    assert polled["abandoned_submissions"] == count
    assert polled["fired_flows"] == []
    assert client.get(endpoint + "/decision-receipt").json() == receipt.json()


@pytest.mark.parametrize("prior_decision", [False, True])
def test_owner_recovers_only_exact_signed_partial_decision_row(
    monkeypatch, tmp_path, prior_decision,
):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("partial-append", name="intake")
    from maverick import audit, file_lock, form_store
    from maverick_dashboard import event_triggers_store, form_recovery

    client = _client()
    count = 2 if prior_decision else 1
    for sequence in range(1, count + 1):
        assert client.post("/form/partial-append", json={"name": f"answer {sequence}"}).status_code == 201
    original = form_store._path("partial-append").read_bytes()
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    if prior_decision:
        first = waiting["submissions"][0]
        assert client.post(
            "/api/v1/event-triggers/intake/form-submissions/1/do-not-run",
            json={"expected_generation": waiting["binding_revision"],
                  "expected_fields_sha256": first["fields_sha256"],
                  "reason": "Handled first answer outside the workflow."},
        ).status_code == 200
    row = waiting["submissions"][count - 1]
    endpoint = f"/api/v1/event-triggers/intake/form-submissions/{count}"
    journal = form_recovery._path("partial-append")
    real_append = file_lock.open_private_append

    def crash_during_append(*_args, **_kwargs):
        pending = json.loads(form_recovery._marker(journal).read_bytes())["pending_decision"]
        exact = form_recovery._row_bytes(pending)
        with journal.open("ab") as handle:
            handle.write(exact[:len(exact) // 2])
            handle.flush()
            os.fsync(handle.fileno())
        raise OSError("simulated partial decision write")

    monkeypatch.setattr(file_lock, "open_private_append", crash_during_append)
    failed = client.post(endpoint + "/do-not-run", json={
        "expected_generation": waiting["binding_revision"],
        "expected_fields_sha256": row["fields_sha256"],
        "reason": "Handled this answer outside the workflow after review.",
    })
    assert failed.status_code == 503
    monkeypatch.setattr(file_lock, "open_private_append", real_append)
    partial = journal.read_bytes()
    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]
    assert client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]["poll_error"]
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before
    held = client.get("/api/v1/event-triggers/intake/form-submissions")
    assert held.status_code == 200, held.text
    recovery = held.json()["interrupted_decision"]
    assert recovery["recovery_phase"] == "partial_journal_pending"
    assert recovery["sequence"] == count
    pins = {"expected_generation": waiting["binding_revision"],
            "expected_fields_sha256": row["fields_sha256"],
            "expected_decision_sha256": recovery["decision_sha256"]}
    damaged = bytearray(partial)
    damaged[-1] ^= 1
    journal.write_bytes(damaged)
    assert client.get("/api/v1/event-triggers/intake/form-submissions").status_code == 503
    assert client.post(endpoint + "/recover-decision", json=pins).status_code == 503
    journal.write_bytes(partial)
    real_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    assert client.post(endpoint + "/recover-decision", json=pins).status_code == 503
    assert journal.read_bytes() == partial
    monkeypatch.setattr(audit, "record", real_record)
    repaired = client.post(endpoint + "/recover-decision", json=pins)
    assert repaired.status_code == 200, repaired.text
    assert journal.read_bytes().startswith(partial)
    assert len(journal.read_bytes().splitlines()) == count
    assert client.post(endpoint + "/recover-decision", json=pins).status_code == 409
    receipt = client.get(endpoint + "/decision-receipt")
    assert receipt.status_code == 200, receipt.text
    assert receipt.json()["decision_sha256"] == recovery["decision_sha256"]
    assert form_store._path("partial-append").read_bytes() == original
    polled = client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]
    assert polled["poll_error"] is False
    assert polled["abandoned_submissions"] == count
    assert polled["fired_flows"] == []


def test_form_decision_refuses_failed_audit_and_damaged_journal(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("stale", name="intake")
    from maverick import audit, form_store
    from maverick_dashboard import event_triggers_store, form_recovery

    client = _client()
    assert client.post("/form/stale", json={"name": "customer answer"}).status_code == 201
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    body = {
        "expected_generation": waiting["binding_revision"],
        "expected_fields_sha256": waiting["submissions"][0]["fields_sha256"],
        "reason": "Handled outside this workflow after direct customer review.",
    }
    real_record = audit.record
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: False)
    refused = client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run", json=body,
    )
    assert refused.status_code == 503
    assert not form_recovery._path("stale").exists()
    from maverick.audit.errors import AuditRefused

    def reject_signed_record(*_args, **_kwargs):
        raise AuditRefused("signed activity record refused")

    monkeypatch.setattr(audit, "record", reject_signed_record)
    refused = client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run", json=body,
    )
    assert refused.status_code == 503
    assert not form_recovery._path("stale").exists()
    monkeypatch.setattr(audit, "record", real_record)
    accepted = client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run", json=body,
    )
    assert accepted.status_code == 200, accepted.text
    journal = form_recovery._path("stale")
    original = journal.read_text(encoding="utf-8")
    forged = json.loads(original)
    forged["reason"] = "Changed locally without an owner decision."
    forged["hash"] = form_recovery.fields_digest({
        key: value for key, value in forged.items() if key not in {"hash", "signature"}
    })
    journal.write_text(json.dumps(forged) + "\n", encoding="utf-8")
    assert client.get("/api/v1/event-triggers/intake/form-submissions").status_code == 503
    assert client.get(
        "/api/v1/event-triggers/intake/form-submissions/1/decision-receipt"
    ).status_code == 503
    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]
    polled = client.post("/api/v1/event-triggers/poll?name=intake")
    assert polled.json()["triggers"][0]["poll_error"] is True
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before
    assert form_store._path("stale").exists()
    journal.write_text(original, encoding="utf-8")
    journal.unlink()
    assert client.get("/api/v1/event-triggers/intake/form-submissions").status_code == 503


def test_form_decision_skips_only_selected_row_and_refuses_started_work(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("mixed", name="intake")
    from maverick.flow import store as flow_store
    from maverick_dashboard import event_triggers_store
    from maverick_dashboard.event_poll import _trigger_key

    client = _client()
    assert client.post("/form/mixed", json={"name": "handled separately"}).status_code == 201
    assert client.post("/form/mixed", json={"name": "run this one"}).status_code == 201
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    first = waiting["submissions"][0]
    assert client.post(
        "/api/v1/event-triggers/intake/form-submissions/1/do-not-run",
        json={"expected_generation": waiting["binding_revision"],
              "expected_fields_sha256": first["fields_sha256"],
              "reason": "Handled separately by the team with the customer."},
    ).status_code == 200
    polled = client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]
    assert polled["poll_error"] is False
    assert polled["abandoned_submissions"] == 1
    assert len(polled["fired_flows"]) == 1
    run = flow_store.load_run(polled["fired_flows"][0])
    assert run.data["name"] == "run this one"
    assert event_triggers_store.pending_form_submissions(
        event_triggers_store.get_trigger("intake", tenant="")
    ) == 0
    # An uncertain cursor rollback must not let the owner dispose of a run
    # that already started, even though the row appears pending again.
    current = event_triggers_store.get_trigger("intake", tenant="")
    assert event_triggers_store.set_cursor(
        "intake", "0", tenant="", expected_cursor=current["cursor"],
        expected_generation=_trigger_key(current), cursor_format=0,
    )
    waiting_again = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    second = waiting_again["submissions"][1]
    refused = client.post(
        "/api/v1/event-triggers/intake/form-submissions/2/do-not-run",
        json={"expected_generation": waiting_again["binding_revision"],
              "expected_fields_sha256": second["fields_sha256"],
              "reason": "This row must be refused because a run exists."},
    )
    assert refused.status_code == 409
    assert "already started" in refused.json()["detail"]


def test_truncated_form_decision_tail_never_replays_as_unanswered(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(str(tmp_path).encode()).hexdigest())
    _register_form("truncation", name="intake")
    from maverick_dashboard import event_triggers_store, form_recovery

    client = _client()
    for name in ("first", "second"):
        assert client.post("/form/truncation", json={"name": name}).status_code == 201
    waiting = client.get("/api/v1/event-triggers/intake/form-submissions").json()
    for row in waiting["submissions"]:
        decided = client.post(
            f"/api/v1/event-triggers/intake/form-submissions/{row['sequence']}/do-not-run",
            json={"expected_generation": waiting["binding_revision"],
                  "expected_fields_sha256": row["fields_sha256"],
                  "reason": f"Handled {row['fields']['name']} outside the workflow."},
        )
        assert decided.status_code == 200, decided.text
    journal = form_recovery._path("truncation")
    lines = journal.read_text(encoding="utf-8").splitlines(keepends=True)
    assert len(lines) == 2
    journal.write_text(lines[0], encoding="utf-8")
    assert client.get("/api/v1/event-triggers/intake/form-submissions").status_code == 503
    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]
    result = client.post("/api/v1/event-triggers/poll?name=intake").json()["triggers"][0]
    assert result["poll_error"] is True
    assert result["fired_flows"] == []
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before
    repair = client.post(
        "/api/v1/event-triggers/intake/form-submissions/2/recover-decision",
        json={"expected_generation": waiting["binding_revision"],
              "expected_fields_sha256": waiting["submissions"][1]["fields_sha256"],
              "expected_decision_sha256": "0" * 64},
    )
    assert repair.status_code == 503
    journal.write_text("".join(lines), encoding="utf-8")
    form_recovery._marker(journal).write_bytes(form_recovery._signed_receipt(0, "0" * 64))
    # Two signed rows beyond the marker cannot be inferred to be one
    # interrupted append, even when every row signature is intact.
    assert client.get("/api/v1/event-triggers/intake/form-submissions").status_code == 503


def test_empty_form_can_be_changed_and_deleted_before_a_first_submission(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("empty", name="intake")
    from maverick_dashboard import event_triggers_store

    assert event_triggers_store.pending_form_submissions(
        event_triggers_store.get_trigger("intake", tenant="")
    ) == 0
    changed = event_triggers_store.set_trigger(
        "intake", "", "form", config={"token": "empty"},
        flow="published-form-flow", params={"department": "sales"}, tenant="",
    )
    assert changed["params"] == {"department": "sales"}
    assert _client().delete("/api/v1/event-triggers/intake").status_code == 200
    assert not list(tmp_path.rglob("*.ndjson"))


def test_missing_or_corrupt_form_history_blocks_changes(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("history", name="intake")
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    client = _client()
    assert client.post("/form/history", json={"name": "accepted"}).status_code == 201
    file = form_store._path("history")
    with file.open("a", encoding="utf-8") as fh:
        fh.write("{damaged\n")
    assert next(t for t in client.get("/api/v1/event-triggers").json()["triggers"]
                if t["name"] == "intake")["pending_submissions"] is None
    assert client.delete("/api/v1/event-triggers/intake").status_code == 503
    with pytest.raises(form_store.FormStoreUnavailable):
        event_triggers_store.set_trigger(
            "intake", "", "form", config={"token": "history"},
            flow="other-flow", tenant="",
        )
    file.write_text('{"seq":1,"ts":0,"fields":{"name":"accepted"}}\n', encoding="utf-8")
    assert client.post("/api/v1/event-triggers/poll?name=intake").status_code == 200
    file.unlink()
    assert client.delete("/api/v1/event-triggers/intake").status_code == 503


def test_damaged_accepted_form_row_cannot_advance_poll_cursor(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("history", name="intake")
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    client = _client()
    for name in ("first", "second", "third"):
        assert client.post("/form/history", json={"name": name}).status_code == 201
    path = form_store._path("history")
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    path.write_text(lines[0] + "{damaged\n" + lines[2], encoding="utf-8")
    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]

    polled = client.post("/api/v1/event-triggers/poll?name=intake")
    assert polled.status_code == 200
    result = polled.json()["triggers"][0]
    assert result["poll_error"] is True
    assert result["new_events"] == 0
    assert result["fired_flows"] == []
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before


def test_missing_first_accepted_form_queue_blocks_delete_and_poll(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("history", name="intake")
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    client = _client()
    assert client.post("/form/history", json={"name": "accepted"}).status_code == 201
    before = event_triggers_store.get_trigger("intake", tenant="")["cursor"]
    form_store._path("history").unlink()

    assert client.delete("/api/v1/event-triggers/intake").status_code == 503
    assert client.post("/form/history", json={"name": "retry"}).status_code == 503
    polled = client.post("/api/v1/event-triggers/poll?name=intake")
    assert polled.status_code == 200
    result = polled.json()["triggers"][0]
    assert result["poll_error"] is True
    assert result["fired_flows"] == []
    assert event_triggers_store.get_trigger("intake", tenant="")["cursor"] == before


def test_form_rebind_is_refused_after_restart_until_original_rows_are_drained(monkeypatch, tmp_path):
    import subprocess
    import sys

    _isolate(monkeypatch, tmp_path)
    _register_form("restart", name="intake")
    assert _client().post("/form/restart", json={"name": "saved"}).status_code == 201
    script = (
        "from maverick_dashboard import event_triggers_store as s\n"
        "t=s.get_trigger('intake', tenant='')\n"
        "assert s.pending_form_submissions(t)==1\n"
        "try:\n"
        " s.set_trigger('intake','', 'form', config={'token':'restart'}, "
        "flow='other-flow', tenant='')\n"
        "except s.FormTriggerPending:\n"
        " print('protected')\n"
        "else:\n"
        " raise AssertionError('rebind was accepted')\n"
    )
    child = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True,
        timeout=30, check=False,
    )
    assert child.returncode == 0, child.stderr
    assert "protected" in child.stdout


def test_public_post_rechecks_binding_if_it_changes_during_body_read(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    _isolate(monkeypatch, tmp_path)
    _register_form("race", name="intake")
    from maverick import form_store
    from maverick_dashboard import app as dashboard_app
    from maverick_dashboard import event_triggers_store

    entered, resume = Event(), Event()
    original = dashboard_app._append_registered_form

    def paused(trigger, token, fields):
        entered.set()
        assert resume.wait(10)
        return original(trigger, token, fields)

    monkeypatch.setattr(dashboard_app, "_append_registered_form", paused)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending_post = pool.submit(lambda: _client().post("/form/race", json={"name": "old"}))
        assert entered.wait(10)
        event_triggers_store.set_trigger(
            "intake", "", "form", config={"token": "race"},
            flow="different-flow", tenant="",
        )
        resume.set()
        assert pending_post.result(timeout=10).status_code == 404
    assert not list(tmp_path.rglob("*.ndjson"))
    assert form_store.pending("race", "0") == 0


def test_public_append_blocks_rebind_until_pending_row_is_visible(monkeypatch, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    _isolate(monkeypatch, tmp_path)
    _register_form("race", name="intake")
    from maverick import form_store
    from maverick_dashboard import event_triggers_store

    entered, resume = Event(), Event()
    original = form_store.append

    def paused(*args, **kwargs):
        entered.set()
        assert resume.wait(10)
        return original(*args, **kwargs)

    monkeypatch.setattr(form_store, "append", paused)
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending_post = pool.submit(lambda: _client().post("/form/race", json={"name": "original"}))
        assert entered.wait(10)
        pending_rebind = pool.submit(
            event_triggers_store.set_trigger, "intake", "", "form",
            config={"token": "race"}, flow="different-flow", tenant="",
        )
        resume.set()
        assert pending_post.result(timeout=10).status_code == 201
        with pytest.raises(event_triggers_store.FormTriggerPending):
            pending_rebind.result(timeout=10)
    assert event_triggers_store.get_trigger("intake", tenant="")["flow"] == "published-form-flow"


def test_urlencoded_submission(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("contact", inputs=[])
    r = _client().post("/form/contact", data={"message": "hello"})
    assert r.status_code == 201
    from maverick import form_store
    events, _ = form_store.since("contact", "0")
    assert events and events[0]["message"] == "hello"


def test_small_multipart_text_submission(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("contact", inputs=[])
    response = _client().post("/form/contact", files={"message": (None, "hello")})
    assert response.status_code == 201
    from maverick import form_store

    events, _ = form_store.since("contact", "0")
    assert events[0]["message"] == "hello"


def test_form_disabled_when_triggers_off(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, triggers="0")
    r = _client().post("/form/x", json={"a": 1})
    assert r.status_code == 404


def test_invalid_json_is_400(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("x")
    r = _client().post("/form/x", content=b"{not json",
                       headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_oversized_json_form_fields_are_rejected_without_truncation(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("sizing")
    client = _client()
    responses = [
        client.post("/form/sizing", json={str(n): "x" for n in range(51)}),
        client.post("/form/sizing", json={"answer": "x" * 2001}),
        client.post("/form/sizing", json={"n" * 201: "x"}),
    ]
    assert [response.status_code for response in responses] == [400, 400, 400]
    assert not list(tmp_path.rglob("*.ndjson"))


def test_revoked_form_owner_cannot_acknowledge_submission(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("owned", owner="user:departed")
    from maverick_dashboard import scim_groups

    monkeypatch.setattr(scim_groups, "active_for_principal", lambda _owner: False)
    response = _client().post("/form/owned", json={"name": "first"})
    assert response.status_code == 503
    assert response.json()["detail"] == "This form is not accepting submissions."
    assert not list(tmp_path.rglob("*.ndjson"))


def test_unregistered_and_non_form_tokens_create_no_submission(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import event_triggers_store

    event_triggers_store.set_trigger(
        "other-source", "", "rss", config={"token": "rss-token"},
        flow="published-form-flow",
    )
    client = _client()
    assert client.post("/form/never-registered", json={"name": "stranger"}).status_code == 404
    assert client.post("/form/rss-token", json={"name": "stranger"}).status_code == 404
    assert not list(tmp_path.rglob("*.ndjson"))


def test_form_rate_limit_runs_before_body_parser(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from maverick_dashboard import app as dashboard_app

    def limited(request, *, source=None):
        assert source is None
        raise HTTPException(status_code=429, detail="slow down")

    async def never_parse(_request):
        raise AssertionError("request body was parsed before rate limiting")

    monkeypatch.setattr(dashboard_app, "check_goal_rate_limit", limited)
    monkeypatch.setattr(dashboard_app, "_read_limited_webhook_body", never_parse)
    response = _client().post("/form/signup", json={"name": "any"})
    assert response.status_code == 429
    assert not list(tmp_path.rglob("*.ndjson"))


def test_disabled_trigger_does_not_accept_new_submissions(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from maverick_dashboard import event_triggers_store

    assert event_triggers_store.delete_trigger("accept-signup", tenant="")
    response = _client().post("/form/signup", json={"name": "stranger"})
    assert response.status_code == 404
    assert not list(tmp_path.rglob("*.ndjson"))


def test_same_token_across_tenants_is_not_routed_arbitrarily(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup", tenant="one")
    _register_form("signup", tenant="two")
    response = _client().post("/form/signup", json={"name": "stranger"})
    assert response.status_code == 404
    assert not list(tmp_path.rglob("*.ndjson"))


def test_form_capacity_error_is_not_reported_as_success(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from maverick import form_store

    monkeypatch.setattr(form_store, "_MAX_LINES", 1)
    client = _client()
    assert client.post("/form/signup", json={"name": "first"}).status_code == 201
    response = client.post("/form/signup", json={"name": "second"})
    assert response.status_code == 507
    assert response.json()["detail"] == (
        "This form has reached its submission limit. Please contact the form owner."
    )
    events, _ = form_store.since("signup", "0")
    assert [event["name"] for event in events] == ["first"]


def test_vendor_form_still_accepts_when_event_triggers_are_on(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import app as dashboard_app

    monkeypatch.setattr(dashboard_app, "_vendor_questionnaire_for", lambda token: {"token": token})
    response = _client().post("/form/vendor-token", data={"answer": "yes"})
    assert response.status_code == 201


def test_new_form_trigger_rejects_aliased_storage_token(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    response = _client().post("/api/v1/event-triggers", json={
        "name": "new-form", "source": "form", "flow": "published-form-flow",
        "config": {"token": "my.form"},
    })
    assert response.status_code == 400


def test_existing_punctuation_token_keeps_its_legacy_form_file(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("lead.v1")
    response = _client().post("/form/lead.v1", json={"name": "first"})
    assert response.status_code == 201
    from maverick import form_store
    from maverick_dashboard.event_poll import admit_event_source_config

    assert (tmp_path / "forms" / "lead-v1.ndjson").exists()
    assert admit_event_source_config("form", {"token": "lead.v1"}) == {"token": "lead.v1"}
    events, _ = form_store.since("lead.v1", "0")
    assert [event["name"] for event in events] == ["first"]


def test_second_form_cannot_reuse_the_same_storage_key(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("lead.v1")
    from maverick_dashboard import event_triggers_store

    with pytest.raises(event_triggers_store.FormTriggerConflict):
        _register_form("lead-v1", name="second-form")
    client = _client()
    assert client.post("/form/lead.v1", json={"name": "first"}).status_code == 201
    assert client.post("/form/lead-v1", json={"name": "second"}).status_code == 404
    assert len(list(tmp_path.rglob("*.ndjson"))) == 1


def test_oversized_multipart_is_rejected_before_parsing(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from starlette.requests import Request

    def never_parse(self, *args, **kwargs):
        raise AssertionError("multipart parser ran before size admission")

    monkeypatch.setattr(Request, "form", never_parse)
    response = _client().post(
        "/form/signup", files={"attachment": ("large.txt", b"x" * 300_000)},
    )
    assert response.status_code == 413
    assert not list(tmp_path.rglob("*.ndjson"))


def test_store_write_failure_is_not_reported_as_success(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from maverick import form_store

    monkeypatch.setattr(form_store, "append", lambda *args, **kwargs: 0)
    response = _client().post("/form/signup", json={"name": "first"})
    assert response.status_code == 503


def test_stale_flow_release_does_not_accept_a_form_submission(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from maverick.flow import store as flow_store

    published = flow_store.load_published_bundle("published-form-flow")
    assert published is not None
    flow_store.unpublish_flow(
        published[0].id,
        expected_version=published[0].version,
        expected_revision=published[0].revision,
    )
    response = _client().post("/form/signup", json={"name": "first"})
    assert response.status_code == 404
    assert not list(tmp_path.rglob("*.ndjson"))


def test_republished_flow_cannot_reuse_an_old_form_binding(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    from maverick.flow import store as flow_store

    published = flow_store.load_published_bundle("published-form-flow")
    assert published is not None
    flow, old_release = published
    assert flow_store.unpublish_flow(
        flow.id, expected_version=flow.version, expected_revision=flow.revision,
    )
    new_release = flow_store.publish_flow(
        flow.id, expected_version=flow.version, expected_revision=flow.revision,
    )
    assert new_release["release_id"] != old_release["release_id"]
    response = _client().post("/form/signup", json={"name": "first"})
    assert response.status_code == 404
    assert not list(tmp_path.rglob("*.ndjson"))


def test_bound_template_form_still_accepts(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick.templates import Template
    from maverick_dashboard import event_triggers_store
    from maverick_dashboard.triggers_store import snapshot_from_template

    template = Template(name="contact", title="Contact", body="Review {{name}}", params=["name"])
    event_triggers_store.set_trigger(
        "contact", "contact", "form", config={"token": "contact"},
        template_snapshot=snapshot_from_template(template),
    )
    response = _client().post("/form/contact", json={"name": "first"})
    assert response.status_code == 201


def test_public_form_rate_limit_is_per_ip_not_url_token(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    _register_form("signup-two", name="accept-signup-two")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "1")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "100")
    from maverick_dashboard import app as dashboard_app

    dashboard_app._goal_times.clear()
    dashboard_app._goal_times_global.clear()
    first = _client("192.0.2.1")
    second = _client("192.0.2.2")
    assert first.post("/form/signup", json={"name": "first"}).status_code == 201
    # A second real form does not buy a fresh window; an unknown token is
    # refused before it reaches the limiter at all.
    assert first.post("/form/signup-two", json={"name": "second"}).status_code == 429
    assert first.post("/form/forged-1", json={"name": "third"}).status_code == 404
    assert second.post("/form/signup", json={"name": "another"}).status_code == 201
    assert set(dashboard_app._goal_times) == {"ip:192.0.2.1", "ip:192.0.2.2"}


def test_unknown_form_tokens_never_spend_the_goal_ceiling_real_starts_share(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _register_form("signup")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_PER_MIN", "100")
    monkeypatch.setenv("MAVERICK_DASHBOARD_MAX_GOALS_GLOBAL_PER_MIN", "5")
    from maverick_dashboard import app as dashboard_app

    for index in range(6):
        stranger = _client(f"198.51.100.{index + 1}")
        assert stranger.post(f"/form/guess-{index}", json={"name": "x"}).status_code == 404
    assert not dashboard_app._goal_times_global
    dashboard_app.check_goal_rate_limit(None, source="task-start")  # a real start is still admitted
    assert _client("192.0.2.9").post("/form/signup", json={"name": "real"}).status_code == 201


@pytest.mark.parametrize("method", ["get", "post"])
def test_questionnaire_migration_is_retryable_not_missing(monkeypatch, tmp_path, method):
    _isolate(monkeypatch, tmp_path, triggers="0")
    from maverick import vendor_management
    from maverick.governed_record_lookup import RecordLookupUnavailable

    def unavailable(_token):
        raise RecordLookupUnavailable("record lookup is rebuilding")
    monkeypatch.setattr(vendor_management, "questionnaire_for_token", unavailable)
    response = getattr(_client(), method)("/form/existing-link")
    assert response.status_code == 503
    assert response.headers["Retry-After"] == "2"


def test_disabled_questionnaire_register_still_returns_missing(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path, triggers="0")
    from maverick import vendor_management
    monkeypatch.setattr(vendor_management, "enabled", lambda: False)
    assert _client().get("/form/unknown").status_code == 404


def test_unknown_form_tokens_are_throttled_per_address_before_any_lookup(monkeypatch, tmp_path):
    # Each lookup scans the registered triggers and vendor questionnaires; an
    # anonymous guesser gets its own per-address limit (not the goal ceiling).
    _isolate(monkeypatch, tmp_path)
    from maverick_dashboard import app as app_module

    lookups = []
    monkeypatch.setattr(app_module, "_registered_form_trigger", lambda token: lookups.append(token))
    monkeypatch.setattr(app_module, "_vendor_questionnaire_for", lambda token: lookups.append(token))
    monkeypatch.setattr(app_module, "_FORM_LOOKUPS_PER_MINUTE", 3)
    client = _client()
    statuses = [client.post(f"/form/guess-{n}", json={"a": "b"}).status_code for n in range(5)]
    assert statuses[:3] == [404, 404, 404]
    assert statuses[3:] == [429, 429]
    assert client.get("/form/guess-page").status_code == 429
    assert len(lookups) <= 6  # only the three admitted guesses reached a lookup
