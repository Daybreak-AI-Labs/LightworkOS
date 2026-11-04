"""Real native SQLite/CAS and durable receipt qualification, without providers."""
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick import governed_records
from maverick.world_model import WorldModel
from maverick_dashboard import api, auth, draft_api, facts_api
from maverick_dashboard import product_operations_facts as ops


@pytest.fixture
def state(tmp_path, monkeypatch):
    from maverick import audit
    from maverick_dashboard import app
    governed_records._reset_process_authority_pin_for_testing()
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_TEMPORAL_MEMORY", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    world = WorldModel(tmp_path / "facts.db")
    state = SimpleNamespace(world=world, context="c" * 64, actor="user:a", allowed=True, tags=True)
    def permission(request, name):
        if not state.allowed:
            raise HTTPException(403, "revoked")
    for module in (auth, api, facts_api):
        monkeypatch.setattr(module, "require_permission", permission)
    for module in (ops, draft_api, facts_api):
        monkeypatch.setattr(module, "context_for", lambda request: state.context)
    monkeypatch.setattr(auth, "caller_principal", lambda request: state.actor)
    monkeypatch.setattr(app, "_require_same_origin", lambda request: None)
    monkeypatch.setattr(api, "_world", lambda: world)
    from maverick_dashboard import _shared
    monkeypatch.setattr(_shared, "_world", lambda: world)
    monkeypatch.setattr(facts_api, "tags_enabled", lambda: state.tags)
    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    yield state
    world.close()
    governed_records._reset_process_authority_pin_for_testing()


def selection(*keys):
    return {"kind": "facts", "keys": list(keys)}


def change(state, action, args, selected=None, operation="op"):
    selected = selected or {}
    preview = ops.prepare(None, selected, args, action=action)
    outcome = ops.execute(None, selected, args, preview.native, operation, action=action)
    return preview.native, outcome


def test_create_actual_revision_and_replay_after_later_delete(state):
    state.world.upsert_fact("unrelated", "x", expected_revision=0)
    prepared, result = change(state, "create", {"key": "hours", "value": "nine"})
    assert result.status == "confirmed"
    row = state.world.fact_record("hours")
    assert result.details["saved_revision"] == row["revision"] > 1
    state.world.delete_fact("hours", expected_revision=row["revision"])
    assert ops.execute(None, {}, {}, prepared, "op", action="create").status == "replayed"
    assert state.world.fact_record("hours") is None
    actor, record_id, binding = ops._binding(None, {}, prepared, "op", "create")
    receipt = json.dumps(ops.STORE.get(record_id))
    assert "hours" not in receipt and "nine" not in receipt


@pytest.mark.parametrize("action,args", [("update", {"value": "old draft"}), ("remove", {}), ("tags", {"labels": "old tag"})])
def test_stale_selected_mutations_never_change_current_value(state, action, args):
    first = state.world.upsert_fact("hours", "nine", expected_revision=0)
    selected = selection("hours")
    prepared = ops.prepare(None, selected, args, action=action).native
    state.world.upsert_fact("hours", "ten", expected_revision=first)
    with pytest.raises(HTTPException) as error:
        ops.execute(None, selected, args, prepared, "stale", action=action)
    assert error.value.status_code == 409
    assert state.world.get_fact("hours") == "ten"
    assert ops.recover(None, selected, args, prepared, "stale", action=action).status == "unconfirmed"


def test_restore_exact_history_as_new_version_and_replay_removal(state):
    first = state.world.upsert_fact("hours", "nine", expected_revision=0)
    state.world.upsert_fact("hours", "ten", expected_revision=first)
    versions = facts_api.record(None, SimpleNamespace(headers={}), key="hours")["history"]
    version = next(v for v in versions if v["value"] == "nine")
    prepared, outcome = change(state, "restore", {"version": ops.digest(version)}, selection("hours"), "restore")
    assert outcome.status == "confirmed" and state.world.get_fact("hours") == "nine"
    prepared, outcome = change(state, "remove", {}, selection("hours"), "remove")
    assert outcome.status == "confirmed"
    assert ops.snapshot(None, selection("hours"), action="remove").blocked
    assert ops.recover(None, selection("hours"), {}, prepared, "remove", action="remove").status == "replayed"


def test_current_role_context_selection_and_policy_are_checked_at_effect(state):
    state.world.upsert_fact("hours", "nine", expected_revision=0)
    selected = selection("hours")
    prepared = ops.prepare(None, selected, {"labels": "office"}, action="tags").native
    state.allowed = False
    with pytest.raises(HTTPException) as error:
        ops.execute(None, selected, {}, prepared, "role", action="tags")
    assert error.value.status_code == 403
    state.allowed, state.context = True, "d" * 64
    with pytest.raises(HTTPException):
        ops.execute(None, selected, {}, prepared, "context", action="tags")
    state.context, state.tags = "c" * 64, False
    with pytest.raises(HTTPException):
        ops.execute(None, selected, {}, prepared, "policy", action="tags")
    assert state.world.fact_record("hours")["tags"] == []


def test_audit_admission_failure_and_unknown_write_never_retry(state, monkeypatch):
    from maverick import audit
    prepared = ops.prepare(None, {}, {"key": "hours", "value": "nine"}, action="create").native
    monkeypatch.setattr(audit, "record", lambda *a, **kw: False)
    assert ops.execute(None, {}, {}, prepared, "audit", action="create").status == "unconfirmed"
    assert state.world.fact_record("hours") is None
    monkeypatch.setattr(audit, "record", lambda *a, **kw: True)
    assert ops.execute(None, {}, {}, prepared, "audit", action="create").status == "unconfirmed"
    original = ops._write
    def lost_response(*args):
        original(*args)
        raise OSError("response lost")
    monkeypatch.setattr(ops, "_write", lost_response)
    with pytest.raises(OSError):
        ops.execute(None, {}, {}, prepared, "unknown", action="create")
    revision = state.world.fact_record("hours")["revision"]
    assert ops.execute(None, {}, {}, prepared, "unknown", action="create").status == "unconfirmed"
    assert state.world.fact_record("hours")["revision"] == revision


def test_receipt_must_match_exact_review_not_equal_current_value(state):
    prepared, _ = change(state, "create", {"key": "hours", "value": "nine"})
    with pytest.raises(HTTPException):
        ops.recover(None, {}, {}, prepared | {"value": "ten"}, "op", action="create")
    assert ops.recover(None, {}, {}, prepared, "other-operation", action="create") is None


def test_bulk_readonly_and_private_fact_names_never_exposed(state):
    for key in ("one", "two", "goal:7:secret", "user:other"):
        state.world.upsert_fact(key, "private or shared", expected_revision=0)
    args = {"query": "", "source": "", "tag": "", "before": "", "page": 1}
    page = ops.prepare(None, {}, args, action="search").native
    assert {row["key"] for row in page["items"]} == {"one", "two"}
    assert len(ops.prepare(None, selection("one", "two"), {}, action="inspect").native["items"]) == 2
    assert ops.snapshot(None, selection("one", "two"), action="remove").blocked
    with pytest.raises(HTTPException):
        ops.snapshot(None, selection("goal:7:secret"), action="inspect")


def test_second_search_page_and_actual_tag_mutation(state):
    for number in range(60):
        state.world.upsert_fact(f"item-{number:02}", "text", expected_revision=0)
    page = ops.prepare(None, {}, {"query": "", "source": "", "tag": "", "before": "", "page": 2}, action="search").native
    assert len(page["items"]) == 10
    _, result = change(state, "tags", {"labels": "Office, office, reviewed"}, selection("item-01"))
    assert result.status == "confirmed"
    assert state.world.fact_record("item-01")["tags"] == ["office", "reviewed"]


def test_shared_review_token_recovers_removed_selection_without_repeating(state, monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from maverick_dashboard import product_operations as registry
    state.world.upsert_fact("hours", "nine", expected_revision=0)
    monkeypatch.setattr(registry, "_adapter_modules", lambda: (ops,))
    monkeypatch.setattr(registry, "_gate", lambda request: auth.require_permission(request, "view"))
    monkeypatch.setattr(registry, "_context", lambda request: state.context)
    monkeypatch.setattr(registry, "enabled_families", lambda: {"learning"})
    application = FastAPI()
    application.include_router(registry.router)
    selected = selection("hours")
    with TestClient(application, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
        body = {"page": "/facts", "selection": selected, "operation": "facts.remove", "context": state.context,
                "revision": ops.snapshot(None, selected, action="remove").revision, "arguments": {}}
        response = client.post("/api/v1/copilot/product-operations/prepare", json=body)
        assert response.status_code == 200, response.text
        token = {"token": response.json()["token"], "confirmed": True}
        first = client.post("/api/v1/copilot/product-operations/execute", json=token)
        assert first.status_code == 200 and first.json()["status"] == "confirmed", first.text
        replay = client.post("/api/v1/copilot/product-operations/execute", json=token)
        assert replay.status_code == 200 and replay.json()["status"] == "replayed", replay.text
        state.allowed = False
        assert client.post("/api/v1/copilot/product-operations/execute", json=token).status_code == 403


def test_completion_audit_failure_is_not_a_confirmed_save(state, monkeypatch):
    from maverick import audit
    calls = []
    def record(*args, **kwargs):
        calls.append((args, kwargs))
        return len(calls) == 1
    monkeypatch.setattr(audit, "record", record)
    prepared, result = change(state, "create", {"key": "hours", "value": "nine"})
    assert state.world.get_fact("hours") == "nine"
    assert result.status == "unconfirmed"
    assert ops.recover(None, {}, {}, prepared, "op", action="create").status == "unconfirmed"
