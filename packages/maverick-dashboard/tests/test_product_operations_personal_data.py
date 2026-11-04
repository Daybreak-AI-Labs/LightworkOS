"""Shared My Data controls preserve native scopes, revisions and independent review."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import product_operations_personal_data as operations


@pytest.fixture
def state(monkeypatch):
    state = {"identity": {"revision": 4, "channels": ["slack"], "links": [], "challenges": []},
             "scopes": [{"id": "dashboard", "channel": "dashboard", "user_id": "a", "revision": 2,
                         "notes": [{"id": "a" * 64, "note": "private preference"}]}],
             "sharing": {"revision": 3}, "policy": {}, "context": "c" * 64}
    monkeypatch.setattr(operations, "_authority", lambda *a, **kw: "user:a")
    monkeypatch.setattr(operations.native, "_state", lambda request: state)
    monkeypatch.setattr(operations.native, "_app", lambda: SimpleNamespace(_world=lambda: SimpleNamespace(get_goal=lambda id: SimpleNamespace(id=id, owner="user:b"))))
    return state


def test_registry_exposes_native_personal_journeys():
    entries = operations.entries()
    assert len(entries) == 14
    assert len({e.id for e in entries}) == 14
    assert all(e.direct_ui == "/my-data" for e in entries)
    assert [e.id for e in entries if e.execute is None] == ["personal_data.status", "personal_data.note_source", "personal_data.deletion_status", "personal_data.export_scope", "personal_data.export_account"]


def test_shared_registry_advertises_every_native_personal_journey():
    from maverick_dashboard.product_operations import adapters

    registered = adapters()
    assert {entry.id for entry in operations.entries()} <= registered.keys()


def test_memory_mutation_uses_current_verified_scope_and_prepared_revision(state, monkeypatch):
    prepared = operations.prepare(None, {}, {"scope_id": "dashboard", "recall": False}, action="recall")
    calls = []
    monkeypatch.setattr(operations.native.personal_memory, "update", lambda *a, **kw: calls.append((a, kw)))
    result = operations.execute(None, {}, {"scope_id": "dashboard", "recall": False}, prepared.native, "op", action="recall")
    assert calls == [(("user:a", "dashboard", "a"), {"expected_revision": 2, "recall": False})]
    assert result.status == "confirmed"


def test_unknown_scope_never_reaches_memory_service(state):
    with pytest.raises(HTTPException) as error:
        operations.prepare(None, {}, {"scope_id": "user:b", "recall": True}, action="recall")
    assert error.value.status_code == 404


def test_unproved_identity_cannot_be_confirmed(state):
    state["identity"]["challenges"] = [{"id": "proof", "status": "waiting"}]
    with pytest.raises(HTTPException):
        operations.prepare(None, {}, {"identity_id": "proof"}, action="link_confirm")


def test_learning_exclusion_never_accepts_other_owner(state):
    with pytest.raises(HTTPException) as error:
        operations.prepare(None, {}, {"goal_id": 9}, action="exclude_task")
    assert error.value.status_code == 403


def test_independent_deletion_review_cannot_review_self(state, monkeypatch):
    monkeypatch.setattr(operations.auth, "require_permission", lambda *a: None)
    monkeypatch.setattr(operations.deletion.STORE, "get", lambda key: {"owner": "user:a", "status": "requested"})
    with pytest.raises(HTTPException) as error:
        operations.prepare(None, {}, {"request_id": "PDR-own", "external_holds_clear": True}, action="deletion_review")
    assert error.value.status_code == 403


def test_dispatched_deletion_never_prepares_another_attempt(state, monkeypatch):
    monkeypatch.setattr(operations.auth, "require_permission", lambda *a: None)
    monkeypatch.setattr(operations.deletion.STORE, "get", lambda key: {"owner": "user:b", "status": "processing"})
    with pytest.raises(HTTPException) as error:
        operations.prepare(None, {}, {"request_id": "PDR-other", "external_holds_clear": True}, action="deletion_review")
    assert error.value.status_code == 409


def test_existing_request_recovery_does_not_repeat_effects(state, monkeypatch):
    monkeypatch.setattr(operations.deletion.STORE, "get", lambda key: {"id": key, "owner": "user:a", "status": "processing"})
    result = operations.recover(None, {}, {}, {"actor": "user:a", "snapshot": "same"}, "op", action="deletion_request")
    assert result.status == "replayed"
    assert "no deletion" in result.message


def test_note_recovery_does_not_infer_execution_from_equal_value(state):
    assert operations.recover(None, {}, {}, {}, "op", action="note") is None


def test_readonly_status_never_exposes_preference_text_in_catalog_details(state, monkeypatch):
    monkeypatch.setattr(operations, "_requests", lambda req: ([], False))
    snapshot = operations.snapshot(None, {}, action="status")
    assert "private preference" not in repr(snapshot.details)


def test_source_reader_never_guesses_missing_lineage(state):
    with pytest.raises(HTTPException) as error:
        operations.prepare(None, {}, {"scope_id": "dashboard", "note_id": "a" * 64}, action="note_source")
    assert error.value.status_code == 404
