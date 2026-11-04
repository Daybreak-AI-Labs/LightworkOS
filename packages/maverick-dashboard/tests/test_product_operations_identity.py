"""Identity Copilot actions invoke native authority and preserve review boundaries."""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import product_operations_identity as operations


def test_identity_operations_are_closed_native_registry_entries():
    entries = operations.entries()
    assert len(entries) == 12
    assert len({entry.id for entry in entries}) == 12
    assert all(entry.family == "reviews" for entry in entries)
    assert all(entry.execute is None for entry in entries if entry.id.endswith(".status"))
    assert all(entry.recover is not None for entry in entries if not entry.id.endswith(".status"))


def test_departure_admission_recovery_never_repeats_uncertain_effects(monkeypatch):
    monkeypatch.setattr(operations.employee_departures_api, "_authority", lambda *a, **k: "user:admin")
    row = {"id": "EDP-recorded", "status": "handoff_required", "steps": [{"status": "dispatching"}]}
    monkeypatch.setattr(operations.employee_departures.STORE, "get", lambda key: row)
    outcome = operations.departure_recover(None, {}, {"principal": "user:employee"}, {"snapshot": "abc", "actor": "user:admin"}, "operation", action="begin")
    assert outcome.status == "unconfirmed"
    assert "no effects were repeated" in outcome.message


def test_departure_close_preparation_refuses_missing_responsibility(monkeypatch):
    monkeypatch.setattr(operations.employee_departures_api, "_authority", lambda *a, **k: "user:admin")
    monkeypatch.setattr(operations, "_departure_case", lambda *a, **k: {"id": "EDP-case", "revision": 2})
    monkeypatch.setattr(operations.employee_departures, "closure_preview", lambda *a: {"can_close": False, "blockers": ["An external obligation has no owner."]})
    with pytest.raises(HTTPException) as error:
        operations.departure_prepare(None, {}, {"case_id": "EDP-case"}, action="close")
    assert error.value.status_code == 409


def test_content_decision_uses_native_revision_and_receipt(monkeypatch):
    calls = []
    def decide(request, identifier, body, **kwargs):
        calls.append((identifier, body.expected_revision, body.decision, kwargs["operation_id"]))
        return {"id": identifier, "revision": 4, "status": "approved", "audit_pending": True}
    monkeypatch.setattr(operations.content_access_api, "decide_current_access", decide)
    outcome = operations.content_execute(None, {}, {"request_id": "ECA-one", "decision": "approve"}, {"revision": 3}, "unique", action="decide")
    assert calls == [("ECA-one", 3, "approve", "unique")]
    assert outcome.status == "unconfirmed"


def test_permission_request_copilot_respects_current_denial(monkeypatch):
    monkeypatch.setattr(operations.permission_requests_api, "authority", lambda *a, **k: "user:a")
    monkeypatch.setattr(operations.permission_requests, "explain", lambda *a: {"allowed": True})
    with pytest.raises(HTTPException) as error:
        operations.permission_prepare(None, {}, {"kind": "tool", "capability": "shell", "reason": "need"}, action="request")
    assert error.value.status_code == 409


def test_permission_review_recovery_does_not_publish_other_request(monkeypatch):
    monkeypatch.setattr(operations.permission_requests_api, "authority", lambda *a, **k: "user:a")
    monkeypatch.setattr(operations.permission_requests.STORE, "list", lambda **kwargs: [{"id": "PAR-other", "operation_id": "target", "owner": "user:b"}])
    monkeypatch.setattr(operations.permission_requests, "visible", lambda *a: False)
    assert operations.permission_recover(SimpleNamespace(), {}, {}, {}, "target", action="request") is None
