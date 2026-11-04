"""Departure safety contracts; authored for later execution with fake stores."""
from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy

import pytest
from fastapi import HTTPException
from maverick_dashboard import auth, scim
from maverick_dashboard import employee_departures as departures


class Store:
    def __init__(self):
        self.rows = {}

    def get(self, key):
        return deepcopy(self.rows.get(key))

    def create(self, row, **_):
        self.rows[row["id"]] = {**row, "revision": 1}
        return self.get(row["id"])

    def update(self, key, mutate, expected_revision, **_):
        row = self.get(key)
        assert row["revision"] == expected_revision
        mutate(row)
        row["revision"] += 1
        self.rows[key] = row
        return self.get(key)


@pytest.fixture
def reviewed(monkeypatch):
    import maverick.authority_effects
    monkeypatch.setattr(maverick.authority_effects, "authority_effect_fence", nullcontext)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda _: "viewer")
    monkeypatch.setattr(departures, "candidates", lambda: [{"principal": "user:reviewer", "active": True, "admin": True}])
    inventory = {"principal": "user:employee", "snapshot": "reviewed", "truncated": False,
                 "items": [], "active": True}
    monkeypatch.setattr(departures, "preview", lambda _: inventory)
    store = Store()
    monkeypatch.setattr(departures, "STORE", store)
    return inventory, store


def test_changed_review_has_no_deactivation_effect(reviewed, monkeypatch):
    calls = []
    monkeypatch.setattr(scim, "_retire_user_identity", calls.append)
    with pytest.raises(HTTPException) as exc:
        departures.begin("user:employee", "user:reviewer", "old", "user:admin", lambda: None)
    assert exc.value.status_code == 409
    assert calls == []


def test_deactivation_is_not_complete_offboarding(reviewed, monkeypatch):
    calls = []
    monkeypatch.setattr(scim, "_retire_user_identity", calls.append)
    result = departures.begin("user:employee", "user:reviewer", "reviewed", "user:admin", lambda: None)
    assert calls == [{"externalId": "employee"}]
    assert result["status"] == "handoff_required"
    assert result["retained_data_owner"] == "user:reviewer"
    assert result["steps"][-1]["sessions"] == "revoked"


def test_interrupted_connection_has_dispatch_receipt(reviewed, monkeypatch):
    import maverick.connections
    inventory, store = reviewed
    inventory["items"] = [{"kind": "connection", "tenant": None, "id": "mail", "revision": "v1"}]
    monkeypatch.setattr(departures, "_tenant", lambda _: nullcontext())
    monkeypatch.setattr(scim, "_retire_user_identity", lambda _: None)
    def unavailable(*_, **__):
        raise OSError("sealed store unavailable")
    monkeypatch.setattr(maverick.connections, "delete_connection", unavailable)
    with pytest.raises(OSError):
        departures.begin("user:employee", "user:reviewer", "reviewed", "user:admin", lambda: None)
    row = next(iter(store.rows.values()))
    assert row["steps"][-1] == {"kind": "connection", "tenant": None, "id": "mail", "status": "dispatching"}
    assert row["status"] != "completed"


def test_departure_closure_requires_all_items_and_fresh_active_owners(reviewed, monkeypatch):
    inventory, store = reviewed
    item = {"kind": "task", "id": "42", "tenant": None, "owner": "user:employee", "status": "running"}
    inventory.update(items=[item], active=False, coverage="test")
    row = store.create({"id": "EDP-case", "principal": "user:employee", "inventory": inventory,
                        "status": "handoff_required", "steps": [], "handoffs": {}})
    assert departures.closure_preview(row["id"], 1)["can_close"] is False
    for key in (departures._item_key(item), "external"):
        row = departures.record_handoff(row["id"], row["revision"], item_key=key,
            owner="user:reviewer", disposition="retained", evidence="Explicit retained responsibility.",
            actor="user:admin", authorize=lambda: None)
    review = departures.closure_preview(row["id"], row["revision"])
    assert review["can_close"] is True
    with pytest.raises(HTTPException):
        departures.close_case(row["id"], row["revision"], "stale", "user:admin", lambda: None)
    result = departures.close_case(row["id"], row["revision"], review["snapshot"], "user:admin", lambda: None)
    assert result["status"] == "closed_with_retained_obligations"
    assert result["closure"]["external_verification"] == "human_attestation"
    assert result["closure"]["private_content_access"] == "unchanged"
    monkeypatch.setattr(departures, "candidates", list)
    assert departures.closure_preview(row["id"], result["revision"])["can_close"] is False


def test_new_items_and_reactivated_identity_block_closure(reviewed):
    inventory, store = reviewed
    store.create({"id": "EDP-case", "principal": "user:employee", "inventory": {**inventory, "items": []},
                  "status": "handoff_required", "handoffs": {"external": {"owner": "user:reviewer"}}})
    inventory["items"] = [{"kind": "connection", "id": "new", "tenant": None}]
    result = departures.closure_preview("EDP-case", 1)
    assert len(result["new_items"]) == 1 and not result["can_close"]
    assert any("still active" in text for text in result["blockers"])
    inventory["coverage"] = "test"
    result = departures.refresh_inventory("EDP-case", 1, "user:admin", lambda: None)
    assert result["inventory"]["items"] == inventory["items"]
    assert len(departures.closure_preview("EDP-case", result["revision"])["missing_handoffs"]) == 1
