"""Reviewed activation erasure retains monotonic barriers and admission safety."""
from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick.privacy_ops import RecordConflict
from maverick_dashboard import employee_activation as activation


class Drafts:
    def __init__(self, rows):
        self.rows = {row["id"]: deepcopy(row) for row in rows}
    def get(self, identity):
        return deepcopy(self.rows.get(identity))
    def list(self, **kwargs):
        return deepcopy(list(self.rows.values()))
    def update(self, identity, mutate, *, expected_revision, **kwargs):
        row = self.get(identity)
        if row["revision"] != expected_revision:
            raise RecordConflict("changed")
        mutate(row)
        row["revision"] += 1
        self.rows[identity] = row
        return self.get(identity)


@pytest.fixture
def data(monkeypatch):
    operation = "a" * 32
    identifier = "EAP-" + activation.hashlib.sha256(("user:alice:" + operation).encode()).hexdigest()[:48]
    store = Drafts([{"id": identifier, "revision": 1, "owner": "user:alice", "state": "draft", "job": "weekly_update", "sealed": "secret source material", "workflow": "private-workflow"},
                    {"id": "EAP-other", "revision": 1, "owner": "user:bob", "state": "draft", "sealed": "other"}])
    state = {"store": store, "id": identifier, "operation": operation, "receipt": None, "goal": None}
    state["world"] = SimpleNamespace(get_goal=lambda identifier: state["goal"])
    monkeypatch.setattr(activation, "DRAFTS", store)
    monkeypatch.setattr(activation, "SubmissionStore", lambda world: SimpleNamespace(lookup=lambda **kwargs: state["receipt"]))
    monkeypatch.setattr(activation, "actor", lambda *args, **kwargs: "user:alice")
    return state


def test_erasure_keeps_tombstone_and_refuses_stale_create_and_update(data, monkeypatch):
    result = activation.erase_owned_activation("user:alice", data["id"], expected_revision=1,
        actor="user:reviewer", operation_id="erase-one", world=data["world"])
    assert result == {"status": "confirmed", "revision": 2}
    saved = data["store"].get(data["id"])
    assert saved["state"] == "erased"
    assert "sealed" not in saved and "workflow" not in saved
    assert data["store"].get("EAP-other")["sealed"] == "other"
    assert activation.owned_activation_inventory("user:alice", world=data["world"]) == []
    with pytest.raises(HTTPException) as error:
        activation._read(None, data["id"])
    assert error.value.status_code == 410
    monkeypatch.setattr(activation, "_binding", lambda *args: None)
    monkeypatch.setattr(activation, "_validated", lambda *args: {"material": "stale source"})
    monkeypatch.setattr(activation.crypto_at_rest, "seal_to_str", lambda value: "sealed:new")
    monkeypatch.setattr(activation.crypto_at_rest, "is_sealed_str", lambda value: True)
    body = activation.DraftIn(context="context", operation_id=data["operation"], job="weekly_update", mode="real", criteria="Review")
    with pytest.raises(HTTPException) as error:
        activation.save(None, body)
    assert error.value.status_code == 410
    assert data["store"].get(data["id"])["state"] == "erased"
    assert activation.erase_owned_activation("user:alice", data["id"], expected_revision=1,
        actor="user:reviewer", operation_id="erase-one", world=data["world"])["status"] == "replayed"


@pytest.mark.parametrize("state,receipt,goal", [
    ("admitting", None, None),
    ("draft", {"goal_id": 1}, SimpleNamespace(owner="user:alice", status="pending")),
    ("started", {"goal_id": 1}, None),
    ("reviewed", {"goal_id": 1}, SimpleNamespace(owner="user:bob", status="done")),
])
def test_active_uncertain_or_foreign_receipts_block_erasure(data, state, receipt, goal):
    data["store"].rows[data["id"]]["state"] = state
    data.update(receipt=receipt, goal=goal)
    assert activation.owned_activation_inventory("user:alice", world=data["world"])[0]["blocked"]
    with pytest.raises(ValueError):
        activation.erase_owned_activation("user:alice", data["id"], expected_revision=1,
            actor="user:reviewer", operation_id="erase-one", world=data["world"])
    assert data["store"].get(data["id"])["sealed"] == "secret source material"


def test_reviewed_terminal_task_is_retained_and_other_owner_denied(data):
    data["store"].rows[data["id"]]["state"] = "reviewed"
    data.update(receipt={"goal_id": 1}, goal=SimpleNamespace(owner="user:alice", status="done"))
    with pytest.raises(ValueError):
        activation.erase_owned_activation("user:bob", data["id"], expected_revision=1,
            actor="user:reviewer", operation_id="erase-one", world=data["world"])
    result = activation.erase_owned_activation("user:alice", data["id"], expected_revision=1,
        actor="user:reviewer", operation_id="erase-one", world=data["world"])
    assert result["status"] == "confirmed"
    assert data["world"].get_goal(1).status == "done"
