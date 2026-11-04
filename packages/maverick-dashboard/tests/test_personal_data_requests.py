"""Real local deletion adapters and durable dispatch behavior, no provider calls."""
import copy
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from maverick_dashboard import personal_data_requests as deletion
from maverick_dashboard.draft_store import DraftConflict, DraftStore


def test_draft_erasure_fences_old_autosave_and_other_owner(tmp_path, monkeypatch):
    from maverick import crypto_at_rest
    from maverick_dashboard import draft_store
    monkeypatch.setattr(draft_store, "seal", lambda value: b"sealed:" + value)
    monkeypatch.setattr(draft_store, "unseal", lambda value: value.removeprefix(b"sealed:"))
    monkeypatch.setattr(draft_store, "is_sealed", lambda value: value.startswith(b"sealed:"))
    del crypto_at_rest
    own = DraftStore("a" * 64, directory=tmp_path / "own")
    other = DraftStore("b" * 64, directory=tmp_path / "other")
    saved = own.save("c" * 64, {"text": "private"}, expected_revision=0, operation_id="first")
    other.save("c" * 64, {"text": "other"}, expected_revision=0, operation_id="other")
    result = own.erase_all(expected_version=own.inventory()["version"])
    assert result["state"] == "purged"
    assert own.read("c" * 64)["payload"] is None
    with pytest.raises(DraftConflict):
        own.save("c" * 64, {"text": "stale"}, expected_revision=saved["revision"], operation_id="late")
    assert other.read("c" * 64)["payload"] == {"text": "other"}


def test_conversation_erasure_refuses_cross_owner_descendant():
    world = SimpleNamespace(list_conversations=lambda channel: [SimpleNamespace(id=1, user_id="alice")],
        plan_conversation_erasure=lambda ids: {"conversation_ids": [1], "goal_ids": [3], "episode_ids": [], "attachment_paths": ["private-path"]},
        get_goal=lambda gid: SimpleNamespace(owner="user:bob", status="done"))
    with pytest.raises(ValueError, match="outside this verified owner"):
        deletion._conversation_plan(world, "user:alice", "dashboard", "alice")


def test_conversation_adapter_deletes_only_reviewed_owned_closure(tmp_path, monkeypatch):
    from maverick import erasure_receipts
    from maverick.world_model import WorldModel
    world = WorldModel(tmp_path / "world.db")
    try:
        conversation = world.get_or_create_conversation("dashboard", "alice")
        goal = world.create_goal("private", owner="user:alice")
        world.set_goal_status(goal, "done")
        world.append_turn(conversation.id, "user", "private turn", goal_id=goal)
        other = world.create_goal("other", owner="user:bob")
        plan = deletion._conversation_plan(world, "user:alice", "dashboard", "alice")
        monkeypatch.setattr(erasure_receipts, "persist_receipt", lambda world, manifest: manifest)
        receipt = deletion._erase_conversations(world, {"owner": "user:alice"}, {"scope": plan})
        assert receipt["state"] == "purged"
        assert world.get_goal(goal) is None
        assert world.get_goal(other) is not None
        assert receipt["stores"]["conversations"]["remaining"] == 0
        assert "global caches" in receipt["retained"]
    finally:
        world.close()


class Store:
    def __init__(self, row):
        self.row = copy.deepcopy(row)

    def get(self, identifier):
        return copy.deepcopy(self.row)

    def update(self, identifier, mutate, *, expected_revision, **kwargs):
        assert self.row["revision"] == expected_revision
        mutate(self.row)
        self.row["revision"] += 1
        return copy.deepcopy(self.row)


@pytest.fixture
def request_store(monkeypatch):
    store = Store({"id": "PDR-case", "revision": 1, "owner": "user:alice", "channel": "dashboard", "user_id": "alice",
                   "status": "requested", "targets": [{"store": "preference_notes", "state": "requested", "count": 2}], "exceptions": deletion.EXCEPTIONS})
    monkeypatch.setattr(deletion, "STORE", store)
    monkeypatch.setattr(deletion, "preservation_snapshot", lambda: {"blocked": False})
    monkeypatch.setattr(deletion.personal_memory, "require_scope", lambda *args: None)
    monkeypatch.setattr(deletion, "preview", lambda *args: {"targets": copy.deepcopy(store.row["targets"])})
    return store


class _Ledger:
    """In-memory request store: ``get`` by id and ``create`` of a new row."""

    def __init__(self):
        self.rows = {}

    def get(self, identifier):
        return copy.deepcopy(self.rows.get(identifier))

    def create(self, record, **kwargs):
        assert record["id"] not in self.rows
        self.rows[record["id"]] = {**copy.deepcopy(record), "revision": 1, "owner": record["owner"]}
        return copy.deepcopy(self.rows[record["id"]])


def test_repeat_request_after_completion_is_a_new_request_for_new_data(monkeypatch):
    # One comment is purged; a new comment brings the same count and so the same
    # snapshot. The finished request must not answer for the new data.
    ledger = _Ledger()
    monkeypatch.setattr(deletion, "STORE", ledger)
    reviewed = {"owner": "user:alice", "channel": "dashboard", "user_id": "alice",
                "targets": [{"store": "comments", "state": "requested", "count": 1}],
                "holds": {"blocked": False}, "exceptions": [], "snapshot": "snapshot-one-comment"}
    monkeypatch.setattr(deletion, "preview", lambda *args: copy.deepcopy(reviewed))

    def ask():
        return deletion.request_deletion("user:alice", "dashboard", "alice", ["comments"],
                                         "snapshot-one-comment", None)

    first = ask()
    assert first["status"] == "requested"
    # A double click, or a retry after a lost response, still finds the same request.
    assert ask()["id"] == first["id"] and len(ledger.rows) == 1
    ledger.rows[first["id"]]["status"] = "processing"
    assert ask()["id"] == first["id"] and len(ledger.rows) == 1
    # Once it has finished, the same state is a fresh request the reviewer can apply.
    ledger.rows[first["id"]]["status"] = "purged-with-retained-exceptions"
    second = ask()
    assert second["id"] != first["id"] and second["status"] == "requested"
    assert second["id"].startswith("PDR-") and len(ledger.rows) == 2
    assert ask()["id"] == second["id"] and len(ledger.rows) == 2
    # Lost-response recovery looks at the newest request for this state.
    assert deletion.latest_request("user:alice", "snapshot-one-comment")["id"] == second["id"]
    assert deletion.latest_request("user:alice", "another-snapshot") is None
    # A partial outcome does not block asking again either.
    ledger.rows[second["id"]]["status"] = "partial"
    third = ask()
    assert third["id"] not in {first["id"], second["id"]} and len(ledger.rows) == 3


def test_known_hold_never_dispatches_or_claims_deletion(request_store, monkeypatch):
    monkeypatch.setattr(deletion, "preservation_snapshot", lambda: {"blocked": True})
    monkeypatch.setattr(deletion, "_erase_target", lambda *a, **k: pytest.fail("hold must prevent dispatch"))
    receipt = deletion.apply("PDR-case", 1, "user:reviewer", lambda: None, None, external_holds_clear=True)
    assert receipt["status"] == "held"
    assert receipt["targets"][0]["state"] == "requested"


def test_own_request_requires_distinct_current_reviewer(request_store):
    with pytest.raises(HTTPException) as error:
        deletion.apply("PDR-case", 1, "user:alice", lambda: None, None, external_holds_clear=True)
    assert error.value.status_code == 403


def test_effect_receipt_precedes_dispatch_failure_stays_unknown(request_store, monkeypatch):
    def erase(*args, authorize=None):
        assert callable(authorize)  # the current reviewer check reaches the store
        assert request_store.row["targets"][0]["state"] == "dispatching"
        raise OSError("interrupted deletion")
    monkeypatch.setattr(deletion, "_erase_target", erase)
    receipt = deletion.apply("PDR-case", 1, "user:reviewer", lambda: None, None, external_holds_clear=True)
    assert receipt["status"] == "partial"
    assert receipt["targets"][0]["state"] == "unconfirmed"
    with pytest.raises(HTTPException):
        deletion.apply("PDR-case", receipt["revision"], "user:reviewer", lambda: None, None, external_holds_clear=True)


def test_purged_scope_keeps_explicit_retained_exceptions(request_store, monkeypatch):
    def erase(*args, authorize=None):
        assert callable(authorize)  # the reviewer's authority is re-checked at each store
        return {"state": "purged", "removed": 2}
    monkeypatch.setattr(deletion, "_erase_target", erase)
    receipt = deletion.apply("PDR-case", 1, "user:reviewer", lambda: None, None, external_holds_clear=True)
    assert receipt["status"] == "purged-with-retained-exceptions"
    assert any(row["state"] == "external-unverified" for row in receipt["exceptions"])


def test_reviewer_revocation_prevents_next_store(request_store, monkeypatch):
    calls = 0
    def authorize():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise HTTPException(403, "revoked")
    monkeypatch.setattr(deletion, "_erase_target", lambda *args, **kwargs: pytest.fail("revoked reviewer must not delete"))
    with pytest.raises(HTTPException):
        deletion.apply("PDR-case", 1, "user:reviewer", authorize, None, external_holds_clear=True)
    assert request_store.row["targets"][0]["state"] == "requested"


def test_activation_adapter_preserves_reviewed_owner_and_tombstone_receipt(monkeypatch):
    from maverick_dashboard import employee_activation
    calls = []
    monkeypatch.setattr(employee_activation, "erase_owned_activation", lambda *args, **kwargs: calls.append((args, kwargs)) or {"status": "confirmed", "revision": 2})
    row = {"id": "PDR-case", "owner": "user:alice", "reviewer": "user:reviewer", "channel": "dashboard", "user_id": "alice"}
    target = {"store": "activation_drafts", "records": [{"id": "EAP-one", "revision": 1}]}
    receipt = deletion._erase_target(None, row, target)
    assert receipt["state"] == "purged"
    assert calls[0][0] == ("user:alice", "EAP-one")
    assert calls[0][1]["actor"] == "user:reviewer" and calls[0][1]["expected_revision"] == 1
    assert "created owned workflows" in receipt["retained"]


def test_project_defaults_adapter_refuses_unconfirmed_receipt(monkeypatch):
    from maverick import project_workspaces
    monkeypatch.setattr(project_workspaces, "erase_owned_defaults", lambda *args, **kwargs: {"status": "unconfirmed"})
    row = {"id": "PDR-case", "owner": "user:alice", "reviewer": "user:reviewer", "channel": "dashboard", "user_id": "alice"}
    with pytest.raises(ValueError, match="receipt is not confirmed"):
        deletion._erase_target(None, row, {"store": "project_defaults", "records": [{"id": "PWD-one", "revision": 1}]})


def test_queued_inbox_preview_refuses_inflight_without_dispatch(monkeypatch):
    from maverick import conversation_inbox
    monkeypatch.setattr(deletion.personal_memory, "require_scope", lambda *a: None)
    monkeypatch.setattr(conversation_inbox, "owned_inventory", lambda actor: [{"id": "CI-private", "revision": 2, "inflight": True}])
    with pytest.raises(ValueError, match="active or unconfirmed"):
        deletion.preview("user:a", "dashboard", "a", ["conversation_inbox"], None)


def test_queued_inbox_erasure_uses_review_owner_revision_and_distinct_actor(monkeypatch):
    from maverick import conversation_inbox
    calls = []
    monkeypatch.setattr(conversation_inbox, "erase_owned", lambda *a, **kw: calls.append((a, kw)) or {"status": "confirmed"})
    result = deletion._erase_target(None, {"id": "PDR-one", "owner": "user:a", "reviewer": "user:b", "channel": "dashboard", "user_id": "a"},
                                   {"store": "conversation_inbox", "records": [{"id": "CI-one", "revision": 3}]})
    assert calls[0][0][:3] == ("user:a", "CI-one", 3)
    assert calls[0][1] == {"actor": "user:b"}
    assert result["state"] == "purged"
    assert "tombstones" in result["retained"]


def test_queued_inbox_unconfirmed_audit_never_claims_purge(monkeypatch):
    from maverick import conversation_inbox
    monkeypatch.setattr(conversation_inbox, "erase_owned", lambda *a, **kw: {"status": "unconfirmed"})
    with pytest.raises(ValueError, match="unconfirmed"):
        deletion._erase_target(None, {"id": "PDR-one", "owner": "user:a", "reviewer": "user:b", "channel": "dashboard", "user_id": "a"},
                               {"store": "conversation_inbox", "records": [{"id": "CI-one", "revision": 3}]})


def test_diagnostic_report_erasure_includes_reports_archived_when_full(monkeypatch):
    # A full diagnostics namespace archives its oldest settled reports; they are
    # still the person's data, so erasure must list and delete them too.
    import maverick.audit as audit
    from maverick.governed_records import GovernedRecordStore

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(audit, "record", lambda *_args, **_row: True)
    store = GovernedRecordStore("owned_task_diagnostics", "OTD", "owned_task_diagnostics")
    monkeypatch.setattr(deletion, "DIAGNOSTICS", store)
    store.create({"id": "OTD-ada-old", "owner": "user:ada", "goal_id": 1, "status": "done"},
                 action="prepare_report", actor="user:ada", max_records=1)
    store.create({"id": "OTD-bob-new", "owner": "user:bob", "goal_id": 2, "status": "done"},
                 action="prepare_report", actor="user:bob", max_records=1)
    assert [row["id"] for row in store.list_archived()] == ["OTD-ada-old"]

    records = deletion._diagnostic_records("user:ada")
    assert [row["id"] for row in records] == ["OTD-ada-old"]
    assert store.delete(records[0]["id"], expected_revision=records[0]["revision"]) is True
    assert store.get("OTD-ada-old") is None
