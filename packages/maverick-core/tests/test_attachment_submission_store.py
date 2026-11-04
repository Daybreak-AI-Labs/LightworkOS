"""Actual SQLite multi-connection admission, retry and crash-boundary contracts."""
from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from maverick import attachments
from maverick.attachment_submissions import SubmissionConflict, SubmissionStore
from maverick.world_model import WorldModel


def _create(store, *, token="request-1", owner="user:alice", fingerprint="a" * 64):
    return store.create(token=token, fingerprint=fingerprint, owner=owner,
                        title="Review", description="Source document", manifest=[])


def test_submission_and_goal_commit_together_as_non_running_draft(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        store = SubmissionStore(world)
        receipt = _create(store)
        assert receipt["state"] == "draft" and receipt["created"]
        assert world.get_goal(receipt["goal_id"]).status == "draft"
        assert not world.list_goals(status="pending")
        assert _create(store)["goal_id"] == receipt["goal_id"]
        assert len(world.list_goals()) == 1
        with pytest.raises(SubmissionConflict, match="different content"):
            _create(store, fingerprint="b" * 64)
        assert _create(store, owner="user:bob")["goal_id"] != receipt["goal_id"]


def test_receipt_lookup_is_owner_scoped_and_retained_store_rejects_tenant_change(tmp_path):
    from maverick.paths import tenant_scope

    with WorldModel(tmp_path / "world.db") as world:
        store = SubmissionStore(world)
        receipt = _create(store)
        assert store.lookup(token="request-1", owner="user:alice")["goal_id"] == receipt["goal_id"]
        assert store.lookup(token="request-1", owner="user:bob") is None
        with tenant_scope(tenant="different-tenant"):
            with pytest.raises(SubmissionConflict, match="context changed"):
                store.lookup(token="request-1", owner="user:alice")


def test_receipt_insert_failure_rolls_back_goal_creation(tmp_path, monkeypatch):
    with WorldModel(tmp_path / "world.db") as world:
        store = SubmissionStore(world)
        execute = store.execute

        def fail(connection, sql, parameters=()):
            if sql.startswith("INSERT INTO attachment_submissions"):
                raise OSError("receipt write failed")
            return execute(connection, sql, parameters)

        monkeypatch.setattr(store, "execute", fail)
        with pytest.raises(OSError):
            _create(store)
        assert world.list_goals() == []


def test_independent_connections_replay_one_goal_and_claim_dispatch_once(tmp_path):
    path = tmp_path / "world.db"
    with WorldModel(path):
        pass

    def submit(_):
        with WorldModel(path) as world:
            return _create(SubmissionStore(world))["goal_id"]

    with ThreadPoolExecutor(max_workers=4) as executor:
        ids = list(executor.map(submit, range(8)))
    assert len(set(ids)) == 1
    with WorldModel(path) as world:
        store = SubmissionStore(world)
        receipt = _create(store)
        assert not store.claim_dispatch(receipt["key"])
        store.update(receipt["key"], state="ready", message="Evidence explicitly available or unavailable")
        assert world.get_goal(ids[0]).result in (None, "")
        assert store.for_goal(ids[0])["detail"]["message"] == "Evidence explicitly available or unavailable"
        assert store.claim_dispatch(receipt["key"])
        assert not store.claim_dispatch(receipt["key"])
        assert world.get_goal(ids[0]).status == "pending"


def test_cancelled_draft_cannot_claim_dispatch(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        store = SubmissionStore(world)
        receipt = _create(store)
        store.update(receipt["key"], state="ready", message="Ready")
        world.set_goal_status(receipt["goal_id"], "cancelled", result="User cancelled this task")
        store.update(receipt["key"], state="ready", message="Delayed preparation finished")
        assert not store.claim_dispatch(receipt["key"])
        assert world.get_goal(receipt["goal_id"]).status == "cancelled"
        assert world.get_goal(receipt["goal_id"]).result == "User cancelled this task"


def test_public_metadata_admission_preserves_supplied_path(tmp_path):
    with WorldModel(tmp_path / "world.db") as world:
        goal_id = world.create_goal("Existing stored attachment")
        world.add_attachment(goal_id, "r.pdf", "application/pdf", 3, "a" * 64, "/tmp/r.pdf")
        assert world.list_attachments(goal_id)[0].path == "/tmp/r.pdf"


def test_concurrent_quota_admission_and_duplicate_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(attachments, "MAX_GOAL_BYTES", 5)
    path = tmp_path / "world.db"
    with WorldModel(path) as world:
        goal_id = world.create_goal("Attachments")

    def attach(index):
        with WorldModel(path) as world:
            try:
                return world.add_attachment(goal_id, f"{index}.txt", "text/plain", 3,
                                            hashlib.sha256(str(index).encode()).hexdigest(), str(tmp_path / f"{index}.txt"))
            except attachments.AttachmentRejected:
                return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(attach, range(2)))
    assert sum(value is not None for value in ids) == 1
    with WorldModel(path) as world:
        records = world.list_attachments(goal_id)
        assert sum(r.size_bytes for r in records) == 3
        record = records[0]
        assert world.add_attachment(goal_id, record.filename, record.mime, record.size_bytes, record.sha256, record.path) == record.id
        assert len(world.list_attachments(goal_id)) == 1


def test_batch_quota_rejection_precedes_file_publication(tmp_path, monkeypatch):
    monkeypatch.setattr(attachments, "MAX_GOAL_BYTES", 5)
    with WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("Quota")
        records = [attachments.Stored(f"{i}.txt", "text/plain", 3, str(i) * 64, tmp_path / f"{i}.txt") for i in range(2)]
        with pytest.raises(attachments.AttachmentRejected):
            SubmissionStore(world).admit(goal, records, publish=lambda r: pytest.fail("quota refusal published file"))
        assert world.list_attachments(goal) == []
