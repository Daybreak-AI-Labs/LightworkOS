"""Failure/concurrency contract using an explicit atomic in-memory adapter."""
from __future__ import annotations

import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from maverick import semantic_recall as sr


class AtomicStore:
    def __init__(self):
        self.recall_identity = uuid.uuid4().hex
        self.docs = {}
        self.fail = None
        self.writes = 0

    def upsert_one(self, document, *, id, metadata, embedding=None):
        self.writes += 1
        if self.fail == "before":
            raise OSError("pre-commit failure")
        self.docs[id] = (document, dict(metadata), embedding)
        if self.fail == "after":
            raise OSError("acknowledgement lost after commit")

    def query(self, *args, **kwargs):
        return [{"metadata": meta, "distance": 0.0} for _, meta, _ in self.docs.values()]

    def delete(self, ids):
        for id in ids:
            self.docs.pop(id, None)


def goal(title="first", id=1):
    return SimpleNamespace(id=id, title=title, description="", status="done")


@pytest.fixture(autouse=True)
def runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")


@pytest.mark.parametrize("failure", ["before", "after"])
def test_failed_write_is_rebuild_required_without_automatic_retry(failure):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    store.fail = failure
    assert not sr.index_goal(goal("replacement"), store=store)
    assert store.writes == 2
    assert len(store.docs) == 1
    assert store.docs["goal:1"][0] == ("first" if failure == "before" else "replacement")
    assert sr.index_status(store=store) == "rebuild_required"
    assert sr.search("anything", store=store) is None
    # A newly constructed adapter in the same storage/tenant sees the marker.
    reopened = AtomicStore()
    reopened.recall_identity = store.recall_identity
    assert sr.index_status(store=reopened) == "rebuild_required"
    store.fail = None
    assert sr.index_goal(goal("unrelated", 2), store=store)
    assert sr.index_status(store=store) == "rebuild_required"
    assert sr.index_goal(goal("replacement"), store=store)
    assert sr.index_status(store=store) == "ready"
    assert sr.search("anything", store=store)


def test_unsupported_adapter_never_deletes_old_record():
    class Legacy:
        def delete(self, ids):
            pytest.fail("non-atomic adapter must not delete")

        def add(self, *args, **kwargs):
            pytest.fail("non-atomic adapter must not insert")

    store = Legacy()
    assert sr.index_status(store=store) == "unsupported"
    assert not sr.index_goal(goal(), store=store)
    assert sr.search("anything", store=store) is None


def test_absent_is_not_reported_as_successful_empty_search():
    store = AtomicStore()
    assert sr.index_status(store=store) == "absent"
    assert sr.search("anything", store=store) is None


def test_old_client_capability_and_oversized_refresh_are_truthful():
    store = AtomicStore()
    store.supports_atomic_recall = False
    assert sr.index_status(store=store) == "unsupported"
    assert not sr.index_goal(goal(), store=store)
    assert store.writes == 0
    store.supports_atomic_recall = True
    assert sr.index_goal(goal(), store=store)
    assert not sr.index_goal(goal("x" * 65537), store=store)
    assert store.docs["goal:1"][0] == "first"
    assert sr.index_status(store=store) == "rebuild_required"


def test_backend_query_outage_triggers_lexical_fallback(monkeypatch):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)

    def unavailable(*args, **kwargs):
        raise OSError("backend unavailable")

    monkeypatch.setattr(store, "query", unavailable)
    assert sr.search("anything", store=store) is None


def test_pending_write_cannot_release_stale_search_results(monkeypatch):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    entered, release = threading.Event(), threading.Event()
    original = store.upsert_one

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        original(*args, **kwargs)

    monkeypatch.setattr(store, "upsert_one", blocked)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(sr.index_goal, goal("replacement"), store=store)
        assert entered.wait(5)
        assert sr.search("anything", store=store) is None
        release.set()
        assert future.result(5)
    assert sr.search("anything", store=store)


def test_concurrent_removal_fences_inflight_update_and_late_retries(monkeypatch):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    entered, release = threading.Event(), threading.Event()
    original = store.upsert_one

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        original(*args, **kwargs)

    monkeypatch.setattr(store, "upsert_one", blocked)
    with ThreadPoolExecutor(max_workers=2) as pool:
        update = pool.submit(sr.index_goal, goal("replacement"), store=store)
        assert entered.wait(5)
        removal = pool.submit(sr.remove_goal, 1, store=store)
        release.set()
        assert update.result(5)
        assert removal.result(5)
    assert not store.docs
    assert sr.search("anything", store=store) == []
    assert not sr.index_goal(goal("late retry"), store=store)
    assert store.writes == 2
    reopened = AtomicStore()
    reopened.recall_identity = store.recall_identity
    assert not sr.index_goal(goal("another instance"), store=reopened)
    assert reopened.writes == 0


def test_failed_removal_remains_invisible_and_explicitly_retryable(monkeypatch):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    original = store.delete

    def failure(ids):
        raise OSError("delete unavailable")

    monkeypatch.setattr(store, "delete", failure)
    assert not sr.remove_goal(1, store=store)
    assert sr.index_status(store=store) == "rebuild_required"
    assert sr.search("anything", store=store) is None
    assert not sr.index_goal(goal("late retry"), store=store)
    monkeypatch.setattr(store, "delete", original)
    assert sr.remove_goal(1, store=store)
    assert not store.docs and sr.index_status(store=store) == "ready"


def test_search_rechecks_revision_and_authority(monkeypatch):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    query = store.query

    def updated(*args, **kwargs):
        hits = query()
        assert sr.index_goal(goal("replacement"), store=store)
        return hits

    monkeypatch.setattr(store, "query", updated)
    assert sr.search("anything", store=store) is None
    monkeypatch.setattr(store, "query", query)
    monkeypatch.setattr("maverick.pilot_learning.excluded", lambda gid: gid == 1)
    assert sr.search("anything", store=store) == []
    assert not sr.index_goal(goal("later retry"), store=store)


def test_exclusion_during_preparation_prevents_write(monkeypatch):
    store = AtomicStore()
    store.requires_precomputed_embeddings = True
    excluded = set()
    monkeypatch.setattr("maverick.pilot_learning.excluded", lambda gid: gid in excluded)

    def embed(texts):
        excluded.add(1)
        return [[1.0, 0.0]]

    monkeypatch.setattr(sr, "_embed_texts", embed)
    assert not sr.index_goal(goal(), store=store)
    assert not store.docs and store.writes == 0
    assert sr.search("anything", store=store) is None


def test_exclusion_during_commit_removes_record_without_resurrection(monkeypatch):
    store = AtomicStore()
    excluded = set()
    monkeypatch.setattr("maverick.pilot_learning.excluded", lambda gid: gid in excluded)
    original = store.upsert_one

    def protect(*args, **kwargs):
        original(*args, **kwargs)
        excluded.add(1)

    monkeypatch.setattr(store, "upsert_one", protect)
    assert not sr.index_goal(goal(), store=store)
    assert not store.docs
    assert not sr.index_goal(goal("late retry"), store=store)
    assert store.writes == 1


@pytest.mark.parametrize("distance", [float("nan"), float("inf")])
def test_nonfinite_distance_is_unavailable(monkeypatch, distance):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    monkeypatch.setattr(store, "query", lambda *a, **k: [{"metadata": {"goal_id": 1}, "distance": distance}])
    assert sr.search("anything", store=store) is None


def test_metadata_cannot_duplicate_content(monkeypatch):
    store = AtomicStore()
    assert sr.index_goal(goal(), store=store)
    monkeypatch.setattr(store, "query", lambda *a, **k: [
        {"metadata": {"goal_id": 1, "status": "done", "result": "secret"}, "distance": 0.0}])
    assert sr.search("anything", store=store) == [(1.0, {"goal_id": 1, "status": "done"})]
