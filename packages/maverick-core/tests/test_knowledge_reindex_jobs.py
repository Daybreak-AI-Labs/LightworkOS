"""Offline durable rebuilds: immutable live index, explicit recovery, bounded policy."""
from __future__ import annotations

import uuid

import pytest
from maverick import knowledge_reindex_jobs as jobs
from maverick_knowledge import DeterministicEmbedder, KnowledgeBase, SqliteVectorStore


@pytest.fixture()
def setup(tmp_path, monkeypatch):
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda: {"knowledge": {"reindex_jobs": True}})
    monkeypatch.setattr(jobs, "data_dir", lambda: tmp_path)
    kb = KnowledgeBase(store=SqliteVectorStore(tmp_path / "knowledge.db"), embedder=DeterministicEmbedder(8))
    for i in range(130):
        kb.ingest_text("policies", "exact text " + str(i), source="source-" + str(i))
    kb.embedder = DeterministicEmbedder(12)
    yield kb, "a" * 64
    kb.close()


def start(kb, context):
    review = jobs.preview(kb, "policies")
    job_id = uuid.uuid4().hex
    return jobs.start(kb, context=context, job_id=job_id, collection="policies", review=review["review"])


def test_rebuild_publishes_all_at_once_and_duplicate_start_is_status_only(setup):
    kb, context = setup
    review = jobs.preview(kb, "policies")
    job = start(kb, context)
    before = kb.store.read_collection("policies", limit=1000)
    embed = kb.embedder.embed
    seen = []
    def checked(texts):
        assert kb.store.read_collection("policies", limit=1000) == before
        seen.append(len(texts))
        return embed(texts)
    kb.embedder.embed = checked
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "completed" and final["done"] == 130
    assert seen == [64, 64, 2]
    again = jobs.start(kb, context=context, job_id=job["job_id"], collection="policies", review=review["review"])
    assert again["state"] == "completed"
    jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert seen == [64, 64, 2]
    assert jobs.list_jobs("b" * 64) == []
    jobs.archive(context, job["job_id"])
    assert jobs.list_jobs(context) == []
    assert len(jobs.list_jobs(context, include_archived=True)) == 1
    assert jobs.start(kb, context=context, job_id=job["job_id"], collection="policies", review=review["review"])["state"] == "completed"


def test_cancel_finishes_only_current_batch_and_preserves_live_index(setup):
    kb, context = setup
    job = start(kb, context)
    before = kb.store.read_collection("policies", limit=1000)
    embed = kb.embedder.embed
    def cancelling(texts):
        jobs.cancel(context, job["job_id"])
        return embed(texts)
    kb.embedder.embed = cancelling
    final = jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    assert final["state"] == "cancelled" and final["done"] == 64
    assert kb.store.read_collection("policies", limit=1000) == before


def test_source_change_and_revoked_authority_prevent_publication(setup):
    kb, context = setup
    job = start(kb, context)
    before = kb.store.read_collection("policies", limit=1000)
    def denied():
        raise PermissionError("revoked")
    assert jobs.run(kb, context=context, job_id=job["job_id"], authority=denied)["state"] == "failed"
    assert kb.store.read_collection("policies", limit=1000) == before
    second = start(kb, context)
    kb.store.delete_where("policies", "source", "source-2")
    assert jobs.run(kb, context=context, job_id=second["job_id"], authority=lambda: None)["state"] == "changed"


def test_paid_adapter_is_blocked_before_embedding_or_dispatch(setup):
    from maverick_knowledge.embed import HostedEmbedder
    kb, _ = setup
    kb.embedder = HostedEmbedder("test-fixture", "https://example.invalid", "not-a-real-key")
    with pytest.raises(ValueError, match="No reviewed standard embedding price"):
        jobs.preview(kb, "policies")


def test_explicit_restart_resumes_shadow_without_repeating_saved_batches(setup, monkeypatch):
    kb, context = setup
    job = start(kb, context)
    original = jobs._update
    def interrupted(path, **changes):
        result = original(path, **changes)
        if changes == {"done": 64}:
            raise KeyboardInterrupt("simulate process death after durable checkpoint")
        return result
    monkeypatch.setattr(jobs, "_update", interrupted)
    with pytest.raises(KeyboardInterrupt):
        jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)
    monkeypatch.setattr(jobs, "_update", original)
    seen = []
    embed = kb.embedder.embed
    def counted(texts):
        seen.append(len(texts))
        return embed(texts)
    kb.embedder.embed = counted
    assert jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)["state"] == "completed"
    assert seen == [64, 2]


def test_source_edit_between_review_and_second_read_is_refused(setup, monkeypatch):
    kb, context = setup
    job = start(kb, context)
    original = kb.store.read_collection
    calls = 0
    def racing(collection, *, limit):
        nonlocal calls
        calls += 1
        if calls == 2:
            kb.store.delete_where("policies", "source", "source-2")
        return original(collection, limit=limit)
    monkeypatch.setattr(kb.store, "read_collection", racing)
    assert jobs.run(kb, context=context, job_id=job["job_id"], authority=lambda: None)["state"] == "changed"


def test_a_short_or_malformed_cohere_batch_fails_at_that_batch():
    # The indexed providers check count and order; Cohere's list was trusted,
    # so a short batch failed only after every later batch had been paid for.
    import pytest
    from maverick.knowledge_reindex_billing import _vectors

    good = {"embeddings": {"float": [[0.1, 0.2], [0.3, 0.4]]}}
    assert _vectors(good, "cohere", 2) == [[0.1, 0.2], [0.3, 0.4]]
    for body in ({"embeddings": {"float": [[0.1, 0.2]]}}, {"embeddings": {"float": [[0.1], []]}},
                 {"embeddings": {}}, {"embeddings": {"float": "nope"}}, []):
        with pytest.raises(ValueError, match="incomplete embedding set"):
            _vectors(body, "cohere", 2)
