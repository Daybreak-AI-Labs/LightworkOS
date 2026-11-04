"""A failed starter-corpus refresh must retain the accepted reference material."""
from __future__ import annotations

import sqlite3

import pytest
from maverick import knowledge_seed
from maverick_knowledge import KnowledgeBase
from maverick_knowledge.embed import DeterministicEmbedder


def _snapshot(kb):
    return kb.store.read_collection("itgrc", limit=1000)


def _revised_corpus(monkeypatch):
    corpus = knowledge_seed._CORPORA[0]
    source, text = corpus["documents"][0]
    revised = text + " This revised reference includes additional review guidance."
    monkeypatch.setattr(knowledge_seed, "_CORPORA", [
        {**corpus, "documents": [(source, revised)]},
    ])
    return source, revised


def test_identical_seed_does_not_embed_or_change_accepted_rows(monkeypatch):
    with KnowledgeBase(embedder=DeterministicEmbedder(4)) as kb:
        first = knowledge_seed.seed_corpora(kb, only="itgrc")
        before = _snapshot(kb)

        def unavailable(_texts):
            pytest.fail("an identical seed must reuse the admitted document")

        monkeypatch.setattr(kb.embedder, "embed", unavailable)
        assert knowledge_seed.seed_corpora(kb, only="itgrc") == first
        assert _snapshot(kb) == before


@pytest.mark.parametrize("failure", ["identity", "embedding", "publication", "retirement"])
def test_failed_seed_replacement_preserves_complete_prior_corpus(monkeypatch, failure):
    with KnowledgeBase(embedder=DeterministicEmbedder(4)) as kb:
        knowledge_seed.seed_corpora(kb, only="itgrc")
        before = _snapshot(kb)
        _revised_corpus(monkeypatch)
        if failure == "identity":
            kb.embedder = DeterministicEmbedder(8)
        elif failure == "embedding":
            def unavailable(_texts):
                raise RuntimeError("synthetic embedding outage")

            monkeypatch.setattr(kb.embedder, "embed", unavailable)
        else:
            # A real storage failure during publication must roll back its
            # transaction, including any staged removal of prior source rows.
            operation = "DELETE" if failure == "retirement" else "INSERT"
            kb.store._db.execute(
                f"CREATE TRIGGER refuse_refresh BEFORE {operation} ON chunks "
                "BEGIN SELECT RAISE(ABORT, 'synthetic publication failure'); END"
            )
            kb.store._db.commit()
        with pytest.raises((RuntimeError, sqlite3.IntegrityError)):
            knowledge_seed.seed_corpora(kb, only="itgrc")
        assert _snapshot(kb) == before


def test_successful_seed_revision_replaces_only_its_source(monkeypatch):
    with KnowledgeBase(embedder=DeterministicEmbedder(4)) as kb:
        knowledge_seed.seed_corpora(kb, only="itgrc")
        before = _snapshot(kb)
        source, revised = _revised_corpus(monkeypatch)
        report = knowledge_seed.seed_corpora(kb, only="itgrc")
        after = _snapshot(kb)
        assert [row for row in after if row.meta["source"] != source] == [
            row for row in before if row.meta["source"] != source
        ]
        replacement = [row for row in after if row.meta["source"] == source]
        assert len(replacement) == report["itgrc"]
        assert kb.exact_document("itgrc", replacement[0].meta["doc_sha256"])["text"] == revised
        assert not {row.chunk_id for row in replacement} & {
            row.chunk_id for row in before if row.meta["source"] == source
        }
