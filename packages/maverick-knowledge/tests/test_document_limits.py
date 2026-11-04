"""Ingestion accepts only documents its default exact projection can read."""
from __future__ import annotations

import hashlib

import pytest
from maverick_knowledge import KnowledgeBase
from maverick_knowledge.embed import DeterministicEmbedder


@pytest.mark.parametrize(("size", "overlap"), [(4, 1), (1000, 200)])
def test_oversized_document_rejected_before_embedding_or_publication(monkeypatch, size, overlap):
    with KnowledgeBase(embedder=DeterministicEmbedder(4), chunk_size=size,
                       chunk_overlap=overlap) as kb:
        text = "x" * (2048 * (size - overlap) + 1)
        calls = []
        embed = kb.embedder.embed

        def counted(texts):
            calls.append(len(texts))
            return embed(texts)

        monkeypatch.setattr(kb.embedder, "embed", counted)
        for _ in range(2):
            with pytest.raises(ValueError, match="2048.*chunks"):
                kb.ingest_text("records", text, source="oversized.txt")
            assert kb.store.count("records") == 0
            assert calls == []


def test_largest_admitted_document_is_exactly_readable_and_retry_is_free(monkeypatch):
    with KnowledgeBase(embedder=DeterministicEmbedder(4), chunk_size=4,
                       chunk_overlap=1) as kb:
        text = "x" * (2048 * 3)
        assert kb.ingest_text("records", text, source="largest.txt") == 2048
        digest = hashlib.sha256(text.encode()).hexdigest()
        assert kb.exact_document("records", digest)["text"] == text

        def unexpected(_texts):
            pytest.fail("a matching retry must not repeat embedding")

        monkeypatch.setattr(kb.embedder, "embed", unexpected)
        assert kb.ingest_text("records", text, source="largest.txt") == 2048
        assert kb.store.count("records") == 2048
