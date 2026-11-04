"""Compaction RAG path: embed + similarity-retrieve episode digests."""
from __future__ import annotations

from maverick.compaction import (
    DigestEntry,
    DigestIndex,
    _cosine,
    compact_messages,
    recall_relevant_digests,
)


class FakeEmbedder:
    """Deterministic bag-of-words embedder over a fixed vocabulary.

    Each text becomes a count vector over ``VOCAB`` so cosine ordering is
    fully predictable without loading any real model.
    """

    VOCAB = ["alpha", "beta", "gamma", "delta", "epsilon"]

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for t in texts:
            words = t.lower().split()
            out.append([float(words.count(w)) for w in self.VOCAB])
        return out


class TestCosine:
    def test_identical_vectors(self):
        assert _cosine([1.0, 2.0, 3.0], [1.0, 2.0, 3.0]) == 1.0

    def test_orthogonal_vectors(self):
        assert _cosine([1.0, 0.0], [0.0, 1.0]) == 0.0

    def test_zero_vector_no_division_error(self):
        assert _cosine([0.0, 0.0], [1.0, 1.0]) == 0.0
        assert _cosine([0.0, 0.0], [0.0, 0.0]) == 0.0

    def test_mismatched_length(self):
        assert _cosine([1.0], [1.0, 2.0]) == 0.0

    def test_empty(self):
        assert _cosine([], []) == 0.0


class TestDigestIndex:
    def test_add_and_retrieve_most_similar_first(self):
        emb = FakeEmbedder()
        idx = DigestIndex()
        idx.add("alpha alpha beta", turn=1, embedder=emb)
        idx.add("gamma delta", turn=2, embedder=emb)
        idx.add("epsilon epsilon", turn=3, embedder=emb)

        hits = idx.retrieve("alpha beta", emb, k=3)
        assert hits[0].turn == 1  # shares alpha+beta -> highest cosine

    def test_respects_k(self):
        emb = FakeEmbedder()
        idx = DigestIndex()
        for i, txt in enumerate(["alpha", "beta", "gamma", "delta"]):
            idx.add(txt, turn=i, embedder=emb)
        assert len(idx.retrieve("alpha beta gamma delta", emb, k=2)) == 2

    def test_add_many_batches(self):
        emb = FakeEmbedder()
        idx = DigestIndex()
        idx.add_many([("alpha", 0), ("beta", 1)], emb)
        assert len(idx.entries) == 2
        assert all(isinstance(e, DigestEntry) for e in idx.entries)

    def test_empty_index_returns_empty(self):
        assert DigestIndex().retrieve("alpha", FakeEmbedder(), k=3) == []

    def test_k_zero_returns_empty(self):
        emb = FakeEmbedder()
        idx = DigestIndex()
        idx.add("alpha", turn=0, embedder=emb)
        assert idx.retrieve("alpha", emb, k=0) == []


class TestRecallBlock:
    def test_formats_recall_block(self):
        emb = FakeEmbedder()
        idx = DigestIndex()
        idx.add("alpha beta", turn=7, embedder=emb)
        block = recall_relevant_digests("alpha beta", idx, emb, k=1)
        assert block.startswith("<recall>")
        assert block.endswith("</recall>")
        assert "[turn 7] alpha beta" in block

    def test_empty_when_nothing_retrieved(self):
        assert recall_relevant_digests("x", DigestIndex(), FakeEmbedder()) == ""


class TestFailOpen:
    """compact_messages must be byte-identical with no embedder supplied."""

    def _sample(self) -> list[dict]:
        big = "x" * 5000
        return [
            {"role": "user", "content": "the original brief"},
            {"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": "abc", "content": big,
            }]},
            {"role": "assistant", "content": [{
                "type": "text", "text": "y" * 5000,
            }]},
            {"role": "user", "content": "recent-1"},
            {"role": "assistant", "content": "recent-2"},
        ]

    def test_compact_unchanged_by_rag_module(self):
        msgs = self._sample()
        # The RAG additions live in the same module; importing them must not
        # alter compact_messages output.
        out = compact_messages(msgs, keep_recent=2, max_tool_bytes=100)
        # Brief preserved verbatim.
        assert out[0] == msgs[0]
        # Recent two untouched.
        assert out[-2:] == msgs[-2:]
        # Oversized old blocks shrunk.
        tr = out[1]["content"][0]
        assert "truncated" in tr["content"]
        txt = out[2]["content"][0]
        assert txt["text"].endswith("truncated to 100B]")
