"""Split documents into overlapping chunks for embedding."""
from __future__ import annotations


def chunk_text(text: str, size: int = 1000, overlap: int = 200) -> list[str]:
    """Greedy fixed-size chunks with character overlap.

    Simple and deterministic -- good enough for retrieval over business docs;
    smarter (sentence/heading-aware) splitting can swap in later behind the same
    signature. ``overlap`` keeps context across boundaries so a fact split by a
    chunk edge stays retrievable.
    """
    text = (text or "").strip()
    if not text:
        return []
    size = max(1, size)
    overlap = max(0, min(overlap, size - 1))
    step = size - overlap
    chunks: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        chunks.append(text[i:i + size])
        i += step
    return chunks
