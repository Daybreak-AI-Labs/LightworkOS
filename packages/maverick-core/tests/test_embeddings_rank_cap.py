"""embeddings rank must bound its candidate set: every candidate is embedded, so
an unbounded model-supplied list is a memory / compute DoS. The cap (and the
query/candidate validation) run before the model loads, so no extra is needed."""
from __future__ import annotations

from maverick.tools.embeddings import _MAX_RANK_CANDIDATES, _op_rank


def test_rank_rejects_too_many_candidates():
    out = _op_rank("q", ["c"] * (_MAX_RANK_CANDIDATES + 1), 5, "m")
    assert out.startswith("ERROR") and "at most" in out


def test_rank_requires_query():
    assert _op_rank("", ["a"], 5, "m").startswith("ERROR")
    assert _op_rank("   ", ["a"], 5, "m").startswith("ERROR")


def test_rank_requires_non_empty_candidates():
    assert _op_rank("q", [], 5, "m").startswith("ERROR")
    assert _op_rank("q", ["", "   "], 5, "m").startswith("ERROR")  # all-blank filtered
