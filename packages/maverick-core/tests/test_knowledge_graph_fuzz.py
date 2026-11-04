"""Regression: knowledge_graph must not crash on malformed model-supplied args."""
from __future__ import annotations

from maverick.tools.knowledge_graph import knowledge_graph


def _fn():
    return knowledge_graph().fn


def test_extract_non_string_text():
    fn = _fn()
    for v in (5, 1.5, True, [1, 2, 3], {"a": 1}):
        out = fn({"op": "extract", "text": v})
        assert isinstance(out, str)


def test_query_non_iterable_triples():
    fn = _fn()
    for v in (5, 1.5, True):
        out = fn({"op": "query", "triples": v, "subject": "a"})
        assert isinstance(out, str)


def test_query_non_string_terms():
    fn = _fn()
    out = fn({"op": "query", "triples": [["a", "rel", "b"]], "subject": 5})
    assert isinstance(out, str)


def test_neighbors_non_string_node():
    out = _fn()({"op": "neighbors", "triples": [["a", "rel", "b"]], "node": 5})
    assert isinstance(out, str)
