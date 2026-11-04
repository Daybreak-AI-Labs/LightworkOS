"""Tests for the Semantic Scholar tool (maverick.tools.semantic_scholar)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

# ---------- semantic_scholar tool ----------

def test_semantic_scholar_requires_op():
    from maverick.tools.semantic_scholar import semantic_scholar
    out = semantic_scholar().fn({})
    assert "ERROR" in out
    assert "op is required" in out


def test_semantic_scholar_unknown_op():
    from maverick.tools.semantic_scholar import semantic_scholar
    out = semantic_scholar().fn({"op": "garbage"})
    assert "unknown op" in out


def test_semantic_scholar_search_requires_query():
    from maverick.tools.semantic_scholar import semantic_scholar
    out = semantic_scholar().fn({"op": "search", "query": ""})
    assert "requires query" in out


def test_semantic_scholar_paper_requires_id():
    from maverick.tools.semantic_scholar import semantic_scholar
    out = semantic_scholar().fn({"op": "paper", "paper_id": ""})
    assert "requires paper_id" in out


def test_semantic_scholar_search_hits_api(monkeypatch):
    from maverick.tools.semantic_scholar import semantic_scholar
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json = MagicMock(return_value={
        "data": [
            {
                "title": "Attention Is All You Need",
                "year": 2017,
                "authors": [{"name": "Vaswani et al."}],
                "citationCount": 100000,
                "abstract": "We propose the Transformer...",
                "url": "https://www.semanticscholar.org/paper/abc",
            },
        ],
    })
    with patch("httpx.get", return_value=fake_resp) as mock_get:
        out = semantic_scholar().fn({"op": "search", "query": "transformer"})
    assert "Attention Is All You Need" in out
    assert "100000" in out
    # API URL hit, fields requested.
    call = mock_get.call_args
    assert "/paper/search" in call.args[0]
    assert "fields" in call.kwargs["params"]


def test_semantic_scholar_paper_by_doi(monkeypatch):
    from maverick.tools.semantic_scholar import semantic_scholar
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json = MagicMock(return_value={
        "title": "T",
        "year": 2024,
        "authors": [{"name": "A"}],
        "citationCount": 1,
        "abstract": "x" * 500,
        "url": "u",
    })
    with patch("httpx.get", return_value=fake_resp) as mock_get:
        out = semantic_scholar().fn({"op": "paper", "paper_id": "10.1234/abc"})
    call = mock_get.call_args
    # DOI without explicit prefix gets prefixed automatically.
    assert "DOI:10.1234/abc" in call.args[0]
    assert "T" in out


def test_semantic_scholar_legacy_arxiv_id(monkeypatch):
    """Old-style arXiv ids contain a slash but are NOT DOIs -- they must be
    looked up as arXiv:<id>, not DOI:<id> (which never resolves)."""
    from maverick.tools.semantic_scholar import semantic_scholar
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.raise_for_status = MagicMock()
    fake_resp.json = MagicMock(return_value={
        "title": "T", "year": 2003, "authors": [{"name": "A"}],
        "citationCount": 1, "abstract": "x", "url": "u",
    })
    with patch("httpx.get", return_value=fake_resp) as mock_get:
        out = semantic_scholar().fn({"op": "paper", "paper_id": "math/0211159"})
    call = mock_get.call_args
    assert "arXiv:math/0211159" in call.args[0]
    assert "DOI:math/0211159" not in call.args[0]
    assert "T" in out


def test_semantic_scholar_404_actionable():
    from maverick.tools.semantic_scholar import semantic_scholar
    fake_resp = MagicMock()
    fake_resp.status_code = 404
    fake_resp.raise_for_status = MagicMock()
    with patch("httpx.get", return_value=fake_resp):
        out = semantic_scholar().fn({
            "op": "paper", "paper_id": "arxiv:0000.0000",
        })
    assert "no paper found" in out
