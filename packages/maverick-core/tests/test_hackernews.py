"""Tests for the Hacker News tool (maverick.tools.hackernews)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for n, v in methods.items():
        setattr(mod, n, v)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


# ---------- hackernews: null points on comment hits ----------

def test_hackernews_handles_null_points(monkeypatch):
    body = {"hits": [
        {"title": None, "comment_text": "a comment", "points": None,
         "objectID": "42"},
    ]}
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=body)
    _fake_httpx(monkeypatch, get=MagicMock(return_value=resp))
    from maverick.tools.hackernews import hackernews
    out = hackernews().fn({"op": "search", "query": "x"})
    assert "ERROR" not in out


# ---------- Hacker News tool ----------

def test_hn_requires_op():
    from maverick.tools.hackernews import hackernews
    assert "op is required" in hackernews().fn({})


def test_hn_top_renders(monkeypatch):
    # Two responses: the id list, then per-item fetches.
    def _make_get_side_effects():
        ids_resp = MagicMock()
        ids_resp.status_code = 200
        ids_resp.json = MagicMock(return_value=[111, 222])
        item1 = MagicMock()
        item1.status_code = 200
        item1.json = MagicMock(return_value={
            "title": "Story One", "score": 100, "descendants": 5,
            "url": "https://x/1",
        })
        item2 = MagicMock()
        item2.status_code = 200
        item2.json = MagicMock(return_value={
            "title": "Story Two", "score": 50, "descendants": 2,
            "url": "https://x/2",
        })
        return iter([ids_resp, item1, item2])

    seq = _make_get_side_effects()
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(side_effect=lambda *a, **k: next(seq))
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.hackernews import hackernews
    out = hackernews().fn({"op": "top", "limit": 2})
    assert "Story One" in out and "Story Two" in out
    assert "https://x/1" in out


def test_hn_get_story(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "id": 100, "type": "story", "title": "A story",
        "by": "alice", "score": 42, "descendants": 7,
        "url": "https://example.com", "text": "body",
    })
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.hackernews import hackernews
    out = hackernews().fn({"op": "get", "item_id": 100})
    assert "[story #100]" in out
    assert "by alice" in out


def test_hn_search_via_algolia(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"hits": [
        {"title": "DeepSeek release", "points": 200,
         "url": "https://x", "objectID": "1"},
    ]})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.hackernews import hackernews
    out = hackernews().fn({"op": "search", "query": "deepseek"})
    assert "DeepSeek release" in out
