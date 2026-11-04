"""Tests for the NewsAPI tool (maverick.tools.newsapi_tool)."""
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


def _resp(status, body, *, text=None):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = text if text is not None else str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = text if text is not None else str(body)
    r.content = (body if isinstance(body, bytes) else str(body).encode())
    return r


# ---------- NewsAPI ----------

def test_newsapi_requires_op():
    from maverick.tools.newsapi_tool import newsapi_tool
    assert "op is required" in newsapi_tool().fn({})


def test_newsapi_missing_key(monkeypatch):
    monkeypatch.delenv("NEWSAPI_KEY", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.newsapi_tool import newsapi_tool
    out = newsapi_tool().fn({"op": "top_headlines"})
    assert "NEWSAPI_KEY" in out


def test_newsapi_search_renders(monkeypatch):
    monkeypatch.setenv("NEWSAPI_KEY", "k")
    body = {"status": "ok", "totalResults": 1, "articles": [
        {"source": {"name": "TechCrunch"}, "title": "AI breakthrough",
         "url": "https://tc/1"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.newsapi_tool import newsapi_tool
    out = newsapi_tool().fn({"op": "search", "query": "ai"})
    assert "AI breakthrough" in out and "TechCrunch" in out
