"""Tests for the Linear tool (maverick.tools.linear)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- linear tool ----------

def test_linear_requires_op():
    from maverick.tools.linear import linear
    assert "op is required" in linear().fn({})


def test_linear_unknown_op_returns_validation():
    from maverick.tools.linear import linear
    out = linear().fn({"op": "garbage"})
    assert "unknown op" in out or "ERROR" in out


def test_linear_missing_key(monkeypatch):
    monkeypatch.delenv("LINEAR_API_KEY", raising=False)
    fake = types.ModuleType("httpx")
    fake.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.linear import linear
    out = linear().fn({"op": "search", "query": "bug"})
    assert "LINEAR_API_KEY" in out


def test_linear_search_calls_graphql(monkeypatch):
    monkeypatch.setenv("LINEAR_API_KEY", "lin_api_xxx")
    fake_resp = MagicMock()
    fake_resp.json = MagicMock(return_value={
        "data": {"issueSearch": {"nodes": [
            {"identifier": "ENG-1", "title": "Crash on load",
             "state": {"name": "Todo"}, "url": "https://x", "priority": 2},
        ]}},
    })
    fake_resp.raise_for_status = MagicMock()

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=fake_resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.linear import linear
    out = linear().fn({"op": "search", "query": "crash"})
    assert "ENG-1" in out
    assert "Crash on load" in out
    fake_httpx.post.assert_called_once()


def test_linear_search_follows_pageinfo_cursor(monkeypatch):
    monkeypatch.setenv("LINEAR_API_KEY", "lin_api_xxx")

    def _page(ident, title, has_next, cursor):
        r = MagicMock()
        r.json = MagicMock(return_value={"data": {"issueSearch": {
            "nodes": [{"identifier": ident, "title": title,
                       "state": {"name": "Todo"}, "url": "https://x", "priority": 2}],
            "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
        }}})
        r.raise_for_status = MagicMock()
        return r

    post = MagicMock(side_effect=[
        _page("ENG-1", "first", True, "cur-2"),
        _page("ENG-2", "second", False, None),
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = post
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.linear import linear
    out = linear().fn({"op": "search", "query": "crash", "limit": 50})
    assert "ENG-1" in out and "ENG-2" in out
    assert post.call_count == 2
    assert post.call_args_list[1].kwargs["json"]["variables"]["after"] == "cur-2"


def test_linear_create_requires_team():
    from maverick.tools.linear import linear
    out = linear().fn({"op": "create", "title": "x"})
    assert "title and team" in out
