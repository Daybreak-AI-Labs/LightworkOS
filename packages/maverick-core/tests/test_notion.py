"""Tests for the Notion tool (maverick.tools.notion)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Notion tool ----------

def test_notion_requires_op():
    from maverick.tools.notion import notion
    assert "op is required" in notion().fn({})


def test_notion_missing_token(monkeypatch):
    monkeypatch.delenv("NOTION_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.notion import notion
    out = notion().fn({"op": "search", "query": "x"})
    assert "NOTION_TOKEN" in out


def test_notion_search_renders(monkeypatch):
    monkeypatch.setenv("NOTION_TOKEN", "ntn_xx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"results": [{
        "object": "page", "id": "abcd1234efgh",
        "properties": {"title": {
            "type": "title",
            "title": [{"plain_text": "My Page"}],
        }},
    }]})

    fake_client = MagicMock()
    fake_client.post = MagicMock(return_value=resp)
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.notion import notion
    out = notion().fn({"op": "search", "query": "page"})
    assert "My Page" in out


def test_notion_search_follows_cursor_pagination(monkeypatch):
    monkeypatch.setenv("NOTION_TOKEN", "ntn_xx")

    def _page(title, has_more, cursor):
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value={
            "results": [{
                "object": "page", "id": f"id-{title}",
                "properties": {"title": {
                    "type": "title", "title": [{"plain_text": title}],
                }},
            }],
            "has_more": has_more,
            "next_cursor": cursor,
        })
        return resp

    fake_client = MagicMock()
    fake_client.post = MagicMock(side_effect=[
        _page("Alpha", True, "cur-2"),
        _page("Beta", False, None),
    ])
    fake_client.__enter__ = MagicMock(return_value=fake_client)
    fake_client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=fake_client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.notion import notion
    out = notion().fn({"op": "search", "query": "x", "limit": 50})
    assert "Alpha" in out and "Beta" in out
    assert fake_client.post.call_count == 2
    # Second request carries the start_cursor from the first response.
    assert fake_client.post.call_args_list[1].kwargs["json"]["start_cursor"] == "cur-2"


def test_notion_page_create_requires_args():
    from maverick.tools.notion import notion
    out = notion().fn({"op": "page_create"})
    assert "parent_id and title" in out
