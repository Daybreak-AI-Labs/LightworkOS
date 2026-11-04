"""Tests for the Confluence tool (maverick.tools.confluence_tool)."""
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


def _confluence_env(monkeypatch):
    monkeypatch.setenv("CONFLUENCE_URL", "https://x.atlassian.net/wiki")
    monkeypatch.setenv("CONFLUENCE_USER", "u@x")
    monkeypatch.setenv("CONFLUENCE_API_TOKEN", "tok")


# ---------- Confluence ----------

def test_confluence_requires_op():
    from maverick.tools.confluence_tool import confluence_tool
    assert "op is required" in confluence_tool().fn({})


def test_confluence_missing_config(monkeypatch):
    for k in ("CONFLUENCE_URL", "CONFLUENCE_USER", "CONFLUENCE_API_TOKEN"):
        monkeypatch.delenv(k, raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.confluence_tool import confluence_tool
    out = confluence_tool().fn({"op": "search", "cql": "text ~ 'x'"})
    assert "CONFLUENCE_URL" in out


def test_confluence_page_get_strips_html(monkeypatch):
    monkeypatch.setenv("CONFLUENCE_URL", "https://x.atlassian.net/wiki")
    monkeypatch.setenv("CONFLUENCE_USER", "u@x")
    monkeypatch.setenv("CONFLUENCE_API_TOKEN", "tok")
    body = {
        "id": "123", "title": "Roadmap",
        "space": {"key": "ENG"}, "version": {"number": 3},
        "body": {"storage": {"value": "<p>Hello <b>world</b></p>"}},
    }
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.confluence_tool import confluence_tool
    out = confluence_tool().fn({"op": "page_get", "page_id": "123"})
    assert "Hello world" in out and "<p>" not in out


def test_confluence_page_create_dry_run(monkeypatch):
    monkeypatch.setenv("CONFLUENCE_URL", "https://x.atlassian.net/wiki")
    monkeypatch.setenv("CONFLUENCE_USER", "u@x")
    monkeypatch.setenv("CONFLUENCE_API_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.confluence_tool import confluence_tool
    out = confluence_tool().fn({
        "op": "page_create", "space_key": "ENG", "title": "New",
    })
    assert "DRY RUN" in out


def test_confluence_page_create_sends_space_key(monkeypatch):
    # The v1 content API keys space by KEY (space.key). Confirm the
    # space_key arg lands in payload["space"]["key"].
    _confluence_env(monkeypatch)
    post = MagicMock(return_value=_resp(200, {"id": "999", "title": "New"}))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.confluence_tool import confluence_tool
    confluence_tool().fn({
        "op": "page_create", "space_key": "ENG", "title": "New",
        "body": "<p>hi</p>", "confirm": True,
    })
    payload = post.call_args.kwargs["json"]
    assert payload["space"]["key"] == "ENG"


def test_confluence_page_create_accepts_legacy_space_id(monkeypatch):
    # Back-compat: the old `space_id` arg still works (treated as the key).
    _confluence_env(monkeypatch)
    post = MagicMock(return_value=_resp(200, {"id": "999", "title": "New"}))
    _fake_httpx(monkeypatch, post=post)
    from maverick.tools.confluence_tool import confluence_tool
    confluence_tool().fn({
        "op": "page_create", "space_id": "ENG", "title": "New", "confirm": True,
    })
    assert post.call_args.kwargs["json"]["space"]["key"] == "ENG"
