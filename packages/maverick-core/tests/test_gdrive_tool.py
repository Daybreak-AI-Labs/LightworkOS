"""Tests for the Google Drive tool (maverick.tools.gdrive_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    elif isinstance(body, str):
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = body
    else:
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    r.content = (body if isinstance(body, bytes) else str(body).encode("utf-8"))
    return r


# ---------- Google Drive ----------

def test_gdrive_requires_op():
    from maverick.tools.gdrive_tool import gdrive_tool
    assert "op is required" in gdrive_tool().fn({})


def test_gdrive_missing_token(monkeypatch):
    monkeypatch.delenv("GDRIVE_ACCESS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.gdrive_tool import gdrive_tool
    out = gdrive_tool().fn({"op": "list"})
    assert "GDRIVE_ACCESS_TOKEN" in out


def test_gdrive_list_renders(monkeypatch):
    monkeypatch.setenv("GDRIVE_ACCESS_TOKEN", "tok")
    body = {"files": [
        {"id": "f1", "name": "Notes", "mimeType": "text/plain"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.gdrive_tool import gdrive_tool
    out = gdrive_tool().fn({"op": "list"})
    assert "f1" in out and "Notes" in out


def test_gdrive_list_follows_next_page_token(monkeypatch):
    monkeypatch.setenv("GDRIVE_ACCESS_TOKEN", "tok")
    page1 = {"files": [{"id": "f1", "name": "one", "mimeType": "text/plain"}],
             "nextPageToken": "tok-2"}
    page2 = {"files": [{"id": "f2", "name": "two", "mimeType": "text/plain"}]}
    get = MagicMock(side_effect=[_resp(200, page1), _resp(200, page2)])
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.gdrive_tool import gdrive_tool
    out = gdrive_tool().fn({"op": "list", "page_size": 50})
    assert "f1" in out and "f2" in out
    assert get.call_count == 2
    assert get.call_args_list[1].kwargs["params"]["pageToken"] == "tok-2"


def test_gdrive_create_dry_run(monkeypatch):
    monkeypatch.setenv("GDRIVE_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.gdrive_tool import gdrive_tool
    out = gdrive_tool().fn({
        "op": "create", "name": "test.txt", "content": "hi",
    })
    assert "DRY RUN" in out
