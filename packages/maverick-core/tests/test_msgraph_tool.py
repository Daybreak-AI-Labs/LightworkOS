"""Tests for the Microsoft Graph tool (maverick.tools.msgraph_tool)."""
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


# ---------- MS Graph ----------

def test_msgraph_requires_op():
    from maverick.tools.msgraph_tool import msgraph_tool
    assert "op is required" in msgraph_tool().fn({})


def test_msgraph_missing_token(monkeypatch):
    monkeypatch.delenv("MSGRAPH_ACCESS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.msgraph_tool import msgraph_tool
    out = msgraph_tool().fn({"op": "me"})
    assert "MSGRAPH_ACCESS_TOKEN" in out


def test_msgraph_send_mail_dry_run(monkeypatch):
    monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.msgraph_tool import msgraph_tool
    out = msgraph_tool().fn({
        "op": "send_mail", "to": ["a@x"], "subject": "hi", "body": "yo",
    })
    assert "DRY RUN" in out


def test_msgraph_messages_renders(monkeypatch):
    monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
    body = {"value": [{
        "subject": "Standup", "isRead": False,
        "from": {"emailAddress": {"address": "boss@x"}},
    }]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.msgraph_tool import msgraph_tool
    out = msgraph_tool().fn({"op": "messages"})
    assert "Standup" in out and "boss@x" in out


def test_msgraph_paths_cannot_traverse_to_other_graph_resources(monkeypatch):
    import maverick.governed_http as governed_http

    monkeypatch.setenv("MSGRAPH_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch)
    urls: list[str] = []

    def _request(method, url, **_kw):
        urls.append(url)
        return _resp(200, {"value": []})

    monkeypatch.setattr(governed_http, "request", _request)
    from maverick.tools.msgraph_tool import msgraph_tool
    tool = msgraph_tool()
    tool.fn({"op": "messages", "folder": "../../users/victim@contoso.com"})
    assert tool.fn({"op": "drive_list", "path": "Docs/../../../../users/x"}).startswith("ERROR:")
    tool.fn({"op": "drive_list", "path": "Docs/Q1 Reports"})
    assert urls[0].endswith("/me/mailFolders/..%2F..%2Fusers%2Fvictim%40contoso.com/messages")
    assert urls[1].endswith("/me/drive/root:/Docs/Q1%20Reports:/children")
