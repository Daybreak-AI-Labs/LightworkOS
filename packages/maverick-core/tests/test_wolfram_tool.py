"""Tests for the Wolfram Alpha tool (maverick.tools.wolfram_tool)."""
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


# ---------- Wolfram ----------

def test_wolfram_requires_query():
    from maverick.tools.wolfram_tool import wolfram_tool
    out = wolfram_tool().fn({"op": "short"})
    assert "query is required" in out


def test_wolfram_missing_appid(monkeypatch):
    monkeypatch.delenv("WOLFRAM_APP_ID", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.wolfram_tool import wolfram_tool
    out = wolfram_tool().fn({"op": "short", "query": "2+2"})
    assert "WOLFRAM_APP_ID" in out


def test_wolfram_short_renders(monkeypatch):
    monkeypatch.setenv("WOLFRAM_APP_ID", "app")
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, "4", text="4")))
    from maverick.tools.wolfram_tool import wolfram_tool
    out = wolfram_tool().fn({"op": "short", "query": "2+2"})
    assert out == "4"
