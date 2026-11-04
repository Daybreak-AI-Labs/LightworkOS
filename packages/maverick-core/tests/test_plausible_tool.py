"""Tests for the Plausible tool (maverick.tools.plausible_tool)."""
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


def _resp(status, body):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = str(body)
    return r


# ---------- Plausible ----------

def test_plausible_requires_op():
    from maverick.tools.plausible_tool import plausible_tool
    assert "op is required" in plausible_tool().fn({})


def test_plausible_event_no_key(monkeypatch):
    monkeypatch.delenv("PLAUSIBLE_API_KEY", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(202, "")))
    from maverick.tools.plausible_tool import plausible_tool
    out = plausible_tool().fn({
        "op": "event", "site_id": "example.com", "name": "signup",
    })
    assert "accepted" in out


def test_plausible_aggregate_requires_key(monkeypatch):
    monkeypatch.delenv("PLAUSIBLE_API_KEY", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.plausible_tool import plausible_tool
    out = plausible_tool().fn({"op": "aggregate", "site_id": "x.com"})
    assert "PLAUSIBLE_API_KEY" in out


def test_plausible_aggregate_renders(monkeypatch):
    monkeypatch.setenv("PLAUSIBLE_API_KEY", "tok")
    body = {"results": {"visitors": {"value": 42},
                         "pageviews": {"value": 100}}}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.plausible_tool import plausible_tool
    out = plausible_tool().fn({"op": "aggregate", "site_id": "x.com"})
    assert "visitors: 42" in out and "pageviews: 100" in out
