"""Tests for the Google Analytics 4 tool (maverick.tools.ga4_tool)."""
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


def test_ga4_guards_non_json(monkeypatch):
    monkeypatch.setenv("GA4_ACCESS_TOKEN", "t")
    monkeypatch.setenv("GA4_PROPERTY_ID", "123")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(side_effect=ValueError("not json"))
    resp.text = "<html>proxy error</html>"
    _fake_httpx(monkeypatch, post=MagicMock(return_value=resp))
    from maverick.tools.ga4_tool import ga4_tool
    out = ga4_tool().fn({"op": "run_report"})
    assert "non-JSON" in out  # graceful, not a raw TypeError/ValueError


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


# ---------- GA4 ----------

def test_ga4_requires_op():
    from maverick.tools.ga4_tool import ga4_tool
    assert "op is required" in ga4_tool().fn({})


def test_ga4_send_event_requires_keys(monkeypatch):
    monkeypatch.delenv("GA4_MEASUREMENT_ID", raising=False)
    monkeypatch.delenv("GA4_API_SECRET", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.ga4_tool import ga4_tool
    out = ga4_tool().fn({"op": "send_event",
                          "client_id": "u", "name": "signup"})
    assert "GA4_MEASUREMENT_ID" in out


def test_ga4_send_event_posts(monkeypatch):
    monkeypatch.setenv("GA4_MEASUREMENT_ID", "G-XX")
    monkeypatch.setenv("GA4_API_SECRET", "sec")
    _fake_httpx(monkeypatch,
                post=MagicMock(return_value=_resp(204, "")))
    from maverick.tools.ga4_tool import ga4_tool
    out = ga4_tool().fn({
        "op": "send_event", "client_id": "u", "name": "signup",
        "params": {"value": 1},
    })
    assert "accepted" in out


def test_ga4_run_report_requires_keys(monkeypatch):
    monkeypatch.delenv("GA4_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("GA4_PROPERTY_ID", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.ga4_tool import ga4_tool
    out = ga4_tool().fn({"op": "run_report"})
    assert "GA4_ACCESS_TOKEN" in out
