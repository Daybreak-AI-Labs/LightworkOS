"""Tests for the Wolfram Alpha tool (maverick.tools.wolfram_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

from maverick.budget import Budget


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
    out = wolfram_tool(budget=Budget()).fn({"op": "short"})
    assert "query is required" in out


def test_wolfram_missing_appid(monkeypatch):
    monkeypatch.delenv("WOLFRAM_APP_ID", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.wolfram_tool import wolfram_tool
    out = wolfram_tool(budget=Budget()).fn({"op": "short", "query": "2+2"})
    assert "WOLFRAM_APP_ID" in out


def test_wolfram_short_renders(monkeypatch):
    monkeypatch.setenv("WOLFRAM_APP_ID", "app")
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, "4", text="4")))
    from maverick.tools.wolfram_tool import wolfram_tool
    out = wolfram_tool(budget=Budget()).fn({"op": "short", "query": "2+2"})
    assert out == "4"


def test_wolfram_query_is_charged_to_the_run_and_needs_a_budget(monkeypatch):
    # Each Wolfram|Alpha query is a paid lookup: charged to the run budget
    # (the per-call safety ceiling with no price set), refused without one.
    import pytest
    from maverick.budget import DEFAULT_UNPRICED_TOOL_CALL_DOLLARS, Budget
    from maverick.tools.wolfram_tool import wolfram_tool

    monkeypatch.setenv("WOLFRAM_APP_ID", "app")
    get = MagicMock(return_value=_resp(200, "42", text="42"))
    _fake_httpx(monkeypatch, get=get)
    monkeypatch.setattr("maverick.tools.wolfram_tool.guarded_redirect_get", lambda send: send)
    budget = Budget()
    assert wolfram_tool(budget=budget).fn({"op": "short", "query": "6*7"}) == "42"
    assert budget.dollars == pytest.approx(DEFAULT_UNPRICED_TOOL_CALL_DOLLARS)
    out = wolfram_tool().fn({"op": "short", "query": "6*7"})
    assert out.startswith("ERROR") and "nothing was sent" in out and get.call_count == 1


def test_wolfram_redirect_blocked_after_the_first_request_is_charged(monkeypatch):
    # Wolfram answered, then its redirect to a private address was refused.
    # A request left, so the call is charged whatever error the hop raised.
    import httpx
    import pytest

    monkeypatch.setenv("WOLFRAM_APP_ID", "app")
    sent = []

    def get(url, **_kw):
        sent.append(url)
        response = httpx.Response(302, headers={"location": "http://169.254.169.254/latest"},
                                  request=httpx.Request("GET", url))
        response.next_request = httpx.Request("GET", "http://169.254.169.254/latest")
        return response

    monkeypatch.setattr(httpx, "get", get)
    from maverick.tools.wolfram_tool import wolfram_tool
    budget = Budget(max_dollars=1.0)
    out = wolfram_tool(budget=budget).fn({"op": "short", "query": "2+2"})
    assert out.startswith("ERROR") and len(sent) == 1
    assert budget.dollars == pytest.approx(0.10) and budget._reserved == 0
