"""Tests for the PagerDuty tool (maverick.tools.pagerduty_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    """Install a dummy httpx module with the given methods (get/post/...) ."""
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status: int, body: object):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    else:
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = str(body)
    return r


# ---------- PagerDuty ----------

def test_pagerduty_requires_op():
    from maverick.tools.pagerduty_tool import pagerduty_tool
    assert "op is required" in pagerduty_tool().fn({})


def test_pagerduty_missing_token(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_API_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.pagerduty_tool import pagerduty_tool
    out = pagerduty_tool().fn({"op": "incidents"})
    assert "PAGERDUTY_API_TOKEN" in out


def test_pagerduty_incidents_renders(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "tok")
    body = {"incidents": [
        {"id": "PQ1", "status": "triggered", "urgency": "high",
         "title": "DB down"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.pagerduty_tool import pagerduty_tool
    out = pagerduty_tool().fn({"op": "incidents"})
    assert "PQ1" in out and "DB down" in out


def test_pagerduty_acknowledge_dry_run(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "tok")
    _fake_httpx(monkeypatch, get=MagicMock(), put=MagicMock())
    from maverick.tools.pagerduty_tool import pagerduty_tool
    out = pagerduty_tool().fn({"op": "acknowledge", "id": "PQ1"})
    assert "DRY RUN" in out


def test_pagerduty_trigger_dry_run(monkeypatch):
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "tok")
    monkeypatch.setenv("PAGERDUTY_EVENTS_KEY", "rk")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.pagerduty_tool import pagerduty_tool
    out = pagerduty_tool().fn({"op": "trigger", "summary": "db down"})
    assert "DRY RUN" in out


def test_pagerduty_acknowledge_sends_from_header(monkeypatch):
    # The status PUT needs a `From` header (requester email) or the
    # REST API 400s 'Requester User Not Found' with an account-level token.
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "tok")
    monkeypatch.setenv("PAGERDUTY_FROM", "oncall@example.com")
    put = MagicMock(return_value=_resp(200, {"incident": {"status": "acknowledged"}}))
    _fake_httpx(monkeypatch, put=put)
    from maverick.tools.pagerduty_tool import pagerduty_tool
    out = pagerduty_tool().fn({"op": "acknowledge", "id": "PQ1", "confirm": True})
    assert "acknowledged" in out
    # The From header was sent on the PUT.
    headers = put.call_args.kwargs["headers"]
    assert headers.get("From") == "oncall@example.com"


def test_pagerduty_acknowledge_errors_without_from(monkeypatch):
    monkeypatch.delenv("PAGERDUTY_FROM", raising=False)
    monkeypatch.delenv("PAGERDUTY_USER_EMAIL", raising=False)
    monkeypatch.setenv("PAGERDUTY_API_TOKEN", "tok")
    put = MagicMock()
    _fake_httpx(monkeypatch, put=put)
    from maverick.tools.pagerduty_tool import pagerduty_tool
    out = pagerduty_tool().fn({"op": "acknowledge", "id": "PQ1", "confirm": True})
    assert "requester email" in out.lower()
    put.assert_not_called()  # no doomed request fired
