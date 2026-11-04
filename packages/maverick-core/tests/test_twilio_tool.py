"""Tests for the Twilio tool (maverick.tools.twilio_tool)."""
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


# ---------- Twilio ----------

def test_twilio_requires_op():
    from maverick.tools.twilio_tool import twilio_tool
    assert "op is required" in twilio_tool().fn({})


def test_twilio_missing_credentials(monkeypatch):
    monkeypatch.delenv("TWILIO_ACCOUNT_SID", raising=False)
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)
    # Provide from_ explicitly so the auth check (not the from-required
    # check) fires when sending the request.
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.twilio_tool import twilio_tool
    out = twilio_tool().fn({
        "op": "sms_send", "to": "+1", "body": "x", "from_": "+15550000", "confirm": True,
    })
    assert "TWILIO_ACCOUNT_SID" in out


def test_twilio_sms_send_dry_run(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC123")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    monkeypatch.setenv("TWILIO_FROM_NUMBER", "+15551234567")
    body = {"sid": "SM999", "status": "queued"}
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.twilio_tool import twilio_tool
    out = twilio_tool().fn({
        "op": "sms_send", "to": "+15555550000", "body": "hello",
    })
    assert "DRY RUN" in out


def test_twilio_sms_send_posts_with_confirm(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC123")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    monkeypatch.setenv("TWILIO_FROM_NUMBER", "+15551234567")
    body = {"sid": "SM999", "status": "queued"}
    _fake_httpx(monkeypatch, post=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.twilio_tool import twilio_tool
    out = twilio_tool().fn({
        "op": "sms_send", "to": "+15555550000", "body": "hello", "confirm": True,
    })
    assert "SM999" in out and "queued" in out


def test_twilio_sms_send_requires_from(monkeypatch):
    monkeypatch.setenv("TWILIO_ACCOUNT_SID", "AC123")
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "tok")
    monkeypatch.delenv("TWILIO_FROM_NUMBER", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.twilio_tool import twilio_tool
    out = twilio_tool().fn({"op": "sms_send", "to": "+1", "body": "x"})
    assert "from_" in out
