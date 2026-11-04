"""Tests for the Gmail tool (maverick.tools.gmail_tool)."""
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


# ---------- Gmail ----------

def test_gmail_requires_op():
    from maverick.tools.gmail_tool import gmail_tool
    assert "op is required" in gmail_tool().fn({})


def test_gmail_missing_token(monkeypatch):
    monkeypatch.delenv("GMAIL_ACCESS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.gmail_tool import gmail_tool
    out = gmail_tool().fn({"op": "labels"})
    assert "GMAIL_ACCESS_TOKEN" in out


def test_gmail_send_dry_run(monkeypatch):
    monkeypatch.setenv("GMAIL_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.gmail_tool import gmail_tool
    out = gmail_tool().fn({
        "op": "send", "to": "a@x", "subject": "hi", "body": "yo",
    })
    assert "DRY RUN" in out


def test_gmail_send_confirmed(monkeypatch):
    monkeypatch.setenv("GMAIL_ACCESS_TOKEN", "tok")
    _fake_httpx(monkeypatch,
                post=MagicMock(return_value=_resp(200, {"id": "m1"})))
    from maverick.tools.gmail_tool import gmail_tool
    out = gmail_tool().fn({
        "op": "send", "to": "a@x", "subject": "hi", "body": "yo",
        "confirm": True,
    })
    assert "sent" in out and "m1" in out


def test_gmail_extract_plain_malformed_base64_never_raises():
    # A sender-controlled text/plain body whose base64url length is 1 (mod 4)
    # must not crash _extract_plain (binascii.Error from the over-padding
    # `+ "==="`). It must reject cleanly (return "") instead.
    import base64

    from maverick.tools.gmail_tool import _decode_b64url, _extract_plain

    bad = {"mimeType": "text/plain", "body": {"data": "AAAAA"}}  # len%4 == 1
    assert _extract_plain(bad) == ""
    assert _decode_b64url("AAAAA") == ""
    # Padding-stripped valid bodies (Gmail strips '=') still round-trip.
    raw = b"hello plain body"
    stripped = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    ok = {"mimeType": "text/plain", "body": {"data": stripped}}
    assert _extract_plain(ok) == raw.decode()
