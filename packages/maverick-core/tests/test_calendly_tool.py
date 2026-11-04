"""Tests for the Calendly tool (maverick.tools.calendly_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def test_calendly_uuid_rejects_path_traversal():
    from maverick.tools.calendly_tool import _safe_uuid
    assert _safe_uuid("AAAA-BBBB-1234")
    assert _safe_uuid("abc_def")
    assert not _safe_uuid("me/../users")
    assert not _safe_uuid("a/b")
    assert not _safe_uuid("../x")
    assert not _safe_uuid("")


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


# ---------- Calendly ----------

def test_calendly_requires_op():
    from maverick.tools.calendly_tool import calendly_tool
    assert "op is required" in calendly_tool().fn({})


def test_calendly_me_missing_token(monkeypatch):
    monkeypatch.delenv("CALENDLY_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.calendly_tool import calendly_tool
    out = calendly_tool().fn({"op": "me"})
    assert "CALENDLY_TOKEN" in out


def test_calendly_cancel_dry_run(monkeypatch):
    monkeypatch.setenv("CALENDLY_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.calendly_tool import calendly_tool
    out = calendly_tool().fn({"op": "cancel", "event_uuid": "abc"})
    assert "DRY RUN" in out


def test_calendly_events_renders(monkeypatch):
    monkeypatch.setenv("CALENDLY_TOKEN", "tok")
    monkeypatch.setenv("CALENDLY_USER_URI", "https://api.calendly.com/users/U")
    body = {"collection": [
        {"uri": "https://api.calendly.com/scheduled_events/E1",
         "status": "active", "start_time": "2026-06-01T10:00:00Z",
         "name": "Intro chat"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.calendly_tool import calendly_tool
    out = calendly_tool().fn({"op": "events"})
    assert "Intro chat" in out and "active" in out
