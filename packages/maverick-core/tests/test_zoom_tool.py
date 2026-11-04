"""Tests for the Zoom tool (maverick.tools.zoom_tool)."""
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


# ---------- Zoom ----------

def test_zoom_requires_op():
    from maverick.tools.zoom_tool import zoom_tool
    assert "op is required" in zoom_tool().fn({})


def test_zoom_missing_token(monkeypatch):
    monkeypatch.delenv("ZOOM_OAUTH_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.zoom_tool import zoom_tool
    out = zoom_tool().fn({"op": "meetings"})
    assert "ZOOM_OAUTH_TOKEN" in out


def test_zoom_meeting_create_dry_run(monkeypatch):
    monkeypatch.setenv("ZOOM_OAUTH_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.zoom_tool import zoom_tool
    out = zoom_tool().fn({
        "op": "meeting_create", "topic": "demo",
        "start_time": "2026-06-01T10:00:00Z",
    })
    assert "DRY RUN" in out


def test_zoom_meetings_renders(monkeypatch):
    monkeypatch.setenv("ZOOM_OAUTH_TOKEN", "tok")
    body = {"meetings": [{
        "id": "123", "start_time": "2026-06-01T10:00:00Z",
        "topic": "Standup",
    }]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.zoom_tool import zoom_tool
    out = zoom_tool().fn({"op": "meetings"})
    assert "Standup" in out
