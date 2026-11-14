"""Tests for the Mixpanel tool (maverick.tools.mixpanel_tool)."""
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


# ---------- Mixpanel ----------

def test_mixpanel_requires_op():
    from maverick.tools.mixpanel_tool import mixpanel_tool
    assert "op is required" in mixpanel_tool().fn({})


def test_mixpanel_track_missing_token(monkeypatch):
    monkeypatch.delenv("MIXPANEL_PROJECT_TOKEN", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.mixpanel_tool import mixpanel_tool
    out = mixpanel_tool().fn({"op": "track", "event": "x", "distinct_id": "u"})
    assert "MIXPANEL_PROJECT_TOKEN" in out


def test_mixpanel_track_posts(monkeypatch):
    monkeypatch.setenv("MIXPANEL_PROJECT_TOKEN", "tok")
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "1"
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.mixpanel_tool import mixpanel_tool
    out = mixpanel_tool().fn({
        "op": "track", "event": "signup", "distinct_id": "user-1",
        "properties": {"plan": "pro"},
    })
    assert "tracked 'signup'" in out


def test_mixpanel_track_properties_cannot_override_token_or_distinct_id(monkeypatch):
    import base64
    import json

    monkeypatch.setenv("MIXPANEL_PROJECT_TOKEN", "tok")
    resp = MagicMock(status_code=200, text="1")
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.mixpanel_tool import mixpanel_tool
    mixpanel_tool().fn({
        "op": "track", "event": "signup", "distinct_id": "user-1",
        "properties": {"token": "other-project", "distinct_id": "someone-else", "plan": "pro"},
    })
    sent = json.loads(base64.b64decode(fake_httpx.post.call_args.kwargs["data"]["data"]))
    assert sent["properties"] == {"plan": "pro", "token": "tok", "distinct_id": "user-1"}
