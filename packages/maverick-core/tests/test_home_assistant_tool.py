"""Tests for the Home Assistant tool (maverick.tools.home_assistant_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def test_home_assistant_safe_seg():
    from maverick.tools.home_assistant_tool import _safe_seg
    assert _safe_seg("light.living_room")
    assert not _safe_seg("../config")
    assert not _safe_seg("a/b")
    assert not _safe_seg("")


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


# ---------- Home Assistant ----------

def test_hass_requires_op():
    from maverick.tools.home_assistant_tool import home_assistant_tool
    assert "op is required" in home_assistant_tool().fn({})


def test_hass_missing_config(monkeypatch):
    monkeypatch.delenv("HASS_URL", raising=False)
    monkeypatch.delenv("HASS_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.home_assistant_tool import home_assistant_tool
    out = home_assistant_tool().fn({"op": "states"})
    assert "HASS_URL" in out


def test_hass_call_service_dry_run(monkeypatch):
    monkeypatch.setenv("HASS_URL", "http://hass.local:8123")
    monkeypatch.setenv("HASS_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.home_assistant_tool import home_assistant_tool
    out = home_assistant_tool().fn({
        "op": "call_service", "domain": "light", "service": "turn_on",
        "data": {"entity_id": "light.living"},
    })
    assert "DRY RUN" in out


def test_hass_states_filters_by_domain(monkeypatch):
    monkeypatch.setenv("HASS_URL", "http://hass.local:8123")
    monkeypatch.setenv("HASS_TOKEN", "tok")
    body = [
        {"entity_id": "light.living", "state": "on",
         "attributes": {"friendly_name": "Living Room"}},
        {"entity_id": "switch.fan", "state": "off",
         "attributes": {"friendly_name": "Fan"}},
    ]
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.home_assistant_tool import home_assistant_tool
    out = home_assistant_tool().fn({"op": "states", "domain": "light"})
    assert "light.living" in out and "switch.fan" not in out
