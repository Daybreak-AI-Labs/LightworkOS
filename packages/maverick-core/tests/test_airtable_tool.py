"""Tests for the Airtable tool (maverick.tools.airtable_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock


def _fake_httpx(monkeypatch, **methods):
    mod = types.ModuleType("httpx")
    for name, value in methods.items():
        setattr(mod, name, value)
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return mod


def _resp(status, body):
    r = MagicMock()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    elif isinstance(body, str):
        r.json = MagicMock(side_effect=ValueError("not json"))
        r.text = body
    else:
        r.json = MagicMock(return_value=body)
        r.text = str(body)
    r.content = (body if isinstance(body, bytes) else str(body).encode("utf-8"))
    return r


# ---------- Airtable ----------

def test_airtable_requires_op():
    from maverick.tools.airtable_tool import airtable_tool
    assert "op is required" in airtable_tool().fn({})


def test_airtable_missing_key(monkeypatch):
    monkeypatch.delenv("AIRTABLE_API_KEY", raising=False)
    monkeypatch.delenv("AIRTABLE_BASE_ID", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.airtable_tool import airtable_tool
    out = airtable_tool().fn({"op": "list", "table": "Tasks"})
    assert "AIRTABLE_API_KEY" in out


def test_airtable_list_renders(monkeypatch):
    monkeypatch.setenv("AIRTABLE_API_KEY", "key")
    monkeypatch.setenv("AIRTABLE_BASE_ID", "appB")
    body = {"records": [
        {"id": "rec1", "fields": {"Name": "Alice", "Score": 99}},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.airtable_tool import airtable_tool
    out = airtable_tool().fn({"op": "list", "table": "People"})
    assert "rec1" in out and "Alice" in out


def test_airtable_create_dry_run(monkeypatch):
    monkeypatch.setenv("AIRTABLE_API_KEY", "key")
    monkeypatch.setenv("AIRTABLE_BASE_ID", "appB")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.airtable_tool import airtable_tool
    out = airtable_tool().fn({
        "op": "create", "table": "T", "fields": {"Name": "X"},
    })
    assert "DRY RUN" in out


def test_airtable_base_id_cannot_retarget_the_api_path(monkeypatch):
    monkeypatch.setenv("AIRTABLE_API_KEY", "key")
    get = MagicMock(return_value=_resp(200, {"records": []}))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.airtable_tool import airtable_tool
    airtable_tool().fn({"op": "list", "table": "People", "base_id": "meta/whoami?x="})
    assert get.call_args.args[0] == "https://api.airtable.com/v0/meta%2Fwhoami%3Fx%3D/People"
    out = airtable_tool().fn({"op": "list", "table": "People", "base_id": ".."})
    assert out.startswith("ERROR") and get.call_count == 1
