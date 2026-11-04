"""Tests for the Asana tool (maverick.tools.asana_tool)."""
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


# ---------- Asana ----------

def test_asana_requires_op():
    from maverick.tools.asana_tool import asana_tool
    assert "op is required" in asana_tool().fn({})


def test_asana_missing_token(monkeypatch):
    monkeypatch.delenv("ASANA_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.asana_tool import asana_tool
    out = asana_tool().fn({"op": "workspaces"})
    assert "ASANA_TOKEN" in out


def test_asana_workspaces(monkeypatch):
    monkeypatch.setenv("ASANA_TOKEN", "tok")
    body = {"data": [{"gid": "1", "name": "Acme"}]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.asana_tool import asana_tool
    out = asana_tool().fn({"op": "workspaces"})
    assert "Acme" in out


def test_asana_task_complete_dry_run(monkeypatch):
    monkeypatch.setenv("ASANA_TOKEN", "tok")
    _fake_httpx(monkeypatch, put=MagicMock())
    from maverick.tools.asana_tool import asana_tool
    out = asana_tool().fn({"op": "task_complete", "task_gid": "1"})
    assert "DRY RUN" in out


def test_asana_tasks_follows_offset(monkeypatch):
    monkeypatch.setenv("ASANA_TOKEN", "tok")
    page1 = {"data": [{"gid": "t1", "name": "one", "completed": False}],
             "next_page": {"offset": "off-2"}}
    page2 = {"data": [{"gid": "t2", "name": "two", "completed": False}],
             "next_page": None}
    get = MagicMock(side_effect=[_resp(200, page1), _resp(200, page2)])
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.asana_tool import asana_tool
    out = asana_tool().fn({"op": "tasks", "project_gid": "P1", "limit": 50})
    assert "t1" in out and "t2" in out
    assert get.call_count == 2
    assert get.call_args_list[1].kwargs["params"]["offset"] == "off-2"
