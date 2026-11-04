"""Tests for the ClickUp tool (maverick.tools.clickup_tool)."""
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


# ---------- ClickUp ----------

def test_clickup_requires_op():
    from maverick.tools.clickup_tool import clickup_tool
    assert "op is required" in clickup_tool().fn({})


def test_clickup_missing_token(monkeypatch):
    monkeypatch.delenv("CLICKUP_API_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.clickup_tool import clickup_tool
    out = clickup_tool().fn({"op": "teams"})
    assert "CLICKUP_API_TOKEN" in out


def test_clickup_teams(monkeypatch):
    monkeypatch.setenv("CLICKUP_API_TOKEN", "tok")
    body = {"teams": [{"id": "1", "name": "Team Alpha"}]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.clickup_tool import clickup_tool
    out = clickup_tool().fn({"op": "teams"})
    assert "Team Alpha" in out


def test_clickup_task_create_dry_run(monkeypatch):
    monkeypatch.setenv("CLICKUP_API_TOKEN", "tok")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.clickup_tool import clickup_tool
    out = clickup_tool().fn({
        "op": "task_create", "list_id": "L1", "name": "Do it",
    })
    assert "DRY RUN" in out


def test_clickup_tasks_follows_pagination(monkeypatch):
    monkeypatch.setenv("CLICKUP_API_TOKEN", "tok")
    page0 = {"tasks": [{"id": "t1", "name": "first"}], "last_page": False}
    page1 = {"tasks": [{"id": "t2", "name": "second"}], "last_page": True}
    get = MagicMock(side_effect=[_resp(200, page0), _resp(200, page1)])
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.clickup_tool import clickup_tool
    out = clickup_tool().fn({"op": "tasks", "list_id": "L1", "limit": 50})
    # Both pages' tasks appear; the loop stopped at last_page.
    assert "first" in out and "second" in out
    assert get.call_count == 2
    assert get.call_args_list[0].kwargs["params"]["page"] == 0
    assert get.call_args_list[1].kwargs["params"]["page"] == 1


def test_clickup_tasks_stops_at_limit(monkeypatch):
    monkeypatch.setenv("CLICKUP_API_TOKEN", "tok")
    # last_page never True, but limit=1 must stop after the first page.
    page = {"tasks": [{"id": "t1", "name": "only"}], "last_page": False}
    get = MagicMock(return_value=_resp(200, page))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.clickup_tool import clickup_tool
    out = clickup_tool().fn({"op": "tasks", "list_id": "L1", "limit": 1})
    assert "only" in out
    assert get.call_count == 1
