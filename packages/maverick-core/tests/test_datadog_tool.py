"""Tests for the Datadog tool (maverick.tools.datadog_tool)."""
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


# ---------- Datadog ----------

def test_datadog_requires_op():
    from maverick.tools.datadog_tool import datadog_tool
    assert "op is required" in datadog_tool().fn({})


def test_datadog_submit_event_validation(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.datadog_tool import datadog_tool
    out = datadog_tool().fn({"op": "submit_event"})
    assert "requires title" in out


def test_datadog_submit_event_dry_run(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    _fake_httpx(
        monkeypatch,
        post=MagicMock(return_value=_resp(200, {"event": {"id": 99}})),
    )
    from maverick.tools.datadog_tool import datadog_tool
    out = datadog_tool().fn({
        "op": "submit_event", "title": "deploy", "text": "v1.2 shipped",
    })
    assert "DRY RUN" in out


def test_datadog_submit_event_posts_with_confirm(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    _fake_httpx(
        monkeypatch,
        post=MagicMock(return_value=_resp(200, {"event": {"id": 99}})),
    )
    from maverick.tools.datadog_tool import datadog_tool
    out = datadog_tool().fn({
        "op": "submit_event", "title": "deploy", "text": "v1.2 shipped", "confirm": True,
    })
    assert "event id=99" in out


def test_datadog_monitors_requires_app_key(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    monkeypatch.delenv("DATADOG_APP_KEY", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.datadog_tool import datadog_tool
    out = datadog_tool().fn({"op": "monitors"})
    assert "DATADOG_APP_KEY" in out


def test_datadog_handles_null_monitor_id(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    monkeypatch.setenv("DATADOG_APP_KEY", "a")
    body = [{"id": None, "overall_state": "OK", "name": "cpu"}]
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.datadog_tool import datadog_tool
    out = datadog_tool().fn({"op": "monitors"})
    assert "ERROR" not in out and "cpu" in out


def test_datadog_monitors_name_filter_uses_search_endpoint(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    monkeypatch.setenv("DATADOG_APP_KEY", "a")
    body = {"monitors": [{"id": 7, "overall_state": "OK", "name": "cpu high"}]}
    get = MagicMock(return_value=_resp(200, body))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.datadog_tool import datadog_tool

    out = datadog_tool().fn({"op": "monitors", "name": "cpu", "limit": 10})
    assert "cpu high" in out
    url = get.call_args.args[0]
    params = get.call_args.kwargs["params"]
    assert url.endswith("/api/v1/monitor/search")
    assert params["query"] == "name:cpu"


def test_datadog_monitors_no_name_uses_list_endpoint(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    monkeypatch.setenv("DATADOG_APP_KEY", "a")
    body = [{"id": 1, "overall_state": "Alert", "name": "disk full"}]
    get = MagicMock(return_value=_resp(200, body))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.datadog_tool import datadog_tool

    out = datadog_tool().fn({"op": "monitors"})
    assert "disk full" in out
    assert get.call_args.args[0].endswith("/api/v1/monitor")


def test_datadog_monitors_search_no_matches(monkeypatch):
    monkeypatch.setenv("DATADOG_API_KEY", "k")
    monkeypatch.setenv("DATADOG_APP_KEY", "a")
    get = MagicMock(return_value=_resp(200, {"monitors": []}))
    _fake_httpx(monkeypatch, get=get)
    from maverick.tools.datadog_tool import datadog_tool

    out = datadog_tool().fn({"op": "monitors", "name": "nope"})
    assert out == "no monitors"
