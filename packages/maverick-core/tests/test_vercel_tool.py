"""Tests for the Vercel tool (maverick.tools.vercel_tool)."""
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


# ---------- Vercel ----------

def test_vercel_requires_op():
    from maverick.tools.vercel_tool import vercel_tool
    assert "op is required" in vercel_tool().fn({})


def test_vercel_missing_token(monkeypatch):
    monkeypatch.delenv("VERCEL_TOKEN", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.vercel_tool import vercel_tool
    out = vercel_tool().fn({"op": "projects"})
    assert "VERCEL_TOKEN" in out


def test_vercel_projects(monkeypatch):
    monkeypatch.setenv("VERCEL_TOKEN", "tok")
    body = {"projects": [
        {"id": "p1", "name": "my-app", "framework": "nextjs",
         "latestDeployments": [{"readyState": "READY"}]},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.vercel_tool import vercel_tool
    out = vercel_tool().fn({"op": "projects"})
    assert "my-app" in out and "READY" in out


def test_vercel_cancel_dry_run(monkeypatch):
    monkeypatch.setenv("VERCEL_TOKEN", "tok")
    _fake_httpx(monkeypatch, patch=MagicMock())
    from maverick.tools.vercel_tool import vercel_tool
    out = vercel_tool().fn({"op": "cancel", "deployment_id": "d1"})
    assert "DRY RUN" in out


def test_vercel_handles_null_project_name(monkeypatch):
    monkeypatch.setenv("VERCEL_TOKEN", "tok")
    body = {"projects": [
        {"id": "p1", "name": None, "framework": "nextjs",
         "latestDeployments": [{"readyState": "READY"}]},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.vercel_tool import vercel_tool
    out = vercel_tool().fn({"op": "projects"})
    assert "ERROR" not in out and "p1" in out
