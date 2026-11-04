"""Tests for the Sentry tool (maverick.tools.sentry_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Sentry ----------

def test_sentry_requires_op():
    from maverick.tools.sentry_tool import sentry_tool
    assert "op is required" in sentry_tool().fn({})


def test_sentry_missing_token(monkeypatch):
    monkeypatch.delenv("SENTRY_AUTH_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.get = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.sentry_tool import sentry_tool
    out = sentry_tool().fn({"op": "issues"})
    assert "SENTRY_AUTH_TOKEN" in out


def test_sentry_issues_requires_project(monkeypatch):
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "x")
    monkeypatch.delenv("SENTRY_ORG", raising=False)
    monkeypatch.delenv("SENTRY_PROJECT", raising=False)
    fake = types.ModuleType("httpx")
    fake.get = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.sentry_tool import sentry_tool
    out = sentry_tool().fn({"op": "issues"})
    assert "SENTRY_ORG" in out and "SENTRY_PROJECT" in out


def test_sentry_issues_renders(monkeypatch):
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "x")
    monkeypatch.setenv("SENTRY_ORG", "org")
    monkeypatch.setenv("SENTRY_PROJECT", "proj")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=[
        {"shortId": "PROJ-1", "level": "error", "count": 12,
         "userCount": 4, "title": "NullPointer in foo"},
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.sentry_tool import sentry_tool
    out = sentry_tool().fn({"op": "issues"})
    assert "PROJ-1" in out and "NullPointer" in out


def test_sentry_resolve_dry_run(monkeypatch):
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "x")
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.put = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.sentry_tool import sentry_tool
    out = sentry_tool().fn({"op": "resolve", "issue_id": "123"})
    assert "DRY RUN" in out
    fake_httpx.put.assert_not_called()


def test_sentry_resolve_confirmed(monkeypatch):
    monkeypatch.setenv("SENTRY_AUTH_TOKEN", "x")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"status": "resolved"})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.put = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.sentry_tool import sentry_tool
    out = sentry_tool().fn({"op": "resolve", "issue_id": "123", "confirm": True})
    assert "resolved 123" in out
