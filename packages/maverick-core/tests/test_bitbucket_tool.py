"""Tests for the Bitbucket tool (maverick.tools.bitbucket_tool)."""
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


# ---------- Bitbucket ----------

def test_bitbucket_requires_op():
    from maverick.tools.bitbucket_tool import bitbucket_tool
    assert "op is required" in bitbucket_tool().fn({})


def test_bitbucket_missing_credentials(monkeypatch):
    monkeypatch.delenv("BITBUCKET_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("BITBUCKET_USERNAME", raising=False)
    monkeypatch.delenv("BITBUCKET_APP_PASSWORD", raising=False)
    _fake_httpx(monkeypatch, get=MagicMock())
    from maverick.tools.bitbucket_tool import bitbucket_tool
    out = bitbucket_tool().fn({"op": "issues", "workspace": "ws", "repo_slug": "r"})
    assert "BITBUCKET" in out


def test_bitbucket_issues_renders(monkeypatch):
    monkeypatch.setenv("BITBUCKET_ACCESS_TOKEN", "tok")
    body = {"values": [
        {"id": 1, "state": "new", "title": "Fix bug"},
    ]}
    _fake_httpx(monkeypatch, get=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.bitbucket_tool import bitbucket_tool
    out = bitbucket_tool().fn({"op": "issues", "workspace": "ws", "repo_slug": "r"})
    assert "Fix bug" in out
