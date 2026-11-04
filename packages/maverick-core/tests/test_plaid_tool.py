"""Tests for the Plaid tool (maverick.tools.plaid_tool)."""
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


# ---------- Plaid ----------

def test_plaid_requires_op():
    from maverick.tools.plaid_tool import plaid_tool
    assert "op is required" in plaid_tool().fn({})


def test_plaid_requires_access_token():
    from maverick.tools.plaid_tool import plaid_tool
    out = plaid_tool().fn({"op": "accounts"})
    assert "access_token" in out


def test_plaid_missing_secrets(monkeypatch):
    monkeypatch.delenv("PLAID_CLIENT_ID", raising=False)
    monkeypatch.delenv("PLAID_SECRET", raising=False)
    _fake_httpx(monkeypatch, post=MagicMock())
    from maverick.tools.plaid_tool import plaid_tool
    out = plaid_tool().fn({"op": "accounts", "access_token": "tok"})
    assert "PLAID_CLIENT_ID" in out


def test_plaid_accounts_renders(monkeypatch):
    monkeypatch.setenv("PLAID_CLIENT_ID", "id")
    monkeypatch.setenv("PLAID_SECRET", "sec")
    body = {"accounts": [{
        "account_id": "acc123abc", "name": "Checking",
        "type": "depository", "subtype": "checking",
        "balances": {"current": 1234.56, "iso_currency_code": "USD"},
    }]}
    _fake_httpx(monkeypatch,
                post=MagicMock(return_value=_resp(200, body)))
    from maverick.tools.plaid_tool import plaid_tool
    out = plaid_tool().fn({"op": "accounts", "access_token": "tok"})
    assert "Checking" in out and "1,234.56" in out
