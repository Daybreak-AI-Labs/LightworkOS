"""Tests for the TrueLayer open-banking tool (read-only).

Offline: httpx is faked via sys.modules and the recording get() captures the
URL / Bearer header / query params, so no real TrueLayer call is made.
"""
from __future__ import annotations

import sys
import types

from maverick.tools.truelayer_tool import truelayer_tool


def _resp(status, body):
    r = types.SimpleNamespace()
    r.status_code = status
    if isinstance(body, (dict, list)):
        r.json = lambda: body
        r.text = str(body)
    else:
        def _raise():
            raise ValueError("not json")
        r.json = _raise
        r.text = str(body)
    return r


def _fake_httpx(monkeypatch, status=200, body=None, sink=None):
    sink = sink if sink is not None else []

    def _get(url, headers=None, params=None, timeout=None):
        sink.append({"url": url, "headers": headers or {}, "params": params or {}})
        return _resp(status, body if body is not None else {})

    mod = types.ModuleType("httpx")
    mod.get = _get
    monkeypatch.setitem(sys.modules, "httpx", mod)
    return sink


def test_requires_op():
    assert truelayer_tool().fn({}).startswith("ERROR: op is required")


def test_requires_access_token(monkeypatch):
    out = truelayer_tool().fn({"op": "accounts"})
    assert out.startswith("ERROR") and "access_token is required" in out


def test_accounts_renders_and_sends_bearer(monkeypatch):
    body = {"results": [
        {"account_id": "acc-123456789", "display_name": "Current",
         "account_type": "TRANSACTION", "currency": "GBP"},
    ]}
    sink = _fake_httpx(monkeypatch, 200, body)
    out = truelayer_tool().fn({"op": "accounts", "access_token": "tok-xyz"})
    assert "Current" in out and "GBP" in out
    req = sink[0]
    assert req["url"].endswith("/data/v1/accounts")
    assert req["headers"].get("Authorization") == "Bearer tok-xyz"


def test_balance_requires_account_id(monkeypatch):
    _fake_httpx(monkeypatch)
    out = truelayer_tool().fn({"op": "balance", "access_token": "t"})
    assert out.startswith("ERROR") and "account_id" in out


def test_balance_renders(monkeypatch):
    body = {"results": [{"currency": "GBP", "current": 1200.5,
                         "available": 1150.0, "overdraft": 0}]}
    sink = _fake_httpx(monkeypatch, 200, body)
    out = truelayer_tool().fn({"op": "balance", "access_token": "t",
                               "account_id": "acc1"})
    assert "1,200.50 GBP" in out and "available=1,150.00 GBP" in out
    assert sink[0]["url"].endswith("/data/v1/accounts/acc1/balance")


def test_transactions_requires_account_id(monkeypatch):
    _fake_httpx(monkeypatch)
    out = truelayer_tool().fn({"op": "transactions", "access_token": "t"})
    assert out.startswith("ERROR") and "account_id" in out


def test_transactions_passes_date_params(monkeypatch):
    body = {"results": [{"timestamp": "2026-01-02T10:00:00Z", "amount": -9.99,
                         "currency": "GBP", "description": "Coffee Shop"}]}
    sink = _fake_httpx(monkeypatch, 200, body)
    out = truelayer_tool().fn({
        "op": "transactions", "access_token": "t", "account_id": "acc1",
        "from_date": "2026-01-01", "to_date": "2026-01-31",
    })
    assert "Coffee Shop" in out and "-9.99 GBP" in out
    assert sink[0]["params"] == {"from": "2026-01-01", "to": "2026-01-31"}
    assert sink[0]["url"].endswith("/data/v1/accounts/acc1/transactions")


def test_info_renders(monkeypatch):
    body = {"results": [{"full_name": "Ada Lovelace",
                         "emails": ["ada@example.com"], "phones": ["+44 7700 900000"]}]}
    _fake_httpx(monkeypatch, 200, body)
    out = truelayer_tool().fn({"op": "info", "access_token": "t"})
    assert "Ada Lovelace" in out and "ada@example.com" in out


def test_http_error_surfaces(monkeypatch):
    _fake_httpx(monkeypatch, 401, {"error": "invalid_token"})
    out = truelayer_tool().fn({"op": "accounts", "access_token": "bad"})
    assert out.startswith("ERROR: accounts (401)")


def test_env_selects_base_url(monkeypatch):
    monkeypatch.setenv("TRUELAYER_ENV", "production")
    sink = _fake_httpx(monkeypatch, 200, {"results": []})
    truelayer_tool().fn({"op": "accounts", "access_token": "t"})
    assert sink[0]["url"].startswith("https://api.truelayer.com")

    monkeypatch.setenv("TRUELAYER_ENV", "sandbox")
    sink2 = _fake_httpx(monkeypatch, 200, {"results": []})
    truelayer_tool().fn({"op": "accounts", "access_token": "t"})
    assert sink2[0]["url"].startswith("https://api.truelayer-sandbox.com")


def test_unknown_op(monkeypatch):
    _fake_httpx(monkeypatch)
    assert truelayer_tool().fn({"op": "nope", "access_token": "t"}).startswith(
        "ERROR: unknown op")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "truelayer" in names
