"""Tests for the Shopify tool (maverick.tools.shopify_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest


def test_shopify_store_rejects_ssrf_chars(monkeypatch):
    from maverick.tools import shopify_tool
    monkeypatch.setenv("SHOPIFY_ACCESS_TOKEN", "tok")
    for bad in ("evil.com#", "evil.com/", "user@evil.com", "evil.com:8080"):
        monkeypatch.setenv("SHOPIFY_STORE", bad)
        with pytest.raises(RuntimeError, match="invalid SHOPIFY_STORE"):
            shopify_tool._config()


def test_shopify_store_clean_subdomain_expands(monkeypatch):
    from maverick.tools import shopify_tool
    monkeypatch.setenv("SHOPIFY_ACCESS_TOKEN", "tok")
    monkeypatch.setenv("SHOPIFY_STORE", "my-store")
    store, tok = shopify_tool._config()
    assert store == "my-store.myshopify.com"
    assert tok == "tok"


# ---------- Shopify tool ----------

def test_shopify_requires_op():
    from maverick.tools.shopify_tool import shopify_tool
    assert "op is required" in shopify_tool().fn({})


def test_shopify_missing_config(monkeypatch):
    monkeypatch.delenv("SHOPIFY_STORE", raising=False)
    monkeypatch.delenv("SHOPIFY_ACCESS_TOKEN", raising=False)
    fake = types.ModuleType("httpx")
    fake.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.shopify_tool import shopify_tool
    out = shopify_tool().fn({"op": "orders"})
    assert "SHOPIFY_STORE" in out and "SHOPIFY_ACCESS_TOKEN" in out


def test_shopify_orders_renders(monkeypatch):
    monkeypatch.setenv("SHOPIFY_STORE", "my-shop")
    monkeypatch.setenv("SHOPIFY_ACCESS_TOKEN", "shpat_xx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"orders": [
        {"name": "#1001", "financial_status": "paid",
         "total_price": "49.99", "currency": "USD",
         "customer": {"email": "alice@x"}},
    ]})

    client = MagicMock()
    client.get = MagicMock(return_value=resp)
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.shopify_tool import shopify_tool
    out = shopify_tool().fn({"op": "orders"})
    assert "#1001" in out and "49.99 USD" in out
    assert "alice@x" in out


def test_shopify_orders_follows_link_header(monkeypatch):
    monkeypatch.setenv("SHOPIFY_STORE", "my-shop")
    monkeypatch.setenv("SHOPIFY_ACCESS_TOKEN", "shpat_xx")

    def _order(name):
        return {"name": name, "financial_status": "paid",
                "total_price": "1.00", "currency": "USD",
                "customer": {"email": "a@x"}}

    def _resp(orders, link):
        r = MagicMock()
        r.status_code = 200
        r.json = MagicMock(return_value={"orders": orders})
        r.headers = {"Link": link} if link else {}
        return r

    nxt = '<https://my-shop.myshopify.com/admin/api/2024-01/orders.json?page_info=CUR2>; rel="next"'
    get = MagicMock(side_effect=[
        _resp([_order("#1")], nxt),
        _resp([_order("#2")], None),
    ])
    client = MagicMock()
    client.get = get
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock(return_value=client)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.shopify_tool import shopify_tool
    out = shopify_tool().fn({"op": "orders", "limit": 50})
    assert "#1" in out and "#2" in out
    assert get.call_count == 2
    # The 2nd request follows the Link-header next URL (page_info cursor).
    assert "page_info=CUR2" in get.call_args_list[1].args[0]


def test_shopify_refund_dry_run(monkeypatch):
    monkeypatch.setenv("SHOPIFY_STORE", "my-shop")
    monkeypatch.setenv("SHOPIFY_ACCESS_TOKEN", "shpat_xx")
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.shopify_tool import shopify_tool
    out = shopify_tool().fn({
        "op": "refund_create", "order_id": 555, "amount_cents": 1000,
        "currency": "USD",
    })
    assert "DRY RUN" in out
    fake_httpx.Client.assert_not_called()


def test_shopify_refund_requires_a_positive_amount(monkeypatch):
    # With no amount the tool posted a refund with no transactions, which moves
    # no money, yet reported a FULL refund; negative amounts were sent as-is.
    monkeypatch.setenv("SHOPIFY_STORE", "my-shop")
    monkeypatch.setenv("SHOPIFY_ACCESS_TOKEN", "shpat_xx")
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.Client = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.shopify_tool import shopify_tool
    for amount in (None, 0, -500):
        out = shopify_tool().fn({"op": "refund_create", "order_id": 555,
                                 "amount_cents": amount, "confirm": True})
        assert out.startswith("ERROR") and "amount_cents" in out, amount
    fake_httpx.Client.assert_not_called()
