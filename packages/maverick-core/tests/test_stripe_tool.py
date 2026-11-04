"""Tests for the Stripe tool (maverick.tools.stripe_tool)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Stripe tool ----------

def test_stripe_requires_op():
    from maverick.tools.stripe_tool import stripe_tool
    assert "op is required" in stripe_tool().fn({})


def test_stripe_missing_key(monkeypatch):
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    fake = types.ModuleType("httpx")
    fake.get = MagicMock()
    fake.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake)
    from maverick.tools.stripe_tool import stripe_tool
    out = stripe_tool().fn({"op": "balance"})
    assert "STRIPE_SECRET_KEY" in out


def test_stripe_balance_renders(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test")
    monkeypatch.setenv("MAVERICK_STRIPE_ENABLE_REFUNDS", "true")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "available": [{"amount": 12345, "currency": "usd"}],
        "pending": [{"amount": 6789, "currency": "usd"}],
    })
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.stripe_tool import stripe_tool
    out = stripe_tool().fn({"op": "balance"})
    assert "available" in out and "123.45" in out
    assert "pending" in out and "67.89" in out


def test_stripe_refund_dry_run(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test")
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock()
    fake_httpx.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.stripe_tool import stripe_tool
    out = stripe_tool().fn({
        "op": "refund_create", "charge_id": "ch_123",
        "amount_cents": 500,
    })
    assert "DRY RUN" in out
    # No POST was issued (still dry-run).
    fake_httpx.post.assert_not_called()


def test_stripe_refund_with_confirm(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test")
    monkeypatch.setenv("MAVERICK_STRIPE_ENABLE_REFUNDS", "true")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "id": "re_xx", "amount": 500, "currency": "usd", "charge": "ch_123",
    })
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.stripe_tool import stripe_tool
    out = stripe_tool().fn({
        "op": "refund_create", "charge_id": "ch_123",
        "amount_cents": 500, "confirm": True,
    })
    assert "refunded re_xx" in out
    fake_httpx.post.assert_called_once()
    # The refund carries an Idempotency-Key so a retry can't double-refund.
    headers = fake_httpx.post.call_args.kwargs["headers"]
    assert headers.get("Idempotency-Key", "").startswith("maverick-refund-")


def test_stripe_refund_idempotency_key_is_intent_scoped(monkeypatch):
    """Same refund intent -> same key (Stripe dedupes a retry); a different
    amount -> different key (a genuinely distinct refund isn't blocked)."""
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test")
    monkeypatch.setenv("MAVERICK_STRIPE_ENABLE_REFUNDS", "true")

    def _run(amount):
        resp = MagicMock()
        resp.status_code = 200
        resp.json = MagicMock(return_value={
            "id": "re_xx", "amount": amount, "currency": "usd", "charge": "ch_123",
        })
        post = MagicMock(return_value=resp)
        fake_httpx = types.ModuleType("httpx")
        fake_httpx.post = post
        monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
        from maverick.tools.stripe_tool import stripe_tool
        stripe_tool().fn({
            "op": "refund_create", "charge_id": "ch_123",
            "amount_cents": amount, "confirm": True,
        })
        return post.call_args.kwargs["headers"]["Idempotency-Key"]

    key_a = _run(500)
    key_a2 = _run(500)
    key_b = _run(700)
    assert key_a == key_a2      # retry of the same refund -> deduped
    assert key_a != key_b       # different amount -> distinct refund allowed


def test_stripe_charges_renders(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"data": [
        {"id": "ch_1", "status": "succeeded", "amount": 1000,
         "currency": "usd", "description": "Pro plan", "refunded": False},
        {"id": "ch_2", "status": "succeeded", "amount": 500,
         "currency": "usd", "description": "addon", "refunded": True},
    ]})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.stripe_tool import stripe_tool
    out = stripe_tool().fn({"op": "charges"})
    assert "ch_1" in out and "10.00" in out
    assert "REFUNDED" in out  # ch_2 marker


def test_stripe_charges_follows_cursor(monkeypatch):
    monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test")

    def _charge(cid):
        return {"id": cid, "status": "succeeded", "amount": 100,
                "currency": "usd", "description": "x", "refunded": False}

    def _resp(rows, has_more):
        r = MagicMock()
        r.status_code = 200
        r.json = MagicMock(return_value={"data": rows, "has_more": has_more})
        return r

    get = MagicMock(side_effect=[
        _resp([_charge("ch_1")], True),
        _resp([_charge("ch_2")], False),
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.get = get
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.stripe_tool import stripe_tool
    out = stripe_tool().fn({"op": "charges", "limit": 50})
    assert "ch_1" in out and "ch_2" in out
    assert get.call_count == 2
    # Second page is cursored on the last id of the first.
    assert get.call_args_list[1].kwargs["params"]["starting_after"] == "ch_1"


class TestStripeZeroDecimal:
    def test_jpy_not_divided_by_100(self):
        from maverick.tools.stripe_tool import _money
        # ¥5000 is returned by Stripe as 5000 (zero-decimal), not 500000.
        assert _money(5000, "jpy") == "5,000 JPY"
        # USD still divides by 100.
        assert _money(5000, "usd") == "50.00 USD"
