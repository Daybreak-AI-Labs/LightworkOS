"""Tests for the currency tool (maverick.tools.currency)."""
from __future__ import annotations

from unittest.mock import MagicMock

# ---------- Currency tool ----------

def test_currency_requires_op():
    from maverick.tools.currency import currency
    assert "op is required" in currency().fn({})


def test_currency_convert_exchangerate(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={
        "result": 92.345,
        "info": {"rate": 0.92345},
    })
    # currency now fetches through the SSRF-safe pinned client, so patch
    # _ssrf.safe_get rather than a raw httpx.get.
    monkeypatch.setattr("maverick.tools._ssrf.safe_get", MagicMock(return_value=resp))
    from maverick.tools.currency import currency
    out = currency().fn({
        "op": "convert", "amount": 100, "from": "USD", "to": "EUR",
    })
    assert "USD = 92.3450 EUR" in out
    assert "rate" in out


def test_currency_falls_back_to_frankfurter(monkeypatch):
    """First provider returns garbage; fall back."""
    calls = {"n": 0}

    def _get(url, *a, **k):
        calls["n"] += 1
        resp = MagicMock()
        if "exchangerate" in url:
            resp.status_code = 500
            resp.json = MagicMock(side_effect=ValueError("nope"))
        else:
            resp.status_code = 200
            resp.json = MagicMock(return_value={"rates": {"JPY": 15000.0}})
        return resp

    monkeypatch.setattr("maverick.tools._ssrf.safe_get", _get)
    from maverick.tools.currency import currency
    out = currency().fn({
        "op": "convert", "amount": 100, "from": "USD", "to": "JPY",
    })
    assert "USD = 15000.0000 JPY" in out
    assert calls["n"] == 2


def test_currency_rates_renders(monkeypatch):
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"rates": {
        "EUR": 0.92, "JPY": 150.0,
    }})
    monkeypatch.setattr("maverick.tools._ssrf.safe_get", MagicMock(return_value=resp))
    from maverick.tools.currency import currency
    out = currency().fn({"op": "rates", "base": "USD"})
    assert "USD -> EUR" in out and "USD -> JPY" in out
