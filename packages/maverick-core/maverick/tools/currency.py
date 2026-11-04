"""Currency conversion tool.

Uses the open ``exchangerate.host`` API (no key required, falls back
to ``frankfurter.app`` if the first is down). Two ops cover the
common cases:

  - convert(amount, from_, to)       — convert a single amount
  - rates(base, symbols)             — fetch rates for a base currency

All values are decimals; ISO 4217 codes (USD, EUR, JPY, etc.).
"""
from __future__ import annotations

import logging
from typing import Any

from . import Tool

log = logging.getLogger(__name__)


_CCY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["convert", "rates"]},
        "amount": {"type": "number"},
        "from": {"type": "string", "description": "ISO 4217 (e.g. 'USD')."},
        "to": {"type": "string"},
        "base": {"type": "string", "description": "Base currency (default 'USD')."},
        "symbols": {
            "type": "array", "items": {"type": "string"},
            "description": "Filter rates to these currencies.",
        },
    },
    "required": ["op"],
}


def _fetch(url: str, params: dict) -> tuple[int, Any]:
    # Route through the SSRF-safe client (pins the resolved public IP, forces
    # follow_redirects=False) so a provider 3xx can't redirect us onto an
    # internal address -- a raw httpx.get(follow_redirects=True) would.
    from ._ssrf import safe_get
    try:
        r = safe_get(url, params=params, timeout=15.0)
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, {}
    except Exception as e:
        return 599, {"error": f"{type(e).__name__}: {e}"}


def _convert_exchangerate(amount: float, src: str, dst: str) -> tuple[bool, str]:
    code, data = _fetch(
        "https://api.exchangerate.host/convert",
        {"from": src, "to": dst, "amount": amount},
    )
    if code != 200 or not isinstance(data, dict) or "result" not in data:
        return False, f"exchangerate.host {code}: {data}"
    result = data["result"]
    rate = (data.get("info") or {}).get("rate")
    return True, (
        f"{amount} {src} = {result:.4f} {dst}"
        f"  (rate {rate:.6f})" if rate is not None
        else f"{amount} {src} = {result:.4f} {dst}"
    )


def _convert_frankfurter(amount: float, src: str, dst: str) -> tuple[bool, str]:
    code, data = _fetch(
        "https://api.frankfurter.app/latest",
        {"amount": amount, "from": src, "to": dst},
    )
    if code != 200 or not isinstance(data, dict):
        return False, f"frankfurter.app {code}: {data}"
    rates = data.get("rates") or {}
    if dst.upper() not in rates:
        return False, f"frankfurter.app missing {dst}"
    result = float(rates[dst.upper()])
    return True, f"{amount} {src} = {result:.4f} {dst}"


def _op_convert(amount: float, src: str, dst: str) -> str:
    if not src or not dst:
        return "ERROR: convert requires from and to"
    ok, msg = _convert_exchangerate(amount, src.upper(), dst.upper())
    if ok:
        return msg
    ok, msg = _convert_frankfurter(amount, src.upper(), dst.upper())
    if ok:
        return msg + "  (via frankfurter)"
    return f"ERROR: all providers failed. Last: {msg}"


def _rates_exchangerate(base: str, symbols: list[str]) -> tuple[bool, str]:
    params = {"base": base}
    if symbols:
        params["symbols"] = ",".join(symbols)
    code, data = _fetch("https://api.exchangerate.host/latest", params)
    if code != 200 or not isinstance(data, dict):
        return False, f"exchangerate.host {code}: {data}"
    rates = data.get("rates") or {}
    if not rates:
        return False, "no rates returned"
    return True, "\n".join(
        f"  {base} -> {sym}: {rate:.6f}" for sym, rate in sorted(rates.items())
    )


def _rates_frankfurter(base: str, symbols: list[str]) -> tuple[bool, str]:
    params = {"from": base}
    if symbols:
        params["to"] = ",".join(symbols)
    code, data = _fetch("https://api.frankfurter.app/latest", params)
    if code != 200 or not isinstance(data, dict):
        return False, f"frankfurter.app {code}: {data}"
    rates = data.get("rates") or {}
    if not rates:
        return False, "no rates returned"
    return True, "\n".join(
        f"  {base} -> {sym}: {float(rate):.6f}" for sym, rate in sorted(rates.items())
    )


def _op_rates(base: str, symbols: list[str]) -> str:
    ok, msg = _rates_exchangerate(base.upper(), [s.upper() for s in symbols])
    if ok:
        return msg
    ok, msg = _rates_frankfurter(base.upper(), [s.upper() for s in symbols])
    if ok:
        return msg + "\n(via frankfurter)"
    return f"ERROR: all providers failed. Last: {msg}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if not op:
        return "ERROR: op is required"
    try:
        import httpx  # noqa: F401
    except ImportError:
        return "ERROR: httpx not installed. Run: python -m pip install -e './packages/maverick-core[issue-trackers]'"
    try:
        if op == "convert":
            return _op_convert(
                float(args.get("amount") or 0),
                str(args.get("from") or ""),
                str(args.get("to") or ""),
            )
        if op == "rates":
            return _op_rates(
                str(args.get("base") or "USD"),
                [str(s) for s in (args.get("symbols") or [])],
            )
    except Exception as e:
        return f"ERROR: currency failed: {type(e).__name__}: {e}"
    return f"ERROR: unknown op {op!r}"


def currency() -> Tool:
    return Tool(
        name="currency",
        description=(
            "Currency conversion + FX rates via exchangerate.host "
            "(falls back to frankfurter.app). ops: convert (amount + "
            "from + to), rates (base + optional symbols filter). No "
            "API key required."
        ),
        input_schema=_CCY_SCHEMA,
        fn=_run,
    )
