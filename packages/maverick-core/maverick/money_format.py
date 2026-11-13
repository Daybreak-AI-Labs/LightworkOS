"""Localized money formatting.

Lightwork reports spend in US dollars. For a non-US operator that reads wrong:
``$1,234.56`` should be ``1.234,56 €`` in Germany or ``¥1,235`` in Japan. This
formats a numeric amount per a (locale, currency) pair — symbol placement,
grouping/decimal separators, and the currency's decimal places — with an
optional operator-supplied FX rate to convert from the base amount.

Distinct from the ``currency`` tool (live-FX *conversion*): this is the offline
*display* layer. A **curated subset** of locales/currencies (not full CLDR —
that needs ``babel``); unknown locales fall back to a plain ``en-US`` format and
an unknown currency to a 2-decimal generic. Pure, deterministic, no live FX.
Exposed as the ``format_money`` tool.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _Locale:
    decimal: str
    group: str
    symbol_prefix: bool      # True: "$1" ; False: "1 €"
    space: bool              # space between symbol and number


# Curated locale formats (separator + symbol placement conventions).
_LOCALES = {
    "en-US": _Locale(".", ",", True, False),
    "en-GB": _Locale(".", ",", True, False),
    "de-DE": _Locale(",", ".", False, True),
    "fr-FR": _Locale(",", " ", False, True),
    "es-ES": _Locale(",", ".", False, True),
    "ja-JP": _Locale(".", ",", True, False),
    "en-IN": _Locale(".", ",", True, False),
}
# Currency symbol + decimal places.
_CURRENCIES = {
    "USD": ("$", 2), "EUR": ("€", 2), "GBP": ("£", 2),
    "JPY": ("¥", 0), "INR": ("₹", 2), "CNY": ("¥", 2),
    "CHF": ("CHF", 2), "CAD": ("$", 2), "AUD": ("$", 2),
}

_DEFAULT_LOCALE = _Locale(".", ",", True, False)


def _group_int(int_str: str, sep: str) -> str:
    out: list[str] = []
    for i, ch in enumerate(reversed(int_str)):
        if i and i % 3 == 0:
            out.append(sep)
        out.append(ch)
    return "".join(reversed(out))


def format_money(amount: float, *, currency: str = "USD", locale: str = "en-US",
                 rate: float | None = None) -> str:
    """Format ``amount`` (optionally × ``rate``) in ``currency`` for ``locale``.

    ``rate`` converts from the base amount (e.g. USD→EUR); omit it to format the
    amount as-is. Unknown locale/currency degrade to sensible generic formats.
    """
    # Coerce defensively: an unknown/None currency degrades to a generic format
    # (matching the locale path's ``.get(..., default)``), never crashes on
    # ``None.upper()``.
    cur = str(currency or "USD").upper()
    symbol, decimals = _CURRENCIES.get(cur, (cur + " ", 2))
    loc = _LOCALES.get(locale, _DEFAULT_LOCALE)
    value = float(amount) * (float(rate) if rate is not None else 1.0)
    s = f"{abs(value):.{decimals}f}"
    # Determine sign from the *rounded* magnitude so a tiny negative that rounds
    # to zero (e.g. -0.004 -> "0.00") does not render a spurious "-$0.00".
    neg = value < 0 and float(s) != 0.0
    int_str, _, frac_str = s.partition(".")
    num = _group_int(int_str, loc.group)
    if frac_str:
        num = num + loc.decimal + frac_str
    gap = " " if loc.space else ""
    # An unknown currency's symbol is "CODE " (the space separates it from the
    # number it precedes); after the number that space would trail.
    body = f"{symbol}{gap}{num}" if loc.symbol_prefix else f"{num}{gap}{symbol.rstrip()}"
    return ("-" + body) if neg else body


def supported() -> dict:
    return {"locales": sorted(_LOCALES), "currencies": sorted(_CURRENCIES)}


__all__ = ["format_money", "supported"]
