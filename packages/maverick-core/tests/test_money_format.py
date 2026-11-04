"""Localized money formatting + the format_money tool."""
from __future__ import annotations

from maverick.money_format import format_money, supported
from maverick.tools.format_money import format_money_tool


def test_en_us_default():
    assert format_money(1234.56) == "$1,234.56"


def test_de_de_euro_suffix_and_separators():
    assert format_money(1234.56, currency="EUR", locale="de-DE") == "1.234,56 €"


def test_fr_fr_space_group():
    assert format_money(1234.56, currency="EUR", locale="fr-FR") == "1 234,56 €"


def test_jpy_no_decimals_rounds():
    assert format_money(1234.56, currency="JPY", locale="ja-JP") == "¥1,235"


def test_gbp_prefix():
    assert format_money(99.5, currency="GBP", locale="en-GB") == "£99.50"


def test_negative_amount():
    assert format_money(-1000, currency="USD") == "-$1,000.00"


def test_rate_conversion():
    # 100 USD * 0.9 -> 90 EUR, German format
    assert format_money(100, currency="EUR", locale="de-DE", rate=0.9) == "90,00 €"


def test_unknown_currency_generic():
    out = format_money(5, currency="XYZ")
    assert out.startswith("XYZ ") and "5.00" in out


def test_unknown_locale_falls_back_to_en_us_style():
    assert format_money(1000, currency="USD", locale="zz-ZZ") == "$1,000.00"


def test_supported_lists():
    s = supported()
    assert "de-DE" in s["locales"] and "JPY" in s["currencies"]


def test_large_grouping():
    assert format_money(1234567.89) == "$1,234,567.89"


# ---- tool ----

def test_tool_format():
    out = format_money_tool().fn({"op": "format", "amount": 1234.5,
                                  "currency": "EUR", "locale": "de-DE"})
    assert out == "1.234,50 €"


def test_tool_default_op_and_currency():
    assert format_money_tool().fn({"amount": 10}) == "$10.00"


def test_tool_requires_amount():
    assert format_money_tool().fn({"op": "format"}).startswith("ERROR")


def test_tool_supported():
    assert "currencies" in format_money_tool().fn({"op": "supported"})


def test_tool_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "format_money" in names
    assert "currency" in names  # the live-FX conversion tool still present
