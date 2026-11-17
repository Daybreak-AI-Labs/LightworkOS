"""Tests for the translate tool (maverick.tools.translate)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

from maverick.budget import Budget

# ---------- Translate tool ----------

def test_translate_requires_text():
    from maverick.tools.translate import translate
    out = translate(budget=Budget()).fn({"op": "translate", "target": "es"})
    assert "text is required" in out


def test_translate_deepl_path(monkeypatch):
    monkeypatch.setenv("DEEPL_API_KEY", "abc:fx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"translations": [
        {"text": "Hola mundo", "detected_source_language": "EN"},
    ]})

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.translate import translate
    out = translate(budget=Budget()).fn({"op": "translate", "text": "hello world",
                          "target": "es"})
    assert "Hola mundo" in out
    assert "from=EN" in out
    url = fake_httpx.post.call_args.args[0]
    assert "api-free.deepl.com" in url


def test_translate_libre_fallback(monkeypatch):
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    monkeypatch.setenv("LIBRETRANSLATE_URL", "https://translate.internal.example")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"translatedText": "Bonjour"})

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.translate import translate
    out = translate(budget=Budget()).fn({"op": "translate", "text": "hello", "target": "fr"})
    assert "Bonjour" in out
    assert fake_httpx.post.call_args.args[0] == "https://translate.internal.example/translate"


def test_translate_sends_nothing_when_no_service_is_configured(monkeypatch):
    # With no DeepL key and no LibreTranslate server chosen, text used to go to
    # the public libretranslate.com; an unknown backend name fell through to it
    # as well.
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    monkeypatch.delenv("LIBRETRANSLATE_URL", raising=False)
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock()
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.translate import translate
    for call in (
        {"op": "translate", "text": "hello", "target": "fr"},
        {"op": "detect", "text": "hello"},
        {"op": "translate", "text": "hello", "target": "fr", "backend": "libretranslate"},
    ):
        out = translate(budget=Budget()).fn(call)
        assert out.startswith("ERROR: no translation service is configured")
        assert "DEEPL_API_KEY" in out and "LIBRETRANSLATE_URL" in out

    monkeypatch.setenv("LIBRETRANSLATE_URL", "https://translate.internal.example")
    out = translate(budget=Budget()).fn({"op": "translate", "text": "hello", "target": "fr", "backend": "google"})
    assert out.startswith("ERROR: unknown backend 'google'")
    fake_httpx.post.assert_not_called()


def test_translate_backend_arg_is_case_insensitive(monkeypatch):
    # A mixed-case backend arg must route to the right provider.
    # _pick_backend strips+lowercases, so "  DeepL  " -> "deepl" and the
    # DeepL endpoint is hit (a non-normalized arg would fall through to libre).
    monkeypatch.setenv("DEEPL_API_KEY", "abc:fx")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"translations": [
        {"text": "Hola", "detected_source_language": "EN"},
    ]})

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.translate import translate
    out = translate(budget=Budget()).fn({"op": "translate", "text": "hi", "target": "es",
                          "backend": "  DeepL  "})
    assert "Hola" in out
    url = fake_httpx.post.call_args.args[0]
    assert "deepl.com" in url, "mixed-case 'DeepL' should route to DeepL"


def test_translate_detect_libre(monkeypatch):
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    monkeypatch.setenv("LIBRETRANSLATE_URL", "https://translate.internal.example")
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=[
        {"language": "ja", "confidence": 0.99},
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.translate import translate
    out = translate(budget=Budget()).fn({"op": "detect", "text": "こんにちは"})
    assert "ja" in out


def _deepl_and_libre(monkeypatch, *, libre_url=""):
    monkeypatch.setenv("DEEPL_API_KEY", "abc:fx")
    if libre_url:
        monkeypatch.setenv("LIBRETRANSLATE_URL", libre_url)
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"translations": [{"text": "Hola"}],
                                        "translatedText": "Bonjour"})
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    return fake_httpx.post


def test_deepl_is_charged_at_the_set_character_price_until_the_limit_stops_it(monkeypatch, tmp_path):
    # Kernel rule 3: a DeepL call is charged to the run at the operator's
    # [budget.tool_prices] price, and the next call that would pass the dollar
    # limit is stopped before it is sent.
    import os

    import pytest
    from maverick import config
    from maverick.budget import BudgetExceeded
    from maverick.tools.translate import translate

    home = os.environ["MAVERICK_HOME"]
    os.makedirs(home, exist_ok=True)
    with open(os.path.join(home, "config.toml"), "w", encoding="utf-8") as f:
        f.write('[budget.tool_prices]\ndeepl = { dollars = 0.001, per = "character" }\n')
    config.reset_config_cache()
    post = _deepl_and_libre(monkeypatch)
    budget = Budget(max_dollars=0.015)
    tool = translate(budget=budget)
    assert "Hola" in tool.fn({"op": "translate", "text": "hello world", "target": "es"})
    assert budget.dollars == pytest.approx(0.011)
    assert budget.pricing_snapshot()["tool:deepl"]["rate_card_version"] == "operator-tool-price-v1"
    with pytest.raises(BudgetExceeded):
        tool.fn({"op": "translate", "text": "hello world", "target": "es"})
    assert post.call_count == 1 and budget.dollars == pytest.approx(0.011)


def test_private_libretranslate_is_free_and_no_budget_refuses_deepl(monkeypatch):
    # A LibreTranslate server on a private address is not charged, by the
    # rule self-hosted model servers use. A tool built with no run budget (a
    # flow's tool step) refuses a paid DeepL call before sending anything.
    from maverick.tools.translate import translate

    post = _deepl_and_libre(monkeypatch, libre_url="http://10.0.0.5:5000")
    budget = Budget()
    out = translate(budget=budget).fn({"op": "translate", "text": "hello", "target": "fr",
                                       "backend": "libretranslate"})
    assert "Bonjour" in out and post.call_count == 1 and budget.dollars == 0
    out = translate().fn({"op": "translate", "text": "hello", "target": "es"})
    assert out.startswith("ERROR") and "spending limit" in out and "nothing was sent" in out
    assert post.call_count == 1


def test_paid_calls_are_refused_while_settings_cannot_be_read(monkeypatch):
    # An unreadable configuration could hide a price the administrator set,
    # so paid tool calls are refused with a plain message instead of guessed.
    from maverick import config
    from maverick.tools.translate import translate

    post = _deepl_and_libre(monkeypatch)
    monkeypatch.setattr(config, "config_source_errors", lambda **_kw: ["config.toml"])
    out = translate(budget=Budget()).fn({"op": "translate", "text": "hello", "target": "es"})
    assert out.startswith("ERROR") and "cannot read its settings" in out and post.call_count == 0
