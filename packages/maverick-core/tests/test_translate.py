"""Tests for the translate tool (maverick.tools.translate)."""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

# ---------- Translate tool ----------

def test_translate_requires_text():
    from maverick.tools.translate import translate
    out = translate().fn({"op": "translate", "target": "es"})
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
    out = translate().fn({"op": "translate", "text": "hello world",
                          "target": "es"})
    assert "Hola mundo" in out
    assert "from=EN" in out
    url = fake_httpx.post.call_args.args[0]
    assert "api-free.deepl.com" in url


def test_translate_libre_fallback(monkeypatch):
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value={"translatedText": "Bonjour"})

    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)

    from maverick.tools.translate import translate
    out = translate().fn({"op": "translate", "text": "hello", "target": "fr"})
    assert "Bonjour" in out


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
    out = translate().fn({"op": "translate", "text": "hi", "target": "es",
                          "backend": "  DeepL  "})
    assert "Hola" in out
    url = fake_httpx.post.call_args.args[0]
    assert "deepl.com" in url, "mixed-case 'DeepL' should route to DeepL"


def test_translate_detect_libre(monkeypatch):
    monkeypatch.delenv("DEEPL_API_KEY", raising=False)
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(return_value=[
        {"language": "ja", "confidence": 0.99},
    ])
    fake_httpx = types.ModuleType("httpx")
    fake_httpx.post = MagicMock(return_value=resp)
    monkeypatch.setitem(sys.modules, "httpx", fake_httpx)
    from maverick.tools.translate import translate
    out = translate().fn({"op": "detect", "text": "こんにちは"})
    assert "ja" in out
