"""Gemini opts into the write-side prompt-cache ordering (implicit cache)."""
from __future__ import annotations

from maverick.providers.gemini_provider import GeminiClient
from maverick.providers.openai_provider import OpenAIClient


def test_gemini_models_opt_into_auto_prompt_cache():
    # Every Gemini model gets the stable-prefix + sorted-tools treatment...
    assert GeminiClient._has_auto_prompt_cache("gemini-3.5-pro") is True
    assert GeminiClient._has_auto_prompt_cache("gemini-anything") is True


def test_base_openai_client_unchanged():
    # ...while the base client still only enables it for OpenAI auto-cache
    # models (gemini-* must not fall through here).
    assert OpenAIClient._has_auto_prompt_cache("gemini-3.5-pro") is False
    assert OpenAIClient._has_auto_prompt_cache("gpt-4.1") is True
    assert OpenAIClient._has_auto_prompt_cache("o3") is True
