"""Gemini provider client.

Google's Gemini exposes an OpenAI-compatible endpoint at
``https://generativelanguage.googleapis.com/v1beta/openai/``, so we can
reuse OpenAIClient with just a different base_url + API key.

Set ``GEMINI_API_KEY`` (preferred) or ``GOOGLE_API_KEY``.
"""
from __future__ import annotations

import os

from .openai_provider import OpenAIClient


class GeminiClient(OpenAIClient):
    # Gemini 3.5 Flash has a current, captured official price. No matching 3.5
    # Pro row was present on that source at capture time, so Pro remains an
    # explicitly unverified estimate rather than the strict-billing default.
    DEFAULT_MODEL = "gemini-3.5-flash"
    # Gemini's implicit context cache discounts cached tokens ~75% (billed at
    # ~0.25x the input rate), steeper than OpenAI's 0.5x. Inheriting 0.5x would
    # over-charge cached input ~2x.
    CACHE_READ_MULT = 0.25

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        key = api_key or env.get("GEMINI_API_KEY") or env.get("GOOGLE_API_KEY")
        super().__init__(
            api_key=key,
            base_url=base_url or "https://generativelanguage.googleapis.com/v1beta/openai/",
            # Don't silently fall back to OPENAI_API_KEY when no Gemini key is
            # set -- that would send the OpenAI key to Google's endpoint.
            allow_openai_env_fallback=False,
            environment=environment,
        )

    @staticmethod
    def _has_auto_prompt_cache(model: str) -> bool:
        # Gemini has implicit context caching, so opt every Gemini model into
        # the same write-side stable-prefix + sorted-tools ordering the base
        # class applies to OpenAI's auto-cache models. The base list is
        # gpt/o-series only, so without this gemini-* fell through and the
        # implicit cache never saw a byte-stable prefix (a non-deterministic
        # tool order silently busts it every call).
        return True
