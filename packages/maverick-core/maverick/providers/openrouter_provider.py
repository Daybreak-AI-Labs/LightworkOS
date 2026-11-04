"""OpenRouter provider client.

OpenRouter is OpenAI-compatible at a different base_url and aggregates
200+ models from many vendors. Models follow the format
``vendor/model-id`` (e.g., ``meta-llama/llama-3.3-70b``).

Uses the OpenAIClient implementation; just swaps base_url + api_key.
"""
from __future__ import annotations

import os

from .openai_provider import OpenAIClient


class OpenRouterClient(OpenAIClient):
    DEFAULT_MODEL = "meta-llama/llama-3.3-70b"
    PRICE_MODEL_PREFIX = "openrouter:"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        super().__init__(
            api_key=api_key or env.get("OPENROUTER_API_KEY"),
            base_url=base_url or "https://openrouter.ai/api/v1",
            allow_openai_env_fallback=False,
            environment=environment,
        )
