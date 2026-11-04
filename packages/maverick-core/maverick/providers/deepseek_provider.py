"""DeepSeek provider.

DeepSeek's API is OpenAI-compatible at https://api.deepseek.com/v1.

Default model is `deepseek-v4-flash`. The legacy `deepseek-chat` and
`deepseek-reasoner` aliases remain callable but are estimate-only until a
current, directly applicable price is captured.

API key env var: DEEPSEEK_API_KEY.
"""
from __future__ import annotations

import os

from .openai_provider import OpenAIClient


class DeepSeekClient(OpenAIClient):
    DEFAULT_MODEL = "deepseek-v4-flash"
    # DeepSeek bills cache hits (prompt_cache_hit_tokens) at ~10% of the
    # cache-miss input rate (a ~90% discount), far steeper than OpenAI's 0.5x.
    # Inheriting 0.5x would over-charge cached input ~5x.
    CACHE_READ_MULT = 0.1

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        key = api_key or env.get("DEEPSEEK_API_KEY")
        url = base_url or env.get(
            "DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1",
        )
        super().__init__(
            api_key=key,
            base_url=url,
            allow_openai_env_fallback=False,
            environment=environment,
        )
