"""Moonshot / Kimi provider.

Moonshot's API is OpenAI-compatible at https://api.moonshot.cn/v1 (China)
and https://api.moonshot.ai/v1 (international). We default to the
international endpoint; users in China can override with the
MOONSHOT_BASE_URL env var or the `base_url` parameter.

Default model is `kimi-k2` (the long-context flagship). Other models:
`kimi-k1.5`, `moonshot-v1-8k`, `moonshot-v1-32k`, `moonshot-v1-128k`.

API key env var: MOONSHOT_API_KEY (falls back to OPENAI_API_KEY only
if explicitly aliased — we keep them separate to avoid accidental
cross-provider billing).
"""
from __future__ import annotations

import os

from .openai_provider import OpenAIClient


class MoonshotClient(OpenAIClient):
    DEFAULT_MODEL = "kimi-k2"

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        key = api_key or env.get("MOONSHOT_API_KEY")
        url = base_url or env.get(
            "MOONSHOT_BASE_URL", "https://api.moonshot.ai/v1",
        )
        super().__init__(
            api_key=key,
            base_url=url,
            allow_openai_env_fallback=False,
            environment=environment,
        )
