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

from .openrouter_provider import _GatewayClient


class MoonshotClient(_GatewayClient):
    DEFAULT_MODEL = "kimi-k2"
    # Official model-specific cached-input ratios, checked 2026-11-14:
    # https://platform.kimi.ai/docs/pricing/chat
    CACHE_READ_MULTIPLIERS = {
        "kimi-k3.1-pro": 0.20 / 2.00,
        "kimi-k3.1-pro-highspeed": 0.20 / 4.00,
        "kimi-k3": 0.30 / 3.00,
        "kimi-k2.7-code": 0.19 / 0.95,
        "kimi-k2.7-code-highspeed": 0.38 / 1.90,
        "kimi-k2.6": 0.16 / 0.95,
    }
    # This adapter sends no TTL override; K3's default 5m writes cost 1x.
    # Unknown models/writes remain unpriced instead of borrowing Anthropic's 1.25x.
    CACHE_WRITE_MULTIPLIERS = {
        "kimi-k3.1-pro": 1.0, "kimi-k3.1-pro-highspeed": 1.0, "kimi-k3": 1.0,
    }

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        key = api_key or env.get("MOONSHOT_API_KEY")
        url = base_url or env.get("MOONSHOT_BASE_URL") or "https://api.moonshot.ai/v1"
        super().__init__(
            api_key=key,
            base_url=url,
            allow_openai_env_fallback=False,
            environment=environment,
        )
