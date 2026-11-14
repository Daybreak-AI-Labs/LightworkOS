"""xAI (Grok) provider.

xAI's API is OpenAI-compatible at https://api.x.ai/v1.

Default model is `grok-4.5`. Other directly priced models include
`grok-build-0.1` and `grok-4.3`; `grok-code-fast` and other aliases without a
current exact pricing row remain estimate-only.

API key env var: XAI_API_KEY (or GROK_API_KEY as a common alias).
"""
from __future__ import annotations

import os

from .openrouter_provider import _GatewayClient


class XaiClient(_GatewayClient):
    DEFAULT_MODEL = "grok-4.5"
    # Official USD input/cached prices, checked 2026-11-14:
    # https://docs.x.ai/developers/pricing
    CACHE_READ_MULTIPLIERS = {
        "grok-4.7": 0.50 / 2.00,
        "grok-4.6": 0.50 / 2.00,
        "grok-4.5": 0.30 / 2.00,
        "grok-build-0.1": 0.20 / 1.00,
        "grok-4.3": 0.20 / 1.25,
        "grok-4.20-multi-agent-0309": 0.20 / 1.25,
        "grok-4.20-0309-reasoning": 0.20 / 1.25,
        "grok-4.20-0309-non-reasoning": 0.20 / 1.25,
    }

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        key = (
            api_key
            or env.get("XAI_API_KEY")
            or env.get("GROK_API_KEY")
        )
        url = base_url or env.get("XAI_BASE_URL") or "https://api.x.ai/v1"
        super().__init__(
            api_key=key,
            base_url=url,
            allow_openai_env_fallback=False,
            environment=environment,
        )
