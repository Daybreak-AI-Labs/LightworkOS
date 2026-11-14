"""xAI (Grok) provider.

xAI's API is OpenAI-compatible at https://api.x.ai/v1.

Default model is `grok-4.5`. Other directly priced models include
`grok-build-0.1` and `grok-4.3`; `grok-code-fast` and other aliases without a
current exact pricing row remain estimate-only.

API key env var: XAI_API_KEY (or GROK_API_KEY as a common alias).
"""
from __future__ import annotations

import os

from .openai_provider import OpenAIClient


class XaiClient(OpenAIClient):
    DEFAULT_MODEL = "grok-4.5"

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
