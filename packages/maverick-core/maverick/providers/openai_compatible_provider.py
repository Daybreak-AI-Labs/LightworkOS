"""Generic OpenAI-compatible provider (base_url-driven).

Many inference servers and gateways speak the OpenAI chat-completions
protocol but live at an arbitrary base_url: LM Studio, llama.cpp's
server, Together, Groq, and any private OpenAI-compatible proxy. Rather
than ship a bespoke client per vendor, this provider re-uses the
OpenAIClient base and reads ``base_url`` + ``api_key`` from
``[providers.openai_compatible]`` in config (or env).

Config::

    [providers.openai_compatible]
    base_url = "https://api.groq.com/openai/v1"
    api_key  = "${GROQ_API_KEY}"

Env fallback: ``OPENAI_COMPATIBLE_BASE_URL`` / ``OPENAI_COMPATIBLE_API_KEY``.

The base_url is passed through verbatim — supply the full documented
endpoint (e.g. Groq's ``/openai/v1``); we don't rewrite it. Model id is
user-chosen via ``[models]``; the placeholder DEFAULT_MODEL is only a
last-resort label.

A missing ``api_key`` is only tolerated for a loopback/private-network
base_url (LM Studio, llama.cpp, or any other key-less local server) --
same as the TGI/vLLM providers' unconditional placeholder key, but scoped
here since this provider (unlike TGI/vLLM, which are always self-hosted by
design) also fronts public gateways like Groq/Together, where a missing
key is a real misconfiguration and stays refused.
"""
from __future__ import annotations

import os

from .openai_provider import OpenAIClient


class OpenAICompatibleClient(OpenAIClient):
    DEFAULT_MODEL = "openai-compatible"
    PRICE_MODEL_PREFIX = "openai_compatible:"  # keep provider context for pricing

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        env = os.environ if environment is None else environment
        from ..config import get_provider_config

        cfg = get_provider_config("openai_compatible") if environment is None else {}
        url = (
            base_url
            or cfg.get("base_url")
            or env.get("OPENAI_COMPATIBLE_BASE_URL")
        )
        if not url:
            raise ValueError(
                "openai-compatible provider needs a base_url. Set "
                "[providers.openai_compatible] base_url in config.toml or "
                "the OPENAI_COMPATIBLE_BASE_URL env var (e.g. a LM Studio / "
                "llama.cpp / Together / Groq endpoint)."
            )
        key = (
            api_key
            or cfg.get("api_key")
            or env.get("OPENAI_COMPATIBLE_API_KEY")
        )
        if not key:
            from ..enterprise import _is_local_endpoint

            if _is_local_endpoint(url):
                # LM Studio / llama.cpp / any other key-less local server --
                # matches the TGI/vLLM "<provider>-no-auth" placeholder so a
                # genuinely key-less endpoint (the docstring's own headline
                # use case) doesn't hit the base client's "no key" refusal.
                key = "openai-compatible-no-auth"
        super().__init__(
            api_key=key,
            base_url=url,
            allow_openai_env_fallback=False,
            environment=environment,
        )
