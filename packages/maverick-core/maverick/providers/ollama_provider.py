"""Ollama provider client.

Local models via Ollama's OpenAI-compatible API at ``/v1``. Nothing
leaves the user's machine; pricing is implicitly $0 since inference
runs locally.

Default base_url is ``http://localhost:11434/v1``. Override via
``[providers.ollama] base_url`` in config.
"""
from __future__ import annotations

from .openai_provider import OpenAIClient


class OllamaClient(OpenAIClient):
    DEFAULT_MODEL = "llama3.3:70b"
    PRICE_MODEL_PREFIX = "ollama:"  # self-hosted: unknown ids price $0
    USAGE_REQUIRED = False  # local server may omit usage; $0 -> nothing to enforce

    def __init__(self, api_key: str | None = None, base_url: str | None = None, *, environment=None):
        url = (base_url or "http://localhost:11434/v1").rstrip("/")
        if not url.endswith("/v1"):
            url += "/v1"
        super().__init__(
            api_key=api_key or "ollama",  # placeholder; Ollama ignores it
            base_url=url,
            environment=environment,
        )

    def _build_kwargs(self, system, messages, tools, max_tokens, model,
                      thinking_budget=None, tool_choice=None):
        # A PROMOTED tenant adapter ([adapter_rung]) is a serving detail of THIS
        # provider: resolve base -> tuned model here, at request-build time, so
        # spec parsing, admin allow-lists, pricing, and telemetry upstream all
        # keep the stable base model id (the adapter carries its own
        # Ed25519-signed weights-rung approval). Fail-open: any error serves
        # the base model unchanged.
        try:
            from ..adapter_rung import effective_wire_model
            model = effective_wire_model("ollama", model or self.DEFAULT_MODEL)
        except Exception:  # pragma: no cover -- the rung must never break serving
            pass
        return super()._build_kwargs(system, messages, tools, max_tokens, model,
                                     thinking_budget=thinking_budget,
                                     tool_choice=tool_choice)
