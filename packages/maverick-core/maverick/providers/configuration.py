"""Immutable provider admission and explicit adapter configuration capabilities."""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class ProviderCapabilities:
    fields: frozenset[str]


_COMMON = frozenset({"api_key", "base_url"})
_HEADERS = _COMMON | {"default_headers"}
CAPABILITIES = MappingProxyType({
    "anthropic": ProviderCapabilities(_HEADERS),
    "openai": ProviderCapabilities(_HEADERS),
    # deployment / api_version / region: set on the dashboard; the provider's
    # own environment variables still win (see LLM._provider_client_config).
    "azure": ProviderCapabilities(_HEADERS | {"auth_mode", "deployment", "api_version"}),
    "bedrock": ProviderCapabilities(_HEADERS | {"auth_mode", "endpoint", "region", "model_id"}),
    # Google Application Default Credentials only: no api_key field exists.
    "vertex": ProviderCapabilities(frozenset({
        "base_url", "default_headers", "project_id", "region", "model_id",
    })),
    **{name: ProviderCapabilities(_COMMON) for name in (
        "moonshot", "xai", "gemini", "deepseek", "openrouter", "ollama",
        "tgi", "vllm", "openai_compatible",
    )},
    "codex_cli": ProviderCapabilities(frozenset({
        "api_key", "binary", "sandbox_mode", "timeout_seconds", "cwd",
    })),
})


@dataclass(frozen=True, repr=False)
class ProviderConfig:
    """Admitted values; secret material never appears in repr or cache keys."""

    api_key: str | None
    base_url: str | None
    default_headers: tuple[tuple[str, str], ...]
    auth_mode: str | None
    provider_environment: tuple[tuple[str, str], ...]
    fingerprint: str
    adapter_options: tuple[tuple[str, str | float], ...] = ()

    def __post_init__(self):
        for field in ("default_headers", "provider_environment", "adapter_options"):
            object.__setattr__(self, field, tuple(tuple(pair) for pair in getattr(self, field)))

    def headers_dict(self) -> dict[str, str] | None:
        return dict(self.default_headers) if self.default_headers else None

    def environment_dict(self) -> dict[str, str]:
        return dict(self.provider_environment)

    def options_dict(self) -> dict[str, str | float]:
        return dict(self.adapter_options)


def validate_fields(provider: str, values) -> None:
    capability = CAPABILITIES.get(provider)
    if capability is None:
        raise ValueError(f"unknown provider {provider!r}. Available: " + ", ".join(CAPABILITIES))
    if not isinstance(values, dict):
        raise ValueError(f"providers.{provider} must be a configuration table")
    for name, value in values.items():
        if name not in capability.fields and value not in (None, "", {}, []):
            field = name if isinstance(name, str) and re.fullmatch(r"[a-zA-Z_][a-zA-Z_0-9]*", name) else "<invalid field>"
            raise ValueError(
                f"providers.{provider}.{field} is unsupported by this adapter; "
                "remove the setting or select an adapter that supports it"
            )
        if name in {"api_key", "base_url", "auth_mode", "endpoint", "deployment", "api_version", "region", "model_id", "project_id"} \
                and value is not None and not isinstance(value, str):
            raise ValueError(f"providers.{provider}.{name} must be a string")


def canonical_headers(value: object) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, dict):
        raise ValueError("provider default_headers must be a table of HTTP header names and values")
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for name, raw in value.items():
        if not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name):
            raise ValueError("provider default_headers contains an invalid HTTP header name")
        if name.casefold() in seen:
            raise ValueError("provider default_headers contains duplicate case-insensitive header names")
        seen.add(name.casefold())
        if not isinstance(raw, (str, int, float, bool)) or any(
            ord(char) > 126 or (ord(char) < 32 and char != "\t") for char in str(raw)
        ):
            raise ValueError("provider default_headers contains an invalid HTTP header value")
        headers[name] = str(raw)
    return tuple(sorted(headers.items(), key=lambda item: item[0].casefold()))


def adapter_options(provider: str, config: dict) -> tuple[tuple[str, str | float], ...]:
    if provider != "codex_cli":
        return ()
    import math

    options: dict[str, str | float] = {}
    for name in ("binary", "sandbox_mode", "cwd"):
        value = config.get(name)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"providers.codex_cli.{name} must be a string")
            if value.strip():
                options[name] = value
    value = config.get("timeout_seconds")
    if value is not None:
        try:
            timeout = float(value)
        except (ValueError, TypeError):
            raise ValueError("providers.codex_cli.timeout_seconds must be finite and positive") from None
        if isinstance(value, bool) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("providers.codex_cli.timeout_seconds must be finite and positive")
        options["timeout_seconds"] = timeout
    return tuple(sorted(options.items()))
