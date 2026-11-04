"""Provider registry. Multi-provider LLM dispatch.

Each provider client implements the same interface as ``AnthropicClient``:

    complete(system, messages, tools=None, budget=None, ...) -> LLMResponse
    complete_async(system, messages, tools=None, budget=None, ...) -> LLMResponse

Accepting Anthropic-format messages/tools and returning a
``maverick.llm.LLMResponse``. OpenAI/OpenRouter/Ollama/Gemini/Moonshot/
DeepSeek/xAI clients translate the format on the fly.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from typing import Any

# Each entry: (canonical name, list of accepted aliases).
# Aliases let users type the brand name they know (kimi → moonshot,
# grok → xai) without us redefining the canonical provider id.
_PROVIDER_ALIASES = {
    "anthropic":  ("claude",),
    "openai":     ("chatgpt", "gpt"),
    "moonshot":   ("kimi",),
    "xai":        ("grok",),
    "gemini":     ("google",),
    "deepseek":   (),
    "openrouter": (),
    "ollama":     ("local",),
    "tgi":        ("huggingface-tgi", "hf-tgi"),
    "vllm":       (),
    "azure":      ("azure-openai",),
    "bedrock":    ("aws-bedrock",),
    "vertex":     ("vertex-ai",),
    "openai_compatible": ("openai-compatible", "custom"),
    # ChatGPT/Codex subscription via the local Codex CLI (`codex exec`) --
    # NOT the metered OpenAI API (that's the `openai` provider above).
    "codex_cli":  ("codex-cli", "codex"),
}


def _canonical(name: str) -> str:
    """Map an alias to the canonical provider name."""
    lower = (name or "").strip().lower()
    if lower in _PROVIDER_ALIASES:
        return lower
    for canon, aliases in _PROVIDER_ALIASES.items():
        if lower in aliases:
            return canon
    return lower


def get_provider_client(
    name: str, api_key: str | None = None, base_url: str | None = None,
    default_headers: dict | None = None,
    environment: Mapping[str, str] | None = None,
    provider_options: Mapping[str, Any] | None = None,
) -> Any:
    """Lazy-import and instantiate the named provider client.

    ``base_url`` reaches the self-hosted / OpenAI-compatible clients (vllm,
    tgi, ollama, openai, openai_compatible), anthropic (for a proxy /
    gateway endpoint), azure / bedrock / vertex (whose clients use it as the
    endpoint, falling back to their env var / regional default when unset),
    AND the OpenAI-translated cloud vendors (openrouter, gemini, moonshot,
    deepseek, xai — each defaults to its vendor endpoint when unset) so a
    ``[providers.<name>] base_url`` in config actually configures the
    endpoint, instead of the client silently falling back to its env var /
    vendor / localhost default.

    ``default_headers`` (from ``[providers.<name>] default_headers``) is a
    data-residency / ZDR control: extra HTTP headers attached to every request
    so a compliance gateway can enforce region pinning / no-retention. Threaded
    to anthropic, openai, azure and bedrock. Other adapters explicitly reject
    nonempty headers before construction; they do not silently discard them.
    """
    canon = _canonical(name)
    from .configuration import canonical_headers, validate_fields
    if provider_options:
        if canon != "codex_cli" or set(provider_options) - {"binary", "sandbox_mode", "cwd", "timeout_seconds"}:
            raise ValueError(f"providers.{canon}.provider_options contains unsupported adapter options")
    headers = canonical_headers(default_headers)
    validate_fields(canon, {
        "api_key": api_key, "base_url": base_url, "default_headers": dict(headers),
        **dict(provider_options or {}),
    })
    default_headers = dict(headers) if headers else None
    extra = {"environment": dict(environment)} if environment is not None else {}
    if canon == "anthropic":
        from .anthropic_provider import AnthropicClient
        return AnthropicClient(api_key=api_key, base_url=base_url,
                               default_headers=default_headers, **extra)
    if canon == "openai":
        from .openai_provider import OpenAIClient
        return OpenAIClient(api_key=api_key, base_url=base_url,
                            default_headers=default_headers, **extra)
    if canon == "openrouter":
        from .openrouter_provider import OpenRouterClient
        return OpenRouterClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "ollama":
        from .ollama_provider import OllamaClient
        return OllamaClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "gemini":
        from .gemini_provider import GeminiClient
        return GeminiClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "moonshot":
        from .moonshot_provider import MoonshotClient
        return MoonshotClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "deepseek":
        from .deepseek_provider import DeepSeekClient
        return DeepSeekClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "xai":
        from .xai_provider import XaiClient
        return XaiClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "tgi":
        from .tgi_provider import TGIClient
        return TGIClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "vllm":
        from .vllm_provider import VLLMClient
        return VLLMClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "azure":
        from .azure_openai_provider import AzureOpenAIClient
        return AzureOpenAIClient(
            api_key=api_key,
            base_url=base_url,
            default_headers=default_headers,
            environment=environment,
        )
    if canon == "bedrock":
        from .bedrock_provider import BedrockClient
        # Native Anthropic Messages client: region, auth mode and
        # endpoint come from the same admitted environment snapshot.
        return BedrockClient(
            api_key=api_key,
            base_url=base_url,
            default_headers=default_headers,
            environment=environment,
        )
    if canon == "vertex":
        from .vertex_provider import VertexClient
        # Claude on Vertex AI: project, region and model come from the admitted
        # environment snapshot; authentication is Google ADC only (no api_key).
        return VertexClient(
            base_url=base_url,
            default_headers=default_headers,
            environment=environment,
        )
    if canon == "openai_compatible":
        from .openai_compatible_provider import OpenAICompatibleClient
        return OpenAICompatibleClient(api_key=api_key, base_url=base_url, **extra)
    if canon == "codex_cli":
        from .codex_cli_provider import CodexCLIClient
        if provider_options is not None:
            extra["provider_options"] = dict(provider_options)
        return CodexCLIClient(api_key=api_key, base_url=base_url, **extra)
    raise ValueError(
        f"unknown provider {name!r}. Available: "
        + ", ".join(KNOWN_PROVIDERS)
    )


KNOWN_PROVIDERS = (
    "anthropic", "openai", "moonshot", "xai", "gemini",
    "deepseek", "openrouter", "ollama", "tgi", "vllm",
    "azure", "bedrock", "vertex", "openai_compatible", "codex_cli",
)

# The pip package each provider's client imports at construction/call time.
# Everything OpenAI-translated needs ``openai``; anthropic, bedrock and vertex
# (the Anthropic SDK's Bedrock and Vertex clients; IAM and Google auth need
# boto3 / google-auth via their extras, checked at client construction) need
# ``anthropic``. codex_cli needs NO pip SDK -- it shells out to the Codex CLI
# binary (checked separately below).
_SDK_MODULE: dict[str, str] = {
    "anthropic": "anthropic",
    "bedrock": "anthropic",
    "vertex": "anthropic",
    **{p: "openai" for p in KNOWN_PROVIDERS
       if p not in ("anthropic", "bedrock", "vertex", "codex_cli")},
}

_SDK_HINT: dict[str, str] = {
    "openai": (
        "openai SDK not installed. From the reviewed checkout run: "
        "python -m pip install -e './packages/maverick-core[openai]'"
    ),
    "anthropic": (
        "anthropic SDK not installed. From the reviewed checkout run: "
        "python -m pip install -e ./packages/maverick-core"
    ),
}

GOOGLE_AUTH_HINT = (
    "Vertex AI needs google-auth for Google Application Default Credentials. "
    "From the reviewed checkout run: python -m pip install -e "
    "'./packages/maverick-core[vertex]'"
)


def google_auth_hint() -> str | None:
    """The install hint when google-auth is not importable, else ``None``.

    Lives here, not in ``vertex_provider``, so that ``missing_sdks`` can report
    it even when the anthropic SDK itself is missing. ``find_spec`` locates the
    packages without importing them, so the check is cheap and side-effect free.
    """
    import importlib.util

    try:
        present = (importlib.util.find_spec("google.auth") is not None
                   and importlib.util.find_spec("requests") is not None)
    except (ImportError, ValueError):
        present = False
    return None if present else GOOGLE_AUTH_HINT


def missing_sdks(model_specs) -> list[str]:
    """Actionable messages for provider SDKs the given model specs need but
    that aren't importable. Empty list == everything resolvable.

    Lets `maverick start` refuse BEFORE creating a goal row, so a missing SDK
    does not surface mid-run and orphan a failed $0 goal per attempt.
    find_spec locates a package without executing it, so this is cheap and
    side-effect free. Unknown providers are skipped (get_provider_client
    raises its own clearer error later).
    """
    import importlib.util

    msgs: list[str] = []
    seen: set[str] = set()
    for spec in model_specs or ():
        if not isinstance(spec, str) or not spec.strip():
            continue
        provider = _canonical(spec.split(":", 1)[0]) if ":" in spec else "anthropic"
        # codex_cli's "SDK" is the Codex CLI binary, not a pip package.
        if provider == "codex_cli" and provider not in seen:
            seen.add(provider)
            import shutil
            binary = "codex"
            try:
                from ..config import get_provider_config
                binary = str((get_provider_config("codex_cli") or {})
                             .get("binary") or binary)
            except Exception:  # fail open: never block start on a config probe
                pass
            if shutil.which(binary) is None:
                msgs.append(
                    f"Codex CLI binary {binary!r} not found (needed for the "
                    "codex_cli provider). Run: npm install -g @openai/codex"
                )
            continue
        # A pre-fetched AD token needs only the OpenAI SDK. The documented
        # DefaultAzureCredential path also needs azure-identity; report that
        # before starting a goal instead of failing on the first model call.
        if (
            provider == "azure"
            and os.environ.get("AZURE_OPENAI_AUTH", "").strip().lower()
            == "entra_id"
            and not os.environ.get("AZURE_OPENAI_AD_TOKEN", "").strip()
            and "azure.identity" not in seen
        ):
            seen.add("azure.identity")
            try:
                identity_present = (
                    importlib.util.find_spec("azure.identity") is not None
                )
            except ModuleNotFoundError:
                identity_present = False
            except Exception:
                identity_present = True
            if not identity_present:
                msgs.append(
                    "Azure Identity SDK not installed. From the reviewed "
                    "checkout run: python -m pip install -e "
                    "'./packages/maverick-core[azure]'"
                )
        # Vertex AI signs in with Google Application Default Credentials, which
        # need google-auth (the ``vertex`` extra) beside the anthropic SDK.
        if provider == "vertex" and "google.auth" not in seen:
            seen.add("google.auth")
            hint = google_auth_hint()
            if hint is not None:
                msgs.append(hint)
        mod = _SDK_MODULE.get(provider)
        if mod is None or mod in seen:
            continue
        seen.add(mod)
        try:
            present = importlib.util.find_spec(mod) is not None
        except Exception:
            present = True  # fail open: never block start on a probe error
        if not present:
            msgs.append(_SDK_HINT.get(mod, f"{mod} is not installed"))
    return msgs


def verify_release_runtime() -> None:
    """Prove the two SDK families shipped in full release artifacts import.

    Client construction is deliberately pointed at a loopback discard endpoint
    and makes no request. The OpenAI SDK backs OpenAI, OpenRouter, Ollama,
    Gemini, DeepSeek, xAI, Moonshot, TGI, vLLM, Azure token/key auth, Bedrock's
    compatible endpoint, and the generic OpenAI-compatible provider.
    """
    missing = missing_sdks(("anthropic:release-smoke", "openai:release-smoke"))
    if missing:
        raise RuntimeError("; ".join(missing))
    client = get_provider_client(
        "openai",
        api_key="release-smoke-not-a-real-key",  # pragma: allowlist secret
        base_url="http://127.0.0.1:9/v1",
    )
    if client is None:  # pragma: no cover - defensive contract
        raise RuntimeError("OpenAI-compatible provider client was not constructed")


__all__ = [
    "get_provider_client",
    "missing_sdks",
    "verify_release_runtime",
    "KNOWN_PROVIDERS",
]
