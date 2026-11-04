"""Provider variables a test session must not inherit from its host.

``maverick.config.any_provider_configured`` treats any of these as "an AI
provider is configured". The repo-root ``conftest.py`` removes the host's
values once at session start so the suite sees a fresh install; a test that
needs a provider sets its own with ``monkeypatch`` afterward. The list is kept
by hand rather than imported from ``maverick.config`` because the root
conftest must not import the kernel before it has redirected HOME;
``packages/maverick-core/tests/test_provider_env_isolation.py`` pins it as a
superset of the config tuples so a new provider variable cannot slip past.
"""
from __future__ import annotations

from collections.abc import MutableMapping

HOST_PROVIDER_ENV_VARS: tuple[str, ...] = (
    # maverick.config.PROVIDER_CREDENTIAL_ENV_VARS
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY", "MOONSHOT_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY",
    "GROK_API_KEY", "TGI_API_KEY", "VLLM_API_KEY", "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_AD_TOKEN", "BEDROCK_API_KEY", "OPENAI_COMPATIBLE_API_KEY",
    "CODEX_ACCESS_TOKEN",
    # maverick.config.PROVIDER_BASE_URL_ENV_VARS
    "ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "MOONSHOT_BASE_URL", "DEEPSEEK_BASE_URL",
    "XAI_BASE_URL", "TGI_BASE_URL", "VLLM_BASE_URL", "AZURE_OPENAI_ENDPOINT",
    "OPENAI_COMPATIBLE_BASE_URL",
    # The Codex CLI state directory. A host login there counts as a configured
    # provider (providers.codex_cli_provider._auth_file_present) even with HOME
    # redirected, because CODEX_HOME wins over ~/.codex.
    "CODEX_HOME",
)


def scrub_host_provider_env(environ: MutableMapping[str, str]) -> list[str]:
    """Remove every host-provided provider variable; return the names removed."""
    removed = [name for name in HOST_PROVIDER_ENV_VARS if name in environ]
    for name in removed:
        del environ[name]
    return removed
