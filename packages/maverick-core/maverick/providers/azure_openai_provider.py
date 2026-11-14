"""Azure OpenAI provider.

Azure's Chat Completions API is OpenAI-compatible at the *wire* level,
but it differs from vanilla OpenAI in two ways the plain ``OpenAI``
client cannot express:

  1. auth is either the ``api-key`` header or a Microsoft Entra bearer
  2. an ``api-version`` query param is required on every request, and
     requests route to a *deployment* (not a model id)

The OpenAI SDK ships a dedicated ``AzureOpenAI`` / ``AsyncAzureOpenAI``
client that handles both. Passing an Azure URL with ``?api-version=``
baked into ``base_url`` to the plain ``OpenAI`` client does NOT work:
the SDK's URL join drops the query string and mangles the deployment
path segment, and it sends a Bearer header Azure ignores. So we build
the Azure clients directly here rather than reusing
``OpenAIClient.__init__``.

Env:
  - AZURE_OPENAI_ENDPOINT  (e.g. https://my-res.openai.azure.com)
  - AZURE_OPENAI_API_KEY (API-key authentication)
  - AZURE_OPENAI_AD_TOKEN (optional pre-fetched Microsoft Entra token)
  - AZURE_OPENAI_AUTH (``api_key`` or ``entra_id``; optional when one
    unambiguous credential is already present)
  - AZURE_OPENAI_TOKEN_SCOPE (DefaultAzureCredential scope; default
    ``https://cognitiveservices.azure.com/.default``)
  - AZURE_OPENAI_DEPLOYMENT (the deployment name; used as the model)
  - AZURE_OPENAI_API_VERSION (default 2024-10-21)

With ``AZURE_OPENAI_AUTH=entra_id`` and no pre-fetched token, the provider
uses Azure Identity's documented ``DefaultAzureCredential`` +
``get_bearer_token_provider`` path. Credential discovery is never attempted
implicitly: selecting Entra authentication is an operator decision.
"""
from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from functools import partial

from .openai_provider import OpenAIClient

_DEFAULT_ENTRA_SCOPE = "https://cognitiveservices.azure.com/.default"
_AUTH_MODES = frozenset({"api_key", "entra_id"})


def _azure_auth(
    api_key: str | None,
    azure_ad_token_provider: Callable[[], str] | None,
    *,
    environment: Mapping[str, str] | None = None,
) -> tuple[dict[str, object], object | None, str]:
    """Resolve exactly one Azure authentication mechanism."""
    env = os.environ if environment is None else environment
    raw_key = api_key if api_key is not None else env.get("AZURE_OPENAI_API_KEY")
    key = raw_key.strip() if raw_key is not None else ""
    token = env.get("AZURE_OPENAI_AD_TOKEN", "").strip()
    mode = env.get("AZURE_OPENAI_AUTH", "").strip().lower()
    if mode and mode not in _AUTH_MODES:
        raise RuntimeError(
            "AZURE_OPENAI_AUTH must be either 'api_key' or 'entra_id'."
        )
    if azure_ad_token_provider is not None and not callable(azure_ad_token_provider):
        raise TypeError("azure_ad_token_provider must be callable")

    selected = sum(bool(value) for value in (key, token, azure_ad_token_provider))
    if selected > 1:
        raise RuntimeError(
            "Azure OpenAI authentication is ambiguous; configure exactly one "
            "of AZURE_OPENAI_API_KEY, AZURE_OPENAI_AD_TOKEN, or "
            "azure_ad_token_provider."
        )

    if mode == "api_key":
        if token or azure_ad_token_provider is not None:
            raise RuntimeError(
                "AZURE_OPENAI_AUTH=api_key cannot be combined with Microsoft "
                "Entra credentials."
            )
        if not key:
            raise RuntimeError(
                "AZURE_OPENAI_AUTH=api_key requires AZURE_OPENAI_API_KEY."
            )
        return {"api_key": key}, None, "api_key"

    if mode == "entra_id" and key:
        raise RuntimeError(
            "AZURE_OPENAI_AUTH=entra_id cannot be combined with "
            "AZURE_OPENAI_API_KEY."
        )
    if token:
        return {"azure_ad_token": token}, None, "entra_id"
    if azure_ad_token_provider is not None:
        return {
            "azure_ad_token_provider": azure_ad_token_provider,
        }, None, "entra_id"
    if mode == "entra_id":
        try:
            from azure.identity import (
                DefaultAzureCredential,
                get_bearer_token_provider,
            )
        except ImportError as e:
            raise ImportError(
                "AZURE_OPENAI_AUTH=entra_id requires Azure Identity. "
                "Install it from a reviewed checkout with: python -m pip "
                "install -e './packages/maverick-core[azure]'"
            ) from e
        credential = DefaultAzureCredential()
        scope = (
            env.get("AZURE_OPENAI_TOKEN_SCOPE", _DEFAULT_ENTRA_SCOPE).strip()
            or _DEFAULT_ENTRA_SCOPE
        )
        provider = get_bearer_token_provider(credential, scope)
        return {"azure_ad_token_provider": provider}, credential, "entra_id"

    if key:
        return {"api_key": key}, None, "api_key"
    raise RuntimeError(
        "Azure OpenAI requires authentication: set AZURE_OPENAI_API_KEY, "
        "AZURE_OPENAI_AD_TOKEN, or select the Azure Identity path with "
        "AZURE_OPENAI_AUTH=entra_id."
    )


class AzureOpenAIClient(OpenAIClient):
    DEFAULT_MODEL = "azure-deployment"

    @staticmethod
    def _wants_max_completion(model: str, *, environment: Mapping[str, str] | None = None) -> bool:
        """Whether to send ``max_completion_tokens`` instead of ``max_tokens``.

        Azure routes to a free-form *deployment* name, so the base class's
        prefix-match on the model id can't tell an o-series / gpt-5 deployment
        (which rejects ``max_tokens`` with a 400) from a gpt-4-turbo one. Let
        the operator force it via ``AZURE_OPENAI_USE_MAX_COMPLETION``; otherwise
        fall back to the base name heuristic (works when the deployment is named
        after the model).
        """
        env = os.environ if environment is None else environment
        override = env.get("AZURE_OPENAI_USE_MAX_COMPLETION")
        if override is not None and override.strip():
            return override.strip().lower() in ("1", "true", "yes", "on")
        return OpenAIClient._wants_max_completion(model)

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        azure_ad_token_provider: Callable[[], str] | None = None,
        default_headers: dict | None = None,
        environment: Mapping[str, str] | None = None,
    ):
        try:
            import openai
            from openai import AsyncAzureOpenAI, AzureOpenAI
        except ImportError as e:
            raise ImportError(
                "openai SDK not installed. Run: python -m pip install -e './packages/maverick-core[openai]'"
            ) from e
        env = dict(os.environ if environment is None else environment)
        # Preserve the class-level compatibility helper while bound clients
        # retain the environment that authorized their request configuration.
        self._wants_max_completion = partial(type(self)._wants_max_completion, environment=env)
        endpoint = (
            base_url
            or env.get("AZURE_OPENAI_ENDPOINT")
            or ""
        ).rstrip("/")
        deployment = env.get("AZURE_OPENAI_DEPLOYMENT", "").strip()
        version = env.get("AZURE_OPENAI_API_VERSION", "").strip() or "2024-10-21"
        if not endpoint or not deployment:
            raise RuntimeError(
                "Azure OpenAI requires AZURE_OPENAI_ENDPOINT + "
                "AZURE_OPENAI_DEPLOYMENT."
            )
        auth, credential, auth_mode = _azure_auth(
            api_key, azure_ad_token_provider, environment=env,
        )
        # Build the dedicated Azure clients directly — they send the selected
        # API-key/Entra header + `api-version` query + route to the
        # deployment. We intentionally do NOT call super().__init__:
        # it would construct a plain OpenAI client that drops the
        # api-version query and mangles the deployment path.
        self.endpoint = endpoint
        self.deployment = deployment
        self.api_version = version
        self.auth_mode = auth_mode
        # Keep DefaultAzureCredential alive alongside the SDK clients. It is
        # None for API-key, static-token, and caller-supplied-provider paths.
        self._azure_credential = credential
        # Apply the configured HTTP timeout (the base OpenAIClient does this;
        # we bypass it here, so wire it in manually or Azure calls can hang).
        from .base import sdk_http_timeout
        _timeout = sdk_http_timeout(openai, environment=environment)
        # Non-streamed calls size their read timeout from the same settings.
        self._timeout_environment = environment
        _extra = {"timeout": _timeout} if _timeout is not None else {}
        # OPENAI_ORG_ID / OPENAI_PROJECT_ID identify an OpenAI account and are
        # never sent to Azure. Empty sentinels block the SDK's own env read.
        if environment is not None:
            _extra.update(organization="", project="")
        if default_headers:
            _extra["default_headers"] = dict(default_headers)
        # ``complete`` / ``complete_async`` are inherited from OpenAIClient,
        # whose bounded Lightwork retry layer is the sole retry authority.
        self._sync = AzureOpenAI(
            azure_endpoint=endpoint,
            api_version=version,
            azure_deployment=deployment,
            max_retries=0,
            **auth,
            **_extra,
        )
        self._async = AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            api_version=version,
            azure_deployment=deployment,
            max_retries=0,
            **auth,
            **_extra,
        )
        for client in (self._sync, self._async):
            if client is not None:
                client.organization = None
                client.project = None
        # The deployment name is what Azure routes on; expose it as the
        # default model so the LLM facade's model id is harmless.
        self.DEFAULT_MODEL = deployment
