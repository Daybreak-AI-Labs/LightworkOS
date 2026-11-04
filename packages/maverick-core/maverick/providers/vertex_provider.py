"""Claude on Google Cloud Vertex AI (native Anthropic Messages API).

Driven through Anthropic's own SDK (``AnthropicVertex``), so prompt caching,
adaptive/extended thinking, thinking-block signatures, tool_choice and stop
reasons behave exactly as on the Claude API -- the same contract the Bedrock
adapter keeps (see ``bedrock_provider``).

Model ids are the Vertex AI ids shown in the Vertex AI Model Garden for your
project and region, in the ``name@version`` form (the SDK's own Vertex tests
use ``claude-haiku-4-5@20251001``). Lightwork ships no Vertex model id: set
``[providers.vertex] model_id`` and every route names the id it calls.

Authentication is Google Application Default Credentials only, loaded by the
SDK on the first request: ``GOOGLE_APPLICATION_CREDENTIALS`` (a service-account
or external-account file), ``gcloud auth application-default login``, or
workload identity / the metadata server. There is no API-key path. The SDK's
``vertex`` extra provides google-auth: the ``vertex`` extra of maverick-core.

Config / env (the configuration table wins; the environment fills what it leaves empty):
  [providers.vertex] project_id  (ANTHROPIC_VERTEX_PROJECT_ID, then GOOGLE_CLOUD_PROJECT)
  [providers.vertex] region      (CLOUD_ML_REGION, the SDK's own variable)
  [providers.vertex] model_id    (VERTEX_MODEL_ID)
  [providers.vertex] base_url    (ANTHROPIC_VERTEX_BASE_URL; optional override)

The project and region are part of the request URL (the region is part of the
host name), so both are validated before any client exists.

The SDK reads the project from its own argument, not from Google credentials,
before it loads them. An explicit project is therefore required.

Pricing: Google Cloud invoices Vertex AI at its own rates, which are not in
Lightwork's verified rate card. ``budget.vertex_rate_card_model_id`` maps a
Vertex Claude id onto the Claude API catalogue so planning estimates work; live
accounting under the default strict pricing refuses with an actionable message
(set ``[budget] strict_pricing=false`` to account at the estimate).
"""
from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Any

import anthropic

from ..budget import Budget, vertex_rate_card_model_id
from . import google_auth_hint
from .anthropic_provider import AnthropicClient

# Project ids are path segments and the region is a host-name label, so both
# are constrained to characters that cannot change the URL they land in.
_PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:_-]{0,127}")
_REGION = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
# The model id is a path segment of the request URL (models/{model}:rawPredict), so
# it is the name@version form exactly: no slash, colon or query character, and one @.
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}@[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_MODEL_ID_HINT = (
    "the Vertex AI model id must look like claude-haiku-4-5@20251001, as shown in the "
    "Vertex AI Model Garden"
)


def valid_model_id(model: str | None) -> bool:
    """Whether ``model`` is a Vertex AI name@version id that may enter a request URL.

    Every path that puts a model id on the wire checks it here first: the
    constructor (a configured default), the request builder and the cache
    prewarm. The dashboard probe uses it as well.
    """
    return _MODEL_ID.fullmatch(model or "") is not None


def _sdk_clients() -> tuple[Any, Any]:
    try:
        return anthropic.AnthropicVertex, anthropic.AsyncAnthropicVertex
    except AttributeError as exc:
        raise RuntimeError(
            "the installed anthropic SDK has no AnthropicVertex; upgrade it "
            "(python -m pip install -U 'anthropic[vertex]') to use Vertex AI"
        ) from exc


def _first(env: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return None


def _default_base_url(region: str) -> str:
    """The endpoint the SDK derives from its region argument, by the same rules."""
    if region == "global":
        return "https://aiplatform.googleapis.com/v1"
    if region in ("us", "eu"):
        return f"https://aiplatform.{region}.rep.googleapis.com/v1"
    return f"https://{region}-aiplatform.googleapis.com/v1"


class VertexClient(AnthropicClient):
    """Claude on Google Cloud Vertex AI through the Anthropic SDK's Vertex clients."""

    # No Vertex model id is shipped (kernel rule 2): the operator names one.
    DEFAULT_MODEL = ""

    def __init__(
        self,
        base_url: str | None = None,
        default_headers: dict | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ):
        # The dispatcher hands over an admitted environment snapshot so a
        # project/region rotation cannot pair old and new values; direct
        # callers get the live environment.
        env = dict(os.environ if environment is None else environment)

        project = _first(env, "ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_CLOUD_PROJECT")
        if not project:
            raise RuntimeError(
                "Vertex AI requires a Google Cloud project id: set [providers.vertex] "
                "project_id, or GOOGLE_CLOUD_PROJECT"
            )
        if not _PROJECT_ID.fullmatch(project):
            raise ValueError("the Vertex AI project id is not a valid Google Cloud project id")
        region = _first(env, "CLOUD_ML_REGION")
        if not region:
            raise RuntimeError(
                "Vertex AI requires a region: set [providers.vertex] region, or "
                "CLOUD_ML_REGION (for example us-east5)"
            )
        if not _REGION.fullmatch(region):
            raise ValueError("the Vertex AI region is not a valid region name (lowercase, for example us-east5)")
        default_model = _first(env, "VERTEX_MODEL_ID") or ""
        if default_model and not valid_model_id(default_model):
            raise ValueError(_MODEL_ID_HINT)

        hint = google_auth_hint()
        if hint is not None:
            raise RuntimeError(hint)

        from .base import sdk_http_timeout

        kw: dict[str, Any] = {
            "project_id": project,
            "region": region,
            "max_retries": 0,
            "base_url": base_url or _first(env, "ANTHROPIC_VERTEX_BASE_URL") or _default_base_url(region),
        }
        if default_headers:
            kw["default_headers"] = dict(default_headers)
        timeout = sdk_http_timeout(anthropic, environment=environment)
        if timeout is not None:
            kw["timeout"] = timeout
        sync_cls, async_cls = _sdk_clients()
        self.client = sync_cls(**kw)
        self.aclient = async_cls(**kw)
        self.project_id = project
        self.region = region
        self.base_url = str(getattr(self.client, "base_url", "") or "")
        self.DEFAULT_MODEL = default_model

    def prewarm(
        self,
        system: str,
        tools: list[dict] | None = None,
        model: str | None = None,
        *,
        budget: Budget | None = None,
    ) -> bool:
        """Prompt-cache warm for a checked Vertex model id only.

        The base class sends the id as-is, so it is checked here first. A
        refused id returns ``False`` without a request, like any other warm
        that cannot run (the base never raises into the caller either).
        """
        wire = model or self.DEFAULT_MODEL
        if not valid_model_id(wire):
            return False
        return super().prewarm(system, tools, wire, budget=budget)

    def _build_request(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None,
        max_tokens: int,
        thinking_budget: int | None,
        model: str | None,
        effort: str | None = None,
        tool_choice: dict | None = None,
    ) -> dict[str, Any]:
        # The Anthropic request builder keys every model-specific decision
        # (adaptive vs manual thinking, cache minimums, forced tool_choice
        # support) off the Claude API id, so build against the canonical id
        # and put the Vertex wire id back on the request.
        wire = model or self.DEFAULT_MODEL
        if not wire:
            raise RuntimeError(
                "Vertex AI needs a model id: set [providers.vertex] model_id to the id "
                "shown in the Vertex AI Model Garden"
            )
        if not valid_model_id(wire):
            raise ValueError(_MODEL_ID_HINT)
        canonical = vertex_rate_card_model_id(wire) or wire
        kwargs = super()._build_request(
            system, messages, tools, max_tokens, thinking_budget, canonical,
            effort, tool_choice=tool_choice,
        )
        kwargs["model"] = wire
        # Fast mode is a first-party-only feature; never send its beta fields.
        kwargs.pop("speed", None)
        kwargs.pop("betas", None)
        return kwargs


__all__ = ["VertexClient", "google_auth_hint", "valid_model_id"]
