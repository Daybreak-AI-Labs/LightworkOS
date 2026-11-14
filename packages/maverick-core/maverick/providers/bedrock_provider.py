"""AWS Bedrock provider (native Anthropic Messages API).

Both Bedrock surfaces are driven through Anthropic's own SDK, so prompt
caching, adaptive/extended thinking, thinking-block signatures, tool_choice
and stop reasons behave exactly as on the Claude API. (Bedrock's
OpenAI-compatible endpoint with a hand-issued bearer would lose every one of
those.)

  endpoint = "mantle"  (default) Claude in Amazon Bedrock, Opus 4.7 and later:
             https://bedrock-mantle.{region}.api.aws/anthropic. Model ids carry
             the provider prefix: anthropic.claude-fable-5-1,
             anthropic.claude-opus-5, anthropic.claude-opus-4-8,
             anthropic.claude-opus-4-7, anthropic.claude-sonnet-5,
             anthropic.claude-haiku-4-5.
  endpoint = "legacy"  Claude on Amazon Bedrock, Opus 4.6 and earlier
             (InvokeModel, ARN-versioned ids such as
             global.anthropic.claude-opus-4-6-v1 or
             us.anthropic.claude-sonnet-4-5-20250929-v1:0).

Authentication (auth_mode):
  iam      (default) SigV4 from the standard AWS credential chain -- env keys,
           ~/.aws profiles, ECS/EKS task roles, IMDS -- the standard enterprise
           deployment. Needs boto3/botocore: the ``bedrock`` extra.
  api_key  A Bedrock bearer token (BEDROCK_API_KEY, or the SDK's own
           AWS_BEARER_TOKEN_BEDROCK) on the same native endpoint.

Config / env:
  [providers.bedrock] auth_mode = "iam" | "api_key"     (BEDROCK_AUTH_MODE)
  [providers.bedrock] endpoint  = "mantle" | "legacy"   (BEDROCK_ENDPOINT)
  [providers.bedrock] base_url  (optional override)
  AWS_REGION / AWS_DEFAULT_REGION (required); BEDROCK_MODEL_ID (default model)

Pricing: Bedrock is invoiced by AWS at its own rates, which are not in
Lightwork's verified rate card. ``budget.bedrock_rate_card_model_id`` maps a
Bedrock id onto the Claude API catalogue so planning estimates work; live
accounting under the default strict pricing refuses with an actionable
message (set ``[budget] strict_pricing=false`` to account at the estimate).
"""
from __future__ import annotations

import importlib.util
import os
from collections.abc import Mapping
from typing import Any

import anthropic

from ..budget import bedrock_rate_card_model_id
from .anthropic_provider import AnthropicClient

_AUTH_MODES = ("iam", "api_key")
_ENDPOINTS = ("mantle", "legacy")
_SDK_CLASSES = {
    "mantle": ("AnthropicBedrockMantle", "AsyncAnthropicBedrockMantle"),
    "legacy": ("AnthropicBedrock", "AsyncAnthropicBedrock"),
}


def _sdk_clients(endpoint: str) -> tuple[Any, Any]:
    sync_name, async_name = _SDK_CLASSES[endpoint]
    try:
        return getattr(anthropic, sync_name), getattr(anthropic, async_name)
    except AttributeError as exc:
        raise RuntimeError(
            f"the installed anthropic SDK has no {sync_name}; upgrade it "
            "(python -m pip install -U anthropic) to use Bedrock natively"
        ) from exc


def _first(env: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return None


class BedrockClient(AnthropicClient):
    """Claude on AWS Bedrock through the Anthropic SDK's Bedrock clients."""

    DEFAULT_MODEL = "anthropic.claude-sonnet-5"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        default_headers: dict | None = None,
        *,
        environment: Mapping[str, str] | None = None,
    ):
        # The dispatcher hands over an admitted environment snapshot so a
        # region/auth rotation cannot pair old and new values; direct callers
        # get the live environment.
        env = dict(os.environ if environment is None else environment)

        region = _first(env, "AWS_REGION", "AWS_DEFAULT_REGION")
        if not region:
            raise RuntimeError("Bedrock requires AWS_REGION (e.g. us-east-1).")

        endpoint = (_first(env, "BEDROCK_ENDPOINT") or "mantle").lower()
        if endpoint not in _ENDPOINTS:
            raise ValueError(
                f"[providers.bedrock] endpoint must be one of {_ENDPOINTS}, not {endpoint!r}"
            )

        key = (api_key or _first(env, "BEDROCK_API_KEY", "AWS_BEARER_TOKEN_BEDROCK") or "").strip() or None
        mode = (_first(env, "BEDROCK_AUTH_MODE") or ("api_key" if key else "iam")).lower()
        if mode not in _AUTH_MODES:
            raise ValueError(
                f"[providers.bedrock] auth_mode must be one of {_AUTH_MODES}, not {mode!r}"
            )
        if mode == "api_key" and not key:
            raise RuntimeError(
                "Bedrock auth_mode=api_key needs BEDROCK_API_KEY (a Bedrock bearer "
                "token); or use auth_mode=iam to sign with AWS credentials."
            )
        if mode == "iam":
            key = None
            if importlib.util.find_spec("boto3") is None or importlib.util.find_spec("botocore") is None:
                raise RuntimeError(
                    "Bedrock IAM (SigV4) auth needs boto3/botocore. From the reviewed "
                    "checkout run: python -m pip install -e './packages/maverick-core"
                    "[bedrock]' -- or set [providers.bedrock] auth_mode = \"api_key\" "
                    "with BEDROCK_API_KEY."
                )

        from .base import sdk_http_timeout

        kw: dict[str, Any] = {"aws_region": region, "max_retries": 0}
        if key:
            kw["api_key"] = key
        endpoint_env = "ANTHROPIC_BEDROCK_MANTLE_BASE_URL" if endpoint == "mantle" else "ANTHROPIC_BEDROCK_BASE_URL"
        default_url = f"https://bedrock-mantle.{region}.api.aws/anthropic" if endpoint == "mantle" else f"https://bedrock-runtime.{region}.amazonaws.com"
        kw["base_url"] = base_url or _first(env, endpoint_env) or default_url
        if default_headers:
            kw["default_headers"] = dict(default_headers)
        timeout = sdk_http_timeout(anthropic, environment=environment)
        if timeout is not None:
            kw["timeout"] = timeout
        sync_cls, async_cls = _sdk_clients(endpoint)
        self.client = sync_cls(**kw)
        self.aclient = None
        # SDKs have their own ambient bearer-token fallback. Admission cannot
        # claim IAM while the SDK selected a different authority. Refuse before
        # any request, rather than mutating private signing state or env vars.
        def confirm(client):
            if mode == "iam":
                if not hasattr(client, "api_key") or client.api_key is not None or (
                    endpoint == "mantle" and getattr(client, "_use_sigv4", None) is not True
                ):
                    raise RuntimeError(
                        "Bedrock IAM configuration conflicts with the installed SDK's authentication; "
                        "remove ambient Bedrock bearer tokens or explicitly configure auth_mode=api_key"
                    )
        try:
            confirm(self.client)
            self.aclient = async_cls(**kw)
            confirm(self.aclient)
        except BaseException as error:
            import inspect

            from ..owned_process import run_sync
            for client in (self.client, self.aclient):
                close = getattr(client, "close", None)
                if close is not None:
                    try:
                        result = close()
                        if inspect.isawaitable(result):
                            run_sync(lambda owned=result: owned)
                    except BaseException:
                        error.cleanup_incomplete = True
            raise
        self.auth_mode = mode
        self.endpoint = endpoint
        self.region = region
        self.base_url = str(getattr(self.client, "base_url", "") or "")
        model = _first(env, "BEDROCK_MODEL_ID")
        if model:
            self.DEFAULT_MODEL = model

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
        # and put the Bedrock wire id back on the request.
        wire = model or self.DEFAULT_MODEL
        canonical = bedrock_rate_card_model_id(wire) or wire
        kwargs = super()._build_request(
            system, messages, tools, max_tokens, thinking_budget, canonical,
            effort, tool_choice=tool_choice,
        )
        kwargs["model"] = wire
        # Fast mode is a first-party-only feature; never send its beta fields.
        kwargs.pop("speed", None)
        kwargs.pop("betas", None)
        return kwargs

    def prewarm(self, system: str, tools: list[dict] | None = None,
                model: str | None = None, *, budget=None) -> bool:
        """Gate the warm on the canonical id's cache minimum.

        The base looks the minimum up by the Bedrock wire id, which no table
        entry matches, so a 2,048/4,096-minimum model was warmed (and billed)
        with a prefix too short to cache.
        """
        from .anthropic_provider import _min_cache_tokens

        wire = model or self.DEFAULT_MODEL
        canonical = bedrock_rate_card_model_id(wire) or wire
        est_tokens = (len(system or "") + sum(len(str(t)) for t in tools or [])) / 4
        if est_tokens < _min_cache_tokens(canonical):
            return False
        return super().prewarm(system, tools, model, budget=budget)


__all__ = ["BedrockClient"]
