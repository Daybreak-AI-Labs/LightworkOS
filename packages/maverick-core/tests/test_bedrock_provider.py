"""Bedrock through the Anthropic SDK's native clients.

The adapter was bearer-only and subclassed OpenAIClient, so Claude on Bedrock
lost prompt caching, adaptive thinking, thinking signatures and tool_choice,
had no IAM path for the standard EKS/ECS task-role deployment, and its ids
were never in the rate card. It now builds on AnthropicClient with the SDK's
Bedrock clients (IAM/SigV4 by default, bearer on request), canonicalises the
Bedrock id for every model-keyed decision, and maps ids onto the Claude API
catalogue for planning estimates.
"""
from __future__ import annotations

import importlib.util

import anthropic
import pytest
from maverick.budget import (
    UnpricedModelError,
    _lookup_price,
    bedrock_rate_card_model_id,
)


class _FakeSDKClient:
    instances: list = []

    def __init__(self, **kw):
        self.kw = kw
        self.api_key = kw.get("api_key")
        self._use_sigv4 = self.api_key is None
        self.base_url = kw.get("base_url") or f"https://fake-{type(self).__name__}/{kw.get('aws_region')}"
        type(self).instances.append(self)


class _Mantle(_FakeSDKClient):
    instances: list = []


class _AsyncMantle(_FakeSDKClient):
    instances: list = []


class _Legacy(_FakeSDKClient):
    instances: list = []


class _AsyncLegacy(_FakeSDKClient):
    instances: list = []


@pytest.fixture
def fake_sdk(monkeypatch):
    for cls in (_Mantle, _AsyncMantle, _Legacy, _AsyncLegacy):
        cls.instances = []
    monkeypatch.setattr(anthropic, "AnthropicBedrockMantle", _Mantle, raising=False)
    monkeypatch.setattr(anthropic, "AsyncAnthropicBedrockMantle", _AsyncMantle, raising=False)
    monkeypatch.setattr(anthropic, "AnthropicBedrock", _Legacy, raising=False)
    monkeypatch.setattr(anthropic, "AsyncAnthropicBedrock", _AsyncLegacy, raising=False)
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION", "BEDROCK_API_KEY",
                 "AWS_BEARER_TOKEN_BEDROCK", "BEDROCK_AUTH_MODE", "BEDROCK_ENDPOINT",
                 "BEDROCK_MODEL_ID"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_REGION", "eu-central-1")


def _pretend_boto3(monkeypatch, present: bool):
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        if name in ("boto3", "botocore"):
            return object() if present else None
        return real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", fake)


def test_default_is_iam_on_the_native_endpoint(fake_sdk, monkeypatch):
    _pretend_boto3(monkeypatch, True)
    from maverick.providers.bedrock_provider import BedrockClient

    c = BedrockClient()
    assert c.auth_mode == "iam" and c.endpoint == "mantle"
    assert isinstance(c.client, _Mantle) and isinstance(c.aclient, _AsyncMantle)
    assert c.client.kw["aws_region"] == "eu-central-1"
    assert "api_key" not in c.client.kw               # SigV4 via the AWS chain
    assert c.client.kw["max_retries"] == 0
    assert c.DEFAULT_MODEL == "anthropic.claude-sonnet-5"


def test_iam_without_boto3_fails_with_the_extra_named(fake_sdk, monkeypatch):
    _pretend_boto3(monkeypatch, False)
    from maverick.providers.bedrock_provider import BedrockClient

    with pytest.raises(RuntimeError, match=r"maverick-core\[bedrock\]"):
        BedrockClient()


def test_bearer_token_selects_api_key_auth_without_boto3(fake_sdk, monkeypatch):
    _pretend_boto3(monkeypatch, False)
    monkeypatch.setenv("BEDROCK_API_KEY", "  bearer-token \n")  # pragma: allowlist secret
    from maverick.providers.bedrock_provider import BedrockClient

    c = BedrockClient()
    assert c.auth_mode == "api_key"
    assert c.client.kw["api_key"] == "bearer-token"  # pragma: allowlist secret


def test_explicit_api_key_mode_without_a_token_fails_closed(fake_sdk, monkeypatch):
    monkeypatch.setenv("BEDROCK_AUTH_MODE", "api_key")
    from maverick.providers.bedrock_provider import BedrockClient

    with pytest.raises(RuntimeError, match="BEDROCK_API_KEY"):
        BedrockClient()


def test_admitted_environment_snapshot_wins_over_the_process_env(fake_sdk, monkeypatch):
    _pretend_boto3(monkeypatch, True)
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    from maverick.providers.bedrock_provider import BedrockClient

    c = BedrockClient(environment={"AWS_REGION": "ap-northeast-1", "BEDROCK_ENDPOINT": "legacy",
                                   "BEDROCK_MODEL_ID": "global.anthropic.claude-opus-4-6-v1"})
    assert c.region == "ap-northeast-1" and c.endpoint == "legacy"
    assert isinstance(c.client, _Legacy) and isinstance(c.aclient, _AsyncLegacy)
    assert c.DEFAULT_MODEL == "global.anthropic.claude-opus-4-6-v1"


def test_unknown_endpoint_or_auth_mode_is_rejected(fake_sdk, monkeypatch):
    from maverick.providers.bedrock_provider import BedrockClient

    monkeypatch.setenv("BEDROCK_ENDPOINT", "converse")
    with pytest.raises(ValueError, match="endpoint"):
        BedrockClient()
    monkeypatch.delenv("BEDROCK_ENDPOINT")
    monkeypatch.setenv("BEDROCK_AUTH_MODE", "sso")
    with pytest.raises(ValueError, match="auth_mode"):
        BedrockClient()


def test_requests_are_built_against_the_canonical_id(fake_sdk, monkeypatch):
    _pretend_boto3(monkeypatch, True)
    from maverick.providers.bedrock_provider import BedrockClient

    c = BedrockClient()
    kw = c._build_request("sys", [{"role": "user", "content": "hi"}], None, 100, None,
                          "anthropic.claude-opus-4-8")
    assert kw["model"] == "anthropic.claude-opus-4-8"          # wire id restored
    assert kw["thinking"] == {"type": "adaptive"}               # Opus 4.8 rule applied
    assert "speed" not in kw and "betas" not in kw
    kw = c._build_request("sys", [{"role": "user", "content": "hi"}],
                          [{"name": "t", "description": "d", "input_schema": {"type": "object"}}],
                          100, None, "anthropic.claude-fable-5-1",
                          tool_choice={"type": "any"})
    assert kw["model"] == "anthropic.claude-fable-5-1"
    assert kw["tool_choice"] == {"type": "auto"}                # Fable clamp applied


@pytest.mark.parametrize(
    ("bedrock_id", "expected"),
    [
        ("anthropic.claude-fable-5-1", "claude-fable-5-1"),
        ("anthropic.claude-opus-5", "claude-opus-5"),
        ("bedrock:anthropic.claude-sonnet-5", "claude-sonnet-5"),
        ("global.anthropic.claude-opus-4-6-v1", "claude-opus-4-6"),
        ("us.anthropic.claude-sonnet-4-5-20250929-v1:0", "claude-sonnet-4-5"),
        ("anthropic.claude-haiku-4-5-20251001-v1:0", "claude-haiku-4-5"),
        ("eu.anthropic.claude-sonnet-4-6", "claude-sonnet-4-6"),
        ("mistral.mistral-large-2407-v1:0", None),
        ("bedrock", None),
        ("", None),
    ],
)
def test_bedrock_ids_map_onto_the_claude_catalogue(bedrock_id, expected):
    assert bedrock_rate_card_model_id(bedrock_id) == expected


def test_bedrock_pricing_is_an_estimate_never_a_bill(monkeypatch):
    monkeypatch.delenv("MAVERICK_STRICT_PRICING", raising=False)
    opus5 = _lookup_price("claude-opus-5", estimate_only=True)
    assert _lookup_price("bedrock:anthropic.claude-opus-5", estimate_only=True) == opus5
    assert _lookup_price("anthropic.claude-opus-5", estimate_only=True) == opus5
    sonnet45 = _lookup_price("claude-sonnet-4-5", estimate_only=True)
    assert _lookup_price("us.anthropic.claude-sonnet-4-5-20250929-v1:0", estimate_only=True) == sonnet45
    with pytest.raises(UnpricedModelError, match="strict_pricing=false"):
        _lookup_price("bedrock:anthropic.claude-opus-5", estimate_only=False)
    # Non-Anthropic Bedrock ids and the bare placeholder get no mapping: strict
    # accounting refuses them exactly as before.
    with pytest.raises(UnpricedModelError):
        _lookup_price("bedrock:mistral.mistral-large-2407-v1:0")
    with pytest.raises(UnpricedModelError):
        _lookup_price("bedrock:bedrock")


def test_iam_config_counts_as_a_configured_provider(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"providers": {"bedrock": {"auth_mode": "iam"}}})
    for name in list(config.PROVIDER_CREDENTIAL_ENV_VARS) + list(config.PROVIDER_BASE_URL_ENV_VARS):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("maverick.providers.codex_cli_provider._auth_file_present", lambda: False)
    assert config.any_provider_configured() is True
    monkeypatch.setattr(config, "load_config", lambda: {"providers": {"bedrock": {}}})
    assert config.any_provider_configured() is False


def test_dispatcher_hands_bedrock_the_admitted_snapshot(fake_sdk, monkeypatch):
    _pretend_boto3(monkeypatch, True)
    from maverick.llm import LLM

    monkeypatch.setenv("AWS_REGION", "us-east-2")
    monkeypatch.setattr("maverick.config.get_provider_config",
                        lambda provider: {"auth_mode": "iam", "endpoint": "legacy"}, raising=False)
    llm = LLM(model="bedrock:global.anthropic.claude-opus-4-6-v1")
    client = llm._get_client("bedrock")
    assert client.region == "us-east-2"
    assert client.endpoint == "legacy" and client.auth_mode == "iam"


def test_bedrock_requires_region(monkeypatch):
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    from maverick.providers.bedrock_provider import BedrockClient
    try:
        BedrockClient()
    except RuntimeError as e:
        assert "AWS_REGION" in str(e)
        return
    raise AssertionError("expected RuntimeError")


def test_bedrock_builds_url(monkeypatch):
    # The native Messages endpoint (Claude in Amazon Bedrock), not the
    # OpenAI-compatible one; a bearer token selects api_key auth.
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("BEDROCK_API_KEY", "k")
    monkeypatch.delenv("BEDROCK_AUTH_MODE", raising=False)
    monkeypatch.delenv("BEDROCK_ENDPOINT", raising=False)
    from maverick.providers.bedrock_provider import BedrockClient
    c = BedrockClient()
    assert "bedrock-mantle.us-east-1.api.aws" in c.base_url
    assert "/openai/" not in c.base_url
    assert c.auth_mode == "api_key" and c.endpoint == "mantle"
