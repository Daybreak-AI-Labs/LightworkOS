"""Claude on Google Cloud Vertex AI through the Anthropic SDK's AnthropicVertex.

Mirrors test_bedrock_provider.py: the SDK clients are replaced by fakes, so no
test needs network access, Google credentials or a real project. The request
contract is the one AnthropicClient already enforces for the Claude API; the
Vertex request must equal it except for the wire model id.

Test model ids are opaque strings to the request builder. The Haiku 4.5 id
with its ``@20251001`` suffix is the shape used by the SDK's own Vertex tests.
"""
from __future__ import annotations

import importlib.util
from types import SimpleNamespace

import anthropic
import pytest
from maverick.budget import UnpricedModelError, _lookup_price, vertex_rate_card_model_id

_ENV_NAMES = (
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "ANTHROPIC_VERTEX_BASE_URL",
    "CLOUD_ML_REGION",
    "GOOGLE_CLOUD_PROJECT",
    "VERTEX_MODEL_ID",
)
_ENV = {"ANTHROPIC_VERTEX_PROJECT_ID": "acme-ai", "CLOUD_ML_REGION": "us-east5"}
_HAIKU = "claude-haiku-4-5@20251001"


class _FakeVertex:
    instances: list = []

    def __init__(self, **kw):
        self.kw = kw
        self.calls: list[dict] = []
        self.messages = SimpleNamespace(create=self._create)
        type(self).instances.append(self)

    def _create(self, **kw):
        self.calls.append(kw)
        return _reply()


class _AsyncFakeVertex(_FakeVertex):
    instances: list = []


def _reply():
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text="ok")],
        stop_reason="end_turn",
        usage=SimpleNamespace(
            input_tokens=3, output_tokens=2,
            cache_read_input_tokens=0, cache_creation_input_tokens=0,
        ),
    )


def _pretend_google_auth(monkeypatch, present: bool):
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        if name in ("google.auth", "requests"):
            return object() if present else None
        return real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", fake)


@pytest.fixture
def fake_sdk(monkeypatch):
    for cls in (_FakeVertex, _AsyncFakeVertex):
        cls.instances = []
    monkeypatch.setattr(anthropic, "AnthropicVertex", _FakeVertex, raising=False)
    monkeypatch.setattr(anthropic, "AsyncAnthropicVertex", _AsyncFakeVertex, raising=False)
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    _pretend_google_auth(monkeypatch, True)


def test_default_client_uses_adc_on_the_regional_endpoint(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment=_ENV)
    assert isinstance(c.client, _FakeVertex) and isinstance(c.aclient, _AsyncFakeVertex)
    assert c.client.kw["project_id"] == "acme-ai"
    assert c.client.kw["region"] == "us-east5"
    assert c.client.kw["base_url"] == "https://us-east5-aiplatform.googleapis.com/v1"
    assert c.client.kw["max_retries"] == 0
    # Google Application Default Credentials only: no key, no pre-fetched token.
    assert "api_key" not in c.client.kw and "access_token" not in c.client.kw
    assert c.project_id == "acme-ai" and c.region == "us-east5"
    # No Vertex model id is shipped: an unset model stays empty, never a guessed id.
    assert c.DEFAULT_MODEL == ""


def test_a_call_without_a_model_id_fails_before_any_request(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment=_ENV)
    with pytest.raises(RuntimeError, match="model"):
        c.complete("sys", [{"role": "user", "content": "hi"}])
    assert c.client.calls == []


@pytest.mark.parametrize(
    ("region", "base_url"),
    [
        ("global", "https://aiplatform.googleapis.com/v1"),
        ("us", "https://aiplatform.us.rep.googleapis.com/v1"),
        ("eu", "https://aiplatform.eu.rep.googleapis.com/v1"),
        ("europe-west4", "https://europe-west4-aiplatform.googleapis.com/v1"),
    ],
)
def test_endpoint_follows_the_sdk_region_mapping(fake_sdk, region, base_url):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment={**_ENV, "CLOUD_ML_REGION": region})
    assert c.client.kw["base_url"] == base_url


def test_base_url_override_wins_over_the_sdk_variable_and_default(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    explicit = VertexClient(base_url="https://gateway.example.com/v1", environment=_ENV)
    assert explicit.client.kw["base_url"] == "https://gateway.example.com/v1"
    from_env = VertexClient(environment={**_ENV, "ANTHROPIC_VERTEX_BASE_URL": "https://sdk-proxy.example.com/v1"})
    assert from_env.client.kw["base_url"] == "https://sdk-proxy.example.com/v1"


def test_project_resolves_the_sdk_variable_before_google_cloud_project(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    both = VertexClient(environment={"GOOGLE_CLOUD_PROJECT": "fallback-project",
                                     "ANTHROPIC_VERTEX_PROJECT_ID": "sdk-project",
                                     "CLOUD_ML_REGION": "us-east5"})
    assert both.project_id == "sdk-project"
    only_google = VertexClient(environment={"GOOGLE_CLOUD_PROJECT": "fallback-project",
                                            "CLOUD_ML_REGION": "us-east5"})
    assert only_google.project_id == "fallback-project"


def test_missing_project_or_region_fails_before_any_client_exists(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    with pytest.raises(RuntimeError, match="project"):
        VertexClient(environment={"CLOUD_ML_REGION": "us-east5"})
    with pytest.raises(RuntimeError, match="region"):
        VertexClient(environment={"ANTHROPIC_VERTEX_PROJECT_ID": "acme-ai"})
    assert _FakeVertex.instances == [] and _AsyncFakeVertex.instances == []


@pytest.mark.parametrize(
    ("name", "value", "match"),
    [
        ("ANTHROPIC_VERTEX_PROJECT_ID", "acme/../other", "project id"),
        ("ANTHROPIC_VERTEX_PROJECT_ID", "acme?x=1", "project id"),
        ("ANTHROPIC_VERTEX_PROJECT_ID", "acme ai", "project id"),
        ("CLOUD_ML_REGION", "us-east5.evil.example#", "region"),  # the region is part of the host name
        ("CLOUD_ML_REGION", "US-EAST5", "region"),
        ("CLOUD_ML_REGION", "../us", "region"),
    ],
)
def test_project_and_region_cannot_steer_the_endpoint(fake_sdk, name, value, match):
    from maverick.providers.vertex_provider import VertexClient

    with pytest.raises(ValueError, match=match):
        VertexClient(environment={**_ENV, name: value})
    assert _FakeVertex.instances == []


def test_missing_google_auth_names_the_extra(fake_sdk, monkeypatch):
    from maverick.providers.vertex_provider import VertexClient

    _pretend_google_auth(monkeypatch, False)
    with pytest.raises(RuntimeError, match=r"maverick-core\[vertex\]"):
        VertexClient(environment=_ENV)
    assert _FakeVertex.instances == []


def test_old_sdk_without_the_vertex_client_is_reported(fake_sdk, monkeypatch):
    from maverick.providers.vertex_provider import VertexClient

    monkeypatch.delattr(anthropic, "AnthropicVertex")
    with pytest.raises(RuntimeError, match="AnthropicVertex"):
        VertexClient(environment=_ENV)


def test_start_refuses_vertex_routes_without_google_auth(monkeypatch):
    from maverick.providers import missing_sdks

    _pretend_google_auth(monkeypatch, False)
    msgs = missing_sdks([f"vertex:{_HAIKU}"])
    assert any("maverick-core[vertex]" in m for m in msgs)


def test_missing_sdks_still_hints_when_the_anthropic_sdk_is_absent(monkeypatch):
    """A broken install without the anthropic SDK must get the install hint, not an ImportError."""
    import sys

    from maverick.providers import missing_sdks

    _pretend_google_auth(monkeypatch, False)
    monkeypatch.delitem(sys.modules, "maverick.providers.vertex_provider", raising=False)
    monkeypatch.setitem(sys.modules, "anthropic", None)
    msgs = missing_sdks([f"vertex:{_HAIKU}"])
    assert any("maverick-core[vertex]" in m for m in msgs)
    assert any("anthropic SDK not installed" in m for m in msgs)


def test_start_accepts_vertex_routes_when_google_auth_is_present(monkeypatch):
    from maverick.providers import missing_sdks

    _pretend_google_auth(monkeypatch, True)
    assert not any("vertex" in m.lower() for m in missing_sdks([f"vertex:{_HAIKU}"]))


def test_vertex_takes_no_api_key(monkeypatch):
    from maverick.providers.configuration import validate_fields

    with pytest.raises(ValueError, match="unsupported"):
        validate_fields("vertex", {"api_key": "not-a-vertex-credential"})  # pragma: allowlist secret
    validate_fields("vertex", {"project_id": "acme-ai", "region": "us-east5",
                               "model_id": _HAIKU, "base_url": ""})


def test_vertex_request_equals_the_claude_api_request_except_the_wire_id(fake_sdk):
    from maverick.providers.anthropic_provider import AnthropicClient
    from maverick.providers.vertex_provider import VertexClient

    base = AnthropicClient(api_key="sk-test-not-real")  # pragma: allowlist secret
    c = VertexClient(environment=_ENV)
    messages = [{"role": "user", "content": "hi"}]
    tools = [{"name": "t", "description": "d", "input_schema": {"type": "object"}}]
    expected = base._build_request("sys", messages, tools, 1024, 2048, "claude-haiku-4-5",
                                   None, tool_choice={"type": "any"})
    actual = c._build_request("sys", messages, tools, 1024, 2048, _HAIKU, None,
                              tool_choice={"type": "any"})
    assert actual["model"] == _HAIKU
    assert "speed" not in actual and "betas" not in actual
    assert "cache_control" in str(actual["system"])  # prompt caching on the system prompt
    assert {k: v for k, v in actual.items() if k != "model"} == \
        {k: v for k, v in expected.items() if k != "model"}


def test_complete_round_trip_keeps_the_wire_id_and_the_stop_reason(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment=_ENV)
    resp = c.complete("sys", [{"role": "user", "content": "hi"}], model=_HAIKU, max_tokens=64)
    assert resp.text == "ok" and resp.stop_reason == "end_turn"
    assert c.client.calls and c.client.calls[0]["model"] == _HAIKU


@pytest.mark.parametrize(
    ("vertex_id", "expected"),
    [
        (_HAIKU, "claude-haiku-4-5"),
        ("vertex:claude-sonnet-4-5@20250929", "claude-sonnet-4-5"),
        ("claude-opus-4-8", "claude-opus-4-8"),
        ("google/gemini-2.5-pro", None),
        ("anthropic.claude-haiku-4-5", None),  # a Bedrock id is not a Vertex id
        ("", None),
    ],
)
def test_vertex_ids_map_onto_the_claude_catalogue(vertex_id, expected):
    assert vertex_rate_card_model_id(vertex_id) == expected


def test_vertex_pricing_is_an_estimate_never_a_bill(monkeypatch):
    monkeypatch.delenv("MAVERICK_STRICT_PRICING", raising=False)
    haiku = _lookup_price("claude-haiku-4-5", estimate_only=True)
    assert _lookup_price(f"vertex:{_HAIKU}", estimate_only=True) == haiku
    with pytest.raises(UnpricedModelError, match="strict_pricing=false"):
        _lookup_price(f"vertex:{_HAIKU}", estimate_only=False)
    # A non-Claude Vertex model has no mapping: strict accounting refuses it.
    with pytest.raises(UnpricedModelError):
        _lookup_price("vertex:google/gemini-2.5-pro")


def test_vertex_project_config_counts_as_a_configured_provider(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "load_config", lambda: {"providers": {
        "vertex": {"project_id": "acme-ai", "region": "us-east5"}}})
    for name in list(config.PROVIDER_CREDENTIAL_ENV_VARS) + list(config.PROVIDER_BASE_URL_ENV_VARS):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("ANTHROPIC_VERTEX_PROJECT_ID", raising=False)
    monkeypatch.setattr("maverick.providers.codex_cli_provider._auth_file_present", lambda: False)
    assert config.any_provider_configured() is True
    monkeypatch.setattr(config, "load_config", lambda: {"providers": {"vertex": {}}})
    assert config.any_provider_configured() is False


def test_dispatcher_hands_vertex_the_configured_project_region_and_model(fake_sdk, monkeypatch):
    from maverick.llm import LLM

    monkeypatch.setenv("ANTHROPIC_VERTEX_PROJECT_ID", "env-project")
    monkeypatch.setenv("CLOUD_ML_REGION", "europe-west1")
    monkeypatch.setattr("maverick.config.get_provider_config", lambda provider: {
        "project_id": "cfg-project", "region": "us-east5", "model_id": _HAIKU,
    }, raising=False)
    client = LLM(model=f"vertex:{_HAIKU}")._get_client("vertex")
    # [providers.vertex] wins over the process environment, as documented.
    assert client.project_id == "cfg-project"
    assert client.region == "us-east5"
    assert client.DEFAULT_MODEL == _HAIKU
    assert client.client.kw["base_url"] == "https://us-east5-aiplatform.googleapis.com/v1"


def test_preflight_names_the_missing_vertex_prerequisites(monkeypatch):
    from maverick import operator_preflight as preflight

    for name in ("ANTHROPIC_VERTEX_PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "CLOUD_ML_REGION"):
        monkeypatch.delenv(name, raising=False)
    assert preflight._route_configuration_missing("vertex", {"providers": {}}) == ("project_id", "region")
    configured = {"providers": {"vertex": {"project_id": "acme-ai", "region": "us-east5"}}}
    assert preflight._route_configuration_missing("vertex", configured) == ()
    rendered = preflight._format_route_missing({"vertex": ("project_id", "region")})
    assert "CLOUD_ML_REGION" in rendered and "GOOGLE_CLOUD_PROJECT" in rendered


@pytest.mark.parametrize("bad", ["claude-haiku-4-5/../../other", "claude-haiku-4-5:rawPredict",
                                 "claude haiku", "claude-haiku-4-5?x=1", "claude-haiku-4-5", ""])
def test_model_ids_cannot_reshape_the_request_path(fake_sdk, bad):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment=_ENV)
    with pytest.raises((RuntimeError, ValueError)):
        c._build_request("sys", [{"role": "user", "content": "hi"}], None, 64, None, bad)
    assert c.client.calls == []


@pytest.mark.parametrize("bad", ["claude-haiku-4-5/../../other@1", "claude-haiku-4-5:rawPredict@1",
                                 "claude-haiku-4-5", "claude-haiku-4-5@2025/x", ""])
def test_prewarm_sends_nothing_for_a_model_id_outside_the_vertex_form(fake_sdk, bad):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment=_ENV)
    # Large enough that the cache-minimum gate would otherwise let the warm through.
    assert c.prewarm("x" * 40_000, None, bad) is False
    assert c.client.calls == []


def test_prewarm_warms_the_cache_for_a_vertex_model(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    c = VertexClient(environment=_ENV)
    assert c.prewarm("x" * 40_000, None, _HAIKU) is True
    assert [call["model"] for call in c.client.calls] == [_HAIKU]


def test_a_hostile_configured_model_id_is_refused_at_construction(fake_sdk):
    from maverick.providers.vertex_provider import VertexClient

    with pytest.raises(ValueError, match="model"):
        VertexClient(environment={**_ENV, "VERTEX_MODEL_ID": "claude-haiku-4-5/../../other@1"})
    assert _FakeVertex.instances == []


def test_a_vertex_model_can_be_put_on_the_allow_list(monkeypatch, tmp_path):
    from maverick import runtime_overrides

    monkeypatch.setattr(runtime_overrides, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    runtime_overrides.set_allowed_models([f"vertex:{_HAIKU}"])
    assert f"vertex:{_HAIKU}" in runtime_overrides.allowed_models()
