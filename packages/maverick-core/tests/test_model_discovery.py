"""Live model discovery: which model ids each configured provider key can reach.

The settings page must offer every model a saved key can actually use, not a
hand-maintained list. Discovery asks each provider's own model-list endpoint
through the SSRF-safe client, keeps only well-formed ids, never leaks the key
into any stored detail, and caches the answer so page loads stay offline.
"""
from __future__ import annotations

import json
import time

import pytest
from maverick import model_discovery as discovery


def _material(configured=True, key="sk-secret-value", base_url=""):  # pragma: allowlist secret
    def material(_provider):
        return {"configured": configured, "api_key": key, "base_url": base_url}
    return material


class FakeFetch:
    """Records requests; answers from a {url_prefix: (status, payload)} map."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, url, headers, *, allow_loopback):
        self.calls.append((url, dict(headers), allow_loopback))
        for prefix, (status, payload) in self.answers.items():
            if url.startswith(prefix):
                body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return status, body
        raise AssertionError("unexpected request " + url)


def test_parse_openai_style_keeps_only_well_formed_ids_sorted_and_unique():
    ids, token = discovery.parse_models("openai", {"object": "list", "data": [
        {"id": "gpt-5.4"}, {"id": "gpt-5.4"}, {"id": "o9 mini"}, {"id": ""},
        {"id": 12}, "junk", {"id": "gpt-5.5-pro"}, {"id": "x" * 129},
    ]})
    assert ids == ["gpt-5.4", "gpt-5.5-pro"]
    assert token is None


def test_parse_anthropic_style_reports_the_next_page():
    ids, token = discovery.parse_models("anthropic", {
        "data": [{"id": "claude-opus-4-8", "type": "model"}, {"id": "claude-haiku-4-5"}],
        "has_more": True, "last_id": "claude-haiku-4-5",
    })
    assert ids == ["claude-haiku-4-5", "claude-opus-4-8"]
    assert token == "claude-haiku-4-5"
    assert discovery.parse_models("anthropic", {"data": [], "has_more": False})[1] is None


def test_parse_gemini_strips_the_models_prefix_and_keeps_generation_models():
    ids, token = discovery.parse_models("gemini", {"models": [
        {"name": "models/gemini-3.5-pro", "supportedGenerationMethods": ["generateContent"]},
        {"name": "models/embedding-001", "supportedGenerationMethods": ["embedContent"]},
        {"name": "models/gemini-3-flash"},
        {"name": "not-a-model"},
    ], "nextPageToken": "page-2"})
    assert ids == ["gemini-3-flash", "gemini-3.5-pro"]
    assert token == "page-2"


def test_parse_ollama_tags_uses_the_installed_tag_names():
    ids, token = discovery.parse_models("ollama", {"models": [
        {"name": "llama-4-maverick:latest", "model": "llama-4-maverick:latest"},
        {"model": "qwen3-32b"}, {"name": ""},
    ]})
    assert ids == ["llama-4-maverick:latest", "qwen3-32b"]
    assert token is None


def test_spec_is_bare_for_anthropic_and_prefixed_for_every_other_provider():
    assert discovery.spec_for("anthropic", "claude-opus-4-8") == "claude-opus-4-8"
    assert discovery.spec_for("openai", "gpt-5.4") == "openai:gpt-5.4"
    assert discovery.spec_for("Grok", "grok-4") == "xai:grok-4"


def test_unconfigured_and_unsupported_providers_make_no_request(monkeypatch):
    fetch = FakeFetch({})
    monkeypatch.setattr(discovery, "_provider_material", _material(configured=False))
    entry = discovery.discover("openai", fetch=fetch)
    assert entry["status"] == "unconfigured" and entry["models"] == []
    monkeypatch.setattr(discovery, "_provider_material", _material())
    entry = discovery.discover("bedrock", fetch=fetch)
    assert entry["status"] == "unsupported" and "catalog" in entry["detail"]
    assert fetch.calls == []


def test_discovery_can_be_switched_off_in_config_and_by_environment(monkeypatch):
    monkeypatch.delenv("MAVERICK_MODEL_DISCOVERY", raising=False)
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda: {"models": {"discovery": False}})
    assert discovery.discovery_enabled() is False
    monkeypatch.setattr(config, "load_config", lambda: {"models": {}})
    assert discovery.discovery_enabled() is True
    monkeypatch.setenv("MAVERICK_MODEL_DISCOVERY", "0")
    assert discovery.discovery_enabled() is False
    fetch = FakeFetch({})
    monkeypatch.setattr(discovery, "_provider_material", _material())
    entry = discovery.discover("openai", fetch=fetch)
    assert entry["status"] == "disabled" and fetch.calls == []


def test_live_discovery_follows_pages_sends_the_right_headers_and_never_stores_the_key(monkeypatch):
    monkeypatch.setattr(discovery, "_provider_material", _material(key="sk-ant-secret-777"))  # pragma: allowlist secret
    fetch = FakeFetch({
        "https://api.anthropic.com/v1/models?after_id=claude-haiku-4-5": (200, {
            "data": [{"id": "claude-sonnet-4-6"}], "has_more": False}),
        "https://api.anthropic.com/v1/models": (200, {
            "data": [{"id": "claude-opus-4-8"}, {"id": "claude-haiku-4-5"}],
            "has_more": True, "last_id": "claude-haiku-4-5"}),
    })
    entry = discovery.discover("anthropic", fetch=fetch)
    assert entry["status"] == "live"
    assert entry["models"] == ["claude-haiku-4-5", "claude-opus-4-8", "claude-sonnet-4-6"]
    assert entry["fetched_at"] is not None
    assert [url for url, _, _ in fetch.calls] == [
        "https://api.anthropic.com/v1/models",
        "https://api.anthropic.com/v1/models?after_id=claude-haiku-4-5",
    ]
    headers = fetch.calls[0][1]
    assert headers["x-api-key"] == "sk-ant-secret-777"  # pragma: allowlist secret
    assert headers["anthropic-version"]
    assert "sk-ant-secret-777" not in json.dumps(entry)  # pragma: allowlist secret


def test_openai_compatible_vendors_use_bearer_and_their_configured_base_url(monkeypatch):
    monkeypatch.setattr(discovery, "_provider_material",
                        _material(key="xai-key", base_url="https://gateway.example.test/v1/"))
    fetch = FakeFetch({"https://gateway.example.test/v1/models": (200, {"data": [{"id": "grok-9"}]})})
    entry = discovery.discover("xai", fetch=fetch)
    assert entry["status"] == "live" and entry["models"] == ["grok-9"]
    url, headers, allow_loopback = fetch.calls[0]
    assert url == "https://gateway.example.test/v1/models"
    assert headers == {"Authorization": "Bearer xai-key"} and allow_loopback is False


def test_gemini_uses_its_native_listing_with_the_key_header(monkeypatch):
    monkeypatch.setattr(discovery, "_provider_material", _material(key="gem-key"))
    fetch = FakeFetch({"https://generativelanguage.googleapis.com/v1beta/models": (200, {"models": [
        {"name": "models/gemini-3.5-pro", "supportedGenerationMethods": ["generateContent"]}]})})
    entry = discovery.discover("gemini", fetch=fetch)
    assert entry["models"] == ["gemini-3.5-pro"]
    assert fetch.calls[0][1] == {"x-goog-api-key": "gem-key"}


@pytest.mark.parametrize("base", ["", "/v1", "/v1/"])
def test_ollama_lists_local_tags_on_loopback_without_a_key(monkeypatch, base):
    monkeypatch.setattr(discovery, "_provider_material",
                        _material(key="", base_url="http://127.0.0.1:11434" + base))
    fetch = FakeFetch({"http://127.0.0.1:11434/api/tags": (200, {"models": [{"name": "qwen3-32b:latest"}]})})
    entry = discovery.discover("ollama", fetch=fetch)
    assert entry["status"] == "live" and entry["models"] == ["qwen3-32b:latest"]
    url, headers, allow_loopback = fetch.calls[0]
    assert url == "http://127.0.0.1:11434/api/tags" and headers == {} and allow_loopback is True


@pytest.mark.parametrize("provider", ["vllm", "tgi"])
def test_self_hosted_root_lists_models_at_the_runtime_api_address(monkeypatch, provider):
    monkeypatch.setattr(discovery, "_provider_material",
                        _material(key="", base_url="http://127.0.0.1:8000"))
    fetch = FakeFetch({"http://127.0.0.1:8000/v1/models": (200, {"data": [{"id": "local-model"}]})})
    entry = discovery.discover(provider, fetch=fetch)
    assert entry["status"] == "live" and entry["models"] == ["local-model"]
    assert fetch.calls[0][0] == "http://127.0.0.1:8000/v1/models"


@pytest.mark.parametrize("failure", ["http", "exception", "junk", "too-many-pages"])
def test_failures_are_unavailable_with_a_bounded_detail_and_no_secret(monkeypatch, failure):
    monkeypatch.setattr(discovery, "_provider_material", _material(key="sk-openai-secret"))  # pragma: allowlist secret
    if failure == "http":
        fetch = FakeFetch({"https://api.openai.com/v1/models": (401, {"error": "bad key sk-openai-secret"})})
    elif failure == "junk":
        fetch = FakeFetch({"https://api.openai.com/v1/models": (200, b"<html>not json")})
    elif failure == "too-many-pages":
        monkeypatch.setattr(discovery, "_provider_material", _material(key="sk-ant"))
        fetch = FakeFetch({"https://api.anthropic.com/v1/models": (200, {
            "data": [{"id": "claude-opus-4-8"}], "has_more": True, "last_id": "claude-opus-4-8"})})
    else:
        def fetch(url, headers, *, allow_loopback):
            raise ConnectionError("dial tcp: key sk-openai-secret refused")  # pragma: allowlist secret
    entry = discovery.discover("anthropic" if failure == "too-many-pages" else "openai", fetch=fetch)
    assert entry["status"] == "unavailable" and entry["models"] == []
    assert "secret" not in json.dumps(entry)
    assert len(entry["detail"]) <= 200
    if failure == "http":
        assert "HTTP 401" in entry["detail"]
    if failure == "exception":
        assert "ConnectionError" in entry["detail"]


def test_model_count_is_capped_per_provider(monkeypatch):
    monkeypatch.setattr(discovery, "_provider_material", _material())
    fetch = FakeFetch({"https://api.openai.com/v1/models": (200, {
        "data": [{"id": f"model-{n:04d}"} for n in range(discovery.MAX_MODELS_PER_PROVIDER + 50)]})})
    entry = discovery.discover("openai", fetch=fetch)
    assert entry["status"] == "live"
    assert len(entry["models"]) == discovery.MAX_MODELS_PER_PROVIDER


def test_refresh_persists_a_private_cache_and_snapshot_marks_stale_entries(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import config
    monkeypatch.setattr(config, "load_config", lambda: {"models": {"discovery_ttl_minutes": 30}})
    monkeypatch.delenv("MAVERICK_MODEL_DISCOVERY", raising=False)
    monkeypatch.setattr(discovery, "_provider_material",
                        lambda provider: {"configured": provider == "openai", "api_key": "k", "base_url": ""})
    fetch = FakeFetch({"https://api.openai.com/v1/models": (200, {"data": [{"id": "gpt-5.4"}, {"id": "gpt-9"}]})})
    monkeypatch.setattr(discovery, "_fetch", fetch)
    now = [1_800_000_000.0]
    monkeypatch.setattr(discovery.time, "time", lambda: now[0])

    entries = discovery.refresh(["openai", "gemini"])
    assert entries["openai"]["status"] == "live" and entries["openai"]["models"] == ["gpt-5.4", "gpt-9"]
    assert entries["gemini"]["status"] == "unconfigured"
    path = discovery.cache_path()
    assert path.is_file() and path.parent == tmp_path / "cache"
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert stored["schema"] == discovery.CACHE_SCHEMA
    assert stored["providers"]["openai"]["models"] == ["gpt-5.4", "gpt-9"]

    fresh = discovery.snapshot()
    assert fresh["openai"]["stale"] is False and fresh["openai"]["models"] == ["gpt-5.4", "gpt-9"]
    now[0] += 31 * 60
    assert discovery.snapshot()["openai"]["stale"] is True
    assert discovery.discovery_ttl_minutes() == 30
    # Refreshing every configured provider touches only configured ones.
    fetch.calls.clear()
    discovery.refresh()
    assert [url for url, _, _ in fetch.calls] == ["https://api.openai.com/v1/models"]
    assert discovery.reachable("openai") == ["gpt-5.4", "gpt-9"]
    assert discovery.reachable("gemini") == []


def test_snapshot_survives_a_corrupt_or_missing_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    assert discovery.snapshot() == {}
    path = discovery.cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    assert discovery.snapshot() == {}
    path.write_text(json.dumps({"schema": discovery.CACHE_SCHEMA, "providers": {
        "openai": {"status": "live", "models": ["ok-model", "bad model!"], "detail": "x" * 5000,
                   "fetched_at": time.time()},
        "bogus provider": {"status": "live", "models": ["a"], "fetched_at": 1},
    }}), encoding="utf-8")
    loaded = discovery.snapshot()
    assert loaded == {}  # Unbound records cannot attest this connection's models.
    stored = json.loads(path.read_text(encoding="utf-8"))
    stored["providers"]["openai"]["material_binding"] = discovery._material_binding("openai")
    path.write_text(json.dumps(stored), encoding="utf-8")
    loaded = discovery.snapshot()
    assert set(loaded) == {"openai"}
    assert loaded["openai"]["models"] == ["ok-model"]
    assert len(loaded["openai"]["detail"]) <= 200


def test_parse_free_models_keeps_only_rows_priced_at_zero_for_prompt_and_completion():
    payload = {"data": [
        {"id": "stealth/union-alpha", "pricing": {"prompt": "0", "completion": "0", "request": "0"}},
        {"id": "vendor/paid", "pricing": {"prompt": "0.000001", "completion": "0"}},
        {"id": "vendor/no-pricing"},
        {"id": "vendor/numeric-zero", "pricing": {"prompt": 0, "completion": 0.0}},
        {"id": "vendor/bool-zero", "pricing": {"prompt": False, "completion": False}},
        {"id": "vendor/request-fee", "pricing": {"prompt": "0", "completion": "0", "request": "0.01"}},
        {"id": "vendor/reasoning-fee", "pricing": {"prompt": "0", "completion": "0", "internal_reasoning": "0.01"}},
        {"id": "vendor/tiny-fee", "pricing": {"prompt": "1e-9999", "completion": "0"}},
        {"id": "bad id!", "pricing": {"prompt": "0", "completion": "0"}},
        "not-a-row",
    ]}
    assert discovery.parse_free_models("openai", payload) == ["stealth/union-alpha", "vendor/numeric-zero"]
    assert discovery.parse_free_models("anthropic", payload) == []
    assert discovery.parse_free_models("openai", {"data": "nope"}) == []
    assert discovery.parse_free_models("openai", "nope") == []


def test_openrouter_discovery_records_the_models_it_advertises_as_free(monkeypatch):
    monkeypatch.setattr(discovery, "_provider_material", _material(key="or-key"))
    fetch = FakeFetch({"https://openrouter.ai/api/v1/models": (200, {"data": [
        {"id": "stealth/union-alpha", "pricing": {"prompt": "0", "completion": "0"}},
        {"id": "openai/gpt-5.5", "pricing": {"prompt": "0.00000125", "completion": "0.00001"}},
    ]})})
    entry = discovery.discover("openrouter", fetch=fetch)
    assert entry["status"] == "live"
    assert entry["models"] == ["openai/gpt-5.5", "stealth/union-alpha"]
    assert entry["free_models"] == ["stealth/union-alpha"]
    # No other provider claims a free tier from the same payload shape.
    monkeypatch.setattr(discovery, "_provider_material", _material(key="oa-key"))
    fetch = FakeFetch({"https://api.openai.com/v1/models": (200, {"data": [
        {"id": "gpt-5.5", "pricing": {"prompt": "0", "completion": "0"}}]})})
    assert discovery.discover("openai", fetch=fetch)["free_models"] == []


def test_free_models_round_trip_through_the_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import config
    monkeypatch.setattr(config, "load_config", dict)
    monkeypatch.delenv("MAVERICK_MODEL_DISCOVERY", raising=False)
    monkeypatch.setattr(discovery, "_provider_material",
                        lambda provider: {"configured": provider == "openrouter", "api_key": "k", "base_url": ""})
    fetch = FakeFetch({"https://openrouter.ai/api/v1/models": (200, {"data": [
        {"id": "stealth/union-alpha", "pricing": {"prompt": "0", "completion": "0"}},
        {"id": "openai/gpt-5.5", "pricing": {"prompt": "0.00000125", "completion": "0.00001"}},
    ]})})
    monkeypatch.setattr(discovery, "_fetch", fetch)
    discovery.refresh(["openrouter"])
    stored = json.loads(discovery.cache_path().read_text(encoding="utf-8"))
    assert stored["providers"]["openrouter"]["free_models"] == ["stealth/union-alpha"]
    assert discovery.free_models("openrouter") == ["stealth/union-alpha"]
    assert discovery.free_models("openai") == []
    # A hand-edited cache cannot smuggle an id the listing never returned as well-formed.
    stored["providers"]["openrouter"]["free_models"] = ["stealth/union-alpha", "bad id!", 7]
    discovery.cache_path().write_text(json.dumps(stored), encoding="utf-8")
    assert discovery.free_models("openrouter") == ["stealth/union-alpha"]
