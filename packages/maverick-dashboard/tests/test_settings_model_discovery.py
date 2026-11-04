"""Settings > Models offers what the saved provider keys can actually reach.

The pickers group models by configured provider, include every id the key's
own model-list endpoint reports (not only the shipped catalog), let the admin
refresh those lists, and still accept a typed id for anything else.
"""
from __future__ import annotations

import re
import time

from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _snapshot():
    now = time.time()
    return {
        "openai": {"provider": "openai", "status": "live", "models": ["gpt-5.4", "gpt-9-preview"],
                   "detail": "2 models reachable with the configured key", "fetched_at": now - 120,
                   "stale": False},
        "xai": {"provider": "xai", "status": "unavailable", "models": [],
                "detail": "provider returned HTTP 401 for the model list", "fetched_at": now - 60,
                "stale": False},
    }


def _prep(monkeypatch, tmp_path, *, configured=("openai", "xai"), snapshot=None):
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_DISCOVERY", raising=False)
    for name in config.PROVIDER_KEY_ENV_VARS + config.PROVIDER_BASE_URL_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    for name in configured:
        monkeypatch.setenv(config.PROVIDER_KEY_ENV_MAP[name][0], "test-key-" + name)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick import model_discovery
    monkeypatch.setattr(model_discovery, "snapshot", lambda: dict(_snapshot() if snapshot is None else snapshot))
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_pickers_group_reachable_models_by_configured_provider(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    text = _client().get("/settings").text
    # Real selects, grouped by provider; only configured providers are offered.
    assert re.search(r'<select\b[^>]*\bname="model"', text)
    assert '<optgroup label="OpenAI">' in text
    assert '<optgroup label="Anthropic (Claude)">' not in text
    # A model the key reaches but the shipped catalog does not know is offered.
    assert 'value="openai:gpt-9-preview"' in text
    assert 'value="openai:gpt-5.4"' in text
    # Typed ids still work: every picker carries a custom option and field.
    assert 'value="__custom__"' in text
    assert 'name="model_custom"' in text and 'name="coder_custom"' in text
    # The allow-list still lists every provider, configured ones expanded.
    assert '<details data-model-group="openai" open' in text
    assert '<details data-model-group="anthropic"' in text and 'data-model-group="anthropic" open' not in text
    assert 'name="models" value="claude-opus-4-8"' in text
    assert 'data-model-source="live"' in text and 'data-model-source="catalog"' in text
    # Discovery status is visible and refreshable.
    assert 'action="/settings/models/discover"' in text
    assert "2 models listed in the current check" in text
    # A failed list reads as a plain sentence, never a status code.
    assert "HTTP 401" not in text
    assert "The provider did not answer" in text


def test_discover_refreshes_every_provider_or_one(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick import model_discovery
    calls = []
    monkeypatch.setattr(model_discovery, "refresh", lambda providers=None: calls.append(providers) or {})
    c = _client()
    r = c.post("/settings/models/discover", data={}, headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings?saved=discover"
    r = c.post("/settings/models/discover", data={"provider": "openai"}, headers=_ORIGIN,
               follow_redirects=False)
    assert r.status_code == 303
    assert calls == [None, ["openai"]]
    r = c.post("/settings/models/discover", data={"provider": "nope"}, headers=_ORIGIN,
               follow_redirects=False)
    assert r.status_code == 400
    r = c.post("/settings/models/discover", data={}, follow_redirects=False)
    assert r.status_code == 403
    assert calls == [None, ["openai"]]
    r = c.get("/settings?saved=discover")
    assert "Model lists refreshed" in r.text


def test_typed_model_ids_reach_the_default_and_role_pins(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import default_model_override, role_model_override
    c = _client()
    r = c.post("/settings/models", data={"model": "__custom__", "model_custom": " openai:gpt-11 "},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert default_model_override() == "openai:gpt-11"
    r = c.post("/settings/models/roles", data={"coder": "__custom__", "coder_custom": "xai:grok-11",
                                               "writer": "openai:gpt-5.4"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert role_model_override("coder") == "xai:grok-11"
    assert role_model_override("writer") == "openai:gpt-5.4"
    # Custom with nothing typed clears the pin instead of storing the marker.
    r = c.post("/settings/models", data={"model": "__custom__", "model_custom": ""},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert default_model_override() is None
    r = c.post("/settings/models", data={"model": "__custom__", "model_custom": "bad model!!"},
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 400


def test_pinned_model_outside_the_offered_lists_is_shown_as_a_typed_id(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import set_default_model, set_role_models
    set_default_model("openai:gpt-77")
    set_role_models({"coder": "deepseek:deepseek-v9"})
    text = _client().get("/settings").text
    assert 'name="model_custom" value="openai:gpt-77"' in text
    assert 'name="coder_custom" value="deepseek:deepseek-v9"' in text
    assert text.count('value="__custom__" selected') == 2


def test_saving_a_provider_key_refreshes_that_provider_and_never_blocks_the_save(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick import model_discovery
    from maverick_dashboard import settings_store
    rotated, refreshed = [], []
    monkeypatch.setattr(settings_store, "rotate_provider",
                        lambda name, **kwargs: rotated.append((name, sorted(kwargs))))
    monkeypatch.setattr(model_discovery, "refresh", lambda providers=None: refreshed.append(providers) or {})
    c = _client()
    r = c.post("/settings/providers", data={"provider": "openai", "api_key": "sk-new"},  # pragma: allowlist secret
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    assert rotated == [("openai", ["api_key", "base_url"])] and refreshed == [["openai"]]

    def explode(providers=None):
        raise RuntimeError("discovery down")

    monkeypatch.setattr(model_discovery, "refresh", explode)
    r = c.post("/settings/providers", data={"provider": "openai", "api_key": "sk-new"},  # pragma: allowlist secret
               headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/settings?saved=providers"


def test_allow_list_still_caps_the_grouped_pickers(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    from maverick.runtime_overrides import set_allowed_models
    set_allowed_models(["openai:gpt-9-preview"])
    text = _client().get("/settings").text
    picker = text.split('name="model"', 1)[1].split("</select>", 1)[0]
    assert 'value="openai:gpt-9-preview"' in picker
    assert 'value="openai:gpt-5.4"' not in picker
    assert "1 model(s) approved" in text or "1 model(s) allowed" in text


def test_allow_listed_models_are_offered_before_their_key_is_saved(monkeypatch, tmp_path):
    # An admin approves Claude models on a deployment with only an OpenAI key
    # (or no key at all): the pickers mirror the allow-list, flagged as keyless,
    # rather than silently dropping the approved models.
    _prep(monkeypatch, tmp_path, configured=("openai",))
    from maverick.runtime_overrides import set_allowed_models
    set_allowed_models(["claude-sonnet-4-6", "openai:gpt-5.4"])
    text = _client().get("/settings").text
    picker = text.split('name="model"', 1)[1].split("</select>", 1)[0]
    assert '<optgroup label="Anthropic (Claude) (not set up)">' in picker
    assert 'value="claude-sonnet-4-6"' in picker and 'value="openai:gpt-5.4"' in picker
    assert 'value="claude-opus-4-8"' not in picker
    # Without an allow-list an unconfigured provider is still not offered.
    set_allowed_models([])
    picker = _client().get("/settings").text.split('name="model"', 1)[1].split("</select>", 1)[0]
    assert "Anthropic" not in picker and 'value="openai:gpt-5.4"' in picker


def test_discovery_switched_off_is_explained_not_silent(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path, snapshot={})
    monkeypatch.setenv("MAVERICK_MODEL_DISCOVERY", "0")
    text = _client().get("/settings").text
    assert "Automatic model lists are turned off" in text
    assert "controlled by your installation" in text  # env override: no button
    # The catalog still offers the configured providers' shipped models.
    assert '<optgroup label="OpenAI">' in text and 'value="openai:gpt-5.4"' in text


def test_model_guidance_does_not_override_disabled_discovery(monkeypatch):
    from maverick import model_discovery, model_guidance
    from maverick_dashboard import model_pickers
    monkeypatch.setattr(model_discovery, "snapshot", dict)
    monkeypatch.setattr(model_discovery, "discovery_enabled", lambda: False)
    monkeypatch.setattr(model_guidance, "enabled", lambda: True)
    value = model_pickers.build([], set())
    assert value["discovery_enabled"] is False
    assert value["model_guidance_enabled"] is True
