"""Model picker spans every provider's catalog, not just Anthropic."""
from __future__ import annotations

from html.parser import HTMLParser

from fastapi.testclient import TestClient

_ORIGIN = {"origin": "http://127.0.0.1"}


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_catalog_spans_providers():
    from maverick.llm import catalog_specs
    specs = {s for s, _ in catalog_specs()}
    # bare anthropic + provider-prefixed others
    assert "claude-opus-4-8" in specs
    assert "openai:gpt-5.4" in specs
    assert "gemini:gemini-3.5-pro" in specs
    assert "xai:grok-4-latest" in specs


def test_settings_picker_is_multi_provider(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/settings")
    assert r.status_code == 200
    # Real pickers with a typed-id escape hatch; every provider's catalog is
    # listed for the allow-list even before a key is saved.
    class ModelPicker(HTMLParser):
        def __init__(self):
            super().__init__()
            self.inside = False
            self.found = False
            self.options = []

        def handle_starttag(self, tag, attrs):
            attributes = dict(attrs)
            if tag == "select":
                self.inside = attributes.get("name") == "model"
                self.found |= self.inside and "select" in attributes.get("class", "").split()
            elif tag == "option" and self.inside:
                self.options.append(attributes.get("value"))

        def handle_endtag(self, tag):
            if tag == "select":
                self.inside = False

    picker = ModelPicker()
    picker.feed(r.text)
    assert picker.found and "__custom__" in picker.options
    assert 'name="models" value="openai:gpt-5.4"' in r.text
    assert 'name="models" value="gemini:gemini-3.5-pro"' in r.text


def test_pin_non_anthropic_model_flows_through(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/settings/models", data={"model": "openai:gpt-5.4"},
                       headers=_ORIGIN, follow_redirects=False)
    assert r.status_code == 303
    from maverick.llm import model_for_role
    from maverick.runtime_overrides import default_model_override
    assert default_model_override() == "openai:gpt-5.4"
    assert model_for_role("writer") == "openai:gpt-5.4"
