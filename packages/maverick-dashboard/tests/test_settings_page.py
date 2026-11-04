"""Settings page: appearance form + model pin via the runtime overlay."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from maverick_dashboard.app import static_url


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1")


def _prep(monkeypatch, tmp_path):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    # Keep the model pin in tmp so the real ~/.maverick is never touched.
    import maverick.runtime_overrides as ro
    monkeypatch.setattr(ro, "OVERRIDES_PATH", tmp_path / "runtime-overrides.toml")
    from maverick_dashboard import app as dash_app
    dash_app._world_cache.clear()


def test_settings_page_renders(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().get("/settings")
    assert r.status_code == 200
    assert "Appearance" in r.text
    assert "Models" in r.text
    assert 'action="/settings/models"' in r.text
    # nav link is wired
    assert 'href="/settings"' in r.text


def test_admin_can_price_private_model_and_read_back_effective_route(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "true")
    today = datetime.now(timezone.utc).date()
    c = _client()
    data = {
        "rate_model": "__custom__",
        "rate_model_custom": "openai_compatible:client-model",
        "input_per_mtok": "4", "output_per_mtok": "12",
        "source": "Contract R1", "as_of": today.isoformat(),
        "valid_until": (today + timedelta(days=30)).isoformat(),
        "confirm": "on",
    }
    response = c.post("/settings/models/rate", data=data,
                      headers={"origin": "http://127.0.0.1"}, follow_redirects=False)
    assert response.status_code == 303
    from maverick.runtime_overrides import model_rate_overrides

    assert model_rate_overrides()["openai_compatible:client-model"]["source"] == "Contract R1"
    pin = c.post("/settings/models", data={"model": "__custom__", "model_custom": "openai_compatible:client-model"},
                 headers={"origin": "http://127.0.0.1"}, follow_redirects=False)
    assert pin.status_code == 303
    page = c.get("/settings", params={"saved": "model_rate"})
    assert page.status_code == 200
    assert "Administrator ceiling" in page.text
    assert "Contract R1" in page.text
    assert "Model spending ceiling updated." in page.text

    removed = c.post("/settings/models/rate/remove", data={"model": "openai_compatible:client-model"},
                     headers={"origin": "http://127.0.0.1"}, follow_redirects=False)
    assert removed.status_code == 303
    assert "openai_compatible:client-model" not in model_rate_overrides()
    assert "Will stop before a paid request" in c.get("/settings").text

    already_tracked = c.post(
        "/settings/models/rate",
        data={**data, "rate_model": "claude-sonnet-4-6"},
        headers={"origin": "http://127.0.0.1"}, follow_redirects=False,
    )
    assert already_tracked.status_code == 409
    assert "anthropic:claude-sonnet-4-6" not in model_rate_overrides()


def test_settings_has_bounded_sections_keyboard_tabs_and_search(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    text = _client().get("/settings").text

    assert 'id="settings-search"' in text
    assert 'role="tablist"' in text
    assert text.count('role="tab" data-settings-tab=') == 6
    for group in ("general", "models", "integrations", "controls", "access", "maintenance"):
        assert f'data-settings-tab="{group}"' in text
        assert f'data-settings-group="{group}"' in text
    # The arrow, Home and End keys come from the shared tab bar's script.
    assert 'data-mv-tabs="panels"' in text and f'<script src="{static_url("lightwork-tabs.js")}" defer></script>' in text
    assert "applySearch" in text
    assert "data-settings-search-item" in text


def test_hidden_attribute_beats_author_display_rules():
    """The tab filter sets ``hidden`` on every off-tab ``.section-head``.

    Shared classes (``.section-head`` is ``display: flex``, ``.btn`` is
    ``inline-flex``) beat the UA ``[hidden]`` rule, so without a reset the
    eight off-tab headings rendered as a wall of orphaned titles under the
    General tab, and the Ekko page showed all four hidden control buttons.
    The shared stylesheet must therefore carry a global ``[hidden]`` reset
    that wins over any author-level display.
    """
    import re
    from pathlib import Path
    css = (Path(__file__).resolve().parents[1] / "maverick_dashboard"
           / "static" / "lightwork.css").read_text(encoding="utf-8")
    assert re.search(r"\.section-head\s*\{[^}]*display:\s*flex", css)
    rule = re.search(r"(?<![\w.#-])\[hidden\]\s*\{([^}]*)\}", css)
    assert rule is not None, "global [hidden] reset missing from lightwork.css"
    assert re.search(r"display:\s*none\s*!important", rule.group(1))


def test_light_theme_flips_the_root_color_scheme():
    """The theme class is on <body>, but the UA canvas, scrollbars and native
    controls follow color-scheme on the root, so Light must switch it there too."""
    import re
    from pathlib import Path
    css = (Path(__file__).resolve().parents[1] / "maverick_dashboard"
           / "static" / "lightwork.css").read_text(encoding="utf-8")
    rule = re.search(r":root:has\(body\.theme-light\)\s*\{([^}]*)\}", css)
    assert rule is not None
    assert re.search(r"color-scheme:\s*light", rule.group(1))


def test_settings_returns_to_section_that_was_saved(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    text = _client().get("/settings", params={"saved": "providers"}).text
    assert 'data-initial-group="integrations"' in text


_GROUPS = ("general", "models", "integrations", "controls", "access", "maintenance")


def _first_paint_state(text):
    """What the page shows before its scripts run: the group the sections
    element names (a rule parsed before the sections hides every other
    group's headings and panels) and the tab marked selected."""
    import re

    before, after = text.split('<div id="settings-sections"', 1)
    active = re.match(r'\s+data-settings-active="(\w+)"', after)
    assert active is not None, after[:200]
    for group in _GROUPS:
        rule = (f'#settings-sections[data-settings-active="{group}"] '
                f'[data-settings-group]:not([data-settings-group="{group}"])')
        assert rule in before, f"no first-paint rule for {group}"
    assert re.search(r'\[data-settings-group="maintenance"\]\)\s*\{\s*display:\s*none;\s*\}', before)
    # No node is hidden or shown by the server any other way.
    assert not re.search(r'data-settings-group="\w+"[^>]*\shidden[\s>]', after)
    selected = re.findall(r'role="tab" data-settings-tab="(\w+)" aria-selected="true" tabindex="0"', text)
    unselected = re.findall(r'role="tab" data-settings-tab="(\w+)" aria-selected="false" tabindex="-1"', text)
    return active.group(1), selected, unselected


def test_settings_paints_one_group_and_its_tab_before_any_script(monkeypatch, tmp_path):
    """All six groups used to paint and then five were hidden by the page
    script (layout shift 0.41-0.77 on Settings): the server now decides."""
    _prep(monkeypatch, tmp_path)
    active, selected, unselected = _first_paint_state(_client().get("/settings").text)
    assert active == "general"
    assert selected == ["general"]
    assert sorted(unselected) == sorted(set(_GROUPS) - {"general"})


def test_saved_section_is_the_group_painted_first(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    active, selected, unselected = _first_paint_state(
        _client().get("/settings", params={"saved": "visibility"}).text)
    assert active == selected[0] == "access" and len(selected) == 1
    assert len(unselected) == 5


def test_group_named_in_the_address_is_applied_before_the_sections_paint(monkeypatch, tmp_path):
    """The server cannot see #settings-access; a small script placed before the
    first section names that group, so a deep link paints it directly."""
    _prep(monkeypatch, tmp_path)
    text = _client().get("/settings").text
    sections = text.index('<div id="settings-sections"')
    first_node = text.index("data-settings-group=", sections)
    early = text[sections:first_node]
    assert '<script nonce="' in early and "window.mvSettingsGroupFor" in early
    assert "dataset.settingsActive" in early
    # The page script hands the painted state to the tabs instead of
    # repainting it, and keeps following later address changes.
    page_script = text[first_node:]
    assert "removeAttribute('data-settings-active')" in page_script
    assert "window.mvSettingsGroupFor ||" in page_script
    assert page_script.count("groupFor(window.location.hash)") == 2  # on load and on hashchange


def test_set_and_clear_default_model(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    c = _client()
    hdr = {"origin": "http://127.0.0.1"}
    r = c.post("/settings/models", data={"model": "claude-opus-4-8"},
               headers=hdr, follow_redirects=False)
    assert r.status_code == 303

    from maverick.runtime_overrides import default_model_override
    assert default_model_override() == "claude-opus-4-8"
    # The pin flows through model resolution (no per-role config in this test).
    from maverick.llm import model_for_role
    assert model_for_role("writer") == "claude-opus-4-8"

    # Clearing reverts to defaults.
    r = c.post("/settings/models", data={"model": ""}, headers=hdr,
               follow_redirects=False)
    assert r.status_code == 303
    assert default_model_override() is None


def test_set_model_rejects_junk(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/settings/models", data={"model": "bad model!!"},
                       headers={"origin": "http://127.0.0.1"},
                       follow_redirects=False)
    assert r.status_code == 400


def test_set_model_blocks_cross_origin(monkeypatch, tmp_path):
    _prep(monkeypatch, tmp_path)
    r = _client().post("/settings/models", data={"model": "claude-opus-4-8"},
                       headers={"origin": "http://evil.example"},
                       follow_redirects=False)
    assert r.status_code == 403


def test_denied_tools_preserved_when_pinning_model(monkeypatch, tmp_path):
    """Writing a model must not wipe the [security] tool-deny overlay."""
    _prep(monkeypatch, tmp_path)
    from maverick import runtime_overrides as ro
    ro.disable_tool("browser")
    ro.set_default_model("claude-sonnet-4-6")
    assert "browser" in ro.denied_tools()
    assert ro.default_model_override() == "claude-sonnet-4-6"
    # and clearing the model leaves the tool deny intact
    ro.clear_default_model()
    assert "browser" in ro.denied_tools()
    assert ro.default_model_override() is None
