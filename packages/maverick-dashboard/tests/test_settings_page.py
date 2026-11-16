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


def test_admin_can_mark_a_self_hosted_server_free(monkeypatch, tmp_path):
    """DR 8: the Prices page can mark an Ollama, vLLM or TGI server free; the
    change is audited like other price changes and other providers refuse."""
    _prep(monkeypatch, tmp_path)
    from maverick.budget import _lookup_price_quote
    from maverick.config import config_path

    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_text('[providers.ollama]\nbase_url = "https://gpu.example.org"\n',
                             encoding="utf-8")
    c = _client()
    headers = {"origin": "http://127.0.0.1"}
    assert _lookup_price_quote("ollama:llama3").rates != (0.0, 0.0)
    assert "Mark a self-hosted server free" in c.get("/settings").text
    saved = c.post("/settings/models/self-hosted-free",
                   data={"provider": "ollama", "free": "on", "confirm": "on"},
                   headers=headers, follow_redirects=False)
    assert saved.status_code == 303
    assert _lookup_price_quote("ollama:llama3").rates == (0.0, 0.0)
    assert c.post("/settings/models/self-hosted-free",
                  data={"provider": "openai", "free": "on", "confirm": "on"},
                  headers=headers, follow_redirects=False).status_code == 400
    assert "Marked free" in c.get("/settings").text
    # Charging again needs no "charges nothing" confirmation.
    cleared = c.post("/settings/models/self-hosted-free",
                     data={"provider": "ollama", "free": "off"},
                     headers=headers, follow_redirects=False)
    assert cleared.status_code == 303
    assert _lookup_price_quote("ollama:llama3").rates != (0.0, 0.0)
    assert "Safety ceiling" in c.get("/settings").text
    # Free set in config.toml by setup cannot be cleared here: say which file.
    config_path().write_text('[providers.ollama]\nbase_url = "https://gpu.example.org"\n'
                             'price_per_mtok = "free"\n', encoding="utf-8")
    kept = c.post("/settings/models/self-hosted-free", data={"provider": "ollama", "free": "off"},
                  headers=headers, follow_redirects=False)
    assert kept.status_code == 409 and str(config_path()) in kept.json()["detail"]
    assert _lookup_price_quote("ollama:llama3").rates == (0.0, 0.0)


def test_copilot_marks_a_self_hosted_server_free_like_the_settings_form(monkeypatch, tmp_path):
    """The Copilot operation runs the form's own function: administrators
    only, the same confirmation, and the price in effect read back."""
    import pytest
    from fastapi import HTTPException
    from maverick.budget import _lookup_price_quote
    from maverick.config import config_path
    from maverick_dashboard import auth
    from maverick_dashboard import product_operations as registry
    from maverick_dashboard import product_operations_models as ops
    from starlette.requests import Request

    _prep(monkeypatch, tmp_path)
    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_text('[providers.ollama]\nbase_url = "https://gpu.example.org"\n',
                             encoding="utf-8")
    assert "models.self_hosted_price" in registry.adapters()
    adapter = {a.id: a for a in ops.entries()}["models.self_hosted_price"]

    def request():
        return Request({"type": "http", "method": "POST", "path": "/settings",
                        "headers": [(b"host", b"127.0.0.1")], "client": ("127.0.0.1", 1)})

    state = adapter.snapshot(request(), {})
    assert "Ollama: Safety ceiling" in state.summary and not state.blocked
    free = {"provider": "ollama", "free": True, "confirmed": True}
    with pytest.raises(HTTPException) as unconfirmed:
        adapter.prepare(request(), {}, dict(free, confirmed=False))
    assert unconfirmed.value.status_code == 400
    review = adapter.prepare(request(), {}, free)
    assert review.changes == [{"field": "Charge for Ollama", "before": "Safety ceiling",
                               "after": "Marked free"}]
    done = adapter.execute(request(), {}, free, review.native, "a" * 32)
    assert done.status == "confirmed" and done.details["server"]["state"] == "Marked free"
    assert _lookup_price_quote("ollama:llama3").rates == (0.0, 0.0)
    again = {"provider": "ollama", "free": False, "confirmed": False}
    assert adapter.execute(request(), {}, again, {}, "b" * 32).details["server"]["state"] == "Safety ceiling"
    assert _lookup_price_quote("ollama:llama3").rates != (0.0, 0.0)

    def deny(_request, _permission):
        raise HTTPException(status_code=403, detail="forbidden")

    monkeypatch.setattr(auth, "require_global_permission", deny)
    for call in (lambda: adapter.snapshot(request(), {}),
                 lambda: adapter.execute(request(), {}, free, {}, "c" * 32)):
        with pytest.raises(HTTPException) as refused:
            call()
        assert refused.value.status_code == 403
    assert _lookup_price_quote("ollama:llama3").rates != (0.0, 0.0)


def test_copilot_sets_and_removes_a_model_price_like_the_settings_form(monkeypatch, tmp_path):
    """The Copilot operations run the form's own functions: administrators
    only, the form's confirmation and refusals, an audited write, and the
    saved price read back."""
    import maverick.audit as audit_pkg
    import pytest
    from fastapi import HTTPException
    from maverick.audit import writer
    from maverick.runtime_overrides import model_rate_overrides
    from maverick_dashboard import auth
    from maverick_dashboard import product_operations as registry
    from maverick_dashboard import product_operations_models as ops
    from starlette.requests import Request

    _prep(monkeypatch, tmp_path)
    monkeypatch.delenv("MAVERICK_MODEL_OVERRIDE", raising=False)
    monkeypatch.setenv("MAVERICK_BILLING_STRICT", "true")
    assert {"models.price.set", "models.price.remove"} <= set(registry.adapters())
    by_id = {a.id: a for a in ops.entries()}
    setter, remover = by_id["models.price.set"], by_id["models.price.remove"]
    seen = []
    real = writer.audit_event
    monkeypatch.setattr(audit_pkg, "audit_event",
                        lambda kind, **row: seen.append({"kind": str(kind), **row}) or real(kind, **row))

    def request():
        return Request({"type": "http", "method": "POST", "path": "/settings",
                        "headers": [(b"host", b"127.0.0.1")], "client": ("127.0.0.1", 1)})

    today = datetime.now(timezone.utc).date()
    spec = "openai_compatible:client-model"
    price = {"model": spec, "input_per_mtok": 4.0, "output_per_mtok": 12.0, "source": "Contract R1",
             "as_of": today.isoformat(), "valid_until": (today + timedelta(days=30)).isoformat(),
             "confirmed": True}
    assert remover.snapshot(request(), {}).blocked and not setter.snapshot(request(), {}).blocked
    # The form's refusals: no confirmation, a model with a tracked price, bad dates.
    for refused, status in ((dict(price, confirmed=False), 400), (dict(price, model="claude-sonnet-4-6"), 409)):
        with pytest.raises(HTTPException) as error:
            setter.prepare(request(), {}, refused)
        assert error.value.status_code == status
    with pytest.raises(HTTPException) as error:
        setter.execute(request(), {}, dict(price, valid_until="2020-01-01"), {}, "a" * 32)
    assert error.value.status_code == 400
    assert not model_rate_overrides() and not seen

    review = setter.prepare(request(), {}, price)
    assert review.changes == [{"field": f"Spending ceiling for {spec}", "before": "No saved price",
                               "after": "Input $4.0000 and output $12.0000 per million tokens"}]
    done = setter.execute(request(), {}, price, review.native, "b" * 32)
    assert done.status == "confirmed" and model_rate_overrides()[spec]["source"] == "Contract R1"
    assert done.details["price"]["input_per_mtok"] == 4.0
    assert model_rate_overrides()[spec]["approved_by"] == "local administrator"
    assert [row["phase"] for row in seen if row.get("section") == "model_rates"] == ["prepared", "completed"]
    assert [row["model"] for row in seen if row.get("action") == "settings_model_rate"] == [spec]

    state = remover.snapshot(request(), {})
    assert not state.blocked and state.fields[0]["choices"][0]["value"] == spec
    review = remover.prepare(request(), {}, {"model": spec})
    assert review.changes[0]["after"] == "No saved price"

    def deny(_request, _permission):
        raise HTTPException(status_code=403, detail="forbidden")

    with monkeypatch.context() as patch:
        patch.setattr(auth, "require_global_permission", deny)
        for call in (lambda: setter.snapshot(request(), {}), lambda: remover.snapshot(request(), {}),
                     lambda: setter.execute(request(), {}, dict(price, input_per_mtok=9.0), {}, "c" * 32),
                     lambda: remover.execute(request(), {}, {"model": spec}, {}, "d" * 32)):
            with pytest.raises(HTTPException) as refused:
                call()
            assert refused.value.status_code == 403
    assert model_rate_overrides()[spec]["input_per_mtok"] == 4.0

    gone = remover.execute(request(), {}, {"model": spec}, review.native, "e" * 32)
    assert gone.status == "confirmed" and spec not in model_rate_overrides()
    assert [row["model"] for row in seen if row.get("action") == "settings_model_rate_removed"] == [spec]


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
