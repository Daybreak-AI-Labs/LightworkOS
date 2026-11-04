"""Glass effects: a display preference offered and stored like the theme.

Off by default (pages are solid and respond faster). A person can turn the
full glass look back on in Display preferences -- on this device only or on
their account -- and an administrator can make it the installation default
(``[dashboard] glass``, Settings > All settings, the setup wizard).
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_CONFIG", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _client() -> TestClient:
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _body_classes(html: str) -> list[str]:
    return re.search(r'<body[^>]*\bclass="([^"]+)"', html).group(1).split()


class _Req:
    def __init__(self, q=None, c=None):
        self.query_params = {"glass": q} if q else {}
        self.cookies = {"mvk_glass": c} if c else {}


def test_glass_is_off_unless_a_person_or_the_installation_turns_it_on(monkeypatch):
    import maverick.config as cfg
    from maverick_dashboard.app import resolve_glass

    assert resolve_glass(_Req()) == "off"
    assert resolve_glass(_Req(q="on")) == "on"
    assert resolve_glass(_Req(c="on")) == "on"
    assert resolve_glass(_Req(q="off", c="on")) == "off"
    assert resolve_glass(_Req(q="sparkle")) == "off"  # unknown -> default
    monkeypatch.setattr(cfg, "load_config", lambda: {"dashboard": {"glass": "on"}})
    assert resolve_glass(_Req()) == "on"
    assert resolve_glass(_Req(c="off")) == "off"  # the person's own choice wins


def test_every_page_shell_says_whether_glass_is_on():
    client = _client()
    page = client.get("/overview")
    assert page.status_code == 200
    assert "glass-off" in _body_classes(page.text)
    chosen = client.get("/overview", params={"glass": "on"})
    assert "glass-on" in _body_classes(chosen.text)
    assert "mvk_glass=on" in chosen.headers.get("set-cookie", "")
    assert "glass-on" in _body_classes(client.get("/chat").text)  # the chat shell too


def test_display_preferences_offer_glass_effects_beside_the_theme():
    page = _client().get("/overview").text
    control = re.search(r'<select[^>]*data-ui-preference="glass".*?</select>', page, re.DOTALL)
    assert control, "Glass effects is missing from Display preferences"
    control = control.group(0)
    assert 'id="glass-select"' in control
    assert re.findall(r'<option value="(\w+)"', control) == ["off", "on"]
    assert re.search(r'<option value="off" selected', control)
    assert page.index('data-ui-preference="theme"') < page.index('data-ui-preference="glass"')


def test_a_device_only_choice_is_kept_on_this_device_and_bad_values_are_refused():
    client = _client()
    page = client.get("/overview").text
    context = re.search(r'name="lightwork-preference-context" content="([^"]*)"', page).group(1)
    saved = client.post("/api/v1/preferences/display",
                        json={"key": "glass", "value": "on", "context": context, "device_only": True})
    assert saved.status_code == 200, saved.text
    assert "mvk_glass=on" in saved.headers.get("set-cookie", "")
    assert "glass-on" in _body_classes(client.get("/overview").text)
    refused = client.post("/api/v1/preferences/display",
                          json={"key": "glass", "value": "sparkle", "context": context, "device_only": True})
    assert refused.status_code == 422


def test_an_account_choice_follows_the_person_and_policy_can_require_it(monkeypatch):
    from maverick_dashboard import auth, preferences_api, product_operations_preferences
    from maverick_dashboard import settings_catalog as catalog

    assert "glass" in preferences_api.PROFILE_FIELDS
    assert "glass" in product_operations_preferences.KEYS
    # The choice list is built from the caller's current Chat choices; glass is fixed.
    current = {"chat_specialists": [], "chat_models": [], "values": {"chat_model": ""}}
    assert dict(product_operations_preferences._choices(current)["glass"]) == {"off": "Off", "on": "On"}
    # Organization policy can require it like any presentation preference.
    required = catalog.BY_ID["personalization.defaults.glass"]
    assert required.control == "select" and [v for v, _ in required.choices] == ["off", "on"]

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:alice")
    client = _client()
    page = client.get("/preferences")
    assert page.status_code == 200, page.text[:300]
    assert 'id="preference-glass"' in page.text
    state = client.get("/api/v1/preferences").json()
    assert (state["values"]["glass"], state["sources"]["glass"]) == ("off", "product default")
    saved = client.post("/api/v1/preferences", json={
        "expected_revision": state["revision"], "context": state["context"],
        "scope": "personal", "changes": {"glass": "on"}})
    assert saved.status_code == 200, saved.text
    assert (saved.json()["values"]["glass"], saved.json()["sources"]["glass"]) == ("on", "personal")
    refused = client.post("/api/v1/preferences", json={
        "expected_revision": saved.json()["revision"], "context": state["context"],
        "scope": "personal", "changes": {"glass": "sparkle"}})
    assert refused.status_code == 422


def test_installation_default_is_a_settings_row_known_to_config_lint():
    from maverick.config_lint import KNOWN_SCHEMA
    from maverick_dashboard import settings_catalog as catalog

    row = catalog.BY_ID["dashboard.glass"]
    assert row.control == "select" and row.default == "off"
    assert [value for value, _ in row.choices] == ["off", "on"]
    assert row.reader == "maverick_dashboard.app"
    assert "glass" in KNOWN_SCHEMA["dashboard"]
