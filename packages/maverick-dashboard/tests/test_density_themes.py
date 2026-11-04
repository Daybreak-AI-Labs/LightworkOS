"""Adaptive UI density (?density= / mvk_density) + pluggable operator themes."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import themes as themes_mod
from maverick_dashboard.app import app, resolve_density

client = TestClient(app, base_url="http://127.0.0.1")


class _Req:
    def __init__(self, q=None, c=None):
        self.query_params = {"density": q} if q else {}
        self.cookies = {"mvk_density": c} if c else {}


# ----------------------------- density -----------------------------


def test_resolve_density_param_cookie_default():
    assert resolve_density(_Req(q="compact")) == "compact"
    assert resolve_density(_Req(c="compact")) == "compact"
    assert resolve_density(_Req(q="comfortable", c="compact")) == "comfortable"
    assert resolve_density(_Req()) == "comfortable"
    assert resolve_density(_Req(q="dense")) == "comfortable"  # bogus -> default


def test_resolve_density_config_fallback(monkeypatch):
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: {"dashboard": {"density": "compact"}})
    assert resolve_density(_Req()) == "compact"


def test_density_param_sets_body_class_and_cookie():
    # ``/`` may redirect an unconfigured deployment through onboarding; use
    # a stable page when asserting the final response's Set-Cookie header.
    r = client.get("/overview", params={"density": "compact"})
    assert r.status_code == 200
    assert "density-compact" in r.text
    assert "mvk_density=compact" in r.headers.get("set-cookie", "")
    # Bogus values: no cookie, default class.
    fresh = TestClient(app, base_url="http://127.0.0.1")
    r2 = fresh.get("/overview", params={"density": "supertight"})
    assert "mvk_density" not in r2.headers.get("set-cookie", "")
    assert "density-comfortable" in r2.text


def test_compact_css_ships_in_stylesheet():
    # The design system lives in the extracted stylesheet (linked by base.html),
    # not inline in the page.
    css = client.get("/static/lightwork.css").text
    assert "body.density-compact" in css
    r = client.get("/")
    assert '/static/lightwork.css' in r.text
    assert 'id="density-select"' in r.text


# ----------------------------- pluggable themes -----------------------------

_GOOD = {"bg": "#101020", "panel": "#181830", "text": "#e0e0f0", "accent": "#7aa2f7"}


def _with_themes(monkeypatch, themes: dict):
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", lambda: {"dashboard": {"themes": themes}})


def test_custom_themes_validation(monkeypatch):
    _with_themes(monkeypatch, {
        "midnight": _GOOD,
        "shorthex": {**_GOOD, "accent": "#fff"},                      # 3-digit hex OK
        "badhex": {**_GOOD, "bg": "red"},                             # not #hex
        "inject": {**_GOOD, "bg": "#fff; } body { background: url(x)"},  # CSS injection
        "dark": _GOOD,                                                # shadows builtin
        "Bad Name!": _GOOD,                                           # invalid slug
        "missing": {"bg": "#000", "panel": "#111", "text": "#fff"},   # no accent
        "extras": {**_GOOD, "sneaky": "#000"},                        # unknown key
    })
    out = themes_mod.custom_themes()
    assert set(out) == {"midnight", "shorthex"}


def test_theme_css_renders_validated_variables():
    css = themes_mod.theme_css({"midnight": _GOOD})
    assert css == ("body.theme-midnight { --bg: #101020; --panel: #181830; "
                   "--text: #e0e0f0; --accent: #7aa2f7; --border: #e0e0f0; "
                   "--muted: #e0e0f0; --warn: #e0e0f0; --danger: #e0e0f0; }")


def test_custom_theme_selectable_like_builtins(monkeypatch):
    _with_themes(monkeypatch, {"midnight": _GOOD})
    r = client.get("/overview", params={"theme": "midnight"})
    assert r.status_code == 200
    assert "theme-midnight" in r.text                       # body class
    assert "--bg: #101020" in r.text                        # CSS vars block
    assert 'value="midnight"' in r.text                     # switcher option
    assert "mvk_theme=midnight" in r.headers.get("set-cookie", "")


def test_unknown_theme_still_falls_back_to_dark(monkeypatch):
    _with_themes(monkeypatch, {"midnight": _GOOD})
    fresh = TestClient(app, base_url="http://127.0.0.1")
    r = fresh.get("/", params={"theme": "nope"})
    assert "theme-dark" in r.text
    assert "mvk_theme" not in r.headers.get("set-cookie", "")


def test_no_config_themes_is_default_off(monkeypatch):
    import maverick.config as cfg
    monkeypatch.setattr(cfg, "load_config", dict)
    assert themes_mod.custom_themes() == {}
    fresh = TestClient(app, base_url="http://127.0.0.1")
    r = fresh.get("/")
    assert "body.theme-midnight" not in r.text


@pytest.fixture
def dashboard_client(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    from maverick.world_model import WorldModel
    w = WorldModel(tmp_path / "world.db")
    w.create_goal("hello", "")
    from maverick_dashboard import app as app_mod
    monkeypatch.setattr(app_mod, "_world", lambda: w)
    yield TestClient(app_mod.app, base_url="http://127.0.0.1")
    w.close()


def _body_classes(html):
    body = re.search(r'<body\b[^>]*\bclass="([^"]*)"', html)
    assert body is not None
    return body.group(1).split()


def test_dashboard_default_theme_is_dark(dashboard_client):
    resp = dashboard_client.get("/")
    assert resp.status_code == 200
    assert "theme-dark" in _body_classes(resp.text)


@pytest.mark.parametrize("theme", ["dark", "light", "solarized", "hicontrast"])
def test_dashboard_theme_query_param(dashboard_client, theme):
    resp = dashboard_client.get(f"/?theme={theme}")
    assert resp.status_code == 200
    assert f"theme-{theme}" in _body_classes(resp.text)


def test_dashboard_invalid_theme_falls_back(dashboard_client):
    resp = dashboard_client.get("/?theme=garbage-not-a-theme")
    assert resp.status_code == 200
    # Falls back to dark (the default).
    assert "theme-dark" in _body_classes(resp.text)


def test_dashboard_theme_cookie_persists(dashboard_client):
    # Use a non-redirecting page so the response being inspected is the one
    # that persists the preference. ``/`` may first redirect to onboarding.
    resp = dashboard_client.get("/overview?theme=light")
    assert resp.status_code == 200
    cookies = resp.cookies
    assert cookies.get("mvk_theme") == "light"
    # The client cookie jar should carry the server-set value into the next
    # request; passing per-request cookies is deprecated and bypasses that
    # persistence behavior.
    resp2 = dashboard_client.get("/overview")
    assert "theme-light" in _body_classes(resp2.text)


def test_dashboard_theme_switcher_options_in_header(dashboard_client):
    """The 4-coloured-dots switcher was replaced with a single
    ``<select>`` element (accessibility + cleaner UI). All four themes
    must still be present as options."""
    resp = dashboard_client.get("/")
    body = resp.text
    for theme in ("dark", "light", "solarized", "hicontrast"):
        # Either as the new <option value="X"> or, transitionally, as
        # a hand-coded link still in the header.
        assert (f'value="{theme}"' in body) or (f"?theme={theme}" in body), (
            f"theme {theme} not exposed via the theme switcher"
        )
