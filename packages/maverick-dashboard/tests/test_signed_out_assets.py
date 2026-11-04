"""Signed-out pages load every file they reference without a sign-in.

The sign-in page, owner setup, invitation acceptance, the public rights-request
form, the vendor questionnaire, shared results and the sign-in error page are
read by people who have no session yet. With named sign-in on, every
stylesheet, script, image and font those pages use must load without
credentials, or the page renders unstyled (the shell stylesheet once answered
401 here). Everything else under ``/static/`` stays behind sign-in.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TOKEN = "signed-out-assets-test-token"  # pragma: allowlist secret
_REF = re.compile(r"""asset\('([^']+)'\)|static_url\('([^']+)'\)|["'](/static/[^"'?#\s]+)""")
_CSS_URL = re.compile(r"url\(\s*['\"]?(/static/[^'\")?#\s]+)")
# Templates people see before they have a session. Every template that extends
# the public shell is included automatically, so a new public page is covered.
_STANDALONE = ("public_base.html", "shared_goal.html", "auth_error.html", "invite_accept.html")


def _templates_dir() -> Path:
    import maverick_dashboard

    return Path(maverick_dashboard.__file__).parent / "templates"


def _signed_out_templates() -> list[Path]:
    folder = _templates_dir()
    found = {folder / name for name in _STANDALONE if (folder / name).exists()}
    for path in folder.glob("*.html"):
        if path.read_text(encoding="utf-8").lstrip().startswith('{% extends "public_base.html" %}'):
            found.add(path)
    return sorted(found)


def _refs(text: str) -> set[str]:
    out = set()
    for match in _REF.finditer(text):
        name = match.group(1) or match.group(2)
        out.add("/static/" + name if name else match.group(3))
    return out


@pytest.fixture
def isolated(monkeypatch, tmp_path):
    from maverick import config, world_model

    for name in ("MAVERICK_DASHBOARD_TOKEN", "LIGHTWORK_DASHBOARD_TOKEN",
                 "MAVERICK_DASHBOARD_INVITES", "LIGHTWORK_DASHBOARD_INVITES",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    config.reset_config_cache()
    yield monkeypatch
    config.reset_config_cache()


def _anonymous():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1")  # no bearer, no cookie, no Origin: a signed-out visitor


def _all_referenced_assets() -> set[str]:
    assets: set[str] = set()
    for path in _signed_out_templates():
        assets |= _refs(path.read_text(encoding="utf-8"))
    return assets


def _with_stylesheet_urls(client, assets: set[str]) -> set[str]:
    expanded = set(assets)
    for asset in assets:
        if asset.endswith(".css"):
            expanded |= set(_CSS_URL.findall(client.get(asset).text))
    return expanded


def test_the_signed_out_template_list_is_real():
    names = {path.name for path in _signed_out_templates()}
    assert {"public_base.html", "local_owner.html", "rights_form.html",
            "shared_goal.html", "auth_error.html"} <= names
    assets = _all_referenced_assets()
    assert "/static/lightwork.css" in assets and "/static/daybreak-logo.jpg" in assets


@pytest.mark.parametrize("mode", ["dashboard token", "named sign-in"])
def test_every_asset_a_signed_out_page_uses_loads_without_credentials(isolated, mode):
    if mode == "dashboard token":
        isolated.setenv("MAVERICK_DASHBOARD_TOKEN", TOKEN)
    else:
        isolated.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    client = _anonymous()
    assert client.get("/goals").status_code == 401  # ordinary pages stay gated
    assets = _with_stylesheet_urls(client, _all_referenced_assets())
    assert any("/fonts/" in asset for asset in assets)  # the stylesheet's own fonts
    failures = {asset: client.get(asset).status_code for asset in sorted(assets)}
    assert {asset: code for asset, code in failures.items() if code != 200} == {}


@pytest.mark.parametrize("mode", ["dashboard token", "named sign-in"])
def test_files_only_signed_in_pages_use_still_need_a_sign_in(isolated, mode):
    if mode == "dashboard token":
        isolated.setenv("MAVERICK_DASHBOARD_TOKEN", TOKEN)
    else:
        isolated.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    client = _anonymous()
    for path in ("/static/lightwork-ui.js", "/static/lightwork-copilot.js",
                 "/static/lightwork-guided-actions.css", "/static/lightwork-settings-admin.js",
                 "/api/v1/features/modules"):
        assert client.get(path).status_code == 401, path


def test_both_gates_exempt_exactly_the_same_public_files():
    from maverick_dashboard import app as app_module
    from maverick_dashboard import auth

    middleware = {path for path in app_module._AUTH_EXEMPT if path.startswith("/static/")}
    assert middleware == set(auth.PUBLIC_STATIC_PATHS)
    assert all(auth._self_authenticated_path(path) for path in middleware)
    # Only files: no folder prefix may open a whole directory.
    assert all("." in path.rsplit("/", 1)[-1] for path in middleware)
    assert not auth._self_authenticated_path("/static/lightwork-ui.js")


def test_rendered_sign_in_page_uses_only_public_files(isolated):
    """Render the real page for a claimed owner, then fetch what it uses."""
    from maverick_dashboard.app import app

    options = dict(base_url="http://127.0.0.1:8765", client=("127.0.0.1", 53210),
                   follow_redirects=False)
    with TestClient(app, **options) as browser:
        owner = browser.post("/auth/local-owner", headers={"Origin": "http://127.0.0.1:8765"},
                             data={"email": "owner@example.com",
                                   "password": "a long local owner fixture phrase",  # pragma: allowlist secret
                                   "password2": "a long local owner fixture phrase",  # pragma: allowlist secret
                                   "confirm": "yes"})
        assert owner.status_code == 303, owner.text
        browser.cookies.clear()
        page = browser.get("/auth/local-login")
        assert page.status_code == 200
        assets = _refs(page.text)
        assert "/static/lightwork.css" in assets
        assert {asset: browser.get(asset).status_code for asset in assets} == dict.fromkeys(assets, 200)


@pytest.fixture
def rights_form(monkeypatch, tmp_path):
    """The public rights form switched on, with one property, as an admin left it."""
    from maverick import audit, config, world_model
    from maverick import public_rights_form as prf

    for name in ("MAVERICK_DASHBOARD_TOKEN", "LIGHTWORK_DASHBOARD_TOKEN",
                 "MAVERICK_DASHBOARD_INVITES", "LIGHTWORK_DASHBOARD_INVITES",
                 "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_TENANT", "MAVERICK_CONFIG_OVERLAY"):
        monkeypatch.delenv(name, raising=False)
    cfg = tmp_path / "config.toml"
    cfg.write_text("[privacy_ops]\nenable = true\n\n[privacy_automation]\nenable = true\n\n"
                   "[privacy_automation.public_rights_form]\nenable = true\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr(audit, "record", lambda *_a, **_k: True)
    monkeypatch.setattr(audit, "record_global", lambda *_a, **_k: True)
    config.reset_config_cache()
    prf.upsert_property("shop", {
        "name": "Acme Shop", "organisation": "Acme Ltd", "contact_email": "privacy@acme.example",
        "jurisdictions": ["eu_gdpr"], "default_jurisdiction": "eu_gdpr",
        "request_types": ["access", "deletion"], "allowed_origins": [],
    }, actor="test")
    yield monkeypatch
    config.reset_config_cache()


def test_public_rights_form_says_what_it_is(rights_form):
    client = _anonymous()
    for path in ("/rights/shop", "/rights/no-such-form", "/rights/verify/unknown"):
        html = client.get(path).text
        assert "Privacy request" in html, path
        assert "questionnaire" not in html.lower(), path
        assert "vendor" not in html.lower(), path


def test_public_rights_form_loads_its_files_with_named_sign_in_on(rights_form):
    rights_form.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    client = _anonymous()
    assert client.get("/goals").status_code == 401
    page = client.get("/rights/shop")
    assert page.status_code == 200
    assets = _refs(page.text)
    assert "/static/lightwork.css" in assets
    assert {asset: client.get(asset).status_code for asset in assets} == dict.fromkeys(assets, 200)


@pytest.mark.parametrize("mode", ["dashboard token", "named sign-in"])
def test_a_dead_share_link_shows_a_public_page_not_the_app(isolated, mode):
    """A recipient of an expired or revoked link has no account: they get a
    plain, styled explanation, never the signed-in app shell."""
    if mode == "dashboard token":
        isolated.setenv("MAVERICK_DASHBOARD_TOKEN", TOKEN)
    else:
        isolated.setenv("MAVERICK_DASHBOARD_INVITES", "1")
    client = _anonymous()
    page = client.get("/share/not-a-real-token", headers={"Accept": "text/html"})
    assert page.status_code == 404
    assert "This shared result is not available" in page.text
    assert "Ask the person who shared it" in page.text
    assert 'id="sidebar"' not in page.text and "Start a task" not in page.text
    assets = _refs(page.text)
    assert "/static/lightwork.css" in assets
    assert {asset: client.get(asset).status_code for asset in assets} == dict.fromkeys(assets, 200)


@pytest.mark.parametrize("reason", ["", "mfa", "store"])
def test_sign_in_error_pages_use_the_public_shell(isolated, monkeypatch, reason):
    """Someone whose company sign-in failed has no session: the page is the
    styled public shell, never the signed-in app (and keeps its plain words)."""
    from maverick_dashboard import oidc_login

    monkeypatch.setattr(oidc_login, "login_enabled", lambda: True)
    page = _anonymous().get("/auth/error" + (f"?reason={reason}" if reason else ""),
                            headers={"Accept": "text/html"})
    assert page.status_code == (403 if reason else 401)
    assert "/static/lightwork.css" in page.text and 'class="brand__logo"' in page.text
    assert 'id="sidebar"' not in page.text and "Start a task" not in page.text
    expected = {"": "Restart sign-in", "mfa": "include a second factor",
                "store": "could not record this sign-in"}[reason]
    assert expected in page.text
    assert page.headers["cache-control"] == "no-store"
