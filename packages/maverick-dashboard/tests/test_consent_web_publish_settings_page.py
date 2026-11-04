from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import consent_web_publish_settings_page as page

ROUTE = "/consent/publish-settings"
PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from maverick_dashboard.app import _theme_context

    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: True)
    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(
        nav_groups=[],
    )
    app = FastAPI()
    app.include_router(page.create_consent_web_publish_settings_page_router(templates))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_store_free_liquid_glass_and_candid(client: TestClient) -> None:
    response = client.get(ROUTE)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-frame-options"] == "DENY"
    csp = response.headers["content-security-policy"]
    for directive in (
        "default-src 'none'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "script-src 'self'",
        "style-src 'self' 'nonce-",
    ):
        assert directive in csp
    for text in (
        "Website banner settings",
        "About this page’s safeguards",
        "never asks for or stores your site’s one-time security codes",
        "stop being used until you save them again",
    ):
        assert text in response.text
    assert 'id="publish-settings-operations" disabled' in response.text


def test_page_has_all_named_closed_settings_and_no_authority_inputs(
    client: TestClient,
) -> None:
    response = client.get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    fields = {
        value
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"}
        for name in ("id", "name")
        if isinstance((value := attrs.get(name)), str)
    }
    # Region rows for asking again are added by the page script.
    source = (PACKAGE / "static" / "lightwork-consent-publish-settings.js").read_text(
        encoding="utf-8"
    )
    assert 'whereSelect.name = "geolocation_reconsent"' in source
    assert {
        "sdk_version",
        "analytics_tracking_enabled",
        "analytics_category_assignments",
        "common_trackers",
        "cookie_same_site",
        "cookie_domain_separation",
        "spa_reload_on_route_change",
        "csp_nonce_required",
        "automatic_refresh_seconds",
    }.issubset(fields)
    for selected in fields:
        for forbidden in (
            "tenant",
            "principal",
            "property_revision",
            "property_sha256",
            "publication_revision",
            "publication_sha256",
            "bundle_sha256",
            "retention",
            "nonce_value",
        ):
            assert forbidden not in selected.lower()
    scripts = [attrs.get("src") for tag, attrs in parser.tags if tag == "script"]
    assert "/static/lightwork-consent-publish-settings.js" in scripts


@pytest.mark.parametrize(
    ("allowed", "admin_disabled", "audit_disabled"),
    (
        (frozenset(), True, True),
        (frozenset({"admin"}), False, True),
        (frozenset({"audit"}), True, False),
        (frozenset({"admin", "audit"}), False, False),
    ),
)
def test_page_server_renders_exact_role_controls(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    allowed: frozenset[str],
    admin_disabled: bool,
    audit_disabled: bool,
) -> None:
    monkeypatch.setattr(
        page, "has_permission", lambda _request, permission: permission in allowed
    )
    response = client.get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    by_id = {
        attrs["id"]: attrs
        for _tag, attrs in parser.tags
        if isinstance(attrs.get("id"), str)
    }
    for control in (
        "publish-settings-create-controls",
        "publish-settings-new",
        "publish-settings-withdraw",
    ):
        assert ("disabled" in by_id[control]) is admin_disabled
    assert (
        "disabled" in by_id["publish-settings-audit-controls"]
    ) is audit_disabled


def test_page_rejects_query_material_and_requires_tenant(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert client.get(f"{ROUTE}?property_id=caller-selected").status_code == 404

    def missing() -> None:
        raise page.HTTPException(
            status_code=409,
            detail="select an active tenant before using web publish settings",
        )

    monkeypatch.setattr(page, "_tenant_selected", missing)
    assert client.get(ROUTE).status_code == 409


def test_page_client_is_bounded_and_has_no_browser_injection_channels() -> None:
    source = (PACKAGE / "static" / "lightwork-consent-publish-settings.js").read_text(
        encoding="utf-8"
    )
    for forbidden in (
        "localStorage",
        "sessionStorage",
        "document.cookie",
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "tenant_id",
        "principal_ref",
        "property_revision",
        "property_sha256",
        "publication_revision",
        "publication_sha256",
        "csp_nonce_value",
    ):
        assert forbidden not in source
    for required in (
        "64 * 1024",
        "512 * 1024",
        "TextEncoder",
        "response.body.getReader",
        'cache: "no-store"',
        'credentials: "same-origin"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        "operations.disabled = true",
        "operations.disabled = false",
        "textContent",
    ):
        assert required in source


def test_page_assets_are_packaged() -> None:
    for relative in (
        "templates/consent_publish_settings.html",
        "static/lightwork-consent-publish-settings.js",
    ):
        selected = PACKAGE / relative
        assert selected.is_file()
        assert selected.stat().st_size > 100


def test_page_lists_versions_with_row_buttons_and_speaks_plainly(client: TestClient) -> None:
    from test_support.plain_language import developer_terms

    page_html = client.get(ROUTE).text
    source = (PACKAGE / "static" / "lightwork-consent-publish-settings.js").read_text(
        encoding="utf-8"
    )
    # The website is chosen from a list; versions load as rows with buttons.
    assert '<select class="select" id="publish-settings-property-id">' in page_html
    assert 'id="publish-settings-versions-table"' in page_html
    for label in ('"Make live"', '"Go back to this"', "New settings", "Turn settings off"):
        assert label in page_html + source
    # Revisions and request references are carried, never typed.
    assert 'type="hidden" id="publish-settings-expected-revision"' in page_html
    assert 'name="idempotency_key" data-auto-reference' in page_html
    for typed in ("Web property reference", "Settings version reference", "SDK version</label>",
                  "google_analytics=analytics", "US=365", "SameSite"):
        assert typed not in page_html
    assert source.count("CW.confirm(") >= 1 and "lifecycle(button" in source
    assert developer_terms(page_html) == []
