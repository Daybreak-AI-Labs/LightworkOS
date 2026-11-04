from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import consent_global_opt_out_page as page

ROUTE = "/consent/global-opt-out"
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

    monkeypatch.setattr(page, "current_tenant_id_strict", lambda: "alpha")
    monkeypatch.setattr(
        page,
        "require_global_permission",
        lambda _request, _permission: None,
    )
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, _permission: True,
    )
    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(
        nav_groups=[],
    )
    app = FastAPI()
    app.include_router(page.create_consent_global_opt_out_page_router(templates))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_workbench_is_store_free_closed_and_liquid_glass(client: TestClient) -> None:
    response = client.get(ROUTE)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    csp = response.headers["content-security-policy"]
    for directive in (
        "default-src 'none'",
        "connect-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    ):
        assert directive in csp
    assert "Opt out everywhere" in response.text
    assert "as an opt-out request" in response.text
    assert "keeps only a fingerprint of each request" in response.text
    assert 'id="goo-operations" disabled' in response.text
    assert 'data-copilot-page="/consent/global-opt-out"' in response.text
    # Shared design system only: no per-page theme stylesheet.
    assert "/static/lightwork-consent-global-opt-out.css" not in response.text
    assert "/static/lightwork-consent-workbench.css" in response.text
    assert "/static/lightwork-consent-global-opt-out.js" in response.text


def test_workbench_forms_have_no_tenant_profile_or_raw_case_selector(client: TestClient) -> None:
    response = client.get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    forms = [attrs for tag, attrs in parser.tags if tag == "form"]
    controls = {
        value
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"}
        for name in ("id", "name")
        if isinstance((value := attrs.get(name)), str)
    }
    assert forms and all("action" not in item for item in forms)
    assert {
        "application_ref",
        "configuration_id",
        "expected_revision",
        "idempotency_key",
        "mobile_title",
        "email_title",
        "supported_devices",
        "supported_services",
    }.issubset(controls)
    for selector in controls:
        for forbidden in (
            "tenant_id",
            "profile_id",
            "client_credential",
            "origin",
            "service_client_id",
            "policy_id",
            "case_id",
            "case_payload",
        ):
            assert forbidden not in selector.lower()


def test_bounded_script_has_no_browser_persistence_or_html_injection() -> None:
    source = (
        PACKAGE / "static" / "lightwork-consent-global-opt-out.js"
    ).read_text(encoding="utf-8")
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
        "profile_id",
        "client_credential",
        "case_id",
    ):
        assert forbidden not in source
    for required in (
        "MAX_REQUEST_BYTES = 64 * 1024",
        "MAX_RESPONSE_BYTES = 256 * 1024",
        'credentials: "same-origin"',
        'cache: "no-store"',
        'referrerPolicy: "no-referrer"',
        "TextEncoder",
        "textContent",
        "encodeURIComponent",
        "operations.disabled = true",
    ):
        assert required in source


def test_page_rejects_unknown_query_keys(client: TestClient) -> None:
    response = client.get(f"{ROUTE}?tenant=alpha")
    assert response.status_code == 404


def test_workbench_lists_set_ups_with_row_buttons_and_speaks_plainly(client: TestClient) -> None:
    from test_support.plain_language import developer_terms

    page_html = client.get(ROUTE).text
    source = (PACKAGE / "static" / "lightwork-consent-global-opt-out.js").read_text(encoding="utf-8")
    assert '<select class="select" id="goo-application-ref" name="application_ref" required>' in page_html
    assert 'type="date"' in page_html
    for label in ('label: "Edit"', 'label: "Switch on"', 'label: "Switch off"', 'label: "History"'):
        assert label in source
    assert "expected_revision: item.revision" in source
    assert source.count("CW.confirm(") >= 2
    for typed in ("Public client ID", "Unix timestamp", "Expected record revision", "Configuration ID"):
        assert typed not in page_html
    assert developer_terms(page_html) == []


def test_turned_off_feature_shows_the_standard_banner(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    from maverick_dashboard import module_activation

    monkeypatch.setattr(module_activation, "_module_switch_enabled", lambda _loaded, _section: False)
    off = client.get(ROUTE).text
    assert 'data-module-gate="consent_preferences.global_opt_out"' in off
    assert "Global opt-out is turned off." in off
    # The banner is the whole availability story: no check repeats it in red
    # below and no loader is left saying "Loading".
    main = off[off.index('id="global-opt-out-shell"'):off.index("<noscript>")]
    assert 'data-module-enabled="false"' in main
    assert '<p id="goo-runtime-status" class="muted" role="status" aria-live="polite" hidden></p>' in main
    assert "Loading" not in main and "Checking" not in main
    assert "Opt-out set-ups appear here once this is turned on." in main
    monkeypatch.setattr(module_activation, "_module_switch_enabled", lambda _loaded, _section: True)
    on = client.get(ROUTE).text
    assert "data-module-gate=" not in on
    assert 'data-module-enabled="true"' in on and "Loading…" in on


def test_global_opt_out_switch_is_registered_and_writable() -> None:
    from maverick_dashboard import api, settings_store

    for section in ("consent_preferences.global_opt_out",
                    "consent_preferences.profile_data.custom_index",
                    "consent_preferences.publishing.web_settings"):
        assert section in api._MODULE_SWITCHES
        assert section in settings_store.MODULE_ENABLE_PATHS
        for parent in api._MODULE_SWITCHES[section]["requires"]:
            assert parent in settings_store.MODULE_ENABLE_PATHS
