from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import consent_application_scanner_page as page

ROUTE = "/consent/application-scans"
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

    monkeypatch.setattr(page, "current_tenant_id_strict", lambda: "tenant-a")
    monkeypatch.setattr(page, "require_permission", lambda *_args: None)
    monkeypatch.setattr(page, "has_permission", lambda *_args: True)
    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(
        nav_groups=[],
    )
    app = FastAPI()
    app.include_router(page.create_consent_application_scanner_page_router(templates))
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
    page = response.text
    assert "App tracking checks" in page
    assert 'id="cas-operations" disabled' in page
    assert 'data-copilot-page="/consent/application-scans"' in page
    assert "/static/lightwork-consent-workbench.js" in page
    assert "/static/lightwork-consent-application-scanner.js" in page
    # Apps and results are lists with row buttons; nothing is typed that a
    # person cannot know.
    assert 'id="cas-apps"' in page and 'id="cas-scans"' in page
    for label in ("Add an app", "Check files", "Save review", "Delete expired results",
                  "Check that records are intact", "About this page’s safeguards"):
        assert label in page
    for typed in ("Application ID", "Expected application revision", "Scan ID",
                  "Expected scan revision", "Review note code", "Operation output"):
        assert typed not in page
    assert '<select class="select" name="review_note_code" required>' in page
    assert 'data-module-gate="consent_preferences.application_scanner"' in page
    from test_support.plain_language import developer_terms

    assert developer_terms(page) == []


def test_forms_expose_no_tenant_actor_or_raw_authority_selector(client: TestClient) -> None:
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
        "platform",
        "bundle_id",
        "display_name",
        "application_id",
        "expected_application_revision",
        "files",
        "scan_id",
        "expected_revision",
        "decision",
        "review_note_code",
    }.issubset(controls)
    hidden = {
        attrs.get("name")
        for tag, attrs in parser.tags
        if tag == "input" and attrs.get("type") == "hidden"
    }
    # Identifiers and versions ride along from the chosen row, never typed.
    assert {"application_id", "expected_application_revision", "scan_id",
            "expected_revision"} <= hidden
    for selector in controls:
        for forbidden in (
            "tenant_id",
            "actor",
            "principal",
            "client_credential",
            "raw_manifest",
            "subject_id",
        ):
            assert forbidden not in selector.lower()


def test_bounded_script_has_no_browser_persistence_or_html_injection() -> None:
    source = (PACKAGE / "static" / "lightwork-consent-application-scanner.js").read_text(
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
        "actor",
        "principal",
        "HTTP ",
        "JSON.stringify(value, null, 2)",
        "window.confirm",
    ):
        assert forbidden not in source
    for required in (
        "MAX_REQUEST_BYTES = 6 * 1024 * 1024",
        "MAX_RESPONSE_BYTES = 2 * 1024 * 1024",
        "MAX_TOTAL_FILE_BYTES = 4 * 1024 * 1024",
        'credentials: "same-origin"',
        'cache: "no-store"',
        'referrerPolicy: "no-referrer"',
        "TextEncoder",
        "TextDecoder",
        "reader.cancel()",
        "arrayBuffer()",
        "btoa(",
        "textContent",
        "encodeURIComponent",
        "operations.disabled = true",
        'call("/readiness", undefined, [503])',
        "CW.confirm(",
        'window.mvForm("Remove "',
    ):
        assert required in source


def test_custom_theme_style_is_bound_to_the_page_csp_nonce(monkeypatch) -> None:
    import maverick.config as config
    from maverick_dashboard.app import _theme_context

    monkeypatch.setattr(config, "load_config", lambda: {
        "dashboard": {"theme": "custom", "themes": {"custom": {
            "bg": "#101010", "panel": "#111", "text": "#fff", "accent": "#0f0",
        }}},
    })
    monkeypatch.setattr(page, "current_tenant_id_strict", lambda: "tenant-a")
    monkeypatch.setattr(page, "require_permission", lambda *_args: None)
    monkeypatch.setattr(page, "has_permission", lambda *_args: True)
    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(
        nav_groups=[],
    )
    app = FastAPI()
    app.include_router(page.create_consent_application_scanner_page_router(templates))
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(ROUTE)
    assert response.status_code == 200
    nonce_match = re.search(r'<style nonce="([A-Za-z0-9_-]+)">', response.text)
    assert nonce_match is not None
    assert "body.theme-custom { --bg: #101010;" in response.text
    assert (
        f"style-src 'self' 'nonce-{nonce_match.group(1)}'"
        in response.headers["content-security-policy"]
    )


def test_page_rejects_unknown_query_keys(client: TestClient) -> None:
    assert client.get(f"{ROUTE}?tenant=tenant-a").status_code == 404
