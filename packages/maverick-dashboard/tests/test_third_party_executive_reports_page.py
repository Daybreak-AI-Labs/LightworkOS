from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import third_party_executive_reports_page as page

PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


class Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    selected.env.globals.update(
        nav_groups=[],
    )
    return selected


def client(monkeypatch, permissions=frozenset({"view", "operate", "audit", "admin"})):
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(
        page,
        "has_permission",
        lambda _request, permission: permission in permissions,
    )
    app = FastAPI()
    app.include_router(page.create_third_party_executive_reports_page_router(templates()))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_store_free_private_csp_closed_and_copilot_enabled(monkeypatch) -> None:
    response = client(monkeypatch).get("/third-party/executive-reports")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "style-src 'self' 'nonce-" in response.headers["content-security-policy"]
    assert "Executive vendor reports" in response.text
    assert 'src="/static/lightwork-record-workflows.js"' in response.text
    assert 'data-api-base="/api/v1/third-party/executive-reports"' in response.text
    assert 'data-copilot-page="/third-party/executive-reports"' in response.text
    assert 'src="/static/lightwork-third-party-executive-reports.js"' in response.text
    parser = Markup()
    parser.feed(response.text)
    nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]
    assert len(nonces) == 1 and nonces[0]
    assert f"'nonce-{nonces[0]}'" in response.headers["content-security-policy"]


def test_page_never_collects_server_derived_authorities_or_executable_branding(
    monkeypatch,
) -> None:
    response = client(monkeypatch).get("/third-party/executive-reports")
    parser = Markup()
    parser.feed(response.text)
    names = {
        value
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"}
        if isinstance((value := attrs.get("name")), str)
    }
    for required in (
        "organization_name",
        "report_title",
        "footer_text",
        "primary_color",
        "accent_color",
        "text_color",
        "report",
        "reason_code",
    ):
        assert required in names
    for forbidden in (
        "selectors_json",
        "report_id",
        "brand_asset_metadata_ref",
        "brand_asset_metadata_sha256",
        "expected_control_revision",
        "idempotency_key",
        "limit",
        "tenant_id",
        "principal_ref",
        "actor_ref",
        "role_view",
        "html",
        "css",
        "logo_url",
        "logo_asset_ref",
        "logo_sha256",
        "credential",
        "storage_path",
    ):
        assert forbidden not in names


def test_page_renders_exact_role_controls_and_rejects_query_material(monkeypatch) -> None:
    selected = client(monkeypatch, frozenset({"view"}))
    response = selected.get("/third-party/executive-reports")
    parser = Markup()
    parser.feed(response.text)
    by_id = {
        attrs["id"]: attrs
        for _tag, attrs in parser.tags
        if isinstance(attrs.get("id"), str)
    }
    assert "disabled" in by_id["tper-create-controls"]
    assert by_id["tper-create-controls"]["data-authorized"] == "false"
    assert "disabled" in by_id["tper-revoke-controls"]
    assert "disabled" in by_id["tper-purge-controls"]
    assert "disabled" in by_id["tper-integrity"]
    assert selected.get(
        "/third-party/executive-reports?tenant_id=caller-selected"
    ).status_code == 404
    assert selected.get("/third-party/executive-reports?theme=light").status_code == 200


def test_static_bearer_page_exposes_operator_controls_only(monkeypatch) -> None:
    selected = client(monkeypatch)
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "executive-report-secret")
    response = selected.get(
        "/third-party/executive-reports",
        headers={"Authorization": "Bearer executive-report-secret"},
    )
    assert response.status_code == 200
    parser = Markup()
    parser.feed(response.text)
    by_id = {
        attrs["id"]: attrs
        for _tag, attrs in parser.tags
        if isinstance(attrs.get("id"), str)
    }
    # Mutation controls start disabled in server-rendered markup. The bounded
    # client may enable only this authorized control after both the module gate
    # and the store-free runtime readiness response are true.
    assert "disabled" in by_id["tper-create-controls"]
    assert by_id["tper-create-controls"]["data-authorized"] == "true"
    assert "disabled" in by_id["tper-download-controls"]
    assert by_id["tper-download-controls"]["data-authorized"] == "true"
    assert "disabled" in by_id["tper-revoke-controls"]
    assert "disabled" in by_id["tper-purge-controls"]
    assert "disabled" in by_id["tper-integrity"]
    assert "Reports are plain text and your chosen colors only" in response.text


def test_page_speaks_plainly(monkeypatch) -> None:
    from test_support.plain_language import developer_terms

    response = client(monkeypatch).get("/third-party/executive-reports")
    assert developer_terms(response.text) == []
    for gone in ("TPM-18", "Evidence boundary", "SHA-256", "source_kind", "JSON"):
        assert gone not in response.text


def test_liquid_glass_and_static_client_are_bounded_and_injection_safe() -> None:
    template = (PACKAGE / "templates" / "third_party_executive_reports.html").read_text(
        encoding="utf-8"
    )
    source = (
        PACKAGE / "static" / "lightwork-third-party-executive-reports.js"
    ).read_text(encoding="utf-8")
    for required in (
        ":focus-visible",
        "prefers-reduced-motion",
        "forced-colors",
        'aria-live="polite"',
    ):
        assert required in template
    for required in (
        "MAX_JSON_BYTES = 256 * 1024",
        "MAX_PDF_BYTES = 4 * 1024 * 1024",
        'headers.get("Content-Length")',
        "response.body.getReader()",
        "reader.cancel()",
        'credentials: "same-origin"',
        'cache: "no-store"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        "textContent",
    ):
        assert required in source
    assert "window.confirm" not in source
    assert "R.newKey()" in source
    assert "innerHTML" not in source
    assert "eval(" not in source
    assert "document.write" not in source
