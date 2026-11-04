from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import governed_document_vault_page as page

ROUTE = "/administration/document-vault"
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

    monkeypatch.setattr(page, "_tenant_selected", lambda: True)
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
    app.include_router(page.create_governed_document_vault_page_router(templates))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_liquid_glass_candid_and_copilot_scoped(client: TestClient) -> None:
    response = client.get(ROUTE)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["referrer-policy"] == "no-referrer"
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
        "Document vault",
        "Files are encrypted before they are stored",
        "work once",
        "does not check outside storage services",
    ):
        assert text in response.text
    assert "prefers-reduced-motion" in response.text
    assert 'data-copilot-page="/administration/document-vault"' in response.text
    assert 'id="document-vault-operations" disabled' in response.text


def test_page_has_live_ingest_revoke_mint_redeem_and_audit_controls(client: TestClient) -> None:
    response = client.get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    identifiers = {
        value
        for _tag, attrs in parser.tags
        if isinstance((value := attrs.get("id")), str)
    }
    assert {
        "document-vault-ingest-form",
        "document-vault-file",
        "document-vault-documents",
        "document-vault-delivery-form",
        "document-vault-audit",
        "document-vault-integrity",
        "document-vault-reconcile",
    }.issubset(identifiers)
    scripts = [attrs.get("src") for tag, attrs in parser.tags if tag == "script"]
    assert "/static/lightwork-governed-document-vault.js" in scripts


def test_page_rejects_authority_query_material_and_requires_tenant(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert client.get(f"{ROUTE}?tenant_id=forbidden").status_code == 404

    monkeypatch.setattr(page, "_tenant_selected", lambda: False)
    missing_page = client.get(ROUTE)
    assert missing_page.status_code == 200
    assert "Choose a workspace first" in missing_page.text
    assert "lightwork-governed-document-vault.js" not in missing_page.text


def test_client_is_bounded_and_has_no_persistent_browser_secret_channels() -> None:
    source = (PACKAGE / "static" / "lightwork-governed-document-vault.js").read_text(
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
        "object_locator",
        "filesystem_path",
    ):
        assert forbidden not in source
    for required in (
        "100 * 1024 * 1024",
        "512 * 1024",
        "TextEncoder",
        "response.body.getReader",
        'cache: "no-store"',
        'credentials: "same-origin"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        "operations.disabled = true",
        "operations.disabled = false",
        "URL.revokeObjectURL",
        "textContent",
    ):
        assert required in source


def test_page_assets_are_packaged() -> None:
    for relative in (
        "templates/governed_document_vault.html",
        "static/lightwork-governed-document-vault.js",
    ):
        selected = PACKAGE / relative
        assert selected.is_file()
        assert selected.stat().st_size > 100


_BANNED = re.compile(
    r"\b(tenant|principals?|payload|endpoint|schema|uuid|sha-?256|digest|"
    r"idempoten\w*|revision|json|yaml|toml|token|ttl|mint|ingest|custody|authority)\b"
    r"|\[[a-z_]+\]|/api/v1|HTTP \d{3}",
    re.IGNORECASE,
)


def test_page_lists_documents_with_row_actions_and_no_typed_references(client: TestClient) -> None:
    body = client.get(ROUTE).text
    main = body.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL))
    assert _BANNED.search(text) is None, _BANNED.search(text)
    for label in ("Add a document", "Upload", "Documents", "Show history",
                  "Check files haven", "Received a download code", "Technical details"):
        assert label in text
    # References, versions and expiry seconds are never typed.
    for removed in ('name="document_ref"', 'name="expected_revision"', "document-vault-token-ttl",
                    "document-vault-mint-idempotency", "document-vault-claim-idempotency",
                    '<input class="input" id="document-vault-record-type"'):
        assert removed not in body
    source = (PACKAGE / "static" / "lightwork-governed-document-vault.js").read_text(encoding="utf-8")
    for required in ('"Stop sharing"', '"Download"', '"Share one-time code"', "record.authority_revision",
                     "global.mvConfirm", '"/documents?limit=500"'):
        assert required in source
