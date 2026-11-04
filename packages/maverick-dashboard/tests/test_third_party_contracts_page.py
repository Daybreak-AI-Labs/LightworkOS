from __future__ import annotations

import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import third_party_contracts_page as page

ROUTE = "/third-party/contracts"
PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


class _Markup(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str | None]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, dict(attrs)))


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    return templates


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: True)
    monkeypatch.setattr(page, "has_global_permission", lambda _request, _permission: True)
    app = FastAPI()
    app.include_router(page.create_third_party_contracts_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_workbench_is_store_free_closed_and_copilot_enabled(client: TestClient) -> None:
    response = client.get(ROUTE)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"
    csp = response.headers["content-security-policy"]
    for directive in (
        "default-src 'none'",
        "base-uri 'none'",
        "connect-src 'self'",
        "form-action 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
    ):
        assert directive in csp
    assert "style-src 'self' 'nonce-" in csp
    assert "Contracts and engagements" in response.text
    assert 'id="tpc-operations" disabled' in response.text
    assert "Checking that contracts are available" in response.text
    assert "Record the key facts here, not the full contract text." in response.text
    assert 'src="/static/lightwork-record-workflows.js"' in response.text
    from test_support.plain_language import developer_terms

    assert developer_terms(response.text) == []
    assert 'data-api-base="/api/v1/third-party/contracts"' in response.text
    assert 'data-copilot-page="/third-party/contracts"' in response.text
    assert 'src="/static/lightwork-copilot.js"' in response.text
    assert 'src="/static/lightwork-third-party-contracts.js"' in response.text
    parser = _Markup()
    parser.feed(response.text)
    nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]
    assert len(nonces) == 1
    assert nonces[0]
    assert f"'nonce-{nonces[0]}'" in csp


@pytest.mark.parametrize(
    ("tenant_permissions", "global_permissions", "operate", "audit", "admin"),
    (
        (frozenset(), frozenset(), False, False, False),
        (frozenset({"operate"}), frozenset(), True, False, False),
        (frozenset(), frozenset({"audit"}), False, True, False),
        (frozenset(), frozenset({"admin"}), False, False, True),
        (frozenset({"operate"}), frozenset({"audit", "admin"}), True, True, True),
    ),
)
def test_page_renders_exact_permission_controls(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    tenant_permissions: frozenset[str],
    global_permissions: frozenset[str],
    operate: bool,
    audit: bool,
    admin: bool,
) -> None:
    monkeypatch.setattr(
        page,
        "has_permission",
        lambda _request, permission: permission in tenant_permissions,
    )
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, permission: permission in global_permissions,
    )
    parser = _Markup()
    parser.feed(client.get(ROUTE).text)
    by_id = {
        attrs["id"]: attrs
        for _tag, attrs in parser.tags
        if isinstance(attrs.get("id"), str)
    }
    shell = by_id["third-party-contracts-shell"]
    assert (shell["data-can-operate"] == "true") is operate
    assert (shell["data-can-audit"] == "true") is audit
    assert (shell["data-can-admin"] == "true") is admin
    assert ("disabled" not in by_id["tpc-new"]) is operate
    assert ("disabled" not in by_id["tpc-verify-integrity"]) is audit
    assert ("disabled" not in by_id["tpc-retention-due"]) is audit
    assert ("disabled" not in by_id["tpc-purge"]) is admin
    assert ("disabled" not in by_id["tpc-recovery-preflight"]) is admin


def test_page_collects_only_closed_fields_through_selectors(client: TestClient) -> None:
    text = client.get(ROUTE).text
    parser = _Markup()
    parser.feed(text)
    forms = [attrs for tag, attrs in parser.tags if tag == "form"]
    controls = {
        attrs.get("name"): tag
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"} and isinstance(attrs.get("name"), str)
    }
    assert forms and all("action" not in form for form in forms)
    # Vendors, people and related contracts are chosen from lists.
    for selector in ("vendor_id", "owner_ref", "business_owner_ref", "parent_contract_id",
                     "agreement_type", "engagement_type", "service_category", "governing_law"):
        assert controls[selector] == "select", selector
    for typed in ("vendor_revision", "title_ref", "agreement_ref", "field_schema_json",
                  "field_values_json", "formulas_json", "lifecycle_json", "idempotency_key",
                  "linked_contract_ids", "update_status"):
        assert typed not in controls
    assert controls["record_id"] == "input" and controls["expected_revision"] == "input"
    assert 'name="record_id" value=""' in text and 'type="hidden" name="record_id"' in text
    assert "<textarea" not in text
    for forbidden in (
        "tenant_id", "actor_ref", "principal_ref", "created_by_ref", "vendor_type",
        "vendor_criticality", "vendor_authority_sha256", "issuer_ref", "revoked",
        "retained_until", "storage_path", "recovery_path", "provider", "adapter",
    ):
        assert forbidden not in controls
    for label in ("Add a custom field", "Add a calculation", "Show contracts due for deletion",
                  "Delete expired contracts"):
        assert label in text


def test_page_rejects_query_material_and_requires_tenant(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert client.get(f"{ROUTE}?vendor_id=caller-selected").status_code == 404
    assert client.get(f"{ROUTE}?tenant_id=caller-selected").status_code == 404
    assert client.get(f"{ROUTE}?theme=light&density=compact").status_code == 200

    def missing_tenant() -> None:
        raise page.HTTPException(
            status_code=409,
            detail="select an active tenant before using Contract and Engagement lifecycle",
        )

    monkeypatch.setattr(page, "_tenant_selected", missing_tenant)
    assert client.get(ROUTE).status_code == 409


def test_custom_theme_uses_same_csp_nonce(monkeypatch: pytest.MonkeyPatch) -> None:
    import maverick.config as config

    monkeypatch.setattr(config, "load_config", lambda: {
        "dashboard": {"themes": {"custom": {
            "bg": "#000", "panel": "#111", "text": "#fff", "accent": "#0f0",
        }}},
    })
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: True)
    monkeypatch.setattr(page, "has_global_permission", lambda _request, _permission: True)
    app = FastAPI()
    app.include_router(page.create_third_party_contracts_page_router(_templates()))
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]
    assert len(nonces) == 2
    assert "body.theme-custom { --bg: #000; --panel: #111;" in response.text
    assert len(set(nonces)) == 1
    assert nonces[0]
    assert f"'nonce-{nonces[0]}'" in response.headers["content-security-policy"]


def test_client_is_bounded_accessible_and_injection_safe() -> None:
    template = (PACKAGE / "templates" / "third_party_contracts.html").read_text(
        encoding="utf-8"
    )
    source = (
        PACKAGE / "static" / "lightwork-third-party-contracts.js"
    ).read_text(encoding="utf-8")
    for required in (":focus-visible", 'aria-live="polite"', "data-copilot-page"):
        assert required in template
    for required in (
        "MAX_RESPONSE_BYTES = 2 * 1024 * 1024",
        'headers.get("Content-Length")',
        "response.body.getReader()",
        "reader.cancel()",
        "JSON.parse(responseText)",
        'credentials: "same-origin"',
        'cache: "no-store"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        "operations.disabled = true",
        "operations.disabled = false",
        'request("/operations/integrity")',
        'request("/operations/retention-due?limit=',
        'request("/operations/purge-expired"',
        "R.confirm(",
        "R.newKey()",
    ):
        assert required in source
    for forbidden in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "eval(",
        "response.json()",
        "window.confirm",
    ):
        assert forbidden not in source


def test_assets_and_integration_constants_are_packaged() -> None:
    assert page.PAGE_PATH == ROUTE
    assert page.API_BASE == "/api/v1/third-party/contracts"
    assert page.ASSET_PATH == "/static/lightwork-third-party-contracts.js"
    for relative in (
        "third_party_contracts_page.py",
        "templates/third_party_contracts.html",
        "static/lightwork-third-party-contracts.js",
    ):
        selected = PACKAGE / relative
        assert selected.is_file()
        assert selected.stat().st_size > 100


def test_contract_client_parses_as_strict_javascript() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    result = subprocess.run(  # noqa: S603 - exact local interpreter and file
        [node, "--check", str(PACKAGE / "static" / "lightwork-third-party-contracts.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("enabled", (False, True))
def test_turned_off_module_shows_its_gate_instead_of_loaders(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, enabled: bool,
) -> None:
    from maverick_dashboard import module_activation

    monkeypatch.setattr(module_activation, "module_activation_enabled", lambda _section: enabled)
    text = client.get(ROUTE).text
    main = text[text.index('<div id="third-party-contracts-shell"'):text.index('<script src="/static/lightwork-record-workflows.js"')]
    assert f'data-module-enabled="{"true" if enabled else "false"}"' in main
    if enabled:
        assert "data-module-gate" not in main and "Loading…" in main
        return
    # The gate follows the title; the availability box is hidden (the banner
    # already says it is off) and no loader says "Loading".
    assert main.index('class="page-title hero-title"') < main.index("data-module-gate")
    assert '<div class="hero-statebox" aria-live="polite" hidden>' in main
    assert "Loading" not in main
    assert "Contracts and engagements appear here once this is turned on." in main
