from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import ai_evidence_analysis_page as page

ROUTE = "/ai-evidence-analysis"
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
    app = FastAPI()
    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    app.include_router(page.create_ai_evidence_analysis_page_router(templates))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_workbench_is_store_free_no_store_and_csp_closed(client: TestClient) -> None:
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

    assert "AI evidence analysis" in response.text
    assert 'id="evidence-operations" disabled' in response.text
    assert "not legal advice or a compliance conclusion" in response.text
    assert "Uploaded files are read within size limits and are not kept" in response.text
    assert "The text read from them is not stored either" in response.text
    assert "a different, authorized person" in response.text
    assert "/api/v1/ai-evidence-analysis" in response.text
    assert "recent guide questions" in response.text
    assert "Do not include document text, passwords," in response.text
    assert 'aria-describedby="mv-copilot-egress"' in response.text


def test_workbench_has_only_closed_evidence_controls(client: TestClient) -> None:
    response = client.get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)

    scripts: list[dict[str, str | None]] = []
    styles: list[dict[str, str | None]] = []
    forms: list[dict[str, str | None]] = []
    inputs: list[dict[str, str | None]] = []
    selectors: list[str] = []
    for tag, attrs in parser.tags:
        if tag == "script":
            scripts.append(attrs)
        if tag == "link" and attrs.get("rel") == "stylesheet":
            styles.append(attrs)
        if tag == "form":
            forms.append(attrs)
        if tag in {"input", "select", "textarea"}:
            if tag == "input":
                inputs.append(attrs)
            selectors.extend(
                value.lower()
                for name in ("id", "name")
                if isinstance((value := attrs.get(name)), str)
            )

    # Shell assets carry a content-hash query; compare the paths.
    script_sources = {(item.get("src") or "").split("?")[0] for item in scripts}
    # The Copilot's script is named on its button and loaded after the page.
    script_sources |= {(attrs.get("data-copilot-src") or "").split("?")[0] for tag, attrs in parser.tags if tag == "button"}
    assert {
        "/static/lightwork-copilot.js",
        "/static/lightwork-ui.js",
        "/static/lightwork-voice.js",
        "/static/lightwork-ai-evidence-analysis.js",
    }.issubset(script_sources)
    style_sources = {(item.get("href") or "").split("?")[0] for item in styles}
    assert {
        "/static/lightwork.css",
        "/static/lightwork-ai-evidence-analysis.css",
    }.issubset(style_sources)
    assert forms and all("action" not in form for form in forms)
    # One file chooser to analyze, one for administrators to register.
    assert sum(item.get("type") == "file" for item in inputs) == 2
    for selector in selectors:
        for forbidden in (
            "tenant",
            "actor",
            "principal",
            "reviewer",
            "adapter",
            "model",
            "provider",
            "valid_until",
            "retained_until",
            "retention_policy",
        ):
            assert forbidden not in selector

    # Choices only: pins, versions and fingerprints are carried from the
    # chosen registry rows, never typed.
    required = {"artifact_file", "artifact", "criteria", "analysis-filter", "register_file"}
    assert required.issubset(set(selectors))
    for typed in ("artifact_id", "source_ref", "source_revision", "expected_artifact_authority_sha256",
                  "criteria_set_id", "expected_criteria_revision", "analysis_id", "reason_code"):
        assert typed not in selectors


@pytest.mark.parametrize(
    ("allowed", "operate_disabled", "audit_disabled", "admin_disabled"),
    (
        (frozenset(), True, True, True),
        (frozenset({"operate"}), False, True, True),
        (frozenset({"audit"}), True, False, True),
        (frozenset({"view", "operate", "audit", "admin"}), False, False, False),
    ),
)
def test_workbench_server_renders_exact_role_controls(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    allowed: frozenset[str],
    operate_disabled: bool,
    audit_disabled: bool,
    admin_disabled: bool,
) -> None:
    monkeypatch.setattr(
        page,
        "has_permission",
        lambda _request, permission: permission in allowed,
    )
    response = client.get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    by_id = {
        attrs["id"]: attrs
        for _tag, attrs in parser.tags
        if isinstance(attrs.get("id"), str)
    }

    assert ("disabled" in by_id["evidence-analyze-controls"]) is operate_disabled
    assert ("disabled" in by_id["verify-integrity"]) is audit_disabled
    assert ("purge-expired" not in by_id) is admin_disabled
    root = by_id["evidence-shell"]
    assert root["data-can-operate"] == ("false" if operate_disabled else "true")
    assert root["data-can-audit"] == ("false" if audit_disabled else "true")
    assert root["data-can-admin"] == ("false" if admin_disabled else "true")


def test_custom_theme_css_uses_a_per_response_csp_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import maverick.config as config
    from maverick_dashboard.app import _theme_context

    monkeypatch.setattr(config, "load_config", lambda: {
        "dashboard": {"theme": "custom", "themes": {"custom": {
            "bg": "#000", "panel": "#111", "text": "#fff", "accent": "#0f0",
        }}},
    })
    monkeypatch.setattr(page, "_tenant_selected", lambda: True)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    templates = Jinja2Templates(
        directory=str(PACKAGE / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    app = FastAPI()
    app.include_router(page.create_ai_evidence_analysis_page_router(templates))
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(ROUTE)

    parser = _Markup()
    parser.feed(response.text)
    nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]
    assert len(nonces) == 1
    assert "body.theme-custom { --bg: #000; --panel: #111;" in response.text
    assert nonces[0]
    assert f"'nonce-{nonces[0]}'" in response.headers["content-security-policy"]


def test_client_uses_raw_file_body_without_persistent_or_html_injection_channels() -> None:
    source = (PACKAGE / "static" / "lightwork-ai-evidence-analysis.js").read_text(encoding="utf-8")
    css = (PACKAGE / "static" / "lightwork-ai-evidence-analysis.css").read_text(encoding="utf-8")
    copilot_source = (PACKAGE / "static" / "lightwork-copilot.js").read_text(encoding="utf-8")

    for forbidden in (
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "FormData",
        "FileReader",
        "arrayBuffer",
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "tenant_id",
        "actor_ref",
        "reviewer_ref",
        "extraction_adapter",
        "analysis_adapter",
        "valid_until",
        "retained_until",
    ):
        assert forbidden not in source
    for required in (
        "body: file",
        '"Content-Type": file.type',
        '"X-Lightwork-Evidence-Metadata": JSON.stringify(metadata)',
        'cache: "no-store"',
        'credentials: "same-origin"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        'schema: "lightwork.ai-evidence.upload-metadata.v1"',
        'fileInput.value = ""',
        'apiRequest("/integrity"',
        'apiRequest("/retention/purge"',
        '"/authorities/artifacts"',
        '"/authorities/criteria"',
        "window.mvConfirm",
    ):
        assert required in source
    assert ":focus-visible" in css
    assert "prefers-reduced-motion" in css
    assert "forced-colors" in css
    assert "configured_for_operation_attempt" in source
    assert "operational_composition_verified" in source
    assert "Evidence analysis is set up." in source
    assert "Text inside images can't be read on this installation." in source
    assert "enabled and composed for operations" not in source
    assert ".status-card > .governance-details" in css
    assert "Grounded in the current page" not in copilot_source
    assert "AI answers can be wrong" in copilot_source
    assert "conversation_token: conversationToken" in copilot_source
    assert "history: history.slice(-6)" not in copilot_source
    assert '{role: "assistant", content: payload.reply}' not in copilot_source


def test_workbench_rejects_query_material_and_requires_tenant(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    query = client.get(f"{ROUTE}?tenant_id=caller-selected")
    assert query.status_code == 404
    assert "AI evidence analysis" not in query.text

    monkeypatch.setattr(page, "_tenant_selected", lambda: False)
    missing = client.get(ROUTE)
    assert missing.status_code == 200
    assert "Choose a workspace first" in missing.text
    assert "lightwork-ai-evidence-analysis.js" not in missing.text


def test_workbench_template_and_assets_are_packaged() -> None:
    for relative in (
        "templates/ai_evidence_analysis.html",
        "static/lightwork-ai-evidence-analysis.js",
        "static/lightwork-ai-evidence-analysis.css",
    ):
        selected = PACKAGE / relative
        assert selected.is_file()
        assert selected.stat().st_size > 100


def test_dashboard_mounts_page_api_visibility_and_security_link() -> None:
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    effective_routes = []
    for route in app.routes:
        if hasattr(route, "effective_candidates"):
            effective_routes.extend(route.effective_candidates())
        else:
            effective_routes.append(route)
    assert any(
        getattr(route, "path", None) == "/ai-evidence-analysis"
        for route in effective_routes
    )
    assert "/api/v1/ai-evidence-analysis/status" in paths
    assert "/api/v1/ai-evidence-analysis/analyses" in paths
    selected = page_for("/ai-evidence-analysis")
    assert selected is not None
    assert selected["floor"] == "view"
    assert selected["in_nav"] is True
    security = (PACKAGE / "templates" / "security.html").read_text(encoding="utf-8")
    assert 'href="/ai-evidence-analysis"' in security


_BANNED = re.compile(
    r"\b(tenant|principals?|payload|endpoint|schema|uuid|sha-?256|digest|"
    r"idempoten\w*|revision|json|yaml|toml|artifact|adapter|authority|revoke)\b"
    r"|\[[a-z_]+\]|/api/v1|HTTP \d{3}",
    re.IGNORECASE,
)


def test_workbench_is_plain_language_with_lists_and_row_actions(client: TestClient) -> None:
    body = client.get(ROUTE).text
    main = body.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL))
    assert _BANNED.search(text) is None, _BANNED.search(text)
    for label in ("Analyze a document", "Analyses", "Register a document for analysis",
                  "Check records are intact", "Delete expired records", "Technical details"):
        assert label in text
    assert 'id="analyses-rows"' in body
    source = (PACKAGE / "static" / "lightwork-ai-evidence-analysis.js").read_text(encoding="utf-8")
    for label in ('"View findings"', '"Approve"', '"Reject"', '"Withdraw"', '"History"'):
        assert label in source


@pytest.mark.parametrize("enabled", (False, True))
def test_turned_off_module_shows_its_gate_instead_of_loaders(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, enabled: bool,
) -> None:
    from maverick_dashboard import module_activation

    monkeypatch.setattr(module_activation, "module_activation_enabled", lambda _section: enabled)
    text = client.get(ROUTE).text
    main = text[text.index('<div class="evidence-workbench"'):text.index("<noscript>")]
    assert f'data-module-enabled="{"true" if enabled else "false"}"' in main
    if enabled:
        assert "data-module-gate" not in main
        assert main.count("Loading…") == 3
        return
    # The gate follows the title; no availability check repeats it and no
    # loader is left saying "Loading".
    assert main.index('class="page-title hero-title"') < main.index("data-module-gate")
    assert 'aria-labelledby="status-title" hidden>' in main
    assert "Loading" not in main
    assert "Analyses appear here once AI evidence analysis is turned on." in main
