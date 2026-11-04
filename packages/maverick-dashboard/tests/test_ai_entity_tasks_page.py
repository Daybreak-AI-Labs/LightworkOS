from __future__ import annotations

import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import ai_entity_tasks_page as page

ROUTE = "/ai-entity-tasks"
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
    monkeypatch.setattr(page, "_tenant_selected", lambda: True)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: True)
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, _permission: True,
    )
    app = FastAPI()
    app.include_router(page.create_ai_entity_tasks_page_router(_templates()))
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

    assert "AI system tasks" in response.text
    assert 'id="aet-operations" disabled' in response.text
    assert "Checking availability before enabling actions" in response.text
    assert "Lightwork checks that the item is current before saving a task" in response.text
    assert "Each task keeps a verification fingerprint linking it to the reviewed inventory record" in response.text
    assert 'data-api-base="/api/v1/ai-entity-tasks"' in response.text
    assert 'data-copilot-page="/ai-entity-tasks"' in response.text
    assert 'src="/static/lightwork-copilot.js' in response.text
    assert 'src="/static/lightwork-ai-entity-tasks.js"' in response.text

    parser = _Markup()
    parser.feed(response.text)
    style_nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]
    assert len(style_nonces) == 1
    assert style_nonces[0]
    assert f"'nonce-{style_nonces[0]}'" in csp


@pytest.mark.parametrize(
    ("tenant_permissions", "global_permissions", "operate", "audit", "admin"),
    (
        (frozenset(), frozenset(), False, False, False),
        (frozenset({"operate"}), frozenset(), True, False, False),
        (frozenset(), frozenset({"audit"}), False, True, False),
        (frozenset(), frozenset({"admin"}), False, False, True),
        (
            frozenset({"operate"}),
            frozenset({"audit", "admin"}),
            True,
            True,
            True,
        ),
    ),
)
def test_page_renders_exact_role_controls(
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

    assert ("disabled" not in by_id["aet-create-controls"]) is operate
    assert ("disabled" not in by_id["aet-update-controls"]) is operate
    assert by_id["ai-entity-task-shell"]["data-can-operate"] == ("true" if operate else "false")
    assert ("disabled" not in by_id["aet-verify-integrity"]) is audit
    assert ("disabled" not in by_id["aet-retention-due"]) is audit
    assert ("disabled" not in by_id["aet-purge-controls"]) is admin


def test_page_collects_only_closed_task_fields(client: TestClient) -> None:
    parser = _Markup()
    parser.feed(client.get(ROUTE).text)
    forms = [attrs for tag, attrs in parser.tags if tag == "form"]
    names = {
        value
        for tag, attrs in parser.tags
        if tag in {"input", "select", "textarea"}
        if isinstance((value := attrs.get("name")), str)
    }

    assert forms and all("action" not in form for form in forms)
    assert {
        "entity_id",
        "kind",
        "title",
        "description",
        "assignee_ref",
        "priority",
        "due_at",
        "idempotency_key",
        "task_id",
        "expected_revision",
        "status",
    }.issubset(names)
    # The AI system, people, task and version are chosen or carried, never typed.
    by_name = {
        attrs.get("name"): (tag, attrs)
        for tag, attrs in parser.tags
        if tag in {"input", "select"} and isinstance(attrs.get("name"), str)
    }
    assert by_name["entity_id"][0] == "select" and by_name["assignee_ref"][0] == "select"
    assert by_name["task_id"][1].get("type") == "hidden"
    assert by_name["expected_revision"][1].get("type") == "hidden"
    assert "entity_revision" not in names and "limit" not in names
    for forbidden in (
        "tenant_id",
        "actor_ref",
        "principal_ref",
        "created_by_ref",
        "entity_authority_sha256",
        "issuer_ref",
        "retained_until",
        "retention_policy",
        "storage_path",
    ):
        assert forbidden not in names


def test_page_rejects_query_material_and_requires_tenant(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert client.get(f"{ROUTE}?entity_id=caller-selected").status_code == 404
    assert client.get(f"{ROUTE}?tenant_id=caller-selected").status_code == 404
    assert client.get(f"{ROUTE}?theme=light&density=compact").status_code == 200

    monkeypatch.setattr(page, "_tenant_selected", lambda: False)
    missing = client.get(ROUTE)
    assert missing.status_code == 200
    assert "Choose a workspace first" in missing.text
    assert page.ASSET_PATH not in missing.text


def test_page_supports_custom_theme_with_one_csp_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import maverick.config as config

    monkeypatch.setattr(config, "load_config", lambda: {
        "dashboard": {"themes": {"custom": {
            "bg": "#000", "panel": "#111", "text": "#fff", "accent": "#0f0",
        }}},
    })
    monkeypatch.setattr(page, "_tenant_selected", lambda: True)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: True)
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, _permission: True,
    )
    app = FastAPI()
    app.include_router(page.create_ai_entity_tasks_page_router(_templates()))
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get(ROUTE)
    parser = _Markup()
    parser.feed(response.text)
    nonces = [attrs.get("nonce") for tag, attrs in parser.tags if tag == "style"]

    assert len(nonces) == 2
    assert "body.theme-custom { --bg: #000; --panel: #111;" in response.text
    assert len(set(nonces)) == 1
    assert nonces[0]
    assert f"'nonce-{nonces[0]}'" in response.headers["content-security-policy"]


def test_liquid_glass_client_is_accessible_bounded_and_injection_safe() -> None:
    template = (PACKAGE / "templates" / "ai_entity_tasks.html").read_text(
        encoding="utf-8"
    )
    source = (
        PACKAGE / "static" / "lightwork-ai-entity-tasks.js"
    ).read_text(encoding="utf-8")

    for required in (
        ":focus-visible",
        "prefers-reduced-motion",
        "forced-colors",
        "aria-live=\"polite\"",
        "data-copilot-page",
    ):
        assert required in template
    for required in (
        "MAX_RESPONSE_BYTES = 64 * 1024",
        'headers.get("Content-Length")',
        "response.body.getReader()",
        "reader.cancel()",
        "JSON.parse(responseText)",
        'credentials: "same-origin"',
        'cache: "no-store"',
        'redirect: "error"',
        'referrerPolicy: "no-referrer"',
        "element.textContent",
        'operations.disabled = true',
        'operations.disabled = false',
        'request("/operations/integrity")',
        'request("/operations/retention-due?limit=',
        'request("/operations/purge-expired"',
        "payload.due_at = null",
        "payload.assignee_ref = null",
        "payload.collaborator_refs = []",
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
    ):
        assert forbidden not in source


def test_page_assets_and_integration_constants_are_packaged() -> None:
    assert page.PAGE_PATH == ROUTE
    assert page.API_BASE == "/api/v1/ai-entity-tasks"
    assert page.ASSET_PATH == "/static/lightwork-ai-entity-tasks.js"
    for relative in (
        "ai_entity_tasks_page.py",
        "templates/ai_entity_tasks.html",
        "static/lightwork-ai-entity-tasks.js",
    ):
        selected = PACKAGE / relative
        assert selected.is_file()
        assert selected.stat().st_size > 100


def test_task_client_parses_as_strict_javascript() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    result = subprocess.run(  # noqa: S603 - exact local interpreter and file
        [node, "--check", str(PACKAGE / "static" / "lightwork-ai-entity-tasks.js")],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_page_is_plain_language_with_a_task_table_and_row_actions(client: TestClient) -> None:
    import re

    body = client.get(ROUTE).text
    main = body.split('<main id="content"', 1)[-1].split("</main>", 1)[0]
    text = re.sub(r"<[^>]+>", " ", re.sub(r"<(script|style)\b.*?</\1>", " ", main, flags=re.DOTALL))
    banned = re.compile(
        r"\b(tenant|principals?|payload|endpoint|schema|uuid|sha-?256|digest|idempoten\w*|"
        r"revision|json|entity id|reference|retention-due)\b|/api/v1|HTTP \d{3}",
        re.IGNORECASE,
    )
    assert banned.search(text) is None, banned.search(text)
    assert 'id="aet-task-list"' in body
    for label in ("All tasks", "New task", "Edit task", "Check records are intact", "Delete expired tasks"):
        assert label in text
    source = (PACKAGE / "static" / "lightwork-ai-entity-tasks.js").read_text(encoding="utf-8")
    assert '"/api/v1/people/assignable"' in source and '"/api/v1/security/assurance/ai-inventory"' in source
    assert "window.mvConfirm" in source


@pytest.mark.parametrize("enabled", (False, True))
def test_turned_off_module_shows_its_gate_instead_of_loaders(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, enabled: bool,
) -> None:
    from maverick_dashboard import module_activation

    monkeypatch.setattr(module_activation, "module_activation_enabled", lambda _section: enabled)
    page_text = client.get(ROUTE).text
    main = page_text[page_text.index('<div class="aet-shell"'):page_text.index("<noscript>")]
    assert f'data-module-enabled="{"true" if enabled else "false"}"' in main
    if enabled:
        assert "data-module-gate" not in main
        assert "Loading tasks…" in main
        return
    # The gate follows the title; the workbench neither checks availability
    # (the gate already says it is off) nor shows a loader that never ends.
    assert main.index('class="page-title hero-title"') < main.index("data-module-gate")
    assert '<section class="panel" aria-labelledby="aet-status-title" hidden>' in main
    assert "Loading" not in main
    assert "Tasks appear here once AI system tasks are turned on." in main
