from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import privacy_drop_management_page as page

ROUTE = "/privacy/drop"
PACKAGE = Path(__file__).resolve().parents[1] / "maverick_dashboard"


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    from maverick_dashboard.app import _theme_context

    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(page, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: True)
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
        nav_groups=[
            SimpleNamespace(
                id="privacy",
                label="Privacy",
                default_open=True,
                links=[
                    SimpleNamespace(href="/privacy", label="Privacy", icon="shield"),
                    SimpleNamespace(
                        href="/privacy/drop",
                        label="California DROP",
                        icon="shield",
                    ),
                ],
            )
        ],
    )
    app = FastAPI()
    app.include_router(page.create_privacy_drop_management_page_router(templates))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_drop_workbench_uses_shared_shell_and_lists_on_arrival(
    client: TestClient,
) -> None:
    response = client.get(ROUTE)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-robots-tag"] == "noindex, nofollow, noarchive"
    text = response.text
    assert "California DROP requests" in text
    assert "California Delete Request and Opt-out Platform (DROP)" in text
    assert 'src="/static/lightwork-record-workflows.js"' in text
    assert 'src="/static/lightwork-privacy-drop-management.js"' in text
    assert 'src="/static/lightwork-copilot.js' in text
    assert 'href="/static/lightwork.css' in text
    assert "/api/v1/privacy/drop" in text
    for element_id in (
        "drop-requests",
        "drop-waiting",
        "drop-brokers",
        "drop-import-form",
        "drop-outcome-form",
        "drop-broker-form",
        "drop-integrity",
        "drop-keys-panel",
        "drop-rotate",
    ):
        assert f'id="{element_id}"' in text
    assert "approval from a second administrator" in text
    assert 'type="date"' in text
    assert 'type="file"' in text


def test_drop_page_never_collects_server_owned_identity_material(
    client: TestClient,
) -> None:
    response = client.get(ROUTE)
    lowered = response.text.lower()
    for forbidden in (
        'name="tenant',
        'name="actor',
        'name="principal',
        'name="subject',
        'name="credential',
        "sha-256",
        "unix seconds",
        "uuid",
        "idempotency",
        "proposal uuid",
        "current version",
        "expected version",
    ):
        assert forbidden not in lowered


def test_drop_page_marks_only_the_most_specific_navigation_link(
    client: TestClient,
) -> None:
    body = client.get(ROUTE).text

    assert body.count('aria-current="page"') == 1
    assert '<a href="/privacy/drop" class="active" aria-current="page">' in body
    assert '<a href="/privacy" class="active"' not in body


def test_drop_page_hides_global_controls_without_their_exact_permissions(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, permission: permission == "audit",
    )
    audit_only = client.get(ROUTE)

    assert audit_only.status_code == 200
    assert 'id="drop-integrity"' in audit_only.text
    assert 'id="drop-waiting"' in audit_only.text
    assert 'id="drop-import"' not in audit_only.text
    assert 'id="drop-broker-form"' not in audit_only.text
    assert 'id="drop-outcome-form"' not in audit_only.text
    assert 'id="drop-rotate"' not in audit_only.text

    monkeypatch.setattr(
        page,
        "has_global_permission",
        lambda _request, permission: permission == "admin",
    )
    admin_only = client.get(ROUTE)

    assert admin_only.status_code == 200
    assert 'id="drop-integrity"' not in admin_only.text
    assert 'id="drop-import"' in admin_only.text
    assert 'id="drop-outcome-form"' in admin_only.text
    assert 'id="drop-broker-form"' in admin_only.text
    assert 'data-can-admin="true"' in admin_only.text


def test_drop_page_offers_lookup_to_viewers(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(page, "has_permission", lambda _request, _permission: False)
    monkeypatch.setattr(page, "has_global_permission", lambda _request, _permission: False)

    response = client.get(ROUTE)

    assert response.status_code == 200
    assert 'data-can-operate="false"' in response.text
    assert "Ask an administrator for access to the full list" in response.text
    assert 'id="drop-waiting"' not in response.text
    assert 'id="drop-import"' not in response.text


def test_drop_page_rejects_query_material_and_requires_tenant(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert client.get(f"{ROUTE}?drop_id=12").status_code == 404
    assert client.get(f"{ROUTE}?theme=light&density=compact").status_code == 200

    def missing_tenant() -> None:
        raise page.HTTPException(
            status_code=409,
            detail="select an active tenant before using DROP management",
        )

    monkeypatch.setattr(page, "_tenant_selected", missing_tenant)
    assert client.get(ROUTE).status_code == 409


def test_drop_page_and_asset_are_mounted_and_registered() -> None:
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    routes = []
    for route in app.routes:
        if hasattr(route, "effective_candidates"):
            routes.extend(route.effective_candidates())
        else:
            routes.append(route)
    assert any(getattr(route, "path", None) == ROUTE for route in routes)
    assert any(
        getattr(route, "path", None) == "/static/lightwork-privacy-drop-management.js"
        for route in routes
    )
    selected = page_for(ROUTE)
    assert selected is not None
    assert selected["floor"] == "view"
    assert selected["in_nav"] is True
    for relative in (
        "privacy_drop_management_page.py",
        "templates/privacy_drop_management.html",
        "static/lightwork-privacy-drop-management.js",
    ):
        assert (PACKAGE / relative).is_file()


def test_drop_client_has_bounded_transport_and_safe_rendering() -> None:
    source = (PACKAGE / "static" / "lightwork-privacy-drop-management.js").read_text(
        encoding="utf-8"
    )
    for required in (
        'credentials: "same-origin"',
        'cache: "no-store"',
        "Number.isSafeInteger",
        "encodeURIComponent(dropId)",
        "refreshStatus().then(",
        "/authority/overview",
        "R.fingerprint",
        "R.confirm",
        'headers.get("Content-Length")',
        "response.body.getReader()",
        "reader.cancel()",
        "JSON.parse(responseText)",
    ):
        assert required in source
    for forbidden in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "localStorage",
        "sessionStorage",
        "document.cookie",
        "eval(",
        "response.json()",
        "window.prompt",
        "alert(",
    ):
        assert forbidden not in source
