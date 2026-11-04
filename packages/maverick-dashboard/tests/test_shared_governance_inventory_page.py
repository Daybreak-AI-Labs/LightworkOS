from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import shared_governance_inventory_page as page


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=Path(page.__file__).parent / "templates",
        context_processors=[_theme_context],
    )
    selected.env.globals.update(nav_groups=[])
    return selected


def test_page_is_liquid_glass_copilot_wired_and_permission_aware(monkeypatch) -> None:
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    monkeypatch.setattr(
        page,
        "has_permission",
        lambda _request, permission: permission in {"operate", "audit"},
    )
    app = FastAPI()
    app.include_router(page.create_shared_governance_inventory_page_router(_templates()))

    response = TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    assert "style-src 'self' 'nonce-" in response.headers["content-security-policy"]
    body = response.text
    assert "Governance inventory" in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert page.ASSET_PATH in body
    assert 'data-can-operate="true"' in body
    assert 'data-can-audit="true"' in body
    assert 'data-can-admin="false"' in body
    assert 'id="sgi-reconcile" type="button" disabled' in body
    assert 'id="sgi-checkpoint" type="button" disabled' in body
    assert 'id="sgi-integrity" type="button">' in body
    # Filters are dropdowns and records load into tables; nothing is typed.
    for control in ("sgi-version", "sgi-source", "sgi-kind", "sgi-relation"):
        assert f'<select class="select" id="{control}"' in body
    for typed in ("Snapshot ID", "Operation ID", "integrity digest", "Expected active revision", "Limit"):
        assert typed not in body
    assert 'id="sgi-entity-rows"' in body and 'id="sgi-link-rows"' in body
    # The strict style policy blocks style attributes; the page styles live in its nonce stylesheet.
    assert " style=" not in body.split('id="sgi-root"')[1]
    from test_support.plain_language import developer_terms

    assert developer_terms(body) == []


def test_page_rejects_unknown_query_parameters(monkeypatch) -> None:
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    app = FastAPI()
    app.include_router(page.create_shared_governance_inventory_page_router(_templates()))

    response = TestClient(app, base_url="http://127.0.0.1").get(
        page.PAGE_PATH + "?return_to=https://attacker.invalid"
    )

    assert response.status_code == 404


def test_shipped_app_mounts_page_api_and_private_asset(monkeypatch) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "test-tenant")
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get(page.PAGE_PATH).status_code == 200
    assert client.get(f"{page.API_BASE}/status").status_code == 200
    asset = client.get(page.ASSET_PATH)
    assert asset.status_code == 200
    assert asset.headers["cache-control"] == "no-store, private, max-age=0"
    assert asset.headers["x-content-type-options"] == "nosniff"
