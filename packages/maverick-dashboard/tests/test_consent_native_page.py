from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import consent_native_page as page
from maverick_dashboard import copilot_context, ui_visibility


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
        "has_global_permission",
        lambda _request, permission: permission == "audit",
    )
    app = FastAPI()
    app.include_router(page.create_consent_native_page_router(_templates()))

    response = TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    assert "style-src 'self' 'nonce-" in response.headers["content-security-policy"]
    body = response.text
    assert "Mobile app consent" in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert page.ASSET_PATH in body
    assert "/static/lightwork-consent-workbench.js" in body
    assert 'data-can-audit="true"' in body
    assert 'data-can-admin="false"' in body
    # Apps and devices are record lists with row buttons, not typed-ID forms.
    assert 'id="nca-apps"' in body and 'id="nca-devices"' in body
    assert 'id="nca-register-form"' in body
    assert '<select class="select" name="public_client_ref" required>' in body
    assert 'id="nca-integrity" type="button"' in body
    assert f'id="nca-public-key-link" href="{page.PUBLIC_KEYS_BASE}"' in body
    assert 'fieldset class="cw-form" disabled' in body
    assert "nca-device-rotate-form" not in body
    assert "nca-device-revoke-form" not in body
    for typed in ("Ed25519", "Attestation nonce", "epoch", "Device reference",
                  "Current device version", "Current directory version"):
        assert typed not in body
    assert "tenant_id" not in body
    assert "principal_ref" not in body
    from test_support.plain_language import developer_terms

    assert developer_terms(body) == []


def test_page_rejects_unknown_query_parameters(monkeypatch) -> None:
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "_tenant_selected", lambda: None)
    app = FastAPI()
    app.include_router(page.create_consent_native_page_router(_templates()))

    response = TestClient(app, base_url="http://127.0.0.1").get(page.PAGE_PATH + "?tenant_id=attacker")

    assert response.status_code == 404


def test_page_has_nav_and_closed_copilot_context() -> None:
    visibility = next(item for item in ui_visibility.PAGES if item["path"] == page.PAGE_PATH)
    assert visibility == {
        "path": "/consent/native",
        "label": "Mobile app consent",
        "aliases": "Consent in Your Apps",
        "group": "Consent",
        "icon": "key",
        "floor": "view",
        "default": "audit",
        "module": "consent_preferences.native_sdk",
        "in_nav": True,
    }
    context = copilot_context.context_for_page(page.PAGE_PATH)
    assert context.title == "Mobile app consent"
    assert any("no permissive fallback" in item for item in context.boundaries)
    assert any("live-device" in item for item in context.boundaries)
