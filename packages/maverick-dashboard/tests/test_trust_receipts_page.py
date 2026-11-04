from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import trust_receipts_page as page


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=Path(page.__file__).parent / "templates",
        context_processors=[_theme_context],
    )
    selected.env.globals.update(
        nav_groups=[],
    )
    return selected


def _app(monkeypatch, permitted: bool = True) -> TestClient:
    def _require(request, permission):
        assert permission == "audit"
        if not permitted:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="insufficient role")
    monkeypatch.setattr(page, "require_permission", _require)
    app = FastAPI()
    app.include_router(page.create_trust_receipts_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1")


def test_page_is_wired_and_hardened(monkeypatch) -> None:
    response = _app(monkeypatch).get(page.PAGE_PATH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    csp = response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "style-src 'self' 'nonce-" in csp
    body = response.text
    assert "Trust receipts" in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert f'data-api-base="{page.API_BASE}"' in body
    assert page.ASSET_PATH in body
    assert 'id="rcp-download-verifier"' in body and "/verifier" not in body
    assert 'id="rcp-verify-form"' in body and 'id="rcp-rows-form"' in body
    for level in ("Signed", "Chained", "Anchored"):
        assert f"<strong>{level}</strong>" in body
    # Upload a file, choose from lists; no pasted documents, no command lines.
    assert 'id="rcp-file"' in body and "<textarea" not in body
    assert 'id="rcp-kind"' in body and "<select" in body
    assert "python " not in body and "--key" not in body
    assert 'id="rcp-proof-form"' in body and 'id="rcp-proof-verify-form"' in body
    assert "<script>" not in body.split('id="rcp-root"')[1]   # the page CSP forbids inline script
    # The strict style policy blocks style attributes; the page styles live in its nonce stylesheet.
    assert " style=" not in body.split('id="rcp-root"')[1]
    from test_support.plain_language import developer_terms

    assert developer_terms(body) == []


def test_page_is_audit_gated(monkeypatch) -> None:
    assert _app(monkeypatch, permitted=False).get(page.PAGE_PATH).status_code == 403


def test_unknown_query_params_are_404(monkeypatch) -> None:
    assert _app(monkeypatch).get(page.PAGE_PATH + "?debug=1").status_code == 404


def test_page_requires_a_template_authority() -> None:
    with pytest.raises(TypeError):
        page.create_trust_receipts_page_router(object())  # type: ignore[arg-type]


def test_page_is_registered_in_the_nav_registry_at_the_audit_floor() -> None:
    from maverick_dashboard import ui_visibility
    entry = next(p for p in ui_visibility.PAGES if p["path"] == page.PAGE_PATH)
    assert entry["group"] == "Govern" and entry["floor"] == "audit" and entry["default"] == "audit"
