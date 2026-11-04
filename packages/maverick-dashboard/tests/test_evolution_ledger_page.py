"""Page, navigation, Copilot, and client boundaries for Evolution Ledger."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import evolution_ledger_page as page


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


def _app(monkeypatch: pytest.MonkeyPatch, *, permitted: bool = True) -> TestClient:
    def require(_request, permission: str) -> None:
        assert permission == "audit"
        if not permitted:
            raise HTTPException(status_code=403, detail="insufficient role")

    monkeypatch.setattr(page, "require_permission", require)
    app = FastAPI()
    app.include_router(page.create_evolution_ledger_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_audit_gated_csp_hardened_and_copilot_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _app(monkeypatch).get(page.PAGE_PATH)

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    csp = response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp
    assert "style-src 'self' 'nonce-" in csp
    body = response.text
    assert "Learning history" in body
    from test_support.plain_language import developer_terms
    assert developer_terms(body.replace("<main", "<main", 1)) == []
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert f'data-api-base="{page.API_BASE}"' in body
    assert 'data-read-only="true"' in body
    assert page.ASSET_PATH in body
    assert 'id="elv-refresh"' in body
    assert 'id="elv-verify-form"' in body
    assert 'type="file" id="elv-receipt" name="receipt"' in body
    assert "No private approval material is accepted here." in body


def test_page_rejects_viewer_and_unknown_query_params(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _app(monkeypatch, permitted=False).get(page.PAGE_PATH).status_code == 403
    assert _app(monkeypatch).get(page.PAGE_PATH + "?debug=1").status_code == 404


def test_page_requires_template_authority() -> None:
    with pytest.raises(TypeError):
        page.create_evolution_ledger_page_router(object())  # type: ignore[arg-type]


def test_nav_registry_and_copilot_use_the_audit_only_page_context() -> None:
    from maverick_dashboard.copilot_context import context_for_page
    from maverick_dashboard.ui_visibility import page_for

    entry = page_for(page.PAGE_PATH)
    assert entry is not None
    assert entry["group"] == "Govern"
    assert entry["floor"] == "audit"
    assert entry["default"] == "audit"
    assert entry["in_nav"] is True
    context = context_for_page(page.PAGE_PATH)
    assert context.title == "Learning history"
    boundaries = " ".join(context.boundaries).lower()
    # The guide changes nothing, and an adoption is not proof of better results.
    assert "page guide is read-only" in boundaries
    assert "does not establish that it improved results" in boundaries


def test_client_is_bounded_and_uses_safe_dom_only() -> None:
    package = Path(page.__file__).parent
    source = (package / "static" / "lightwork-evolution-ledger.js").read_text(encoding="utf-8")
    template = (package / "templates" / "evolution_ledger.html").read_text(encoding="utf-8")
    for unsafe in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "window.prompt(",
        "window.confirm(",
    ):
        assert unsafe not in source
    assert "textContent" in source
    assert "AbortController" in source
    assert "response.body.getReader" in source
    assert "maxResponseBytes" in source
    assert 'request("/snapshot")' in source
    assert 'request("/verify-receipt"' in source
    assert "/promote" not in source and "/rollback" not in source
    for forbidden in (
        'name="approval_request"',
        'name="approval_signature"',
        'name="trusted_key"',
        'name="ledger_path"',
        'name="raw_journal"',
        'name="candidate_id"',
    ):
        assert forbidden not in template


def test_main_dashboard_mounts_page_api_static_asset_and_context() -> None:
    from maverick_dashboard.app import app

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    paths = set(app.openapi()["paths"])
    # The dashboard's FastAPI version retains included routers as lazy wrapper
    # objects rather than flattening every path into ``app.routes``. Exercise
    # dispatch instead of coupling this feature test to that implementation.
    assert client.get(page.PAGE_PATH).status_code == 200
    assert f"{page.API_BASE}/snapshot" in paths
    assert f"{page.API_BASE}/verify-receipt" in paths
    assert client.get(page.ASSET_PATH).status_code == 200
