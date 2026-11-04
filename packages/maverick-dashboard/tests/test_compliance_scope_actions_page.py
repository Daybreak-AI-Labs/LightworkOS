from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import compliance_scope_actions_api as api


@pytest.fixture()
def page_client() -> TestClient:
    from maverick_dashboard.app import _theme_context

    template_dir = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    templates = Jinja2Templates(
        directory=str(template_dir),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    app = FastAPI()
    app.include_router(api.router, prefix="/api/v1")

    @app.get("/compliance/scope-actions")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "compliance_scope_actions.html",
            {"compliance_scope_actions_enabled": enabled, "can_admin": True, "can_audit": True},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_complete_honest_operator_workbench(page_client) -> None:
    response = page_client.get("/compliance/scope-actions")
    assert response.status_code == 200
    page = response.text
    assert "Turn scope into tasks" in page
    assert "About this page&rsquo;s safeguards" in page
    assert "does not include licensed framework text" in page
    assert "/api/v1/compliance/scope-actions" in page
    for element in ('id="csa-scopes"', 'id="csa-plans"', 'id="csa-reports"',
                    'id="csa-catalogs"', "lightwork-compliance-scope-actions.js"):
        assert element in page
    before, technical = page.split("<summary>Technical details: advanced operations</summary>", 1)
    for jargon in ("JSON", "Tenant", "CAS", "callback", "SHA-256", "Operation"):
        assert jargon not in before.split("<main", 1)[-1], jargon
    assert 'id="csa-operation"' in technical
    for operation in (
        "catalog-create",
        "catalog-get",
        "catalog-approve",
        "plan-create",
        "plan-get",
        "plan-history",
        "plan-approve",
        "plan-apply",
        "plan-reconcile",
        "plan-rollback",
        "plan-export",
        "export-get",
        "integrity",
    ):
        assert f'value="{operation}"' in page
    assert "csa-confirm" in page
    assert "textContent" in page


def test_page_fails_closed_and_template_uses_safe_dom(page_client) -> None:
    disabled = page_client.get(
        "/compliance/scope-actions",
        params={"enabled": False},
    )
    assert disabled.status_code == 200
    assert 'data-module-gate="tech_risk_compliance.scope_actions"' in disabled.text
    assert "[tech_risk_compliance] enable = true" not in disabled.text
    assert "[tech_risk_compliance.scope_actions] enable = true" not in disabled.text

    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "compliance_scope_actions.html"
    ).read_text(encoding="utf-8")
    for unsafe in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
    ):
        assert unsafe not in template
    for forbidden in (
        'name="tenant"',
        'name="tenant_id"',
        'name="actor"',
        'name="actor_ref"',
        'name="principal_ref"',
        'name="framework_text"',
        'name="raw_evidence"',
        'name="signing_key"',
        'name="provider"',
        'name="target"',
        'name="code"',
    ):
        assert forbidden not in template


def test_assumed_page_and_api_prefix_contract_is_mountable(page_client) -> None:
    paths = set(page_client.app.openapi()["paths"])
    assert "/compliance/scope-actions" in paths
    assert "/api/v1/compliance/scope-actions/status" in paths
    assert "/api/v1/compliance/scope-actions/catalogs/{catalog_id}/versions" in paths
    assert "/api/v1/compliance/scope-actions/scopes/{scope_id}/plans/{plan_id}" in paths
    assert "/api/v1/compliance/scope-actions/plans/{plan_id}/apply" in paths
    assert "/api/v1/compliance/scope-actions/plans/{plan_id}/exports/{export_id}" in paths
    assert "/api/v1/compliance/scope-actions/integrity" in paths

    source = Path(api.__file__).read_text(encoding="utf-8")
    assert 'prefix="/compliance/scope-actions"' in source
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "compliance_scope_actions.html"
    ).read_text(encoding="utf-8")
    assert 'var API = "/api/v1/compliance/scope-actions";' in template


def test_main_dashboard_mounts_scope_actions_page_api_and_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-compliance-scope-actions.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/compliance/scope-actions" in paths
    assert "/api/v1/compliance/scope-actions/status" in paths
    page = page_for("/compliance/scope-actions")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False

    from maverick_dashboard.copilot_context import context_for_page

    assert context_for_page("/compliance/scope-actions").path == "/compliance/scope-actions"
    templates = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    assert 'href="/compliance/scope-actions"' in (templates / "compliance.html").read_text(
        encoding="utf-8"
    )
