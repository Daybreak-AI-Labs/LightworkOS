from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient


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

    @app.get("/compliance/scoping")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "compliance_scoping.html",
            {"compliance_scoping_enabled": enabled, "can_admin": True, "can_audit": True},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_complete_honest_confirmed_workbench(page_client) -> None:
    response = page_client.get("/compliance/scoping")
    assert response.status_code == 200
    page = response.text
    assert "Find which controls apply" in page
    assert "About this page&rsquo;s safeguards" in page
    assert "does not include licensed framework text" in page
    assert "/api/v1/compliance/scoping" in page
    # The everyday workflow: record lists with buttons, no typed references.
    for element in ('id="cs-assessments"', 'id="cs-scopes"', 'id="cs-reports"',
                    'id="cs-questionnaires"', 'id="cs-new-assessment"',
                    "lightwork-compliance-scoping.js"):
        assert element in page
    # The raw operation console survives only inside collapsed technical details.
    before, technical = page.split('<summary>Technical details: advanced operations</summary>', 1)
    for jargon in ("JSON", "Tenant", "SHA-256", "revision", "env:", "Operation"):
        assert jargon not in before.split("<main", 1)[-1], jargon
    assert 'id="cs-operation"' in technical
    for operation in (
        "questionnaire-create",
        "questionnaire-get",
        "questionnaire-publish",
        "assessment-create",
        "assessment-get",
        "required-questions",
        "response-record",
        "scope-compute",
        "scope-get",
        "scope-overlaps",
        "scope-crosswalks",
        "scope-responsibilities",
        "scope-approve",
        "scope-finalize",
        "scope-export",
        "export-get",
        "retention-purge",
        "integrity",
    ):
        assert f'value="{operation}"' in page
    assert "cs-confirm" in page
    assert "textContent" in page


def test_page_fails_closed_and_template_uses_safe_dom(page_client) -> None:
    disabled = page_client.get("/compliance/scoping", params={"enabled": False})
    assert disabled.status_code == 200
    assert 'data-module-gate="tech_risk_compliance.scoping"' in disabled.text
    assert "[tech_risk_compliance] enable = true" not in disabled.text
    assert "[tech_risk_compliance.scoping] enable = true" not in disabled.text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "compliance_scoping.html"
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
        'name="raw_evidence"',
        'name="signing_key"',
    ):
        assert forbidden not in template


def test_dashboard_mounts_page_api_visibility_and_compliance_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-compliance-scoping.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/compliance/scoping" in paths
    assert "/api/v1/compliance/scoping/status" in paths
    assert "/api/v1/compliance/scoping/scopes/{scope_id}/exports/{export_id}" in paths
    page = page_for("/compliance/scoping")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
    compliance = (
        Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "compliance.html"
    ).read_text(encoding="utf-8")
    assert 'href="/compliance/scoping"' in compliance
