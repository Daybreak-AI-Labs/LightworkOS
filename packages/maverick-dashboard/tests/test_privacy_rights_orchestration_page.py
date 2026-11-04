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

    @app.get("/privacy/rights-orchestration")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "privacy_rights_orchestration.html",
            {"privacy_rights_orchestration_enabled": enabled, "can_admin": True, "can_audit": True},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_complete_honest_confirmed_workbench(page_client) -> None:
    response = page_client.get("/privacy/rights-orchestration")
    assert response.status_code == 200
    page = response.text
    assert "Privacy requests" in page
    assert "About this page&rsquo;s safeguards" in page
    assert "Microsoft 365, Google Workspace, Salesforce, ServiceNow" in page
    assert "never shown again" in page
    assert "/api/v1/privacy/rights-orchestration" in page
    for element in ('id="pro-cases"', 'id="pro-new-case"', 'id="pro-sources"', 'id="pro-case"',
                    "lightwork-privacy-rights-orchestration.js"):
        assert element in page
    before, technical = page.split("<summary>Technical details: advanced operations</summary>", 1)
    for jargon in ("JSON", "Tenant", "principal", "callback", "lease", "Operation"):
        assert jargon not in before.split("<main", 1)[-1], jargon
    assert 'id="pro-operation"' in technical
    for operation in (
        "source-enroll",
        "case-open",
        "identity-evidence",
        "legal-hold",
        "retention-gate",
        "task-plan",
        "destructive-approve",
        "callback-claim",
        "callback-list",
        "callback-fail",
        "callback-ack",
        "callback-requeue",
        "source-runtime-run",
        "source-runtime-reconcile",
        "source-evidence",
        "manifest-build",
        "package-create",
        "closure-approve",
        "case-close",
        "case-export",
        "retention-purge",
        "integrity",
    ):
        assert f'value="{operation}"' in page
    assert "pro-confirm" in page
    assert "textContent" in page


def test_page_fails_closed_and_new_template_uses_safe_dom(page_client) -> None:
    disabled = page_client.get("/privacy/rights-orchestration", params={"enabled": False})
    assert disabled.status_code == 200
    assert 'data-module-gate="privacy_automation.rights_orchestration"' in disabled.text
    assert "Privacy request handling is turned off." in disabled.text
    assert "[privacy_automation.rights_orchestration] enable = true" not in disabled.text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "privacy_rights_orchestration.html"
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
    ):
        assert forbidden not in template


def test_dashboard_mounts_page_api_visibility_and_privacy_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-privacy-rights.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/privacy/rights-orchestration" in paths
    assert "/api/v1/privacy/rights-orchestration/status" in paths
    assert "/api/v1/privacy/rights-orchestration/cases/{case_id}/closure/approve" in paths
    page = page_for("/privacy/rights-orchestration")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
    privacy = (
        Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "privacy.html"
    ).read_text(encoding="utf-8")
    assert 'href="/privacy/rights-orchestration"' in privacy
