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

    @app.get("/privacy/notices")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "privacy_notice_governance.html",
            {"privacy_notice_governance_enabled": enabled, "can_admin": True, "can_audit": True},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_complete_honest_confirmed_workbench(page_client) -> None:
    response = page_client.get("/privacy/notices")
    assert response.status_code == 200
    page = response.text
    assert "Privacy notices" in page
    assert "About this page&rsquo;s safeguards" in page
    assert "only update Lightwork&rsquo;s own consent publishing records" in page
    assert "/api/v1/privacy/notices" in page
    for element in ('id="png-releases"', 'id="png-new-version"', 'id="png-release-form"',
                    'id="png-policies"', 'id="png-proposals"', 'id="png-effective"',
                    'type="date"', 'type="file"', 'name="jurisdiction"',
                    "lightwork-privacy-notice-governance.js"):
        assert element in page
    before, technical = page.split("<summary>Technical details: advanced operations</summary>", 1)
    for jargon in ("JSON", "Tenant", "SHA-256", "digest", "lease token", "Operation", "revision"):
        assert jargon not in before.split("<main", 1)[-1], jargon
    assert 'id="png-operation"' in technical
    assert 'data-copilot-page="/privacy/notice-governance"' in page
    assert "Publication updates in Lightwork" in page
    assert "/publication-runtime/status" in page
    assert "/publication-runtime/run-once" in page
    assert "does not publish changes to a website, app, tag manager" in page
    for operation in (
        "policy-set",
        "policy-get",
        "release-create",
        "release-get",
        "release-submit",
        "release-approve",
        "approval-revoke",
        "release-schedule",
        "intent-claim",
        "intent-fail",
        "intent-requeue",
        "intent-acknowledge",
        "release-rollback",
        "release-withdraw",
        "release-effective",
        "proposal-create",
        "proposal-get",
        "proposal-review",
        "notice-export",
        "export-get",
        "retention-purge",
        "integrity",
    ):
        assert f'value="{operation}"' in page
    assert "png-confirm" in page
    assert "textContent" in page


def test_page_fails_closed_and_template_uses_safe_dom(page_client) -> None:
    disabled = page_client.get("/privacy/notices", params={"enabled": False})
    assert disabled.status_code == 200
    assert 'data-module-gate="privacy_automation.notice_governance"' in disabled.text
    assert "Privacy notice approval is turned off." in disabled.text
    assert "[privacy_automation.notice_governance] enable = true" not in disabled.text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "privacy_notice_governance.html"
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
        'name="raw_content"',
        'name="notice_content"',
        'name="signing_key"',
    ):
        assert forbidden not in template
