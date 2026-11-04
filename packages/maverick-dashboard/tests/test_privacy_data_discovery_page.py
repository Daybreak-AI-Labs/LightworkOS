from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient


@pytest.fixture()
def page_client():
    from maverick_dashboard.app import _theme_context

    template_dir = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    templates = Jinja2Templates(
        directory=str(template_dir),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    app = FastAPI()

    @app.get("/privacy/data-discovery")
    async def page(request: Request, enabled: bool = True, admin: bool = False):
        return templates.TemplateResponse(
            request,
            "privacy_data_discovery.html",
            {
                "privacy_data_discovery_enabled": enabled,
                "privacy_data_discovery_api_base": "/api/v1/privacy/data-discovery",
                "privacy_data_discovery_page_path": "/privacy/data-discovery",
                "privacy_data_discovery_can_operate": True,
                "privacy_data_discovery_can_audit": True,
                "privacy_data_discovery_can_admin": admin,
            },
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_renders_full_operator_contract(page_client: TestClient) -> None:
    response = page_client.get("/privacy/data-discovery")
    assert response.status_code == 200
    text = response.text
    assert "Find personal data" in text
    for provider in (
        "Amazon S3",
        "Azure Blob Storage",
        "Google Cloud Storage",
        "Snowflake",
        "ServiceNow",
        "Microsoft Entra",
    ):
        assert provider in text
    assert "listed as not read, never treated as checked" in text
    assert "Finding nothing does not prove there is no personal data" in text
    assert "A different person must approve each checked finding" in text
    for section in ("Data sources", "Scans", "Scan reports", "Waiting for approval", "What your data map shows"):
        assert section in text
    assert "Check the activity history is intact" in text
    # Operators without admin rights do not see admin-only buttons.
    assert 'id="pdd-new-source"' not in text
    assert 'id="pdd-rotate-key"' not in text
    assert 'id="pdd-purge"' not in text
    assert "/api/v1/privacy/data-discovery" in text
    assert 'data-copilot-page="/privacy/data-discovery"' in text
    assert "/static/lightwork-privacy-data-discovery.css" in text
    assert "/static/lightwork-record-workflows.js" in text
    assert text.count("/static/lightwork-privacy-data-discovery.js") == 1
    assert 'data-can-admin="false"' in text
    assert '<a class="back-link" href="/privacy">' in text and ">Back to Privacy<" in text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "privacy_data_discovery.html"
    ).read_text(encoding="utf-8")
    assert ".innerHTML" not in template
    assert "<script>" not in template
    assert "style=" not in template
    for jargon in ("adapter", "SHA-256", "tenant", "idempotency", "lease", "HTTP"):
        assert jargon not in template
    assert "credential_value" not in template
    assert "evidence_key_value" not in template


def test_page_shows_admin_controls_to_admins(page_client: TestClient) -> None:
    response = page_client.get("/privacy/data-discovery", params={"admin": True})
    assert 'id="pdd-new-source"' in response.text
    assert 'id="pdd-rotate-key"' in response.text
    assert "Replace the protection key" in response.text


def test_page_renders_fail_closed_gate_guidance(page_client: TestClient) -> None:
    response = page_client.get(
        "/privacy/data-discovery",
        params={"enabled": False},
    )
    assert response.status_code == 200
    assert 'data-module-gate="privacy_automation.data_discovery"' in response.text
    assert "Finding personal data is turned off." in response.text
    assert "privacy_automation.data_discovery.enable" not in response.text
    assert 'id="pdd-sources"' not in response.text


def test_main_dashboard_mounts_privacy_discovery_api_page_and_visibility() -> None:
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/privacy/data-discovery" in paths
    assert "/api/v1/privacy/data-discovery/status" in paths
    page = page_for("/privacy/data-discovery")
    assert page is not None
    assert page["floor"] == "view"
    assert page["default"] == "view"
    assert page["in_nav"] is True
