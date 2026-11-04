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

    @app.get("/privacy/rights-consumer-delivery")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "privacy_rights_consumer_delivery.html",
            {"privacy_rights_consumer_delivery_enabled": enabled, "can_admin": True, "can_audit": True},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_honest_one_time_operator_workbench(page_client) -> None:
    response = page_client.get("/privacy/rights-consumer-delivery")
    assert response.status_code == 200
    page = response.text
    assert "Send people their data" in page
    assert "This code is shown once." in page
    assert "keeps only a fingerprint of each code" in page
    assert "signed in again to prove who they are" in page
    assert "/api/v1/privacy/rights-consumer-delivery" in page
    for element in ('id="prcd-packages"', 'id="prcd-ready"', 'id="prcd-copy"',
                    "lightwork-privacy-rights-consumer-delivery.js"):
        assert element in page
    before, technical = page.split("<summary>Technical details: advanced operations</summary>", 1)
    for jargon in ("JSON", "Tenant", "principal", "digest", "mint", "capability", "Operation"):
        assert jargon not in before.split("<main", 1)[-1], jargon
    assert 'id="prcd-operation"' in technical
    for operation in (
        "delivery-mint",
        "delivery-get",
        "delivery-revoke",
        "export-create",
        "export-get",
        "retention-purge",
        "integrity",
    ):
        assert f'value="{operation}"' in page
    assert 'credentials: "same-origin"' in page
    assert 'cache: "no-store"' in page
    assert "textContent" in page


def test_page_fails_closed_and_template_uses_safe_ephemeral_dom(page_client) -> None:
    disabled = page_client.get(
        "/privacy/rights-consumer-delivery",
        params={"enabled": False},
    )
    assert disabled.status_code == 200
    assert 'data-module-gate="privacy_automation.rights_consumer_delivery"' in disabled.text
    assert "Sending people their data is turned off." in disabled.text
    assert "[privacy_automation.rights_consumer_delivery] enable = true" not in disabled.text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "privacy_rights_consumer_delivery.html"
    ).read_text(encoding="utf-8")
    for unsafe in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "localStorage",
        "sessionStorage",
    ):
        assert unsafe not in template
    for forbidden in (
        'name="tenant"',
        'name="tenant_id"',
        'name="actor"',
        'name="principal"',
        'name="consumer_subject"',
        'name="capability"',
    ):
        assert forbidden not in template


def test_dashboard_mounts_page_api_visibility_and_privacy_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-rights-delivery.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/privacy/rights-consumer-delivery" in paths
    assert "/api/v1/privacy/rights-consumer-delivery/status" in paths
    assert "/api/v1/privacy/rights-consumer-delivery/deliveries/{delivery_id}/revoke" in paths
    page = page_for("/privacy/rights-consumer-delivery")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
    privacy = (
        Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "privacy.html"
    ).read_text(encoding="utf-8")
    assert 'href="/privacy/rights-consumer-delivery"' in privacy
    from maverick_dashboard.copilot_context import context_for_page

    assert (
        context_for_page("/privacy/rights-consumer-delivery").path
        == "/privacy/rights-consumer-delivery"
    )
