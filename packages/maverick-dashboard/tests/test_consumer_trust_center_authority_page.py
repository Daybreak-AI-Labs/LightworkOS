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

    @app.get("/consent/trust-center-authority")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "consumer_trust_center_authority.html",
            {"consumer_trust_center_authority_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_full_four_eyes_authority_workbench(page_client) -> None:
    from test_support.plain_language import developer_terms

    response = page_client.get("/consent/trust-center-authority")
    assert response.status_code == 200
    page = response.text
    assert "Trust center access" in page
    assert "two approvals from people other than the one who asked" in page
    assert "/api/v1/consent/trust-center-authority" in page
    # Records are lists with row buttons; the four-eyes steps are buttons.
    for host in ("tca-contexts", "tca-access", "tcb-assets", "tcb-domains", "tcb-projections"):
        assert f'id="{host}"' in page
    for label in ("Connect a person", "Ask for access", "Link a privacy request", "Approve",
                  "Disconnect", "Download record", "Upload a logo", "Make live",
                  "Add a web address", "Check address", "Go live", "Show the brand on a website"):
        assert label in page
    for route in ("/overview", "/privacy-rights-contexts/prepare", "/capability-grants",
                  "/rights-authorizations/for-case", "/assets", "/domains", "/projections"):
        assert route in page
    # No operation dropdown, JSON boxes or typed references remain.
    for typed in ('id="tca-operation"', 'id="tca-path-values"', 'id="tca-body"',
                  "Strict JSON", "Path/query values", "Closed path values",
                  "Strict request JSON", 'type="checkbox" id="tca-confirm"'):
        assert typed not in page
    assert 'type="file" name="file" accept="image/png,image/jpeg"' in page
    assert page.count("CW.confirm(") >= 7
    assert 'credentials: "same-origin"' in page
    assert 'cache: "no-store"' in page
    assert "textContent" in page
    assert developer_terms(page) == []


def test_page_fails_closed_and_template_uses_safe_ephemeral_dom(page_client) -> None:
    disabled = page_client.get(
        "/consent/trust-center-authority",
        params={"enabled": False},
    )
    assert disabled.status_code == 200
    assert 'data-module-gate="consent_preferences.trust_center"' in disabled.text
    assert "Consumer Trust Center is turned off." in disabled.text
    assert "[consent_preferences.trust_center] enable = true" not in disabled.text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consumer_trust_center_authority.html"
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
        'name="property_id"',
        'name="profile_id"',
        'name="credential"',
        'name="signing_key"',
    ):
        assert forbidden not in template


def test_dashboard_mounts_page_api_visibility_help_and_consent_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-trust-center-authority.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/consent/trust-center-authority" in paths
    assert "/api/v1/consent/trust-center-authority/status" in paths
    assert (
        "/api/v1/consent/trust-center-authority/privacy-rights-contexts/prepare"
        in paths
    )
    assert "/api/v1/consent/trust-center-authority/capability-grants/{grant_ref}/approve" in paths
    assert (
        "/api/v1/consent/trust-center-authority/rights-authorizations/{authorization_ref}/approve"
    ) in paths
    page = page_for("/consent/trust-center-authority")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
    consent = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_preferences.html"
    ).read_text(encoding="utf-8")
    # The consent overview links every consent page through its shared nav.
    assert '{% include "_consent_nav.html" %}' in consent
    nav = (
        Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "_consent_nav.html"
    ).read_text(encoding="utf-8")
    assert "('/consent/trust-center-authority'," in nav
    from maverick_dashboard.copilot_context import context_for_page

    assert (
        context_for_page("/consent/trust-center-authority").path
        == "/consent/trust-center-authority"
    )
