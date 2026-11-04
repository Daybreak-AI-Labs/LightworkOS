from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import consent_scan_notice_proposals_api as api


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

    @app.get("/consent/scan-notice-proposals")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "consent_scan_notice_proposals.html",
            {"consent_scan_notice_proposals_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_complete_honest_operator_workbench(page_client) -> None:
    from test_support.plain_language import developer_terms

    response = page_client.get("/consent/scan-notice-proposals")
    assert response.status_code == 200
    page = response.text
    assert "Disclosure suggestions" in page
    assert "Three different people take part" in page
    assert "does not change your website or write any notice text" in page
    assert "/api/v1/consent/scan-notice-proposals" in page
    # Suggestions are rows with the buttons each person may use, not an
    # operation dropdown with typed IDs and versions.
    assert 'id="csnp-list"' in page
    for label in ("Suggest an update from the latest scan", "Approve", "Withdraw my approval",
                  "Accept", "Download", "What changes", "Check that records are intact"):
        assert label in page
    for typed in ("Proposal ID", "Current proposal version", "Expected head revision",
                  "Expected approval revision", 'name="operation"', "Content-free result"):
        assert typed not in page
    assert "acknowledge_local_baseline_only: true" in page
    assert page.count("CW.confirm(") >= 5
    assert "textContent" in page
    assert developer_terms(page) == []


def test_page_fails_closed_and_template_uses_safe_dom(page_client) -> None:
    disabled = page_client.get(
        "/consent/scan-notice-proposals",
        params={"enabled": False},
    )
    assert disabled.status_code == 200
    assert 'data-module-gate="consent_preferences.scanner.notice_proposals"' in disabled.text
    assert "Disclosure suggestions is turned off." in disabled.text
    assert "[consent_preferences.scanner.notice_proposals]" not in disabled.text

    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_scan_notice_proposals.html"
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
        'name="property_id"',
        'name="report_id"',
        'name="inventory_revision"',
        'name="raw_scan_data"',
        'name="scanner_report"',
        'name="host"',
        'name="origin"',
        'name="url"',
        'name="legal_copy"',
        'name="notice_text"',
        'name="signing_key"',
        'name="provider_target"',
        'name="site_target"',
        'name="publication_target"',
    ):
        assert forbidden not in template


def test_assumed_page_and_api_prefix_contract_is_mountable(page_client) -> None:
    paths = set(page_client.app.openapi()["paths"])
    assert "/consent/scan-notice-proposals" in paths
    assert "/api/v1/consent/scan-notice-proposals/status" in paths
    assert "/api/v1/consent/scan-notice-proposals/proposals" in paths
    assert "/api/v1/consent/scan-notice-proposals/proposals/{proposal_id}/accept-local" in paths
    assert "/api/v1/consent/scan-notice-proposals/integrity" in paths

    source = Path(api.__file__).read_text(encoding="utf-8")
    assert 'prefix="/consent/scan-notice-proposals"' in source
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_scan_notice_proposals.html"
    ).read_text(encoding="utf-8")
    assert 'var API = "/api/v1/consent/scan-notice-proposals";' in template


def test_main_dashboard_mounts_page_api_visibility_tips_and_parent_links(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-scan-notice-proposals.toml")),
    )
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/consent/scan-notice-proposals" in paths
    assert "/api/v1/consent/scan-notice-proposals/status" in paths
    page = page_for("/consent/scan-notice-proposals")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False

    from maverick_dashboard.copilot_context import context_for_page

    assert (
        context_for_page("/consent/scan-notice-proposals").path
        == "/consent/scan-notice-proposals"
    )
    templates = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    assert '{% include "_consent_nav.html" %}' in (
        templates / "consent_preferences.html"
    ).read_text(encoding="utf-8")
    assert "('/consent/scan-notice-proposals'," in (
        templates / "_consent_nav.html"
    ).read_text(encoding="utf-8")
    assert 'href="/consent/scan-notice-proposals"' in (
        templates / "consent_scan_inventory.html"
    ).read_text(encoding="utf-8")

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    response = client.get("/consent/scan-notice-proposals")
    assert response.status_code == 200, response.text
    assert "Disclosure suggestions" in response.text
    assert 'data-module-gate="consent_preferences.scanner.notice_proposals"' in response.text
