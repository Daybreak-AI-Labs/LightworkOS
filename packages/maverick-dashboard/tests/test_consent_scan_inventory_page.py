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

    @app.get("/consent/scan-inventory")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "consent_scan_inventory.html",
            {"consent_scan_inventory_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_scan_inventory_page_renders_safe_operator_contract(page_client: TestClient) -> None:
    from test_support.plain_language import developer_terms

    response = page_client.get("/consent/scan-inventory")
    assert response.status_code == 200
    page = response.text
    assert "Tracker scans" in page
    assert "cannot prove a tracker is absent" in page
    assert "Only “Scan now” and “Run due scans now” visit your websites" in page
    # Websites, scans and trackers are lists with row buttons; the worker
    # protocol runs behind "Scan now" on the server.
    for host in ("csi-sites", "csi-jobs", "csi-trackers", "csi-reports", "csi-approvals"):
        assert f'id="{host}"' in page
    for label in ("Add a website", "Scan now", "Run due scans now", "Trackers found",
                  "Apply reviewed results", "Compare with previous", "Try again",
                  "Reviews waiting for a second person", "Delete old scan data"):
        assert label in page
    assert "/scan-now" in page and "/review-requests" in page
    from test_support.plain_language import visible_text

    text = visible_text(page)
    assert 'type="password"' not in page and "lease_token" not in page
    for typed in ("lease", "Lease", "Tracker key", "Property ID", "Job ID",
                  "Unix time", "Second reviewer", "Interval seconds", "Claim work"):
        assert typed not in text
    assert 'type="datetime-local"' in page and 'type="date"' in page
    assert "window.confirm" not in page
    assert page.count("CW.confirm(") >= 6
    assert "/api/v1/consent/scan-inventory" in page
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_scan_inventory.html"
    ).read_text(encoding="utf-8")
    assert ".innerHTML" not in template
    assert developer_terms(page) == []


def test_scan_inventory_page_renders_when_gate_is_off(page_client: TestClient) -> None:
    response = page_client.get("/consent/scan-inventory", params={"enabled": False})
    assert response.status_code == 200
    assert 'data-module-gate="consent_preferences.scanner"' in response.text
    assert "Website tracker scans is turned off." in response.text
    assert "[consent_preferences.scanner] enable = true" not in response.text
    assert 'id="csi-controls" disabled' in response.text
