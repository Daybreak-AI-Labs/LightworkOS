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

    @app.get("/privacy/regulatory-intelligence")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "privacy_regulatory_intelligence.html",
            {"privacy_regulatory_intelligence_enabled": enabled, "can_admin": True},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_renders_operator_contract_and_no_unsafe_dom_sink(
    page_client: TestClient,
) -> None:
    response = page_client.get("/privacy/regulatory-intelligence")
    assert response.status_code == 200
    body = response.text
    assert "Privacy law research" in body
    assert "does not include any third-party legal database" in body
    assert "a different administrator confirms" in body
    assert "Lightwork says so instead of guessing" in body
    assert "not legal advice" in body
    for element in ('id="pri-research"', 'id="pri-trackers"', 'id="pri-reports"', 'id="pri-documents"',
                    'id="pri-sources"', 'name="pri-where"', 'type="date"', 'id="pri-doc-authority"',
                    "lightwork-privacy-regulatory-intelligence.js"):
        assert element in body
    main = body.split("<main", 1)[-1]
    for jargon in ("JSON", "comma-separated", "Retention seconds", "Cadence seconds", "Source ID",
                   "Tracker ID", "Report ID", "Current version", "SHA-256", "lease", "Claim"):
        assert jargon not in main, jargon
    script = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "static"
        / "lightwork-privacy-regulatory-intelligence.js"
    ).read_text(encoding="utf-8")
    assert "/api/v1/privacy/regulatory-intelligence" in script
    assert ".innerHTML" not in script
    assert "textContent" in script
    assert "window.confirm" not in script


def test_page_renders_fail_closed_gate_guidance(page_client: TestClient) -> None:
    response = page_client.get(
        "/privacy/regulatory-intelligence",
        params={"enabled": False},
    )
    assert response.status_code == 200
    assert 'data-module-gate="privacy_automation.regulatory_intelligence"' in response.text
    assert "Privacy law research is turned off." in response.text
    assert "privacy_automation.regulatory_intelligence.enable" not in response.text


def test_main_dashboard_mounts_privacy_intelligence_page_api_and_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-privacy-intelligence.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/privacy/regulatory-intelligence" in paths
    assert "/api/v1/privacy/regulatory-intelligence/status" in paths
    page = page_for("/privacy/regulatory-intelligence")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
