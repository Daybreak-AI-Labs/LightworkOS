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

    @app.get("/compliance/continuous-evidence")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "trc_continuous_evidence.html",
            {"trc_continuous_evidence_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_lists_sources_and_names_all_stock_collectors(page_client):
    response = page_client.get("/compliance/continuous-evidence")
    assert response.status_code == 200
    page = response.text
    assert "Continuous evidence" in page
    assert "/api/v1/compliance/continuous-evidence" in page
    assert "/static/lightwork-trc-continuous-evidence.js" in page
    for name in (
        "AWS Security Hub",
        "AWS Config",
        "Azure Defender",
        "Azure Policy",
        "Google Cloud Security Command Center",
        "GitHub security streams",
        "Okta policy posture",
    ):
        assert name in page
    for host in ("trc-sources", "trc-definitions", "trc-runs", "trc-alerts"):
        assert f'id="{host}"' in page
    assert "Collect evidence now" in page and "Run one bounded scheduler cycle" not in page
    for gone in ('id="trc-operation"', "trc-path-values", "Strict request body", "<textarea"):
        assert gone not in page
    assert "isn't a compliance certificate" in page
    from test_support.plain_language import developer_terms

    assert developer_terms(page) == []


def test_page_fails_closed_and_uses_safe_dom_only(page_client):
    response = page_client.get(
        "/compliance/continuous-evidence",
        params={"enabled": False},
    )
    assert response.status_code == 200
    assert 'data-module-gate="tech_risk_compliance.continuous_evidence"' in response.text
    assert "stock_collectors.sources" not in response.text
    assert "[tech_risk_compliance.continuous_evidence] enable = true" not in response.text

    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "trc_continuous_evidence.html"
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
        'name="provider"',
        'name="origin"',
        'name="scope_ref"',
        'name="credential"',
        'name="raw_evidence"',
    ):
        assert forbidden not in template


def test_main_dashboard_mounts_page_api_visibility_and_copilot(monkeypatch):
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-trc-stock-collectors.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.copilot_context import context_for_page
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/compliance/continuous-evidence" in paths
    assert "/api/v1/compliance/continuous-evidence/status" in paths
    assert "/api/v1/compliance/continuous-evidence/scheduler/run-once" in paths
    page = page_for("/compliance/continuous-evidence")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is True
    context = context_for_page("/compliance/continuous-evidence")
    assert context.title == "Continuous evidence"
    templates = Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates"
    assert 'href="/compliance/continuous-evidence"' in (
        templates / "compliance.html"
    ).read_text(encoding="utf-8")
