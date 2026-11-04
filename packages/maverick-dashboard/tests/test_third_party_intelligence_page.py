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

    @app.get("/third-party/intelligence")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "third_party_intelligence.html",
            {"third_party_intelligence_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_a_set_of_record_lists_in_plain_words(
    page_client: TestClient,
) -> None:
    response = page_client.get("/third-party/intelligence")
    assert response.status_code == 200
    page = response.text
    assert "Third-party intelligence" in page
    assert "/api/v1/third-party/intelligence" in page
    assert "/static/lightwork-third-party-intelligence.js" in page
    assert "Enhanced due diligence" in page
    assert "different person reviews them" in page
    for host in ("tpi-sources", "tpi-vendors", "tpi-runs", "tpi-policies", "tpi-decisions",
                 "tpi-cases", "tpi-monitors", "tpi-alerts", "tpi-consents"):
        assert f'id="{host}"' in page
    for label in ("Add a data source", "Add a vendor", "Create risk policy",
                  "Review waiting alerts", "See what partners shared", "Delete expired records"):
        assert label in page
    # No operation consoles, JSON boxes, sample ids or confirm() walls.
    for gone in ("Closed request JSON", "<textarea", "Load safe example", 'value="vendor-1"',
                 'value="source-sanctions"', "window.confirm", "tpi-workbench"):
        assert gone not in page
    from test_support.plain_language import developer_terms

    assert developer_terms(page) == []


def test_page_is_fail_closed_and_uses_no_unsafe_dom_or_secret_inputs(
    page_client: TestClient,
) -> None:
    response = page_client.get(
        "/third-party/intelligence",
        params={"enabled": False},
    )
    assert response.status_code == 200
    assert 'data-module-gate="third_party_management.intelligence"' in response.text
    assert "[third_party_management.intelligence] enable = true" not in response.text
    assert "sanctions and risk data sources" in response.text

    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "third_party_intelligence.html"
    ).read_text(encoding="utf-8")
    assert ".innerHTML" not in template
    assert ".outerHTML" not in template
    assert "insertAdjacentHTML" not in template
    assert "document.write" not in template
    assert "eval(" not in template
    assert 'name="tenant_id"' not in template
    assert 'name="actor_ref"' not in template
    assert 'name="credential_value"' not in template
    assert 'name="raw_profile"' not in template


def test_main_dashboard_mounts_third_party_intelligence_page_api_and_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-third-party-intelligence.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/third-party/intelligence" in paths
    assert "/api/v1/third-party/intelligence/status" in paths
    assert "/api/v1/third-party/intelligence/provider-runtime/status" in paths
    assert (
        "/api/v1/third-party/intelligence/provider-runtime/sources/"
        "{source_id}/readiness"
    ) in paths
    assert "/api/v1/third-party/intelligence/outbox/review" in paths
    assert "/api/v1/third-party/intelligence/outbox/run" in paths
    assert app.state.third_party_intelligence_provider_runtime is not None
    assert app.state.third_party_intelligence_feed_scheduler is not None
    page = page_for("/third-party/intelligence")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
