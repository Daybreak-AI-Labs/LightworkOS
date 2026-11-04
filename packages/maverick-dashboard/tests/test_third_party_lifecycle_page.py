from __future__ import annotations

from html import unescape
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

    @app.get("/third-party/lifecycle")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "third_party_lifecycle.html",
            {"third_party_lifecycle_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_is_a_list_workflow_in_plain_words(page_client) -> None:
    response = page_client.get("/third-party/lifecycle")
    assert response.status_code == 200
    page = response.text
    assert "Third-party lifecycle" in page
    assert "doesn't contact vendors" in unescape(page)
    assert "/api/v1/third-party/lifecycle" in page
    # Lists load on open, with a button to start each kind of record.
    for host in ("tpl-templates", "tpl-assessments", "tpl-lifecycles", "tpl-offboarding"):
        assert f'id="{host}"' in page
    for label in ("Create questionnaire", "Create assessment", "Start tracking a vendor",
                  "Delete expired records", "Check records haven't been changed"):
        assert label in page
    assert "/static/lightwork-third-party-lifecycle.js" in page
    assert "/static/lightwork-record-workflows.js" in page
    # No operation dropdown, no JSON boxes, no confirmation checkbox wall.
    for gone in ('id="tpl-operation"', "tpl-path-values", "Record references (JSON)",
                 "Action details (JSON)", "callback-claim", "<textarea"):
        assert gone not in page
    from test_support.plain_language import developer_terms

    assert developer_terms(page) == []


def test_page_fails_closed_and_static_dom_is_safe(page_client) -> None:
    disabled = page_client.get("/third-party/lifecycle", params={"enabled": False})
    assert disabled.status_code == 200
    assert 'data-module-gate="third_party_management.lifecycle"' in disabled.text
    assert "[third_party_management] enable = true" not in disabled.text
    assert "[third_party_management.lifecycle] enable = true" not in disabled.text
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "third_party_lifecycle.html"
    ).read_text(encoding="utf-8")
    for unsafe in (".innerHTML", ".outerHTML", "insertAdjacentHTML", "eval("):
        assert unsafe not in template
    for forbidden in ('name="tenant_id"', 'name="actor_ref"'):
        assert forbidden not in template


def test_dashboard_mounts_page_api_visibility_and_security_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-third-party-lifecycle.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/third-party/lifecycle" in paths
    assert "/api/v1/third-party/lifecycle/status" in paths
    assert "/api/v1/third-party/lifecycle/offboarding/{plan_id}/complete" in paths
    page = page_for("/third-party/lifecycle")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
    security = (
        Path(__file__).resolve().parents[1] / "maverick_dashboard" / "templates" / "security.html"
    ).read_text(encoding="utf-8")
    assert 'href="/third-party/lifecycle"' in security
