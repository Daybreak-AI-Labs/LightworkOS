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

    @app.get("/consent/profile-data")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "consent_profile_data.html",
            {"consent_profile_data_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_exposes_complete_governed_operator_contract(page_client: TestClient) -> None:
    from test_support.plain_language import developer_terms

    response = page_client.get("/consent/profile-data")
    assert response.status_code == 200
    page = response.text
    assert "Preference questions" in page
    assert "cannot approve it" in page
    assert "About this page’s safeguards" in page
    assert "/api/v1/consent/profile-data" in page
    # Question sets and asking plans load on open with a button per row.
    for element in ("cpd-catalogs", "cpd-journeys", "cpd-catalog", "cpd-journey",
                    "cpd-integrity", "cpd-purge"):
        assert f'id="{element}"' in page
    assert 'request("/catalogs?limit=500")' in page and 'request("/journeys?limit=500")' in page
    for label in ("Approve", "Start", "Pause", "Stop", "Roll back", "Create asking plan"):
        assert f'label: "{label}"' in page
    for action in ("approve", "activate", "pause", "kill", "rollback", "/contract?"):
        assert action in page
    # Published facts are looked up by the server, never typed or pasted.
    for typed in ("Record references (JSON)", "Action details (JSON)", "Load bounded example",
                  "cpd-operation", '"0".repeat(64)', "replace-catalog-create-key"):
        assert typed not in page
    assert page.count("CW.confirm(") >= 3
    assert "encodeURIComponent" in page
    assert developer_terms(page) == []


def test_page_fails_closed_and_uses_only_safe_dom(page_client: TestClient) -> None:
    disabled = page_client.get("/consent/profile-data", params={"enabled": False})
    assert disabled.status_code == 200
    assert 'data-module-gate="consent_preferences.profile_data"' in disabled.text
    assert "Consent profile data is turned off." in disabled.text
    assert "[consent_preferences.profile_data] enable = true" not in disabled.text
    assert "Turn this feature on to use it." in disabled.text

    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_profile_data.html"
    ).read_text(encoding="utf-8")
    for unsafe in (
        ".innerHTML",
        ".outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "Function(",
    ):
        assert unsafe not in template
    for forbidden in (
        'name="tenant"',
        'name="tenant_id"',
        'name="actor"',
        'name="actor_ref"',
        'name="profile_id"',
        'name="profile_capability"',
        'name="raw_capability"',
        'name="key"',
        'name="key_material"',
        'name="email"',
        'name="free_text"',
    ):
        assert forbidden not in template


def test_main_api_router_mounts_profile_data_under_v1_prefix() -> None:
    from maverick_dashboard.api import router

    app = FastAPI()
    app.include_router(router)
    paths = set(app.openapi()["paths"])
    assert "/api/v1/consent/profile-data/status" in paths
    assert "/api/v1/consent/profile-data/catalogs" in paths
    assert "/api/v1/consent/profile-data/journeys" in paths
    assert "/api/v1/consent/profile-data/integrity" in paths
    assert "/api/v1/consent/profile-data/retention/purge" in paths


def test_main_dashboard_mounts_profile_page_and_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-consent-profile-data.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/consent/profile-data" in paths
    assert "/api/v1/consent/profile-data/status" in paths
    page = page_for("/consent/profile-data")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False

    from maverick_dashboard.copilot_context import context_for_page

    assert context_for_page("/consent/profile-data").path == "/consent/profile-data"

    consent_home = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_preferences.html"
    ).read_text(encoding="utf-8")
    consent_nav = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "_consent_nav.html"
    ).read_text(encoding="utf-8")
    assert '{% include "_consent_nav.html" %}' in consent_home
    assert "('/consent/profile-data', 'Preference questions')" in consent_nav
