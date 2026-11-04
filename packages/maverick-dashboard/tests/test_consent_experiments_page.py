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

    @app.get("/consent/experiments")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "consent_experiments.html",
            {"consent_experiments_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_page_renders_full_governed_experiment_workflow(page_client: TestClient) -> None:
    from test_support.plain_language import developer_terms

    response = page_client.get("/consent/experiments")
    assert response.status_code == 200
    page = response.text
    assert "Banner experiments" in page
    assert "creates an experiment cannot approve it" in page
    assert "About this page’s safeguards" in page
    assert "/api/v1/consent/experiments" in page
    for element in ("ce-table", "ce-create", "ce-results-panel", "ce-assignment", "ce-purge"):
        assert f'id="{element}"' in page
    # Every lifecycle step is a row button with a plain confirmation.
    for action in ("approve", "activate", "pause", "resume", "kill", "rollback", "analysis",
                   "audit-export", "/variant-content"):
        assert action in page
    for label in ("Approve", "Start", "Pause", "Resume", "Stop", "Back to original", "Check results"):
        assert f'label: "{label}"' in page
    assert "CW.confirm(" in page and "window.confirm" not in page
    # Nothing a person cannot know is typed: no IDs, digests, JSON or Unix times.
    for typed in ("Experiment ID", "Variants JSON", "Audience JSON", "Unix time", "basis points",
                  "Familywise alpha", "Current version", "Subject identity"):
        assert typed not in page
    assert 'type="datetime-local"' in page
    # Review evidence is fingerprinted from attached files, never typed.
    assert 'input.type = "file"' in page and "CW.sha256File(" in page
    assert developer_terms(page) == []


def test_page_is_safe_and_explicit_when_independent_gate_is_off(
    page_client: TestClient,
) -> None:
    response = page_client.get("/consent/experiments", params={"enabled": False})
    assert response.status_code == 200
    assert 'data-module-gate="consent_preferences.experiments"' in response.text
    assert "Consent experiments is turned off." in response.text
    assert "[consent_preferences.experiments] enable = true" not in response.text
    assert "Visitors whose browser asks not to be tracked" in response.text

    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "consent_experiments.html"
    ).read_text(encoding="utf-8")
    assert ".innerHTML" not in template
    assert "document.write" not in template
    assert "eval(" not in template


def test_main_dashboard_mounts_consent_experiment_page_api_and_visibility(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv(
        "MAVERICK_CONFIG",
        str(Path(__file__).with_name("nonexistent-consent-experiments.toml")),
    )
    from maverick import config

    config.reset_config_cache()
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/consent/experiments" in paths
    assert "/api/v1/consent/experiments/status" in paths
    page = page_for("/consent/experiments")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
