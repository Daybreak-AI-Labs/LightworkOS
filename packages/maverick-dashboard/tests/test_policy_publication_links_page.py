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

    @app.get("/compliance/policy-links")
    async def page(request: Request, enabled: bool = True):
        return templates.TemplateResponse(
            request,
            "policy_publication_links.html",
            {"policy_publication_links_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_operator_page_renders_full_safe_contract(page_client: TestClient) -> None:
    from test_support.plain_language import developer_terms

    response = page_client.get("/compliance/policy-links")
    assert response.status_code == 200
    page = response.text
    assert "Policy links" in page
    assert "Two other people" in page
    # Policies, links and scheduled changes load as lists with row buttons.
    for host in ("ppl-policies", "ppl-links", "ppl-jobs"):
        assert f'id="{host}"' in page
    for label in ("Write a policy", "Create a link", "Publish a version", "Schedule an end",
                  "New access code", "Turn off", "Run scheduled changes now",
                  "Show change history", "Check that records are intact"):
        assert label in page
    assert "Access code (shown once)" in page and "Copy access code" in page
    assert 'type="datetime-local"' in page
    # Nothing a person cannot know is typed: no IDs, versions, tokens or times.
    for typed in ("Policy ID", "Stable link ID", "Job ID", "lease token", "pointer revision",
                  "Unix time", "Rationale SHA-256", "Claim bounded batch", "Apply leased job",
                  'type="password"'):
        assert typed not in page
    assert "/api/v1/policy-publication-links" in page
    assert "textContent" in page
    assert page.count("CW.confirm(") >= 4
    assert "window.confirm" not in page
    assert "Production" not in page or "encrypted" in page
    template = (
        Path(__file__).resolve().parents[1]
        / "maverick_dashboard"
        / "templates"
        / "policy_publication_links.html"
    ).read_text(encoding="utf-8")
    assert ".innerHTML" not in template
    assert "tenant_id" not in template
    assert developer_terms(page) == []


def test_operator_page_explains_disabled_gate(page_client: TestClient) -> None:
    response = page_client.get(
        "/compliance/policy-links",
        params={"enabled": False},
    )
    assert response.status_code == 200
    assert 'data-module-gate="tech_risk_compliance.policy_publication_links"' in response.text
    assert "[tech_risk_compliance.policy_publication_links] enable = true" not in response.text
    assert 'id="ppl-root" data-feature-enabled="false"' in response.text


def test_main_dashboard_mounts_only_the_public_retrieval_auth_exemption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from maverick_dashboard.app import app
    from maverick_dashboard.auth import _self_authenticated_path
    from maverick_dashboard.ui_visibility import page_for

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setenv("MAVERICK_DASHBOARD_TOKEN", "dashboard-secret")
    paths = set(app.openapi()["paths"])
    assert "/api/v1/policy-publication-links/links" in paths
    assert "/api/v1/public/policies/{link_id}" in paths
    assert "/compliance/policy-links" in paths
    assert _self_authenticated_path("/api/v1/public/policies/PPL-opaque")
    assert not _self_authenticated_path("/api/v1/policy-publication-links/links")
    assert not _self_authenticated_path("/api/v1/public/policies-admin")

    page = page_for("/compliance/policy-links")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False

    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    assert client.get("/api/v1/public/policies/PPL-opaque").status_code == 404
    assert client.get("/api/v1/policy-publication-links/audit").status_code == 401
