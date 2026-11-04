from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient


def _client(*, enabled: bool) -> TestClient:
    from maverick_dashboard.app import _theme_context

    templates = Jinja2Templates(
        directory=str(Path(__file__).parents[1] / "maverick_dashboard" / "templates"),
        context_processors=[_theme_context],
    )
    templates.env.globals.update(nav_groups=[])
    app = FastAPI()

    @app.get("/third-party/collaboration")
    async def page(request: Request):
        return templates.TemplateResponse(
            request,
            "third_party_collaboration.html",
            {"third_party_collaboration_enabled": enabled},
        )

    return TestClient(app, base_url="http://127.0.0.1")


def test_enabled_page_is_an_invitation_list_with_an_invite_form() -> None:
    page = _client(enabled=True).get("/third-party/collaboration")
    assert page.status_code == 200
    text = page.text
    assert "/api/v1/third-party/collaboration" in text
    assert "/static/lightwork-third-party-collaboration.js" in text
    for label in ("Invite a vendor", "Create invitation", "Choose the notice file",
                  "Clean up expired data", "shown only once"):
        assert label in text
    assert 'id="tpc-invitations"' in text and 'id="tpc-once"' in text
    # No operation dropdown, path JSON, body JSON or confirmation wall.
    for gone in ('id="tpc-operation"', "tpc-path-values", "Action details (JSON)",
                 "<textarea", "I reviewed the exact"):
        assert gone not in text
    from test_support.plain_language import developer_terms

    assert developer_terms(text) == []


def test_disabled_page_is_inert_and_names_all_required_gates() -> None:
    page = _client(enabled=False).get("/third-party/collaboration")
    assert page.status_code == 200
    text = page.text
    assert 'data-module-gate="third_party_management.lifecycle.portal"' in text
    assert "[third_party_management.lifecycle.portal]" not in text
    assert "public web address" in text
    assert "/api/v1/third-party/collaboration" not in text


def test_shipped_app_wires_page_api_and_security_link() -> None:
    from maverick_dashboard.app import app
    from maverick_dashboard.ui_visibility import page_for

    paths = set(app.openapi()["paths"])
    assert "/third-party/collaboration" in paths
    assert "/api/v1/third-party/collaboration/status" in paths
    assert (
        "/api/v1/external/third-party-collaboration/{portal_ref}/contract"
        in paths
    )
    page = page_for("/third-party/collaboration")
    assert page is not None
    assert page["floor"] == "operate"
    assert page["in_nav"] is False
    security = (
        Path(__file__).parents[1]
        / "maverick_dashboard"
        / "templates"
        / "security.html"
    ).read_text(encoding="utf-8")
    assert 'href="/third-party/collaboration"' in security
