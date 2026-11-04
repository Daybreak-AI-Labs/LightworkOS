from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
from fastapi.testclient import TestClient
from maverick_dashboard import regulatory_obligations_page as page


def _templates() -> Jinja2Templates:
    from maverick_dashboard.app import _theme_context

    selected = Jinja2Templates(
        directory=Path(page.__file__).parent / "templates",
        context_processors=[_theme_context],
    )
    selected.env.globals.update(
        nav_groups=[],
    )
    return selected


def _app(monkeypatch, allowed) -> TestClient:
    monkeypatch.setattr(page, "require_permission", lambda *_: None)
    monkeypatch.setattr(page, "has_permission",
                        lambda _request, permission: permission in allowed)
    app = FastAPI()
    app.include_router(page.create_regulatory_obligations_page_router(_templates()))
    return TestClient(app, base_url="http://127.0.0.1")


def test_page_is_wired_and_hardened(monkeypatch) -> None:
    response = _app(monkeypatch, {"view"}).get(page.PAGE_PATH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, private, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    csp = response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in csp and "style-src 'self' 'nonce-" in csp
    body = response.text
    assert "Regulations and rules" in body
    assert f'data-copilot-page="{page.PAGE_PATH}"' in body
    assert f'data-api-base="{page.API_BASE}"' in body
    assert page.ASSET_PATH in body
    assert 'id="rob-check-form"' in body and 'id="rob-library"' in body
    assert 'id="rob-gateway-preview-form"' in body
    assert 'id="rob-gateway-preview-state"' in body
    assert "Advanced: preview rules from an AI gateway" in body
    assert 'id="rob-action"' in body and "<select" in body
    # The strict style policy blocks style attributes; the page styles live in its nonce stylesheet.
    assert " style=" not in body.split('id="rob-root"')[1]
    for banned in ("maverick regulatory", "[compliance]", "profiles =", "JSON", "Tool / action",
                   "sql_query", "Vacuous", "rob-output"):
        assert banned not in body, banned


def test_unknown_query_params_are_404(monkeypatch) -> None:
    assert _app(monkeypatch, set()).get(page.PAGE_PATH + "?x=1").status_code == 404


def test_technical_disclosures_do_not_hide_decisions_or_enforcement_problems(monkeypatch) -> None:
    class DisclosureMarkup(HTMLParser):
        def __init__(self):
            super().__init__()
            self.details = []
            self.contexts = {}

        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if tag == "details":
                self.details.append(values)
            if values.get("id"):
                self.contexts[values["id"]] = list(self.details)

        def handle_endtag(self, tag):
            if tag == "details":
                self.details.pop()

    markup = DisclosureMarkup()
    markup.feed(_app(monkeypatch, {"view"}).get(page.PAGE_PATH).text)
    assert markup.contexts["rob-gateway-preview-form"]
    assert all("open" not in attrs for attrs in markup.contexts["rob-gateway-preview-form"])
    for identifier in ("rob-check-form", "rob-verdict", "rob-problem-list", "rob-health-title"):
        assert markup.contexts[identifier] == []


def test_page_requires_a_template_authority() -> None:
    with pytest.raises(TypeError):
        page.create_regulatory_obligations_page_router(object())  # type: ignore[arg-type]


def test_page_is_registered_in_the_nav_registry() -> None:
    from maverick_dashboard import ui_visibility
    entry = next(p for p in ui_visibility.PAGES if p["path"] == page.PAGE_PATH)
    assert entry["group"] == "Govern" and entry["floor"] == "view"
    assert entry.get("in_nav", True) is True
