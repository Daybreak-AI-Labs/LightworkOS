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


def test_page_renders_in_the_worker_pool_not_on_the_event_loop() -> None:
    """The page checks its settings and permissions and renders the shell, all
    file reads; FastAPI runs a plain ``def`` handler in its worker pool."""
    import inspect

    router = page.create_regulatory_obligations_page_router(_templates())
    endpoints = [route.endpoint for route in router.routes if getattr(route, "path", None) == page.PAGE_PATH]
    assert endpoints
    assert not any(inspect.iscoroutinefunction(endpoint) for endpoint in endpoints)


def test_a_refused_update_feed_is_released_so_the_page_settles() -> None:
    """With the regulatory feed off, its notices list answers 403. The page
    read only the status and left the body unread, so the request never
    finished and the page never reached network idle."""
    import json
    import re
    import shutil
    import subprocess

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable")
    source = (
        Path(__file__).resolve().parents[1] / "maverick_dashboard" / "static"
        / "lightwork-regulatory-obligations.js"
    ).read_text(encoding="utf-8")
    match = re.search(r"\n  async function readJson\(response\) \{\n.*?\n  \}\n", source, re.DOTALL)
    assert match
    harness = match.group(0) + """
var maxResponseBytes = 1024;
var released = false;
var body = new ReadableStream({
  start(controller) { controller.enqueue(new TextEncoder().encode('{"detail":"off"}')); },
  cancel() { released = true; },
});
readJson(new Response(body, { status: 403 })).then(
  function () { console.log(JSON.stringify({ thrown: false, released: released })); },
  function (failure) { console.log(JSON.stringify({ thrown: true, status: failure.status, released: released })); });
"""
    completed = subprocess.run(  # noqa: S603 - exact local interpreter
        [node, "-e", harness], capture_output=True, check=False, text=True, timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"thrown": True, "status": 403, "released": True}


def test_regulatory_updates_are_not_asked_for_while_the_feed_is_off(monkeypatch) -> None:
    # Live: every visit logged a refused regulatory-feed request (403) in the
    # browser console. The page says whether the feed is on, so its script
    # shows the turned-off line without asking.
    from maverick import ai_regulatory_feed

    monkeypatch.setattr(ai_regulatory_feed, "enabled", lambda: False)
    body = _app(monkeypatch, {"view"}).get(page.PAGE_PATH).text
    assert 'data-feed-enabled="false"' in body.split('id="rob-root"')[1].split(">")[0]
    monkeypatch.setattr(ai_regulatory_feed, "enabled", lambda: True)
    body = _app(monkeypatch, {"view"}).get(page.PAGE_PATH).text
    assert 'data-feed-enabled="true"' in body.split('id="rob-root"')[1].split(">")[0]
