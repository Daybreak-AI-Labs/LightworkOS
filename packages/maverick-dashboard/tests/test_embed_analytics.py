"""Embedded analytics web component: static JS route + demo page."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app, static_url

client = TestClient(app, base_url="http://127.0.0.1")


def test_component_js_served_with_correct_content_type():
    r = client.get("/static/lightwork-analytics.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/javascript")
    body = r.text
    # a real self-contained custom element, not a framework loader
    assert 'customElements.define("lightwork-analytics"' in body
    assert "extends HTMLElement" in body
    # it reads the existing endpoints and nothing else
    assert "/api/v1/spend" in body and "/api/v1/goals" in body
    # the same-origin + token caveats are documented in the file itself
    assert "HONEST LIMITS" in body
    assert "CORS" in body


def test_legacy_component_url_and_tag_still_work():
    # Pages embedded before the Lightwork rebrand load the old URL and use the
    # old tag; both must keep working.
    r = client.get("/static/maverick-analytics.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/javascript")
    assert 'customElements.define("maverick-analytics"' in r.text


def test_demo_page_embeds_component_and_documents_limits():
    r = client.get("/embed-demo")
    assert r.status_code == 200
    assert "<lightwork-analytics>" in r.text
    assert f'src="{static_url("lightwork-analytics.js")}"' in r.text
    # honest usage notes on the page, not just in the JS comment
    assert "Do not paste an administrator access key into shared HTML" in r.text
    assert "use individual sessions" in r.text
    assert "Copy the code" in r.text  # the snippet sits under Technical details
    assert "View-only" in r.text


def test_component_js_is_inert_text_for_other_methods():
    # only GET serves it; mutating verbs are 405, not silently accepted
    assert client.post(
        "/static/lightwork-analytics.js",
        headers={"Origin": "http://127.0.0.1"},
    ).status_code == 405
    assert client.post(
        "/static/maverick-analytics.js",
        headers={"Origin": "http://127.0.0.1"},
    ).status_code == 405
