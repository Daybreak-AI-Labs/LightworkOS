"""Visual goal-templates marketplace (/templates, /api/v1/templates[,/suggested])
and the chat-form prefill it links to."""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    from maverick_dashboard import api as api_mod
    from maverick_dashboard import app as app_mod
    api_mod._world_cache.clear()
    app_mod._world_cache.clear()
    # Deterministic template catalog: a tmp user dir, no bundled repo templates.
    import maverick.templates as tpl_mod
    user_dir = tmp_path / "templates"
    user_dir.mkdir()
    monkeypatch.setattr(tpl_mod, "USER_TEMPLATES", user_dir)
    monkeypatch.setattr(tpl_mod, "_BUNDLED_CANDIDATES", [])
    yield user_dir


@pytest.fixture
def catalog(_isolated):
    (_isolated / "trip-plan.md").write_text(
        "---\nowner: local\ntitle: Plan a trip to {{ city }}\nparams:\n  - city\n---\n"
        "Plan a trip to {{ city }} under budget.",
        encoding="utf-8",
    )
    (_isolated / "research-report.md").write_text(
        "---\nowner: local\ntitle: Research a topic\n---\nResearch it deeply.",
        encoding="utf-8",
    )
    return _isolated


def test_templates_page_lists_catalog_with_ratings(catalog):
    from maverick.marketplace.ratings import RatingsLedger
    RatingsLedger().rate("templates", "trip-plan", 4)
    r = client.get("/templates")
    assert r.status_code == 200
    assert "trip-plan" in r.text and "research-report" in r.text
    assert "★★★★☆" in r.text       # rated template
    assert "Not rated yet" in r.text      # the other one
    # (Templates is folded out of the sidebar in the moderate declutter; still
    # reachable at /templates and rendered above.)


def test_use_template_collects_inputs_before_chat_review(catalog):
    r = client.get("/templates")
    # In-app preparation collects declared inputs without exposing drafts in URLs.
    assert 'data-prepare-template' in r.text
    assert 'data-template-param="city"' in r.text
    assert 'Check in Chat' in r.text
    assert 'You&#39;ll be asked for: city' in r.text or "You'll be asked for: city" in r.text
    assert 'href="/chat?title=' not in r.text
    # No goal was created by rendering the marketplace.
    from maverick_dashboard.app import _world
    assert _world().list_goals() == []


def test_templates_page_empty_state(_isolated):
    r = client.get("/templates")
    assert r.status_code == 200
    assert "No templates yet" in r.text


def test_templates_api(catalog):
    from maverick.marketplace.ratings import RatingsLedger
    RatingsLedger().rate("templates", "research-report", 5)
    body = client.get("/api/v1/templates").json()
    by_name = {e["name"]: e for e in body["templates"]}
    assert by_name["trip-plan"]["params"] == ["city"]
    assert by_name["trip-plan"]["stars"] is None
    assert by_name["research-report"]["stars"] == 5
    assert by_name["research-report"]["rating_bar"].startswith("★★★★★")


def test_suggested_api_ranks_for_this_user(catalog):
    from maverick_dashboard.app import _world
    w = _world()
    for _ in range(3):
        w.create_goal("research the market", "")
    body = client.get("/api/v1/templates/suggested").json()
    names = [e["name"] for e in body["suggested"]]
    assert names[0] == "research-report"
    assert body["suggested"][0]["score"] > 0
    # k caps the list.
    assert len(client.get("/api/v1/templates/suggested?k=1").json()["suggested"]) == 1


def test_chat_prefill_from_query_params(catalog):
    r = client.get("/chat", params={
        "title": 'Plan a "big" trip', "description": "Use <param> {{ city }}",
    })
    assert r.status_code == 200
    # Prefilled, HTML-escaped, and the details block is opened.
    # The composer's message box is a textarea: the title is its escaped text.
    assert '>Plan a &#34;big&#34; trip</textarea>' in r.text
    assert "Use &lt;param&gt; {{ city }}" in r.text
    assert "<details open>" in r.text
    # No prefill -> unchanged empty form.
    r2 = client.get("/chat")
    assert re.search(r'id="composer-title"[^>]*>\s*</textarea>', r2.text) and "<details>" in r2.text
