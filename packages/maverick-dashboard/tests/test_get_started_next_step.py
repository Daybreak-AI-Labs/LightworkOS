"""Get started shows one next step.

A fresh install used to open on 33-36 controls: five "Add an AI provider key"
buttons, eight primary buttons, six "Turn on" assurance buttons and two red
"Needs attention" panels. The page now leads with the next step and one
primary action, keeps the checklist, folds every other way in and shows the
assurance features as optional for later, never as an alarm. Nothing that was
reachable before is removed.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient


def _verdict(verdict: str) -> dict:
    action = None if verdict == "ready" else {"label": "Add an AI provider key",
                                              "href": "/settings#settings-integrations"}
    return {
        "providers": [], "verdict": verdict,
        "verdict_label": {"ready": "Connected", "not_ready": "Not connected"}[verdict],
        "badge_class": "ok" if verdict == "ready" else "blocked",
        "reason": {"ready": "OpenAI connected: the last connection test worked.",
                   "not_ready": "Anthropic (Claude) is not set up, and your models use it."}[verdict],
        "next_action": action, "summary": "", "configured_count": 0, "connected_count": 0, "total": 14,
    }


@pytest.fixture
def start_page(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_WORKDIR", str(tmp_path / "work"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    config_path = tmp_path / "config.toml"
    config_path.write_text("[client]\nid = 'get-started'\n", encoding="utf-8")  # the installer wrote it
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    from maverick import config, world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    import maverick.templates as tpl
    monkeypatch.setattr(tpl, "USER_TEMPLATES", tmp_path / ".maverick" / "templates")
    import maverick.domain_edit as de
    monkeypatch.setattr(de, "list_agents", list)
    config.reset_config_cache()
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import onboarding_state
    dashboard._world_cache.clear()

    def render(*, ready: bool) -> str:
        monkeypatch.setattr(onboarding_state, "workspace_readiness",
                            lambda: _verdict("ready" if ready else "not_ready"))
        monkeypatch.setattr(onboarding_state, "selected_model_route_state", lambda: {
            "status": "configured" if ready else "incomplete", "configured": ready, "detail": "",
            "evidence": {"kind": "offline_configuration", "live_provider_verified": False}})
        page = TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/start")
        assert page.status_code == 200
        return page.text

    yield render
    config.reset_config_cache()


def _main(page: str) -> str:
    return page.split('<main id="content"', 1)[1].split("</main>", 1)[0]


def _outside_folds(html: str) -> str:
    """What a person sees without opening a folded section."""
    html = re.sub(r"<(script|style)\b.*?</\1>", " ", html, flags=re.DOTALL)
    previous = None
    while previous != html:  # innermost folded sections first
        previous = html
        html = re.sub(r"<details\b(?:(?!<details\b).)*?</details>", " ", html, flags=re.DOTALL)
    return html


def _controls(html: str) -> int:
    return len(re.findall(r"<(?:a\s[^>]*href|button\b|select\b|input\b(?![^>]*type=\"hidden\"))", html))


def test_a_fresh_install_leads_with_one_next_step_and_one_primary_action(start_page):
    page = start_page(ready=False)
    seen = _outside_folds(_main(page))
    primaries = re.findall(r'class="[^"]*\bbtn--primary\b[^"]*"', seen)
    assert len(primaries) == 1, primaries
    next_step = seen.split('class="panel gs__next"', 1)[1].split("</section>", 1)[0]
    assert "Next step" in next_step and "Connect your AI service" in next_step
    assert 'href="/settings#settings-integrations">Add an AI provider key</a>' in next_step
    assert seen.count(">Add an AI provider key<") == 1
    assert _controls(seen) <= 14, _controls(seen)


def test_assurance_features_are_optional_not_an_alarm(start_page):
    page = start_page(ready=False)
    main = _main(page)
    assert re.search(r'<details class="[^"]*\bgs__optional\b', main), "assurance setup is an optional fold"
    optional = main.split("gs__optional", 1)[1]  # the last section on the page
    assert "Optional" in optional and "gs__status--blocked" not in optional
    assert "Needs attention" not in optional
    # Folded away: its Turn on buttons are not on the page until opened.
    assert "Turn on" not in _outside_folds(main)
    assert 'data-module-gate="evidence_graph"' in main  # still one click away


def test_everything_that_was_reachable_still_is(start_page):
    main = _main(start_page(ready=False))
    for href in ("/agents", "/chat", "/deliverables", "/permissions", "/start/setup",
                 "/settings#settings-integrations", "/security/assurance", "/get-started/employee"):
        assert f'href="{href}"' in main, href
    for text in ("Test connections", "Run checks again", "Download setup report",
                 "Choose your first outcome", "Installation checks", "Fix next:"):
        assert text in main, text


def test_with_ai_ready_the_next_step_is_running_the_sample_task(start_page):
    page = start_page(ready=True)
    seen = _outside_folds(_main(page))
    primaries = re.findall(r'<(?:a|button)\b[^>]*class="[^"]*\bbtn--primary\b[^"]*"[^>]*>', seen)
    assert len(primaries) == 1 and 'id="first-outcome-run"' in primaries[0], primaries
    next_step = seen.split('class="panel gs__next"', 1)[1].split("</section>", 1)[0]
    assert "Run your first task on sample data" in next_step
    assert 'href="/agents"' in next_step or 'href="/chat"' in next_step  # or describe your own
    assert seen.count('id="first-outcome-department"') == 1
