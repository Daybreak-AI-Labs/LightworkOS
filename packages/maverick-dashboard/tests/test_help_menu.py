"""Help on every page: the AI service banner, a person to ask with the
context filled in, and "How this works" for the page's task."""
from __future__ import annotations

import html
import re
from pathlib import Path

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from maverick.oidc import VerifiedPrincipal

TEMPLATES = Path(__file__).parents[1] / "maverick_dashboard" / "templates"
FAILURE = "lw-failure-" + "0123456789abcdef" * 2


@pytest.fixture
def client_and_world(monkeypatch, tmp_path):
    from maverick import circuit_breaker, config, world_model
    from maverick_dashboard import app as dashboard
    from maverick_dashboard import auth

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    circuit_breaker.reset_all()
    dashboard._world_cache.clear()

    async def bind(request: Request):
        request.state.principal = VerifiedPrincipal(sub=("user:alice").removeprefix("user:"), issuer="https://idp.test", audience="lightwork")
        return request.state.principal

    dashboard.app.dependency_overrides[auth.require_principal_in_request_context] = bind
    monkeypatch.setattr(auth, "role_for_principal", lambda _principal: "operator")
    try:
        with TestClient(dashboard.app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}) as client:
            yield client, dashboard._world(), tmp_path
    finally:
        dashboard.app.dependency_overrides.clear()
        dashboard._world_cache.clear()
        circuit_breaker.reset_all()
        config.reset_config_cache()


def _support(tmp_path, **values):
    from maverick import config

    body = "[support]\n" + "".join(f'{key} = "{value}"\n' for key, value in values.items())
    (tmp_path / "config.toml").write_text(body, encoding="utf-8")
    config.reset_config_cache()


def _pause(provider="anthropic"):
    from maverick import circuit_breaker

    breaker = circuit_breaker.get(f"llm:{provider}")
    for _ in range(breaker.failure_threshold):
        breaker.record_failure()


@pytest.mark.parametrize("path", ["/goals", "/chat"])
def test_both_shells_offer_a_person_and_help_for_this_page(client_and_world, path):
    client, _world, _home = client_and_world
    page = client.get(path).text
    assert 'id="help-menu"' in page
    assert "Get help from a person" in page and "data-get-help" in page
    assert 'href="/help"' in page and "Help and diagnostics" in page
    assert re.search(r'href="/help#how-[a-z-]+"', page), "How this works for the page's task"
    assert "lightwork-help-menu.js" in page
    assert "Service status" not in page  # no status page configured: no link


def test_the_status_page_appears_in_the_help_menu_only_when_set(client_and_world):
    client, _world, home = client_and_world
    _support(home, status_page_url="https://status.example.com/lightwork")
    page = client.get("/goals").text
    assert 'href="https://status.example.com/lightwork"' in page and "data-service-status-link" in page
    _support(home, status_page_url="http://status.example.com")
    assert "data-service-status-link" not in client.get("/goals").text


@pytest.mark.parametrize("path", ["/goals", "/chat"])
def test_a_paused_ai_service_shows_what_is_affected_tasks_and_next_check_on_every_page(client_and_world, path):
    client, _world, _home = client_and_world
    assert 'id="service-status-banner"' not in client.get(path).text
    _pause("anthropic")
    page = html.unescape(client.get(path).text)
    banner = page[page.index('id="service-status-banner"'):]
    banner = banner[:banner.index("</div>")]
    assert 'data-service-level="down"' in banner
    assert "Anthropic is paused after repeated errors" in banner          # what is affected
    assert "stop and show “Failed”" in banner and "kept" in banner          # what happens to tasks
    assert "Lightwork tries Anthropic again at" in banner and "<time" in banner  # when it checks again


def test_get_help_from_a_person_is_prefilled_with_page_task_and_error_reference(client_and_world):
    client, world, _home = client_and_world
    goal = world.create_goal("Quarterly PRIVATE vendor review", owner="user:alice")
    world.set_goal_status(goal, "failed", result="PRIVATE FAILURE TEXT")
    page = client.get(f"/help?from=/chat/goal/{goal}&task={goal}&failure={FAILURE}").text
    body = html.unescape(page[page.index('id="get-help-body"'):page.index("</textarea>")])
    assert f"Page: /chat/goal/{goal}" in body
    assert f"Task: #{goal}" in body
    assert f"Error reference: {FAILURE}" in body
    assert "PRIVATE" not in body  # never task text or results
    assert "Lightwork administrator" in page  # no support address set: it goes to the administrator
    assert 'id="get-help-email"' not in page
    assert 'href="#issue-report"' in page  # the existing task report is one step away


def test_get_help_drops_values_it_cannot_trust(client_and_world):
    client, _world, _home = client_and_world
    page = html.unescape(client.get("/help?from=//evil.example/x&task=999999&failure=lw-failure-zz").text)
    body = page[page.index('id="get-help-body"'):page.index("</textarea>")]
    assert "Page:" not in body and "Task:" not in body and "Error reference:" not in body


def test_a_configured_support_address_gets_an_email_draft_nothing_is_sent(client_and_world):
    client, _world, home = client_and_world
    _support(home, contact_email="help@vendor.example")
    page = html.unescape(client.get("/help?from=/goals").text)
    assert "Your support contact is" in page and "help@vendor.example" in page
    link = re.search(r'id="get-help-email" href="([^"]+)"', page).group(1)
    assert link.startswith("mailto:help@vendor.example?subject=Lightwork%20help%20request")
    assert "Page%3A%20/goals" in link
    assert "Nothing is sent automatically" in page


def test_every_how_this_works_topic_has_steps_on_help_and_current_labels():
    from maverick_dashboard.help_topics import TOPICS, topic_for

    assert len(TOPICS) == 20
    assert len({topic.slug for topic in TOPICS}) == 20
    for topic in TOPICS:
        assert topic.steps and all(step.endswith((".", ")")) for step in topic.steps), topic.slug
        for path in topic.paths:
            assert topic_for(path) is topic, path
        for template, label in topic.labels:  # stale help fails the build
            assert label in html.unescape((TEMPLATES / template).read_text(encoding="utf-8")), (topic.slug, label)
    assert topic_for("/chat/goal/12").slug == "follow-task"
    assert topic_for("/chat").slug == "start-task"
    assert topic_for("/nowhere") is None


def test_the_help_page_lists_every_topic_as_steps(client_and_world):
    from maverick_dashboard.help_topics import TOPICS

    client, _world, _home = client_and_world
    page = html.unescape(client.get("/help").text)
    for topic in TOPICS:
        assert f'id="how-{topic.slug}"' in page
        assert topic.steps[0] in page
