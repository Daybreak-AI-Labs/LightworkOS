"""Scheduled attack checks on the AI assurance page: rendered controls."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

_BANNED = re.compile(
    r"\b(tenant|principal|payload|endpoint|schema|uuid|sha-?256|digest|json|revision|"
    r"idempoten\w*|cadence|materiali[sz]e)\b|/api/v1|HTTP \d{3}|maverick red-team",
    re.IGNORECASE,
)


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "alpha")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _red_team_on(monkeypatch) -> None:
    from maverick import ai_evidence_gateway, external_agents, red_team_assurance

    monkeypatch.setattr(ai_evidence_gateway, "enabled", lambda: False)
    monkeypatch.setattr(red_team_assurance, "enabled", lambda: True)
    monkeypatch.setattr(
        red_team_assurance,
        "list_campaigns",
        lambda **_kwargs: {"items": [], "count": 0, "truncated": False, "limit": 20},
    )
    monkeypatch.setattr(
        external_agents,
        "roster",
        lambda: [{"id": "runner-one", "active": True, "display_name": "Night runner",
                  "platform_label": "Isolated test runner"}],
    )


def _section(page: str) -> str:
    tail = page.split('id="rts-root"', 1)[1]
    return tail.split(">", 1)[1].split("</form>", 1)[0]


def test_admin_sees_schedule_list_form_and_run_due_button(monkeypatch):
    _red_team_on(monkeypatch)
    page = client.get("/security/assurance").text
    assert 'id="rts-root"' in page
    assert 'id="rts-rows"' in page
    assert 'id="rts-run-due"' in page
    assert 'id="rts-create"' in page
    assert 'type="datetime-local" name="first_run_at"' in page
    assert '<option value="604800" selected>Every week</option>' in page
    assert 'value="runner-one"' in page
    assert "data-auto-reference" in _section(page)
    assert '/static/lightwork-red-team-schedules.js' in page
    names = page.split('id="rts-names">', 1)[1].split("</script>", 1)[0]
    assert '"runner-one": "Night runner"' in names


def test_schedule_section_speaks_plainly(monkeypatch):
    _red_team_on(monkeypatch)
    page = client.get("/security/assurance").text
    section = _section(page)
    visible = re.sub(
        r"<script[\s\S]*?</script>|<style[\s\S]*?</style>|<[^>]+>", " ", section,
    )
    assert "Scheduled checks" in visible
    assert "Schedule a check" in visible
    assert not _BANNED.search(visible), visible


def test_non_admin_sees_the_list_but_no_controls(monkeypatch):
    from maverick_dashboard import auth

    _red_team_on(monkeypatch)
    monkeypatch.setattr(auth, "has_global_permission", lambda *_args: False)
    page = client.get("/security/assurance").text
    assert 'id="rts-rows"' in page
    assert 'data-admin="0"' in page
    assert 'id="rts-run-due"' not in page
    assert 'id="rts-create"' not in page


def test_schedule_section_hidden_while_attack_testing_is_off(monkeypatch):
    from maverick import red_team_assurance

    monkeypatch.setattr(red_team_assurance, "enabled", lambda: False)
    page = client.get("/security/assurance").text
    assert 'id="rts-root"' not in page


def test_schedule_script_is_served():
    response = client.get("/static/lightwork-red-team-schedules.js")
    assert response.status_code == 200
    assert "javascript" in response.headers["content-type"]
    assert "mvConfirm" in response.text
    assert "window.confirm(" not in response.text
