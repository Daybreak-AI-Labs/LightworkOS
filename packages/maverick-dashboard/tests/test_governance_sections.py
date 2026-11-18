"""Governance tools that are turned off are not called from /security/assurance.

Live: every turned-off tool on the page called its API on load, got 403 or
404, and showed "Your sign-in or access changed", "Rules could not be
loaded" and similar false errors, plus the raw "([ai_business_intake]
enable)" switch name.
"""
from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import governance_sections
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "governance-sections-test")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH", "MAVERICK_OIDC_ENABLED",
                 "MAVERICK_PROXY_AUTH", "MAVERICK_TENANT_BY_USER"):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield path
    config.reset_config_cache()


def _section_tag(page, panel_id):
    match = re.search(rf'<section id="{panel_id}"[^>]*>', page)
    assert match, panel_id
    return match.group(0)


def test_turned_off_tools_are_hidden_and_marked_so_the_page_never_calls_them():
    page = client.get("/security/assurance").text
    for panel_id in governance_sections.SECTIONS:
        tag = _section_tag(page, panel_id)
        assert " hidden" in tag and "data-feature-off=" in tag, tag
    summary = re.search(r'<details[^>]*data-governance-off[^>]*>.*?</details>', page, re.DOTALL)
    assert summary, "one plain turned-off summary"
    text = summary.group(0)
    assert f"{len(governance_sections.SECTIONS)} tools here are turned off" in text
    assert "AI business intake" in text and "AI training records" in text
    # Switch names stay out of the page; no suggestions widget asks a turned-off API.
    assert "[ai_business_intake]" not in page and "enable)" not in page
    assert 'data-kind="ai-policy"' not in page


def test_a_turned_on_tool_loads_as_before(_isolated):
    from maverick import config

    _isolated.write_text("[ai_literacy]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    page = client.get("/security/assurance").text
    assert "data-feature-off" not in _section_tag(page, "ai-literacy-panel")
    assert "data-feature-off" in _section_tag(page, "ai-business-intake-panel")


def test_an_unreadable_switch_is_not_reported_as_off(monkeypatch):
    from maverick import ai_literacy

    def broken():
        raise RuntimeError("synthetic")

    monkeypatch.setattr(ai_literacy, "enabled", broken)
    assert "ai-literacy-panel" not in {row["id"] for row in governance_sections.off_sections()}


def test_turned_off_ai_use_rules_answer_as_turned_off_not_missing():
    response = client.get("/api/v1/policy-suggestions?kind=ai-policy")
    assert response.status_code == 403
    assert response.headers["X-Lightwork-Reason"] == "feature-off"
    assert response.json()["detail"] == "AI use rules are turned off."
