"""Rendered contract for the consent publishing operator workspace."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def isolated_page(tmp_path, monkeypatch):
    from maverick import config

    path = tmp_path / "config.toml"
    path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "publishing-page")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield path
    config.reset_config_cache()


def test_page_exposes_full_publishing_lifecycle_and_default_off_boundary() -> None:
    response = client.get("/consent/publishing")
    assert response.status_code == 200
    page = response.text
    assert "Banner and preference center" in page
    assert 'data-module-gate="consent_preferences.publishing"' in page
    assert "Consent publishing is turned off." in page
    assert "[consent_preferences.publishing] enable = true" not in page
    # Everything sits inside the natively disabled workbench while turned off.
    assert re.search(r'id="cpp-root"[^>]*disabled', page)
    for element in (
        "cpp-property-table",
        "cpp-property",
        "cpp-resource-table",
        "cpp-resource",
        "cpp-promotion",
        "cpp-history-panel",
        "cpp-preview",
        "cpp-publish",
    ):
        assert f'id="{element}"' in page
    for kind in ("Uses of data", "Topics", "Extra questions", "Privacy notices",
                 "Banner designs", "Brand themes", "Languages", "Display rules"):
        assert f">{kind}</option>" in page
    script = client.get("/static/lightwork-consent-publishing.js").text
    assert "innerHTML" not in script
    # Destructive and public actions confirm with a plain consequence.
    for phrase in ("Publish to ", "Restore version "):
        assert phrase in script
    assert script.count("CW.confirm(") >= 3
    # Withdrawing a banner is a separate review of every address it shows on.
    assert "Review every current address and the exact banner. Keep the banner to cancel." in script
    assert "window.confirm" not in script


def test_enabled_page_removes_disabled_banner_and_speaks_plainly(isolated_page) -> None:
    from maverick import config

    from test_support.plain_language import developer_terms

    isolated_page.write_text(
        "[consent_preferences]\nenable = true\n[consent_preferences.publishing]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    page = client.get("/consent/publishing").text
    assert 'data-module-gate="consent_preferences.publishing"' not in page
    assert re.search(r'id="cpp-root"[^>]*disabled', page) is None
    # Revisions and request references ride in hidden fields from the row.
    for name in ("expected_revision", "expected_property_revision",
                 "expected_publication_revision", "expected_current_version"):
        assert f'<input type="hidden" name="{name}"' in page
    assert page.count('data-auto-reference name="idempotency_key"') == 2
    for typed in ("Property ID", "Resource ID", "Target publication ID", "Rule group version",
                  "Publication details JSON", "hexadecimal"):
        assert typed not in page
    assert developer_terms(page) == []
    assert "Banner and preference center" in client.get("/consent").text
