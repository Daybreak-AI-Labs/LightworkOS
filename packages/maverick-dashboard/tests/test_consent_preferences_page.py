"""Rendered contract for the Consent & Preferences operator workspace."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolated_consent_page(tmp_path, monkeypatch):
    from maverick import config

    config_path = tmp_path / "config.toml"
    config_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
    monkeypatch.setenv("MAVERICK_TENANT", "consent-page-test")
    for name in (
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
        "MAVERICK_TENANT_BY_USER",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    yield config_path
    config.reset_config_cache()


def test_consent_page_is_explicit_about_default_off_and_product_boundary():
    response = client.get("/consent")

    assert response.status_code == 200
    page = response.text
    assert "Consent and preferences" in page
    # Default-off is explicit, and the gate is switchable IN-APP: the shared
    # module-gate banner with a Turn on control, no config keys in the UI.
    assert 'data-module-gate="consent_preferences"' in page
    assert "Consent preferences is turned off." in page
    assert "[consent_preferences] enable = true" not in page
    assert "Consent management" in page
    for form in (
        "cp-policy-form",
        "cp-preference-form",
        "cp-decision-form",
        "cp-tracker-form",
        "cp-analytics-form",
        "cp-identity-form",
        "cp-profile-form",
    ):
        assert f'id="{form}"' in page
    assert 'data-module-gate="consent_preferences.analytics"' in page
    assert "[consent_preferences.analytics] enable = true" not in page
    assert "Small groups are hidden" in page
    # The optional consent register is off by default: the page shows its
    # turned-off card and does not ask for records it cannot have.
    assert 'data-registry-enabled="false"' in page
    assert 'data-module-gate="consent_registry"' in page
    assert "Consent register is turned off." in page
    assert "[consent_registry]" not in page
    assert "/identity-links/integrity?limit=500" in page
    assert "Links change only when the person verifies themselves" in page
    assert 'value="web_tracker"' in page
    assert "consent_required" not in page


def test_consent_page_lists_records_with_row_buttons_and_no_typed_plumbing(
    _isolated_consent_page,
):
    from maverick import config

    from test_support.plain_language import developer_terms

    _isolated_consent_page.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.analytics]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()

    response = client.get("/consent")

    assert response.status_code == 200
    page = response.text
    assert "Module disabled." not in page
    # Records load on page open and every row carries its own buttons.
    for host in ("cp-policy-table", "cp-profile-table", "cp-tracker-table"):
        assert f'id="{host}"' in page
    for label in ("New policy", "Add a person", "Add a tracker", "Record a choice",
                  "Check consent", "Linked accounts", "Publish new version"):
        assert label in page
    assert '/profiles?limit=500' in page and '/trackers?limit=500' in page
    # The privacy register's totals (a command-line-only view before) show here.
    assert 'call("/posture")' in page and 'id="cp-posture"' in page
    # Versions, fingerprints and request references are carried, never typed.
    assert '<input type="hidden" name="version">' in page
    assert '<input type="hidden" name="expected_current_version">' in page
    assert '<input type="hidden" name="notice_sha256">' in page
    assert '<input type="hidden" name="expected_revision">' in page
    assert 'data-auto-reference name="idempotency_key"' in page
    assert 'type="datetime-local"' in page and 'type="date"' in page
    assert 'id="cp-notice-select"' in page and 'type="file"' in page
    assert "Subject SHA-256" not in page and "Notice SHA-256" not in page
    assert "Effective timestamp" not in page
    assert "mvConfirm" not in page or "CW.confirm" in page
    assert "CW.confirm(" in page
    assert developer_terms(page) == []


@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("lightwork-consent-workbench.js", "application/javascript"),
        ("lightwork-consent-workbench.css", "text/css"),
    ],
)
def test_consent_workbench_assets_are_served(name, kind):
    response = client.get(f"/static/{name}")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith(kind)
