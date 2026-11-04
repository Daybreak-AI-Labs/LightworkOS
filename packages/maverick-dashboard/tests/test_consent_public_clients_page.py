from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def isolated_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import config, world_model

    path = tmp_path / "config.toml"
    path.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.publishing]\nenable = true\n"
        "[consent_preferences.public_api]\nenable = true\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-a")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
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


def test_public_clients_page_explains_once_only_credentials_and_sdk(isolated_page: Path) -> None:
    from maverick import config

    from test_support.plain_language import developer_terms

    isolated_page.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.publishing]\nenable = true\n"
        "[consent_preferences.public_api]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    response = client.get("/consent/public-clients")
    assert response.status_code == 200
    page = response.text
    assert "Website and app keys" in page
    assert "shown only once" in page and "Your new key (shown once)" in page
    assert "LightworkConsent" in page
    assert "/api/v1/public/consent/sdk.js" in page
    assert "window.location.origin" in page and "YOUR-LIGHTWORK" not in page
    # Existing keys and signed-in people load as rows with their own buttons.
    assert 'id="pcc-table"' in page and 'id="pcc-profiles"' in page
    assert 'call("/profiles?limit=500")' in page
    for label in ("Create a key", "Revoke", "Revoke access", "Copy key", "Copy website code"):
        assert label in page
    assert page.count("CW.confirm(") >= 2
    # Everything is chosen from lists; nothing is typed that a person cannot know.
    for typed in ("Property ID", "Rule group version", "Receipt policy ID", "Client ID",
                  "Review evidence SHA-256", "Profile reference"):
        assert typed not in page
    assert developer_terms(page) == []


def test_public_clients_page_reports_gate_off(isolated_page: Path) -> None:
    isolated_page.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.publishing]\nenable = true\n"
        "[consent_preferences.public_api]\nenable = false\n",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    response = client.get("/consent/public-clients")
    assert response.status_code == 200
    assert 'data-module-gate="consent_preferences.public_api"' in response.text
    assert "Consent public clients is turned off." in response.text
    assert "[consent_preferences.public_api]" not in response.text
