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
        "[consent_preferences.delivery]\nenable = true\n",
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


def test_delivery_page_lists_destinations_and_confirms_external_sends(isolated_page: Path) -> None:
    from maverick import config

    from test_support.plain_language import developer_terms

    isolated_page.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.delivery]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    response = client.get("/consent/delivery")
    assert response.status_code == 200
    page = response.text
    assert "Send choices to other systems" in page
    assert "/api/v1/consent/delivery" in page
    # Records load on open, with a button per row.
    for host in ("cd-destination-table", "cd-dead-table", "cd-history-table", "cd-ambiguous-table"):
        assert f'id="{host}"' in page
    assert '"/destinations?limit=500"' in page
    for label in ("Add a destination", "Change signing key", "Stop sending", "Try again",
                  "Check again", "Prepare updates", "Send now", "Delete old records"):
        assert label in page
    # External calls and irreversible changes are confirmed in plain words.
    assert "over the internet" in page
    assert page.count("CW.confirm(") >= 5
    assert "window.confirm" not in page
    # Nothing to type that a person cannot know: no IDs, digests or seconds.
    for typed in ("Destination ID", "Message SHA-256", "Retention seconds", "Expected destination revision",
                  "Destination IDs (comma separated)"):
        assert typed not in page
    assert 'data-auto-reference name="idempotency_key"' in page
    assert developer_terms(page) == []


def test_delivery_page_reports_disabled_gate(
    isolated_page: Path,
) -> None:
    isolated_page.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.delivery]\nenable = false\n",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    response = client.get("/consent/delivery")
    assert response.status_code == 200
    assert 'data-module-gate="consent_preferences.delivery"' in response.text
    assert "Consent delivery is turned off." in response.text
    assert "[consent_preferences.delivery] enable = true" not in response.text
