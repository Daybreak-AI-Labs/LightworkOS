"""Rendered contract for the Data Use Governance workspace."""

from __future__ import annotations

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
    monkeypatch.setenv("MAVERICK_TENANT", "data-use-page")
    from maverick import world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
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


def test_default_off_page_exposes_authority_workflows_and_limits() -> None:
    from test_support.plain_language import developer_terms

    response = client.get("/data-use")
    assert response.status_code == 200
    page = response.text
    assert "Data use rules" in page
    assert 'data-module-gate="data_use_governance"' in page
    assert "[data_use_governance] enable = true" not in page
    for form in ("dug-catalog", "dug-context", "dug-policy", "dug-request", "dug-label",
                 "dug-exception", "dug-assign"):
        assert f'id="{form}"' in page
    # Every record type loads as a list with row buttons.
    for host in ("dug-assets", "dug-contexts", "dug-labels", "dug-policies",
                 "dug-exceptions", "dug-requests"):
        assert f'id="{host}"' in page
    assert "each from a different source" in page
    assert "a second person switches it on" in page
    # The policy is built from choices, never typed as a document.
    assert "Closed policy document" not in page and "<textarea class=\"input\" name=\"document\"" not in page
    for typed in ("SHA-256", "Unix", "Asset ID", "Request ID", "Decision ID", "Expected pointer",
                  "comma separated)", "control IR"):
        assert typed not in page
    assert developer_terms(page) == []


def test_request_form_offers_the_persons_projects(isolated_page) -> None:
    from maverick import config
    from maverick_dashboard._shared import _world

    isolated_page.write_text("[data_use_governance]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    project_id = _world().create_project("Spring campaign")
    page = client.get("/data-use").text
    assert f'<option value="project-{project_id}">Spring campaign</option>' in page


def test_enabled_authority_still_labels_disabled_compiler(isolated_page) -> None:
    from maverick import config

    isolated_page.write_text(
        "[data_use_governance]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    page = client.get("/data-use").text
    assert 'data-module-gate="data_use_governance"' not in page
    assert 'data-module-gate="data_use_governance.compiler"' in page
    assert "[data_use_governance.compiler] enable = true" not in page

    isolated_page.write_text(
        "[data_use_governance]\nenable = true\n"
        "[data_use_governance.compiler]\nenable = true\n",
        encoding="utf-8",
    )
    config.reset_config_cache()
    assert (
        'data-module-gate="data_use_governance.compiler"'
        not in client.get("/data-use").text
    )
