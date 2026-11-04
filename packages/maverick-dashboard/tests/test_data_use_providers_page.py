"""Rendering contract for the native Data Use Governance console."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def isolated_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    from maverick import config, world_model
    from maverick.audit import writer as audit_writer

    path = tmp_path / "config.toml"
    path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    monkeypatch.setenv("MAVERICK_TENANT", "provider-page")
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    for name in (
        "MAVERICK_DASHBOARD_ADMINS",
        "MAVERICK_DASHBOARD_TOKEN",
        "MAVERICK_DASHBOARD_REQUIRE_AUTH",
        "MAVERICK_OIDC_ENABLED",
        "MAVERICK_PROXY_AUTH",
    ):
        monkeypatch.delenv(name, raising=False)
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield path
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def test_native_provider_page_explains_disabled_and_external_boundaries() -> None:
    from test_support.plain_language import developer_terms

    response = client.get("/data-use/providers")
    assert response.status_code == 200
    page = response.text
    assert "Snowflake and Databricks" in page
    assert 'data-module-gate="data_use_governance.enforcement"' in page
    assert 'data-module-gate="data_use_governance.snowflake"' in page
    assert 'data-module-gate="data_use_governance.databricks"' in page
    assert "not to how it was before Lightwork" in page
    assert "never typed here" in page
    assert "nobody can type database commands here" in page
    # Mapping tables and confirmations instead of typed documents and codes.
    assert 'id="dup-field-map"' in page and 'id="dup-mask-map"' in page and 'id="dup-row-map"' in page
    for typed in ("Field map JSON", "mask bindings JSON", "SHA-256", "Binding ID", "Decision ID",
                  "Current version"):
        assert typed not in page
    assert page.count("CW.confirm(") >= 2
    assert developer_terms(page) == []


def test_native_provider_page_reflects_exact_direct_provider_gate(
    isolated_page: Path,
) -> None:
    from maverick import config

    isolated_page.write_text(
        "[data_use_governance]\n"
        "enable = true\n"
        "[data_use_governance.compiler]\n"
        "enable = true\n"
        "[data_use_governance.enforcement]\n"
        "enable = true\n"
        "[data_use_governance.snowflake]\n"
        "enable = true\n"
        'origin = "https://acct1.snowflakecomputing.com"\n'
        'credential_secret_ref = "$SNOWFLAKE_TOKEN"\n',
        encoding="utf-8",
    )
    config.reset_config_cache()
    page = client.get("/data-use/providers").text
    assert 'data-module-gate="data_use_governance.enforcement"' not in page
    assert 'data-module-gate="data_use_governance.snowflake"' not in page
    assert 'data-module-gate="data_use_governance.databricks"' in page
    assert 'data-snowflake="true"' in page and 'data-databricks="false"' in page
