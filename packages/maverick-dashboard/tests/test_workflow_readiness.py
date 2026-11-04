"""Published readiness links and permissions stay grounded in real routes."""
import pytest
from fastapi.testclient import TestClient
from maverick import config, world_model
from maverick_dashboard import workflow_readiness as readiness
from maverick_dashboard.app import app


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def test_every_readiness_link_is_a_registered_page():
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
    # FastAPI's included routers are lazy; a root app.routes scan misses them.
    for row in readiness.CATALOG:
        if row["href"]:
            assert client.get(row["href"]).status_code != 404, row["href"]
    assert set(row["stage"] for row in readiness.CATALOG) == set(readiness.LABELS)


def test_readiness_renders_limits_and_never_equates_enablement_with_acceptance():
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/workflow-readiness")
    assert response.status_code == 200
    assert "does not prove it works for your business" in response.text
    assert "Needs a real-world check" in response.text
    assert "Turned off in Settings" in response.text
    assert "Turn on in Settings" in response.text
    from test_support.plain_language import developer_terms

    assert developer_terms(response.text) == []
    pilot = next(row for row in readiness.for_request(None) if row["feature"] == "outcome_measurement")
    assert pilot["can_open"] is False
    assert response.headers["Cache-Control"] == "private, no-store"


def test_suite_and_role_filtering_keeps_unavailable_operations_out_of_links(monkeypatch):
    monkeypatch.setattr("maverick_dashboard.auth.suite_allowed", lambda request, suite: suite in {None, "finance"})
    monkeypatch.setattr("maverick_dashboard.auth.has_permission", lambda request, permission: permission == "view")
    rows = readiness.for_request(None)
    assert not any(row.get("suite") == "privacy" for row in rows)
    assert not any(row["can_open"] and row["permission"] != "view" for row in rows)


def test_supplier_catalog_points_to_setup_and_reports_unsupported_profile(monkeypatch):
    row = next(row for row in readiness.for_request(None) if row["href"] == "/third-party/vendor-onboarding")
    assert row["configuration"] == "Open the page to choose an owner and connect Jira"
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "2")
    row = next(row for row in readiness.for_request(None) if row["href"] == "/third-party/vendor-onboarding")
    assert row["configuration"] != "Open the page to choose an owner and connect Jira"
    assert row["stage_label"] == "Needs a real-world check"


def test_turned_off_page_explains_and_links_admins_to_settings(tmp_path):
    (tmp_path / "config.toml").write_text("[features]\nworkflow_readiness = false\n", encoding="utf-8")
    config.reset_config_cache()
    response = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"}).get("/workflow-readiness")
    assert response.status_code == 403
    assert "This page is turned off" in response.text
    assert 'href="/settings#settings-sections"' in response.text
    assert "disabled in Settings or configuration" not in response.text
