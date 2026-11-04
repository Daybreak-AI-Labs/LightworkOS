"""Field Core Web Vitals in the dashboard: off by default, routes not addresses,
aggregate counts only, a feature-off refusal, and the administrators' view."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

ORIGIN = {"Origin": "http://127.0.0.1"}


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    from maverick import config, world_model
    from maverick_dashboard import app as app_mod

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("[analytics]\nweb_vitals = true\n")
    for name in ("MAVERICK_DASHBOARD_ADMINS", "MAVERICK_DASHBOARD_TOKEN", "MAVERICK_TENANT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    app_mod._world_cache.clear()
    config.reset_config_cache()
    yield tmp_path
    app_mod._world_cache.clear()
    config.reset_config_cache()


def _as(monkeypatch, principal, role="operator"):
    from maverick_dashboard import auth, rbac

    monkeypatch.setattr(auth, "caller_principal", lambda request: principal)
    monkeypatch.setattr(auth, "_authorization_principal", lambda request: principal)
    monkeypatch.setattr(auth, "role_for_principal", lambda p: role)
    monkeypatch.setattr(auth, "global_role_for_principal", lambda p: role)
    monkeypatch.setattr(rbac, "list_users", lambda: {principal: role})


def _client():
    from maverick_dashboard.app import app

    return TestClient(app, base_url="http://127.0.0.1", headers=ORIGIN, follow_redirects=False)


def _off(tmp_path):
    from maverick import config

    (tmp_path / "config.toml").write_text("")
    config.reset_config_cache()


def test_off_by_default_no_script_and_a_feature_off_refusal(isolated, monkeypatch):
    _off(isolated)
    _as(monkeypatch, "user:kim")
    client = _client()
    assert "lightwork-web-vitals.js" not in client.get("/goals").text
    refused = client.post("/api/v1/telemetry/vitals", json={"path": "/goals", "device": "desktop", "lcp": 900})
    assert refused.status_code == 403
    assert refused.headers["X-Lightwork-Reason"] == "feature-off"


def test_on_the_script_loads_in_both_shells_with_its_sample_rate(isolated, monkeypatch):
    from maverick import web_vitals

    _as(monkeypatch, "user:kim")
    client = _client()
    for page in ("/goals", "/chat"):
        text = client.get(page).text
        assert "lightwork-web-vitals.js" in text, page
        assert f'data-sample-rate="{web_vitals.SAMPLE_RATE}"' in text, page


def test_a_measurement_is_kept_under_its_route_not_its_address(isolated, monkeypatch):
    from maverick import web_vitals

    _as(monkeypatch, "user:kim")
    client = _client()
    for _ in range(web_vitals.MIN_SAMPLES):
        sent = client.post("/api/v1/telemetry/vitals",
                           json={"path": "/chat/goal/4127", "device": "phone", "lcp": 1800, "inp": 90, "cls": 0.01})
        assert sent.status_code == 204
    stored = web_vitals.store_path().read_text()
    assert "4127" not in stored and "user:kim" not in stored
    (row,) = web_vitals.report()["rows"]
    assert row["route"] == "/chat/goal/{goal_id}" and row["device"] == "phone" and row["passes"] is True


@pytest.mark.parametrize("body", [
    {"path": "/api/v1/goals", "device": "desktop", "lcp": 1},       # not a page
    {"path": "/static/lightwork.css", "device": "desktop", "lcp": 1},
    {"path": "/no-such-page", "device": "desktop", "lcp": 1},       # no route
    {"path": "/goals", "device": "watch", "lcp": 1},
    {"path": "/goals", "device": "desktop", "lcp": -5},
    {"path": "/goals", "device": "desktop"},
    {"path": "/goals", "device": "desktop", "lcp": 1, "who": "user:kim"},  # extra fields refused
])
def test_refuses_what_it_will_not_keep(isolated, monkeypatch, body):
    _as(monkeypatch, "user:kim")
    assert _client().post("/api/v1/telemetry/vitals", json=body).status_code in (404, 422)


def test_needs_a_signed_in_same_origin_visitor(isolated, monkeypatch):
    from maverick_dashboard.app import app

    _as(monkeypatch, "user:kim")
    cross = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "https://elsewhere.example"})
    assert cross.post("/api/v1/telemetry/vitals", json={"path": "/goals", "device": "desktop", "lcp": 1}).status_code == 403
    _as(monkeypatch, "")
    assert _client().post("/api/v1/telemetry/vitals",
                          json={"path": "/goals", "device": "desktop", "lcp": 1}).status_code in (401, 403)


def test_the_page_speed_view_is_for_administrators(isolated, monkeypatch):
    from maverick import web_vitals

    for _ in range(web_vitals.MIN_SAMPLES):
        web_vitals.record("/goals", "phone", {"lcp": 3100, "inp": 120, "cls": 0.02})
    _as(monkeypatch, "user:kim", role="operator")
    assert _client().get("/settings/page-speed").status_code == 403
    _as(monkeypatch, "user:ada", role="admin")
    page = _client().get("/settings/page-speed")
    assert page.status_code == 200
    assert "/goals" in page.text and "Phone" in page.text and "Needs work" in page.text
    assert "28 days" in page.text


def test_the_view_says_when_measurement_is_off(isolated, monkeypatch):
    _off(isolated)
    _as(monkeypatch, "user:ada", role="admin")
    page = _client().get("/settings/page-speed")
    assert page.status_code == 200
    assert "turned off" in page.text
    assert 'href="/settings/all?id=analytics.web_vitals"' in page.text


def test_settings_catalog_row_is_the_dashboard_control():
    from maverick_dashboard import settings_catalog

    rows = [row for row in settings_catalog.SETTINGS if (row.section, row.key) == ("analytics", "web_vitals")]
    assert len(rows) == 1 and rows[0].control == "toggle" and rows[0].default is False
    assert rows[0].reader == "maverick.web_vitals"
    assert json.dumps(rows[0].help).count("Nothing is sent anywhere") == 1


def test_settings_links_to_the_page_speed_view_for_administrators(isolated, monkeypatch):
    _as(monkeypatch, "user:ada", role="admin")
    assert 'href="/settings/page-speed"' in _client().get("/settings").text


def test_the_sample_rate_setting_reaches_the_page_and_has_its_control(isolated, monkeypatch):
    from maverick import config
    from maverick_dashboard import settings_catalog

    (isolated / "config.toml").write_text("[analytics]\nweb_vitals = true\nweb_vitals_sample_rate = 0.2\n")
    config.reset_config_cache()
    _as(monkeypatch, "user:kim")
    assert 'data-sample-rate="0.2"' in _client().get("/goals").text
    rows = [row for row in settings_catalog.SETTINGS if (row.section, row.key) == ("analytics", "web_vitals_sample_rate")]
    assert len(rows) == 1
    row = rows[0]
    assert row.control == "number" and row.default == 0.5 and row.minimum == 0 and row.maximum == 1
    assert row.reader == "maverick.web_vitals"
