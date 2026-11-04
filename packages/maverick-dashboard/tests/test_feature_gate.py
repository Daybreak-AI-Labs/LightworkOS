"""A feature that is turned off is never reported as a missing permission.

The API marks the refusal with a stable reason (``X-Lightwork-Reason:
feature-off``), the feature and whether it can be turned on in the app; a
permission refusal carries none of that.
"""
from __future__ import annotations

from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient
from maverick_dashboard import feature_gate
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    from maverick import config, world_model

    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    for name in ("MAVERICK_DASHBOARD_TOKEN", "MAVERICK_DASHBOARD_REQUIRE_AUTH",
                 "MAVERICK_OIDC_ENABLED", "MAVERICK_PROXY_AUTH", "MAVERICK_ENTERPRISE"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "config.toml").write_text("[privacy_ops]\nenable = true\n", encoding="utf-8")
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _off(response, section, label, switch=True):
    assert response.status_code == 403
    assert response.headers[feature_gate.REASON_HEADER] == "feature-off"
    assert response.headers[feature_gate.FEATURE_HEADER] == section
    assert unquote(response.headers[feature_gate.LABEL_HEADER]) == label
    assert (response.headers.get(feature_gate.SWITCH_HEADER) == "module") is switch


def test_saving_a_rights_form_property_while_the_form_is_off_says_it_is_off():
    r = client.put("/api/v1/privacy/rights-form/properties/shop", json={
        "name": "Shop", "organisation": "Acme", "contact_email": "privacy@acme.example",
        "jurisdictions": ["eu_gdpr"], "request_types": ["access"]})
    _off(r, "privacy_automation.public_rights_form", "Rights request form")
    assert r.json()["detail"] == "Rights request form is turned off."


def test_the_breach_planner_says_it_is_off_and_can_be_turned_on():
    r = client.get("/api/v1/breach/regimes")
    _off(r, "breach_notification", "Breach deadline planner")
    assert "[breach_notification]" not in r.json()["detail"]


def test_an_older_gate_is_recognised_from_its_text():
    r = client.get("/api/v1/vendors/posture")
    _off(r, "vendor_management", "Vendor management")
    assert r.json() == {"detail": "the vendor register is disabled ([vendor_management] enable)"}


def test_a_permission_refusal_is_never_marked_as_turned_off(monkeypatch):
    from maverick_dashboard import auth, rbac

    monkeypatch.setenv("MAVERICK_DASHBOARD_ADMINS", "")
    rbac.set_role("user:v", "viewer")
    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:v")
    r = client.get("/api/v1/breach/regimes")
    assert r.status_code == 403
    assert feature_gate.REASON_HEADER not in r.headers


def test_a_browser_landing_on_a_turned_off_page_is_offered_turn_on(tmp_path):
    from maverick import config, privacy_ops

    request = privacy_ops.open_dsar("a@example.com", "access")
    (tmp_path / "config.toml").write_text("[privacy_ops]\nenable = false\n", encoding="utf-8")
    config.reset_config_cache()
    page = client.get(f"/privacy/dsar/{request['id']}", headers={"Accept": "text/html"})
    assert page.status_code == 403
    assert "The privacy register is turned off" in page.text
    assert "Permission required" not in page.text


@pytest.mark.parametrize("detail,section", [
    ("the data map is disabled ([data_map] enable)", "data_map"),
    ("governed_document_vault_disabled", "governed_document_vault"),
    ({"code": "connections_disabled", "message": "Connections are turned off."}, "connections"),
    ("privacy_ops is not enabled", "privacy_ops"),
    ("Promise reviews are off. An administrator can enable them in Settings.", None),
])
def test_refusal_text_that_says_off_is_classified(detail, section):
    headers = feature_gate.refusal_headers(detail)
    assert headers[feature_gate.REASON_HEADER] == "feature-off"
    assert headers.get(feature_gate.FEATURE_HEADER) == section


@pytest.mark.parametrize("detail", [
    "this page is not enabled for your role",
    "This learning feature is turned off or not allowed for you here.",
    "insufficient role for this action",
    "Your Viewer role from the default does not allow operate. Ask your administrator.",
    "Only the current task owner can change this work.",
    "",
    None,
])
def test_refusals_about_the_person_are_left_alone(detail):
    assert feature_gate.refusal_headers(detail) == {}
