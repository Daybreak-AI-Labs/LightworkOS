from __future__ import annotations

import hashlib
import itertools
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from maverick.consent_delivery import ConsentDeliveryStore
from maverick.consent_preferences import (
    ConsentContext,
    ConsentPreferenceStore,
    PreferenceChoice,
)
from maverick_dashboard.app import app

from test_support.starlette_state import patch_state

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})
API = "/api/v1/consent/delivery"
NOW = 1_800_000_000.0
DIGEST = hashlib.sha256(b"authority").hexdigest()


@pytest.fixture()
def authorities(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from maverick import config, consent_delivery_runtime, world_model
    from maverick.audit import writer as audit_writer
    from maverick_dashboard import consent_delivery_api

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[consent_preferences]\n"
        "enable = true\n"
        "[consent_preferences.delivery]\n"
        "enable = true\n"
        "max_attempts = 6\n"
        "retry_base_seconds = 5\n"
        "retry_max_seconds = 3600\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(config_path))
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
    ids = itertools.count(1)
    preferences = ConsentPreferenceStore(
        tmp_path / "preferences.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
    )
    delivery = ConsentDeliveryStore(
        tmp_path / "delivery.sqlite3",
        clock=lambda: NOW,
        id_factory=lambda prefix: f"{prefix}-{next(ids)}",
        config_gate=lambda: True,
        origin_validator=lambda _origin: None,
    )
    monkeypatch.setattr(consent_delivery_api, "_preference_store", lambda _tenant: preferences)
    monkeypatch.setattr(
        consent_delivery_api,
        "_delivery_store",
        lambda _ops, _tenant: delivery,
    )
    dispatched = []

    def fake_runtime(tenant, destinations, **kwargs):
        dispatched.append((tenant, destinations, kwargs))
        return {
            "synchronized": {"changes_queued": 0, "complete": True},
            "dispatched": {"claimed": 0, "delivered": 0},
            "source_complete": True,
            "live_external_acceptance": False,
        }

    monkeypatch.setattr(consent_delivery_runtime, "run_delivery_once", fake_runtime)
    audit_writer._default = None
    audit_writer._defaults.clear()
    yield preferences, delivery, dispatched, config_path
    config.reset_config_cache()
    audit_writer._default = None
    audit_writer._defaults.clear()


def _ok(response, expected=200):
    assert response.status_code == expected, response.text
    return response.json()


def _enroll(destination="crm"):
    return _ok(
        client.post(
            f"{API}/destinations/{destination}",
            json={
                "origin": f"https://{destination}.example.com",
                "signing_key_id": f"{destination}-key-v1",
                "idempotency_key": f"enroll-{destination}",
                "max_attempts": 6,
                "base_backoff_seconds": 5.0,
                "max_backoff_seconds": 3600.0,
                "default_retention_seconds": 2592000,
            },
        ),
        201,
    )


def _seed_receipt(preferences: ConsentPreferenceStore):
    preferences.publish_policy(
        "tenant-a", "notice", 1, {"analytics": "consent"}, DIGEST, NOW - 1
    )
    preferences.create_profile("tenant-a", "profile-a", "anonymous", DIGEST, "profile")
    return preferences.record_preferences(
        "tenant-a",
        "profile-a",
        "notice",
        1,
        ConsentContext("global", "US", "", "web", asserted_source="edge"),
        [PreferenceChoice("analytics", "grant")],
        expected_revision=0,
        idempotency_key="receipt",
        actor_sha256=DIGEST,
    )


def test_delivery_admin_lifecycle_and_status(authorities) -> None:
    _preferences, _delivery, _dispatched, _config = authorities
    enrolled = _enroll()
    assert enrolled["revision"] == 1
    detail = _ok(client.get(f"{API}/destinations/crm"))
    assert detail["active_key_id"] == "crm-key-v1"

    rotated = _ok(
        client.post(
            f"{API}/destinations/crm/rotate-key",
            json={
                "new_key_id": "crm-key-v2",
                "expected_revision": 1,
                "idempotency_key": "rotate-crm",
            },
        )
    )
    assert rotated["revision"] == 2
    status = _ok(client.get(f"{API}/status"))
    assert status["counts"]["pending"] == 0
    assert status["privacy_posture"]["key_material_persisted"] is False
    assert status["audit_chain"]["valid"] is True
    assert status["external_acceptance"] is False
    assert _ok(client.get(f"{API}/audit"))["events"]


def test_sync_constructs_delivery_from_receipt_authority_only(authorities) -> None:
    preferences, delivery, _dispatched, _config = authorities
    receipt = _seed_receipt(preferences)
    _enroll()
    synced = _ok(
        client.post(
            f"{API}/sync",
            json={"destination_ids": ["crm"], "limit": 100},
        )
    )
    assert synced["changes_queued"] == 1
    assert synced["messages_queued"] == 1
    assert delivery.counts("tenant-a")["queued"] == 1
    dead = _ok(client.get(f"{API}/dead-letters"))
    assert dead == {"items": []}
    with __import__("sqlite3").connect(delivery.path) as connection:
        payload = connection.execute("SELECT payload_json FROM delivery_messages").fetchone()[0]
    assert receipt["receipt_sha256"] in payload


def test_dispatch_is_explicit_admin_operation_with_server_derived_worker(authorities) -> None:
    preferences, delivery, dispatched, _config = authorities
    result = _ok(
        client.post(
            f"{API}/dispatch",
            json={
                "destination_ids": ["crm"],
                "sync_limit": 100,
                "delivery_limit": 10,
                "lease_seconds": 60.0,
            },
        )
    )
    assert result["live_external_acceptance"] is False
    assert dispatched[0][0] == "tenant-a"
    assert dispatched[0][1] == ["crm"]
    assert dispatched[0][2]["worker_id"].startswith("delivery-api-")
    assert dispatched[0][2]["preference_store"] is preferences
    assert dispatched[0][2]["delivery_store"] is delivery
    assert dispatched[0][2]["transport"] is None


def _write_salesforce_destination_config(config_path: Path) -> None:
    config_path.write_text(
        "[consent_preferences]\n"
        "enable = true\n"
        "[consent_preferences.delivery]\n"
        "enable = true\n"
        "max_attempts = 6\n"
        "retry_base_seconds = 5\n"
        "retry_max_seconds = 3600\n"
        "[consent_preferences.delivery.destinations]\n"
        "enable = true\n"
        'enabled_providers = ["salesforce"]\n'
        "timeout_seconds = 10.0\n"
        "max_response_bytes = 65536\n"
        "[consent_preferences.delivery.destinations.salesforce]\n"
        'destination_id = "salesforce"\n'
        'origin = "https://tenant.my.salesforce.com"\n'
        'credential_secret_ref = "$SALESFORCE_CONSENT_TOKEN"\n'
        "credential_revision = 1\n"
        'api_version = "v65.0"\n'
        'object_api_name = "Lightwork_Consent_Event__c"\n'
        'external_id_field = "Lightwork_Message_Id__c"\n'
        'payload_digest_field = "Lightwork_Payload_SHA256__c"\n',
        encoding="utf-8",
    )


def test_named_destination_routes_and_lazy_composition_are_mounted(authorities) -> None:
    assert callable(app.state.consent_destination_runtime_factory)
    assert callable(app.state.consent_destination_readiness_probe)
    paths = set(app.openapi()["paths"])
    assert "/api/v1/consent/delivery/destination-adapters/status" in paths
    assert "/api/v1/consent/delivery/destination-adapters/{destination_id}/reconcile" in paths

    status = _ok(client.get(f"{API}/destination-adapters/status"))
    assert status["enabled"] is False
    assert status["ready"] is False
    assert status["credential_values_resolved"] is False
    assert status["provider_session_opened"] is False
    assert status["live_provider_acceptance_verified"] is False


def test_named_destination_dispatch_uses_stock_reconciliation_authority(
    authorities,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _preferences, _delivery, dispatched, config_path = authorities
    _write_salesforce_destination_config(config_path)
    monkeypatch.setenv("SALESFORCE_CONSENT_TOKEN", "placed-not-resolved")
    monkeypatch.delattr(
        app.state,
        "consent_destination_reconciliation_authority_factory",
        raising=False,
    )
    from maverick import config

    config.reset_config_cache()
    response = client.post(
        f"{API}/dispatch",
        json={
            "destination_ids": ["salesforce"],
            "sync_limit": 100,
            "delivery_limit": 10,
            "lease_seconds": 60.0,
        },
    )
    assert response.status_code == 200, response.text
    assert len(dispatched) == 1
    transport = dispatched[0][2]["transport"]
    assert transport.readiness()["reconciliation_supported"] == {
        "salesforce": True
    }


def test_named_destination_dispatch_passes_ready_transport_and_same_stores(
    authorities,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    preferences, delivery, dispatched, config_path = authorities
    _write_salesforce_destination_config(config_path)
    monkeypatch.setenv("SALESFORCE_CONSENT_TOKEN", "placed-not-resolved")

    class Reconciler:
        def inspect(self, _probe):
            raise AssertionError("dispatch construction must not reconcile")

    patch_state(
        monkeypatch,
        app.state,
        "consent_destination_reconciliation_authority_factory",
        lambda *, tenant_id: Reconciler(),
        raising=False,
    )
    from maverick import config

    config.reset_config_cache()
    result = _ok(
        client.post(
            f"{API}/dispatch",
            json={
                "destination_ids": ["salesforce"],
                "sync_limit": 100,
                "delivery_limit": 10,
                "lease_seconds": 60.0,
            },
        )
    )
    assert result["live_external_acceptance"] is False
    kwargs = dispatched[0][2]
    assert kwargs["preference_store"] is preferences
    assert kwargs["delivery_store"] is delivery
    assert kwargs["transport"].registry.binding("salesforce").tenant_id == "tenant-a"


def test_consent_delivery_page_exposes_named_adapter_workbench(authorities) -> None:
    response = client.get("/consent/delivery")
    assert response.status_code == 200
    source = response.text
    for provider in (
        "Salesforce",
        "Marketo",
        "Adobe Experience Platform",
        "Snowflake",
    ):
        assert provider in source
    assert "cd-adapter-status" in source
    assert "cd-ambiguous-table" in source
    assert "/reconcile" in source
    assert "/destination-adapters" in source


def test_delivery_api_is_tenant_scoped_strict_and_default_off(
    authorities, monkeypatch: pytest.MonkeyPatch
) -> None:
    _preferences, _delivery, _dispatched, config_path = authorities
    _enroll()
    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert client.get(f"{API}/destinations/crm").status_code == 404
    rejected = client.post(
        f"{API}/sync",
        json={"destination_ids": ["crm"], "limit": 100, "event": {}},
    )
    assert rejected.status_code == 422

    config_path.write_text(
        "[consent_preferences]\nenable = true\n"
        "[consent_preferences.delivery]\nenable = false\n",
        encoding="utf-8",
    )
    from maverick import config

    config.reset_config_cache()
    assert client.get(f"{API}/status").status_code == 403


def test_destination_list_is_read_only_tenant_scoped_and_needs_audit(
    authorities, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi import HTTPException
    from maverick_dashboard import consent_delivery_api

    _enroll("crm")
    _enroll("email")
    listed = _ok(client.get(f"{API}/destinations"))
    assert {item["destination_id"] for item in listed["items"]} == {"crm", "email"}
    assert listed["truncated"] is False
    crm = next(item for item in listed["items"] if item["destination_id"] == "crm")
    assert crm["revision"] == 1 and crm["active_key_id"] == "crm-key-v1"
    assert client.post(f"{API}/destinations", json={}).status_code == 405

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-b")
    assert _ok(client.get(f"{API}/destinations"))["items"] == []

    asked: list[str] = []

    def deny(_request, permission):
        asked.append(permission)
        raise HTTPException(status_code=403, detail="insufficient role for this action")

    monkeypatch.setattr(consent_delivery_api, "require_global_permission", deny)
    assert client.get(f"{API}/destinations").status_code == 403
    assert asked == ["audit"]
