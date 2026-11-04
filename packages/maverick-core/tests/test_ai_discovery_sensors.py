"""Focused privacy and authority contracts for AI discovery sensors."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import ai_discovery_sensors as discovery
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict

NOW = 1_800_000_000.0


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class ManualClock:
    def __init__(self, value: float = NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    (tmp_path / "config.toml").write_text(
        "[ai_discovery_sensors]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    yield tmp_path
    config.reset_config_cache()


def _store(label: str, kind: str) -> GovernedRecordStore:
    if kind == "sensor":
        return GovernedRecordStore(
            f"test_ai_discovery_sensors_{label}",
            "DSN",
            "test_ai_discovery_sensor_identity",
        )
    return GovernedRecordStore(
        f"test_ai_discovery_observations_{label}",
        "DSO",
        "test_ai_discovery_sensor_observation",
    )


def _service(label: str = "main", *, ttl: int = 600):
    sensors = _store(label, "sensor")
    observations = _store(label, "observation")
    clock = ManualClock()
    service = discovery.DiscoverySensorService(
        sensors=sensors,
        observations=observations,
        clock=clock,
        observation_ttl_seconds=ttl,
    )
    return service, sensors, observations, clock


PREPARER = discovery.SensorActor("user:preparer")
APPROVER = discovery.SensorActor("user:approver")
REVOKER = discovery.SensorActor("user:revoker")
REVOCATION_APPROVER = discovery.SensorActor("user:security")


def _approved(service: discovery.DiscoverySensorService, *, kind="network_egress"):
    pending = service.register_sensor(
        sensor_name="corp-egress-east",
        sensor_type=kind,
        config_sha256=_hex("config-v1"),
        actor=PREPARER,
    )
    return service.approve_sensor(
        pending["sensor_id"], expected_revision=pending["revision"], actor=APPROVER
    )


def _observation(
    *,
    event="event-1",
    observed_at=NOW,
    service_code="assistant-api",
    contexts=("employee-facing", "unapproved-use"),
):
    return discovery.NormalizedDiscoveryObservation(
        event_sha256=_hex(event),
        observed_at=observed_at,
        ai_service_code=service_code,
        ai_product_code="general-assistant",
        provider_code="example-provider",
        domain_category="generative-ai",
        deployment_type="hosted_api",
        environment_code="production",
        context_codes=contexts,
    )


def _ingest(service, sensor, observation=None):
    return service.ingest_observation(
        sensor["sensor_id"],
        sensor_revision=sensor["sensor_revision"],
        config_sha256=sensor["config_sha256"],
        observation=observation or _observation(),
    )


def test_feature_is_default_off_and_explicit_tenant_is_required(
    tmp_path, monkeypatch
):
    from maverick import config

    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    service, _, _, _ = _service("disabled")
    with tenant_scope(tenant="acme"):
        with pytest.raises(discovery.AIDiscoverySensorsConfigError):
            service.list_sensors()

    (tmp_path / "config.toml").write_text(
        "[ai_discovery_sensors]\nenable = true\n", encoding="utf-8"
    )
    config.reset_config_cache()
    with pytest.raises(discovery.AIDiscoverySensorsStateError, match="explicit tenant"):
        service.list_sensors()

    monkeypatch.setattr(config, "config_source_errors", lambda: ["unreadable"])
    assert discovery.enabled() is False


def test_registration_and_configuration_approval_are_human_four_eyes_and_cas():
    service, _, _, _ = _service("approval")
    with tenant_scope(tenant="acme"):
        pending = service.register_sensor(
            sensor_name="browser-controls",
            sensor_type="browser_extension",
            config_sha256=_hex("browser-v1"),
            actor=PREPARER,
        )
        assert pending["status"] == "pending_approval"
        with pytest.raises(discovery.AIDiscoverySensorsApprovalError, match="different"):
            service.approve_sensor(
                pending["sensor_id"],
                expected_revision=pending["revision"],
                actor=PREPARER,
            )
        active = service.approve_sensor(
            pending["sensor_id"],
            expected_revision=pending["revision"],
            actor=APPROVER,
        )
        assert active["status"] == "active"
        assert active["approved_by"] == APPROVER.principal

        with pytest.raises(RecordConflict):
            service.prepare_sensor_configuration(
                active["sensor_id"],
                config_sha256=_hex("browser-v2"),
                expected_revision=pending["revision"],
                actor=PREPARER,
            )
        update = service.prepare_sensor_configuration(
            active["sensor_id"],
            config_sha256=_hex("browser-v2"),
            expected_revision=active["revision"],
            actor=PREPARER,
        )
        assert update["status"] == "pending_approval"
        assert update["sensor_revision"] == 2
        active_v2 = service.approve_sensor(
            update["sensor_id"],
            expected_revision=update["revision"],
            actor=APPROVER,
        )
        assert active_v2["sensor_revision"] == 2


def test_all_supported_sensor_types_can_be_registered_but_are_not_live_adapters():
    service, _, _, _ = _service("types")
    with tenant_scope(tenant="acme"):
        for index, kind in enumerate(sorted(discovery.SENSOR_TYPES)):
            pending = service.register_sensor(
                sensor_name=f"sensor-{index}",
                sensor_type=kind,
                config_sha256=_hex(kind),
                actor=PREPARER,
            )
            assert pending["sensor_type"] == kind
            assert pending["status"] == "pending_approval"
        assert {row["sensor_type"] for row in service.list_sensors()} == set(
            discovery.SENSOR_TYPES
        )
        assert "does not establish complete" in discovery.DISCOVERY_LIMIT_NOTICE


def test_ingestion_requires_exact_current_approved_sensor_binding():
    service, _, _, _ = _service("binding")
    with tenant_scope(tenant="acme"):
        pending = service.register_sensor(
            sensor_name="oauth-monitor",
            sensor_type="oauth_grant",
            config_sha256=_hex("oauth-v1"),
            actor=PREPARER,
        )
        with pytest.raises(discovery.AIDiscoverySensorsBindingError, match="approved"):
            _ingest(service, pending)
        sensor = service.approve_sensor(
            pending["sensor_id"], expected_revision=pending["revision"], actor=APPROVER
        )
        with pytest.raises(discovery.AIDiscoverySensorsBindingError, match="exact"):
            service.ingest_observation(
                sensor["sensor_id"],
                sensor_revision=999,
                config_sha256=sensor["config_sha256"],
                observation=_observation(),
            )
        with pytest.raises(discovery.AIDiscoverySensorsBindingError, match="exact"):
            service.ingest_observation(
                sensor["sensor_id"],
                sensor_revision=sensor["sensor_revision"],
                config_sha256=_hex("wrong"),
                observation=_observation(),
            )
        admitted = _ingest(service, sensor)
        assert admitted["current"] is True
        assert admitted["sensor_binding"] == {
            "sensor_id": sensor["sensor_id"],
            "sensor_revision": 1,
            "config_sha256": _hex("oauth-v1"),
            "sensor_type": "oauth_grant",
        }


def test_closed_observation_has_no_raw_activity_or_identity_fields():
    service, _, observations, _ = _service("privacy")
    with tenant_scope(tenant="acme"):
        sensor = _approved(service)
        row = _ingest(service, sensor)
        persisted = observations.get(row["observation_id"])
        encoded = json.dumps(persisted, sort_keys=True)
        for prohibited in (
            "https://",
            "raw_url",
            "browsing_history",
            "prompt_text",
            "user_identity",
            "ip_address",
            "access_token",
            "secret_value",
            "provider_payload",
        ):
            assert prohibited not in encoded
        assert set(persisted["normalized"]) == {
            "ai_service_code",
            "ai_product_code",
            "provider_code",
            "domain_category",
            "deployment_type",
            "environment_code",
            "context_codes",
        }

        with pytest.raises(TypeError):
            discovery.NormalizedDiscoveryObservation(  # type: ignore[call-arg]
                **_observation().__dict__, raw_url="https://example.test/private"
            )
        with pytest.raises(ValueError, match="non-sensitive opaque"):
            _ingest(
                service,
                sensor,
                _observation(event="event-url", service_code="https://ai.example"),
            )
        with pytest.raises(ValueError, match="non-sensitive opaque"):
            _ingest(
                service,
                sensor,
                _observation(event="event-prompt", service_code="prompt"),
            )
        with pytest.raises(ValueError, match="non-sensitive opaque"):
            _ingest(
                service,
                sensor,
                _observation(event="event-hostname", service_code="private.example.com"),
            )


def test_event_digest_replay_is_idempotent_and_conflicting_reuse_fails_closed():
    service, _, _, _ = _service("replay")
    with tenant_scope(tenant="acme"):
        sensor = _approved(service)
        first = _ingest(service, sensor)
        duplicate = _ingest(service, sensor)
        assert duplicate["observation_id"] == first["observation_id"]
        assert duplicate["revision"] == first["revision"]

        conflict = _observation(event="event-1", service_code="other-service")
        with pytest.raises(discovery.AIDiscoverySensorsIdempotencyConflict):
            _ingest(service, sensor, conflict)


def test_sensor_registration_is_idempotent_but_configuration_conflict_is_rejected():
    service, _, _, _ = _service("registration-replay")
    with tenant_scope(tenant="acme"):
        first = service.register_sensor(
            sensor_name="catalog-west",
            sensor_type="data_catalog",
            config_sha256=_hex("catalog-v1"),
            actor=PREPARER,
        )
        duplicate = service.register_sensor(
            sensor_name="catalog-west",
            sensor_type="data_catalog",
            config_sha256=_hex("catalog-v1"),
            actor=PREPARER,
        )
        assert duplicate["sensor_id"] == first["sensor_id"]
        with pytest.raises(discovery.AIDiscoverySensorsIdempotencyConflict):
            service.register_sensor(
                sensor_name="catalog-west",
                sensor_type="data_catalog",
                config_sha256=_hex("catalog-v2"),
                actor=PREPARER,
            )


def test_ttl_configuration_change_and_revocation_make_projection_stale():
    service, _, _, clock = _service("stale", ttl=600)
    with tenant_scope(tenant="acme"):
        sensor = _approved(service)
        observation = _ingest(service, sensor)
        clock.value = NOW + 601
        expired = service.get_observation(observation["observation_id"])
        assert expired["current"] is False
        assert expired["stale_reasons"] == ["observation_expired"]

        clock.value = NOW + 100
        update = service.prepare_sensor_configuration(
            sensor["sensor_id"],
            config_sha256=_hex("config-v2"),
            expected_revision=sensor["revision"],
            actor=PREPARER,
        )
        pending = service.get_observation(observation["observation_id"])
        assert pending["current"] is False
        assert "sensor_not_active" in pending["stale_reasons"]
        assert "sensor_authority_changed" in pending["stale_reasons"]

        active_v2 = service.approve_sensor(
            update["sensor_id"], expected_revision=update["revision"], actor=APPROVER
        )
        requested = service.request_sensor_revocation(
            active_v2["sensor_id"],
            reason_code="retired",
            expected_revision=active_v2["revision"],
            actor=REVOKER,
        )
        with pytest.raises(discovery.AIDiscoverySensorsBindingError, match="approved"):
            _ingest(service, active_v2, _observation(event="after-stop"))
        with pytest.raises(discovery.AIDiscoverySensorsApprovalError, match="different"):
            service.approve_sensor_revocation(
                requested["sensor_id"],
                expected_revision=requested["revision"],
                actor=REVOKER,
            )
        revoked = service.approve_sensor_revocation(
            requested["sensor_id"],
            expected_revision=requested["revision"],
            actor=REVOCATION_APPROVER,
        )
        assert revoked["status"] == "revoked"


def test_safe_aggregate_counts_current_findings_without_completeness_or_people_claims():
    service, _, _, _ = _service("aggregate")
    with tenant_scope(tenant="acme"):
        sensor = _approved(service)
        _ingest(service, sensor, _observation(event="one"))
        _ingest(service, sensor, _observation(event="two"))
        aggregate = service.aggregate_findings()
        assert aggregate["schema"] == discovery.AGGREGATE_SCHEMA
        assert aggregate["current_observation_count"] == 2
        assert aggregate["complete_discovery_assessed"] is False
        assert aggregate["identifies_people"] is False
        assert aggregate["findings"][0]["current_observation_count"] == 2
        assert aggregate["findings"][0]["sensor_types"] == ["network_egress"]
        assert len(aggregate["findings"][0]["finding_sha256"]) == 64
        assert "does not establish complete" in aggregate["notice"]


def test_tenant_scoping_hides_sensor_and_observation_rows():
    service, _, _, _ = _service("tenant")
    with tenant_scope(tenant="acme"):
        sensor_acme = _approved(service)
        observation_acme = _ingest(service, sensor_acme)
    with tenant_scope(tenant="beta"):
        assert service.get_sensor(sensor_acme["sensor_id"]) is None
        assert service.get_observation(observation_acme["observation_id"]) is None
        sensor_beta = _approved(service)
        assert sensor_beta["sensor_id"] != sensor_acme["sensor_id"]
        assert len(service.list_sensors()) == 1
    with tenant_scope(tenant="acme"):
        assert service.get_sensor(sensor_acme["sensor_id"])["status"] == "active"
        assert len(service.list_observations()) == 1


def test_tampered_sensor_and_observation_state_fail_closed():
    service, sensors, observations, _ = _service("tamper")
    with tenant_scope(tenant="acme"):
        sensor = _approved(service)
        observation = _ingest(service, sensor)

        sensors.update(
            sensor["sensor_id"],
            lambda row: row["configuration"].update(
                {"config_sha256": _hex("tampered")}
            ),
            expected_revision=sensor["revision"],
            action="test_tamper",
            actor="user:test",
        )
        with pytest.raises(discovery.AIDiscoverySensorsStateError):
            service.get_sensor(sensor["sensor_id"])

        observations.update(
            observation["observation_id"],
            lambda row: row["normalized"].update(
                {"provider_code": "tampered-provider"}
            ),
            expected_revision=observation["revision"],
            action="test_tamper",
            actor="user:test",
        )
        with pytest.raises(discovery.AIDiscoverySensorsStateError):
            service.get_observation(observation["observation_id"])


def test_bounds_and_closed_taxonomies_fail_before_persistence():
    service, _, observations, clock = _service("bounds")
    with tenant_scope(tenant="acme"):
        sensor = _approved(service)
        with pytest.raises(ValueError, match="bounded list"):
            _ingest(
                service,
                sensor,
                _observation(event="contexts", contexts=tuple(f"ctx-{i}" for i in range(17))),
            )
        with pytest.raises(ValueError, match="opaque"):
            _ingest(
                service,
                sensor,
                _observation(event="long", service_code="x" * 65),
            )
        with pytest.raises(ValueError, match="future"):
            _ingest(
                service,
                sensor,
                _observation(event="future", observed_at=clock.value + 301),
            )
        assert observations.list(limit=10) == []
        with pytest.raises(ValueError, match="observation_ttl_seconds"):
            discovery.DiscoverySensorService(observation_ttl_seconds=299)
        with pytest.raises(ValueError, match="not supported"):
            service.register_sensor(
                sensor_name="fake",
                sensor_type="filesystem_spy",
                config_sha256=_hex("fake"),
                actor=PREPARER,
            )
