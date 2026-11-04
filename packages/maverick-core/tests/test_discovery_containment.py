"""Current reviewed discovery findings may control only an explicitly bound agent."""
from __future__ import annotations

import hashlib
import json

import pytest
from maverick import ai_discovery_sensors as discovery
from maverick import discovery_containment as containment
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope

_NOW = 1_800_000_000.0
_PREPARER = discovery.SensorActor("user:preparer")
_REVIEWER = discovery.SensorActor("user:reviewer")
_OPERATOR = discovery.SensorActor("user:operator")


class _Clock:
    def __init__(self, value: float = _NOW) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_CONTROL_PLANE", "1")
    monkeypatch.setenv("MAVERICK_EXTERNAL_AGENTS", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_HALT_FILE", str(tmp_path / "HALT"))
    (tmp_path / "config.toml").write_text(
        "[ai_discovery_sensors]\nenable = true\n", encoding="utf-8"
    )
    from maverick import audit, config, killswitch, revocation

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    revocation.reset_shared()
    yield
    try:
        killswitch.clear()
    except Exception:
        pass
    config.reset_config_cache()
    revocation.reset_shared()


def _bridge(label: str, *, ttl: int = 600):
    clock = _Clock()
    sensors = GovernedRecordStore(f"test_dc_sensor_{label}", "DSN", "test_dc_sensor")
    observations = GovernedRecordStore(
        f"test_dc_observation_{label}", "DSO", "test_dc_observation"
    )
    bindings = GovernedRecordStore(
        f"test_dc_binding_{label}", "DCB", "test_dc_binding"
    )
    actions = GovernedRecordStore(f"test_dc_action_{label}", "DCA", "test_dc_action")
    sensor_service = discovery.DiscoverySensorService(
        sensors=sensors,
        observations=observations,
        clock=clock,
        observation_ttl_seconds=ttl,
    )
    bridge = containment.DiscoveryContainmentService(
        sensor_service=sensor_service,
        bindings=bindings,
        actions=actions,
        clock=clock,
    )
    return bridge, sensor_service, bindings, actions, clock


def _finding(sensor_service: discovery.DiscoverySensorService) -> str:
    pending = sensor_service.register_sensor(
        sensor_name="identity-directory-east",
        sensor_type="identity_directory",
        config_sha256=_sha("sensor-config"),
        actor=_PREPARER,
    )
    sensor = sensor_service.approve_sensor(
        pending["sensor_id"], expected_revision=pending["revision"], actor=_REVIEWER
    )
    sensor_service.ingest_observation(
        sensor["sensor_id"],
        sensor_revision=sensor["sensor_revision"],
        config_sha256=sensor["config_sha256"],
        observation=discovery.NormalizedDiscoveryObservation(
            event_sha256=_sha("identity-audit-event"),
            observed_at=_NOW,
            ai_service_code="openai",
            ai_product_code="chatgpt",
            provider_code="openai",
            domain_category="identity_directory",
            deployment_type="saas",
            environment_code="production",
            context_codes=("managed_device", "user_consent"),
        ),
    )
    aggregate = sensor_service.aggregate_findings()
    assert aggregate["identifies_people"] is False
    return aggregate["findings"][0]["finding_sha256"]


def _enroll(agent_id: str = "shadow-bot") -> None:
    from maverick import external_agents

    external_agents.enroll(
        agent_id,
        "custom",
        max_risk="high",
        max_dollars=10.0,
        description="test governed agent",
    )


def _approved_binding(bridge, sensor_service, *, agent_id: str = "shadow-bot"):
    finding = _finding(sensor_service)
    _enroll(agent_id)
    staged = bridge.prepare_binding(
        finding, agent_principal=f"agent:{agent_id}", actor=_PREPARER
    )
    return bridge.approve_binding(
        staged["binding_id"], expected_revision=staged["revision"], actor=_REVIEWER
    )


def test_discovery_cannot_infer_an_identity_and_requires_four_eyes_before_control() -> None:
    bridge, sensor_service, _, _, _ = _bridge("four-eyes")
    with tenant_scope(tenant="acme"):
        finding = _finding(sensor_service)
        _enroll()
        from maverick.revocation import is_revoked

        assert not is_revoked("agent:shadow-bot")
        staged = bridge.prepare_binding(
            finding, agent_principal="agent:shadow-bot", actor=_PREPARER
        )
        assert staged["status"] == "pending_review" and staged["current"] is True
        with pytest.raises(containment.DiscoveryContainmentApprovalError, match="different human"):
            bridge.approve_binding(
                staged["binding_id"], expected_revision=staged["revision"], actor=_PREPARER
            )
        with pytest.raises(containment.DiscoveryContainmentApprovalError, match="not human reviewed"):
            bridge.execute(
                staged["binding_id"],
                action="contain",
                reason_code="unapproved_ai",
                operation_key="incident_001",
                actor=_OPERATOR,
            )
        assert not is_revoked("agent:shadow-bot")
        with pytest.raises(TypeError):
            bridge.prepare_binding(finding, actor=_PREPARER)  # type: ignore[call-arg]


def test_reviewed_current_binding_invokes_existing_acp_containment_and_emits_digest_only_receipt() -> None:
    bridge, sensor_service, bindings, actions, _ = _bridge("contain")
    with tenant_scope(tenant="acme"):
        approved = _approved_binding(bridge, sensor_service)
        outcome = bridge.execute(
            approved["binding_id"],
            action="contain",
            reason_code="unapproved_ai",
            operation_key="incident_002",
            actor=_OPERATOR,
        )
        from maverick import external_agents
        from maverick.revocation import is_revoked

        assert outcome["status"] == "committed"
        assert outcome["control"] == {"ok": True, "code": "ok"}
        assert is_revoked("agent:shadow-bot")
        assert external_agents.containment_state("shadow-bot") is True
        assert outcome["finding_sha256"] == approved["finding_sha256"]
        assert outcome["binding_sha256"] == approved["binding_sha256"]
        assert len(outcome["control_sha256"]) == 64

        encoded = json.dumps(
            {"binding": bindings.get(approved["binding_id"]), "action": actions.get(outcome["action_id"])},
            sort_keys=True,
        )
        for forbidden in (
            "private.person@example.test",
            "private-provider-payload",
            "access_token",
            "raw_url",
            "identity-audit-event",
            "unapproved_ai",
        ):
            assert forbidden not in encoded


def test_stale_or_cross_tenant_or_unenrolled_bindings_are_refused_before_acp() -> None:
    bridge, sensor_service, _, _, clock = _bridge("stale", ttl=600)
    with tenant_scope(tenant="acme"):
        finding = _finding(sensor_service)
        _enroll()
        staged = bridge.prepare_binding(
            finding, agent_principal="agent:shadow-bot", actor=_PREPARER
        )
        with pytest.raises(containment.DiscoveryContainmentBindingError, match="not enrolled"):
            bridge.prepare_binding(
                finding, agent_principal="agent:unknown-bot", actor=_PREPARER
            )
        clock.value = _NOW + 601
        with pytest.raises(containment.DiscoveryContainmentBindingError, match="not currently"):
            bridge.approve_binding(
                staged["binding_id"], expected_revision=staged["revision"], actor=_REVIEWER
            )
    with tenant_scope(tenant="other-tenant"):
        assert bridge.get_binding(staged["binding_id"]) is None


def test_suspend_attenuate_and_halt_route_through_acp_with_replay_safe_terminal_rows(monkeypatch) -> None:
    bridge, sensor_service, _, _, _ = _bridge("verbs")
    with tenant_scope(tenant="acme"):
        approved = _approved_binding(bridge, sensor_service)
        suspended = bridge.execute(
            approved["binding_id"],
            action="suspend",
            reason_code="policy_breach",
            operation_key="incident_003",
            actor=_OPERATOR,
        )
        from maverick.agent_trust import load_registry
        from maverick.revocation import is_revoked

        assert suspended["status"] == "committed"
        assert is_revoked("agent:shadow-bot") and load_registry()["shadow-bot"].revoked

        # A reviewed binding may request a narrower ceiling, never an inferred
        # response. Resume only so the following assertion observes attenuation.
        from maverick import agent_control_plane as acp

        assert acp.resume("agent:shadow-bot", actor="operator").ok
        attenuated = bridge.execute(
            approved["binding_id"],
            action="attenuate",
            reason_code="reduce_scope",
            operation_key="incident_004",
            actor=_OPERATOR,
            deny_tools=("write_external",),
            max_risk="medium",
        )
        assert attenuated["status"] == "committed"
        narrowed = load_registry()["shadow-bot"]
        assert narrowed.max_risk == "medium" and "write_external" in narrowed.deny_tools

        calls = []

        def unavailable_halt(reason, *, actor=""):
            calls.append((reason, actor))
            return acp.ControlResult("halt", "*", ok=False, code="dependency_unavailable")

        monkeypatch.setattr(acp, "halt_all", unavailable_halt)
        halted = bridge.execute(
            approved["binding_id"],
            action="halt",
            reason_code="containment_escalation",
            operation_key="incident_005",
            actor=_OPERATOR,
        )
        assert calls == [("discovery-containment_escalation", "user:operator")]
        assert halted["status"] == "failed"
        assert halted["control"] == {"ok": False, "code": "dependency_unavailable"}
        assert bridge.execute(
            approved["binding_id"],
            action="halt",
            reason_code="containment_escalation",
            operation_key="incident_005",
            actor=_OPERATOR,
        )["action_id"] == halted["action_id"]
        assert len(calls) == 1


def test_terminal_receipt_write_failure_is_indeterminate_and_never_replays_control(monkeypatch) -> None:
    bridge, sensor_service, _, actions, _ = _bridge("indeterminate")
    with tenant_scope(tenant="acme"):
        approved = _approved_binding(bridge, sensor_service)
        from maverick import agent_control_plane as acp

        calls = []
        original_suspend = acp.suspend

        def recorded_suspend(*args, **kwargs):
            calls.append((args, kwargs))
            return original_suspend(*args, **kwargs)

        monkeypatch.setattr(acp, "suspend", recorded_suspend)
        monkeypatch.setattr(actions, "update", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("private authority")))
        first = bridge.execute(
            approved["binding_id"],
            action="suspend",
            reason_code="investigate",
            operation_key="incident_006",
            actor=_OPERATOR,
        )
        assert first["status"] == "indeterminate"
        again = bridge.execute(
            approved["binding_id"],
            action="suspend",
            reason_code="investigate",
            operation_key="incident_006",
            actor=_OPERATOR,
        )
        assert again["status"] == "indeterminate"
        assert len(calls) == 1
