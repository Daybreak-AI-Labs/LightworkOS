"""Contract tests for semantic, retry-safe outbound GRC synchronization."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest
from maverick import grc_outbound_sync as gos
from maverick.governed_records import GovernedRecordStore
from maverick.paths import tenant_scope


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class Clock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.value = start

    def __call__(self) -> float:
        self.value += 1.0
        return self.value


class FakeTransport:
    """A typed transport that can fail deterministically before acknowledging."""

    def __init__(
        self,
        *,
        failures: list[Exception] | None = None,
        responder: Callable[[gos.OutboundRequest], gos.OutboundResponse] | None = None,
    ) -> None:
        self.failures = list(failures or [])
        self.requests: list[gos.OutboundRequest] = []
        self._responder = responder

    def send(self, request: gos.OutboundRequest) -> gos.OutboundResponse:
        self.requests.append(request)
        if self.failures:
            raise self.failures.pop(0)
        if self._responder is not None:
            return self._responder(request)
        external_id = (
            request.external_reference.external_id
            if request.external_reference is not None
            else f"EXT-{hashlib.sha256(request.source_id.encode()).hexdigest()[:24]}"
        )
        return gos.OutboundResponse(
            idempotency_key=request.idempotency_key,
            source_revision=request.source_revision,
            source_digest=request.source_digest,
            external_id=external_id,
            external_url=f"https://grc.example.test/records/{external_id}",
            external_revision=f"revision-{request.source_revision}",
        )


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "local")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick import audit, config

    monkeypatch.setattr(audit, "record", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(audit, "record_global", lambda *_args, **_kwargs: True)
    config.reset_config_cache()
    yield
    config.reset_config_cache()


def _sync(*, max_attempts: int = 8) -> gos.GRCOutboundSync:
    return gos.GRCOutboundSync(
        policy=gos.GRCOutboundPolicy(
            enabled=True,
            allowed_targets=frozenset({
                gos.GRCSystem.SERVICENOW_IRM,
                gos.GRCSystem.ARCHER,
            }),
            max_attempts_per_revision=max_attempts,
        ),
        state_store=GovernedRecordStore(
            "test_grc_outbound_states", "GOS", "test_grc_outbound_state"
        ),
        event_store=GovernedRecordStore(
            "test_grc_outbound_events", "GOE", "test_grc_outbound_event"
        ),
        clock=Clock(),
    )


def test_configured_policy_is_explicit_and_target_allowlisted(monkeypatch):
    from maverick import config

    monkeypatch.setattr(config, "config_source_errors", list)
    monkeypatch.setattr(config, "load_config", dict)
    assert gos.enabled() is False
    monkeypatch.setattr(
        config,
        "load_config",
        lambda: {
            "grc_outbound_sync": {
                "enable": True,
                "targets": ["servicenow_irm"],
                "max_attempts_per_revision": 4,
            }
        },
    )

    policy = gos.policy_from_config()

    assert policy.enabled is True
    assert policy.allowed_targets == frozenset({gos.GRCSystem.SERVICENOW_IRM})
    assert policy.max_attempts_per_revision == 4
    with pytest.raises(gos.GRCOutboundConfigError, match="not admitted"):
        policy.require(gos.GRCSystem.ARCHER)


def _finding(
    *,
    revision: int = 1,
    digest: str | None = None,
    summary: str = "Evaluation evidence is stale.",
) -> gos.FindingSource:
    return gos.FindingSource(
        finding_id="MRF-0123456789abcdef01234567",
        asset_id="MAA-0123456789abcdef0123456789abcdef",
        finding_type="evaluation_evidence_missing",
        severity="high",
        summary=summary,
        source_revision=revision,
        source_digest=digest or _hex(f"finding-{revision}"),
    )


def _acceptance(*, revision: int = 1) -> gos.RiskAcceptanceSource:
    return gos.RiskAcceptanceSource(
        acceptance_id="MRX-0123456789abcdef0123456789abcdef",
        finding_id="MRF-0123456789abcdef01234567",
        asset_id="MAA-0123456789abcdef0123456789abcdef",
        severity="high",
        rationale="The owner accepted the bounded residual risk.",
        reviewer="risk-owner@example.test",
        decided_at=1_800_000_000.0,
        expires_at=1_802_592_000.0,
        status="accepted",
        source_revision=revision,
        source_digest=_hex(f"acceptance-{revision}"),
    )


def _incident(*, revision: int = 1) -> gos.AIIncidentSource:
    return gos.AIIncidentSource(
        incident_id="MRI-0123456789abcdef0123456789abcdef",
        asset_id="MAA-0123456789abcdef0123456789abcdef",
        incident_source_id="drift-monitor-2026-08-28",
        severity="critical",
        summary="The production model crossed its approved drift threshold.",
        status="contained",
        occurred_at=1_800_000_010.0,
        resolution="Traffic is pinned to the last approved artifact.",
        source_revision=revision,
        source_digest=_hex(f"incident-{revision}"),
    )


@pytest.mark.parametrize(
    ("target", "source", "operation", "semantic_field"),
    [
        (
            gos.GRCSystem.SERVICENOW_IRM,
            _finding(),
            "servicenow_irm.upsert_issue",
            "finding_type",
        ),
        (
            gos.GRCSystem.SERVICENOW_IRM,
            _acceptance(),
            "servicenow_irm.upsert_risk_response",
            "response_type",
        ),
        (
            gos.GRCSystem.SERVICENOW_IRM,
            _incident(),
            "servicenow_irm.upsert_risk_event",
            "incident_source_id",
        ),
        (
            gos.GRCSystem.ARCHER,
            _finding(),
            "archer.upsert_finding",
            "finding_type",
        ),
        (
            gos.GRCSystem.ARCHER,
            _acceptance(),
            "archer.upsert_risk_acceptance",
            "response_strategy",
        ),
        (
            gos.GRCSystem.ARCHER,
            _incident(),
            "archer.upsert_ai_incident",
            "source_event_id",
        ),
    ],
)
def test_fixed_semantic_adapter_contracts_have_no_caller_path(
    target: gos.GRCSystem,
    source: gos.GRCSource,
    operation: str,
    semantic_field: str,
):
    bridge = _sync()
    transport = FakeTransport()
    with tenant_scope(tenant="acme"):
        preview = bridge.preview(source, target=target)
        state = bridge.sync(
            source,
            target=target,
            transport=transport,
            actor="grc-sync-worker",
        )

    assert preview["schema"] == gos.OUTBOUND_REQUEST_SCHEMA
    assert preview["operation"] == operation
    assert semantic_field in preview["payload"]
    assert preview["external_reference"] is None
    assert "path" not in preview
    assert "endpoint" not in preview
    assert "url" not in preview
    assert transport.requests[0].operation == operation
    assert not hasattr(transport.requests[0], "path")
    assert state["status"] == "delivered"
    assert state["receipt"]["schema"] == gos.OUTBOUND_RECEIPT_SCHEMA
    assert state["receipt"]["source_revision"] == source.source_revision
    assert state["receipt"]["source_digest"] == source.source_digest
    assert state["receipt"]["external_url"].startswith("https://grc.example.test/")


def test_retry_reuses_exact_idempotency_and_payload_then_stops_after_receipt():
    secret = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz"
    bridge = _sync()
    transport = FakeTransport(failures=[RuntimeError(f"provider rejected {secret}")])
    source = _finding()

    with tenant_scope(tenant="acme"):
        with pytest.raises(gos.GRCOutboundDeliveryError) as captured:
            bridge.sync(
                source,
                target=gos.GRCSystem.SERVICENOW_IRM,
                transport=transport,
                actor="grc-sync-worker",
            )
        failed = bridge.get_state(
            target=gos.GRCSystem.SERVICENOW_IRM,
            source_kind=gos.SourceKind.FINDING,
            source_id=source.source_id,
        )
        events = bridge.list_events()
        delivered = bridge.sync(
            source,
            target=gos.GRCSystem.SERVICENOW_IRM,
            transport=transport,
            actor="grc-sync-worker",
        )
        cached = bridge.sync(
            source,
            target=gos.GRCSystem.SERVICENOW_IRM,
            transport=transport,
            actor="grc-sync-worker",
        )

    assert failed["status"] == "failed"
    assert failed["attempts"] == 1
    assert failed["failure"]["error_type"] == "RuntimeError"
    assert failed["failure"]["retryable"] is True
    assert len(events) == 1 and events[0]["event_kind"] == "failure"
    assert len(transport.requests) == 2
    assert transport.requests[0].idempotency_key == transport.requests[1].idempotency_key
    assert transport.requests[0].payload_sha256 == transport.requests[1].payload_sha256
    assert delivered["status"] == "delivered"
    assert delivered["attempts"] == 2
    assert cached == delivered
    serialized = json.dumps({
        "error": str(captured.value),
        "failed": failed,
        "events": events,
        "delivered": delivered,
    })
    assert secret not in serialized
    assert "abcdefghijklmnopqrstuvwxyz" not in serialized


def test_new_revision_round_trips_external_identity_and_archives_receipt():
    bridge = _sync()
    transport = FakeTransport()
    first = _finding(revision=1)
    second = _finding(revision=2)

    with tenant_scope(tenant="acme"):
        state_one = bridge.sync(
            first,
            target=gos.GRCSystem.ARCHER,
            transport=transport,
            actor="grc-sync-worker",
        )
        state_two = bridge.sync(
            second,
            target=gos.GRCSystem.ARCHER,
            transport=transport,
            actor="grc-sync-worker",
        )

    assert len(transport.requests) == 2
    request_one, request_two = transport.requests
    assert request_one.idempotency_key != request_two.idempotency_key
    assert request_two.external_reference == gos.ExternalReference(
        external_id=state_one["receipt"]["external_id"],
        external_revision=state_one["receipt"]["external_revision"],
    )
    assert state_two["receipt"]["external_id"] == state_one["receipt"]["external_id"]
    assert state_two["receipt"]["external_revision"] == "revision-2"
    assert len(state_two["history"]) == 1
    prior = state_two["history"][0]
    assert prior["status"] == "delivered"
    assert prior["source"]["revision"] == 1
    assert prior["receipt"]["receipt_id"] == state_one["receipt"]["receipt_id"]


def test_same_revision_with_another_digest_is_a_governed_conflict():
    bridge = _sync()
    transport = FakeTransport()
    original = _finding()
    conflicting = _finding(digest=_hex("conflicting-content"))

    with tenant_scope(tenant="acme"):
        bridge.sync(
            original,
            target=gos.GRCSystem.SERVICENOW_IRM,
            transport=transport,
            actor="grc-sync-worker",
        )
        with pytest.raises(gos.GRCOutboundConflict, match="another digest"):
            bridge.sync(
                conflicting,
                target=gos.GRCSystem.SERVICENOW_IRM,
                transport=transport,
                actor="grc-sync-worker",
            )
        events = bridge.list_events()
        state = bridge.get_state(
            target=gos.GRCSystem.SERVICENOW_IRM,
            source_kind=gos.SourceKind.FINDING,
            source_id=original.source_id,
        )

    assert len(transport.requests) == 1
    assert state["status"] == "delivered"
    assert state["source"]["digest"] == original.source_digest
    assert len(events) == 1
    assert events[0]["event_kind"] == "conflict"
    assert events[0]["reason"] == "source_revision_digest_mismatch"
    assert events[0]["details"]["stored_digest"] == original.source_digest
    assert events[0]["details"]["incoming_digest"] == conflicting.source_digest


def test_transport_echo_and_external_identity_conflicts_fail_closed():
    def wrong_binding(request: gos.OutboundRequest) -> gos.OutboundResponse:
        return gos.OutboundResponse(
            idempotency_key=request.idempotency_key,
            source_revision=request.source_revision,
            source_digest=_hex("wrong-source"),
            external_id="EXT-wrong",
            external_url="https://grc.example.test/records/EXT-wrong",
            external_revision="revision-wrong",
        )

    bridge = _sync()
    transport = FakeTransport(responder=wrong_binding)
    source = _incident()
    with tenant_scope(tenant="acme"):
        with pytest.raises(gos.GRCOutboundConflict, match="receipt conflicts"):
            bridge.sync(
                source,
                target=gos.GRCSystem.ARCHER,
                transport=transport,
                actor="grc-sync-worker",
            )
        state = bridge.get_state(
            target=gos.GRCSystem.ARCHER,
            source_kind=gos.SourceKind.AI_INCIDENT,
            source_id=source.source_id,
        )
        events = bridge.list_events()
        with pytest.raises(gos.GRCOutboundConflict, match="operator resolution"):
            bridge.sync(
                source,
                target=gos.GRCSystem.ARCHER,
                transport=transport,
                actor="grc-sync-worker",
            )

    assert len(transport.requests) == 1
    assert state["status"] == "conflict"
    assert state["failure"]["retryable"] is False
    assert events[0]["reason"] == "response_binding_conflict"


def test_safe_projection_redacts_source_text_and_rejects_secret_actor_or_url():
    secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    bridge = _sync()
    source = _finding(summary=f"Evaluation failed; copied credential {secret}")
    transport = FakeTransport()
    with tenant_scope(tenant="acme"):
        state = bridge.sync(
            source,
            target=gos.GRCSystem.SERVICENOW_IRM,
            transport=transport,
            actor="grc-sync-worker",
        )
        with pytest.raises(ValueError, match="actor contains secret"):
            bridge.sync(
                _acceptance(),
                target=gos.GRCSystem.ARCHER,
                transport=transport,
                actor=f"worker {secret}",
            )

    serialized = json.dumps({
        "request": transport.requests[0].safe_projection(),
        "state": state,
    })
    assert secret not in serialized
    assert "[REDACTED:openai_api_key]" in serialized
    assert "authorization" not in {
        key.lower() for key in transport.requests[0].payload
    }
    with pytest.raises(ValueError, match="credential-free HTTPS"):
        gos.OutboundResponse(
            idempotency_key=transport.requests[0].idempotency_key,
            source_revision=source.source_revision,
            source_digest=source.source_digest,
            external_id="EXT-safe",
            external_url="https://alice:secret@grc.example.test/records/EXT-safe",
            external_revision="one",
        )


def test_state_and_idempotency_are_tenant_isolated():
    bridge = _sync()
    transport = FakeTransport()
    source = _finding()

    with tenant_scope(tenant="acme"):
        acme = bridge.sync(
            source,
            target=gos.GRCSystem.ARCHER,
            transport=transport,
            actor="grc-sync-worker",
        )
    with tenant_scope(tenant="globex"):
        assert bridge.get_state(
            target=gos.GRCSystem.ARCHER,
            source_kind=gos.SourceKind.FINDING,
            source_id=source.source_id,
        ) is None
        globex = bridge.sync(
            source,
            target=gos.GRCSystem.ARCHER,
            transport=transport,
            actor="grc-sync-worker",
        )
    with tenant_scope(tenant="acme"):
        recovered = bridge.get_state(
            target=gos.GRCSystem.ARCHER,
            source_kind=gos.SourceKind.FINDING,
            source_id=source.source_id,
        )

    assert acme["id"] != globex["id"]
    assert acme["tenant_sha256"] != globex["tenant_sha256"]
    assert acme["idempotency_key"] != globex["idempotency_key"]
    assert recovered["id"] == acme["id"]
    assert len(transport.requests) == 2


def test_core_is_default_off_requires_tenant_and_typed_targets():
    source = _finding()
    with tenant_scope(tenant="acme"):
        with pytest.raises(gos.GRCOutboundConfigError, match="disabled"):
            gos.GRCOutboundSync().sync(
                source,
                target=gos.GRCSystem.ARCHER,
                transport=FakeTransport(),
                actor="grc-sync-worker",
            )

    bridge = _sync()
    with pytest.raises(gos.GRCOutboundStateError, match="explicit tenant"):
        bridge.sync(
            source,
            target=gos.GRCSystem.ARCHER,
            transport=FakeTransport(),
            actor="grc-sync-worker",
        )
    with tenant_scope(tenant="acme"):
        with pytest.raises(TypeError, match="GRCSystem"):
            bridge.sync(
                source,
                target="archer",  # type: ignore[arg-type]
                transport=FakeTransport(),
                actor="grc-sync-worker",
            )


def test_retry_limit_preserves_failed_state_without_another_side_effect():
    bridge = _sync(max_attempts=1)
    transport = FakeTransport(failures=[TimeoutError("first call failed")])
    source = _acceptance()
    with tenant_scope(tenant="acme"):
        with pytest.raises(gos.GRCOutboundDeliveryError, match="retry-safe state"):
            bridge.sync(
                source,
                target=gos.GRCSystem.ARCHER,
                transport=transport,
                actor="grc-sync-worker",
            )
        with pytest.raises(gos.GRCOutboundDeliveryError, match="retry limit"):
            bridge.sync(
                source,
                target=gos.GRCSystem.ARCHER,
                transport=transport,
                actor="grc-sync-worker",
            )
        state = bridge.get_state(
            target=gos.GRCSystem.ARCHER,
            source_kind=gos.SourceKind.RISK_ACCEPTANCE,
            source_id=source.source_id,
        )

    assert len(transport.requests) == 1
    assert state["status"] == "failed"
    assert state["attempts"] == 1
