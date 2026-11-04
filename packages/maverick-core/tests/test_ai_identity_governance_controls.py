"""Focused tests for identity federation, coupling, and governed writeback."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from dataclasses import replace

import pytest
from maverick.ai_identity_governance_controls import (
    CAPABILITY_MAPPING_SCHEMA,
    CHANGE_DELIVERY_ACK_SCHEMA,
    CONDITIONAL_ACCESS_SCHEMA,
    FEDERATION_OBSERVATION_SCHEMA,
    PURVIEW_ACK_SCHEMA,
    AgentPrincipalAuthority,
    AgentPrincipalFederationBinding,
    AgentPrincipalFederationObservation,
    CapabilityRule,
    ChangeDeliveryAck,
    ConditionalAccessDecisionEngine,
    ConditionalAccessObservation,
    ConditionalAccessObserver,
    EntraAgentPrincipalFederationAdapter,
    GovernedPurviewWritebackService,
    IdentityCapabilityMapper,
    IdentityGovernanceBindingError,
    IdentityGovernanceControlConfigError,
    IdentityGovernanceDeliveryError,
    IdentityGovernanceIdempotencyConflict,
    IdentityGovernanceStaleBinding,
    NormalizedIdentityChangeCoupler,
    OktaAgentPrincipalFederationAdapter,
    PurviewAssetBinding,
    PurviewWritebackAck,
)
from maverick.privacy_ops import RecordConflict


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha(value: object) -> str:
    material = value.encode() if isinstance(value, str) else _canonical(value)
    return hashlib.sha256(material).hexdigest()


def _pid(prefix: str, value: str) -> str:
    return f"{prefix}_{_sha(value)[:32]}"


TENANT = _sha("tenant-alpha")
OTHER_TENANT = _sha("tenant-beta")


class FakeCASStore:
    def __init__(self) -> None:
        self.records: dict[str, dict] = {}
        self.lock = threading.RLock()

    def authoritative_time(self) -> float:
        return 1_000.0

    def get(self, record_id: str):
        with self.lock:
            record = self.records.get(record_id)
            return copy.deepcopy(record) if record is not None else None

    def list(self, *, limit=None):
        with self.lock:
            rows = [copy.deepcopy(value) for _, value in sorted(self.records.items())]
            return rows if limit is None else rows[:limit]

    def create(self, record, *, action, actor, max_records=None):
        del action, actor, max_records
        with self.lock:
            if record["id"] in self.records:
                raise RecordConflict("duplicate")
            saved = copy.deepcopy(record)
            saved["revision"] = 1
            saved["created_at"] = 1_000.0
            saved["updated_at"] = 1_000.0
            self.records[saved["id"]] = saved
            return copy.deepcopy(saved)

    def update(
        self,
        record_id,
        mutate,
        *,
        expected_revision,
        action,
        actor,
    ):
        del action, actor
        with self.lock:
            current = self.records.get(record_id)
            if current is None:
                return None
            if current["revision"] != expected_revision:
                raise RecordConflict("stale")
            saved = copy.deepcopy(current)
            mutate(saved)
            saved["revision"] += 1
            saved["updated_at"] = 1_000.0
            self.records[record_id] = saved
            return copy.deepcopy(saved)


def _authority(
    tenant: str = TENANT,
    *,
    revision: int = 3,
    principal: str = "agent:governance-orchestrator@example.invalid",
) -> AgentPrincipalAuthority:
    return AgentPrincipalAuthority.from_principal(
        tenant_sha256=tenant,
        principal=principal,
        authority_binding_sha256=_sha(f"authority-binding:{tenant}:{revision}"),
        revision=revision,
    )


def _binding(
    authority: AgentPrincipalAuthority,
    *,
    provider: str = "entra",
) -> AgentPrincipalFederationBinding:
    return AgentPrincipalFederationBinding.bind(
        authority,
        provider=provider,
        provider_subject_id=_pid("sub", f"{provider}-service-principal"),
    )


def _observation(
    binding: AgentPrincipalFederationBinding,
    *,
    active: bool = True,
    permissions: tuple[str, ...] | None = None,
    observed_at: float = 1_000.0,
) -> AgentPrincipalFederationObservation:
    return AgentPrincipalFederationObservation(
        schema=FEDERATION_OBSERVATION_SCHEMA,
        tenant_sha256=binding.tenant_sha256,
        provider=binding.provider,
        principal_ref=binding.principal_ref,
        provider_subject_id=binding.provider_subject_id,
        binding_sha256=binding.binding_sha256,
        binding_revision=binding.authority_revision,
        active=active,
        permission_ids=permissions or (_pid("prm", "purview-governance"),),
        source_sha256=_sha("federation-source"),
        observed_at=observed_at,
    )


def _mapping(
    authority: AgentPrincipalAuthority,
    binding: AgentPrincipalFederationBinding,
    *,
    capabilities: tuple[str, ...] = (
        "agent.execute",
        "purview.classification.rollback",
        "purview.classification.write",
    ),
    observed_at: float = 1_000.0,
    now: float = 1_000.0,
):
    observation = _observation(binding, observed_at=observed_at)
    mapper = IdentityCapabilityMapper(
        (
            CapabilityRule(
                tenant_sha256=authority.tenant_sha256,
                provider=binding.provider,
                permission_id=observation.permission_ids[0],
                capabilities=capabilities,
                revision=7,
            ),
        ),
        revision=11,
        clock=lambda: now,
    )
    return mapper.map(
        authority,
        binding,
        observation,
        expected_binding_sha256=binding.binding_sha256,
        expected_authority_revision=authority.revision,
    )


class FederationTransport:
    def __init__(self, result) -> None:
        self.result = result
        self.requests = []

    def observe(self, request):
        self.requests.append(request)
        return self.result


@pytest.mark.parametrize(
    ("provider", "adapter_type"),
    (
        ("entra", EntraAgentPrincipalFederationAdapter),
        ("okta", OktaAgentPrincipalFederationAdapter),
    ),
)
def test_federation_adapters_use_only_exact_pseudonymous_bindings(
    provider,
    adapter_type,
) -> None:
    raw_principal = "agent:private-agent@example.invalid"
    authority = _authority(principal=raw_principal)
    binding = _binding(authority, provider=provider)
    transport = FederationTransport(_observation(binding))
    adapter = adapter_type(transport)

    result = adapter.observe(
        binding,
        expected_binding_sha256=binding.binding_sha256,
        expected_revision=authority.revision,
    )

    assert result.provider == provider
    assert transport.requests[0].principal_ref == authority.principal_ref
    assert raw_principal not in json.dumps(transport.requests[0].__dict__, sort_keys=True)
    assert raw_principal not in repr(authority)
    assert adapter.status()["provider_writes"] is False
    assert adapter.status()["live_acceptance_verified"] is False


def test_federation_adapter_rejects_cross_tenant_and_stale_results() -> None:
    authority = _authority()
    binding = _binding(authority)
    wrong_tenant = replace(_observation(binding), tenant_sha256=OTHER_TENANT)
    adapter = EntraAgentPrincipalFederationAdapter(FederationTransport(wrong_tenant))
    with pytest.raises(IdentityGovernanceBindingError, match="binding_mismatch"):
        adapter.observe(
            binding,
            expected_binding_sha256=binding.binding_sha256,
            expected_revision=authority.revision,
        )

    adapter = EntraAgentPrincipalFederationAdapter(FederationTransport(_observation(binding)))
    with pytest.raises(IdentityGovernanceStaleBinding, match="stale"):
        adapter.observe(
            binding,
            expected_binding_sha256=_sha("obsolete-binding"),
            expected_revision=authority.revision,
        )
    assert adapter._transport.requests == []

    class FailingTransport:
        def observe(self, _request):
            raise RuntimeError("Bearer federation-secret raw@example.invalid")

    with pytest.raises(
        IdentityGovernanceDeliveryError,
        match="federation_observation_unavailable",
    ) as failure:
        EntraAgentPrincipalFederationAdapter(FailingTransport()).observe(
            binding,
            expected_binding_sha256=binding.binding_sha256,
            expected_revision=authority.revision,
        )
    assert "federation-secret" not in str(failure.value)


class ConditionalAccessTransport:
    def __init__(self, result: ConditionalAccessObservation) -> None:
        self.result = result
        self.requests = []

    def observe(self, request):
        self.requests.append(request)
        return self.result


def _conditional_observation(
    binding: AgentPrincipalFederationBinding,
    outcome: str = "allow",
) -> ConditionalAccessObservation:
    return ConditionalAccessObservation(
        schema=CONDITIONAL_ACCESS_SCHEMA,
        tenant_sha256=binding.tenant_sha256,
        provider=binding.provider,
        principal_ref=binding.principal_ref,
        provider_subject_id=binding.provider_subject_id,
        binding_sha256=binding.binding_sha256,
        binding_revision=binding.authority_revision,
        outcome=outcome,
        policy_sha256=_sha("conditional-access-policy"),
        reason_codes=("policy.observed",),
        source_sha256=_sha("conditional-access-source"),
        observed_at=1_000.0,
    )


def test_capability_mapping_and_conditional_access_decision_fail_closed() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    transport = ConditionalAccessTransport(_conditional_observation(binding))
    observer = ConditionalAccessObserver("entra", transport)
    observation = observer.observe(
        binding,
        expected_binding_sha256=binding.binding_sha256,
        expected_revision=authority.revision,
    )
    engine = ConditionalAccessDecisionEngine(clock=lambda: 1_000.0)

    permit = engine.decide(
        authority,
        mapping,
        observation,
        required_capability="agent.execute",
        expected_binding_sha256=binding.binding_sha256,
        expected_revision=authority.revision,
        idempotency_key="conditional-decision-0001",
    )
    denied = engine.decide(
        authority,
        mapping,
        replace(observation, outcome="block"),
        required_capability="agent.execute",
        expected_binding_sha256=binding.binding_sha256,
        expected_revision=authority.revision,
        idempotency_key="conditional-decision-0002",
    )
    missing = engine.decide(
        authority,
        mapping,
        observation,
        required_capability="agent.admin",
        expected_binding_sha256=binding.binding_sha256,
        expected_revision=authority.revision,
        idempotency_key="conditional-decision-0003",
    )

    assert mapping.schema == CAPABILITY_MAPPING_SCHEMA
    assert permit.action == "permit"
    assert denied.action == "deny"
    assert denied.reason_code == "provider_policy_block"
    assert missing.action == "deny"
    assert missing.reason_code == "capability_not_mapped"
    assert permit.provider_policy_mutated is False
    assert permit.live_acceptance_verified is False

    foreign_rule_mapper = IdentityCapabilityMapper(
        (
            CapabilityRule(
                tenant_sha256=OTHER_TENANT,
                provider=binding.provider,
                permission_id=_observation(binding).permission_ids[0],
                capabilities=("agent.execute",),
                revision=1,
            ),
        ),
        revision=1,
        clock=lambda: 1_000.0,
    )
    foreign_mapping = foreign_rule_mapper.map(
        authority,
        binding,
        _observation(binding),
        expected_binding_sha256=binding.binding_sha256,
        expected_authority_revision=authority.revision,
    )
    assert foreign_mapping.capabilities == ()
    assert foreign_mapping.unmapped_permission_count == 1


def test_conditional_access_decision_rejects_stale_mapping_binding() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    observation = _conditional_observation(binding)
    with pytest.raises(IdentityGovernanceStaleBinding, match="stale"):
        ConditionalAccessDecisionEngine(clock=lambda: 1_000.0).decide(
            authority,
            mapping,
            observation,
            required_capability="agent.execute",
            expected_binding_sha256=_sha("new-federation-binding"),
            expected_revision=authority.revision,
            idempotency_key="conditional-decision-stale",
        )

    with pytest.raises(IdentityGovernanceStaleBinding, match="observation_stale"):
        ConditionalAccessDecisionEngine(clock=lambda: 2_000.0).decide(
            authority,
            mapping,
            observation,
            required_capability="agent.execute",
            expected_binding_sha256=binding.binding_sha256,
            expected_revision=authority.revision,
            idempotency_key="conditional-observation-expired",
        )


def _change_payload(tenant: str = TENANT) -> dict:
    categories = {
        "identities": {
            "added_count": 1,
            "removed_count": 0,
            "added_sha256": [_sha("identity-digest")],
            "removed_sha256": [],
            "digests_truncated": False,
        },
        "grants": {
            "added_count": 0,
            "removed_count": 0,
            "added_sha256": [],
            "removed_sha256": [],
            "digests_truncated": False,
        },
        "data_classifications": {
            "added_count": 0,
            "removed_count": 0,
            "added_sha256": [],
            "removed_sha256": [],
            "digests_truncated": False,
        },
    }
    delta = {
        "schema": "lightwork.identity_governance.snapshot-delta.v1",
        "change_kind": "baseline",
        "changed": True,
        "previous_snapshot_sha256": None,
        "current_snapshot_sha256": _sha("snapshot-current"),
        "configuration_changed": False,
        "provider_tenant_changed": False,
        "categories": categories,
        "risk_generated": False,
    }
    payload = {
        "schema": "lightwork.identity_governance.normalized-change.v1",
        "tenant_sha256": tenant,
        "provider": "entra",
        "slot": 16,
        "collected_at": 1_000.0,
        "source_state": "incomplete",
        "source_complete": False,
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
        "delta": delta,
        "risk_generated": False,
    }
    payload["change_sha256"] = _sha(payload)
    return payload


def _delivery_ack(event: dict, sink: str) -> ChangeDeliveryAck:
    return ChangeDeliveryAck(
        schema=CHANGE_DELIVERY_ACK_SCHEMA,
        sink=sink,
        event_id=event["event_id"],
        idempotency_sha256=_sha({"event_id": event["event_id"], "sink": sink}),
        receipt_sha256=_sha(f"{sink}-receipt"),
        accepted=True,
    )


def test_change_coupling_retries_only_failed_sink_and_replay_is_idempotent() -> None:
    store = FakeCASStore()
    alert_events: list[dict] = []
    risk_events: list[dict] = []

    def alert_sink(event):
        alert_events.append(event)
        return _delivery_ack(event, "alert")

    def risk_sink(event):
        risk_events.append(event)
        if len(risk_events) == 1:
            raise RuntimeError("Bearer raw-secret for person@example.invalid")
        return _delivery_ack(event, "dynamic_risk")

    coupler = NormalizedIdentityChangeCoupler(
        enable=True,
        tenant_sha256=TENANT,
        risk_sink=risk_sink,
        alert_sink=alert_sink,
        store=store,
    )
    payload = _change_payload()

    with pytest.raises(IdentityGovernanceDeliveryError, match="degraded"):
        coupler.handle(payload)
    degraded = next(iter(store.records.values()))
    assert degraded["status"] == "degraded"
    assert degraded["deliveries"]["alert"]["status"] == "delivered"
    assert degraded["deliveries"]["dynamic_risk"]["status"] == "failed"
    assert degraded["deliveries"]["dynamic_risk"]["last_error_type"] == "RuntimeError"
    assert "raw-secret" not in json.dumps(store.records, sort_keys=True)
    assert "person@example.invalid" not in json.dumps(store.records, sort_keys=True)

    delivered = coupler.handle(payload)
    replay = coupler.handle(payload)
    assert delivered["status"] == "delivered"
    assert replay["status"] == "delivered"
    assert len(alert_events) == 1
    assert len(risk_events) == 2
    assert alert_events[0]["risk_assessment_required"] is True
    assert alert_events[0]["live_acceptance_verified"] is False
    assert coupler.status()["risk_score_generated"] is False


def test_change_coupling_rejects_cross_tenant_and_tampered_claims_before_delivery() -> None:
    store = FakeCASStore()
    calls = []
    coupler = NormalizedIdentityChangeCoupler(
        enable=True,
        tenant_sha256=TENANT,
        alert_sink=lambda event: calls.append(event),
        store=store,
    )
    with pytest.raises(IdentityGovernanceBindingError, match="tenant_mismatch"):
        coupler.handle(_change_payload(OTHER_TENANT))

    tampered = _change_payload()
    tampered["live_acceptance_verified"] = True
    with pytest.raises(ValueError, match="unsupported claims"):
        coupler.handle(tampered)
    assert calls == []
    assert store.records == {}


def test_change_coupling_is_default_off_and_requires_a_sink() -> None:
    disabled = NormalizedIdentityChangeCoupler(
        tenant_sha256=TENANT,
        alert_sink=lambda _event: None,
    )
    with pytest.raises(IdentityGovernanceControlConfigError, match="disabled"):
        disabled.handle(_change_payload())
    unavailable = NormalizedIdentityChangeCoupler(enable=True, tenant_sha256=TENANT)
    with pytest.raises(IdentityGovernanceControlConfigError, match="unavailable"):
        unavailable.handle(_change_payload())
    assert disabled.status()["provider_writes"] is False
    assert disabled.status()["live_acceptance_verified"] is False


class PurviewTransport:
    def __init__(self, asset_box: dict[str, PurviewAssetBinding]) -> None:
        self.asset_box = asset_box
        self.apply_requests = []
        self.compensation_requests = []
        self.fail_apply = 0
        self.fail_compensation = 0
        self.crash_after_apply = 0

    def _ack(self, request, operation):
        result = PurviewAssetBinding(
            tenant_sha256=request.tenant_sha256,
            asset_id=request.asset_id,
            binding_sha256=_sha(f"{operation}:{request.request_sha256}:{request.source_revision}"),
            revision=request.source_revision + 1,
            classification_codes=request.classification_codes,
        )
        self.asset_box["current"] = result
        return PurviewWritebackAck(
            schema=PURVIEW_ACK_SCHEMA,
            operation=operation,
            tenant_sha256=request.tenant_sha256,
            intent_id=request.intent_id,
            request_sha256=request.request_sha256,
            idempotency_sha256=request.idempotency_sha256,
            result_binding_sha256=result.binding_sha256,
            result_revision=result.revision,
            receipt_sha256=_sha(f"{operation}-receipt:{request.request_sha256}"),
            accepted=True,
        )

    def apply(self, request):
        self.apply_requests.append(request)
        if self.fail_apply > 0:
            self.fail_apply -= 1
            raise RuntimeError("Bearer apply-secret for raw@example.invalid")
        acknowledgement = self._ack(request, "apply")
        if self.crash_after_apply > 0:
            self.crash_after_apply -= 1
            raise SystemExit("simulated process exit after provider acknowledgement")
        return acknowledgement

    def compensate(self, request):
        self.compensation_requests.append(request)
        if self.fail_compensation > 0:
            self.fail_compensation -= 1
            raise RuntimeError("Bearer compensation-secret")
        return self._ack(request, "compensate")


def _purview_service(
    *,
    enable: bool = True,
    authority: AgentPrincipalAuthority | None = None,
    asset: PurviewAssetBinding | None = None,
    clock=lambda: 1_000.0,
):
    authority = authority or _authority()
    asset = asset or PurviewAssetBinding(
        tenant_sha256=TENANT,
        asset_id=_pid("ast", "purview-asset"),
        binding_sha256=_sha("purview-source-binding"),
        revision=7,
        classification_codes=("confidential",),
    )
    authority_box = {"current": authority}
    asset_box = {"current": asset}
    store = FakeCASStore()
    transport = PurviewTransport(asset_box)
    service = GovernedPurviewWritebackService(
        enable=enable,
        tenant_sha256=TENANT,
        principal_resolver=lambda tenant, principal: (
            authority_box["current"]
            if (
                tenant == authority_box["current"].tenant_sha256
                and principal == authority_box["current"].principal_ref
            )
            else None
        ),
        asset_binding_resolver=lambda tenant, asset_id: (
            asset_box["current"]
            if tenant == TENANT and asset_id == asset_box["current"].asset_id
            else None
        ),
        transport=transport,
        store=store,
        clock=clock,
    )
    return service, store, transport, authority_box, asset_box


class Clock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_purview_prepared_changes_are_listed_for_this_tenant_only() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, _transport, _authority_box, asset_box = _purview_service(authority=authority)
    initial = asset_box["current"]
    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="listed-purview-change-0001",
    )
    foreign = copy.deepcopy(store.records[prepared["id"]])
    foreign["id"] = "IGPW-" + ("9" * 32)
    foreign["tenant_sha256"] = "9" * 64
    store.records[foreign["id"]] = foreign

    rows = service.list_intents(limit=10)

    assert [row["intent_id"] for row in rows] == [prepared["id"]]
    assert rows[0]["capability_mapping_sha256"] == mapping.mapping_sha256
    assert rows[0]["principal_ref"] == authority.principal_ref
    assert rows[0]["revision"] == prepared["revision"]
    assert rows[0]["classification_codes"] == ["regulated"]
    disabled, *_ = _purview_service(enable=False)
    with pytest.raises(IdentityGovernanceControlConfigError):
        disabled.list_intents()


def test_purview_writeback_apply_replay_and_compensation_are_revision_bound() -> None:
    raw_principal = "agent:private-purview-agent@example.invalid"
    authority = _authority(principal=raw_principal)
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, transport, _authority_box, asset_box = _purview_service(authority=authority)
    initial = asset_box["current"]
    raw_idempotency = "private-purview-idempotency-0001"

    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key=raw_idempotency,
    )
    applied = service.execute(
        prepared["id"],
        authority,
        mapping,
        expected_revision=prepared["revision"],
    )
    replay = service.execute(
        prepared["id"],
        authority,
        mapping,
        expected_revision=applied["revision"],
    )
    prepared_replay = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key=raw_idempotency,
    )
    compensated = service.compensate(
        prepared["id"],
        authority,
        mapping,
        expected_revision=applied["revision"],
    )
    compensation_replay = service.compensate(
        prepared["id"],
        authority,
        mapping,
        expected_revision=compensated["revision"],
    )

    assert applied["status"] == "applied"
    assert replay["status"] == "applied"
    assert prepared_replay["status"] == "applied"
    assert compensated["status"] == "compensated"
    assert compensation_replay["status"] == "compensated"
    assert compensated["compensation_authorization"]["mapping_sha256"] == mapping.mapping_sha256
    assert len(transport.apply_requests) == 1
    assert len(transport.compensation_requests) == 1
    assert asset_box["current"].classification_codes == ("confidential",)
    assert applied["live_acceptance_verified"] is False
    assert compensated["live_acceptance_verified"] is False
    serialized = json.dumps(store.records, sort_keys=True)
    assert raw_principal not in serialized
    assert raw_idempotency not in serialized
    assert "secret" not in serialized.lower()


def test_purview_writeback_failure_degrades_safely_then_retries_same_request() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, transport, _authority_box, asset_box = _purview_service(authority=authority)
    initial = asset_box["current"]
    transport.fail_apply = 1
    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="purview-retry-idempotency-0001",
    )

    with pytest.raises(IdentityGovernanceDeliveryError, match="degraded"):
        service.execute(
            prepared["id"],
            authority,
            mapping,
            expected_revision=prepared["revision"],
        )
    failed = store.get(prepared["id"])
    assert failed["status"] == "failed"
    assert failed["last_error_type"] == "RuntimeError"
    assert failed["provider_write_state"] == "unknown"
    assert "apply-secret" not in json.dumps(failed, sort_keys=True)
    applied = service.execute(
        prepared["id"],
        authority,
        mapping,
        expected_revision=failed["revision"],
    )
    assert applied["status"] == "applied"
    assert len(transport.apply_requests) == 2
    assert transport.apply_requests[0].request_sha256 == transport.apply_requests[1].request_sha256
    assert (
        transport.apply_requests[0].idempotency_sha256
        == transport.apply_requests[1].idempotency_sha256
    )


def test_purview_writeback_recovers_post_ack_process_exit_after_claim_expiry() -> None:
    clock = Clock()
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, transport, _authority_box, asset_box = _purview_service(
        authority=authority,
        clock=clock,
    )
    initial = asset_box["current"]
    transport.crash_after_apply = 1
    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="purview-crash-recovery-0001",
    )

    with pytest.raises(SystemExit, match="simulated process exit"):
        service.execute(
            prepared["id"],
            authority,
            mapping,
            expected_revision=prepared["revision"],
        )
    claimed = service.get_intent(prepared["id"], authority, mapping)
    assert claimed is not None
    assert claimed["status"] == "applying"
    with pytest.raises(IdentityGovernanceDeliveryError, match="in_progress"):
        service.execute(
            prepared["id"],
            authority,
            mapping,
            expected_revision=claimed["revision"],
        )

    clock.advance(61)
    recovered = service.execute(
        prepared["id"],
        authority,
        mapping,
        expected_revision=claimed["revision"],
    )
    assert recovered["status"] == "applied"
    assert len(transport.apply_requests) == 2
    assert transport.apply_requests[0].request_sha256 == transport.apply_requests[1].request_sha256
    assert (
        transport.apply_requests[0].idempotency_sha256
        == transport.apply_requests[1].idempotency_sha256
    )


def test_purview_compensation_failure_is_retryable_with_same_binding() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, transport, _authority_box, asset_box = _purview_service(authority=authority)
    initial = asset_box["current"]
    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="purview-compensation-retry-0001",
    )
    applied = service.execute(
        prepared["id"],
        authority,
        mapping,
        expected_revision=prepared["revision"],
    )
    transport.fail_compensation = 1
    with pytest.raises(IdentityGovernanceDeliveryError, match="degraded"):
        service.compensate(
            prepared["id"],
            authority,
            mapping,
            expected_revision=applied["revision"],
        )
    failed = store.get(prepared["id"])
    assert failed["status"] == "compensation_failed"
    assert failed["provider_write_state"] == "unknown"
    compensated = service.compensate(
        prepared["id"],
        authority,
        mapping,
        expected_revision=failed["revision"],
    )
    assert compensated["status"] == "compensated"
    assert len(transport.compensation_requests) == 2
    assert (
        transport.compensation_requests[0].request_sha256
        == transport.compensation_requests[1].request_sha256
    )
    assert (
        transport.compensation_requests[0].idempotency_sha256
        == transport.compensation_requests[1].idempotency_sha256
    )


def test_purview_compensation_accepts_fresh_map_on_same_federation_binding() -> None:
    clock = Clock()
    authority = _authority()
    binding = _binding(authority)
    prepared_mapping = _mapping(authority, binding)
    service, _store, transport, _authority_box, asset_box = _purview_service(
        authority=authority,
        clock=clock,
    )
    initial = asset_box["current"]
    prepared = service.prepare(
        authority,
        prepared_mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="purview-fresh-compensation-map-0001",
    )
    applied = service.execute(
        prepared["id"],
        authority,
        prepared_mapping,
        expected_revision=prepared["revision"],
    )
    clock.advance(400)
    fresh_mapping = _mapping(
        authority,
        binding,
        observed_at=clock(),
        now=clock(),
    )
    assert fresh_mapping.mapping_sha256 != prepared_mapping.mapping_sha256

    compensated = service.compensate(
        prepared["id"],
        authority,
        fresh_mapping,
        expected_revision=applied["revision"],
    )
    assert compensated["status"] == "compensated"
    assert (
        compensated["compensation_authorization"]["mapping_sha256"] == fresh_mapping.mapping_sha256
    )
    assert len(transport.compensation_requests) == 1


def test_purview_writeback_rejects_stale_asset_principal_and_record_revision() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, transport, authority_box, asset_box = _purview_service(authority=authority)
    initial = asset_box["current"]
    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="purview-stale-idempotency-0001",
    )
    asset_box["current"] = replace(
        initial,
        binding_sha256=_sha("concurrent-purview-update"),
        revision=initial.revision + 1,
    )
    with pytest.raises(IdentityGovernanceStaleBinding, match="asset_binding_stale"):
        service.execute(
            prepared["id"],
            authority,
            mapping,
            expected_revision=prepared["revision"],
        )
    assert transport.apply_requests == []
    stale = store.get(prepared["id"])
    assert stale["status"] == "stale_binding"

    authority_box["current"] = replace(
        authority,
        authority_binding_sha256=_sha("revoked-agent-binding"),
        revision=authority.revision + 1,
    )
    with pytest.raises(IdentityGovernanceStaleBinding, match="principal_binding_stale"):
        service.execute(
            prepared["id"],
            authority,
            mapping,
            expected_revision=stale["revision"],
        )

    expired_service, expired_store, expired_transport, *_ = _purview_service(
        authority=authority,
        clock=lambda: 1_301.0,
    )
    with pytest.raises(IdentityGovernanceStaleBinding, match="capability_mapping_expired"):
        expired_service.prepare(
            authority,
            mapping,
            asset_id=initial.asset_id,
            classification_codes=("regulated",),
            expected_binding_sha256=initial.binding_sha256,
            expected_source_revision=initial.revision,
            idempotency_key="purview-expired-capability-map-0001",
        )
    assert expired_store.records == {}
    assert expired_transport.apply_requests == []


def test_purview_writeback_cross_tenant_idempotency_and_default_off() -> None:
    authority = _authority()
    binding = _binding(authority)
    mapping = _mapping(authority, binding)
    service, store, transport, _authority_box, asset_box = _purview_service(authority=authority)
    initial = asset_box["current"]
    prepared = service.prepare(
        authority,
        mapping,
        asset_id=initial.asset_id,
        classification_codes=("regulated",),
        expected_binding_sha256=initial.binding_sha256,
        expected_source_revision=initial.revision,
        idempotency_key="purview-conflict-idempotency-0001",
    )
    assert (
        service.prepare(
            authority,
            mapping,
            asset_id=initial.asset_id,
            classification_codes=("regulated",),
            expected_binding_sha256=initial.binding_sha256,
            expected_source_revision=initial.revision,
            idempotency_key="purview-conflict-idempotency-0001",
        )["id"]
        == prepared["id"]
    )
    with pytest.raises(IdentityGovernanceIdempotencyConflict, match="conflict"):
        service.prepare(
            authority,
            mapping,
            asset_id=initial.asset_id,
            classification_codes=("restricted",),
            expected_binding_sha256=initial.binding_sha256,
            expected_source_revision=initial.revision,
            idempotency_key="purview-conflict-idempotency-0001",
        )

    other_authority = _authority(OTHER_TENANT)
    other_binding = _binding(other_authority)
    other_mapping = _mapping(other_authority, other_binding)
    with pytest.raises(IdentityGovernanceBindingError, match="tenant_mismatch"):
        service.prepare(
            other_authority,
            other_mapping,
            asset_id=initial.asset_id,
            classification_codes=("regulated",),
            expected_binding_sha256=initial.binding_sha256,
            expected_source_revision=initial.revision,
            idempotency_key="purview-other-tenant-0001",
        )
    assert transport.apply_requests == []
    assert len(store.records) == 1

    disabled, *_ = _purview_service(enable=False, authority=authority)
    assert disabled.status()["provider_writes_possible"] is False
    assert disabled.status()["live_acceptance_verified"] is False
    with pytest.raises(IdentityGovernanceControlConfigError, match="disabled"):
        disabled.prepare(
            authority,
            mapping,
            asset_id=initial.asset_id,
            classification_codes=("regulated",),
            expected_binding_sha256=initial.binding_sha256,
            expected_source_revision=initial.revision,
            idempotency_key="purview-disabled-idempotency-0001",
        )
