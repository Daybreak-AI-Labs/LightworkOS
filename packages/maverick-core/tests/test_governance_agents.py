from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace

import pytest
from maverick import config as maverick_config
from maverick import governance_agents as governance_agent_module
from maverick.budget import Budget
from maverick.governance_agents import (
    ACTION_CODES,
    AGENT_KINDS,
    CAPABILITY_REGISTRY,
    FINDING_CODES,
    GovernanceAgentAnalysis,
    GovernanceAgentConfigError,
    GovernanceAgentConflict,
    GovernanceAgentIntegrityError,
    GovernanceAgentLimits,
    GovernanceAgentPermissionDenied,
    GovernanceAgentQuotaExceeded,
    GovernanceAgentStore,
    GovernanceAgentTenantSnapshot,
    GovernanceAgentValidationError,
    GovernanceContextItem,
    build_adapter_authority,
    build_dispatcher_authority,
    build_execution_outcome,
    build_finding,
    execution_receipt_signing_payload,
    load_governance_agent_tenant_snapshot,
)


class MutablePrincipal:
    def __init__(self, value: str = "publisher") -> None:
        self.value = value

    def __call__(self) -> str:
        return self.value


class MutableClock:
    def __init__(self, value: float = 1_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def store_with_limits(
    tmp_path,
    *,
    limits: GovernanceAgentLimits,
    tenant_limits_resolver=None,
):
    principal = MutablePrincipal()
    clock = MutableClock()
    analysis_bindings = {}
    token_vault = {}

    def escrow(tenant_id, run_id, token, token_sha256):
        if digest(token.encode()) != token_sha256:
            return False
        token_vault[(tenant_id, run_id)] = token
        return True

    store = GovernanceAgentStore(
        tmp_path / "bounded-agents.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        policy_approver_resolver=lambda _tenant, _policy, _revision: (
            "reviewer-a",
            "reviewer-b",
        ),
        analysis_binding_resolver=lambda tenant, kind: analysis_bindings[(tenant, kind)],
        execution_token_escrow=escrow,
        execution_token_resolver=lambda tenant, run: token_vault[(tenant, run)],
        tenant_limits_resolver=tenant_limits_resolver,
        clock=clock,
        limits=limits,
        budget=Budget(max_tool_calls=100),
    )
    store._test_analysis_bindings = analysis_bindings
    return store, principal, clock


@pytest.fixture
def harness(tmp_path):
    principal = MutablePrincipal()
    clock = MutableClock()
    analysis_bindings = {}
    execution_bindings = {}
    token_vault = {}

    def escrow(tenant_id, run_id, token, token_sha256):
        if digest(token.encode()) != token_sha256:
            return False
        key = (tenant_id, run_id)
        prior = token_vault.get(key)
        if prior is not None and prior != token:
            return False
        token_vault[key] = token
        return True

    store = GovernanceAgentStore(
        tmp_path / "agents.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        policy_approver_resolver=lambda _tenant, _policy, _revision: (
            "reviewer-a",
            "reviewer-b",
        ),
        analysis_binding_resolver=lambda tenant, kind: analysis_bindings[(tenant, kind)],
        execution_binding_resolver=lambda tenant, kind: execution_bindings[(tenant, kind)],
        execution_token_escrow=escrow,
        execution_token_resolver=lambda tenant, run: token_vault[(tenant, run)],
        clock=clock,
        limits=GovernanceAgentLimits(retention_seconds=3_600),
        budget=Budget(max_tool_calls=100),
    )
    store._test_analysis_bindings = analysis_bindings
    store._test_execution_bindings = execution_bindings
    store._test_token_vault = token_vault
    return store, principal, clock


def authority(agent_kind: str, clock: MutableClock, *, valid_for: float = 600):
    return build_adapter_authority(
        adapter_id=f"adapter:{agent_kind}",
        revision=1,
        agent_kind=agent_kind,
        implementation_sha256=digest(f"impl:{agent_kind}".encode()),
        configuration_sha256=digest(f"config:{agent_kind}".encode()),
        deterministic=True,
        network_access=False,
        legal_conclusion_enabled=False,
        valid_until=clock.value + valid_for,
    )


def dispatcher_authority(agent_kind: str, clock: MutableClock, *, revision: int = 1):
    return build_dispatcher_authority(
        dispatcher_id=f"dispatcher:{agent_kind}",
        revision=revision,
        agent_kind=agent_kind,
        implementation_sha256=digest(f"dispatch-impl:{agent_kind}:{revision}".encode()),
        configuration_sha256=digest(f"dispatch-config:{agent_kind}:{revision}".encode()),
        execution_enabled=True,
        valid_until=clock.value + 600,
    )


def _proof(material: dict) -> str:
    encoded = json.dumps(
        material,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return digest(encoded)


def bound_outcome(
    run,
    enrolled_authority,
    *,
    outcome: str,
    provider_status_code: str,
    external_reference_sha256: str | None = None,
    retryable: bool = False,
):
    material = execution_receipt_signing_payload(
        run=run,
        dispatcher_authority=enrolled_authority,
        outcome=outcome,
        provider_status_code=provider_status_code,
        external_reference_sha256=external_reference_sha256,
        retryable=retryable,
    )
    return build_execution_outcome(
        run=run,
        dispatcher_authority=enrolled_authority,
        outcome=outcome,
        provider_status_code=provider_status_code,
        external_reference_sha256=external_reference_sha256,
        retryable=retryable,
        receipt_proof_sha256=_proof(material),
    )


def rehash_outcome(outcome, **changes):
    material = asdict(outcome)
    material.update(changes)
    material.pop("receipt_sha256")
    return replace(outcome, **changes, receipt_sha256=_proof(material))


def enroll_dispatcher(
    store: GovernanceAgentStore,
    clock: MutableClock,
    behavior,
    *,
    agent_kind: str = "breach_response",
    enrolled_authority=None,
):
    selected_authority = enrolled_authority or dispatcher_authority(agent_kind, clock)

    def dispatcher(*, run, idempotency_key):
        return behavior(run, idempotency_key, selected_authority)

    def verifier(authority_value, outcome):
        material = asdict(outcome)
        proof = material.pop("receipt_proof_sha256")
        material.pop("receipt_sha256")
        return authority_value == selected_authority and hmac.compare_digest(
            proof, _proof(material)
        )

    store._test_execution_bindings[("tenant-a", agent_kind)] = (
        selected_authority,
        dispatcher,
        verifier,
    )
    return dispatcher, selected_authority, verifier


def publish(
    store: GovernanceAgentStore,
    principal: MutablePrincipal,
    clock: MutableClock,
    *,
    agent_kind: str = "breach_response",
    execution_enabled: bool = True,
    policy_id: str = "policy:one",
    tenant_id: str = "tenant-a",
    valid_for: float = 600,
):
    principal.value = "publisher"
    capabilities = tuple(sorted(CAPABILITY_REGISTRY[agent_kind]))
    return store.publish_policy(
        tenant_id,
        policy_id=policy_id,
        revision=1,
        agent_kind=agent_kind,
        allowed_capabilities=capabilities,
        required_approvals=2 if execution_enabled else 1,
        execution_enabled=execution_enabled,
        approver_principals=("reviewer-a", "reviewer-b"),
        valid_until=clock.value + valid_for,
        idempotency_key=f"publish:{policy_id}",
    )


def context(raw: bytes = b"sensitive incident context"):
    return (
        GovernanceContextItem(
            item_id="evidence:1",
            source_kind="incident",
            source_ref="incident:123",
            source_revision=1,
            collected_at=999.0,
            content=raw,
        ),
    )


def adapter_for(agent_kind: str, *, complete: bool = True):
    finding_code = sorted(FINDING_CODES[agent_kind])[0]
    action_code = sorted(ACTION_CODES[agent_kind])[0]

    def adapter(**kwargs):
        assert kwargs["agent_kind"] == agent_kind
        assert kwargs["context"][0].content
        return GovernanceAgentAnalysis(
            findings=(
                build_finding(
                    agent_kind=agent_kind,
                    finding_id="finding:1",
                    finding_code=finding_code,
                    severity="high",
                    evidence_item_ids=("evidence:1",),
                    recommended_action_code=action_code,
                    rationale_code="evidence_sufficient",
                    confidence_bps=8_000,
                ),
            ),
            limitations=() if complete else ("human_context_required",),
            complete=complete,
        )

    return adapter


def submit(
    store: GovernanceAgentStore,
    principal: MutablePrincipal,
    clock: MutableClock,
    *,
    agent_kind: str = "breach_response",
    run_id: str = "run:one",
    raw: bytes = b"sensitive incident context",
    policy_id: str = "policy:one",
    tenant_id: str = "tenant-a",
):
    principal.value = "requester"
    selected_authority = authority(agent_kind, clock)
    selected_adapter = adapter_for(agent_kind)
    store._test_analysis_bindings[(tenant_id, agent_kind)] = (
        selected_authority,
        selected_adapter,
    )
    return store.submit_run(
        tenant_id,
        run_id=run_id,
        policy_id=policy_id,
        policy_revision=1,
        capability=sorted(CAPABILITY_REGISTRY[agent_kind])[0],
        context=context(raw),
        adapter_authority=selected_authority,
        adapter=selected_adapter,
        idempotency_key=f"submit:{run_id}",
    )


def approve_twice(
    store: GovernanceAgentStore,
    principal: MutablePrincipal,
    run,
):
    principal.value = "reviewer-a"
    run = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="approve",
        rationale_code="evidence_sufficient",
    )
    principal.value = "reviewer-b"
    return store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="approve",
        rationale_code="policy_threshold",
    )


def test_store_fails_closed_when_gate_is_disabled(tmp_path):
    def disabled():
        raise GovernanceAgentConfigError("disabled")

    with pytest.raises(GovernanceAgentConfigError, match="disabled"):
        GovernanceAgentStore(tmp_path / "disabled.sqlite3", config_gate=disabled)


def test_tenant_snapshot_canonicalizes_agents_and_only_narrows_defaults():
    snapshot = load_governance_agent_tenant_snapshot(
        "tenant-a",
        {
            "governance_agents": {
                "enable": True,
                "enabled_agents": ["program_copilot", "breach_response"],
                "max_context_items": 1,
                "max_context_bytes": 1_024,
                "max_output_bytes": 1_024,
                "retention_seconds": 3_600,
            }
        },
    )
    assert snapshot.enabled_agents == ("breach_response", "program_copilot")
    assert snapshot.limits.max_context_items == 1
    assert snapshot.limits.max_context_bytes == 1_024
    assert snapshot.limits.max_output_bytes == 1_024
    assert snapshot.limits.retention_seconds == 3_600

    expanded = load_governance_agent_tenant_snapshot(
        "tenant-a",
        {
            "governance_agents": {
                "enable": True,
                "max_context_items": 1_000,
                "max_context_bytes": 10_485_760,
                "max_output_bytes": 1_048_576,
                "retention_seconds": 315_360_000,
            }
        },
    )
    assert expanded.enabled_agents == tuple(sorted(AGENT_KINDS))
    assert expanded.limits == GovernanceAgentLimits()


def test_tenant_snapshot_rechecks_source_errors_after_config_load(monkeypatch):
    state = {"loaded": False}

    def load_config():
        state["loaded"] = True
        return {"governance_agents": {"enable": True}}

    def source_errors():
        return {"tenant-config.toml": "invalid"} if state["loaded"] else {}

    monkeypatch.setattr(maverick_config, "load_config", load_config)
    monkeypatch.setattr(maverick_config, "config_source_errors", source_errors)
    with pytest.raises(GovernanceAgentConfigError, match="unreadable"):
        load_governance_agent_tenant_snapshot("tenant-a")

    state["loaded"] = False
    assert governance_agent_module.enabled() is False


def test_tenant_snapshot_blocks_disabled_agent_before_approval_resolution(tmp_path):
    resolver_calls: list[tuple[str, str, int]] = []
    snapshot = GovernanceAgentTenantSnapshot(
        tenant_id="tenant-a",
        enabled_agents=("breach_response",),
        limits=GovernanceAgentLimits(retention_seconds=3_600),
    )

    def approvers(tenant_id: str, policy_id: str, revision: int):
        resolver_calls.append((tenant_id, policy_id, revision))
        return ("reviewer-a", "reviewer-b")

    store = GovernanceAgentStore(
        tmp_path / "agent-allowlist.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: "publisher",
        policy_approver_resolver=approvers,
        tenant_snapshot_resolver=lambda _tenant: snapshot,
    )
    with pytest.raises(GovernanceAgentConfigError, match="kind is disabled"):
        store.publish_policy(
            "tenant-a",
            policy_id="vendor",
            revision=1,
            agent_kind="third_party_risk",
            allowed_capabilities=tuple(sorted(CAPABILITY_REGISTRY["third_party_risk"])),
            required_approvals=1,
            execution_enabled=False,
            approver_principals=("reviewer-a", "reviewer-b"),
            valid_until=2_000.0,
            idempotency_key="publish:vendor",
        )
    assert resolver_calls == []


def test_tenant_snapshot_binding_compares_non_ascii_tenant_ids(tmp_path):
    # Tenant ids may be any Unicode text: a snapshot for another tenant is
    # misbound and a matching one proceeds, rather than either raising TypeError.
    snapshot = GovernanceAgentTenantSnapshot(
        tenant_id="tenant-é",
        enabled_agents=("breach_response",),
        limits=GovernanceAgentLimits(retention_seconds=3_600),
    )
    store = GovernanceAgentStore(
        tmp_path / "unicode-tenant.sqlite3",
        config_gate=lambda: None,
        principal_resolver=lambda: "publisher",
        policy_approver_resolver=lambda *_args: ("reviewer-a", "reviewer-b"),
        tenant_snapshot_resolver=lambda _tenant: snapshot,
    )
    policy = {
        "policy_id": "vendor",
        "revision": 1,
        "agent_kind": "third_party_risk",
        "allowed_capabilities": tuple(sorted(CAPABILITY_REGISTRY["third_party_risk"])),
        "required_approvals": 1,
        "execution_enabled": False,
        "approver_principals": ("reviewer-a", "reviewer-b"),
        "valid_until": 2_000.0,
        "idempotency_key": "publish:vendor",
    }
    with pytest.raises(GovernanceAgentConfigError, match="misbound"):
        store.publish_policy("tenant-a", **policy)
    with pytest.raises(GovernanceAgentConfigError, match="kind is disabled"):
        store.publish_policy("tenant-é", **policy)


def test_tenant_snapshot_lower_context_limit_prevents_adapter_execution(tmp_path):
    snapshot = load_governance_agent_tenant_snapshot(
        "tenant-a",
        {
            "governance_agents": {
                "enable": True,
                "enabled_agents": ["breach_response"],
                "max_context_items": 1,
                "max_context_bytes": 1_024,
                "retention_seconds": 3_600,
            }
        },
    )
    principal = MutablePrincipal()
    clock = MutableClock()
    adapter_calls: list[str] = []
    base_adapter = adapter_for("breach_response")

    def counting_adapter(**kwargs):
        adapter_calls.append("called")
        return base_adapter(**kwargs)

    selected_authority = authority("breach_response", clock)
    store = GovernanceAgentStore(
        tmp_path / "lower-context-limit.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        policy_approver_resolver=lambda _tenant, _policy, _revision: (
            "reviewer-a",
            "reviewer-b",
        ),
        analysis_binding_resolver=lambda _tenant, _kind: (
            selected_authority,
            counting_adapter,
        ),
        tenant_snapshot_resolver=lambda _tenant: snapshot,
        clock=clock,
    )
    publish(store, principal, clock, execution_enabled=False)
    principal.value = "requester"
    second = GovernanceContextItem(
        item_id="evidence:2",
        source_kind="incident",
        source_ref="incident:456",
        source_revision=1,
        collected_at=999.0,
        content=b"second item",
    )
    with pytest.raises(GovernanceAgentValidationError, match="item bound"):
        store.submit_run(
            "tenant-a",
            run_id="run:too-many-items",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=(*context(), second),
            adapter_authority=selected_authority,
            adapter=counting_adapter,
            idempotency_key="submit:too-many-items",
        )
    assert adapter_calls == []

    with pytest.raises(GovernanceAgentValidationError, match="byte bound"):
        store.submit_run(
            "tenant-a",
            run_id="run:too-many-bytes",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(b"x" * 1_025),
            adapter_authority=selected_authority,
            adapter=counting_adapter,
            idempotency_key="submit:too-many-bytes",
        )
    assert adapter_calls == []

    run = store.submit_run(
        "tenant-a",
        run_id="run:within-limits",
        policy_id="policy:one",
        policy_revision=1,
        capability="containment_plan",
        context=context(b"within limits"),
        adapter_authority=selected_authority,
        adapter=counting_adapter,
        idempotency_key="submit:within-limits",
    )
    assert adapter_calls == ["called"]
    assert run.retained_until == clock.value + 3_600


def test_tenant_snapshot_lower_output_limit_is_enforced(tmp_path):
    snapshot = load_governance_agent_tenant_snapshot(
        "tenant-a",
        {
            "governance_agents": {
                "enable": True,
                "enabled_agents": ["breach_response"],
                "max_output_bytes": 1_024,
                "retention_seconds": 3_600,
            }
        },
    )
    principal = MutablePrincipal()
    clock = MutableClock()
    selected_authority = authority("breach_response", clock)
    adapter_calls: list[str] = []

    def oversized_adapter(**_kwargs):
        adapter_calls.append("called")
        return GovernanceAgentAnalysis(
            findings=tuple(
                build_finding(
                    agent_kind="breach_response",
                    finding_id=f"finding:{index:02d}",
                    finding_code=sorted(FINDING_CODES["breach_response"])[0],
                    severity="high",
                    evidence_item_ids=("evidence:1",),
                    recommended_action_code=sorted(
                        ACTION_CODES["breach_response"]
                    )[0],
                    rationale_code="evidence_sufficient",
                    confidence_bps=8_000,
                )
                for index in range(10)
            ),
            limitations=(),
            complete=True,
        )

    store = GovernanceAgentStore(
        tmp_path / "lower-output-limit.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        policy_approver_resolver=lambda _tenant, _policy, _revision: (
            "reviewer-a",
            "reviewer-b",
        ),
        analysis_binding_resolver=lambda _tenant, _kind: (
            selected_authority,
            oversized_adapter,
        ),
        tenant_snapshot_resolver=lambda _tenant: snapshot,
        clock=clock,
    )
    publish(store, principal, clock, execution_enabled=False)
    principal.value = "requester"
    with pytest.raises(GovernanceAgentValidationError, match="canonical byte bound"):
        store.submit_run(
            "tenant-a",
            run_id="run:oversized-output",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=selected_authority,
            adapter=oversized_adapter,
            idempotency_key="submit:oversized-output",
        )
    assert adapter_calls == ["called"]


def test_policy_requires_independent_approvers(harness):
    store, principal, clock = harness
    with pytest.raises(GovernanceAgentPermissionDenied, match="two distinct"):
        store.publish_policy(
            "tenant-a",
            policy_id="unsafe",
            revision=1,
            agent_kind="breach_response",
            allowed_capabilities=("containment_plan",),
            required_approvals=2,
            execution_enabled=True,
            approver_principals=(principal.value, "other"),
            valid_until=clock.value + 10,
            idempotency_key="unsafe",
        )


def test_policy_idempotency_and_conflict(harness):
    store, principal, clock = harness
    first = publish(store, principal, clock)
    second = publish(store, principal, clock)
    assert second == first
    with pytest.raises(GovernanceAgentConflict, match="different canonical"):
        store.publish_policy(
            "tenant-a",
            policy_id="policy:one",
            revision=1,
            agent_kind="breach_response",
            allowed_capabilities=("containment_plan",),
            required_approvals=2,
            execution_enabled=True,
            approver_principals=("reviewer-a", "reviewer-b"),
            valid_until=clock.value + 601,
            idempotency_key="publish:policy:one",
        )


@pytest.mark.parametrize("agent_kind", sorted(AGENT_KINDS))
def test_all_five_packaged_agents_have_closed_workflows(harness, agent_kind):
    store, principal, clock = harness
    policy_id = f"policy:{agent_kind}"
    publish(
        store,
        principal,
        clock,
        agent_kind=agent_kind,
        execution_enabled=False,
        policy_id=policy_id,
    )
    run = submit(
        store,
        principal,
        clock,
        agent_kind=agent_kind,
        run_id=f"run:{agent_kind}",
        policy_id=policy_id,
    )
    assert run.agent_kind == agent_kind
    assert run.state == "pending_review"
    assert run.findings[0].finding_code in FINDING_CODES[agent_kind]
    assert run.findings[0].recommended_action_code in ACTION_CODES[agent_kind]


def test_raw_context_is_ephemeral_and_idempotent(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    raw = b"highly-secret-raw-context-never-persist"
    first = submit(store, principal, clock, raw=raw)
    second = submit(store, principal, clock, raw=raw)
    assert second == first
    assert first.context[0].content_sha256 == digest(raw)
    assert raw not in store.path.read_bytes()


def test_submit_rejects_out_of_request_citation(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    principal.value = "requester"

    def bad_adapter(**_kwargs):
        return GovernanceAgentAnalysis(
            findings=(
                build_finding(
                    agent_kind="breach_response",
                    finding_id="bad",
                    finding_code="incident_scope_unclear",
                    severity="high",
                    evidence_item_ids=("evidence:outside",),
                    recommended_action_code="create_incident_task",
                    rationale_code="evidence_sufficient",
                    confidence_bps=5_000,
                ),
            ),
            limitations=(),
            complete=True,
        )

    selected_authority = authority("breach_response", clock)
    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        bad_adapter,
    )
    with pytest.raises(GovernanceAgentIntegrityError, match="outside the exact request"):
        store.submit_run(
            "tenant-a",
            run_id="bad-run",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=selected_authority,
            adapter=bad_adapter,
            idempotency_key="bad-run",
        )


def test_unsafe_or_expired_adapter_authority_is_rejected(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    principal.value = "requester"
    unsafe = build_adapter_authority(
        adapter_id="unsafe",
        revision=1,
        agent_kind="breach_response",
        implementation_sha256=digest(b"impl"),
        configuration_sha256=digest(b"config"),
        deterministic=True,
        network_access=False,
        legal_conclusion_enabled=True,
        valid_until=clock.value + 20,
    )
    with pytest.raises(GovernanceAgentConfigError, match="unsafe"):
        store.submit_run(
            "tenant-a",
            run_id="unsafe",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=unsafe,
            adapter=adapter_for("breach_response"),
            idempotency_key="unsafe",
        )


def test_self_pinned_analysis_authority_cannot_replace_enrolled_binding(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    principal.value = "requester"
    proposed_authority = authority("breach_response", clock)
    proposed_adapter = adapter_for("breach_response")
    enrolled_authority = build_adapter_authority(
        adapter_id="adapter:breach_response",
        revision=2,
        agent_kind="breach_response",
        implementation_sha256=digest(b"different-implementation"),
        configuration_sha256=digest(b"different-configuration"),
        deterministic=True,
        network_access=False,
        legal_conclusion_enabled=False,
        valid_until=clock.value + 600,
    )
    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        enrolled_authority,
        proposed_adapter,
    )
    with pytest.raises(GovernanceAgentPermissionDenied, match="enrolled authority"):
        store.submit_run(
            "tenant-a",
            run_id="self-pinned-adapter",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=proposed_authority,
            adapter=proposed_adapter,
            idempotency_key="self-pinned-adapter",
        )


def test_analysis_authority_is_re_resolved_after_adapter_call(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    principal.value = "requester"
    selected_authority = authority("breach_response", clock)
    base_adapter = adapter_for("breach_response")

    def drifting_adapter(**kwargs):
        revoked = build_adapter_authority(
            adapter_id=selected_authority.adapter_id,
            revision=selected_authority.revision,
            agent_kind="breach_response",
            implementation_sha256=selected_authority.implementation_sha256,
            configuration_sha256=selected_authority.configuration_sha256,
            deterministic=True,
            network_access=False,
            legal_conclusion_enabled=False,
            valid_until=clock.value + 600,
            revoked=True,
        )
        store._test_analysis_bindings[("tenant-a", "breach_response")] = (
            revoked,
            drifting_adapter,
        )
        return base_adapter(**kwargs)

    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        drifting_adapter,
    )
    with pytest.raises(GovernanceAgentConfigError, match="unavailable"):
        store.submit_run(
            "tenant-a",
            run_id="adapter-revoked-mid-call",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=selected_authority,
            adapter=drifting_adapter,
            idempotency_key="adapter-revoked-mid-call",
        )


def test_requester_cannot_self_approve_and_cas_is_enforced(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = submit(store, principal, clock)
    principal.value = "requester"
    with pytest.raises(GovernanceAgentPermissionDenied, match="own run"):
        store.review(
            "tenant-a",
            run.run_id,
            expected_revision=run.revision,
            decision="approve",
            rationale_code="evidence_sufficient",
        )
    principal.value = "reviewer-a"
    with pytest.raises(GovernanceAgentConflict, match="revision changed"):
        store.review(
            "tenant-a",
            run.run_id,
            expected_revision=99,
            decision="approve",
            rationale_code="evidence_sufficient",
        )


def test_two_reviews_are_required_for_execution(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = submit(store, principal, clock)
    principal.value = "reviewer-a"
    once = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="approve",
        rationale_code="evidence_sufficient",
    )
    assert once.state == "pending_review"
    with pytest.raises(GovernanceAgentConflict, match="not eligible"):
        store.execute(
            "tenant-a",
            once.run_id,
            expected_revision=once.revision,
            dispatcher=lambda **_: None,
        )
    principal.value = "reviewer-b"
    approved = store.review(
        "tenant-a",
        once.run_id,
        expected_revision=once.revision,
        decision="approve",
        rationale_code="policy_threshold",
    )
    assert approved.state == "approved"


def test_policy_execution_is_default_off(harness):
    store, principal, clock = harness
    publish(store, principal, clock, execution_enabled=False)
    run = submit(store, principal, clock)
    principal.value = "reviewer-a"
    approved = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="approve",
        rationale_code="evidence_sufficient",
    )
    with pytest.raises(GovernanceAgentPermissionDenied, match="disabled"):
        store.execute(
            "tenant-a",
            approved.run_id,
            expected_revision=approved.revision,
            dispatcher=lambda **_: None,
        )


def test_approved_execution_records_content_free_receipt(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    captured = {}

    def behavior(run, idempotency_key, enrolled_authority):
        captured["run"] = run
        captured["token"] = idempotency_key
        captured["outcome"] = bound_outcome(
            run,
            enrolled_authority,
            outcome="applied",
            provider_status_code="accepted",
            external_reference_sha256=digest(b"provider-reference"),
        )
        return captured["outcome"]

    dispatcher, enrolled_authority, verifier = enroll_dispatcher(
        store,
        clock,
        behavior,
    )
    principal.value = "operator"
    executed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    store._validate_outcome(
        captured["outcome"],
        captured["run"],
        enrolled_authority,
        verifier,
    )
    assert executed.state == "executed", (
        executed.failure_code,
        executed.execution_outcome,
    )
    assert executed.execution_outcome is not None
    assert executed.execution_outcome.outcome == "applied"
    assert digest(captured["token"].encode()) == executed.execution_idempotency_sha256
    assert captured["token"].encode() not in store.path.read_bytes()


def test_forged_execution_receipt_fails_independent_verification(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))

    def behavior(executing, _token, enrolled_authority):
        valid = bound_outcome(
            executing,
            enrolled_authority,
            outcome="applied",
            provider_status_code="accepted",
        )
        return rehash_outcome(valid, receipt_proof_sha256=digest(b"forged-proof"))

    dispatcher, _authority, _verifier = enroll_dispatcher(store, clock, behavior)
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    assert failed.state == "execution_failed"
    assert failed.failure_code == "invalid_dispatch_receipt"


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("tenant_sha256", digest(b"other-tenant")),
        ("run_id", "other-run"),
        ("execution_idempotency_sha256", digest(b"other-token")),
        ("action_codes_sha256", digest(b"other-actions")),
    ],
)
def test_receipt_exact_tenant_run_token_and_action_bindings(harness, field, forged_value):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))

    def behavior(executing, _token, enrolled_authority):
        valid = bound_outcome(
            executing,
            enrolled_authority,
            outcome="no_change",
            provider_status_code="unchanged",
        )
        return rehash_outcome(valid, **{field: forged_value})

    enrolled_authority = dispatcher_authority("breach_response", clock)

    def dispatcher(*, run, idempotency_key):
        return behavior(run, idempotency_key, enrolled_authority)

    def verifier(_authority, _outcome):
        return True

    store._test_execution_bindings[("tenant-a", "breach_response")] = (
        enrolled_authority,
        dispatcher,
        verifier,
    )
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    assert failed.state == "execution_failed"
    assert failed.failure_code == "invalid_dispatch_receipt"


def test_execution_fails_before_intent_when_token_vault_confirmation_mismatches(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    called = False

    def behavior(*_args):
        nonlocal called
        called = True
        raise AssertionError("dispatcher must not run")

    dispatcher, _authority, _verifier = enroll_dispatcher(store, clock, behavior)
    store._execution_token_escrow = lambda *_: True
    store._execution_token_resolver = lambda *_: "mismatched-token"
    principal.value = "operator"
    with pytest.raises(GovernanceAgentIntegrityError, match="confirmation mismatched"):
        store.execute(
            "tenant-a",
            run.run_id,
            expected_revision=run.revision,
            dispatcher=dispatcher,
        )
    assert called is False
    assert store.get_run("tenant-a", run.run_id).state == "approved"


def test_dispatcher_revocation_after_call_fails_closed(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    binding = {}

    def behavior(executing, _token, enrolled_authority):
        outcome = bound_outcome(
            executing,
            enrolled_authority,
            outcome="applied",
            provider_status_code="accepted",
        )
        revoked = build_dispatcher_authority(
            dispatcher_id=enrolled_authority.dispatcher_id,
            revision=enrolled_authority.revision,
            agent_kind=enrolled_authority.agent_kind,
            implementation_sha256=enrolled_authority.implementation_sha256,
            configuration_sha256=enrolled_authority.configuration_sha256,
            execution_enabled=True,
            valid_until=clock.value + 600,
            revoked=True,
        )
        store._test_execution_bindings[("tenant-a", "breach_response")] = (
            revoked,
            binding["dispatcher"],
            binding["verifier"],
        )
        return outcome

    dispatcher, _authority, verifier = enroll_dispatcher(store, clock, behavior)
    binding.update(dispatcher=dispatcher, verifier=verifier)
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    assert failed.state == "execution_failed"
    assert failed.failure_code == "dispatcher_authority_changed"


def test_failed_execution_recovers_with_exact_original_token(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    captured = {}

    attempts = 0

    def behavior(run, idempotency_key, enrolled_authority):
        nonlocal attempts
        attempts += 1
        captured["token"] = idempotency_key
        if attempts == 1:
            raise OSError("provider outage")
        return bound_outcome(
            run,
            enrolled_authority,
            outcome="no_change",
            provider_status_code="already_applied",
        )

    dispatcher, _enrolled_authority, _verifier = enroll_dispatcher(
        store,
        clock,
        behavior,
    )
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    assert failed.state == "execution_failed"
    assert failed.failure_code == "dispatcher_unavailable"

    recovered = store.recover_execution(
        "tenant-a",
        run.run_id,
        expected_revision=failed.revision,
        dispatcher=dispatcher,
    )
    assert recovered.state == "executed"
    assert recovered.execution_attempts == 2
    assert recovered.execution_outcome.outcome == "no_change"


def test_crash_after_intent_commit_recovers_from_durable_token_vault(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    attempts = 0

    def behavior(executing, _token, enrolled_authority):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise KeyboardInterrupt("simulated process death")
        return bound_outcome(
            executing,
            enrolled_authority,
            outcome="no_change",
            provider_status_code="recovered",
        )

    dispatcher, _authority, _verifier = enroll_dispatcher(store, clock, behavior)
    principal.value = "operator"
    with pytest.raises(KeyboardInterrupt, match="process death"):
        store.execute(
            "tenant-a",
            run.run_id,
            expected_revision=run.revision,
            dispatcher=dispatcher,
        )
    executing = store.get_run("tenant-a", run.run_id)
    assert executing.state == "executing"
    assert executing.execution_idempotency_sha256 is not None
    assert digest(store._test_token_vault[("tenant-a", run.run_id)].encode()) == (
        executing.execution_idempotency_sha256
    )
    recovered = store.recover_execution(
        "tenant-a",
        run.run_id,
        expected_revision=executing.revision,
        dispatcher=dispatcher,
    )
    assert recovered.state == "executed"
    assert recovered.execution_attempts == 2


def test_wrong_recovery_token_is_denied(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    dispatcher, _authority, _verifier = enroll_dispatcher(
        store,
        clock,
        lambda *_: (_ for _ in ()).throw(OSError("down")),
    )
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    store._test_token_vault[("tenant-a", run.run_id)] = "wrong-token"
    with pytest.raises(GovernanceAgentPermissionDenied, match="did not match"):
        store.recover_execution(
            "tenant-a",
            run.run_id,
            expected_revision=failed.revision,
            dispatcher=dispatcher,
        )


def test_recovery_revalidates_policy_authority(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    captured = {}

    def unavailable(run, idempotency_key, _enrolled_authority):
        captured["token"] = idempotency_key
        raise OSError("down")

    dispatcher, _authority, _verifier = enroll_dispatcher(
        store,
        clock,
        unavailable,
    )
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    store.revoke_policy(
        "tenant-a",
        "policy:one",
        revision=1,
        reason_code="human_override",
    )
    with pytest.raises(GovernanceAgentPermissionDenied, match="revoked"):
        store.recover_execution(
            "tenant-a",
            run.run_id,
            expected_revision=failed.revision,
            dispatcher=dispatcher,
        )


def test_non_retryable_provider_outcome_cannot_be_recovered(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = approve_twice(store, principal, submit(store, principal, clock))
    captured = {}

    def denied(run, idempotency_key, enrolled_authority):
        captured["token"] = idempotency_key
        return bound_outcome(
            run,
            enrolled_authority,
            outcome="failed",
            provider_status_code="denied",
            retryable=False,
        )

    dispatcher, _authority, _verifier = enroll_dispatcher(store, clock, denied)
    principal.value = "operator"
    failed = store.execute(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )
    with pytest.raises(GovernanceAgentConflict, match="not retryable"):
        store.recover_execution(
            "tenant-a",
            run.run_id,
            expected_revision=failed.revision,
            dispatcher=dispatcher,
        )


def test_policy_revocation_blocks_review(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = submit(store, principal, clock)
    principal.value = "security-admin"
    store.revoke_policy("tenant-a", "policy:one", revision=1, reason_code="human_override")
    principal.value = "reviewer-a"
    with pytest.raises(GovernanceAgentConflict, match="no longer valid"):
        store.review(
            "tenant-a",
            run.run_id,
            expected_revision=run.revision,
            decision="approve",
            rationale_code="evidence_sufficient",
        )


def test_tenant_isolation(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = submit(store, principal, clock)
    principal.value = "reader"
    assert store.get_run("tenant-a", run.run_id) == run
    with pytest.raises(Exception, match="not found"):
        store.get_run("tenant-b", run.run_id)


def test_rejection_revocation_retention_and_integrity(harness):
    store, principal, clock = harness
    publish(store, principal, clock, execution_enabled=False)
    run = submit(store, principal, clock)
    principal.value = "reviewer-a"
    rejected = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="reject",
        rationale_code="evidence_conflicting",
    )
    assert rejected.state == "rejected"
    report = store.verify_integrity("tenant-a")
    assert report.verified_policies == 1
    assert report.verified_runs == 1
    assert report.audit_events == 3
    clock.value = rejected.retained_until + 1
    assert store.purge_expired("tenant-a") == 1
    assert store.verify_integrity("tenant-a").verified_runs == 0


def test_tamper_is_detected(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    submit(store, principal, clock)
    with sqlite3.connect(store.path) as connection:
        # The runs index orders by a store-registered SQL function that itself
        # refuses a malformed payload. An outside tamperer drops those indexes
        # first and rewrites the row directly.
        connection.execute("DROP INDEX run_recent")
        connection.execute("DROP INDEX run_state_recent")
        connection.execute("UPDATE runs SET payload_json='{}' WHERE tenant_id='tenant-a'")
    principal.value = "auditor"
    with pytest.raises(GovernanceAgentIntegrityError, match="integrity"):
        store.verify_integrity("tenant-a")


@pytest.mark.parametrize(
    ("statement", "message"),
    [
        ("UPDATE runs SET retained_until=0 WHERE tenant_id='tenant-a'", "run mirror"),
        ("UPDATE policies SET revoked=1 WHERE tenant_id='tenant-a'", "policy mirror"),
        ("UPDATE operations SET result_id='forged' WHERE tenant_id='tenant-a'", "idempotency"),
    ],
)
def test_query_mirror_and_idempotency_tamper_is_detected(harness, statement, message):
    store, principal, clock = harness
    publish(store, principal, clock)
    submit(store, principal, clock)
    with sqlite3.connect(store.path) as connection:
        connection.execute(statement)
    principal.value = "auditor"
    with pytest.raises(GovernanceAgentIntegrityError, match=message):
        store.verify_integrity("tenant-a")


def test_budget_exhaustion_blocks_analysis(tmp_path):
    principal = MutablePrincipal()
    clock = MutableClock()
    bindings = {}
    store = GovernanceAgentStore(
        tmp_path / "budget.sqlite3",
        config_gate=lambda: None,
        principal_resolver=principal,
        policy_approver_resolver=lambda _tenant, _policy, _revision: (
            "reviewer-a",
            "reviewer-b",
        ),
        analysis_binding_resolver=lambda tenant, kind: bindings[(tenant, kind)],
        clock=clock,
        budget=Budget(max_tool_calls=0),
    )
    publish(store, principal, clock)
    principal.value = "requester"
    selected_authority = authority("breach_response", clock)
    selected_adapter = adapter_for("breach_response")
    bindings[("tenant-a", "breach_response")] = (selected_authority, selected_adapter)
    with pytest.raises(GovernanceAgentConfigError, match="budget"):
        store.submit_run(
            "tenant-a",
            run_id="budget-run",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=selected_authority,
            adapter=selected_adapter,
            idempotency_key="budget-run",
        )


def test_policy_quota_is_tenant_configurable_atomic_and_replay_safe(tmp_path):
    defaults = GovernanceAgentLimits(retention_seconds=3_600)
    tenant_limits = {
        "tenant-a": replace(defaults, max_policy_records=1),
        "tenant-b": replace(defaults, max_policy_records=2),
    }
    store, principal, clock = store_with_limits(
        tmp_path,
        limits=defaults,
        tenant_limits_resolver=tenant_limits.__getitem__,
    )

    first = publish(store, principal, clock, tenant_id="tenant-a")
    assert publish(store, principal, clock, tenant_id="tenant-a") == first
    with pytest.raises(GovernanceAgentQuotaExceeded, match="policies quota"):
        publish(
            store,
            principal,
            clock,
            tenant_id="tenant-a",
            policy_id="policy:two",
        )
    publish(store, principal, clock, tenant_id="tenant-b")
    publish(
        store,
        principal,
        clock,
        tenant_id="tenant-b",
        policy_id="policy:two",
    )

    principal.value = "auditor"
    assert store.verify_integrity("tenant-a").verified_policies == 1
    assert store.verify_integrity("tenant-b").verified_policies == 2


@pytest.mark.parametrize(
    "limits",
    [
        replace(GovernanceAgentLimits(retention_seconds=3_600), max_run_records=1),
        replace(GovernanceAgentLimits(retention_seconds=3_600), max_operation_records=2),
        replace(GovernanceAgentLimits(retention_seconds=3_600), max_audit_events=2),
    ],
    ids=("runs", "operations", "audit"),
)
def test_run_capacity_backpressure_precedes_adapter_call_and_preserves_replay(
    tmp_path,
    limits,
):
    store, principal, clock = store_with_limits(tmp_path, limits=limits)
    publish(store, principal, clock)
    first = submit(store, principal, clock)
    assert submit(store, principal, clock) == first

    calls = 0
    selected_authority = authority("breach_response", clock)
    base_adapter = adapter_for("breach_response")

    def counting_adapter(**kwargs):
        nonlocal calls
        calls += 1
        return base_adapter(**kwargs)

    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        counting_adapter,
    )
    principal.value = "requester"
    with pytest.raises(GovernanceAgentQuotaExceeded, match="quota"):
        store.submit_run(
            "tenant-a",
            run_id="run:two",
            policy_id="policy:one",
            policy_revision=1,
            capability=sorted(CAPABILITY_REGISTRY["breach_response"])[0],
            context=context(),
            adapter_authority=selected_authority,
            adapter=counting_adapter,
            idempotency_key="submit:run:two",
        )
    assert calls == 0
    assert store.verify_integrity("tenant-a").verified_runs == 1


def test_audit_quota_rolls_back_mutation(tmp_path):
    limits = replace(
        GovernanceAgentLimits(retention_seconds=3_600),
        max_audit_events=1,
    )
    store, principal, clock = store_with_limits(tmp_path, limits=limits)
    published = publish(store, principal, clock)

    principal.value = "security-admin"
    with pytest.raises(GovernanceAgentQuotaExceeded, match="audit quota"):
        store.revoke_policy(
            "tenant-a",
            published.policy_id,
            revision=published.revision,
            reason_code="human_override",
        )
    assert store.get_policy("tenant-a", published.policy_id).revoked is False
    assert store.verify_integrity("tenant-a").audit_events == 1


def test_concurrent_identical_submit_uses_one_active_analysis_lease(tmp_path):
    store, principal, clock = store_with_limits(
        tmp_path,
        limits=GovernanceAgentLimits(retention_seconds=3_600, analysis_lease_seconds=30),
    )
    publish(store, principal, clock)
    selected_authority = authority("breach_response", clock)
    base_adapter = adapter_for("breach_response")
    started = threading.Event()
    release = threading.Event()
    calls = 0
    call_lock = threading.Lock()

    def blocking_adapter(**kwargs):
        nonlocal calls
        with call_lock:
            calls += 1
        started.set()
        assert release.wait(5)
        return base_adapter(**kwargs)

    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        blocking_adapter,
    )
    principal.value = "requester"
    submit_kwargs = {
        "run_id": "run:lease",
        "policy_id": "policy:one",
        "policy_revision": 1,
        "capability": sorted(CAPABILITY_REGISTRY["breach_response"])[0],
        "context": context(),
        "adapter_authority": selected_authority,
        "adapter": blocking_adapter,
        "idempotency_key": "submit:run:lease",
    }
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.submit_run, "tenant-a", **submit_kwargs)
        assert started.wait(5)
        with sqlite3.connect(store.path) as connection:
            reservation = connection.execute(
                "SELECT owner_sha256,payload_json FROM analysis_reservations "
                "WHERE tenant_id='tenant-a'"
            ).fetchone()
        assert reservation is not None
        assert "ga-analysis:" not in "".join(reservation)
        with pytest.raises(GovernanceAgentConflict, match="already in flight"):
            store.submit_run("tenant-a", **submit_kwargs)
        assert calls == 1
        release.set()
        completed = future.result(timeout=5)
    assert store.submit_run("tenant-a", **submit_kwargs) == completed
    assert calls == 1


def test_crashed_analysis_reclaims_only_after_lease_expiry(tmp_path):
    store, principal, clock = store_with_limits(
        tmp_path,
        limits=GovernanceAgentLimits(retention_seconds=3_600, analysis_lease_seconds=5),
    )
    publish(store, principal, clock)
    selected_authority = authority("breach_response", clock)
    base_adapter = adapter_for("breach_response")
    calls = 0

    def crash_once(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise KeyboardInterrupt("simulated analysis worker crash")
        return base_adapter(**kwargs)

    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        crash_once,
    )
    principal.value = "requester"
    submit_kwargs = {
        "run_id": "run:crash",
        "policy_id": "policy:one",
        "policy_revision": 1,
        "capability": sorted(CAPABILITY_REGISTRY["breach_response"])[0],
        "context": context(),
        "adapter_authority": selected_authority,
        "adapter": crash_once,
        "idempotency_key": "submit:run:crash",
    }
    with pytest.raises(KeyboardInterrupt, match="worker crash"):
        store.submit_run("tenant-a", **submit_kwargs)
    with pytest.raises(GovernanceAgentConflict, match="already in flight"):
        store.submit_run("tenant-a", **submit_kwargs)
    assert calls == 1

    with sqlite3.connect(store.path) as connection:
        stored = connection.execute(
            "SELECT owner_sha256,payload_json FROM analysis_reservations"
        ).fetchone()
    assert stored is not None
    assert "ga-analysis:" not in "".join(stored)
    clock.value += 5
    recovered = store.submit_run("tenant-a", **submit_kwargs)
    assert recovered.state == "pending_review"
    assert calls == 2
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM analysis_reservations").fetchone()[0] == 0


def test_reclaimed_analysis_lease_fences_old_worker(tmp_path):
    store, principal, clock = store_with_limits(
        tmp_path,
        limits=GovernanceAgentLimits(retention_seconds=3_600, analysis_lease_seconds=5),
    )
    publish(store, principal, clock)
    selected_authority = authority("breach_response", clock)
    base_adapter = adapter_for("breach_response")
    first_started = threading.Event()
    release_first = threading.Event()
    call_lock = threading.Lock()
    calls = 0

    def fenced_adapter(**kwargs):
        nonlocal calls
        with call_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            first_started.set()
            assert release_first.wait(5)
        return base_adapter(**kwargs)

    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        fenced_adapter,
    )
    principal.value = "requester"
    submit_kwargs = {
        "run_id": "run:fenced",
        "policy_id": "policy:one",
        "policy_revision": 1,
        "capability": sorted(CAPABILITY_REGISTRY["breach_response"])[0],
        "context": context(),
        "adapter_authority": selected_authority,
        "adapter": fenced_adapter,
        "idempotency_key": "submit:run:fenced",
    }
    with ThreadPoolExecutor(max_workers=1) as pool:
        stale_worker = pool.submit(store.submit_run, "tenant-a", **submit_kwargs)
        assert first_started.wait(5)
        clock.value += 5
        winner = store.submit_run("tenant-a", **submit_kwargs)
        release_first.set()
        with pytest.raises(GovernanceAgentConflict, match="no longer owned"):
            stale_worker.result(timeout=5)
    assert calls == 2
    assert store.get_run("tenant-a", "run:fenced") == winner


def test_purge_retains_replay_tombstone_and_blocks_run_id_reuse(tmp_path):
    store, principal, clock = store_with_limits(
        tmp_path,
        limits=GovernanceAgentLimits(retention_seconds=3_600),
    )
    publish(store, principal, clock, execution_enabled=False, valid_for=7_200)
    selected_authority = authority("breach_response", clock, valid_for=7_200)
    selected_adapter = adapter_for("breach_response")
    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        selected_adapter,
    )
    principal.value = "requester"
    submit_kwargs = {
        "run_id": "run:tombstone",
        "policy_id": "policy:one",
        "policy_revision": 1,
        "capability": sorted(CAPABILITY_REGISTRY["breach_response"])[0],
        "context": context(),
        "adapter_authority": selected_authority,
        "adapter": selected_adapter,
        "idempotency_key": "submit:run:tombstone",
    }
    run = store.submit_run("tenant-a", **submit_kwargs)
    principal.value = "reviewer-a"
    rejected = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="reject",
        rationale_code="evidence_conflicting",
    )
    clock.value = rejected.retained_until + 1
    principal.value = "retention-admin"
    assert store.purge_expired("tenant-a") == 1

    principal.value = "requester"
    with pytest.raises(GovernanceAgentConflict, match="tombstoned"):
        store.submit_run("tenant-a", **submit_kwargs)
    with pytest.raises(GovernanceAgentConflict, match="different canonical content"):
        store.submit_run(
            "tenant-a",
            **{**submit_kwargs, "context": context(b"changed retained content")},
        )
    with pytest.raises(GovernanceAgentConflict, match="purge tombstone"):
        store.submit_run(
            "tenant-a",
            **{**submit_kwargs, "idempotency_key": "submit:run:tombstone:new"},
        )
    assert store.verify_integrity("tenant-a").verified_runs == 0


def test_purge_backlink_or_audit_failure_rolls_back(tmp_path):
    limits = replace(
        GovernanceAgentLimits(retention_seconds=3_600),
        max_audit_events=3,
    )
    store, principal, clock = store_with_limits(tmp_path, limits=limits)
    publish(store, principal, clock, execution_enabled=False, valid_for=7_200)
    run = submit(store, principal, clock)
    principal.value = "reviewer-a"
    rejected = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="reject",
        rationale_code="evidence_conflicting",
    )
    clock.value = rejected.retained_until + 1
    principal.value = "retention-admin"
    with pytest.raises(GovernanceAgentQuotaExceeded, match="audit quota"):
        store.purge_expired("tenant-a")
    assert store.get_run("tenant-a", run.run_id).state == "rejected"
    with sqlite3.connect(store.path) as connection:
        result_kind = connection.execute(
            "SELECT result_kind FROM operations WHERE result_id=?",
            (run.run_id,),
        ).fetchone()[0]
    assert result_kind == "run"
    assert store.verify_integrity("tenant-a").verified_runs == 1


def test_expired_reservation_cleanup_releases_promised_capacity(tmp_path):
    limits = replace(
        GovernanceAgentLimits(retention_seconds=3_600, analysis_lease_seconds=5),
        max_run_records=1,
    )
    store, principal, clock = store_with_limits(tmp_path, limits=limits)
    publish(store, principal, clock)
    selected_authority = authority("breach_response", clock)

    def crashed_adapter(**_kwargs):
        raise KeyboardInterrupt("abandoned analysis")

    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        crashed_adapter,
    )
    principal.value = "requester"
    with pytest.raises(KeyboardInterrupt, match="abandoned"):
        store.submit_run(
            "tenant-a",
            run_id="run:abandoned",
            policy_id="policy:one",
            policy_revision=1,
            capability="containment_plan",
            context=context(),
            adapter_authority=selected_authority,
            adapter=crashed_adapter,
            idempotency_key="submit:run:abandoned",
        )

    clock.value += 5
    principal.value = "lease-admin"
    assert store.purge_expired_analysis_reservations("tenant-a") == 1
    selected_adapter = adapter_for("breach_response")
    store._test_analysis_bindings[("tenant-a", "breach_response")] = (
        selected_authority,
        selected_adapter,
    )
    principal.value = "requester"
    completed = store.submit_run(
        "tenant-a",
        run_id="run:after-cleanup",
        policy_id="policy:one",
        policy_revision=1,
        capability="containment_plan",
        context=context(),
        adapter_authority=selected_authority,
        adapter=selected_adapter,
        idempotency_key="submit:run:after-cleanup",
    )
    assert completed.state == "pending_review"
    assert store.verify_integrity("tenant-a").verified_runs == 1


def test_missing_run_backlink_aborts_purge_without_deleting_run(tmp_path):
    store, principal, clock = store_with_limits(
        tmp_path,
        limits=GovernanceAgentLimits(retention_seconds=3_600),
    )
    publish(store, principal, clock, execution_enabled=False)
    run = submit(store, principal, clock)
    principal.value = "reviewer-a"
    rejected = store.review(
        "tenant-a",
        run.run_id,
        expected_revision=run.revision,
        decision="reject",
        rationale_code="evidence_conflicting",
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "DELETE FROM operations WHERE tenant_id='tenant-a' "
            "AND result_kind='run' AND result_id=?",
            (run.run_id,),
        )
    clock.value = rejected.retained_until + 1
    principal.value = "retention-admin"
    with pytest.raises(GovernanceAgentIntegrityError, match="exactly one"):
        store.purge_expired("tenant-a")
    assert store.get_run("tenant-a", run.run_id).state == "rejected"


def test_integrity_rejects_recomputed_tombstone_with_live_run(harness):
    store, principal, clock = harness
    publish(store, principal, clock)
    run = submit(store, principal, clock)
    with sqlite3.connect(store.path) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id='tenant-a' "
            "AND result_kind='run' AND result_id=?",
            (run.run_id,),
        ).fetchone()
        binding = {
            "tenant_id": row["tenant_id"],
            "operation_sha256": row["operation_sha256"],
            "request_sha256": row["request_sha256"],
            "result_kind": "run_tombstone",
            "result_id": row["result_id"],
        }
        connection.execute(
            "UPDATE operations SET result_kind='run_tombstone',integrity_sha256=? "
            "WHERE tenant_id='tenant-a' AND operation_sha256=?",
            (_proof(binding), row["operation_sha256"]),
        )
    principal.value = "auditor"
    with pytest.raises(GovernanceAgentIntegrityError, match="tombstone conflicts"):
        store.verify_integrity("tenant-a")


def test_list_policies_returns_current_revision_per_policy_for_the_tenant(harness):
    store, principal, clock = harness
    publish(store, principal, clock, policy_id="policy:one")
    publish(store, principal, clock, policy_id="policy:two", agent_kind="privacy_risk_assessment")
    listed = store.list_policies("tenant-a")
    assert [policy.policy_id for policy in listed] == ["policy:one", "policy:two"]
    assert {policy.agent_kind for policy in listed} == {"breach_response", "privacy_risk_assessment"}
    assert store.list_policies("tenant-b") == ()
    with pytest.raises(ValueError):
        store.list_policies("tenant-a", limit=0)
