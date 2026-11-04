from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick import governance_agents as agents
from maverick_dashboard import governance_agents_composition as composition


class Clock:
    def __init__(self, value: float = 10_000.0) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def snapshot_for(
    tenant_id: str,
    *,
    enabled_agents: tuple[str, ...] = tuple(sorted(agents.AGENT_KINDS)),
) -> agents.GovernanceAgentTenantSnapshot:
    return agents.GovernanceAgentTenantSnapshot(
        tenant_id=tenant_id,
        enabled_agents=enabled_agents,
        limits=agents.GovernanceAgentLimits(retention_seconds=3_600),
    )


def roster() -> dict[str, str]:
    return {
        "user:publisher": "admin",
        "user:reviewer-a": "operator",
        "user:reviewer-b": "operator",
        "user:auditor": "auditor",
        "user:viewer": "viewer",
    }


def build_composition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    clock: Clock | None = None,
    enabled_agents: tuple[str, ...] = tuple(sorted(agents.AGENT_KINDS)),
) -> composition.GovernanceAgentsReferenceComposition:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    selected_clock = clock or Clock()
    return composition.GovernanceAgentsReferenceComposition(
        tenant_snapshot_resolver=lambda tenant: snapshot_for(
            tenant, enabled_agents=enabled_agents
        ),
        roster_resolver=lambda _tenant: roster(),
        clock=selected_clock,
    )


def test_install_is_lazy_idempotent_and_attaches_every_api_seam(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    app = FastAPI()
    instance = composition.install_governance_agents_composition(
        app,
        tenant_snapshot_resolver=snapshot_for,
        roster_resolver=lambda _tenant: roster(),
    )

    assert list(tmp_path.rglob("*")) == []
    assert composition.install_governance_agents_composition(app) is instance
    assert app.state.governance_agents_store_factory == instance.store_factory
    assert app.state.governance_agent_tenant_snapshot_resolver == instance.tenant_snapshot
    assert app.state.governance_agent_policy_approver_resolver == instance.policy_approvers
    assert app.state.governance_agent_context_resolver == instance.resolve_context
    assert app.state.governance_agent_adapter_resolver == instance.resolve_adapter
    assert app.state.governance_agent_dispatcher_resolver == instance.resolve_dispatcher
    assert app.state.governance_agent_execution_token_escrow == instance.escrow_token
    assert app.state.governance_agent_execution_token_resolver == instance.resolve_token
    assert app.state.governance_agent_composition_readiness == instance.readiness
    assert app.state.governance_agent_retention_runner == instance.purge_retention
    assert app.state.governance_agent_reference_maintenance is instance


def test_role_backed_approvers_are_tenant_scoped_opaque_and_exclude_publisher() -> None:
    authority = composition.RoleBackedPolicyApproverAuthority(
        lambda tenant: roster() if tenant == "tenant-a" else {},
        policy=composition.ReferenceBindingPolicy(),
    )
    publisher = composition.governance_agent_principal_ref(
        "tenant-a", "user:publisher"
    )
    expected = tuple(
        sorted(
            {
                composition.governance_agent_principal_ref(
                    "tenant-a", "user:reviewer-a"
                ),
                composition.governance_agent_principal_ref(
                    "tenant-a", "user:reviewer-b"
                ),
            }
        )
    )

    assert authority.bind(publisher)("tenant-a", "policy-a", 1) == expected
    assert authority("tenant-b", "policy-a", 1) == ()
    assert all("reviewer" not in value for value in expected)

    insufficient = composition.RoleBackedPolicyApproverAuthority(
        lambda _tenant: {"user:publisher": "admin", "user:reviewer-a": "operator"},
        policy=composition.ReferenceBindingPolicy(),
    )
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="two tenant RBAC approvers",
    ):
        insufficient.bind(publisher)("tenant-a", "policy-a", 1)


def test_large_eligible_roster_accepts_bounded_independent_quorum(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    clock = Clock()
    large_roster = {
        "user:publisher": "admin",
        **{f"user:reviewer-{index}": "operator" for index in range(9)},
    }
    instance = composition.GovernanceAgentsReferenceComposition(
        tenant_snapshot_resolver=lambda tenant: snapshot_for(
            tenant, enabled_agents=("breach_response",)
        ),
        roster_resolver=lambda _tenant: large_roster,
        clock=clock,
    )
    publisher = _store_for(instance, "user:publisher")
    eligible = instance.approver_authority.bind(
        composition.governance_agent_principal_ref(
            "tenant-a", "user:publisher"
        )
    )("tenant-a", "policy-large-roster", 1)

    assert len(eligible) == 9
    policy = publisher.publish_policy(
        "tenant-a",
        policy_id="policy-large-roster",
        revision=1,
        agent_kind="breach_response",
        allowed_capabilities=("incident_triage",),
        required_approvals=2,
        execution_enabled=True,
        approver_principals=eligible[:2],
        valid_until=clock.value + 600,
        idempotency_key="publish-policy-large-roster",
    )

    assert policy.approver_principals == eligible[:2]
    assert instance.readiness("tenant-a")["policy_publication_ready"] is True


def test_context_authority_resolves_exact_server_projection_and_revokes() -> None:
    authority = composition.EphemeralGovernanceContextAuthority(
        clock=lambda: 100.0,
        max_items=2,
        max_bytes=1_024,
    )
    first = agents.GovernanceContextItem(
        item_id="item-a",
        source_kind="incident",
        source_ref="incident-a",
        source_revision=1,
        collected_at=99.0,
        content=b"server-owned incident projection",
    )
    authority.publish("tenant-a", first)
    references = [
        {
            "item_id": "item-a",
            "source_kind": "incident",
            "source_ref": "incident-a",
            "source_revision": 1,
        }
    ]
    limits = agents.GovernanceAgentLimits(max_context_bytes=1_024)

    assert authority.resolve("tenant-a", references, limits=limits) == (first,)
    with pytest.raises(composition.GovernanceAgentsCompositionError):
        authority.resolve("tenant-b", references, limits=limits)
    assert authority.revoke(
        "tenant-a",
        source_kind="incident",
        source_ref="incident-a",
        source_revision=1,
    )
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="not enrolled",
    ):
        authority.resolve("tenant-a", references, limits=limits)


def test_registered_context_source_must_preserve_exact_reference_binding() -> None:
    authority = composition.EphemeralGovernanceContextAuthority(clock=lambda: 100.0)
    authority.register_source("risk", lambda _tenant, _ref, _revision: b"risk projection")
    reference = {
        "item_id": "risk-item",
        "source_kind": "risk",
        "source_ref": "risk-a",
        "source_revision": 7,
    }
    resolved = authority.resolve(
        "tenant-a",
        [reference],
        limits=agents.GovernanceAgentLimits(),
    )
    assert resolved[0].item_id == "risk-item"
    assert resolved[0].source_revision == 7
    assert resolved[0].content == b"risk projection"

    authority.unregister_source("risk")
    authority.register_source(
        "risk",
        lambda _tenant, _ref, _revision: agents.GovernanceContextItem(
            item_id="wrong-item",
            source_kind="risk",
            source_ref="risk-a",
            source_revision=7,
            collected_at=100.0,
            content=b"wrong binding",
        ),
    )
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="changed the requested source binding",
    ):
        authority.resolve(
            "tenant-a",
            [reference],
            limits=agents.GovernanceAgentLimits(),
        )


def _store_for(
    instance: composition.GovernanceAgentsReferenceComposition,
    principal: str,
) -> agents.GovernanceAgentStore:
    tenant = "tenant-a"
    principal_ref = composition.governance_agent_principal_ref(tenant, principal)
    snapshot = instance.tenant_snapshot(tenant)
    return instance.store_factory(
        tenant_id=tenant,
        principal_ref=principal_ref,
        principal_resolver=lambda: principal_ref,
        tenant_snapshot_resolver=lambda requested: (
            snapshot if requested == tenant else snapshot_for(requested)
        ),
    )


def test_reference_composition_runs_full_governed_internal_intent_workflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    instance = build_composition(
        tmp_path,
        monkeypatch,
        clock=clock,
        enabled_agents=("breach_response",),
    )
    publisher = _store_for(instance, "user:publisher")
    approvers = instance.approver_authority.bind(
        composition.governance_agent_principal_ref("tenant-a", "user:publisher")
    )("tenant-a", "policy-a", 1)
    policy = publisher.publish_policy(
        "tenant-a",
        policy_id="policy-a",
        revision=1,
        agent_kind="breach_response",
        allowed_capabilities=("incident_triage",),
        required_approvals=2,
        execution_enabled=True,
        approver_principals=approvers,
        valid_until=clock.value + 600,
        idempotency_key="publish-policy-a",
    )
    assert policy.execution_enabled is True

    context_item = agents.GovernanceContextItem(
        item_id="incident-context",
        source_kind="incident",
        source_ref="incident-a",
        source_revision=1,
        collected_at=clock.value - 1,
        content=b'{"status":"reported","scope":"unverified"}',
    )
    instance.context_authority.publish("tenant-a", context_item)
    resolved_context = instance.resolve_context(
        "tenant-a",
        [
            {
                "item_id": "incident-context",
                "source_kind": "incident",
                "source_ref": "incident-a",
                "source_revision": 1,
            }
        ],
    )
    adapter_authority, adapter = instance.resolve_adapter(
        "tenant-a", "breach_response"
    )
    run = publisher.submit_run(
        "tenant-a",
        run_id="run-a",
        policy_id="policy-a",
        policy_revision=1,
        capability="incident_triage",
        context=resolved_context,
        adapter_authority=adapter_authority,
        adapter=adapter,
        idempotency_key="analyze-run-a",
    )
    assert run.analysis_complete is False
    assert run.limitations == ("human_context_required", "legal_review_required")
    assert run.findings[0].recommended_action_code == "create_incident_task"

    reviewer_a = _store_for(instance, "user:reviewer-a")
    run = reviewer_a.review(
        "tenant-a",
        "run-a",
        expected_revision=run.revision,
        decision="approve",
        rationale_code="evidence_sufficient",
    )
    reviewer_b = _store_for(instance, "user:reviewer-b")
    run = reviewer_b.review(
        "tenant-a",
        "run-a",
        expected_revision=run.revision,
        decision="approve",
        rationale_code="evidence_sufficient",
    )
    dispatcher_authority, dispatcher, verifier = instance.resolve_dispatcher(
        "tenant-a", "breach_response"
    )
    executed = publisher.execute(
        "tenant-a",
        "run-a",
        expected_revision=run.revision,
        dispatcher=dispatcher,
    )

    assert executed.state == "executed"
    assert executed.execution_outcome is not None
    assert executed.execution_outcome.outcome == "applied"
    assert executed.execution_outcome.provider_status_code == "internal_intent_recorded"
    assert executed.execution_outcome.external_reference_sha256 is not None
    assert verifier(dispatcher_authority, executed.execution_outcome) is True
    assert instance._state_for("tenant-a").intent_count() == 1
    intents = instance.list_internal_intents("tenant-a")
    assert intents == (
        {
            "schema": "lightwork.governance-agent.internal-intent.v1",
            "tenant_id": "tenant-a",
            "run_id": "run-a",
            "agent_kind": "breach_response",
            "action_codes_sha256": intents[0]["action_codes_sha256"],
            "intent_sha256": executed.execution_outcome.external_reference_sha256,
            "status": "pending_human_action",
            "created_at": clock.value,
            "external_writes": False,
        },
    )
    assert "token" not in intents[0]
    assert instance._state_for("tenant-a").health()["external_writes_enabled"] is False
    assert instance.reconcile_execution_tokens("tenant-a") == 1
    assert instance._state_for("tenant-a").active_token_count() == 0
    assert publisher.verify_integrity("tenant-a").verified_runs == 1

    clock.value += 3_601
    retained = instance.purge_retention("tenant-a", store=publisher, limit=100)

    assert retained == {
        "schema": "lightwork.governance-agent.coordinated-retention.v1",
        "purged": 1,
        "execution_tokens_settled": 0,
        "sealed_tokens_purged": 1,
        "internal_intents_purged": 1,
        "retention_anchors": 1,
        "plaintext_tokens_persisted": False,
        "external_writes": False,
    }
    assert publisher.has_run_tombstone("tenant-a", "run-a") is True
    with pytest.raises(agents.GovernanceAgentNotFound):
        publisher.get_run("tenant-a", "run-a")
    assert instance._state_for("tenant-a").intent_count() == 0
    assert instance._state_for("tenant-a").active_token_count() == 0
    assert instance._state_for("tenant-a").health()["retention_anchors"] == 1
    integrity = publisher.verify_integrity("tenant-a")
    assert integrity.verified_runs == 0
    assert integrity.audit_events > 0


def test_token_custody_survives_rotation_then_revocation_blocks_recovery(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = build_composition(tmp_path, monkeypatch)
    state = instance._state_for("tenant-a")
    token = "ga:reference-recovery-token"
    token_sha256 = hashlib.sha256(token.encode()).hexdigest()
    assert state.escrow_token("tenant-a", "run-a", token, token_sha256)
    before = state._read_keyring()["current"]

    after = state.rotate_custody_key()
    assert after != before
    assert state.resolve_token("tenant-a", "run-a") == token
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="active recovery tokens",
    ):
        state.retire_custody_key(before)

    assert state.revoke_token("run-a")
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="unavailable or revoked",
    ):
        state.resolve_token("tenant-a", "run-a")
    state.retire_custody_key(before)
    assert before not in state._read_keyring()["order"]


def test_binding_rotation_and_revocation_are_explicit_and_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = build_composition(
        tmp_path,
        monkeypatch,
        enabled_agents=("program_copilot",),
    )
    first_adapter, _adapter = instance.resolve_adapter("tenant-a", "program_copilot")
    assert first_adapter.revision == 1
    assert instance.rotate_adapter("tenant-a", "program_copilot") == 2
    second_adapter, _adapter = instance.resolve_adapter("tenant-a", "program_copilot")
    assert second_adapter.revision == 2
    assert second_adapter.authority_sha256 != first_adapter.authority_sha256
    instance.revoke_adapter("tenant-a", "program_copilot")
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="revoked or expired",
    ):
        instance.resolve_adapter("tenant-a", "program_copilot")
    assert instance.rotate_adapter("tenant-a", "program_copilot") == 3
    reenrolled_adapter, _adapter = instance.resolve_adapter(
        "tenant-a", "program_copilot"
    )
    assert reenrolled_adapter.revision == 3

    first_dispatcher, _dispatcher, _verifier = instance.resolve_dispatcher(
        "tenant-a", "program_copilot"
    )
    assert first_dispatcher.revision == 1
    token = "ga:active-token"
    assert instance.escrow_token(
        "tenant-a",
        "active-run",
        token,
        hashlib.sha256(token.encode()).hexdigest(),
    )
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="reconciliation",
    ):
        instance.rotate_dispatcher("tenant-a", "program_copilot")
    assert instance.revoke_execution_token("tenant-a", "active-run")
    assert instance.rotate_dispatcher("tenant-a", "program_copilot") == 2
    instance.revoke_dispatcher("tenant-a", "program_copilot")
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="revoked or expired",
    ):
        instance.resolve_dispatcher("tenant-a", "program_copilot")
    assert instance.rotate_dispatcher("tenant-a", "program_copilot") == 3
    reenrolled_dispatcher, _dispatcher, _verifier = instance.resolve_dispatcher(
        "tenant-a", "program_copilot"
    )
    assert reenrolled_dispatcher.revision == 3


def test_readiness_is_operational_honest_and_never_claims_external_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = build_composition(
        tmp_path,
        monkeypatch,
        enabled_agents=("program_copilot",),
    )
    before = instance.readiness("tenant-a")
    assert before["configured"] is True
    assert before["store_integrity_verified"] is True
    assert before["analysis_ready"] is False
    assert before["internal_intent_execution_ready"] is True
    assert before["external_writes_enabled"] is False
    assert before["live_provider_acceptance_verified"] is False
    assert before["live_customer_acceptance_verified"] is False

    instance.context_authority.publish(
        "tenant-a",
        agents.GovernanceContextItem(
            item_id="metric-a",
            source_kind="metric",
            source_ref="metric-a",
            source_revision=1,
            collected_at=10_000.0,
            content=b"bounded metric projection",
        ),
    )
    after = instance.readiness("tenant-a")
    assert after["analysis_ready"] is True
    assert after["context_source_kinds"] == ["metric"]
    assert after["adapter_authorities_verified"] == 1
    assert after["dispatcher_authorities_verified"] == 1


def test_store_factory_rejects_principal_snapshot_and_tenant_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = build_composition(tmp_path, monkeypatch)
    principal = composition.governance_agent_principal_ref(
        "tenant-a", "user:publisher"
    )
    drifted_principal = composition.governance_agent_principal_ref(
        "tenant-a", "user:reviewer-a"
    )
    with pytest.raises(
        agents.GovernanceAgentPermissionDenied,
        match="principal changed",
    ):
        store = instance.store_factory(
            tenant_id="tenant-a",
            principal_ref=principal,
            principal_resolver=lambda: drifted_principal,
            tenant_snapshot_resolver=instance.tenant_snapshot,
        )
        store.verify_integrity("tenant-a")

    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="snapshot changed",
    ):
        instance.store_factory(
            tenant_id="tenant-a",
            principal_ref=principal,
            principal_resolver=lambda: principal,
            tenant_snapshot_resolver=lambda _tenant: snapshot_for(
                "tenant-a", enabled_agents=("breach_response",)
            ),
        )


def test_disabled_agent_binding_is_not_constructed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    instance = build_composition(
        tmp_path,
        monkeypatch,
        enabled_agents=("program_copilot",),
    )
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="disabled by tenant configuration",
    ):
        instance.resolve_adapter("tenant-a", "breach_response")
    assert instance._states == {}


def test_reference_binding_policy_rejects_unbounded_or_non_operational_roles() -> None:
    with pytest.raises(composition.GovernanceAgentsCompositionError):
        composition.ReferenceBindingPolicy(authority_lifetime_seconds=1)
    with pytest.raises(composition.GovernanceAgentsCompositionError):
        composition.ReferenceBindingPolicy(approver_roles=("admin", "auditor"))
    with pytest.raises(composition.GovernanceAgentsCompositionError):
        composition.ReferenceBindingPolicy(approver_roles=("admin", "admin"))


def test_invalid_existing_install_marker_fails_closed() -> None:
    app = SimpleNamespace(state=SimpleNamespace(governance_agents_reference_composition=object()))
    with pytest.raises(
        composition.GovernanceAgentsCompositionError,
        match="marker is invalid",
    ):
        composition.install_governance_agents_composition(app)
