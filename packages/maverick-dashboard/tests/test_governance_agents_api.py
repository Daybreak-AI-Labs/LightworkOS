from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from maverick import governance_agents as agents
from maverick.budget import Budget
from maverick_dashboard import governance_agents_api as api

API = "/api/v1/governance-agents"


def _principal_ref(subject: str, tenant: str = "tenant-a") -> str:
    digest = hashlib.sha256(
        f"lightwork.governance-agent.identity.v1:{tenant}:user:{subject}".encode()
    ).hexdigest()
    return f"ga-principal-{digest[:32]}"


class Clock:
    value = 1_000.0

    def __call__(self) -> float:
        return self.value


@pytest.fixture
def environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # noqa: C901
    state: dict[str, object] = {
        "enabled": True,
        "tenant": "tenant-a",
        "factory_calls": [],
        "permission_calls": [],
        "dispatch_tokens": [],
        "adapter_calls": [],
        "snapshot_calls": [],
        "maintenance_calls": [],
        "enabled_agents": tuple(sorted(agents.AGENT_KINDS)),
        "limits": agents.GovernanceAgentLimits(retention_seconds=3_600),
    }
    database = tmp_path / "governance-agents.sqlite3"
    clock = Clock()
    analysis_bindings: dict[tuple[str, str], tuple[object, object]] = {}
    execution_bindings: dict[tuple[str, str], tuple[object, object, object]] = {}
    token_vault: dict[tuple[str, str], str] = {}

    def require_enabled() -> None:
        if not state["enabled"]:
            raise agents.GovernanceAgentConfigError("disabled for test")

    monkeypatch.setattr(agents, "require_enabled", require_enabled)
    monkeypatch.setattr(agents, "enabled", lambda: bool(state["enabled"]))
    monkeypatch.setattr(api, "_tenant_id", lambda: str(state["tenant"]))

    def tenant_permission(_request, permission):
        state["permission_calls"].append(("tenant", permission))

    def global_permission(_request, permission):
        state["permission_calls"].append(("global", permission))

    monkeypatch.setattr(api, "require_permission", tenant_permission)
    monkeypatch.setattr(api, "require_global_permission", global_permission)

    app = FastAPI()

    @app.middleware("http")
    async def principal(request: Request, call_next):
        subject = request.headers.get("X-Test-Subject", "owner")
        request.state.principal = SimpleNamespace(principal=f"user:{subject}")
        return await call_next(request)

    def policy_approvers(tenant_id: str, _policy_id: str, _revision: int):
        return (_principal_ref("reviewer-a", tenant_id), _principal_ref("reviewer-b", tenant_id))

    def store_factory(**kwargs):
        state["factory_calls"].append(kwargs)
        return agents.GovernanceAgentStore(
            database,
            config_gate=lambda: None,
            principal_resolver=kwargs["principal_resolver"],
            policy_approver_resolver=kwargs["policy_approver_resolver"],
            analysis_binding_resolver=kwargs["analysis_binding_resolver"],
            execution_binding_resolver=kwargs["execution_binding_resolver"],
            execution_token_escrow=kwargs["execution_token_escrow"],
            execution_token_resolver=kwargs["execution_token_resolver"],
            tenant_snapshot_resolver=kwargs["tenant_snapshot_resolver"],
            clock=clock,
            budget=Budget(max_tool_calls=100),
        )

    def context_resolver(tenant_id: str, references, agent_kind: str):
        assert tenant_id == state["tenant"]
        assert agent_kind == "breach_response"
        return tuple(
            agents.GovernanceContextItem(
                item_id=item["item_id"],
                source_kind=item["source_kind"],
                source_ref=item["source_ref"],
                source_revision=item["source_revision"],
                collected_at=clock.value - 1,
                content=f"server-owned:{item['source_ref']}".encode(),
            )
            for item in references
        )

    def adapter_resolver(_tenant_id: str, agent_kind: str):
        state["adapter_calls"].append((_tenant_id, agent_kind))
        key = (_tenant_id, agent_kind)
        if key in analysis_bindings:
            return analysis_bindings[key]
        authority = agents.build_adapter_authority(
            adapter_id=f"adapter:{agent_kind}",
            revision=1,
            agent_kind=agent_kind,
            implementation_sha256=hashlib.sha256(b"implementation").hexdigest(),
            configuration_sha256=hashlib.sha256(b"configuration").hexdigest(),
            deterministic=True,
            network_access=False,
            legal_conclusion_enabled=False,
            valid_until=clock.value + 600,
        )

        def adapter(**kwargs):
            return agents.GovernanceAgentAnalysis(
                findings=(
                    agents.build_finding(
                        agent_kind=agent_kind,
                        finding_id="finding:one",
                        finding_code=sorted(agents.FINDING_CODES[agent_kind])[0],
                        severity="high",
                        evidence_item_ids=(kwargs["context"][0].item_id,),
                        recommended_action_code=sorted(agents.ACTION_CODES[agent_kind])[0],
                        rationale_code="evidence_sufficient",
                        confidence_bps=8_000,
                    ),
                ),
                limitations=(),
                complete=True,
            )

        analysis_bindings[key] = (authority, adapter)
        return analysis_bindings[key]

    def _proof(material: dict) -> str:
        encoded = json.dumps(
            material,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    def dispatcher_resolver(_tenant_id: str, _agent_kind: str):
        key = (_tenant_id, _agent_kind)
        if key in execution_bindings:
            return execution_bindings[key]
        authority = agents.build_dispatcher_authority(
            dispatcher_id=f"dispatcher:{_agent_kind}",
            revision=1,
            agent_kind=_agent_kind,
            implementation_sha256=hashlib.sha256(b"dispatcher-implementation").hexdigest(),
            configuration_sha256=hashlib.sha256(b"dispatcher-configuration").hexdigest(),
            execution_enabled=True,
            valid_until=clock.value + 600,
        )

        def dispatcher(*, run, idempotency_key):
            state["dispatch_tokens"].append(idempotency_key)
            material = agents.execution_receipt_signing_payload(
                run=run,
                dispatcher_authority=authority,
                outcome="no_change",
                provider_status_code="accepted_no_change",
                external_reference_sha256=None,
                retryable=False,
            )
            return agents.build_execution_outcome(
                run=run,
                dispatcher_authority=authority,
                outcome="no_change",
                provider_status_code="accepted_no_change",
                external_reference_sha256=None,
                retryable=False,
                receipt_proof_sha256=_proof(material),
            )

        def verifier(enrolled_authority, outcome):
            material = asdict(outcome)
            receipt_proof = material.pop("receipt_proof_sha256")
            material.pop("receipt_sha256")
            return enrolled_authority == authority and hmac.compare_digest(
                receipt_proof,
                _proof(material),
            )

        execution_bindings[key] = (authority, dispatcher, verifier)
        return execution_bindings[key]

    def token_escrow(tenant_id: str, run_id: str, token: str, token_sha256: str) -> bool:
        if hashlib.sha256(token.encode()).hexdigest() != token_sha256:
            return False
        key = (tenant_id, run_id)
        prior = token_vault.get(key)
        if prior is not None and prior != token:
            return False
        token_vault[key] = token
        return True

    def token_resolver(tenant_id: str, run_id: str) -> str:
        return token_vault[(tenant_id, run_id)]

    def tenant_snapshot_resolver(tenant_id: str):
        state["snapshot_calls"].append(tenant_id)
        return agents.GovernanceAgentTenantSnapshot(
            tenant_id=tenant_id,
            enabled_agents=tuple(state["enabled_agents"]),
            limits=state["limits"],
        )

    app.state.governance_agent_policy_approver_resolver = policy_approvers
    app.state.governance_agents_store_factory = store_factory
    app.state.governance_agent_context_resolver = context_resolver
    app.state.governance_agent_adapter_resolver = adapter_resolver
    app.state.governance_agent_dispatcher_resolver = dispatcher_resolver
    app.state.governance_agent_execution_token_escrow = token_escrow
    app.state.governance_agent_execution_token_resolver = token_resolver
    app.state.governance_agent_tenant_snapshot_resolver = tenant_snapshot_resolver

    class ReferenceMaintenance:
        def _record(self, name: str, tenant_id: str, *args, **kwargs):
            state["maintenance_calls"].append((name, tenant_id, args, kwargs))

        def readiness(self, tenant_id: str):
            self._record("readiness", tenant_id)
            return {
                "schema": "lightwork.governance-agent.composition-readiness.v1",
                "tenant_id": tenant_id,
                "configured": True,
                "store_integrity_verified": True,
            }

        def rotate_adapter(self, tenant_id: str, agent_kind: str):
            self._record("rotate_adapter", tenant_id, agent_kind)
            return 2

        def revoke_adapter(self, tenant_id: str, agent_kind: str):
            self._record("revoke_adapter", tenant_id, agent_kind)
            return 3

        def rotate_dispatcher(self, tenant_id: str, agent_kind: str):
            self._record("rotate_dispatcher", tenant_id, agent_kind)
            return 4

        def revoke_dispatcher(self, tenant_id: str, agent_kind: str):
            self._record("revoke_dispatcher", tenant_id, agent_kind)
            return 5

        def rotate_custody_key(self, tenant_id: str):
            self._record("rotate_custody_key", tenant_id)
            return "custody:two"

        def retire_custody_key(self, tenant_id: str, revision: str):
            self._record("retire_custody_key", tenant_id, revision)

        def revoke_execution_token(self, tenant_id: str, run_id: str):
            self._record("revoke_execution_token", tenant_id, run_id)
            return True

        def reconcile_execution_tokens(self, tenant_id: str):
            self._record("reconcile_execution_tokens", tenant_id)
            return 6

        def list_internal_intents(self, tenant_id: str, *, limit: int):
            self._record("list_internal_intents", tenant_id, limit=limit)
            return (
                {
                    "schema": "lightwork.governance-agent.internal-intent.v1",
                    "run_id": "run-one",
                    "status": "pending_human_action",
                },
            )

    app.state.governance_agent_reference_maintenance = ReferenceMaintenance()
    app.include_router(api.router, prefix="/api/v1")
    client = TestClient(
        app, base_url="http://127.0.0.1",
        headers={"Origin": "http://127.0.0.1", "X-Test-Subject": "owner"},
    )
    return client, state


def _policy_body(*, execution_enabled: bool = True) -> dict:
    return {
        "revision": 1,
        "agent_kind": "breach_response",
        "allowed_capabilities": [
            "containment_plan",
            "evidence_preservation_plan",
            "incident_triage",
            "notification_draft",
            "regulatory_clock_review",
        ],
        "required_approvals": 2 if execution_enabled else 1,
        "execution_enabled": execution_enabled,
        "approver_principals": [
            _principal_ref("reviewer-a"),
            _principal_ref("reviewer-b"),
        ],
        "valid_until": 1_600.0,
        "idempotency_key": "publish:breach",
    }


def _analysis_body() -> dict:
    return {
        "policy_id": "breach",
        "policy_revision": 1,
        "capability": "containment_plan",
        "context": [
            {
                "item_id": "evidence:one",
                "source_kind": "incident",
                "source_ref": "incident:one",
                "source_revision": 1,
            }
        ],
        "idempotency_key": "analysis:one",
    }


def _publish_and_analyze(client: TestClient):
    published = client.put(f"{API}/policies/breach", json=_policy_body())
    assert published.status_code == 200, published.text
    analyzed = client.put(f"{API}/runs/run-one/analysis", json=_analysis_body())
    assert analyzed.status_code == 200, analyzed.text
    return analyzed.json()


def test_status_is_honest_store_free_and_feature_off_is_denied(environment):
    client, state = environment
    response = client.get(f"{API}/status")
    assert response.status_code == 200
    status = response.json()
    assert status["execution_default_off"] is True
    assert status["raw_context_accepted_over_http"] is False
    assert status["caller_selected_adapters"] is False
    assert status["live_provider_acceptance_verified"] is False
    composition = status["composition"]
    assert composition["assessment"] == "configured_for_attempt_only"
    assert composition["status_opened_store"] is False
    assert composition["operational_verification_performed"] is False
    assert composition["principal_available"] is True
    assert all(composition["server_seams_callable"].values())
    assert all(composition["operations_configured_for_attempt"].values())
    assert not any(composition["operations_operationally_verified"].values())
    assert state["factory_calls"] == []
    assert state["snapshot_calls"] == []
    assert state["adapter_calls"] == []

    state["enabled"] = False
    disabled = client.get(f"{API}/status").json()
    assert disabled["enabled"] is False
    assert not any(
        disabled["composition"]["operations_configured_for_attempt"].values()
    )
    assert client.get(f"{API}/runs/anything").status_code == 403


def test_status_reports_missing_seams_without_invoking_or_echoing_them(environment):
    client, state = environment
    client.app.state.governance_agent_adapter_resolver = object()
    client.app.state.governance_agent_dispatcher_resolver = object()

    response = client.get(f"{API}/status")

    assert response.status_code == 200
    composition = response.json()["composition"]
    assert composition["server_seams_callable"]["analysis_adapter"] is False
    assert composition["server_seams_callable"]["execution_dispatcher"] is False
    operations = composition["operations_configured_for_attempt"]
    assert operations["analysis"] is False
    assert operations["execution"] is False
    assert operations["recovery"] is False
    assert operations["run_read"] is True
    assert state["factory_calls"] == []
    assert state["snapshot_calls"] == []
    assert state["adapter_calls"] == []
    assert "object at" not in response.text


def test_retention_route_uses_coordinated_reference_state_runner(environment):
    client, state = environment
    calls: list[tuple[str, object, int]] = []

    def purge_runner(tenant_id: str, *, store: object, limit: int):
        calls.append((tenant_id, store, limit))
        return {
            "schema": "lightwork.governance-agent.coordinated-retention.v1",
            "purged": 2,
            "sealed_tokens_purged": 2,
            "internal_intents_purged": 1,
        }

    client.app.state.governance_agent_retention_runner = purge_runner
    response = client.post(f"{API}/retention/purge", json={"limit": 23})

    assert response.status_code == 200, response.text
    assert response.json() == {
        "schema": "lightwork.governance-agent.coordinated-retention.v1",
        "purged": 2,
        "sealed_tokens_purged": 2,
        "internal_intents_purged": 1,
    }
    assert len(calls) == 1
    assert calls[0][0] == "tenant-a"
    assert calls[0][2] == 23
    assert calls[0][1] is not None
    assert state["permission_calls"][-1] == ("global", "admin")


@pytest.mark.parametrize(
    ("path", "method_name", "operation"),
    [
        (
            "/maintenance/adapters/breach_response/rotate",
            "rotate_adapter",
            "adapter_rotated",
        ),
        (
            "/maintenance/adapters/breach_response/revoke",
            "revoke_adapter",
            "adapter_revoked",
        ),
        (
            "/maintenance/dispatchers/breach_response/rotate",
            "rotate_dispatcher",
            "dispatcher_rotated",
        ),
        (
            "/maintenance/dispatchers/breach_response/revoke",
            "revoke_dispatcher",
            "dispatcher_revoked",
        ),
        (
            "/maintenance/custody/rotate",
            "rotate_custody_key",
            "custody_key_rotated",
        ),
        (
            "/maintenance/custody/custody:one/retire",
            "retire_custody_key",
            "custody_key_retired",
        ),
        (
            "/maintenance/tokens/run-one/revoke",
            "revoke_execution_token",
            "execution_token_revoked",
        ),
        (
            "/maintenance/tokens/reconcile",
            "reconcile_execution_tokens",
            "execution_tokens_reconciled",
        ),
    ],
)
def test_reference_maintenance_mutations_are_admin_tenant_derived(
    environment,
    path: str,
    method_name: str,
    operation: str,
):
    client, state = environment

    response = client.post(f"{API}{path}", json={})

    assert response.status_code == 200, response.text
    assert response.json()["operation"] == operation
    assert state["maintenance_calls"][0][0:2] == (method_name, "tenant-a")
    assert state["permission_calls"][-1] == ("global", "admin")


def test_reference_maintenance_readiness_and_intents_are_bounded(environment):
    client, state = environment

    readiness = client.get(f"{API}/maintenance/readiness")
    intents = client.get(f"{API}/maintenance/intents?limit=17")

    assert readiness.status_code == 200, readiness.text
    assert readiness.json()["tenant_id"] == "tenant-a"
    assert intents.status_code == 200, intents.text
    assert intents.json()["items"][0]["run_id"] == "run-one"
    assert state["maintenance_calls"] == [
        ("readiness", "tenant-a", (), {}),
        ("list_internal_intents", "tenant-a", (), {"limit": 17}),
    ]
    assert state["permission_calls"][-2:] == [
        ("global", "admin"),
        ("global", "audit"),
    ]


def test_reference_maintenance_rejects_unknown_agent_and_body_fields(environment):
    client, state = environment

    unknown = client.post(
        f"{API}/maintenance/adapters/not_an_agent/rotate",
        json={},
    )
    spoofed = client.post(
        f"{API}/maintenance/custody/rotate",
        json={"tenant_id": "forged"},
    )

    assert unknown.status_code == 422
    assert spoofed.status_code == 422
    assert state["maintenance_calls"] == []


@pytest.mark.parametrize("field", ["tenant", "tenant_id", "actor", "adapter_id"])
def test_strict_bodies_reject_authority_spoofing(environment, field):
    client, _state = environment
    response = client.put(
        f"{API}/policies/breach",
        json={**_policy_body(), field: "forged"},
    )
    assert response.status_code == 422


def test_policy_approvers_must_match_server_authority(environment):
    client, _state = environment
    body = _policy_body()
    body["approver_principals"] = ["fake-a", "fake-b"]
    response = client.put(f"{API}/policies/breach", json=body)
    assert response.status_code == 403
    assert "independent authority" in response.json()["detail"]


def test_analysis_uses_server_context_and_adapter(environment):
    client, state = environment
    run = _publish_and_analyze(client)
    assert run["state"] == "pending_review"
    expected = hashlib.sha256(b"server-owned:incident:one").hexdigest()
    assert run["context"][0]["content_sha256"] == expected
    assert run["findings"][0]["evidence_item_ids"] == ["evidence:one"]
    assert state["permission_calls"][-1] == ("tenant", "operate")


def test_only_enrolled_reviewers_can_approve_and_two_are_required(environment):
    client, _state = environment
    run = _publish_and_analyze(client)
    denied = client.post(
        f"{API}/runs/run-one/review",
        headers={"X-Test-Subject": "outsider"},
        json={
            "expected_revision": run["revision"],
            "decision": "approve",
            "rationale_code": "evidence_sufficient",
        },
    )
    assert denied.status_code == 403
    assert "not enrolled" in denied.json()["detail"]

    first = client.post(
        f"{API}/runs/run-one/review",
        headers={"X-Test-Subject": "reviewer-a"},
        json={
            "expected_revision": run["revision"],
            "decision": "approve",
            "rationale_code": "evidence_sufficient",
        },
    )
    assert first.status_code == 200
    assert first.json()["state"] == "pending_review"
    second = client.post(
        f"{API}/runs/run-one/review",
        headers={"X-Test-Subject": "reviewer-b"},
        json={
            "expected_revision": first.json()["revision"],
            "decision": "approve",
            "rationale_code": "policy_threshold",
        },
    )
    assert second.status_code == 200
    assert second.json()["state"] == "approved"


def test_execution_uses_server_dispatcher_and_integrity_is_queryable(environment):
    client, state = environment
    run = _publish_and_analyze(client)
    for subject, rationale in (
        ("reviewer-a", "evidence_sufficient"),
        ("reviewer-b", "policy_threshold"),
    ):
        response = client.post(
            f"{API}/runs/run-one/review",
            headers={"X-Test-Subject": subject},
            json={
                "expected_revision": run["revision"],
                "decision": "approve",
                "rationale_code": rationale,
            },
        )
        assert response.status_code == 200, response.text
        run = response.json()
    executed = client.post(
        f"{API}/runs/run-one/execute",
        json={"expected_revision": run["revision"]},
    )
    assert executed.status_code == 200, executed.text
    assert executed.json()["state"] == "executed"
    assert executed.json()["execution_outcome"]["outcome"] == "no_change"
    assert len(state["dispatch_tokens"]) == 1

    integrity = client.get(f"{API}/integrity")
    assert integrity.status_code == 200
    assert integrity.json()["valid"] is True
    assert integrity.json()["verified_runs"] == 1


def test_tenant_isolation_and_no_raw_context_field(environment):
    client, state = environment
    _publish_and_analyze(client)
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/runs/run-one").status_code == 404

    state["tenant"] = "tenant-a"
    body = _analysis_body()
    body["context"][0]["content"] = "forged raw bytes"
    assert client.put(f"{API}/runs/run-two/analysis", json=body).status_code == 422


@pytest.mark.parametrize(
    "dependency",
    ["store_for", "tenant_snapshot_for", "context_resolver"],
)
def test_dependencies_reject_non_callable_authority_seams(dependency):
    with pytest.raises(TypeError, match=rf"{dependency} must be callable"):
        api.GovernanceAgentDependencies(**{dependency: object()})


def test_store_factory_signature_failure_is_sanitized_as_unavailable(environment):
    client, _state = environment

    def incompatible_factory(_only_one_argument):
        raise AssertionError("the incompatible factory must not be entered")

    client.app.state.governance_agents_store_factory = incompatible_factory
    response = client.get(f"{API}/runs")
    assert response.status_code == 503
    assert response.json() == {"detail": "governance-agent store is unavailable"}
    assert "only_one_argument" not in response.text


def test_recovery_resolver_outage_matches_execute_failure_mapping(environment):
    client, _state = environment
    run = _publish_and_analyze(client)

    def unavailable_dispatcher_resolver(_tenant_id: str, _agent_kind: str):
        raise RuntimeError("private dispatcher topology")

    client.app.state.governance_agent_dispatcher_resolver = (
        unavailable_dispatcher_resolver
    )
    response = client.post(
        f"{API}/runs/run-one/recover",
        json={"expected_revision": run["revision"]},
    )
    assert response.status_code == 503
    assert response.json() == {
        "detail": "governance-agent recovery composition is unavailable"
    }
    assert "private dispatcher topology" not in response.text


def test_status_allows_only_genuine_auth_off_without_mutation_authority(
    monkeypatch: pytest.MonkeyPatch,
):
    auth_off = {"allowed": True}
    monkeypatch.setattr(api, "_tenant_id", lambda: "tenant-a")
    monkeypatch.setattr(api, "_enabled", lambda: True)
    monkeypatch.setattr(agents, "require_enabled", lambda: None)
    monkeypatch.setattr(api, "require_permission", lambda _request, _permission: None)
    monkeypatch.setattr(
        api,
        "require_global_permission",
        lambda _request, _permission: None,
    )
    monkeypatch.setattr(
        api,
        "anonymous_local_access_allowed",
        lambda: auth_off["allowed"],
    )
    app = FastAPI()
    app.include_router(api.create_governance_agents_router(), prefix="/api/v1")
    client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

    status = client.get(f"{API}/status")
    assert status.status_code == 200
    assert status.json()["principal_ref"] is None
    composition = status.json()["composition"]
    assert composition["principal_available"] is False
    assert not any(composition["operations_configured_for_attempt"].values())
    assert client.put(
        f"{API}/policies/breach",
        json=_policy_body(),
    ).status_code == 401

    auth_off["allowed"] = False
    assert client.get(f"{API}/status").status_code == 401


def test_changed_agent_allowlist_blocks_adapter_resolution_for_existing_policy(
    environment,
):
    client, state = environment
    published = client.put(f"{API}/policies/breach", json=_policy_body())
    assert published.status_code == 200, published.text
    state["enabled_agents"] = ("third_party_risk",)

    response = client.put(f"{API}/runs/run-one/analysis", json=_analysis_body())
    assert response.status_code == 403
    assert response.json()["detail"] == (
        "governance-agent kind is disabled by tenant configuration"
    )
    assert state["adapter_calls"] == []


def test_lower_tenant_item_limit_blocks_context_and_adapter_resolution(environment):
    client, state = environment
    state["limits"] = agents.GovernanceAgentLimits(
        max_context_items=1,
        retention_seconds=3_600,
    )
    published = client.put(f"{API}/policies/breach", json=_policy_body())
    assert published.status_code == 200, published.text
    body = _analysis_body()
    body["context"].append(
        {
            "item_id": "evidence:two",
            "source_kind": "incident",
            "source_ref": "incident:two",
            "source_revision": 1,
        }
    )

    response = client.put(f"{API}/runs/run-one/analysis", json=body)
    assert response.status_code == 422
    assert response.json()["detail"] == "context is outside its tenant item bound"
    assert state["adapter_calls"] == []


def test_policy_list_is_view_scoped_and_tenant_isolated(environment):
    client, state = environment
    _publish_and_analyze(client)
    listed = client.get(f"{API}/policies")
    assert listed.status_code == 200, listed.text
    items = listed.json()["items"]
    assert [item["policy_id"] for item in items] == ["breach"]
    assert items[0]["agent_kind"] == "breach_response"
    state["tenant"] = "tenant-b"
    assert client.get(f"{API}/policies").json()["items"] == []
