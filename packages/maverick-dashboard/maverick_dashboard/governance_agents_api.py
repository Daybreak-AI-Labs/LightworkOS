"""Strict HTTP composition for packaged governance agents.

The API never accepts tenant identifiers, actor identities, raw context bytes,
adapter authorities, execution credentials, or dispatch destinations from the
request body.  Those authorities are independently resolved by the deployed
application.  Consequently a caller can request analysis or execution, but
cannot choose the evidence bytes, model/adapter, provider transport, or runtime
principal that authorizes it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import (
    _dashboard_token_authenticated,
    anonymous_local_access_allowed,
    require_global_permission,
    require_permission,
)

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
AgentKind = Literal[
    "breach_response",
    "privacy_risk_assessment",
    "program_copilot",
    "knowledgebase_governance",
    "third_party_risk",
]
PolicyApproverResolver = Callable[[str, str, int], Sequence[str]]
AnalysisBindingResolver = Callable[[str, str], Any]
ExecutionBindingResolver = Callable[[str, str], Any]
ExecutionTokenEscrow = Callable[[str, str, str, str], bool]
ExecutionTokenResolver = Callable[[str, str], str]
TenantSnapshotResolver = Callable[[str], Any]
ContextResolver = Callable[[str, Sequence[Mapping[str, object]], str], Any]
StoreFor = Callable[
    [
        str,
        str,
        PolicyApproverResolver | None,
        AnalysisBindingResolver | None,
        ExecutionBindingResolver | None,
        ExecutionTokenEscrow | None,
        ExecutionTokenResolver | None,
        TenantSnapshotResolver,
    ],
    Any,
]
_STORE_METHODS = (
    "publish_policy",
    "revoke_policy",
    "get_policy",
    "submit_run",
    "get_run",
    "list_runs",
    "review",
    "execute",
    "recover_execution",
    "revoke_run",
    "purge_expired",
    "verify_integrity",
)
_REFERENCE_MAINTENANCE_METHODS = (
    "readiness",
    "rotate_adapter",
    "revoke_adapter",
    "rotate_dispatcher",
    "revoke_dispatcher",
    "rotate_custody_key",
    "retire_custody_key",
    "revoke_execution_token",
    "reconcile_execution_tokens",
    "list_internal_intents",
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PolicyPublishIn(_StrictModel):
    revision: int = Field(ge=1, le=2_147_483_647)
    agent_kind: AgentKind
    allowed_capabilities: list[OpaqueId] = Field(min_length=1, max_length=32)
    required_approvals: int = Field(ge=1, le=8)
    execution_enabled: bool = False
    approver_principals: list[OpaqueId] = Field(min_length=2, max_length=8)
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class PolicyRevokeIn(_StrictModel):
    revision: int = Field(ge=1, le=2_147_483_647)
    reason_code: Literal[
        "evidence_sufficient",
        "evidence_partial",
        "evidence_conflicting",
        "evidence_stale",
        "authority_required",
        "policy_threshold",
        "human_override",
        "false_positive",
        "risk_accepted",
        "not_applicable",
    ]


class ContextReferenceIn(_StrictModel):
    item_id: OpaqueId
    source_kind: Literal[
        "audit",
        "assessment",
        "control",
        "document",
        "incident",
        "inventory",
        "knowledge",
        "metric",
        "policy",
        "provider_signal",
        "risk",
        "vendor",
    ]
    source_ref: OpaqueId
    source_revision: int = Field(ge=1, le=2_147_483_647)


class AnalyzeRunIn(_StrictModel):
    policy_id: OpaqueId
    policy_revision: int = Field(ge=1, le=2_147_483_647)
    capability: OpaqueId
    context: list[ContextReferenceIn] = Field(min_length=1, max_length=1_000)
    idempotency_key: IdempotencyKey


class ReviewRunIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2_147_483_647)
    decision: Literal["approve", "reject"]
    rationale_code: Literal[
        "evidence_sufficient",
        "evidence_partial",
        "evidence_conflicting",
        "evidence_stale",
        "authority_required",
        "policy_threshold",
        "human_override",
        "false_positive",
        "risk_accepted",
        "not_applicable",
    ]


class ExpectedRevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2_147_483_647)


class RevokeRunIn(ExpectedRevisionIn):
    reason_code: Literal[
        "evidence_sufficient",
        "evidence_partial",
        "evidence_conflicting",
        "evidence_stale",
        "authority_required",
        "policy_threshold",
        "human_override",
        "false_positive",
        "risk_accepted",
        "not_applicable",
    ]


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, ge=1, le=1_000)


class EmptyIn(_StrictModel):
    pass


def _enabled() -> bool:
    from maverick import governance_agents as ops

    return ops.enabled()


def governance_agents_enabled_for_page() -> bool:
    """Read only the feature gate; do not construct stores or adapters."""

    return _enabled()


def _ops():
    from maverick import governance_agents as ops

    try:
        ops.require_enabled()
    except ops.GovernanceAgentConfigError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return ops


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using governance agents",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    verified = getattr(request.state, "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if not isinstance(subject, str) or not subject:
        raise HTTPException(
            status_code=401,
            detail="an authenticated principal is required for governance agents",
        )
    digest = hashlib.sha256(
        (f"lightwork.governance-agent.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"ga-principal-{digest[:32]}"


def _status_principal(request: Request, tenant_id: str) -> str | None:
    """Return a verified status identity or the genuine auth-off sentinel."""

    try:
        return _principal(request, tenant_id)
    except HTTPException as exc:
        if exc.status_code == 401 and (
            anonymous_local_access_allowed() or _dashboard_token_authenticated(request)
        ):
            return None
        raise


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _default_store_for(
    tenant_id: str,
    principal_ref: str,
    policy_approver_resolver: PolicyApproverResolver | None,
    analysis_binding_resolver: AnalysisBindingResolver | None,
    execution_binding_resolver: ExecutionBindingResolver | None,
    execution_token_escrow: ExecutionTokenEscrow | None,
    execution_token_resolver: ExecutionTokenResolver | None,
    tenant_snapshot_resolver: TenantSnapshotResolver,
):
    from maverick.governance_agents import GovernanceAgentStore
    from maverick.paths import data_dir

    return GovernanceAgentStore(
        data_dir("governance_agents", "governance-agents.sqlite3", tenant=tenant_id),
        principal_resolver=lambda: principal_ref,
        policy_approver_resolver=policy_approver_resolver,
        analysis_binding_resolver=analysis_binding_resolver,
        execution_binding_resolver=execution_binding_resolver,
        execution_token_escrow=execution_token_escrow,
        execution_token_resolver=execution_token_resolver,
        tenant_snapshot_resolver=tenant_snapshot_resolver,
    )


def _default_tenant_snapshot_for(tenant_id: str):
    from maverick.governance_agents import load_governance_agent_tenant_snapshot

    return load_governance_agent_tenant_snapshot(tenant_id)


class GovernanceAgentDependencies:
    """Server-owned authority seams for evidence, adapters, and dispatch."""

    def __init__(
        self,
        *,
        store_for: StoreFor = _default_store_for,
        tenant_snapshot_for: TenantSnapshotResolver = _default_tenant_snapshot_for,
        context_resolver: ContextResolver | None = None,
        adapter_resolver: AnalysisBindingResolver | None = None,
        dispatcher_resolver: ExecutionBindingResolver | None = None,
        execution_token_escrow: ExecutionTokenEscrow | None = None,
        execution_token_resolver: ExecutionTokenResolver | None = None,
    ) -> None:
        required = {
            "store_for": store_for,
            "tenant_snapshot_for": tenant_snapshot_for,
        }
        optional = {
            "context_resolver": context_resolver,
            "adapter_resolver": adapter_resolver,
            "dispatcher_resolver": dispatcher_resolver,
            "execution_token_escrow": execution_token_escrow,
            "execution_token_resolver": execution_token_resolver,
        }
        invalid = [name for name, value in required.items() if not callable(value)]
        invalid.extend(
            name
            for name, value in optional.items()
            if value is not None and not callable(value)
        )
        if invalid:
            raise TypeError(f"{sorted(invalid)[0]} must be callable")
        self.store_for = store_for
        self.tenant_snapshot_for = tenant_snapshot_for
        self.context_resolver = context_resolver
        self.adapter_resolver = adapter_resolver
        self.dispatcher_resolver = dispatcher_resolver
        self.execution_token_escrow = execution_token_escrow
        self.execution_token_resolver = execution_token_resolver


def create_governance_agents_router(  # noqa: C901 - explicit endpoint trust boundaries
    dependencies: GovernanceAgentDependencies | None = None,
) -> APIRouter:
    deps = dependencies or GovernanceAgentDependencies()
    router = APIRouter(prefix="/governance-agents", tags=["governance-agents"])

    def authority(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(request.app.state, "governance_agents_store_factory", None)
        snapshot_source = getattr(
            request.app.state,
            "governance_agent_tenant_snapshot_resolver",
            deps.tenant_snapshot_for,
        )
        policy_resolver = getattr(
            request.app.state, "governance_agent_policy_approver_resolver", None
        )
        analysis_resolver = getattr(
            request.app.state,
            "governance_agent_adapter_resolver",
            deps.adapter_resolver,
        )
        execution_resolver = getattr(
            request.app.state,
            "governance_agent_dispatcher_resolver",
            deps.dispatcher_resolver,
        )
        token_escrow = getattr(
            request.app.state,
            "governance_agent_execution_token_escrow",
            deps.execution_token_escrow,
        )
        token_resolver = getattr(
            request.app.state,
            "governance_agent_execution_token_resolver",
            deps.execution_token_resolver,
        )

        def resolver() -> str:
            return principal

        try:
            if factory is not None and not callable(factory):
                raise TypeError("governance-agent store factory is not callable")
            if not callable(snapshot_source):
                raise TypeError("governance-agent tenant snapshot resolver is not callable")
            snapshot = snapshot_source(tenant)
            if not isinstance(snapshot, ops.GovernanceAgentTenantSnapshot):
                raise TypeError("governance-agent tenant snapshot is invalid")
            if snapshot.tenant_id != tenant:
                raise ops.GovernanceAgentConfigError(
                    "governance-agent tenant snapshot is misbound"
                )

            def bound_snapshot_resolver(requested_tenant: str):
                if requested_tenant != tenant:
                    raise ops.GovernanceAgentConfigError(
                        "governance-agent tenant snapshot is misbound"
                    )
                return snapshot

            store = (
                factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=resolver,
                    policy_approver_resolver=policy_resolver,
                    analysis_binding_resolver=analysis_resolver,
                    execution_binding_resolver=execution_resolver,
                    execution_token_escrow=token_escrow,
                    execution_token_resolver=token_resolver,
                    tenant_snapshot_resolver=bound_snapshot_resolver,
                    request=request,
                )
                if callable(factory)
                else deps.store_for(
                    tenant,
                    principal,
                    policy_resolver,
                    analysis_resolver,
                    execution_resolver,
                    token_escrow,
                    token_resolver,
                    bound_snapshot_resolver,
                )
            )
            if store is None or any(
                not callable(getattr(store, method, None)) for method in _STORE_METHODS
            ):
                raise TypeError("governance-agent store contract is invalid")
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="governance-agent store is unavailable"
            ) from exc
        return ops, tenant, principal, store, snapshot

    def require_agent_enabled(snapshot, agent_kind: str) -> None:
        if agent_kind not in snapshot.enabled_agents:
            raise HTTPException(
                status_code=403,
                detail="governance-agent kind is disabled by tenant configuration",
            )

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.GovernanceAgentNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ops.GovernanceAgentPermissionDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.GovernanceAgentConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ops.GovernanceAgentValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except ops.GovernanceAgentConfigError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except ops.GovernanceAgentIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="governance-agent integrity verification failed",
            ) from exc
        except ops.GovernanceAgentError as exc:
            raise HTTPException(
                status_code=503, detail="governance-agent operation failed"
            ) from exc

    def context_resolver(request: Request):
        return getattr(
            request.app.state,
            "governance_agent_context_resolver",
            deps.context_resolver,
        )

    def adapter_resolver(request: Request):
        return getattr(
            request.app.state,
            "governance_agent_adapter_resolver",
            deps.adapter_resolver,
        )

    def dispatcher_resolver(request: Request):
        return getattr(
            request.app.state,
            "governance_agent_dispatcher_resolver",
            deps.dispatcher_resolver,
        )

    def composition_status(
        request: Request,
        *,
        feature_enabled: bool,
        principal_available: bool,
    ) -> dict[str, Any]:
        """Describe callable seams without invoking them or opening a store.

        Callability is only a conservative preflight signal.  A callable may
        still fail, reject the active tenant, or point at an unavailable
        provider when an operation is attempted, so this status must never be
        presented as health, readiness, or acceptance evidence.
        """

        state = request.app.state

        def configured(name: str, fallback: Any = None) -> bool:
            return callable(getattr(state, name, fallback))

        store_override = getattr(state, "governance_agents_store_factory", None)
        maintenance = getattr(
            state,
            "governance_agent_reference_maintenance",
            None,
        )
        maintenance_methods = {
            name: callable(getattr(maintenance, name, None))
            for name in _REFERENCE_MAINTENANCE_METHODS
        }
        seams = {
            "store": callable(
                deps.store_for if store_override is None else store_override
            ),
            "tenant_snapshot": configured(
                "governance_agent_tenant_snapshot_resolver",
                deps.tenant_snapshot_for,
            ),
            "policy_approvers": configured(
                "governance_agent_policy_approver_resolver"
            ),
            "context": configured(
                "governance_agent_context_resolver",
                deps.context_resolver,
            ),
            "analysis_adapter": configured(
                "governance_agent_adapter_resolver",
                deps.adapter_resolver,
            ),
            "execution_dispatcher": configured(
                "governance_agent_dispatcher_resolver",
                deps.dispatcher_resolver,
            ),
            "execution_token_escrow": configured(
                "governance_agent_execution_token_escrow",
                deps.execution_token_escrow,
            ),
            "execution_token_resolver": configured(
                "governance_agent_execution_token_resolver",
                deps.execution_token_resolver,
            ),
            "reference_maintenance": all(maintenance_methods.values()),
        }
        core = (
            feature_enabled
            and principal_available
            and seams["store"]
            and seams["tenant_snapshot"]
        )
        execution = (
            core
            and seams["execution_dispatcher"]
            and seams["execution_token_escrow"]
            and seams["execution_token_resolver"]
        )
        operations = {
            "policy_publish": core and seams["policy_approvers"],
            "policy_revoke": core,
            "analysis": core and seams["context"] and seams["analysis_adapter"],
            "run_read": core,
            "review": core,
            "execution": execution,
            "recovery": execution,
            "run_revoke": core,
            "retention_purge": core,
            "integrity": core,
            "maintenance_readiness": core and maintenance_methods["readiness"],
            "maintenance_bindings": core
            and all(
                maintenance_methods[name]
                for name in (
                    "rotate_adapter",
                    "revoke_adapter",
                    "rotate_dispatcher",
                    "revoke_dispatcher",
                )
            ),
            "maintenance_custody": core
            and all(
                maintenance_methods[name]
                for name in (
                    "rotate_custody_key",
                    "retire_custody_key",
                    "revoke_execution_token",
                    "reconcile_execution_tokens",
                )
            ),
            "maintenance_intents": core
            and maintenance_methods["list_internal_intents"],
        }
        return {
            "assessment": "configured_for_attempt_only",
            "status_opened_store": False,
            "operational_verification_performed": False,
            "principal_available": principal_available,
            "server_seams_callable": seams,
            "operations_configured_for_attempt": operations,
            "operations_operationally_verified": dict.fromkeys(operations, False),
        }

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        principal_ref = _status_principal(request, tenant)
        feature_enabled = _enabled()
        return {
            "schema": "lightwork.governance-agent-status.v1",
            "enabled": feature_enabled,
            "principal_ref": principal_ref,
            "packaged_agents": [
                "breach_response",
                "knowledgebase_governance",
                "privacy_risk_assessment",
                "program_copilot",
                "third_party_risk",
            ],
            "raw_context_accepted_over_http": False,
            "caller_selected_adapters": False,
            "caller_selected_dispatchers": False,
            "execution_default_off": True,
            "durable_execution_token_vault_required": True,
            "human_review_required": True,
            "live_provider_acceptance_verified": False,
            "licensed_content_corpus_bundled": False,
            "composition": composition_status(
                request,
                feature_enabled=feature_enabled,
                principal_available=principal_ref is not None,
            ),
        }

    @router.put("/policies/{policy_id}")
    async def publish_policy(request: Request, policy_id: ObjectPath, body: PolicyPublishIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store, snapshot = authority(request)
        require_agent_enabled(snapshot, body.agent_kind)
        return _jsonable(
            await call(
                ops,
                store.publish_policy,
                tenant,
                policy_id=policy_id,
                **body.model_dump(),
            )
        )

    @router.post("/policies/{policy_id}/revoke")
    async def revoke_policy(request: Request, policy_id: ObjectPath, body: PolicyRevokeIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        return _jsonable(
            await call(
                ops,
                store.revoke_policy,
                tenant,
                policy_id,
                **body.model_dump(),
            )
        )

    @router.put("/runs/{run_id}/analysis")
    async def analyze(request: Request, run_id: ObjectPath, body: AnalyzeRunIn):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store, snapshot = authority(request)
        if len(body.context) > snapshot.limits.max_context_items:
            raise HTTPException(
                status_code=422,
                detail="context is outside its tenant item bound",
            )
        policy = await call(
            ops,
            store.get_policy,
            tenant,
            body.policy_id,
            revision=body.policy_revision,
        )
        require_agent_enabled(snapshot, policy.agent_kind)
        resolve_context = context_resolver(request)
        resolve_adapter = adapter_resolver(request)
        if not callable(resolve_context) or not callable(resolve_adapter):
            raise HTTPException(
                status_code=503,
                detail="governance-agent analysis composition is unavailable",
            )
        references = [item.model_dump() for item in body.context]
        resolved_context = await call(
            ops,
            resolve_context,
            tenant,
            references,
            policy.agent_kind,
        )
        resolved_authority, resolved_adapter = await call(
            ops,
            resolve_adapter,
            tenant,
            policy.agent_kind,
        )
        payload = body.model_dump(exclude={"context"})
        return _jsonable(
            await call(
                ops,
                store.submit_run,
                tenant,
                run_id=run_id,
                context=resolved_context,
                adapter_authority=resolved_authority,
                adapter=resolved_adapter,
                **payload,
            )
        )

    @router.get("/policies")
    async def list_policies(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        """This workspace's current policies, for the page's pickers."""
        require_permission(request, "view")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        reader = getattr(store, "list_policies", None)
        if not callable(reader):
            raise HTTPException(
                status_code=503,
                detail="governance-agent policy list is unavailable",
            )
        items = await call(ops, reader, tenant, limit=limit)
        return {"items": _jsonable(items)}

    @router.get("/runs/{run_id}")
    async def get_run(request: Request, run_id: ObjectPath):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        return _jsonable(await call(ops, store.get_run, tenant, run_id))

    @router.get("/runs")
    async def list_runs(
        request: Request,
        state: str | None = Query(default=None, max_length=32),
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_permission(request, "view")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        items = await call(ops, store.list_runs, tenant, state=state, limit=limit)
        return {"items": _jsonable(items)}

    @router.post("/runs/{run_id}/review")
    async def review(request: Request, run_id: ObjectPath, body: ReviewRunIn):
        require_permission(request, "operate")
        ops, tenant, _principal_ref, store, snapshot = authority(request)
        run = await call(ops, store.get_run, tenant, run_id)
        require_agent_enabled(snapshot, run.agent_kind)
        return _jsonable(await call(ops, store.review, tenant, run_id, **body.model_dump()))

    @router.post("/runs/{run_id}/execute")
    async def execute(request: Request, run_id: ObjectPath, body: ExpectedRevisionIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store, snapshot = authority(request)
        resolve_dispatcher = dispatcher_resolver(request)
        if not callable(resolve_dispatcher):
            raise HTTPException(
                status_code=503,
                detail="governance-agent execution composition is unavailable",
            )
        run = await call(ops, store.get_run, tenant, run_id)
        require_agent_enabled(snapshot, run.agent_kind)
        try:
            binding = await run_in_threadpool(resolve_dispatcher, tenant, run.agent_kind)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="governance-agent execution composition is unavailable",
            ) from exc
        if not isinstance(binding, tuple) or len(binding) != 3 or not callable(binding[1]):
            raise HTTPException(
                status_code=503,
                detail="governance-agent execution composition is unavailable",
            )
        dispatcher = binding[1]
        return _jsonable(
            await call(
                ops,
                store.execute,
                tenant,
                run_id,
                dispatcher=dispatcher,
                **body.model_dump(),
            )
        )

    @router.post("/runs/{run_id}/recover")
    async def recover(request: Request, run_id: ObjectPath, body: ExpectedRevisionIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store, snapshot = authority(request)
        resolve_dispatcher = dispatcher_resolver(request)
        if not callable(resolve_dispatcher):
            raise HTTPException(
                status_code=503,
                detail="governance-agent recovery composition is unavailable",
            )
        run = await call(ops, store.get_run, tenant, run_id)
        require_agent_enabled(snapshot, run.agent_kind)
        try:
            binding = await run_in_threadpool(resolve_dispatcher, tenant, run.agent_kind)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="governance-agent recovery composition is unavailable",
            ) from exc
        if not isinstance(binding, tuple) or len(binding) != 3 or not callable(binding[1]):
            raise HTTPException(
                status_code=503,
                detail="governance-agent recovery composition is unavailable",
            )
        dispatcher = binding[1]
        return _jsonable(
            await call(
                ops,
                store.recover_execution,
                tenant,
                run_id,
                dispatcher=dispatcher,
                **body.model_dump(),
            )
        )

    @router.post("/runs/{run_id}/revoke")
    async def revoke_run(request: Request, run_id: ObjectPath, body: RevokeRunIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        return _jsonable(await call(ops, store.revoke_run, tenant, run_id, **body.model_dump()))

    @router.post("/retention/purge")
    async def purge(request: Request, body: PurgeIn):
        require_global_permission(request, "admin")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        runner = getattr(
            request.app.state,
            "governance_agent_retention_runner",
            None,
        )
        if callable(runner):
            result = await call(
                ops,
                runner,
                tenant,
                store=store,
                **body.model_dump(),
            )
            if not isinstance(result, Mapping):
                raise HTTPException(
                    status_code=503,
                    detail="governance-agent retention result is invalid",
                )
            return dict(result)
        return {
            "purged": await call(
                ops,
                store.purge_expired,
                tenant,
                **body.model_dump(),
            ),
            "reference_state_retention_managed": False,
        }

    def reference_maintenance(request: Request):
        maintenance = getattr(
            request.app.state,
            "governance_agent_reference_maintenance",
            None,
        )
        if maintenance is None or any(
            not callable(getattr(maintenance, method, None))
            for method in _REFERENCE_MAINTENANCE_METHODS
        ):
            raise HTTPException(
                status_code=503,
                detail="governance-agent reference maintenance is unavailable",
            )
        return maintenance

    async def maintenance_result(
        request: Request,
        method: str,
        *args: object,
        **kwargs: object,
    ) -> object:
        ops = _ops()
        tenant = _tenant_id()
        target = reference_maintenance(request)
        return await call(ops, getattr(target, method), tenant, *args, **kwargs)

    @router.get("/maintenance/readiness")
    async def maintenance_readiness(request: Request):
        require_global_permission(request, "admin")
        result = await maintenance_result(request, "readiness")
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="governance-agent readiness result is invalid",
            )
        return dict(result)

    @router.post("/maintenance/adapters/{agent_kind}/rotate")
    async def rotate_adapter(request: Request, agent_kind: AgentKind, body: EmptyIn):
        require_global_permission(request, "admin")
        _ = body
        revision = await maintenance_result(request, "rotate_adapter", agent_kind)
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "adapter_rotated",
            "agent_kind": agent_kind,
            "revision": revision,
        }

    @router.post("/maintenance/adapters/{agent_kind}/revoke")
    async def revoke_adapter(request: Request, agent_kind: AgentKind, body: EmptyIn):
        require_global_permission(request, "admin")
        _ = body
        revision = await maintenance_result(request, "revoke_adapter", agent_kind)
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "adapter_revoked",
            "agent_kind": agent_kind,
            "revision": revision,
        }

    @router.post("/maintenance/dispatchers/{agent_kind}/rotate")
    async def rotate_dispatcher(
        request: Request,
        agent_kind: AgentKind,
        body: EmptyIn,
    ):
        require_global_permission(request, "admin")
        _ = body
        revision = await maintenance_result(request, "rotate_dispatcher", agent_kind)
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "dispatcher_rotated",
            "agent_kind": agent_kind,
            "revision": revision,
        }

    @router.post("/maintenance/dispatchers/{agent_kind}/revoke")
    async def revoke_dispatcher(
        request: Request,
        agent_kind: AgentKind,
        body: EmptyIn,
    ):
        require_global_permission(request, "admin")
        _ = body
        revision = await maintenance_result(request, "revoke_dispatcher", agent_kind)
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "dispatcher_revoked",
            "agent_kind": agent_kind,
            "revision": revision,
        }

    @router.post("/maintenance/custody/rotate")
    async def rotate_custody_key(request: Request, body: EmptyIn):
        require_global_permission(request, "admin")
        _ = body
        revision = await maintenance_result(request, "rotate_custody_key")
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "custody_key_rotated",
            "revision": revision,
        }

    @router.post("/maintenance/custody/{revision}/retire")
    async def retire_custody_key(
        request: Request,
        revision: ObjectPath,
        body: EmptyIn,
    ):
        require_global_permission(request, "admin")
        _ = body
        await maintenance_result(request, "retire_custody_key", revision)
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "custody_key_retired",
            "revision": revision,
        }

    @router.post("/maintenance/tokens/{run_id}/revoke")
    async def revoke_execution_token(
        request: Request,
        run_id: ObjectPath,
        body: EmptyIn,
    ):
        require_global_permission(request, "admin")
        _ = body
        revoked = await maintenance_result(request, "revoke_execution_token", run_id)
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "execution_token_revoked",
            "run_id": run_id,
            "revoked": bool(revoked),
        }

    @router.post("/maintenance/tokens/reconcile")
    async def reconcile_execution_tokens(request: Request, body: EmptyIn):
        require_global_permission(request, "admin")
        _ = body
        reconciled = await maintenance_result(request, "reconcile_execution_tokens")
        return {
            "schema": "lightwork.governance-agent.maintenance-result.v1",
            "operation": "execution_tokens_reconciled",
            "reconciled": reconciled,
        }

    @router.get("/maintenance/intents")
    async def list_internal_intents(
        request: Request,
        limit: int = Query(default=100, ge=1, le=1_000),
    ):
        require_global_permission(request, "audit")
        intents = await maintenance_result(
            request,
            "list_internal_intents",
            limit=limit,
        )
        if not isinstance(intents, Sequence) or isinstance(intents, (str, bytes)):
            raise HTTPException(
                status_code=503,
                detail="governance-agent intent result is invalid",
            )
        return {
            "schema": "lightwork.governance-agent.internal-intent-list.v1",
            "items": list(intents),
        }

    @router.get("/integrity")
    async def integrity(request: Request):
        require_global_permission(request, "audit")
        ops, tenant, _principal_ref, store, _snapshot = authority(request)
        result = _jsonable(await call(ops, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_governance_agents_router()

__all__ = [
    "GovernanceAgentDependencies",
    "create_governance_agents_router",
    "governance_agents_enabled_for_page",
    "router",
]
