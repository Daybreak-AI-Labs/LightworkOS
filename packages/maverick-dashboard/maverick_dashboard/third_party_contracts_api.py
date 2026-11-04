"""Strict HTTP adapter for first-class Contract and Engagement lifecycles.

Tenant, actor and exact vendor authority are server-owned.  Callers can select
an enrolled vendor ID/revision and closed lifecycle fields, but cannot inject a
tenant, principal, authority, provider adapter, database path or recovery path.
Sensitive custom values are redacted by default.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import asdict
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StringConstraints,
)
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import has_global_permission, require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
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
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
ContractStatus = Literal[
    "draft", "negotiation", "active", "suspended", "expired", "terminated", "archived"
]
EngagementStatus = Literal[
    "planned", "active", "paused", "completed", "cancelled", "terminated", "archived"
]
FieldType = Literal[
    "boolean",
    "decimal",
    "digest",
    "integer",
    "multi_choice",
    "single_choice",
    "text_ref",
    "timestamp",
]
Sensitivity = Literal["public", "internal", "confidential", "restricted"]
FormulaOperator = Literal[
    "add", "subtract", "multiply", "divide", "minimum", "maximum", "count"
]
CustomValue = StrictBool | StrictInt | StrictFloat | OpaqueId | list[OpaqueId]

_REQUIRED_STORE_METHODS = (
    "create_contract",
    "create_engagement",
    "update_record",
    "archive_record",
    "delete_record",
    "get_record",
    "get_tombstone",
    "list_records",
    "history",
    "verify_integrity",
    "retention_due",
    "purge_expired",
    "create_recovery_backup",
)
_SECURE_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CustomFieldIn(_StrictModel):
    field_id: OpaqueId
    label_ref: OpaqueId
    field_type: FieldType
    required: StrictBool
    sensitivity: Sensitivity
    options: list[OpaqueId] = Field(default_factory=list, max_length=256)


class FormulaOperandIn(_StrictModel):
    source: Literal["field", "literal"]
    field_id: OpaqueId | None = None
    value: StrictInt | StrictFloat | None = None


class FormulaIn(_StrictModel):
    formula_id: OpaqueId
    operator: FormulaOperator
    operands: list[FormulaOperandIn] = Field(min_length=1, max_length=16)
    round_digits: int = Field(default=2, strict=True, ge=0, le=8)


class ContractLifecycleIn(_StrictModel):
    agreement_type: Literal[
        "data_processing",
        "license",
        "master_services",
        "nda",
        "other",
        "statement_of_work",
        "subscription",
    ]
    agreement_ref: OpaqueId
    effective_at: float | None = Field(default=None, strict=True, gt=0)
    expires_at: float | None = Field(default=None, strict=True, gt=0)
    renewal_mode: Literal["none", "manual", "automatic"]
    notice_period_days: int = Field(default=0, strict=True, ge=0, le=3_650)
    governing_law_ref: OpaqueId | None = None
    parent_contract_id: OpaqueId | None = None


class EngagementLifecycleIn(_StrictModel):
    engagement_type: Literal[
        "consulting", "data_processing", "other", "outsourcing", "service", "software"
    ]
    service_category_ref: OpaqueId
    start_at: float | None = Field(default=None, strict=True, gt=0)
    end_at: float | None = Field(default=None, strict=True, gt=0)
    operational_criticality: Literal["low", "medium", "high", "critical"]
    data_access: Literal["none", "metadata", "confidential", "restricted"]
    hosting_model: Literal[
        "none", "vendor_cloud", "customer_cloud", "on_premises", "hybrid"
    ]
    linked_contract_ids: list[OpaqueId] = Field(default_factory=list, max_length=128)
    business_owner_ref: OpaqueId


class _CreateCommon(_StrictModel):
    vendor_id: OpaqueId
    vendor_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    record_id: OpaqueId | None = None
    title_ref: OpaqueId
    owner_ref: OpaqueId
    field_schema: list[CustomFieldIn] = Field(default_factory=list, max_length=128)
    field_values: dict[OpaqueId, CustomValue] = Field(default_factory=dict, max_length=128)
    formulas: list[FormulaIn] = Field(default_factory=list, max_length=64)
    idempotency_key: IdempotencyKey


class CreateContractIn(_CreateCommon):
    status: Literal["draft", "active"] = "draft"
    lifecycle: ContractLifecycleIn


class CreateEngagementIn(_CreateCommon):
    status: Literal["planned", "active"] = "planned"
    lifecycle: EngagementLifecycleIn


class UpdateContractIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    title_ref: OpaqueId | None = None
    owner_ref: OpaqueId | None = None
    status: ContractStatus | None = None
    lifecycle: ContractLifecycleIn | None = None
    field_schema: list[CustomFieldIn] | None = Field(default=None, max_length=128)
    field_values: dict[OpaqueId, CustomValue] | None = Field(default=None, max_length=128)
    formulas: list[FormulaIn] | None = Field(default=None, max_length=64)
    idempotency_key: IdempotencyKey


class UpdateEngagementIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    title_ref: OpaqueId | None = None
    owner_ref: OpaqueId | None = None
    status: EngagementStatus | None = None
    lifecycle: EngagementLifecycleIn | None = None
    field_schema: list[CustomFieldIn] | None = Field(default=None, max_length=128)
    field_values: dict[OpaqueId, CustomValue] | None = Field(default=None, max_length=128)
    formulas: list[FormulaIn] | None = Field(default=None, max_length=64)
    idempotency_key: IdempotencyKey


class RevisionOperationIn(_StrictModel):
    expected_revision: int = Field(strict=True, ge=1, le=2_147_483_647)
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    limit: int = Field(default=100, strict=True, ge=1, le=1_000)


class ThirdPartyContractDependencies:
    """Deployment-owned lifecycle composition seams."""

    def __init__(
        self,
        *,
        store_factory: Callable[..., Any] | None = None,
        enabled_probe: Callable[[str], bool] | None = None,
        readiness_probe: Callable[[str], bool] | None = None,
    ) -> None:
        for dependency in (store_factory, enabled_probe, readiness_probe):
            if dependency is not None and not callable(dependency):
                raise TypeError("Contract lifecycle dependency must be callable")
        self.store_factory = store_factory
        self.enabled_probe = enabled_probe
        self.readiness_probe = readiness_probe


def _ops():
    from maverick import third_party_contracts as contracts

    return contracts


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using Contract and Engagement lifecycle",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for Contract lifecycle",
    )
    digest = hashlib.sha256(
        f"lightwork.third-party-contract.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"contract-principal-{digest[:32]}"


def _dependency(request: Request, state_name: str, fallback: object) -> object:
    try:
        return getattr(request.app.state, state_name)
    except AttributeError:
        return fallback


def _secure(response: Response) -> None:
    for name, value in _SECURE_HEADERS.items():
        response.headers[name] = value


def _jsonable(value: object) -> object:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)  # type: ignore[arg-type]
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def create_third_party_contracts_router(  # noqa: C901, PLR0915
    dependencies: ThirdPartyContractDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ThirdPartyContractDependencies()
    router = APIRouter(
        prefix="/third-party/contracts",
        tags=["third-party-contracts"],
    )

    def probes(request: Request, tenant: str) -> tuple[bool, bool, bool]:
        ops = _ops()
        enabled_probe = _dependency(
            request,
            "third_party_contracts_enabled_probe",
            deps.enabled_probe,
        )
        try:
            feature_enabled = (
                enabled_probe(tenant) if callable(enabled_probe) else ops.enabled()
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle configuration is unavailable",
            ) from exc
        if type(feature_enabled) is not bool:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle configuration is unavailable",
            )
        factory = _dependency(
            request,
            "third_party_contracts_store_factory",
            deps.store_factory,
        )
        readiness_probe = _dependency(
            request,
            "third_party_contracts_readiness_probe",
            deps.readiness_probe,
        )
        configured = callable(factory) and callable(readiness_probe)
        ready = False
        if feature_enabled and configured:
            try:
                ready = readiness_probe(tenant)  # type: ignore[operator]
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Contract lifecycle readiness is unavailable",
                ) from exc
            if type(ready) is not bool:
                raise HTTPException(
                    status_code=503,
                    detail="Contract lifecycle readiness is unavailable",
                )
        return feature_enabled, configured, ready

    async def composition(request: Request):
        ops = _ops()
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(
            probes,
            request,
            tenant,
        )
        if not feature_enabled:
            raise HTTPException(status_code=403, detail="Contract lifecycle is disabled")
        if not configured or ready is not True:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle operational readiness is not verified",
            )
        principal = _principal(request, tenant)
        factory = _dependency(
            request,
            "third_party_contracts_store_factory",
            deps.store_factory,
        )
        try:
            store = await run_in_threadpool(
                factory,  # type: ignore[arg-type]
                tenant_id=tenant,
                principal_ref=principal,
                request=request,
            )
            bound_tenant = store.tenant_id
            contract_valid = all(
                callable(getattr(store, method, None)) for method in _REQUIRED_STORE_METHODS
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle store is unavailable",
            ) from exc
        if bound_tenant != tenant or not contract_valid:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle store is unavailable",
            )
        return ops, tenant, store

    async def call(ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.ThirdPartyContractNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="Contract or Engagement was not found",
            ) from exc
        except ops.ThirdPartyContractPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="Contract lifecycle action is not authorized",
            ) from exc
        except ops.ThirdPartyContractConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Contract lifecycle action conflicts with current authority or state",
            ) from exc
        except ops.ThirdPartyContractValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="Contract lifecycle request is invalid",
            ) from exc
        except ops.ThirdPartyContractIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle integrity verification failed",
            ) from exc
        except ops.ThirdPartyContractConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle dependency is unavailable",
            ) from exc
        except ops.ThirdPartyContractError as exc:
            raise HTTPException(
                status_code=503,
                detail="Contract lifecycle operation failed",
            ) from exc

    def include_sensitive(request: Request, requested: bool) -> bool:
        if requested and not has_global_permission(request, "audit"):
            raise HTTPException(
                status_code=403,
                detail="sensitive Contract fields require global audit authority",
            )
        return requested

    def projection(ops, record, *, sensitive: bool) -> dict[str, object]:
        return ops.redacted_record(record, include_sensitive=sensitive)

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, object]:
        require_permission(request, "view")
        tenant = _tenant_id()
        feature_enabled, configured, ready = await run_in_threadpool(
            probes,
            request,
            tenant,
        )
        _secure(response)
        return {
            "schema": "lightwork.third-party-contract-api-status.v1",
            "enabled": feature_enabled,
            "configured": configured,
            "ready": bool(feature_enabled and configured and ready),
            "configuration": {
                "store_opened_for_status": False,
                "vendor_authority_resolved_for_status": False,
                "store_factory_configured": callable(
                    _dependency(
                        request,
                        "third_party_contracts_store_factory",
                        deps.store_factory,
                    )
                ),
                "readiness_probe_configured": callable(
                    _dependency(
                        request,
                        "third_party_contracts_readiness_probe",
                        deps.readiness_probe,
                    )
                ),
            },
            "record_kinds": ["contract", "engagement"],
            "contract_statuses": sorted(_ops().CONTRACT_STATUSES),
            "engagement_statuses": sorted(_ops().ENGAGEMENT_STATUSES),
            "field_types": sorted(_ops().FIELD_TYPES),
            "formula_operators": sorted(_ops().FORMULA_OPERATORS),
            "caller_tenant_or_actor_fields_accepted": False,
            "vendor_authority_caller_controlled": False,
            "arbitrary_formula_execution_supported": False,
            "raw_documents_stored": False,
            "licensed_template_content_included": False,
            "live_provider_acceptance_verified": False,
        }

    @router.post("/contracts")
    async def create_contract(
        request: Request,
        response: Response,
        body: CreateContractIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        record = await call(
            ops,
            store.create_contract,
            tenant,
            **body.model_dump(mode="python"),
        )
        _secure(response)
        return projection(ops, record, sensitive=False)

    @router.post("/engagements")
    async def create_engagement(
        request: Request,
        response: Response,
        body: CreateEngagementIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        record = await call(
            ops,
            store.create_engagement,
            tenant,
            **body.model_dump(mode="python"),
        )
        _secure(response)
        return projection(ops, record, sensitive=False)

    @router.get("")
    async def list_records(
        request: Request,
        response: Response,
        record_kind: Literal["contract", "engagement"] | None = Query(default=None),
        vendor_id: OpaqueId | None = Query(default=None),
        status_filter: OpaqueId | None = Query(default=None, alias="status"),
        owner_ref: OpaqueId | None = Query(default=None),
        include_sensitive_fields: bool = Query(default=False),
        limit: int = Query(default=100, ge=1, le=1_000),
    ) -> dict[str, object]:
        require_permission(request, "view")
        sensitive = include_sensitive(request, include_sensitive_fields)
        ops, tenant, store = await composition(request)
        records = await call(
            ops,
            store.list_records,
            tenant,
            record_kind=record_kind,
            vendor_id=vendor_id,
            status=status_filter,
            owner_ref=owner_ref,
            limit=limit,
        )
        _secure(response)
        return {
            "schema": "lightwork.third-party-contract-page.v1",
            "items": [projection(ops, record, sensitive=sensitive) for record in records],
            "count": len(records),
            "sensitive_values_included": sensitive,
        }

    @router.get("/operations/integrity")
    async def integrity(request: Request, response: Response) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.verify_integrity, tenant)
        _secure(response)
        return result

    @router.get("/operations/retention-due")
    async def retention_due(
        request: Request,
        response: Response,
        limit: int = Query(default=100, ge=1, le=1_000),
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        records = await call(ops, store.retention_due, tenant, limit=limit)
        _secure(response)
        return {
            "schema": "lightwork.third-party-contract-retention-page.v1",
            "items": [projection(ops, record, sensitive=False) for record in records],
            "count": len(records),
        }

    @router.post("/operations/purge-expired")
    async def purge_expired(
        request: Request,
        response: Response,
        body: PurgeIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        removed = await call(ops, store.purge_expired, tenant, limit=body.limit)
        _secure(response)
        return {
            "schema": "lightwork.third-party-contract-purge-result.v1",
            "removed": removed,
        }

    @router.get("/{record_id}")
    async def get_record(
        request: Request,
        response: Response,
        record_id: ObjectPath,
        include_sensitive_fields: bool = Query(default=False),
    ) -> dict[str, object]:
        require_permission(request, "view")
        sensitive = include_sensitive(request, include_sensitive_fields)
        ops, tenant, store = await composition(request)
        record = await call(ops, store.get_record, tenant, record_id)
        _secure(response)
        return projection(ops, record, sensitive=sensitive)

    async def update(
        request: Request,
        response: Response,
        record_id: str,
        body: UpdateContractIn | UpdateEngagementIn,
        kind: str,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        selected = body.model_fields_set - {"expected_revision", "idempotency_key"}
        if not selected:
            raise HTTPException(status_code=422, detail="Contract lifecycle update is empty")
        changes = {
            name: getattr(body, name).model_dump(mode="python")
            if isinstance(getattr(body, name), BaseModel)
            else [
                item.model_dump(mode="python") if isinstance(item, BaseModel) else item
                for item in getattr(body, name)
            ]
            if isinstance(getattr(body, name), list)
            else getattr(body, name)
            for name in selected
        }
        ops, tenant, store = await composition(request)
        existing = await call(ops, store.get_record, tenant, record_id, record_kind=kind)
        if existing.record_kind != kind:
            raise HTTPException(status_code=404, detail="Contract or Engagement was not found")
        record = await call(
            ops,
            store.update_record,
            tenant,
            record_id,
            expected_revision=body.expected_revision,
            changes=changes,
            idempotency_key=body.idempotency_key,
        )
        _secure(response)
        return projection(ops, record, sensitive=False)

    @router.patch("/contracts/{record_id}")
    async def update_contract(
        request: Request,
        response: Response,
        record_id: ObjectPath,
        body: UpdateContractIn,
    ) -> dict[str, object]:
        return await update(request, response, record_id, body, "contract")

    @router.patch("/engagements/{record_id}")
    async def update_engagement(
        request: Request,
        response: Response,
        record_id: ObjectPath,
        body: UpdateEngagementIn,
    ) -> dict[str, object]:
        return await update(request, response, record_id, body, "engagement")

    @router.post("/{record_id}/archive")
    async def archive_record(
        request: Request,
        response: Response,
        record_id: ObjectPath,
        body: RevisionOperationIn,
    ) -> dict[str, object]:
        require_permission(request, "operate")
        ops, tenant, store = await composition(request)
        record = await call(
            ops,
            store.archive_record,
            tenant,
            record_id,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
        )
        _secure(response)
        return projection(ops, record, sensitive=False)

    @router.delete("/{record_id}")
    async def delete_record(
        request: Request,
        response: Response,
        record_id: ObjectPath,
        body: RevisionOperationIn,
    ) -> dict[str, object]:
        require_global_permission(request, "admin")
        ops, tenant, store = await composition(request)
        tombstone = await call(
            ops,
            store.delete_record,
            tenant,
            record_id,
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
        )
        _secure(response)
        return _jsonable(tombstone)  # type: ignore[return-value]

    @router.get("/{record_id}/history")
    async def history(
        request: Request,
        response: Response,
        record_id: ObjectPath,
        include_sensitive_fields: bool = Query(default=False),
    ) -> dict[str, object]:
        require_permission(request, "view")
        sensitive = include_sensitive(request, include_sensitive_fields)
        ops, tenant, store = await composition(request)
        events = await call(ops, store.history, tenant, record_id)
        items = []
        for event in events:
            item = asdict(event)
            item["record"] = projection(ops, event.record, sensitive=sensitive)
            items.append(item)
        _secure(response)
        return {
            "schema": "lightwork.third-party-contract-history-page.v1",
            "items": items,
            "count": len(items),
            "sensitive_values_included": sensitive,
        }

    @router.get("/{record_id}/tombstone")
    async def tombstone(
        request: Request,
        response: Response,
        record_id: ObjectPath,
    ) -> dict[str, object]:
        require_global_permission(request, "audit")
        ops, tenant, store = await composition(request)
        result = await call(ops, store.get_tombstone, tenant, record_id)
        _secure(response)
        return _jsonable(result)  # type: ignore[return-value]

    return router


router = create_third_party_contracts_router()

__all__ = [
    "ContractLifecycleIn",
    "CreateContractIn",
    "CreateEngagementIn",
    "CustomFieldIn",
    "EngagementLifecycleIn",
    "FormulaIn",
    "FormulaOperandIn",
    "PurgeIn",
    "RevisionOperationIn",
    "ThirdPartyContractDependencies",
    "UpdateContractIn",
    "UpdateEngagementIn",
    "create_third_party_contracts_router",
    "router",
]
