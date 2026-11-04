"""Strict operator API for reviewed scan-to-disclosure proposals.

The browser never selects a tenant, principal, property, report, inventory
revision, review-revocation set, signing key, legal copy, or publication
target.  Those authorities are installed by the server.  The HTTP contract is
limited to opaque proposal identifiers, exact CAS revisions, and idempotency
keys; accepted metadata remains a local baseline and is never published here.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import asdict, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_IDEMPOTENCY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_RESPONSE_ITEMS = 20_000
_MAX_RESPONSE_STRING = 4_096

OpaquePath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=192,
        pattern=_IDEMPOTENCY_PATTERN,
    ),
]


class _GenericValidationRoute(APIRoute):
    """Never reflect rejected scan data, legal copy, URLs, or secrets."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="scan disclosure-proposal request is invalid",
                ) from exc

        return handler


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CreateProposalIn(_StrictModel):
    expected_head_revision: int = Field(ge=0, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class ProposalRevisionIn(_StrictModel):
    expected_proposal_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class RevokeApprovalIn(_StrictModel):
    expected_proposal_revision: int = Field(ge=1, le=2**31 - 1)
    expected_approval_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: IdempotencyKey


class AcceptLocalIn(_StrictModel):
    expected_proposal_revision: int = Field(ge=1, le=2**31 - 1)
    expected_head_revision: int = Field(ge=1, le=2**31 - 1)
    acknowledge_local_baseline_only: Literal[True]
    idempotency_key: IdempotencyKey


class ExportIn(_StrictModel):
    idempotency_key: IdempotencyKey


_FORBIDDEN_RESPONSE_KEYS = frozenset(
    {
        "body",
        "content",
        "cookies",
        "data",
        "findings",
        "headers",
        "host",
        "hostname",
        "legal_copy",
        "legal_text",
        "notice_copy",
        "notice_text",
        "origin",
        "origins",
        "path",
        "paths",
        "provider_target",
        "publication_target",
        "query",
        "raw",
        "raw_scan",
        "raw_scan_data",
        "scanner_report",
        "secret",
        "signing_key",
        "site_target",
        "token",
        "url",
        "urls",
    }
)


def _enabled() -> bool:
    from maverick.consent_scan_notice_proposals import notice_proposals_enabled

    return notice_proposals_enabled()


def scan_notice_proposals_enabled_for_page() -> bool:
    """Read the exact feature gate without opening inventory or proposal state."""

    return _enabled()


def _ops():
    from maverick import consent_scan_notice_proposals as proposals

    try:
        proposals.require_notice_proposals_enabled()
    except proposals.NoticeProposalDisabled as exc:
        raise HTTPException(
            status_code=403,
            detail="scan disclosure proposals are disabled",
        ) from exc
    return proposals


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using scan disclosure proposals",
        )
    return tenant


def _principal_ref(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request,
        error_detail="an authenticated principal is required for scan disclosure proposals",
    )
    digest = hashlib.sha256(
        (f"lightwork.consent-scan-notice-proposal.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"csnp-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _closed_response(value: Any) -> Any:
    """Reject output that crosses the proposal authority's metadata boundary."""

    result = _jsonable(value)
    item_count = 0

    def inspect(item: Any) -> None:
        nonlocal item_count
        item_count += 1
        if item_count > _MAX_RESPONSE_ITEMS:
            raise ValueError("proposal response exceeds its item bound")
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if not isinstance(key, str) or key in _FORBIDDEN_RESPONSE_KEYS:
                    raise ValueError("proposal response contains a forbidden field")
                inspect(nested)
            return
        if isinstance(item, list):
            for nested in item:
                inspect(nested)
            return
        if isinstance(item, str):
            if len(item.encode("utf-8")) > _MAX_RESPONSE_STRING:
                raise ValueError("proposal response string exceeds its bound")
            return
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, int):
            return
        if isinstance(item, float) and math.isfinite(item):
            return
        raise ValueError("proposal response contains an unsupported value")

    inspect(result)
    encoded = json.dumps(
        result,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    if not 1 <= len(encoded) <= _MAX_RESPONSE_BYTES:
        raise ValueError("proposal response exceeds its byte bound")
    return result


def _default_store(
    request: Request,
    proposals: Any,
    tenant_id: str,
    principal_ref: str,
) -> Any:
    """Join server-enrolled authority seams; accept no browser-selected scope."""

    binding_factory = getattr(
        request.app.state,
        "consent_scan_notice_proposal_binding_resolver_factory",
        None,
    )
    revocation_factory = getattr(
        request.app.state,
        "consent_scan_notice_proposal_revocation_resolver_factory",
        None,
    )
    signing_key_resolver = getattr(
        request.app.state,
        "consent_scan_notice_proposal_signing_key_resolver",
        None,
    )
    if not all(callable(value) for value in (binding_factory, revocation_factory)) or not callable(
        signing_key_resolver
    ):
        raise HTTPException(
            status_code=503,
            detail="scan disclosure-proposal runtime is unavailable",
        )

    try:
        binding_resolver = binding_factory(tenant_id=tenant_id)
        revocation_resolver = revocation_factory(tenant_id=tenant_id)
        if not callable(binding_resolver) or not callable(revocation_resolver):
            raise TypeError("resolver factory returned a non-callable value")
        inventory_factory = getattr(
            request.app.state,
            "consent_scan_notice_proposal_inventory_factory",
            None,
        )
        if callable(inventory_factory):
            inventory = inventory_factory(tenant_id=tenant_id, request=request)
        else:
            from maverick import consent_scan_inventory

            from .consent_scan_inventory_api import _inventory

            inventory = _inventory(consent_scan_inventory, tenant_id)
        snapshot_resolver = proposals.ConsentScanInventorySnapshotAdapter(
            inventory,
            binding_resolver=binding_resolver,
            revoked_review_resolver=revocation_resolver,
        )
        from maverick.paths import data_dir

        return proposals.ConsentScanNoticeProposalStore(
            data_dir(
                "consent_preferences",
                "consent-scan-notice-proposals.sqlite3",
                tenant=tenant_id,
            ),
            snapshot_resolver=snapshot_resolver,
            actor_resolver=lambda: principal_ref,
            signing_key_resolver=signing_key_resolver,
            signing_key_ref="managed-consent-scan-notice-proposals-v1",
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="scan disclosure-proposal runtime is unavailable",
        ) from exc


class ConsentScanNoticeProposalDependencies:
    """Explicit tenant/principal-bound store seam for trusted runtimes/tests."""

    def __init__(
        self,
        *,
        store_for: Callable[..., Any] | None = None,
    ) -> None:
        self.store_for = store_for


def create_consent_scan_notice_proposals_router(  # noqa: C901
    dependencies: ConsentScanNoticeProposalDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ConsentScanNoticeProposalDependencies()
    router = APIRouter(
        prefix="/consent/scan-notice-proposals",
        tags=["consent-scan-notice-proposals"],
        route_class=_GenericValidationRoute,
    )

    def authority(request: Request) -> tuple[Any, Any]:
        proposals = _ops()
        tenant = _tenant_id()
        principal = _principal_ref(request, tenant)
        try:
            if deps.store_for is not None:
                store = deps.store_for(
                    tenant_id=tenant,
                    principal_ref=principal,
                    actor_resolver=lambda: principal,
                    request=request,
                )
            else:
                factory = getattr(
                    request.app.state,
                    "consent_scan_notice_proposal_store_factory",
                    None,
                )
                store = (
                    factory(
                        tenant_id=tenant,
                        principal_ref=principal,
                        actor_resolver=lambda: principal,
                        request=request,
                    )
                    if callable(factory)
                    else _default_store(request, proposals, tenant, principal)
                )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="scan disclosure-proposal authority is unavailable",
            ) from exc
        if store is None:
            raise HTTPException(
                status_code=503,
                detail="scan disclosure-proposal authority is unavailable",
            )
        return proposals, store

    async def call(proposals: Any, function: Callable[..., Any], *args: Any, **kwargs: Any):
        try:
            result = await run_in_threadpool(function, *args, **kwargs)
            return _closed_response(result)
        except proposals.NoticeProposalNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="scan disclosure proposal was not found",
            ) from exc
        except proposals.NoticeProposalConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="scan disclosure-proposal state conflict",
            ) from exc
        except proposals.NoticeProposalValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="scan disclosure-proposal request is invalid",
            ) from exc
        except proposals.NoticeProposalDisabled as exc:
            raise HTTPException(
                status_code=403,
                detail="scan disclosure proposals are disabled",
            ) from exc
        except proposals.NoticeProposalIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="scan disclosure-proposal integrity verification failed",
            ) from exc
        except proposals.ConsentScanNoticeProposalError as exc:
            raise HTTPException(
                status_code=503,
                detail="scan disclosure-proposal operation failed",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="scan disclosure-proposal operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        principal = _principal_ref(request, tenant)
        from maverick.consent_scan_notice_proposals import (
            ConsentScanInventorySnapshotAdapter,
            ConsentScanNoticeProposalStore,
        )

        state = request.app.state
        injected_store = deps.store_for is not None or callable(
            getattr(state, "consent_scan_notice_proposal_store_factory", None)
        )
        binding = callable(
            getattr(
                state,
                "consent_scan_notice_proposal_binding_resolver_factory",
                None,
            )
        )
        revocations = callable(
            getattr(
                state,
                "consent_scan_notice_proposal_revocation_resolver_factory",
                None,
            )
        )
        key = callable(getattr(state, "consent_scan_notice_proposal_signing_key_resolver", None))
        return {
            "schema": "lightwork.consent-scan-notice-proposal-status.v1",
            "enabled": _enabled(),
            "principal_ref": principal,
            "server_authority": {
                "store_factory_configured": injected_store,
                "binding_resolver_configured": injected_store or binding,
                "revocation_resolver_configured": injected_store or revocations,
                "signing_key_resolver_configured": injected_store or key,
                "browser_may_select_tenant": False,
                "browser_may_select_property_or_report": False,
            },
            "proposal_boundaries": ConsentScanNoticeProposalStore.product_boundaries(),
            "inventory_adapter_boundaries": (
                ConsentScanInventorySnapshotAdapter.product_boundaries()
            ),
            "status_invoked_inventory": False,
            "status_performed_network_io": False,
        }

    @router.post("/proposals", status_code=201)
    async def create_proposal(request: Request, body: CreateProposalIn):
        require_permission(request, "operate")
        proposals, store = authority(request)
        return await call(
            proposals,
            store.propose,
            expected_revision=body.expected_head_revision,
            idempotency_key=body.idempotency_key,
        )

    @router.get("/proposals")
    async def list_proposals(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_permission(request, "view")
        proposals, store = authority(request)
        return await call(proposals, store.list_proposals, limit=limit)

    @router.get("/proposals/{proposal_id}")
    async def get_proposal(request: Request, proposal_id: OpaquePath):
        require_permission(request, "view")
        proposals, store = authority(request)
        return await call(proposals, store.get, proposal_id)

    @router.post("/rollback-proposals/{target_proposal_id}", status_code=201)
    async def create_rollback_proposal(
        request: Request,
        target_proposal_id: OpaquePath,
        body: CreateProposalIn,
    ):
        require_permission(request, "operate")
        proposals, store = authority(request)
        return await call(
            proposals,
            store.propose_rollback,
            target_proposal_id,
            expected_revision=body.expected_head_revision,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/proposals/{proposal_id}/approve")
    async def approve_proposal(
        request: Request,
        proposal_id: OpaquePath,
        body: ProposalRevisionIn,
    ):
        require_global_permission(request, "admin")
        proposals, store = authority(request)
        return await call(
            proposals,
            store.approve,
            proposal_id,
            expected_revision=body.expected_proposal_revision,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/proposals/{proposal_id}/approval/revoke")
    async def revoke_proposal_approval(
        request: Request,
        proposal_id: OpaquePath,
        body: RevokeApprovalIn,
    ):
        require_global_permission(request, "admin")
        proposals, store = authority(request)
        return await call(
            proposals,
            store.revoke_approval,
            proposal_id,
            expected_proposal_revision=body.expected_proposal_revision,
            expected_approval_revision=body.expected_approval_revision,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/proposals/{proposal_id}/accept-local")
    async def accept_local_baseline(
        request: Request,
        proposal_id: OpaquePath,
        body: AcceptLocalIn,
    ):
        require_global_permission(request, "admin")
        proposals, store = authority(request)
        return await call(
            proposals,
            store.accept_local,
            proposal_id,
            expected_revision=body.expected_proposal_revision,
            expected_head_revision=body.expected_head_revision,
            idempotency_key=body.idempotency_key,
        )

    @router.post("/proposals/{proposal_id}/exports", status_code=201)
    async def export_proposal_metadata(
        request: Request,
        proposal_id: OpaquePath,
        body: ExportIn,
    ):
        require_permission(request, "operate")
        proposals, store = authority(request)
        return await call(
            proposals,
            store.export_signed_metadata,
            proposal_id,
            idempotency_key=body.idempotency_key,
        )

    @router.get("/integrity")
    async def verify_integrity(request: Request):
        require_global_permission(request, "audit")
        proposals, store = authority(request)
        result = await call(proposals, store.verify_integrity)
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="scan disclosure-proposal operation failed",
            )
        return {**result, "valid": True}

    return router


router = create_consent_scan_notice_proposals_router()

__all__ = [
    "ConsentScanNoticeProposalDependencies",
    "create_consent_scan_notice_proposals_router",
    "router",
    "scan_notice_proposals_enabled_for_page",
]
