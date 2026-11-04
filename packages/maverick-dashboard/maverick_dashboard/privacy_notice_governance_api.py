"""Strict tenant-bound adapter for local privacy-notice governance.

Only content-free notice metadata crosses this boundary.  Tenant and actor
authority are derived from the active tenant and authenticated request; callers
cannot select either.  Publication records are durable worker intents only and
this adapter performs no provider I/O, SDK deployment, or site mutation.
"""

from __future__ import annotations

import hashlib
import sqlite3
import time
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
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_REF_PATTERN = r"^(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"
_LOCALE_PATTERN = r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}$"
_JURISDICTION_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"
_ERROR_PATTERN = r"^[a-z][a-z0-9_]{0,47}$"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
VersionPath = Annotated[int, ApiPath(ge=1, le=1_000_000)]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
LeaseToken = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(strict=True, min_length=64, max_length=64, pattern=_DIGEST_PATTERN),
]
SigningKeyRef = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=5,
        max_length=128,
        pattern=_KEY_REF_PATTERN,
    ),
]
Locale = Annotated[
    str,
    StringConstraints(strict=True, min_length=2, max_length=35, pattern=_LOCALE_PATTERN),
]
Jurisdiction = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=64,
        pattern=_JURISDICTION_PATTERN,
    ),
]
ErrorCode = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=48, pattern=_ERROR_PATTERN),
]
ApprovalRole = Literal["privacy", "legal", "brand", "accessibility"]


class _GenericValidationRoute(APIRoute):
    """Avoid reflecting rejected notice content, secrets, or lease tokens."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                return await original(request)
            except RequestValidationError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="privacy-notice request is invalid",
                ) from exc

        return handler


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ApprovalPolicyIn(_StrictModel):
    required_roles: list[ApprovalRole] = Field(min_length=1, max_length=4)
    quorum: int = Field(ge=1, le=4)
    approval_ttl_seconds: int = Field(ge=60, le=31_536_000)
    expected_revision: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class ReleaseCreateIn(_StrictModel):
    expected_context: Digest | None = None
    property_id: OpaqueId
    jurisdictions: list[Jurisdiction] = Field(min_length=1, max_length=64)
    locales: list[Locale] = Field(min_length=1, max_length=64)
    policy_sha256: Digest
    content_sha256: Digest
    configuration_sha256: Digest
    consent_publication_ref: OpaqueId
    approval_policy_id: OpaqueId
    effective_from: float | int = Field(gt=0, lt=100_000_000_000.0)
    effective_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    update_proposal_ref: OpaqueId | None = None
    expected_latest_version: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ApprovalIn(RevisionIn):
    role: ApprovalRole
    expected_release_sha256: Digest


class ApprovalRevocationIn(_StrictModel):
    expected_approval_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class ScheduleIn(RevisionIn):
    activate_at: float | int = Field(gt=0, lt=100_000_000_000.0)
    expected_release_sha256: Digest
    max_attempts: int = Field(ge=1, le=20)


class ClaimPublicationIntentsIn(_StrictModel):
    limit: int = Field(default=10, ge=1, le=100)
    lease_seconds: int = Field(default=60, ge=1, le=3_600)


class FailPublicationIntentIn(RevisionIn):
    lease_token: LeaseToken
    error_code: ErrorCode
    retry_delay_seconds: int = Field(ge=0, le=604_800)


class AcknowledgePublicationIntentIn(RevisionIn):
    lease_token: LeaseToken
    acknowledgement_sha256: Digest
    acknowledgement_ref: OpaqueId


class RollbackIn(RevisionIn):
    target_version: int = Field(ge=1, le=1_000_000)
    reason_code: OpaqueId
    max_attempts: int = Field(ge=1, le=20)


class WithdrawIn(RevisionIn):
    reason_code: OpaqueId
    max_attempts: int = Field(ge=1, le=20)


class RegulatoryCitationIn(_StrictModel):
    document_ref: OpaqueId
    source_ref: OpaqueId
    evidence_sha256: Digest


class UpdateProposalIn(_StrictModel):
    notice_id: OpaqueId
    base_version: int = Field(ge=1, le=1_000_000)
    policy_sha256: Digest
    content_sha256: Digest
    configuration_sha256: Digest
    consent_publication_ref: OpaqueId
    regulatory_citations: list[RegulatoryCitationIn] = Field(
        min_length=1,
        max_length=64,
    )
    reason_codes: list[OpaqueId] = Field(min_length=1, max_length=64)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class UpdateProposalReviewIn(RevisionIn):
    decision: Literal["approved", "rejected"]


class ExportNoticeIn(_StrictModel):
    signing_key_ref: SigningKeyRef
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class NoticeRecordIn(_StrictModel):
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


#: Signing key the page's "Download signed record" button uses; nobody types
#: a key reference. The key itself stays in the environment.
DEFAULT_NOTICE_SIGNING_KEY_REF = "env:MAVERICK_PRIVACY_NOTICE_SIGNING_KEY"


class PurgeIn(_StrictModel):
    cutoff: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class PublicationRuntimeRunOnceIn(_StrictModel):
    """Intentionally empty: tenant and target selection are never request input."""


def _enabled() -> bool:
    from maverick import privacy_notice_governance as notice

    return notice.enabled()


def privacy_notice_governance_enabled_for_page() -> bool:
    """Read only the exact feature gate without opening tenant storage."""

    return _enabled()


def _notice():
    from maverick import privacy_notice_governance as notice

    try:
        notice.require_enabled()
    except notice.PrivacyNoticeConfigError as exc:
        raise HTTPException(
            status_code=403,
            detail="privacy-notice governance is disabled",
        ) from exc
    return notice


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using privacy-notice governance",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request,
        error_detail="an authenticated principal is required for privacy-notice governance",
    )
    digest = hashlib.sha256(
        (f"lightwork.privacy-notice.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"png-principal-{digest[:32]}"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _without_lease(value: Any) -> Any:
    """Recursively remove lease tokens from every non-claim response."""

    result = _jsonable(value)
    if isinstance(result, dict):
        return {key: _without_lease(item) for key, item in result.items() if key != "lease_token"}
    if isinstance(result, list):
        return [_without_lease(item) for item in result]
    return result


def _default_store_for(tenant_id: str, principal_ref: str):
    from maverick.paths import data_dir
    from maverick.privacy_notice_governance import PrivacyNoticeGovernanceStore

    return PrivacyNoticeGovernanceStore(
        data_dir(
            "privacy_automation",
            "privacy-notice-governance.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=lambda: principal_ref,
        regulatory_reference_resolver=_approved_regulatory_reference,
    )


def _approved_regulatory_reference(tenant, document, source, evidence):
    from .privacy_notice_proposals import reference_allowed
    return reference_allowed(tenant, document, source, evidence)


class PrivacyNoticeGovernanceDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for



def authority(request: Request, *, store_for=_default_store_for):
    notice = _notice()
    tenant = _tenant_id()
    principal = _principal(request, tenant)
    factory = getattr(
        request.app.state,
        "privacy_notice_governance_store_factory",
        None,
    )

    def resolver() -> str:
        return principal

    try:
        store = (
            factory(
                tenant_id=tenant,
                principal_ref=principal,
                principal_resolver=resolver,
                request=request,
            )
            if callable(factory)
            else store_for(tenant, principal)
        )
    except (notice.PrivacyNoticeGovernanceError, OSError) as exc:
        raise HTTPException(
            status_code=503,
            detail="privacy-notice governance store is unavailable",
        ) from exc
    if store is None:
        raise HTTPException(
            status_code=503,
            detail="privacy-notice governance store is unavailable",
        )
    return notice, tenant, store


def _fresh_decision_access(request: Request) -> None:
    from . import auth, session_revocation

    require_global_permission(request, "admin")
    auth.require_api_key_scope(request, "approvals:decide")
    principal = getattr(request.state, "principal", None)
    claims = getattr(principal, "claims", None) or {}
    via = claims.get("via")
    fresh = principal
    if via in {"session", "invite", "proxy"}:
        fresh = (auth._session_principal(request) if via == "session" else
                 auth._invite_session_principal(request) if via == "invite" else
                 auth._proxy_principal(request))
    expiry = claims.get("exp")
    if (fresh is None or getattr(fresh, "principal", None) != auth.caller_principal(request)
            or (expiry is not None and (type(expiry) not in {int, float}
                or not time.time() < expiry < float("inf")))):
        raise HTTPException(401, "Sign in again before reviewing this notice.")
    subject = getattr(principal, "sub", None)
    if subject is not None:
        if (via not in {"session", "invite", "proxy", "api_key"}
                and session_revocation.is_revoked(subject, claims.get("iat"))):
            raise HTTPException(401, "Sign in again before reviewing this notice.")
        auth._enforce_scim_active(fresh)
        auth._enforce_workspace_policies(request, fresh)


def _decision_guard(request: Request) -> Callable[[], None]:
    from . import auth, workspace_tenants
    from .draft_api import context_for

    with auth.fresh_configuration():
        _fresh_decision_access(request)
        actor, tenant, context = auth.caller_principal(request), _tenant_id(), context_for(request)
        selection = (workspace_tenants.get_selection_binding(actor)
                     if getattr(request.state, "workspace_tenant_source", None) == "principal_selection" else None)

    def guard():
        with auth.fresh_configuration():
            _fresh_decision_access(request)
            if (auth.caller_principal(request) != actor or _tenant_id() != tenant
                    or context_for(request) != context or (selection is not None
                        and workspace_tenants.get_selection_binding(actor) != selection)):
                raise HTTPException(409, "Your account or workspace changed. Reopen the current notice before reviewing it.")

    return guard


async def _guarded_decision(notice, function, *args, call, guard, **kwargs):
    from maverick.authority_effects import authority_effect_fence

    def decide():
        with authority_effect_fence():
            guard()
            return function(*args, effect_guard=guard, **kwargs)

    try:
        return await call(notice, decide)
    except HTTPException as exc:
        if exc.status_code != 503:
            raise
        raise HTTPException(503, "This decision could not be confirmed. It may already be saved. Read the current notice before deciding again.") from exc
    except (OSError, sqlite3.Error) as exc:
        raise HTTPException(503, "This decision could not be confirmed. It may already be saved. Read the current notice before deciding again.") from exc


def create_privacy_notice_governance_router(  # noqa: C901, PLR0915
    dependencies: PrivacyNoticeGovernanceDependencies | None = None,
) -> APIRouter:
    deps = dependencies or PrivacyNoticeGovernanceDependencies()
    router = APIRouter(
        prefix="/privacy/notices",
        tags=["privacy-notice-governance"],
        route_class=_GenericValidationRoute,
    )

    def route_authority(request: Request):
        return authority(request, store_for=deps.store_for)

    async def call(notice, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except notice.PrivacyNoticeNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="privacy-notice record was not found",
            ) from exc
        except notice.PrivacyNoticePermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="privacy-notice operation is not permitted",
            ) from exc
        except notice.PrivacyNoticeConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="privacy-notice state conflict",
            ) from exc
        except notice.PrivacyNoticeValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="privacy-notice request is invalid",
            ) from exc
        except notice.PrivacyNoticeConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-notice configuration is unavailable",
            ) from exc
        except notice.PrivacyNoticeIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-notice integrity verification failed",
            ) from exc
        except notice.PrivacyNoticeGovernanceError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-notice operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "view")
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        from maverick.privacy_notice_governance import (
            PrivacyNoticeGovernanceStore,
        )

        readiness_probe = getattr(
            request.app.state,
            "privacy_notice_publication_readiness_probe",
            None,
        )
        runtime_readiness = (
            readiness_probe(tenant) if callable(readiness_probe) else None
        )
        return {
            "schema": "lightwork.privacy-notice-governance-status.v1",
            "enabled": _enabled(),
            "principal_ref": principal,
            **PrivacyNoticeGovernanceStore.product_boundaries(),
            "publication_intents_are_worker_intent_only": True,
            "publication_transport_worker_implemented": True,
            "publication_runtime_configured": bool(
                isinstance(runtime_readiness, Mapping)
                and runtime_readiness.get("configured") is True
            ),
            "regulatory_reference_resolver_required": True,
            "claim_is_only_live_lease_token_response": True,
            "status_request_external_network_io": False,
        }

    @router.get("/publication-runtime/status")
    async def publication_runtime_status(request: Request) -> dict[str, Any]:
        """Return tenant-derived configuration and content-free scheduler health."""

        require_permission(request, "view")
        _notice()
        tenant = _tenant_id()
        _principal(request, tenant)
        readiness_probe = getattr(
            request.app.state,
            "privacy_notice_publication_readiness_probe",
            None,
        )
        scheduler_probe = getattr(
            request.app.state,
            "privacy_notice_publication_scheduler_status",
            None,
        )
        if not callable(readiness_probe) or not callable(scheduler_probe):
            raise HTTPException(
                status_code=503,
                detail="privacy-notice publication runtime is unavailable",
            )
        try:
            readiness_value = await run_in_threadpool(readiness_probe, tenant)
            scheduler_value = await run_in_threadpool(scheduler_probe)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-notice publication runtime status is unavailable",
            ) from exc
        return {
            "schema": "lightwork.privacy-notice-publication-operator-status.v1",
            "readiness": _without_lease(readiness_value),
            "scheduler": _without_lease(scheduler_value),
            "tenant_derived_from_authenticated_context": True,
            "request_selected_target": False,
            "local_consent_publication_only": True,
            "provider_network_io": False,
            "provider_writes": False,
            "site_mutation": False,
            "sdk_deployment": False,
            "live_acceptance_verified": False,
        }

    @router.post("/publication-runtime/run-once")
    async def publication_runtime_run_once(
        request: Request,
        _body: PublicationRuntimeRunOnceIn,
    ) -> dict[str, Any]:
        """Run one bounded cycle for the authenticated active tenant only."""

        require_global_permission(request, "admin")
        _notice()
        tenant = _tenant_id()
        _principal(request, tenant)
        readiness_probe = getattr(
            request.app.state,
            "privacy_notice_publication_readiness_probe",
            None,
        )
        if not callable(readiness_probe):
            raise HTTPException(
                status_code=503,
                detail="privacy-notice publication runtime is unavailable",
            )
        readiness_value = await run_in_threadpool(readiness_probe, tenant)
        if not isinstance(readiness_value, Mapping) or (
            readiness_value.get("configuration_preflight_ready") is not True
        ):
            raise HTTPException(
                status_code=409,
                detail="privacy-notice publication runtime requires exact tenant bindings",
            )
        from .privacy_notice_publication_scheduler import (
            PrivacyNoticePublicationSchedulerBusy,
            PrivacyNoticePublicationSchedulerError,
            run_once_for_tenant,
        )

        try:
            cycle = await run_in_threadpool(run_once_for_tenant, request.app, tenant)
        except PrivacyNoticePublicationSchedulerBusy as exc:
            raise HTTPException(
                status_code=409,
                detail="a privacy-notice publication cycle is already running",
            ) from exc
        except PrivacyNoticePublicationSchedulerError as exc:
            raise HTTPException(
                status_code=503,
                detail="privacy-notice publication execution is unavailable",
            ) from exc
        return {
            "schema": "lightwork.privacy-notice-publication-run-once.v1",
            "cycle": _without_lease(cycle),
            "tenant_derived_from_authenticated_context": True,
            "request_selected_target": False,
            "local_consent_publication_only": True,
            "provider_network_io": False,
            "provider_writes": False,
            "site_mutation": False,
            "sdk_deployment": False,
            "live_acceptance_verified": False,
        }

    @router.get("/records")
    async def records(request: Request) -> dict[str, Any]:
        """Approval rules, notice versions, approvals, update proposals,
        signed records and the publication queue size, for the page lists."""

        require_permission(request, "view")
        notice, tenant, store = route_authority(request)
        listed = await call(notice, store.list_records, tenant)
        return {
            "policies": [
                {
                    "policy_id": p.policy_id,
                    "required_roles": list(p.required_roles),
                    "quorum": p.quorum,
                    "approval_ttl_seconds": p.approval_ttl_seconds,
                    "revision": p.revision,
                }
                for p in listed["policies"]
            ],
            "releases": [
                {
                    "notice_id": r.notice_id,
                    "version": r.version,
                    "property_id": r.property_id,
                    "jurisdictions": list(r.jurisdictions),
                    "locales": list(r.locales),
                    "approval_policy_id": r.approval_policy_id,
                    "required_roles": list(r.required_roles),
                    "quorum": r.quorum,
                    "state": r.state,
                    "activate_at": r.activate_at,
                    "effective_from": r.effective_from,
                    "effective_until": r.effective_until,
                    "retained_until": r.retained_until,
                    "release_sha256": r.definition_sha256,
                    "revision": r.state_revision,
                    "created_at": r.created_at,
                }
                for r in listed["releases"]
            ],
            "approvals": [
                {
                    "notice_id": a.notice_id,
                    "version": a.release_version,
                    "role": a.role,
                    "expires_at": a.expires_at,
                    "revoked": a.revoked_at is not None,
                    "revision": a.revision,
                }
                for a in listed["approvals"]
            ],
            "proposals": [
                {
                    "proposal_id": p.proposal_id,
                    "notice_id": p.notice_id,
                    "base_version": p.base_version,
                    "status": p.status,
                    "reason_codes": list(p.reason_codes),
                    "citations": len(p.regulatory_citations),
                    "revision": p.revision,
                    "created_at": p.created_at,
                }
                for p in listed["proposals"]
            ],
            "records": [
                {"export_id": e.export_id, "notice_id": e.notice_id, "created_at": e.created_at}
                for e in listed["exports"]
            ],
            "queue": dict(listed["queue"]),
        }

    @router.post("/releases/{notice_id}/record")
    async def create_notice_record(
        request: Request,
        notice_id: ObjectPath,
        body: NoticeRecordIn,
    ):
        """Signed metadata record for one notice with the deployment key."""

        require_permission(request, "operate")
        notice, tenant, store = route_authority(request)
        export_id = "record-" + hashlib.sha256(
            f"{notice_id}:{body.idempotency_key}".encode()
        ).hexdigest()[:24]
        return _without_lease(
            await call(
                notice,
                store.export_notice,
                tenant,
                notice_id,
                export_id,
                signing_key_ref=DEFAULT_NOTICE_SIGNING_KEY_REF,
                retained_until=body.retained_until,
                idempotency_key=body.idempotency_key,
            )
        )

    @router.put("/approval-policies/{policy_id}")
    async def set_approval_policy(
        request: Request,
        policy_id: ObjectPath,
        body: ApprovalPolicyIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.set_approval_policy,
                tenant,
                policy_id,
                **body.model_dump(),
            )
        )

    @router.get("/approval-policies/{policy_id}")
    async def get_approval_policy(request: Request, policy_id: ObjectPath):
        require_permission(request, "view")
        notice, tenant, store = route_authority(request)
        return _without_lease(await call(notice, store.get_approval_policy, tenant, policy_id))

    @router.put("/releases/{notice_id}/versions")
    async def create_release(
        request: Request,
        notice_id: ObjectPath,
        body: ReleaseCreateIn,
    ):
        require_permission(request, "operate")
        notice, tenant, store = route_authority(request)
        if body.update_proposal_ref is not None or body.expected_context is not None:
            from .privacy_notice_proposals import create_version
            return _without_lease(await call(notice, create_version, request, store, tenant, notice_id, body.model_dump()))
        return _without_lease(await call(notice, store.create_release, tenant, notice_id, **body.model_dump(exclude={"expected_context"})))

    @router.get("/releases/{notice_id}/versions/{version}")
    async def get_release(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
    ):
        require_permission(request, "view")
        notice, tenant, store = route_authority(request)
        return _without_lease(await call(notice, store.get_release, tenant, notice_id, version))

    @router.post("/releases/{notice_id}/versions/{version}/submit")
    async def submit_for_review(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
        body: RevisionIn,
    ):
        require_permission(request, "operate")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.submit_for_review,
                tenant,
                notice_id,
                version,
                **body.model_dump(),
            )
        )

    @router.post("/releases/{notice_id}/versions/{version}/approvals")
    async def approve_release(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
        body: ApprovalIn,
    ):
        guard = _decision_guard(request)
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await _guarded_decision(
                notice,
                store.approve_release,
                tenant,
                notice_id,
                version,
                call=call, guard=guard,
                **body.model_dump(),
            )
        )

    @router.post("/releases/{notice_id}/versions/{version}/approvals/{role}/revoke")
    async def revoke_approval(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
        role: ApprovalRole,
        body: ApprovalRevocationIn,
    ):
        guard = _decision_guard(request)
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await _guarded_decision(
                notice,
                store.revoke_approval,
                tenant,
                notice_id,
                version,
                role=role,
                call=call, guard=guard,
                **body.model_dump(),
            )
        )

    @router.post("/releases/{notice_id}/versions/{version}/schedule")
    async def schedule_release(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
        body: ScheduleIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.schedule_release,
                tenant,
                notice_id,
                version,
                **body.model_dump(),
            )
        )

    @router.post("/publication-intents/claim")
    async def claim_publication_intents(
        request: Request,
        body: ClaimPublicationIntentsIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        items = await call(
            notice,
            store.claim_publication_intents,
            tenant,
            **body.model_dump(),
        )
        return {"items": _jsonable(items), "count": len(items)}

    @router.post("/publication-intents/{intent_id}/fail")
    async def fail_publication_intent(
        request: Request,
        intent_id: ObjectPath,
        body: FailPublicationIntentIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.fail_publication_intent,
                tenant,
                intent_id,
                **body.model_dump(),
            )
        )

    @router.post("/publication-intents/{intent_id}/requeue")
    async def requeue_publication_intent(
        request: Request,
        intent_id: ObjectPath,
        body: RevisionIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.requeue_publication_intent,
                tenant,
                intent_id,
                **body.model_dump(),
            )
        )

    @router.post("/publication-intents/{intent_id}/acknowledge")
    async def acknowledge_publication_intent(
        request: Request,
        intent_id: ObjectPath,
        body: AcknowledgePublicationIntentIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.ack_publication_intent,
                tenant,
                intent_id,
                **body.model_dump(),
            )
        )

    @router.post("/releases/{notice_id}/versions/{version}/rollback")
    async def rollback_release(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
        body: RollbackIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.rollback_release,
                tenant,
                notice_id,
                version,
                **body.model_dump(),
            )
        )

    @router.post("/releases/{notice_id}/versions/{version}/withdraw")
    async def withdraw_release(
        request: Request,
        notice_id: ObjectPath,
        version: VersionPath,
        body: WithdrawIn,
    ):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.withdraw_release,
                tenant,
                notice_id,
                version,
                **body.model_dump(),
            )
        )

    @router.get("/effective/{property_id}")
    async def current_effective_release(
        request: Request,
        property_id: ObjectPath,
        jurisdiction: Jurisdiction = Query(),
        locale: Locale = Query(),
        at: float | None = Query(default=None, gt=0, lt=100_000_000_000.0),
    ):
        require_permission(request, "view")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.current_effective_release,
                tenant,
                property_id,
                jurisdiction,
                locale,
                at=at,
            )
        )

    @router.put("/update-proposals/{proposal_id}")
    async def create_update_proposal(
        request: Request,
        proposal_id: ObjectPath,
        body: UpdateProposalIn,
    ):
        require_permission(request, "operate")
        notice, tenant, store = route_authority(request)
        payload = body.model_dump()
        payload["regulatory_citations"] = [
            citation.model_dump() for citation in body.regulatory_citations
        ]
        from .privacy_notice_proposals import legacy_proposal
        return _without_lease(
            await call(
                notice,
                legacy_proposal,
                request,
                store,
                tenant,
                proposal_id,
                payload,
            )
        )

    @router.get("/update-proposals/{proposal_id}")
    async def get_update_proposal(request: Request, proposal_id: ObjectPath):
        require_permission(request, "view")
        notice, tenant, store = route_authority(request)
        return _without_lease(await call(notice, store.get_update_proposal, tenant, proposal_id))

    @router.post("/update-proposals/{proposal_id}/review")
    async def review_update_proposal(
        request: Request,
        proposal_id: ObjectPath,
        body: UpdateProposalReviewIn,
    ):
        guard = _decision_guard(request)
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await _guarded_decision(
                notice,
                store.review_update_proposal,
                tenant,
                proposal_id,
                call=call, guard=guard,
                **body.model_dump(),
            )
        )

    @router.put("/releases/{notice_id}/exports/{export_id}")
    async def export_notice(
        request: Request,
        notice_id: ObjectPath,
        export_id: ObjectPath,
        body: ExportNoticeIn,
    ):
        require_permission(request, "operate")
        notice, tenant, store = route_authority(request)
        return _without_lease(
            await call(
                notice,
                store.export_notice,
                tenant,
                notice_id,
                export_id,
                **body.model_dump(),
            )
        )

    @router.get("/exports/{export_id}")
    async def get_export(request: Request, export_id: ObjectPath):
        require_permission(request, "view")
        notice, tenant, store = route_authority(request)
        return _without_lease(await call(notice, store.get_export, tenant, export_id))

    @router.post("/retention/purge")
    async def purge_expired(request: Request, body: PurgeIn):
        require_global_permission(request, "admin")
        notice, tenant, store = route_authority(request)
        return _without_lease(await call(notice, store.purge_expired, tenant, **body.model_dump()))

    @router.get("/integrity")
    async def verify_integrity(request: Request):
        require_global_permission(request, "audit")
        notice, tenant, store = route_authority(request)
        result = _without_lease(await call(notice, store.verify_integrity, tenant))
        result["valid"] = True
        return result

    return router


router = create_privacy_notice_governance_router()

__all__ = [
    "DEFAULT_NOTICE_SIGNING_KEY_REF",
    "PrivacyNoticeGovernanceDependencies",
    "create_privacy_notice_governance_router",
    "privacy_notice_governance_enabled_for_page",
    "router",
]
