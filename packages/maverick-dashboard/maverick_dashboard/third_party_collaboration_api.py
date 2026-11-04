"""Internal and invitation-authenticated third-party collaboration APIs.

Internal routes derive tenant and principal from the authenticated dashboard.
External routes accept only a deployment-owned public portal reference and an
opaque invitation credential.  Neither surface accepts a tenant, lifecycle
authority, scoring rule, approval, or provider credential.

The one external route that receives file bytes (``/evidence``) authenticates
the invitation and learns that invitation's own size bound before reading any
of the body, then hands the bytes to the store, which measures them (SHA-256,
size, type from the content) and keeps only the measurement.  Draft and final
submissions are accepted only with manifests that match such a measurement.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_PORTAL_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{15,127}$"
_TOKEN_RE = re.compile(r"tpc1\.[A-Za-z0-9_-]{43}\Z")
_EXTENSION_RE = re.compile(r"[a-z0-9]{1,10}\Z")
_EVIDENCE_EXTENSION_HEADER = "x-evidence-file-extension"

OpaqueId = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_ID_PATTERN),
]
ObjectPath = Annotated[
    str,
    ApiPath(min_length=1, max_length=128, pattern=_ID_PATTERN),
]
PortalPath = Annotated[
    str,
    ApiPath(min_length=16, max_length=128, pattern=_PORTAL_PATTERN),
]
IdempotencyKey = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=192, pattern=_OP_PATTERN),
]
Digest = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=64,
        max_length=64,
        pattern=_DIGEST_PATTERN,
    ),
]
ArtifactKind = Literal[
    "audit_report",
    "certification",
    "policy",
    "questionnaire",
    "test_report",
    "other_evidence",
]
BoundedAnswerString = Annotated[
    str,
    StringConstraints(strict=True, max_length=512),
]
BoundedAnswerInteger = Annotated[
    int,
    Field(strict=True, ge=-(2**63), le=2**63 - 1),
]
JsonScalar = bool | BoundedAnswerInteger | BoundedAnswerString | None
JsonValue = JsonScalar | Annotated[list[JsonScalar], Field(max_length=100)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ArtifactPolicyIn(_StrictModel):
    allowed_kinds: list[ArtifactKind] = Field(max_length=6)
    maximum_artifacts: int = Field(ge=0, le=100)
    maximum_total_bytes: int = Field(ge=0, le=100 * 1024 * 1024)


class IssueInvitationIn(_StrictModel):
    invitation_id: OpaqueId
    assessment_id: OpaqueId
    respondent_ref: OpaqueId
    allowed_question_ids: list[OpaqueId] = Field(min_length=1, max_length=1_000)
    notice_ref: OpaqueId
    notice_sha256: Digest
    artifact_policy: ArtifactPolicyIn
    expires_in_seconds: int = Field(ge=300, le=90 * 24 * 3_600)
    retention_seconds: int = Field(ge=3_600, le=10 * 365 * 24 * 3_600)
    idempotency_key: IdempotencyKey


class RotateInvitationIn(_StrictModel):
    expires_in_seconds: int = Field(ge=300, le=90 * 24 * 3_600)
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class RevokeInvitationIn(_StrictModel):
    reason_code: OpaqueId
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class FollowUpIn(_StrictModel):
    question_ids: list[OpaqueId] = Field(min_length=1, max_length=1_000)
    reason_code: OpaqueId
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class LegalHoldIn(_StrictModel):
    active: bool
    evidence_ref: OpaqueId
    expected_revision: int = Field(ge=1, le=1_000_000)
    idempotency_key: IdempotencyKey


class PurgeIn(_StrictModel):
    before: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class AnswerIn(_StrictModel):
    value: JsonValue
    artifact_ids: list[OpaqueId] = Field(max_length=100)


class ArtifactManifestIn(_StrictModel):
    artifact_id: OpaqueId
    kind: ArtifactKind
    content_sha256: Digest
    size_bytes: int = Field(ge=1, le=100 * 1024 * 1024)
    media_type_ref: OpaqueId


class DraftIn(_StrictModel):
    answers: dict[OpaqueId, AnswerIn] = Field(max_length=1_000)
    artifacts: list[ArtifactManifestIn] = Field(max_length=100)
    expected_revision: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class FinalizeIn(_StrictModel):
    answers: dict[OpaqueId, AnswerIn] = Field(min_length=1, max_length=1_000)
    artifacts: list[ArtifactManifestIn] = Field(max_length=100)
    attested: Literal[True]
    expected_draft_revision: int = Field(ge=0, le=1_000_000)
    idempotency_key: IdempotencyKey


class _ExternalArtifactPolicyOut(_StrictModel):
    allowed_kinds: list[ArtifactKind] = Field(max_length=6)
    maximum_artifacts: int = Field(ge=0, le=100)
    maximum_total_bytes: int = Field(ge=0, le=100 * 1024 * 1024)


class _ExternalArtifactManifestOut(_StrictModel):
    artifact_id: OpaqueId
    kind: ArtifactKind
    content_sha256: Digest
    size_bytes: int = Field(ge=1, le=100 * 1024 * 1024)
    media_type_ref: OpaqueId


class _ExternalQuestionOut(_StrictModel):
    question_id: OpaqueId
    domain: OpaqueId
    prompt_ref: OpaqueId
    response_type: Literal[
        "boolean",
        "single_choice",
        "multi_choice",
        "integer",
        "text_ref",
    ]
    required: bool
    options: list[OpaqueId] = Field(max_length=1_000)


class _ExternalContractOut(_StrictModel):
    schema_name: Literal["lightwork.third-party-collaboration-contract.v1"] = Field(
        alias="schema"
    )
    tenant_id: OpaqueId
    invitation_id: OpaqueId
    vendor_ref: OpaqueId
    assessment_id: OpaqueId
    notice_ref: OpaqueId
    notice_sha256: Digest
    artifact_policy: _ExternalArtifactPolicyOut
    questions: list[_ExternalQuestionOut] = Field(max_length=1_000)
    required_question_ids: list[OpaqueId] = Field(max_length=1_000)
    answered_question_ids: list[OpaqueId] = Field(max_length=1_000)
    draft_revision: int = Field(ge=0, le=1_000_000)
    draft_artifacts: list[_ExternalArtifactManifestOut] = Field(max_length=100)
    expires_at: float | int = Field(gt=0, lt=100_000_000_000.0)
    limitations: list[
        Literal[
            "respondent_attestations_are_unverified",
            "artifact_manifests_only_no_upload_bytes",
            "no_network_or_email_delivery",
            "no_model_inference",
        ]
    ] = Field(min_length=4, max_length=4)


class _ExternalDraftOut(_StrictModel):
    tenant_id: OpaqueId
    invitation_id: OpaqueId
    revision: int = Field(ge=1, le=1_000_000)
    draft_sha256: Digest
    active_question_ids: list[OpaqueId] = Field(max_length=1_000)
    required_question_ids: list[OpaqueId] = Field(max_length=1_000)
    artifact_count: int = Field(ge=0, le=100)
    idempotent_replay: bool


class _ExternalEvidenceOut(_StrictModel):
    tenant_id: OpaqueId
    invitation_id: OpaqueId
    artifact_id: OpaqueId
    content_sha256: Digest
    size_bytes: int = Field(ge=1, le=100 * 1024 * 1024)
    media_type_ref: OpaqueId
    idempotent_replay: bool


class _ExternalFinalOut(_StrictModel):
    schema_name: Literal["lightwork.third-party-collaboration-receipt.v1"] = Field(
        alias="schema"
    )
    tenant_id: OpaqueId
    invitation_id: OpaqueId
    assessment_id: OpaqueId
    assessment_revision: int = Field(ge=1, le=1_000_000)
    assessment_integrity_sha256: Digest
    question_ids: list[OpaqueId] = Field(min_length=1, max_length=1_000)
    attestation_sha256: Digest
    evidence_status: Literal["respondent_attestation_unverified"]
    idempotent_replay: bool


@dataclass(frozen=True)
class ExternalPortalAuthority:
    """Server-resolved portal authority; the public reference is not a tenant."""

    tenant_id: str
    store: Any


class ThirdPartyCollaborationDependencies:
    def __init__(
        self,
        *,
        store_for: Callable[[str, str], Any] | None = None,
        portal_resolver: Callable[[str, Request], ExternalPortalAuthority] | None = None,
        external_rate_limit: Callable[[str, str], None] | None = None,
    ) -> None:
        for dependency in (store_for, portal_resolver, external_rate_limit):
            if dependency is not None and not callable(dependency):
                raise TypeError("third-party collaboration dependency must be callable")
        self.store_for = store_for
        self.portal_resolver = portal_resolver
        self.external_rate_limit = external_rate_limit


def _enabled() -> bool:
    try:
        from maverick.third_party_collaboration import enabled

        return enabled()
    except Exception:
        return False


def third_party_collaboration_enabled_for_page() -> bool:
    return _enabled()


def _ops():
    from maverick import third_party_collaboration as operations

    try:
        operations.require_enabled()
    except operations.ThirdPartyCollaborationConfigError as exc:
        raise HTTPException(status_code=403, detail="third_party_collaboration_disabled") from exc
    return operations


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using third-party collaboration",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(request, error_detail="an authenticated principal is required")
    digest = hashlib.sha256(
        f"lightwork.third-party-collaboration.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"tpc-principal-{digest[:40]}"


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {key: _jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_jsonable(item) for item in value]
    return value


def _external_safe(
    value: Any,
    *,
    kind: Literal["contract", "draft", "final", "evidence"],
    tenant_id: str,
) -> dict[str, Any]:
    """Validate the complete external response before removing tenant authority.

    A permissive top-level key filter is not enough here: a compromised or
    misconfigured store could otherwise place tenant identifiers, credentials,
    or internal rules inside nested values.  The closed DTOs reject every
    unknown field at every level before anything is serialized to the public
    invitation surface.
    """

    models: dict[str, type[BaseModel]] = {
        "contract": _ExternalContractOut,
        "draft": _ExternalDraftOut,
        "final": _ExternalFinalOut,
        "evidence": _ExternalEvidenceOut,
    }
    try:
        validated = models[kind].model_validate(_jsonable(value), strict=True)
    except (KeyError, ValidationError) as exc:
        raise HTTPException(
            status_code=503,
            detail="invitation authority unavailable",
        ) from exc
    payload = validated.model_dump(mode="json", by_alias=True)
    returned_tenant = payload.pop("tenant_id", None)
    if returned_tenant != tenant_id:
        raise HTTPException(status_code=503, detail="invitation authority unavailable")
    if kind == "contract" and payload.get("limitations") != [
        "respondent_attestations_are_unverified",
        "artifact_manifests_only_no_upload_bytes",
        "no_network_or_email_delivery",
        "no_model_inference",
    ]:
        raise HTTPException(status_code=503, detail="invitation authority unavailable")
    return payload


def _default_store_for(tenant_id: str, principal_ref: str):
    from maverick.paths import data_dir
    from maverick.third_party_collaboration import (
        ThirdPartyCollaborationStore,
        load_policy,
    )

    return ThirdPartyCollaborationStore(
        data_dir(
            "third_party_management",
            "third-party-collaboration.sqlite3",
            tenant=tenant_id,
        ),
        lifecycle_path=data_dir(
            "third_party_management",
            "third-party-lifecycle.sqlite3",
            tenant=tenant_id,
        ),
        principal_resolver=lambda: principal_ref,
        policy=load_policy(),
    )


async def _call(ops: Any, function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    try:
        return _jsonable(await run_in_threadpool(function, *args, **kwargs))
    except ops.ThirdPartyCollaborationNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ops.ThirdPartyCollaborationPermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ops.ThirdPartyCollaborationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ops.ThirdPartyCollaborationValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ops.ThirdPartyCollaborationAuthError as exc:
        raise HTTPException(status_code=404, detail="invitation unavailable") from exc
    except (
        ops.ThirdPartyCollaborationConfigError,
        ops.ThirdPartyCollaborationIntegrityError,
    ) as exc:
        raise HTTPException(
            status_code=503,
            detail="third-party collaboration authority unavailable",
        ) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="third-party collaboration dependency unavailable",
        ) from exc


def _sharing(request: Request, ops: Any) -> dict[str, Any]:
    portal = None
    resolver = getattr(request.app.state, "third_party_collaboration_current_portal_ref", None)
    if callable(resolver):
        try:
            portal = f"/api/v1/external/third-party-collaboration/{resolver()}/portal"
        except Exception:
            portal = None
    try:
        policy = ops.load_policy()
        limits = {
            "invitation_seconds": int(policy.invitation_ttl_seconds),
            "retention_seconds": int(policy.retention_seconds),
            "max_artifacts": int(policy.max_artifacts),
            "max_artifact_bytes": int(policy.max_artifact_bytes),
        }
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="third-party collaboration authority unavailable",
        ) from exc
    return {"portal_path": portal, "limits": limits}


def create_third_party_collaboration_router(
    dependencies: ThirdPartyCollaborationDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ThirdPartyCollaborationDependencies()
    router = APIRouter(
        prefix="/third-party/collaboration",
        tags=["third-party-collaboration"],
    )

    def authority(request: Request) -> tuple[Any, str, Any]:
        ops = _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(
            request.app.state,
            "third_party_collaboration_store_factory",
            None,
        )
        try:
            if callable(factory):
                store = factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=lambda: principal,
                    request=request,
                )
            else:
                selected = deps.store_for or _default_store_for
                store = selected(tenant, principal)
        except (ops.ThirdPartyCollaborationError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="third-party collaboration authority unavailable",
            ) from exc
        required = (
            "issue_invitation",
            "get_invitation",
            "list_invitations",
            "rotate_invitation",
            "revoke_invitation",
            "request_follow_up",
            "reopen_follow_up",
            "set_legal_hold",
            "purge_expired",
            "verify_integrity",
        )
        if any(not callable(getattr(store, name, None)) for name in required):
            raise HTTPException(
                status_code=503,
                detail="third-party collaboration authority unavailable",
            )
        return ops, tenant, store

    @router.get("/status")
    async def status(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        if not _enabled():
            return {
                "schema": "lightwork.third-party-collaboration-api-status.v1",
                "enabled": False,
                "external_portal_configured": False,
                "network_transport_implemented": False,
                "email_delivery_implemented": False,
                "upload_bytes_implemented": False,
                "vendor_identity_independently_verified": False,
            }
        _ops_value, _tenant, _store = authority(request)
        return {
            "schema": "lightwork.third-party-collaboration-api-status.v1",
            "enabled": True,
            "external_portal_configured": callable(
                getattr(
                    request.app.state,
                    "third_party_collaboration_portal_resolver",
                    None,
                )
            ),
            "network_transport_implemented": False,
            "email_delivery_implemented": False,
            "upload_bytes_implemented": False,
            "vendor_identity_independently_verified": False,
        }

    @router.get("/sharing")
    async def sharing(request: Request) -> dict[str, Any]:
        """Where vendors answer, and the limits an invitation must fit in, so
        the invite form offers only choices the portal will accept."""
        require_permission(request, "admin")
        ops, _tenant, _store = authority(request)
        return _sharing(request, ops)

    @router.get("/invitations")
    async def list_invitations(
        request: Request,
        limit: int = Query(default=100, ge=1, le=500),
        after: str | None = Query(default=None, min_length=1, max_length=128),
    ) -> dict[str, Any]:
        require_permission(request, "audit")
        ops, tenant, store = authority(request)
        return await _call(ops, store.list_invitations, tenant, limit=limit, after=after)

    @router.get("/invitations/{invitation_id}")
    async def get_invitation(request: Request, invitation_id: ObjectPath) -> dict[str, Any]:
        require_permission(request, "audit")
        ops, tenant, store = authority(request)
        return await _call(ops, store.get_invitation, tenant, invitation_id)

    @router.post("/invitations", status_code=201)
    async def issue_invitation(
        body: IssueInvitationIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        result = await _call(
            ops,
            store.issue_invitation,
            tenant,
            body.invitation_id,
            assessment_id=body.assessment_id,
            respondent_ref=body.respondent_ref,
            allowed_question_ids=body.allowed_question_ids,
            notice_ref=body.notice_ref,
            notice_sha256=body.notice_sha256,
            artifact_policy=body.artifact_policy.model_dump(),
            expires_in_seconds=body.expires_in_seconds,
            retention_seconds=body.retention_seconds,
            idempotency_key=body.idempotency_key,
        )
        _private(response)
        return result

    @router.post("/invitations/{invitation_id}/rotate")
    async def rotate_invitation(
        invitation_id: ObjectPath,
        body: RotateInvitationIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        result = await _call(
            ops,
            store.rotate_invitation,
            tenant,
            invitation_id,
            **body.model_dump(),
        )
        _private(response)
        return result

    @router.post("/invitations/{invitation_id}/revoke")
    async def revoke_invitation(
        invitation_id: ObjectPath,
        body: RevokeInvitationIn,
        request: Request,
    ) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        return await _call(
            ops,
            store.revoke_invitation,
            tenant,
            invitation_id,
            **body.model_dump(),
        )

    @router.post("/invitations/{invitation_id}/follow-up")
    async def request_follow_up(
        invitation_id: ObjectPath,
        body: FollowUpIn,
        request: Request,
    ) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        return await _call(
            ops,
            store.request_follow_up,
            tenant,
            invitation_id,
            **body.model_dump(),
        )

    @router.post("/invitations/{invitation_id}/follow-up/reopen")
    async def reopen_follow_up(
        invitation_id: ObjectPath,
        body: RotateInvitationIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        result = await _call(
            ops,
            store.reopen_follow_up,
            tenant,
            invitation_id,
            **body.model_dump(),
        )
        _private(response)
        return result

    @router.post("/invitations/{invitation_id}/legal-hold")
    async def set_legal_hold(
        invitation_id: ObjectPath,
        body: LegalHoldIn,
        request: Request,
    ) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        return await _call(
            ops,
            store.set_legal_hold,
            tenant,
            invitation_id,
            **body.model_dump(),
        )

    @router.post("/purge")
    async def purge(body: PurgeIn, request: Request) -> dict[str, Any]:
        require_permission(request, "admin")
        ops, tenant, store = authority(request)
        return await _call(ops, store.purge_expired, tenant, **body.model_dump())

    @router.get("/integrity")
    async def integrity(request: Request) -> dict[str, Any]:
        require_permission(request, "audit")
        ops, tenant, store = authority(request)
        return await _call(ops, store.verify_integrity, tenant)

    return router


def _invitation_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, separator, value = header.partition(" ")
    if separator != " " or scheme != "ThirdPartyInvitation" or not _TOKEN_RE.fullmatch(value):
        raise HTTPException(status_code=404, detail="invitation unavailable")
    return value


def _evidence_measurer(store: Any) -> Callable[..., Any]:
    measure = getattr(store, "measure_evidence", None)
    if not callable(measure):
        raise HTTPException(status_code=404, detail="invitation unavailable")
    return measure


def _matching_measurement(
    result: dict[str, Any],
    declared: int,
    contract: Mapping[str, Any],
) -> dict[str, Any]:
    """The store must report exactly the bytes received, for this invitation."""

    if result["size_bytes"] != declared or result["invitation_id"] != contract["invitation_id"]:
        raise HTTPException(status_code=503, detail="invitation authority unavailable")
    return result


def _evidence_request(request: Request) -> tuple[str | None, int]:
    """Check an evidence upload's headers before any of its body is read."""

    origin = request.headers.get("origin")
    if origin is not None and urlparse(origin).netloc != request.url.netloc:
        raise HTTPException(status_code=403, detail="cross-site upload blocked")
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/octet-stream":
        raise HTTPException(status_code=415, detail="evidence must be sent as file bytes")
    extension = request.headers.get(_EVIDENCE_EXTENSION_HEADER)
    if extension is not None and not _EXTENSION_RE.fullmatch(extension):
        raise HTTPException(status_code=422, detail="submission is invalid")
    declared_header = request.headers.get("content-length")
    if declared_header is None:
        raise HTTPException(status_code=411, detail="file size is required")
    try:
        declared = int(declared_header)
    except ValueError:
        raise HTTPException(status_code=400, detail="file size is invalid") from None
    if declared < 1:
        raise HTTPException(status_code=422, detail="submission is invalid")
    return extension, declared


async def _read_evidence(request: Request, declared: int, policy: Mapping[str, Any]) -> bytes:
    """Stream at most the invitation's byte bound, and exactly the declared size."""

    maximum = int(policy["maximum_total_bytes"])
    if int(policy["maximum_artifacts"]) == 0 or maximum == 0:
        raise HTTPException(status_code=403, detail="submission is outside the invitation")
    if declared > maximum:
        raise HTTPException(status_code=413, detail="file is larger than the invitation allows")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > declared:
            raise HTTPException(status_code=413, detail="file is larger than the invitation allows")
    if len(body) != declared:
        raise HTTPException(status_code=400, detail="file was not received completely")
    return bytes(body)


def create_external_third_party_collaboration_router(
    dependencies: ThirdPartyCollaborationDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ThirdPartyCollaborationDependencies()
    router = APIRouter(
        prefix="/api/v1/external/third-party-collaboration",
        tags=["external-third-party-collaboration"],
    )

    def authority(
        portal_ref: str,
        request: Request,
        action: str,
    ) -> tuple[Any, ExternalPortalAuthority, str]:
        if not _enabled():
            raise HTTPException(status_code=404, detail="invitation unavailable")
        ops = _ops()
        if request.query_params or any(
            request.headers.get(name)
            for name in ("x-lightwork-tenant", "x-maverick-tenant", "x-tenant-id")
        ):
            raise HTTPException(status_code=404, detail="invitation unavailable")
        token = _invitation_token(request)
        resolver = getattr(
            request.app.state,
            "third_party_collaboration_portal_resolver",
            None,
        )
        selected = resolver if callable(resolver) else deps.portal_resolver
        limiter = getattr(
            request.app.state,
            "third_party_collaboration_rate_limit",
            None,
        )
        selected_limiter = limiter if callable(limiter) else deps.external_rate_limit
        if not callable(selected) or not callable(selected_limiter):
            raise HTTPException(status_code=404, detail="invitation unavailable")
        credential_sha256 = hashlib.sha256(token.encode("ascii")).hexdigest()
        try:
            selected_limiter(credential_sha256, action)
            material = selected(portal_ref, request)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=404, detail="invitation unavailable") from exc
        if not isinstance(material, ExternalPortalAuthority):
            raise HTTPException(status_code=404, detail="invitation unavailable")
        required = ("contract_for_token", "save_draft", "finalize_submission")
        if (
            not isinstance(material.tenant_id, str)
            or not material.tenant_id
            or any(not callable(getattr(material.store, name, None)) for name in required)
        ):
            raise HTTPException(status_code=404, detail="invitation unavailable")
        return ops, material, token

    async def external_call(
        ops: Any,
        function: Callable[..., Any],
        *args: Any,
        kind: Literal["contract", "draft", "final", "evidence"],
        tenant_id: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        try:
            result = await run_in_threadpool(function, *args, **kwargs)
        except (
            ops.ThirdPartyCollaborationAuthError,
            ops.ThirdPartyCollaborationNotFound,
        ) as exc:
            raise HTTPException(status_code=404, detail="invitation unavailable") from exc
        except ops.ThirdPartyCollaborationPermissionDenied as exc:
            raise HTTPException(status_code=403, detail="submission is outside the invitation") from exc
        except ops.ThirdPartyCollaborationConflict as exc:
            raise HTTPException(status_code=409, detail="invitation state changed") from exc
        except ops.ThirdPartyCollaborationValidationError as exc:
            raise HTTPException(status_code=422, detail="submission is invalid") from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="invitation authority unavailable") from exc
        return _external_safe(result, kind=kind, tenant_id=tenant_id)

    @router.get("/{portal_ref}/contract")
    async def contract(
        portal_ref: PortalPath,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        ops, material, token = authority(portal_ref, request, "contract")
        result = await external_call(
            ops,
            material.store.contract_for_token,
            material.tenant_id,
            token,
            kind="contract",
            tenant_id=material.tenant_id,
        )
        _private(response)
        return result

    @router.post("/{portal_ref}/evidence")
    async def measure_evidence(
        portal_ref: PortalPath,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        """Measure one evidence file; its bytes are read only after the invitation
        is authenticated, only up to that invitation's own bound, and are not kept."""

        ops, material, token = authority(portal_ref, request, "evidence")
        measure = _evidence_measurer(material.store)
        extension, declared = _evidence_request(request)
        contract = await external_call(
            ops,
            material.store.contract_for_token,
            material.tenant_id,
            token,
            kind="contract",
            tenant_id=material.tenant_id,
        )
        content = await _read_evidence(request, declared, contract["artifact_policy"])
        result = await external_call(
            ops,
            measure,
            material.tenant_id,
            token,
            content=content,
            file_extension=extension,
            kind="evidence",
            tenant_id=material.tenant_id,
        )
        _private(response)
        return _matching_measurement(result, declared, contract)

    @router.put("/{portal_ref}/draft")
    async def save_draft(
        portal_ref: PortalPath,
        body: DraftIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        ops, material, token = authority(portal_ref, request, "draft")
        result = await external_call(
            ops,
            material.store.save_draft,
            material.tenant_id,
            token,
            answers={key: value.model_dump() for key, value in body.answers.items()},
            artifacts=[item.model_dump() for item in body.artifacts],
            expected_revision=body.expected_revision,
            idempotency_key=body.idempotency_key,
            kind="draft",
            tenant_id=material.tenant_id,
        )
        _private(response)
        return result

    @router.post("/{portal_ref}/finalize")
    async def finalize(
        portal_ref: PortalPath,
        body: FinalizeIn,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        ops, material, token = authority(portal_ref, request, "finalize")
        result = await external_call(
            ops,
            material.store.finalize_submission,
            material.tenant_id,
            token,
            answers={key: value.model_dump() for key, value in body.answers.items()},
            artifacts=[item.model_dump() for item in body.artifacts],
            attested=body.attested,
            expected_draft_revision=body.expected_draft_revision,
            idempotency_key=body.idempotency_key,
            kind="final",
            tenant_id=material.tenant_id,
        )
        _private(response)
        return result

    return router


router = create_third_party_collaboration_router()
external_router = create_external_third_party_collaboration_router()

__all__ = [
    "ExternalPortalAuthority",
    "ThirdPartyCollaborationDependencies",
    "create_external_third_party_collaboration_router",
    "create_third_party_collaboration_router",
    "external_router",
    "router",
    "third_party_collaboration_enabled_for_page",
]
