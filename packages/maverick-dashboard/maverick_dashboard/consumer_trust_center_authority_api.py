"""Authenticated operator API for persisted consumer Trust Center authority.

Tenant and operator identity are derived from authenticated server context.  The
consumer/property/profile binding, principal permission authority, and signing
key are constructor-bound trusted resolvers; none can be selected or supplied
by a browser request.  The API exposes only closed, digest-only lifecycle
metadata and delegates every four-eyes, CAS, retention, and integrity invariant
to :mod:`maverick.consumer_trust_center_authority`.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable, Mapping
from dataclasses import asdict, fields, is_dataclass
from typing import Annotated, Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator
from starlette.concurrency import run_in_threadpool

from ._shared import authenticated_subject
from .auth import require_global_permission, require_permission

_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_OP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}$"
_DIGEST_PATTERN = r"^[0-9a-f]{64}$"
_KEY_REF_PATTERN = r"^(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$"
_SCHEMA_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_CLOSED_TEXT_RE = re.compile(_ID_PATTERN)
_MAX_EXPORT_BYTES = 2 * 1024 * 1024
_PRIVATE_HEADERS = {
    "Cache-Control": "no-store, private",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}

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
CredentialRef = Annotated[
    str,
    StringConstraints(strict=True, min_length=5, max_length=128, pattern=_KEY_REF_PATTERN),
]
SchemaRef = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128, pattern=_SCHEMA_PATTERN),
]
ObjectKind = Literal["context", "grant", "rights_authorization"]


class _GenericValidationRoute(APIRoute):
    """Never reflect rejected authority metadata or credential-shaped input."""

    def get_route_handler(self):
        original = super().get_route_handler()

        async def handler(request: Request):
            try:
                response = await original(request)
            except RequestValidationError as exc:
                raise HTTPException(
                    status_code=422,
                    detail="Trust Center authority request is invalid",
                    headers=_PRIVATE_HEADERS,
                ) from exc
            except HTTPException as exc:
                headers = dict(_PRIVATE_HEADERS)
                headers.update(exc.headers or {})
                exc.headers = headers
                raise
            for key, value in _PRIVATE_HEADERS.items():
                response.headers.setdefault(key, value)
            return response

        return handler


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ContextCreateIn(_StrictModel):
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    publication_history_limit: int = Field(default=25, ge=1, le=100)
    receipt_limit: int = Field(default=25, ge=1, le=100)
    idempotency_key: IdempotencyKey


class PrivacyRightsContextPrepareIn(ContextCreateIn):
    """Non-secret selectors for an operator-prepared rights intake context."""

    client_credential_id: OpaqueId
    property_id: OpaqueId
    profile_id: OpaqueId
    expected_client_revision: int = Field(ge=1, le=2_147_483_647)
    expected_profile_revision: int = Field(ge=0, le=2_147_483_647)


class ContextReviseIn(ContextCreateIn):
    expected_revision: int = Field(ge=1, le=2_147_483_647)


class RevisionIn(_StrictModel):
    expected_revision: int = Field(ge=1, le=2_147_483_647)
    idempotency_key: IdempotencyKey


class ChildRevisionIn(RevisionIn):
    expected_context_revision: int = Field(ge=1, le=2_147_483_647)


class CapabilityProposalIn(_StrictModel):
    capability: OpaqueId
    expected_context_revision: int = Field(ge=1, le=2_147_483_647)
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class RightsAuthorizationProposalIn(_StrictModel):
    case_id: OpaqueId
    expected_case_sha256: Digest
    expected_context_revision: int = Field(ge=1, le=2_147_483_647)
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class RightsCaseAuthorizationIn(_StrictModel):
    """Choose a privacy request; its fingerprint is read on the server."""

    case_id: OpaqueId
    expected_context_revision: int = Field(ge=1, le=2_147_483_647)
    valid_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    idempotency_key: IdempotencyKey


class ExportCreateIn(_StrictModel):
    idempotency_key: IdempotencyKey


class SignedExportIn(_StrictModel):
    schema_ref: SchemaRef = Field(alias="schema")
    export_id: OpaqueId
    tenant_sha256: Digest
    context_ref: OpaqueId
    signing_key_ref: CredentialRef
    payload: dict[str, Any]
    payload_sha256: Digest
    signature_sha256: Digest
    retained_until: float | int = Field(gt=0, lt=100_000_000_000.0)
    created_at: float | int = Field(gt=0, lt=100_000_000_000.0)

    @model_validator(mode="after")
    def bounded_payload(self):
        try:
            encoded = json.dumps(
                self.payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("signed export payload is invalid") from exc
        if len(encoded) > _MAX_EXPORT_BYTES:
            raise ValueError("signed export payload is too large")
        return self


class PurgeIn(_StrictModel):
    before: float | int = Field(gt=0, lt=100_000_000_000.0)
    limit: int = Field(default=100, ge=1, le=500)
    idempotency_key: IdempotencyKey


def _enabled() -> bool:
    from maverick.consumer_trust_center import trust_center_enabled

    return trust_center_enabled()


def consumer_trust_center_authority_enabled_for_page() -> bool:
    """Read the exact nested gate without opening tenant storage."""

    return _enabled()


def _ops():
    from maverick import consumer_trust_center as trust_center
    from maverick import consumer_trust_center_authority as authority

    try:
        trust_center.require_trust_center_enabled()
    except trust_center.TrustCenterDisabled as exc:
        raise HTTPException(
            status_code=403,
            detail="consumer Trust Center authority is disabled",
        ) from exc
    return authority, trust_center


def _tenant_id() -> str:
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using Trust Center authority",
        )
    return tenant


def _principal(request: Request, tenant_id: str) -> str:
    subject = authenticated_subject(
        request, error_detail="an authenticated principal is required for Trust Center authority",
    )
    digest = hashlib.sha256(
        (f"lightwork.consumer-trust-center-authority.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"tca-principal-{digest[:32]}"


def _private(response: Response) -> None:
    for key, value in _PRIVATE_HEADERS.items():
        response.headers[key] = value


def _closed_jsonable(value: Any) -> Any:
    """Serialize only the authority module's closed metadata vocabulary."""

    if is_dataclass(value) and not isinstance(value, type):
        return _closed_jsonable(asdict(value))
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        if len(value) > 512:
            raise ValueError("authority mapping is too large")
        for key, item in value.items():
            if not isinstance(key, str) or not _CLOSED_TEXT_RE.fullmatch(key):
                raise ValueError("authority mapping key is not closed")
            result[key] = _closed_jsonable(item)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 500:
            raise ValueError("authority sequence is too large")
        return [_closed_jsonable(item) for item in value]
    if isinstance(value, str):
        if not _CLOSED_TEXT_RE.fullmatch(value):
            raise ValueError("authority text is not closed")
        return value
    if isinstance(value, bool) or value is None:
        return value
    if type(value) is int:
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise ValueError("authority output contains an unsupported value")


def _safe(value: Any) -> Any:
    try:
        return _closed_jsonable(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(
            status_code=503,
            detail="Trust Center authority returned an invalid contract",
        ) from exc


def _expect(value: Any, expected: type) -> Any:
    if not isinstance(value, expected):
        raise HTTPException(
            status_code=503,
            detail="Trust Center authority returned an invalid contract",
        )
    return value


def _exact_export(ops, body: SignedExportIn):
    payload = body.payload
    expected_top = {
        "schema",
        "tenant_sha256",
        "context",
        "capability_grants",
        "rights_authorizations",
        "boundaries",
    }
    if set(payload) != expected_top:
        raise HTTPException(
            status_code=422,
            detail="Trust Center authority request is invalid",
        )
    expected_fields = ((payload.get("context"), ops.TrustCenterContextAuthority),)
    grants = payload.get("capability_grants")
    rights = payload.get("rights_authorizations")
    boundaries = payload.get("boundaries")
    if (
        any(
            not isinstance(item, Mapping) or set(item) != {field.name for field in fields(model)}
            for item, model in expected_fields
        )
        or not isinstance(grants, list)
        or len(grants) > 500
        or any(
            not isinstance(item, Mapping)
            or set(item) != {field.name for field in fields(ops.CapabilityGrantAuthority)}
            for item in grants
        )
        or not isinstance(rights, list)
        or len(rights) > 500
        or any(
            not isinstance(item, Mapping)
            or set(item) != {field.name for field in fields(ops.RightsCaseAuthorizationAuthority)}
            for item in rights
        )
        or not isinstance(boundaries, Mapping)
        or set(boundaries) != set(ops.ConsumerTrustCenterAuthorityStore.product_boundaries())
    ):
        raise HTTPException(
            status_code=422,
            detail="Trust Center authority request is invalid",
        )
    try:
        _closed_jsonable(payload)
        return ops.SignedTrustCenterAuthorityExport(**body.model_dump(by_alias=True))
    except (TypeError, ValueError, UnicodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail="Trust Center authority request is invalid",
        ) from exc


def _default_store_for(
    request: Request,
    tenant_id: str,
    principal_ref: str,
):
    """Open tenant-local state only when every server authority is injected."""

    from maverick.consumer_trust_center_authority import (
        ConsumerTrustCenterAuthorityStore,
        TrustCenterAuthorityConfigError,
    )
    from maverick.paths import data_dir

    state = request.app.state
    binding_factory = getattr(
        state,
        "consumer_trust_center_authority_binding_resolver_factory",
        None,
    )
    principal_factory = getattr(
        state,
        "consumer_trust_center_authority_principal_resolver_factory",
        None,
    )
    signing_key_resolver = getattr(
        state,
        "consumer_trust_center_authority_signing_key_resolver",
        None,
    )
    if not all(
        callable(value) for value in (binding_factory, principal_factory, signing_key_resolver)
    ):
        raise TrustCenterAuthorityConfigError(
            "binding, principal-authority, and signing-key resolvers are required"
        )
    context = {
        "tenant_id": tenant_id,
        "principal_ref": principal_ref,
        "request": request,
    }
    binding_resolver = binding_factory(**context)
    principal_resolver = principal_factory(**context)
    if not callable(binding_resolver) or not callable(principal_resolver):
        raise TrustCenterAuthorityConfigError(
            "Trust Center authority resolver factories returned an invalid boundary"
        )
    signing_key_ref = getattr(
        state,
        "consumer_trust_center_authority_signing_key_ref",
        "env:MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY",
    )
    return ConsumerTrustCenterAuthorityStore(
        data_dir(
            "consent_preferences",
            "consumer-trust-center-authority.sqlite3",
            tenant=tenant_id,
        ),
        binding_resolver=binding_resolver,
        principal_authority_resolver=principal_resolver,
        signing_key_resolver=signing_key_resolver,
        signing_key_ref=signing_key_ref,
    )


class ConsumerTrustCenterAuthorityDependencies:
    """Explicit tenant/principal-bound store seam for runtimes and tests."""

    def __init__(
        self,
        *,
        store_for: Callable[[Request, str, str], Any] = _default_store_for,
    ) -> None:
        self.store_for = store_for


def create_consumer_trust_center_authority_router(  # noqa: C901, PLR0915
    dependencies: ConsumerTrustCenterAuthorityDependencies | None = None,
) -> APIRouter:
    deps = dependencies or ConsumerTrustCenterAuthorityDependencies()
    router = APIRouter(
        prefix="/consent/trust-center-authority",
        tags=["consumer-trust-center-authority"],
        route_class=_GenericValidationRoute,
    )

    def authority(request: Request):
        ops, trust_center = _ops()
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        factory = getattr(
            request.app.state,
            "consumer_trust_center_authority_store_factory",
            None,
        )

        def principal_resolver() -> str:
            return principal

        try:
            store = (
                factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=principal_resolver,
                    request=request,
                )
                if callable(factory)
                else deps.store_for(request, tenant, principal)
            )
        except (trust_center.ConsumerTrustCenterError, OSError) as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority is unavailable",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority is unavailable",
            ) from exc
        required = (
            "create_context",
            "revise_context",
            "revoke_context",
            "propose_capability_grant",
            "approve_capability_grant",
            "revoke_capability_grant",
            "propose_rights_authorization",
            "approve_rights_authorization",
            "revoke_rights_authorization",
            "get_context_authority",
            "export_signed_metadata",
            "get_signed_metadata",
            "verify_signed_metadata",
            "retention_due",
            "purge_expired",
            "history",
            "verify_integrity",
        )
        if store is None or any(not callable(getattr(store, name, None)) for name in required):
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        return ops, trust_center, tenant, store

    async def call(ops, trust_center, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except ops.TrustCenterAuthorityNotFound as exc:
            raise HTTPException(
                status_code=404,
                detail="Trust Center authority record was not found",
            ) from exc
        except ops.TrustCenterAuthorityPermissionDenied as exc:
            raise HTTPException(
                status_code=403,
                detail="Trust Center authority operation is not authorized",
            ) from exc
        except trust_center.TrustCenterDisabled as exc:
            raise HTTPException(
                status_code=403,
                detail="consumer Trust Center authority is disabled",
            ) from exc
        except trust_center.TrustCenterConflict as exc:
            raise HTTPException(
                status_code=409,
                detail="Trust Center authority state conflict",
            ) from exc
        except trust_center.TrustCenterValidationError as exc:
            raise HTTPException(
                status_code=422,
                detail="Trust Center authority request is invalid",
            ) from exc
        except trust_center.TrustCenterIntegrityError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority integrity verification failed",
            ) from exc
        except ops.TrustCenterAuthorityConfigError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority is unavailable",
            ) from exc
        except trust_center.ConsumerTrustCenterError as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority operation failed",
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority operation failed",
            ) from exc

    @router.get("/status")
    async def status(request: Request, response: Response) -> dict[str, Any]:
        require_permission(request, "view")
        _private(response)
        tenant = _tenant_id()
        principal = _principal(request, tenant)
        from maverick import consumer_trust_center_authority as ops

        state = request.app.state
        return _safe(
            {
                "schema": "lightwork.consumer-trust-center-authority-status.v1",
                "enabled": _enabled(),
                "principal_ref": principal,
                "supported_capabilities": tuple(sorted(ops.CAPABILITIES)),
                **ops.ConsumerTrustCenterAuthorityStore.product_boundaries(),
                "server_authority": {
                    "store_factory_configured": callable(
                        getattr(state, "consumer_trust_center_authority_store_factory", None)
                    ),
                    "binding_resolver_factory_configured": callable(
                        getattr(
                            state,
                            "consumer_trust_center_authority_binding_resolver_factory",
                            None,
                        )
                    ),
                    "principal_resolver_factory_configured": callable(
                        getattr(
                            state,
                            "consumer_trust_center_authority_principal_resolver_factory",
                            None,
                        )
                    ),
                    "signing_key_resolver_configured": callable(
                        getattr(
                            state,
                            "consumer_trust_center_authority_signing_key_resolver",
                            None,
                        )
                    ),
                    "rights_intake_pairing_verifier_configured": callable(
                        getattr(
                            state,
                            "consumer_trust_center_authority_pairing_verifier",
                            None,
                        )
                    ),
                },
                "tenant_or_principal_selector_accepted": False,
                "raw_consumer_binding_accepted": False,
                "raw_signing_key_accepted": False,
                "status_request_opens_tenant_storage": False,
            }
        )

    @router.put("/contexts/{context_ref}", status_code=201)
    async def create_context(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: ContextCreateIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, _tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.create_context,
                    context_ref=context_ref,
                    **body.model_dump(),
                ),
                ops.TrustCenterContextAuthority,
            )
        )

    @router.post("/privacy-rights-contexts/prepare", status_code=201)
    async def prepare_privacy_rights_context(
        request: Request,
        response: Response,
        body: PrivacyRightsContextPrepareIn,
    ) -> dict[str, Any]:
        """Prepare one context; capability proposal and approvals stay separate."""

        require_global_permission(request, "admin")
        _private(response)
        tenant = _tenant_id()
        public_factory = getattr(
            request.app.state,
            "privacy_rights_intake_public_dependencies_factory",
            None,
        )
        pairing_verifier = getattr(
            request.app.state,
            "consumer_trust_center_authority_pairing_verifier",
            None,
        )
        if not callable(public_factory) or not callable(pairing_verifier):
            raise HTTPException(
                status_code=503,
                detail="privacy-rights context preparation is unavailable",
            )
        try:
            from maverick.consent_identity_federation import (
                ConsentIdentityEvidence,
                ConsentPairingContext,
            )

            from .consent_identity_federation_api import resolve_consent_pairing_context
            from .consent_public_api import PublicConsentDependencies
            from .privacy_rights_intake_composition import (
                privacy_rights_intake_trust_context_ref,
            )

            public = public_factory(request=request)
            if not isinstance(public, PublicConsentDependencies):
                raise TypeError("public consent dependency contract is invalid")
            client, profile = await run_in_threadpool(
                public.credential_store.resolve_pairing_authority_by_admin_refs,
                tenant,
                body.client_credential_id,
                body.property_id,
                body.profile_id,
                expected_client_revision=body.expected_client_revision,
            )
            pairing = await run_in_threadpool(
                resolve_consent_pairing_context,
                public,
                client,
                profile,
            )
            if (
                not isinstance(pairing, ConsentPairingContext)
                or pairing.tenant_id != tenant
                or pairing.client_revision != body.expected_client_revision
                or pairing.profile_revision != body.expected_profile_revision
            ):
                raise ValueError("public pairing authority changed")
            verified_pairing = await run_in_threadpool(
                pairing_verifier,
                request=request,
                pairing=pairing,
            )
            if not isinstance(verified_pairing, ConsentIdentityEvidence):
                raise ValueError("redeemed identity authority is unavailable")
            context_ref = privacy_rights_intake_trust_context_ref(pairing)
            await run_in_threadpool(
                public.credential_store.register_rights_intake_context,
                context_ref,
                client,
                profile,
            )
        except HTTPException:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            # The selector and identity boundaries are deliberately generic:
            # neither tenant membership nor credential/profile digests become
            # an enumeration oracle through this authenticated route.
            raise HTTPException(
                status_code=409,
                detail="privacy-rights context authority is not current",
            ) from exc

        ops, trust_center, _tenant, store = authority(request)
        context = _expect(
            await call(
                ops,
                trust_center,
                store.create_context,
                context_ref=context_ref,
                valid_until=body.valid_until,
                retained_until=body.retained_until,
                publication_history_limit=body.publication_history_limit,
                receipt_limit=body.receipt_limit,
                idempotency_key=body.idempotency_key,
            ),
            ops.TrustCenterContextAuthority,
        )
        return _safe(
            {
                "schema": "lightwork.privacy-rights-context-preparation.v1",
                "context_ref": context.context_ref,
                "context_revision": context.revision,
                "status": context.status,
                "required_capability": "rights_cases",
                "capability_grant_created": False,
                "distinct_approvals_required": 2,
                "next_action": "propose_rights_cases_capability_grant",
            }
        )

    @router.get("/contexts/{context_ref}")
    async def get_context(request: Request, response: Response, context_ref: ObjectPath):
        require_permission(request, "view")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.get_context_authority,
                    tenant,
                    context_ref,
                ),
                ops.TrustCenterContextAuthority,
            )
        )

    @router.patch("/contexts/{context_ref}")
    async def revise_context(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: ContextReviseIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.revise_context,
                    tenant,
                    context_ref,
                    **body.model_dump(),
                ),
                ops.TrustCenterContextAuthority,
            )
        )

    @router.post("/contexts/{context_ref}/revoke")
    async def revoke_context(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: RevisionIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.revoke_context,
                    tenant,
                    context_ref,
                    **body.model_dump(),
                ),
                ops.TrustCenterContextAuthority,
            )
        )

    @router.post("/contexts/{context_ref}/capability-grants", status_code=201)
    async def propose_capability_grant(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: CapabilityProposalIn,
    ):
        require_permission(request, "operate")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.propose_capability_grant,
                    tenant,
                    context_ref,
                    body.capability,
                    expected_context_revision=body.expected_context_revision,
                    valid_until=body.valid_until,
                    idempotency_key=body.idempotency_key,
                ),
                ops.CapabilityGrantAuthority,
            )
        )

    @router.post("/capability-grants/{grant_ref}/approve")
    async def approve_capability_grant(
        request: Request,
        response: Response,
        grant_ref: ObjectPath,
        body: ChildRevisionIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.approve_capability_grant,
                    tenant,
                    grant_ref,
                    **body.model_dump(),
                ),
                ops.CapabilityGrantAuthority,
            )
        )

    @router.post("/capability-grants/{grant_ref}/revoke")
    async def revoke_capability_grant(
        request: Request,
        response: Response,
        grant_ref: ObjectPath,
        body: ChildRevisionIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.revoke_capability_grant,
                    tenant,
                    grant_ref,
                    **body.model_dump(),
                ),
                ops.CapabilityGrantAuthority,
            )
        )

    @router.post("/contexts/{context_ref}/rights-authorizations", status_code=201)
    async def propose_rights_authorization(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: RightsAuthorizationProposalIn,
    ):
        require_permission(request, "operate")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.propose_rights_authorization,
                    tenant,
                    context_ref,
                    body.case_id,
                    body.expected_case_sha256,
                    expected_context_revision=body.expected_context_revision,
                    valid_until=body.valid_until,
                    idempotency_key=body.idempotency_key,
                ),
                ops.RightsCaseAuthorizationAuthority,
            )
        )

    @router.post("/rights-authorizations/{authorization_ref}/approve")
    async def approve_rights_authorization(
        request: Request,
        response: Response,
        authorization_ref: ObjectPath,
        body: ChildRevisionIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.approve_rights_authorization,
                    tenant,
                    authorization_ref,
                    **body.model_dump(),
                ),
                ops.RightsCaseAuthorizationAuthority,
            )
        )

    @router.post("/rights-authorizations/{authorization_ref}/revoke")
    async def revoke_rights_authorization(
        request: Request,
        response: Response,
        authorization_ref: ObjectPath,
        body: ChildRevisionIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.revoke_rights_authorization,
                    tenant,
                    authorization_ref,
                    **body.model_dump(),
                ),
                ops.RightsCaseAuthorizationAuthority,
            )
        )

    @router.get("/history/{object_kind}/{object_ref}")
    async def history(
        request: Request,
        response: Response,
        object_kind: ObjectKind,
        object_ref: ObjectPath,
        limit: int = Query(default=100, ge=1, le=100),
    ):
        require_permission(request, "view")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        items = await call(
            ops,
            trust_center,
            store.history,
            tenant,
            object_kind,
            object_ref,
            limit=limit,
        )
        if not isinstance(items, tuple):
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        return _safe({"items": items, "count": len(items)})

    @router.post("/contexts/{context_ref}/exports", status_code=201)
    async def create_export(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: ExportCreateIn,
    ):
        require_permission(request, "operate")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        exported = _expect(
            await call(
                ops,
                trust_center,
                store.export_signed_metadata,
                tenant,
                context_ref,
                **body.model_dump(),
            ),
            ops.SignedTrustCenterAuthorityExport,
        )
        verified = await call(
            ops,
            trust_center,
            store.verify_signed_metadata,
            exported,
        )
        if type(verified) is not bool:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        return _safe({"export": exported, "valid": verified})

    @router.post("/exports/verify")
    async def verify_export(
        request: Request,
        response: Response,
        body: SignedExportIn,
    ):
        require_global_permission(request, "audit")
        _private(response)
        ops, trust_center, _tenant, store = authority(request)
        exported = _exact_export(ops, body)
        verified = await call(
            ops,
            trust_center,
            store.verify_signed_metadata,
            exported,
        )
        if type(verified) is not bool:
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        return _safe(
            {
                "schema": "lightwork.consumer-trust-center-authority-verification.v1",
                "valid": verified,
            }
        )

    @router.get("/exports/{export_id}")
    async def get_export(
        request: Request,
        response: Response,
        export_id: ObjectPath,
    ):
        require_global_permission(request, "audit")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        exported = _expect(
            await call(
                ops,
                trust_center,
                store.get_signed_metadata,
                tenant,
                export_id,
            ),
            ops.SignedTrustCenterAuthorityExport,
        )
        return _safe({"export": exported, "valid": True})

    @router.get("/retention/due")
    async def retention_due(
        request: Request,
        response: Response,
        before: float = Query(gt=0, lt=100_000_000_000.0),
        limit: int = Query(default=100, ge=1, le=500),
    ):
        require_global_permission(request, "audit")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        contexts = await call(
            ops,
            trust_center,
            store.retention_due,
            tenant,
            before=before,
            limit=limit,
        )
        if not isinstance(contexts, tuple):
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        return _safe({"contexts": contexts, "count": len(contexts)})

    @router.post("/retention/purge")
    async def purge_retention(
        request: Request,
        response: Response,
        body: PurgeIn,
    ):
        require_global_permission(request, "admin")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        result = await call(
            ops,
            trust_center,
            store.purge_expired,
            tenant,
            **body.model_dump(),
        )
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        return _safe(result)

    @router.get("/integrity")
    async def integrity(request: Request, response: Response):
        require_global_permission(request, "audit")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        result = await call(
            ops,
            trust_center,
            store.verify_integrity,
            tenant,
        )
        if not isinstance(result, Mapping):
            raise HTTPException(
                status_code=503,
                detail="Trust Center authority returned an invalid contract",
            )
        payload = dict(result)
        payload["valid"] = True
        return _safe(payload)

    def _labels(tenant: str) -> dict[str, str]:
        """Readable website and person references for stored digests (best effort)."""

        labels: dict[str, str] = {}
        try:
            from .consent_public_admin_api import _enabled as public_enabled
            from .consent_public_admin_api import _registry

            if not public_enabled():
                return labels
            listed = _registry().list_profile_bindings(tenant, limit=500)
        except Exception:
            return labels
        for item in listed.get("items", []):
            for key in ("property_id", "profile_id"):
                value = item.get(key)
                if isinstance(value, str) and _CLOSED_TEXT_RE.fullmatch(value):
                    labels[hashlib.sha256(value.encode("utf-8")).hexdigest()] = value
        return labels

    @router.get("/overview")
    async def overview(request: Request, response: Response) -> dict[str, Any]:
        """Every context, grant and rights authorization, with the viewer's role."""

        require_permission(request, "view")
        _private(response)
        ops, trust_center, tenant, store = authority(request)
        lister = getattr(store, "list_authority", None)
        if not callable(lister):
            raise HTTPException(status_code=503, detail="Trust Center authority is unavailable")
        listed = await call(ops, trust_center, lister, tenant, limit=100)
        me = hashlib.sha256(_principal(request, tenant).encode("utf-8")).hexdigest()
        labels = await run_in_threadpool(_labels, tenant)

        def contexts(item: Any) -> dict[str, Any]:
            return {
                "context_ref": item.context_ref,
                "property_label": labels.get(item.property_sha256),
                "profile_label": labels.get(item.profile_sha256),
                "status": item.status,
                "valid_until": item.valid_until,
                "retained_until": item.retained_until,
                "publication_history_limit": item.publication_history_limit,
                "receipt_limit": item.receipt_limit,
                "revision": item.revision,
                "created_at": item.created_at,
            }

        def child(item: Any, ref_field: str, extra: dict[str, Any]) -> dict[str, Any]:
            approvals = [
                value
                for value in (item.approved_by_sha256, item.second_approved_by_sha256)
                if value
            ]
            return {
                ref_field: getattr(item, ref_field),
                "context_ref": item.context_ref,
                "status": item.status,
                "valid_until": item.valid_until,
                "revision": item.revision,
                "created_at": item.created_at,
                "approval_count": len(approvals),
                "requested_by_me": item.requested_by_sha256 == me,
                "approved_by_me": me in approvals,
                **extra,
            }

        return _safe(
            {
                "contexts": [contexts(item) for item in listed["contexts"]],
                "grants": [
                    child(item, "grant_ref", {"capability": item.capability})
                    for item in listed["grants"]
                ],
                "rights_authorizations": [
                    child(item, "authorization_ref", {"case_id": item.case_id})
                    for item in listed["rights_authorizations"]
                ],
            }
        )

    def _rights_store(request: Request, tenant: str):
        from . import privacy_rights_orchestration_api as rights_api

        rights_ops = rights_api._ops()
        principal = rights_api._principal(request, tenant)
        factory = getattr(request.app.state, "privacy_rights_orchestration_store_factory", None)
        try:
            store = (
                factory(
                    tenant_id=tenant,
                    principal_ref=principal,
                    principal_resolver=lambda: principal,
                    request=request,
                )
                if callable(factory)
                else rights_api._default_store_for(tenant, principal)
            )
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="privacy requests are unavailable"
            ) from exc
        return rights_ops, store

    async def _rights_call(rights_ops, function, *args, **kwargs):
        try:
            return await run_in_threadpool(function, *args, **kwargs)
        except rights_ops.PrivacyRightsNotFound as exc:
            raise HTTPException(status_code=404, detail="privacy request not found") from exc
        except Exception as exc:
            raise HTTPException(
                status_code=503, detail="privacy requests are unavailable"
            ) from exc

    @router.get("/rights-cases")
    async def rights_cases(request: Request, response: Response) -> dict[str, Any]:
        """Open privacy requests a person's Trust Center access can be tied to."""

        require_permission(request, "view")
        _private(response)
        tenant = _tenant_id()
        rights_ops, store = _rights_store(request, tenant)
        cases = await _rights_call(rights_ops, store.list_cases, tenant, limit=200)
        return _safe(
            {
                "items": [
                    {
                        "case_id": case.case_id,
                        "rights": list(case.rights),
                        "status": case.status,
                        "created_at": case.created_at,
                        "retained_until": case.retained_until,
                    }
                    for case in cases
                ]
            }
        )

    @router.post(
        "/contexts/{context_ref}/rights-authorizations/for-case",
        status_code=201,
    )
    async def propose_rights_authorization_for_case(
        request: Request,
        response: Response,
        context_ref: ObjectPath,
        body: RightsCaseAuthorizationIn,
    ):
        """Propose access to one chosen request, pinning its current fingerprint."""

        require_permission(request, "operate")
        _private(response)
        tenant = _tenant_id()
        rights_ops, rights_store = _rights_store(request, tenant)
        case = await _rights_call(rights_ops, rights_store.get_case, tenant, body.case_id)
        ops, trust_center, tenant, store = authority(request)
        return _safe(
            _expect(
                await call(
                    ops,
                    trust_center,
                    store.propose_rights_authorization,
                    tenant,
                    context_ref,
                    body.case_id,
                    case.integrity_sha256,
                    expected_context_revision=body.expected_context_revision,
                    valid_until=body.valid_until,
                    idempotency_key=body.idempotency_key,
                ),
                ops.RightsCaseAuthorizationAuthority,
            )
        )

    return router


router = create_consumer_trust_center_authority_router()

__all__ = [
    "ConsumerTrustCenterAuthorityDependencies",
    "consumer_trust_center_authority_enabled_for_page",
    "create_consumer_trust_center_authority_router",
    "router",
]
