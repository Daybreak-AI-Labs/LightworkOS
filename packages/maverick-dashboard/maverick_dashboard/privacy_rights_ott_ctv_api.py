"""Self-authenticating OTT/CTV service API for privacy-rights intake.

The caller supplies only its existing public service-client credential, device
profile capability, and CAS/idempotency echoes.  Tenant, property, client,
bundle, platform, profile, publication, policy, Trust Center capability, and
rights-orchestration authority are resolved server-side.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentIdentityFederationError,
    ConsentPairingContext,
)
from maverick.paths import data_dir
from maverick.privacy_rights_ott_ctv import (
    OTTCTVPrivacyRightsConfigError,
    OTTCTVPrivacyRightsConflict,
    OTTCTVPrivacyRightsIntegrityError,
    OTTCTVPrivacyRightsNotFound,
    OTTCTVPrivacyRightsStore,
    OTTCTVPrivacyRightsValidationError,
    OTTCTVServiceAuthority,
    SignedOTTCTVRequestStatus,
    build_service_authority,
    enabled,
    ott_ctv_trust_context_ref,
)
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .consent_identity_federation_api import resolve_consent_pairing_context
from .consent_public_api import (
    PublicClientBinding,
    PublicConsentCredentialError,
    PublicConsentDependencies,
    PublicConsentRateLimitExceeded,
    PublicProfileBinding,
    _cache_limited_body,
    default_public_consent_dependencies,
)

_AUTH_DETAIL = "invalid public consent credential"
_AUTHORITY_DETAIL = "OTT/CTV rights authority changed"
_MAX_CASE_ID = 128


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class OTTCTVRequestCreateIn(_StrictModel):
    right: Literal["access", "deletion"]
    expected_revision: Literal[0]
    idempotency_key: str = Field(
        min_length=8,
        max_length=192,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}$",
    )
    client_revision: int = Field(ge=1, le=2**31 - 1)
    profile_revision: int = Field(ge=1, le=2**31 - 1)
    identity_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    identity_evidence_revision: int = Field(ge=1, le=2**31 - 1)
    identity_evidence_valid_until: float = Field(gt=0)
    publication_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: int = Field(ge=1, le=2**31 - 1)
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust_context_revision: int = Field(ge=1, le=2**31 - 1)
    trust_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    capability_grant_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class _Admitted:
    client: PublicClientBinding
    profile: PublicProfileBinding
    authority: OTTCTVServiceAuthority
    bridge: OTTCTVPrivacyRightsStore


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _authorization_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, raw = authorization.partition(" ")
    if not separator or scheme.lower() != "consentpublic" or not 24 <= len(raw) <= 256:
        raise PublicConsentCredentialError(_AUTH_DETAIL)
    return raw


def _private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"


def _account_binding(
    public: PublicConsentDependencies,
    pairing: ConsentPairingContext,
) -> str:
    try:
        profile = public.preference_store_for(pairing.tenant_id).get_profile_authority(
            pairing.tenant_id,
            pairing.profile_id,
        )
    except Exception as exc:
        raise OTTCTVPrivacyRightsConflict("linked account authority is unavailable") from exc
    linked = profile.get("linked_known_profile_id") if isinstance(profile, Mapping) else None
    link_sha = profile.get("link_sha256") if isinstance(profile, Mapping) else None
    if (
        not isinstance(linked, str)
        or not linked
        or not isinstance(link_sha, str)
        or len(link_sha) != 64
        or profile.get("identity_kind") != "anonymous"
        or profile.get("revision") != pairing.profile_revision
    ):
        raise OTTCTVPrivacyRightsConflict("linked account authority changed")
    return _sha256(
        {
            "schema": "lightwork.privacy-rights-ott-ctv-account-binding.v1",
            "anonymous_profile_sha256": hashlib.sha256(
                pairing.profile_id.encode("utf-8")
            ).hexdigest(),
            "known_profile_sha256": hashlib.sha256(linked.encode("utf-8")).hexdigest(),
            "link_sha256": link_sha,
            "profile_revision": pairing.profile_revision,
        }
    )


def _service_principal(pairing: ConsentPairingContext) -> str:
    digest = _sha256(
        {
            "schema": "lightwork.privacy-rights-ott-ctv-principal.v1",
            "tenant_id": pairing.tenant_id,
            "client_credential_sha256": pairing.client_credential_sha256,
            "profile_credential_sha256": pairing.profile_credential_sha256,
        }
    )
    return f"pro-ott-ctv-{digest[:32]}"


def _default_trust_context_for(
    request: Request,
    pairing: ConsentPairingContext,
) -> object:
    from .consumer_trust_center_authority_api import _default_store_for

    principal = _service_principal(pairing)
    factory = getattr(
        request.app.state,
        "consumer_trust_center_authority_store_factory",
        None,
    )

    def principal_resolver() -> str:
        return principal

    store = (
        factory(
            tenant_id=pairing.tenant_id,
            principal_ref=principal,
            principal_resolver=principal_resolver,
            request=request,
        )
        if callable(factory)
        else _default_store_for(request, pairing.tenant_id, principal)
    )
    resolver = store.make_context_resolver(ott_ctv_trust_context_ref(pairing))
    return resolver()


def _default_rights_store_for(
    request: Request,
    pairing: ConsentPairingContext,
) -> object:
    from .privacy_rights_orchestration_api import _default_store_for

    principal = _service_principal(pairing)
    factory = getattr(request.app.state, "privacy_rights_orchestration_store_factory", None)

    def principal_resolver() -> str:
        return principal

    return (
        factory(
            tenant_id=pairing.tenant_id,
            principal_ref=principal,
            principal_resolver=principal_resolver,
            request=request,
        )
        if callable(factory)
        else _default_store_for(pairing.tenant_id, principal)
    )


def _default_identity_evidence_for(
    request: Request,
    pairing: ConsentPairingContext,
) -> ConsentIdentityEvidence:
    from .consent_identity_federation_api import (
        default_consent_identity_federation_dependencies,
    )

    factory = getattr(
        request.app.state,
        "consent_identity_federation_store_factory",
        None,
    )
    if callable(factory):
        store = factory(tenant_id=pairing.tenant_id, request=request)
    else:
        store = default_consent_identity_federation_dependencies().pairing_store
    resolver = getattr(store, "resolve_redeemed_identity_evidence", None)
    if not callable(resolver):
        raise OTTCTVPrivacyRightsConfigError("identity evidence authority is unavailable")
    try:
        evidence = resolver(pairing)
    except ConsentIdentityFederationError as exc:
        raise OTTCTVPrivacyRightsConflict("fresh identity evidence changed") from exc
    if not isinstance(evidence, ConsentIdentityEvidence):
        raise OTTCTVPrivacyRightsConfigError("identity evidence authority is unavailable")
    return evidence


def _default_bridge_store_for(
    request: Request,
    pairing: ConsentPairingContext,
    rights_store: object,
    authority_resolver: Callable[[OTTCTVServiceAuthority], OTTCTVServiceAuthority],
) -> OTTCTVPrivacyRightsStore:
    factory = getattr(request.app.state, "privacy_rights_ott_ctv_store_factory", None)
    if callable(factory):
        return factory(
            tenant_id=pairing.tenant_id,
            rights_store=rights_store,
            authority_resolver=authority_resolver,
            request=request,
        )
    return OTTCTVPrivacyRightsStore(
        data_dir(
            "privacy_automation",
            "privacy-rights-ott-ctv.sqlite3",
            tenant=pairing.tenant_id,
        ),
        rights_store=rights_store,
        authority_resolver=authority_resolver,
    )


@dataclass(frozen=True)
class OTTCTVPrivacyRightsAPIDependencies:
    public: PublicConsentDependencies
    identity_evidence_for: Callable[
        [Request, ConsentPairingContext], ConsentIdentityEvidence
    ]
    trust_context_for: Callable[[Request, ConsentPairingContext], object]
    rights_store_for: Callable[[Request, ConsentPairingContext], object]
    bridge_store_for: Callable[
        [
            Request,
            ConsentPairingContext,
            object,
            Callable[[OTTCTVServiceAuthority], OTTCTVServiceAuthority],
        ],
        OTTCTVPrivacyRightsStore,
    ]
    gate: Callable[[], bool] = enabled
    clock: Callable[[], float] = time.time


def default_ott_ctv_privacy_rights_dependencies() -> OTTCTVPrivacyRightsAPIDependencies:
    return OTTCTVPrivacyRightsAPIDependencies(
        public=default_public_consent_dependencies(),
        identity_evidence_for=_default_identity_evidence_for,
        trust_context_for=_default_trust_context_for,
        rights_store_for=_default_rights_store_for,
        bridge_store_for=_default_bridge_store_for,
    )


def _status_response(status: SignedOTTCTVRequestStatus) -> dict[str, Any]:
    return {
        **dict(status.payload),
        "signing_key_ref": status.signing_key_ref,
        "signature": status.signature,
        "evidence_sha256": status.evidence_sha256,
    }


def create_ott_ctv_privacy_rights_router(  # noqa: C901 - closed route composition
    dependencies: OTTCTVPrivacyRightsAPIDependencies | None = None,
) -> APIRouter:
    deps = dependencies or default_ott_ctv_privacy_rights_dependencies()
    router = APIRouter(
        prefix="/api/v1/public/consent/ott-ctv/rights",
        tags=["public-consent-ott-ctv-rights"],
    )

    async def admitted(request: Request) -> _Admitted:  # noqa: C901
        try:
            if deps.gate() is not True or deps.public.gate() is not True:
                raise HTTPException(status_code=404, detail="not found")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        forbidden_headers = (
            "x-lightwork-tenant",
            "x-lightwork-property",
            "x-lightwork-profile-id",
            "x-lightwork-device-id",
            "x-lightwork-consumer",
            "x-maverick-tenant",
            "x-maverick-property",
        )
        if request.query_params or any(request.headers.get(name) for name in forbidden_headers):
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL)
        try:
            raw_client = _authorization_token(request)
            client = await run_in_threadpool(
                deps.public.credential_store.resolve_client,
                raw_client,
            )
            service_header = request.headers.get("x-lightwork-consent-service-client")
            if (
                request.headers.get("origin") is not None
                or client.client_kind != "service"
                or service_header != client.service_client_id
                or client.target_origin is not None
                or client.target_bundle_id is None
                or client.target_platform is None
            ):
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            deps.public.rate_limit(client.credential_sha256, request.url.path)
            await _cache_limited_body(request)
            raw_profile = request.headers.get("x-lightwork-profile-credential", "")
            profile = await run_in_threadpool(
                deps.public.credential_store.resolve_profile,
                raw_profile,
                client,
            )
            pairing = await run_in_threadpool(
                resolve_consent_pairing_context,
                deps.public,
                client,
                profile,
            )
            account_sha = await run_in_threadpool(_account_binding, deps.public, pairing)
            identity_evidence = await run_in_threadpool(
                deps.identity_evidence_for,
                request,
                pairing,
            )
            trust_context = await run_in_threadpool(
                deps.trust_context_for,
                request,
                pairing,
            )
            authority = build_service_authority(
                pairing,
                trust_context,
                service_client_id=str(client.service_client_id),
                target_bundle_id=str(client.target_bundle_id),
                target_platform=str(client.target_platform),
                account_binding_sha256=account_sha,
                identity_evidence=identity_evidence,
                client_expires_at=client.expires_at,
                now=deps.clock(),
            )

            def current(
                _expected: OTTCTVServiceAuthority,
            ) -> OTTCTVServiceAuthority:
                current_client = deps.public.credential_store.resolve_client_authority(
                    pairing.client_credential_sha256
                )
                current_profile = deps.public.credential_store.resolve_profile_authority(
                    pairing.profile_credential_sha256,
                    current_client,
                )
                current_pairing = resolve_consent_pairing_context(
                    deps.public,
                    current_client,
                    current_profile,
                )
                current_account = _account_binding(deps.public, current_pairing)
                current_identity = deps.identity_evidence_for(request, current_pairing)
                current_trust = deps.trust_context_for(request, current_pairing)
                return build_service_authority(
                    current_pairing,
                    current_trust,
                    service_client_id=str(current_client.service_client_id),
                    target_bundle_id=str(current_client.target_bundle_id),
                    target_platform=str(current_client.target_platform),
                    account_binding_sha256=current_account,
                    identity_evidence=current_identity,
                    client_expires_at=current_client.expires_at,
                    now=deps.clock(),
                )

            rights_store = await run_in_threadpool(
                deps.rights_store_for,
                request,
                pairing,
            )
            bridge = await run_in_threadpool(
                deps.bridge_store_for,
                request,
                pairing,
                rights_store,
                current,
            )
            if not isinstance(bridge, OTTCTVPrivacyRightsStore):
                raise OTTCTVPrivacyRightsConfigError("bridge store factory is invalid")
            return _Admitted(client, profile, authority, bridge)
        except PublicConsentRateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail="rate limit reached",
                headers={"Retry-After": "60"},
            ) from exc
        except HTTPException:
            raise
        except PublicConsentCredentialError as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc
        except OTTCTVPrivacyRightsConflict as exc:
            raise HTTPException(status_code=409, detail=_AUTHORITY_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=503, detail="OTT/CTV rights unavailable") from exc

    @router.get("/status")
    async def product_status(
        response: Response,
        _access: _Admitted = Depends(admitted),
    ) -> dict[str, Any]:
        _private(response)
        return {
            "enabled": True,
            **OTTCTVPrivacyRightsStore.product_boundaries(),
            "authority": "service_client_profile_and_trust_center_grant",
            "orchestration": "privacy_rights_orchestration",
        }

    @router.post("/requests", status_code=201)
    async def create_request(
        body: OTTCTVRequestCreateIn,
        request: Request,
        response: Response,
        access: _Admitted = Depends(admitted),
    ) -> dict[str, Any]:
        expected = {
            "client_revision": access.authority.client_revision,
            "profile_revision": access.authority.profile_revision,
            "identity_evidence_sha256": access.authority.identity_evidence_sha256,
            "identity_evidence_revision": access.authority.identity_evidence_revision,
            "identity_evidence_valid_until": (
                access.authority.identity_evidence_valid_until
            ),
            "publication_sha256": access.authority.publication_sha256,
            "bundle_sha256": access.authority.publication_bundle_sha256,
            "configuration_sha256": access.authority.configuration_sha256,
            "policy_version": access.authority.policy_version,
            "policy_sha256": access.authority.policy_sha256,
            "profile_binding_sha256": access.authority.profile_binding_sha256,
            "trust_context_revision": access.authority.trust_context_revision,
            "trust_context_sha256": access.authority.trust_context_sha256,
            "capability_grant_sha256": access.authority.capability_grant_sha256,
        }
        if any(
            not (
                hmac.compare_digest(str(value), str(expected[name]))
                if isinstance(value, str)
                else value == expected[name]
            )
            for name, value in body.model_dump().items()
            if name in expected
        ):
            raise HTTPException(status_code=409, detail=_AUTHORITY_DETAIL)
        try:
            status = await run_in_threadpool(
                access.bridge.create_request,
                access.authority,
                right=body.right,
                expected_revision=body.expected_revision,
                idempotency_key=body.idempotency_key,
            )
        except OTTCTVPrivacyRightsNotFound as exc:
            raise HTTPException(status_code=404, detail="rights request not found") from exc
        except OTTCTVPrivacyRightsConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except OTTCTVPrivacyRightsValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except (OTTCTVPrivacyRightsConfigError, OTTCTVPrivacyRightsIntegrityError) as exc:
            raise HTTPException(status_code=503, detail="OTT/CTV rights unavailable") from exc
        except Exception as exc:
            from maverick import privacy_rights_orchestration as rights

            if isinstance(exc, rights.PrivacyRightsConflict):
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            if isinstance(exc, rights.PrivacyRightsValidationError):
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            raise HTTPException(status_code=503, detail="OTT/CTV rights unavailable") from exc
        _private(response)
        response.headers["Location"] = (
            "/api/v1/public/consent/ott-ctv/rights/requests/"
            + str(status.payload["case_id"])
        )
        return _status_response(status)

    @router.get("/requests/{case_id}")
    async def request_status(
        case_id: str,
        response: Response,
        access: _Admitted = Depends(admitted),
    ) -> dict[str, Any]:
        if not 1 <= len(case_id) <= _MAX_CASE_ID:
            raise HTTPException(status_code=404, detail="rights request not found")
        try:
            status = await run_in_threadpool(
                access.bridge.get_status,
                access.authority,
                case_id,
            )
        except OTTCTVPrivacyRightsNotFound as exc:
            raise HTTPException(status_code=404, detail="rights request not found") from exc
        except OTTCTVPrivacyRightsConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except OTTCTVPrivacyRightsValidationError as exc:
            raise HTTPException(status_code=404, detail="rights request not found") from exc
        except (OTTCTVPrivacyRightsConfigError, OTTCTVPrivacyRightsIntegrityError) as exc:
            raise HTTPException(status_code=503, detail="OTT/CTV rights unavailable") from exc
        _private(response)
        return _status_response(status)

    return router


__all__ = [
    "OTTCTVPrivacyRightsAPIDependencies",
    "OTTCTVRequestCreateIn",
    "create_ott_ctv_privacy_rights_router",
    "default_ott_ctv_privacy_rights_dependencies",
]
