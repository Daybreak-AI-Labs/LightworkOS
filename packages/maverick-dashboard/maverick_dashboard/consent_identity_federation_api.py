"""Narrow public API for verified consent identity and device pairing.

Consumers never submit tenant, property, policy, client, or profile selectors.
Those authorities are resolved from the existing opaque public client and
profile capabilities, then pinned into the digest-only core workflow.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from maverick.consent_identity_federation import (
    MAX_PAIRING_TTL_SECONDS,
    ConsentIdentityFederationConfigError,
    ConsentIdentityFederationConflict,
    ConsentIdentityFederationStore,
    ConsentIdentitySettings,
    ConsentOIDCVerifier,
    ConsentPairingContext,
    InjectedConsentOIDCVerifier,
    load_consent_identity_settings,
)
from maverick.paths import data_dir
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .consent_public_api import (
    PublicClientBinding,
    PublicConsentCredentialError,
    PublicConsentDependencies,
    PublicConsentRateLimitExceeded,
    PublicProfileBinding,
    _cache_limited_body,
    _origin,
    default_public_consent_dependencies,
    require_public_session,
)

_AUTH_DETAIL = "invalid public consent credential"
_PAIRING_DETAIL = "consent identity pairing unavailable"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PairingBeginIn(_StrictModel):
    code_challenge: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")


class PairingAuthorizeIn(_StrictModel):
    pairing_code: str = Field(
        min_length=39,
        max_length=200,
        pattern=r"^lwcp1\.[A-Za-z0-9_-]{32,192}$",
    )
    oidc_nonce: str = Field(min_length=32, max_length=256)
    oidc_token: str = Field(min_length=32, max_length=16_384)


class PairingRedeemIn(_StrictModel):
    pairing_code: str = Field(
        min_length=39,
        max_length=200,
        pattern=r"^lwcp1\.[A-Za-z0-9_-]{32,192}$",
    )
    code_verifier: str = Field(
        min_length=43,
        max_length=128,
        pattern=r"^[A-Za-z0-9._~-]+$",
    )


class PairingRevokeIn(_StrictModel):
    pairing_code: str = Field(
        min_length=39,
        max_length=200,
        pattern=r"^lwcp1\.[A-Za-z0-9_-]{32,192}$",
    )
    reason_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class IdentityUnlinkIn(_StrictModel):
    expected_profile_revision: int = Field(ge=1, le=2**31 - 1)
    expected_link_revision: int = Field(ge=1, le=2**31 - 1)
    idempotency_key: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    )
    reason_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class _PublicAuthority:
    client: PublicClientBinding
    profile: PublicProfileBinding


@dataclass(frozen=True)
class ConsentIdentityFederationAPIDependencies:
    public: PublicConsentDependencies
    pairing_store: ConsentIdentityFederationStore
    settings_for: Callable[[], ConsentIdentitySettings]
    context_for: Callable[[PublicClientBinding, PublicProfileBinding], ConsentPairingContext]
    oidc_verifier_for: Callable[[Request], ConsentOIDCVerifier]
    subject_digest_key_for: Callable[[Request], bytes]
    clock: Callable[[], float] = time.time


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _authorization_token(request: Request) -> str:
    authorization = request.headers.get("authorization", "")
    scheme, separator, raw = authorization.partition(" ")
    if not separator or scheme.lower() != "consentpublic" or not 24 <= len(raw) <= 256:
        raise PublicConsentCredentialError(_AUTH_DETAIL)
    return raw


def _private_headers(response: Response, request: Request, client: PublicClientBinding) -> None:
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    if client.client_kind == "browser":
        origin = request.headers.get("origin")
        if origin is not None and origin == client.browser_origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"


def _channel_binding(client: PublicClientBinding) -> tuple[str, str]:
    kind = "browser-origin" if client.client_kind == "browser" else "service-client"
    return kind, _sha256(
        {
            "client_kind": client.client_kind,
            "browser_origin": client.browser_origin,
            "service_client_id": client.service_client_id,
            "target_origin": client.target_origin,
            "target_bundle_id": client.target_bundle_id,
            "target_platform": client.target_platform,
        }
    )


def resolve_consent_pairing_context(
    public: PublicConsentDependencies,
    client: PublicClientBinding,
    profile: PublicProfileBinding,
) -> ConsentPairingContext:
    """Re-validate publication, policy, capability, and profile CAS pins."""

    resolved_client = public.credential_store.resolve_client_authority(client.credential_sha256)
    resolved_profile = public.credential_store.resolve_profile_authority(
        profile.credential_sha256,
        resolved_client,
    )
    if resolved_client != client or resolved_profile != profile:
        raise ConsentIdentityFederationConflict("public capability authority changed")

    publishing = public.publishing_store_for(client.tenant_id)
    preview = publishing.preview(
        client.tenant_id,
        client.property_id,
        client.rule_group_id,
        client.rule_group_version,
    )
    preview_bundle = preview.get("bundle") if isinstance(preview, Mapping) else None
    preview_property = (
        preview_bundle.get("property") if isinstance(preview_bundle, Mapping) else None
    )
    if (
        not isinstance(preview_property, Mapping)
        or not hmac.compare_digest(
            str(preview_property.get("record_sha256", "")),
            client.property_sha256,
        )
        or not hmac.compare_digest(
            str(preview.get("bundle_sha256", "")),
            client.bundle_sha256,
        )
    ):
        raise ConsentIdentityFederationConflict("published consent authority changed")
    configuration = publishing.resolve_public_configuration(
        client.tenant_id,
        client.property_id,
        server_origin=client.target_origin,
        server_bundle_id=client.target_bundle_id,
        server_platform=client.target_platform,
        jurisdiction=client.jurisdiction,
        country_code=client.country_code,
        region_code=client.region_code,
        requested_locale=client.default_locale,
        evaluated_at=public.clock(),
    )
    if not isinstance(configuration, Mapping) or configuration.get("allowed") is not True:
        raise ConsentIdentityFederationConflict("published consent authority changed")
    publication = configuration.get("publication")
    property_binding = configuration.get("property")
    configuration_sha = configuration.get("configuration_sha256")
    if (
        not isinstance(publication, Mapping)
        or not isinstance(property_binding, Mapping)
        or not isinstance(configuration_sha, str)
        or property_binding.get("property_id") != client.property_id
        or property_binding.get("revision") != client.property_revision
        or publication.get("property_revision") != client.property_revision
        or not hmac.compare_digest(
            str(publication.get("publication_sha256", "")),
            client.publication_sha256,
        )
        or not hmac.compare_digest(str(publication.get("bundle_sha256", "")), client.bundle_sha256)
    ):
        raise ConsentIdentityFederationConflict("published consent authority changed")

    preferences = public.preference_store_for(client.tenant_id)
    policy = preferences.get_active_policy(client.tenant_id, client.policy_id, at=public.clock())
    if (
        not isinstance(policy, Mapping)
        or policy.get("version") != client.policy_version
        or not hmac.compare_digest(str(policy.get("policy_sha256", "")), client.policy_sha256)
    ):
        raise ConsentIdentityFederationConflict("policy authority changed")
    content = configuration.get("configuration")
    if not isinstance(content, Mapping):
        raise ConsentIdentityFederationConflict("published consent authority changed")
    purposes = content.get("purposes")
    notice = content.get("notice")
    if not isinstance(purposes, list) or not isinstance(notice, Mapping):
        raise ConsentIdentityFederationConflict("published consent authority changed")
    published_purposes: dict[str, str] = {}
    for item in purposes:
        if not isinstance(item, Mapping):
            raise ConsentIdentityFederationConflict("published consent authority changed")
        purpose_id = str(item.get("id", ""))
        if purpose_id in published_purposes:
            raise ConsentIdentityFederationConflict("published consent authority changed")
        published_purposes[purpose_id] = str(item.get("lawful_basis", ""))
    if published_purposes != policy.get("purposes") or not hmac.compare_digest(
        str(notice.get("document_sha256", "")),
        str(policy.get("notice_sha256", "")),
    ):
        raise ConsentIdentityFederationConflict("published policy authority changed")
    profile_authority = preferences.get_profile_authority(
        client.tenant_id,
        profile.profile_id,
    )
    channel_kind, channel_sha = _channel_binding(client)
    return ConsentPairingContext(
        tenant_id=client.tenant_id,
        property_id=client.property_id,
        profile_id=profile.profile_id,
        profile_revision=int(profile_authority["revision"]),
        client_credential_sha256=client.credential_sha256,
        client_revision=client.revision,
        client_record_sha256=client.record_sha256,
        profile_credential_sha256=profile.credential_sha256,
        profile_binding_sha256=profile.binding_sha256,
        property_revision=client.property_revision,
        property_sha256=client.property_sha256,
        publication_sha256=client.publication_sha256,
        bundle_sha256=client.bundle_sha256,
        configuration_sha256=configuration_sha,
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        channel_kind=channel_kind,
        channel_binding_sha256=channel_sha,
    )


def _context_from_digest(
    public: PublicConsentDependencies,
    expected: ConsentPairingContext,
) -> ConsentPairingContext:
    client = public.credential_store.resolve_client_authority(expected.client_credential_sha256)
    profile = public.credential_store.resolve_profile_authority(
        expected.profile_credential_sha256,
        client,
    )
    return resolve_consent_pairing_context(public, client, profile)


def _default_settings() -> ConsentIdentitySettings:
    try:
        from maverick.config import config_source_errors

        if config_source_errors():
            raise ConsentIdentityFederationConfigError(
                "consent identity configuration is unavailable"
            )
    except ConsentIdentityFederationConfigError:
        raise
    except Exception as exc:
        raise ConsentIdentityFederationConfigError(
            "consent identity configuration is unavailable"
        ) from exc
    return load_consent_identity_settings()


def _default_oidc_verifier(request: Request) -> ConsentOIDCVerifier:
    verifier = getattr(request.app.state, "consent_identity_oidc_verifier", None)
    if callable(verifier):
        return verifier
    signing_key_for = getattr(
        request.app.state,
        "consent_identity_oidc_signing_key_for",
        None,
    )
    if callable(signing_key_for):
        return InjectedConsentOIDCVerifier(signing_key_for)
    raise ConsentIdentityFederationConfigError(
        "injected OIDC verification authority is unavailable"
    )


def _default_subject_digest_key(request: Request) -> bytes:
    value = getattr(request.app.state, "consent_identity_subject_digest_key", None)
    if not isinstance(value, bytes) or len(value) < 32:
        raise ConsentIdentityFederationConfigError(
            "consent identity subject digest key is unavailable"
        )
    return value


def default_consent_identity_federation_dependencies() -> ConsentIdentityFederationAPIDependencies:
    public = default_public_consent_dependencies()

    def context_for(
        client: PublicClientBinding,
        profile: PublicProfileBinding,
    ) -> ConsentPairingContext:
        return resolve_consent_pairing_context(public, client, profile)

    pairing = ConsentIdentityFederationStore(
        data_dir(
            "consent_public_api",
            "consent-identity-pairings.sqlite3",
            tenant=None,
        ),
        preference_store_for=public.preference_store_for,
        context_resolver=lambda expected: _context_from_digest(public, expected),
        clock=public.clock,
    )
    return ConsentIdentityFederationAPIDependencies(
        public=public,
        pairing_store=pairing,
        settings_for=_default_settings,
        context_for=context_for,
        oidc_verifier_for=_default_oidc_verifier,
        subject_digest_key_for=_default_subject_digest_key,
        clock=public.clock,
    )


def create_consent_identity_federation_router(  # noqa: C901 - isolated route factory
    dependencies: ConsentIdentityFederationAPIDependencies | None = None,
) -> APIRouter:
    deps = dependencies or default_consent_identity_federation_dependencies()
    router = APIRouter(
        prefix="/api/v1/public/consent/identity",
        tags=["public-consent-identity"],
    )

    async def authority(request: Request) -> _PublicAuthority:
        try:
            deps.settings_for()
            if not deps.public.gate():
                raise HTTPException(status_code=404, detail="not found")
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=404, detail="not found") from exc
        if request.query_params or any(
            request.headers.get(name)
            for name in (
                "x-lightwork-property",
                "x-lightwork-tenant",
                "x-maverick-property",
                "x-maverick-tenant",
            )
        ):
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL)
        try:
            raw = _authorization_token(request)
            client = await run_in_threadpool(deps.public.credential_store.resolve_client, raw)
            origin = request.headers.get("origin")
            service_client = request.headers.get("x-lightwork-consent-service-client")
            if client.client_kind == "browser":
                admitted = (
                    origin is not None
                    and _origin(origin) == client.browser_origin
                    and service_client is None
                )
            else:
                admitted = origin is None and service_client == client.service_client_id
            if not admitted:
                raise PublicConsentCredentialError(_AUTH_DETAIL)
            deps.public.rate_limit(client.credential_sha256, request.url.path)
            # A live visitor session too, when the public service uses them.
            await require_public_session(request, deps.public, client)
            await _cache_limited_body(request)
            raw_profile = request.headers.get("x-lightwork-profile-credential", "")
            profile = await run_in_threadpool(
                deps.public.credential_store.resolve_profile,
                raw_profile,
                client,
            )
            return _PublicAuthority(client, profile)
        except PublicConsentRateLimitExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail="rate limit reached",
                headers={"Retry-After": "60"},
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=401, detail=_AUTH_DETAIL) from exc

    async def current_context(authority: _PublicAuthority) -> ConsentPairingContext:
        try:
            return await run_in_threadpool(
                deps.context_for,
                authority.client,
                authority.profile,
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc

    @router.post("/pairings")
    async def begin_pairing(
        body: PairingBeginIn,
        request: Request,
        response: Response,
        admitted: _PublicAuthority = Depends(authority),
    ) -> dict[str, Any]:
        context = await current_context(admitted)
        try:
            settings = deps.settings_for()
            challenge = await run_in_threadpool(
                deps.pairing_store.begin_pairing,
                context,
                code_challenge=body.code_challenge,
                ttl_seconds=min(settings.token_ttl_seconds, MAX_PAIRING_TTL_SECONDS),
                retention_seconds=settings.link_lifecycle_retention_seconds,
            )
        except ConsentIdentityFederationConflict as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=403, detail=_PAIRING_DETAIL) from exc
        _private_headers(response, request, admitted.client)
        return {
            "pairing_code": challenge.pairing_code,
            "oidc_nonce": challenge.oidc_nonce,
            "expires_at": challenge.expires_at,
        }

    @router.post("/pairings/authorize")
    async def authorize_pairing(
        body: PairingAuthorizeIn,
        request: Request,
        response: Response,
        admitted: _PublicAuthority = Depends(authority),
    ) -> dict[str, Any]:
        context = await current_context(admitted)
        try:
            verifier = deps.oidc_verifier_for(request)
            subject_key = deps.subject_digest_key_for(request)
            authorized = await run_in_threadpool(
                deps.pairing_store.authorize_pairing,
                body.pairing_code,
                oidc_nonce=body.oidc_nonce,
                oidc_token=body.oidc_token,
                source=context,
                settings=deps.settings_for(),
                oidc_verifier=verifier,
                subject_digest_key=subject_key,
            )
        except ConsentIdentityFederationConflict as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=403, detail=_PAIRING_DETAIL) from exc
        _private_headers(response, request, admitted.client)
        return {"status": authorized.status, "expires_at": authorized.expires_at}

    @router.post("/pairings/redeem")
    async def redeem_pairing(
        body: PairingRedeemIn,
        request: Request,
        response: Response,
        admitted: _PublicAuthority = Depends(authority),
    ) -> dict[str, Any]:
        context = await current_context(admitted)
        try:
            redeemed = await run_in_threadpool(
                deps.pairing_store.redeem_pairing,
                body.pairing_code,
                code_verifier=body.code_verifier,
                target=context,
            )
        except ConsentIdentityFederationConflict as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=403, detail=_PAIRING_DETAIL) from exc
        _private_headers(response, request, admitted.client)
        return {"status": redeemed.status, "linked": True}

    @router.post("/pairings/revoke")
    async def revoke_pairing(
        body: PairingRevokeIn,
        request: Request,
        response: Response,
        admitted: _PublicAuthority = Depends(authority),
    ) -> dict[str, Any]:
        context = await current_context(admitted)
        try:
            revoked = await run_in_threadpool(
                deps.pairing_store.revoke_pairing,
                body.pairing_code,
                authority=context,
                reason_sha256=body.reason_sha256,
            )
        except ConsentIdentityFederationConflict as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=403, detail=_PAIRING_DETAIL) from exc
        _private_headers(response, request, admitted.client)
        return {"status": revoked["status"]}

    @router.get("/link")
    async def current_link(
        request: Request,
        response: Response,
        admitted: _PublicAuthority = Depends(authority),
    ) -> dict[str, Any]:
        context = await current_context(admitted)
        try:
            profile = await run_in_threadpool(
                deps.public.preference_store_for(context.tenant_id).get_profile_authority,
                context.tenant_id,
                context.profile_id,
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc
        _private_headers(response, request, admitted.client)
        return {
            "status": profile.get("link_status", "never_linked"),
            "profile_revision": profile["revision"],
            "link_revision": profile.get("link_revision", 0),
            "linked": profile.get("link_status") == "linked",
            "receipt_histories_merged": False,
        }

    @router.post("/link/unlink")
    async def unlink_current_identity(
        body: IdentityUnlinkIn,
        request: Request,
        response: Response,
        admitted: _PublicAuthority = Depends(authority),
    ) -> dict[str, Any]:
        context = await current_context(admitted)
        try:
            unlinked = await run_in_threadpool(
                deps.pairing_store.unlink_current_identity,
                context,
                expected_profile_revision=body.expected_profile_revision,
                expected_link_revision=body.expected_link_revision,
                idempotency_key=body.idempotency_key,
                reason_sha256=body.reason_sha256,
                settings=deps.settings_for(),
            )
        except ConsentIdentityFederationConflict as exc:
            raise HTTPException(status_code=409, detail=_PAIRING_DETAIL) from exc
        except Exception as exc:
            raise HTTPException(status_code=403, detail=_PAIRING_DETAIL) from exc
        _private_headers(response, request, admitted.client)
        return {
            "status": unlinked["link_status"],
            "profile_revision": unlinked["anonymous_revision"],
            "link_revision": unlinked["link_revision"],
            "pairing_revoked": True,
            "receipt_histories_merged": False,
        }

    return router


__all__ = [
    "ConsentIdentityFederationAPIDependencies",
    "create_consent_identity_federation_router",
    "default_consent_identity_federation_dependencies",
    "resolve_consent_pairing_context",
]
