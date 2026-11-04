"""Production authority seams for persisted consumer Trust Center contexts.

The operator API intentionally accepts no tenant, consumer, credential, or
signing-key authority from a request body.  This module supplies those missing
server boundaries from the same public-consent credential registry used by the
public API.  Context references are resolved through its immutable digest-only
rights-intake mapping and every lookup rechecks the current client, profile,
publication, policy, and profile revision before returning a core binding.

Installation is lazy.  Attaching the composition opens no registry, identity,
or tenant database and reads no signing key.  An explicitly injected callable
always wins; an invalid injection is left in place so the API fails closed
instead of silently falling back to a weaker authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
from dataclasses import asdict, replace
from typing import Any

from fastapi import FastAPI, Request
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentPairingContext,
)
from maverick.consumer_trust_center import TrustCenterIntegrityError
from maverick.consumer_trust_center_authority import (
    ResolvedTrustCenterBinding,
    TrustCenterAuthorityConfigError,
    TrustCenterAuthorityPermissionDenied,
    TrustCenterPrincipalAuthority,
    principal_authority_sha256,
)
from maverick.paths import canonical_tenant_id

from .auth import has_global_permission, has_permission
from .consent_identity_federation_api import (
    default_consent_identity_federation_dependencies,
    resolve_consent_pairing_context,
)
from .consent_public_api import (
    PublicClientBinding,
    PublicConsentDependencies,
    PublicProfileBinding,
    default_public_consent_dependencies,
)

_DEFAULT_SIGNING_KEY_REF = "env:MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY"
_PRINCIPAL_AUTHORITY_TTL_SECONDS = 60.0
_PRINCIPAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_RIGHTS_INTAKE_PRINCIPAL_RE = re.compile(r"pro-rights-intake-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise TrustCenterIntegrityError("authority material is invalid") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
    except UnicodeEncodeError:
        return False


def _request_for_app(request: object, app: FastAPI) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise TrustCenterAuthorityConfigError("request authority is unavailable")
    return request


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise TrustCenterAuthorityConfigError("tenant authority is unavailable") from exc


def _principal_ref(value: object) -> str:
    if not isinstance(value, str) or not _PRINCIPAL_RE.fullmatch(value):
        raise TrustCenterAuthorityPermissionDenied("principal authority is unavailable")
    return value


def _clock(request: Request) -> float:
    resolver = getattr(
        request.app.state,
        "consumer_trust_center_authority_clock",
        time.time,
    )
    if not callable(resolver):
        raise TrustCenterAuthorityConfigError("authority clock is unavailable")
    value = resolver()
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrustCenterAuthorityConfigError("authority clock is unavailable")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise TrustCenterAuthorityConfigError("authority clock is unavailable")
    return normalized


def _public_dependencies(request: Request) -> PublicConsentDependencies:
    factory = getattr(
        request.app.state,
        "privacy_rights_intake_public_dependencies_factory",
        None,
    )
    try:
        value = (
            factory(request=request) if callable(factory) else default_public_consent_dependencies()
        )
    except Exception as exc:
        raise TrustCenterAuthorityConfigError("public consent authority is unavailable") from exc
    if not isinstance(value, PublicConsentDependencies):
        raise TrustCenterAuthorityConfigError("public consent authority is unavailable")
    return value


def _current_pairing(
    public: PublicConsentDependencies,
    client: PublicClientBinding,
    profile: PublicProfileBinding,
) -> ConsentPairingContext:
    try:
        resolved = resolve_consent_pairing_context(public, client, profile)
        if type(resolved) is not ConsentPairingContext:
            raise TrustCenterIntegrityError("public pairing authority is unavailable")
        pairing = resolved.normalized()
    except TrustCenterIntegrityError:
        raise
    except Exception as exc:
        raise TrustCenterIntegrityError("public pairing authority changed") from exc
    if (
        pairing.tenant_id != client.tenant_id
        or pairing.tenant_id != profile.tenant_id
        or pairing.property_id != client.property_id
        or pairing.property_id != profile.property_id
        or pairing.profile_id != profile.profile_id
        or pairing.client_revision != client.revision
        or pairing.property_revision != client.property_revision
        or not _same(pairing.client_credential_sha256, client.credential_sha256)
        or not _same(pairing.client_record_sha256, client.record_sha256)
        or not _same(pairing.profile_credential_sha256, profile.credential_sha256)
        or not _same(pairing.profile_binding_sha256, profile.binding_sha256)
        or not _same(pairing.property_sha256, client.property_sha256)
        or not _same(pairing.publication_sha256, client.publication_sha256)
        or not _same(pairing.bundle_sha256, client.bundle_sha256)
        or pairing.policy_id != client.policy_id
        or pairing.policy_version != client.policy_version
        or not _same(pairing.policy_sha256, client.policy_sha256)
    ):
        raise TrustCenterIntegrityError("public pairing authority changed")
    return pairing


def _public_actor_sha256(
    client: PublicClientBinding,
    profile: PublicProfileBinding,
) -> str:
    return hashlib.sha256(
        (f"public-consent-actor\0{client.credential_sha256}\0{profile.credential_sha256}").encode()
    ).hexdigest()


def _privacy_rights_context_ref(pairing: ConsentPairingContext) -> str:
    digest = _sha256(
        {
            "schema": "lightwork.privacy-rights-intake-context-ref.v1",
            "tenant_id": pairing.tenant_id,
            "client_credential_sha256": pairing.client_credential_sha256,
            "profile_credential_sha256": pairing.profile_credential_sha256,
            "channel_binding_sha256": pairing.channel_binding_sha256,
        }
    )
    return f"TCA.PRI.{digest[:32]}"


def _binding_resolver_factory(app: FastAPI, **kwargs: Any):
    request = _request_for_app(kwargs.get("request"), app)
    tenant_id = _tenant(kwargs.get("tenant_id"))
    _principal_ref(kwargs.get("principal_ref"))
    public = _public_dependencies(request)
    registry = public.credential_store
    resolve_mapping = getattr(registry, "resolve_rights_intake_context", None)
    if not callable(resolve_mapping):
        raise TrustCenterAuthorityConfigError("rights-intake context authority is unavailable")

    def resolve(context_ref: str) -> ResolvedTrustCenterBinding:
        try:
            current = resolve_mapping(tenant_id, context_ref)
        except Exception as exc:
            raise TrustCenterIntegrityError(
                "rights-intake context authority is unavailable"
            ) from exc
        if (
            type(current) is not tuple
            or len(current) != 2
            or type(current[0]) is not PublicClientBinding
            or type(current[1]) is not PublicProfileBinding
        ):
            raise TrustCenterIntegrityError("rights-intake context authority is unavailable")
        client, profile = current
        pairing = _current_pairing(public, client, profile)
        if pairing.tenant_id != tenant_id:
            raise TrustCenterIntegrityError("rights-intake tenant authority changed")
        if not _same(context_ref, _privacy_rights_context_ref(pairing)):
            raise TrustCenterIntegrityError("rights-intake context authority changed")
        return ResolvedTrustCenterBinding(
            tenant_id=tenant_id,
            property_id=pairing.property_id,
            profile_id=pairing.profile_id,
            actor_sha256=_public_actor_sha256(client, profile),
            requested_locale=client.default_locale,
            server_origin=client.target_origin,
            server_bundle_id=client.target_bundle_id,
            server_platform=client.target_platform,
            jurisdiction=client.jurisdiction,
            country_code=client.country_code,
            region_code=client.region_code,
            # Rights-case provisioning does not assert that the independently
            # governed profile-data catalog exists.  A future profile-data
            # workflow must resolve and pin that authority separately.
            profile_authority=None,
        )

    return resolve


def _operator_principal_ref(request: Request, tenant_id: str) -> str:
    verified = getattr(request.state, "principal", None)
    subject = getattr(verified, "principal", None) or getattr(verified, "sub", None)
    if not isinstance(subject, str) or not subject:
        raise TrustCenterAuthorityPermissionDenied("principal authority is unavailable")
    digest = hashlib.sha256(
        (f"lightwork.consumer-trust-center-authority.identity.v1:{tenant_id}:{subject}").encode()
    ).hexdigest()
    return f"tca-principal-{digest[:32]}"


def _operator_permissions(request: Request) -> tuple[str, ...]:
    permissions: set[str] = set()
    try:
        may_view = has_permission(request, "view") is True
        may_operate = has_permission(request, "operate") is True
        may_audit = has_global_permission(request, "audit") is True
        may_administer = has_global_permission(request, "admin") is True
    except Exception as exc:
        raise TrustCenterAuthorityPermissionDenied(
            "principal permission authority is unavailable"
        ) from exc
    if may_view or may_audit or may_administer:
        permissions.add("authority_read")
    if may_operate:
        permissions.update(
            {
                "capability_request",
                "metadata_export",
                "rights_request",
            }
        )
    if may_administer:
        permissions.update(
            {
                "capability_approve",
                "context_admin",
                "retention_purge",
                "rights_approve",
            }
        )
    return tuple(sorted(permissions))


def _principal_resolver_factory(app: FastAPI, **kwargs: Any):
    request = _request_for_app(kwargs.get("request"), app)
    tenant_id = _tenant(kwargs.get("tenant_id"))
    principal_ref = _principal_ref(kwargs.get("principal_ref"))
    is_rights_intake = _RIGHTS_INTAKE_PRINCIPAL_RE.fullmatch(principal_ref) is not None
    if not is_rights_intake:
        expected = _operator_principal_ref(request, tenant_id)
        if not _same(principal_ref, expected):
            raise TrustCenterAuthorityPermissionDenied("principal authority is unavailable")

    def resolve(resolved_tenant_id: str) -> TrustCenterPrincipalAuthority:
        resolved_tenant = _tenant(resolved_tenant_id)
        if resolved_tenant != tenant_id:
            raise TrustCenterAuthorityPermissionDenied("principal tenant authority changed")
        # The public intake service may read the approved rights_cases grant,
        # but cannot create, request, approve, revoke, export, or purge anything.
        permissions = ("authority_read",) if is_rights_intake else _operator_permissions(request)
        if not permissions:
            raise TrustCenterAuthorityPermissionDenied(
                "principal permission authority is unavailable"
            )
        raw = TrustCenterPrincipalAuthority(
            tenant_sha256=_text_sha256(tenant_id),
            principal_sha256=_text_sha256(principal_ref),
            permissions=permissions,
            valid_until=_clock(request) + _PRINCIPAL_AUTHORITY_TTL_SECONDS,
            authority_sha256="0" * 64,
            revoked=False,
        )
        return replace(raw, authority_sha256=principal_authority_sha256(raw))

    return resolve


def _environment_signing_key_resolver(tenant_id: str, key_ref: str) -> bytes:
    _tenant(tenant_id)
    if key_ref != _DEFAULT_SIGNING_KEY_REF:
        raise TrustCenterAuthorityConfigError("Trust Center authority signing key is unavailable")
    value = os.environ.get("MAVERICK_TRUST_CENTER_AUTHORITY_SIGNING_KEY")
    if value is None or len(value.encode("utf-8")) < 32:
        raise TrustCenterAuthorityConfigError(
            "Trust Center authority signing key is absent or too short"
        )
    return value.encode("utf-8")


def _identity_store(request: Request, tenant_id: str) -> object:
    factory = getattr(
        request.app.state,
        "consent_identity_federation_store_factory",
        None,
    )
    try:
        if callable(factory):
            value = factory(tenant_id=tenant_id, request=request)
        elif factory is not None:
            raise TrustCenterAuthorityConfigError("redeemed pairing authority is unavailable")
        else:
            value = default_consent_identity_federation_dependencies().pairing_store
    except TrustCenterAuthorityConfigError:
        raise
    except Exception as exc:
        raise TrustCenterAuthorityConfigError("redeemed pairing authority is unavailable") from exc
    if not callable(getattr(value, "resolve_redeemed_identity_evidence", None)):
        raise TrustCenterAuthorityConfigError("redeemed pairing authority is unavailable")
    return value


def _validated_identity_evidence(
    value: object,
    *,
    pairing: ConsentPairingContext,
    now: float,
) -> ConsentIdentityEvidence:
    if type(value) is not ConsentIdentityEvidence:
        raise TrustCenterIntegrityError("redeemed pairing evidence is unavailable")
    body = asdict(value)
    supplied = body.pop("evidence_sha256", None)
    digests = (
        value.target_fingerprint,
        value.source_fingerprint,
        value.subject_binding_sha256,
        value.oidc_verification_sha256,
        value.source_link_sha256,
        value.target_link_sha256,
    )
    if (
        value.schema != "lightwork.consent.identity-evidence.v1"
        or value.tenant_id != pairing.tenant_id
        or not _same(value.target_fingerprint, pairing.fingerprint)
        or any(not isinstance(item, str) or not _DIGEST_RE.fullmatch(item) for item in digests)
        or not _same(supplied, _sha256(body))
        or isinstance(value.pairing_revision, bool)
        or not isinstance(value.pairing_revision, int)
        or value.pairing_revision < 1
        or isinstance(value.valid_until, bool)
        or not isinstance(value.valid_until, (int, float))
        or not math.isfinite(float(value.valid_until))
        or float(value.valid_until) <= now
    ):
        raise TrustCenterIntegrityError("redeemed pairing evidence changed")
    return value


def _pairing_verifier(app: FastAPI, **kwargs: Any) -> ConsentIdentityEvidence:
    request = _request_for_app(kwargs.get("request"), app)
    supplied = kwargs.get("pairing")
    if type(supplied) is not ConsentPairingContext:
        raise TrustCenterIntegrityError("public pairing authority is unavailable")
    try:
        expected = supplied.normalized()
        public = _public_dependencies(request)
        client = public.credential_store.resolve_client_authority(expected.client_credential_sha256)
        profile = public.credential_store.resolve_profile_authority(
            expected.profile_credential_sha256,
            client,
        )
        current = _current_pairing(public, client, profile)
    except TrustCenterIntegrityError:
        raise
    except Exception as exc:
        raise TrustCenterIntegrityError("public pairing authority changed") from exc
    if current != expected:
        raise TrustCenterIntegrityError("public pairing authority changed")
    store = _identity_store(request, current.tenant_id)
    try:
        evidence = store.resolve_redeemed_identity_evidence(current)
    except Exception as exc:
        raise TrustCenterIntegrityError("redeemed pairing evidence is unavailable") from exc
    return _validated_identity_evidence(
        evidence,
        pairing=current,
        now=_clock(request),
    )


def attach_consumer_trust_center_authority_composition(app: FastAPI) -> None:
    """Install lazy production resolvers without opening tenant state."""

    state = app.state
    if (
        getattr(
            state,
            "consumer_trust_center_authority_binding_resolver_factory",
            None,
        )
        is None
    ):
        state.consumer_trust_center_authority_binding_resolver_factory = lambda **kwargs: (
            _binding_resolver_factory(app, **kwargs)
        )
    if (
        getattr(
            state,
            "consumer_trust_center_authority_principal_resolver_factory",
            None,
        )
        is None
    ):
        state.consumer_trust_center_authority_principal_resolver_factory = lambda **kwargs: (
            _principal_resolver_factory(app, **kwargs)
        )
    if (
        getattr(
            state,
            "consumer_trust_center_authority_signing_key_resolver",
            None,
        )
        is None
    ):
        state.consumer_trust_center_authority_signing_key_resolver = (
            _environment_signing_key_resolver
        )
    if (
        getattr(
            state,
            "consumer_trust_center_authority_signing_key_ref",
            None,
        )
        is None
    ):
        state.consumer_trust_center_authority_signing_key_ref = _DEFAULT_SIGNING_KEY_REF
    if (
        getattr(
            state,
            "consumer_trust_center_authority_pairing_verifier",
            None,
        )
        is None
    ):
        state.consumer_trust_center_authority_pairing_verifier = lambda **kwargs: _pairing_verifier(
            app, **kwargs
        )


__all__ = ["attach_consumer_trust_center_authority_composition"]
