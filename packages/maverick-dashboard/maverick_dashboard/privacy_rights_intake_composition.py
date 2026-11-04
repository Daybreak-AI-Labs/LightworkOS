"""Production composition for authenticated public privacy-rights intake.

The public API has already authenticated an opaque client/profile capability
before it calls this module.  This composition re-resolves that capability,
requires a current redeemed OIDC federation proof and an independently
approved Trust Center ``rights_cases`` grant, and then opens the existing
privacy-rights orchestration authority.  It never accepts or manufactures a
tenant selector, subject identifier, identity token, or identity proof.

Installation is deliberately lazy: :func:`attach_privacy_rights_intake_composition`
only installs app-state callables.  Tenant-local stores are opened on an
admitted request, never while the dashboard imports or starts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from maverick.consent_identity_federation import (
    ConsentIdentityEvidence,
    ConsentIdentitySettings,
    ConsentPairingContext,
    consent_identity_enabled,
    load_consent_identity_settings,
)
from maverick.consumer_trust_center import (
    ConsumerTrustCenterSourceAdapter,
    TrustCenterCapabilityGrant,
    TrustCenterContext,
)
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope
from maverick.privacy_rights_intake import (
    ConsumerRightsIdentityEvidence,
    ConsumerRightsIntakeAuthority,
    PrivacyRightsIntakeConfigError,
    PrivacyRightsIntakeConflict,
    PrivacyRightsIntakeStore,
)
from maverick.privacy_rights_intake import (
    enabled as intake_enabled,
)

from .consent_identity_federation_api import (
    default_consent_identity_federation_dependencies,
    resolve_consent_pairing_context,
)
from .consent_public_api import (
    PublicClientBinding,
    PublicConsentDependencies,
    PublicProfileBinding,
    PublicRequestContext,
    PublicRightsIntakeMaterial,
    default_public_consent_dependencies,
)

_DIGEST_BYTES = 32
_DEFAULT_REQUEST_TTL_SECONDS = 86_400
_DEFAULT_RETENTION_SECONDS = 365 * 24 * 3_600
_DEFAULT_MAX_ACTIVE_REQUESTS = 1_000


@dataclass(frozen=True, slots=True)
class PrivacyRightsIntakeCompositionSettings:
    request_ttl_seconds: int
    retention_seconds: int
    max_active_requests: int
    max_active_requests_per_subject: int = 25


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
        raise PrivacyRightsIntakeConfigError(
            "privacy-rights intake authority metadata is invalid"
        ) from exc


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


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != _DIGEST_BYTES * 2
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise PrivacyRightsIntakeConfigError(f"{label} is unavailable")
    return value


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PrivacyRightsIntakeConfigError(f"{label} is outside its bound")
    return value


def privacy_rights_intake_composition_enabled(
    config: Mapping[str, Any] | None = None,
) -> bool:
    """Probe code-plane readiness, or an explicitly supplied tenant snapshot.

    A no-argument app-level probe deliberately does not read ambient config:
    public requests establish their tenant only after opaque credential
    authentication.  The request factory evaluates the exact tenant overlay.
    """

    if config is None:
        return True
    try:
        return intake_enabled(config) is True and consent_identity_enabled(config) is True
    except Exception:
        return False


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            source_errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsIntakeConfigError(
            "privacy-rights intake tenant configuration is unavailable"
        ) from exc
    if source_errors or not isinstance(config, Mapping):
        raise PrivacyRightsIntakeConfigError(
            "privacy-rights intake tenant configuration source is invalid"
        )
    if not privacy_rights_intake_composition_enabled(config):
        raise PrivacyRightsIntakeConfigError("privacy-rights intake is disabled for this tenant")
    return config


def _settings(config: Mapping[str, Any]) -> PrivacyRightsIntakeCompositionSettings:
    privacy = config.get("privacy_automation") if isinstance(config, Mapping) else None
    table = privacy.get("rights_consumer_intake") if isinstance(privacy, Mapping) else None
    if not isinstance(table, Mapping) or table.get("enable") is not True:
        raise PrivacyRightsIntakeConfigError("consumer rights intake is disabled")
    max_active_requests = _bounded_integer(
        table.get("max_active_requests", _DEFAULT_MAX_ACTIVE_REQUESTS),
        "max_active_requests",
        minimum=1,
        maximum=10_000,
    )
    max_active_requests_per_subject = _bounded_integer(
        table.get("max_active_requests_per_subject", 25),
        "max_active_requests_per_subject",
        minimum=1,
        maximum=10_000,
    )
    if max_active_requests_per_subject > max_active_requests:
        raise PrivacyRightsIntakeConfigError(
            "max_active_requests_per_subject exceeds the tenant-wide limit"
        )
    return PrivacyRightsIntakeCompositionSettings(
        request_ttl_seconds=_bounded_integer(
            table.get("request_ttl_seconds", _DEFAULT_REQUEST_TTL_SECONDS),
            "request_ttl_seconds",
            minimum=60,
            maximum=2_592_000,
        ),
        retention_seconds=_bounded_integer(
            table.get("retention_seconds", _DEFAULT_RETENTION_SECONDS),
            "retention_seconds",
            minimum=3_600,
            maximum=316_224_000,
        ),
        max_active_requests=max_active_requests,
        max_active_requests_per_subject=max_active_requests_per_subject,
    )


def privacy_rights_intake_trust_context_ref(pairing: ConsentPairingContext) -> str:
    """Derive the selector-free Trust Center context reference for a capability."""

    context = pairing.normalized()
    digest = _sha256(
        {
            "schema": "lightwork.privacy-rights-intake-context-ref.v1",
            "tenant_id": context.tenant_id,
            "client_credential_sha256": context.client_credential_sha256,
            "profile_credential_sha256": context.profile_credential_sha256,
            "channel_binding_sha256": context.channel_binding_sha256,
        }
    )
    return f"TCA.PRI.{digest[:32]}"


def _service_principal(pairing: ConsentPairingContext) -> str:
    digest = _sha256(
        {
            "schema": "lightwork.privacy-rights-intake-principal.v1",
            "tenant_id": pairing.tenant_id,
            "client_credential_sha256": pairing.client_credential_sha256,
            "profile_credential_sha256": pairing.profile_credential_sha256,
        }
    )
    return f"pro-rights-intake-{digest[:32]}"


def _validate_contract(
    pairing: ConsentPairingContext,
    public_configuration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> None:
    publication = public_configuration.get("publication")
    property_binding = public_configuration.get("property")
    if (
        not isinstance(publication, Mapping)
        or not isinstance(property_binding, Mapping)
        or property_binding.get("property_id") != pairing.property_id
        or property_binding.get("revision") != pairing.property_revision
        or publication.get("property_revision") != pairing.property_revision
        or not _same(publication.get("publication_sha256"), pairing.publication_sha256)
        or not _same(publication.get("bundle_sha256"), pairing.bundle_sha256)
        or not _same(
            public_configuration.get("configuration_sha256"),
            pairing.configuration_sha256,
        )
        or policy.get("policy_id") != pairing.policy_id
        or policy.get("version") != pairing.policy_version
        or not _same(policy.get("policy_sha256"), pairing.policy_sha256)
    ):
        raise PrivacyRightsIntakeConflict("published consent authority changed")


def _validate_public_snapshot(
    resolved: object,
    *,
    tenant_id: str,
    initial_client: PublicClientBinding,
    initial_profile: PublicProfileBinding,
) -> tuple[PublicClientBinding, PublicProfileBinding, PublicRequestContext, str]:
    client = getattr(resolved, "binding", None)
    profile = getattr(resolved, "profile", None)
    context = getattr(resolved, "context", None)
    actor_sha256 = getattr(resolved, "actor_sha256", None)
    if (
        not isinstance(client, PublicClientBinding)
        or not isinstance(profile, PublicProfileBinding)
        or not isinstance(context, PublicRequestContext)
        or client != initial_client
        or profile != initial_profile
        or client.tenant_id != tenant_id
        or profile.tenant_id != tenant_id
    ):
        raise PrivacyRightsIntakeConflict("public client/profile authority changed")
    _digest(actor_sha256, "public actor authority")
    return client, profile, context, actor_sha256


def _bridged_identity_evidence(
    raw: object,
    *,
    pairing: ConsentPairingContext,
    settings: ConsentIdentitySettings,
    now: float,
    request: Request,
) -> ConsumerRightsIdentityEvidence:
    if not isinstance(raw, ConsentIdentityEvidence):
        raise PrivacyRightsIntakeConfigError("identity evidence authority is unavailable")
    raw_body = asdict(raw)
    supplied = raw_body.pop("evidence_sha256", None)
    if (
        raw.schema != "lightwork.consent.identity-evidence.v1"
        or raw.tenant_id != pairing.tenant_id
        or not _same(raw.target_fingerprint, pairing.fingerprint)
        or not _same(supplied, _sha256(raw_body))
        or raw.valid_until <= now
        or isinstance(raw.pairing_revision, bool)
        or not isinstance(raw.pairing_revision, int)
        or raw.pairing_revision < 1
    ):
        raise PrivacyRightsIntakeConflict("fresh OIDC identity evidence changed")
    _digest(raw.subject_binding_sha256, "OIDC subject binding")
    _digest(raw.oidc_verification_sha256, "OIDC verification evidence")
    resolver = getattr(
        request.app.state,
        "privacy_rights_intake_identity_assurance_resolver",
        None,
    )
    if not callable(resolver):
        # Verified OIDC transport alone contains no ACR, AMR, auth_time, or
        # issuer-specific assurance mapping.  Refuse intake instead of
        # manufacturing a substantial/high assurance claim.
        raise PrivacyRightsIntakeConfigError("explicit identity assurance authority is unavailable")
    try:
        value = resolver(
            federation_evidence=raw,
            pairing_context=pairing,
            identity_settings=settings,
            resolved_at=now,
            request=request,
        )
    except PrivacyRightsIntakeConfigError:
        raise
    except Exception as exc:
        raise PrivacyRightsIntakeConflict(
            "explicit identity assurance evidence is unavailable"
        ) from exc
    if not isinstance(value, ConsumerRightsIdentityEvidence):
        raise PrivacyRightsIntakeConfigError("explicit identity assurance authority is unavailable")
    evidence = value.normalized()
    expected_ref = f"CONSENT-OIDC-{raw.evidence_sha256}"
    if (
        evidence.tenant_id != pairing.tenant_id
        or not _same(evidence.property_sha256, pairing.property_sha256)
        or not _same(evidence.profile_sha256, _text_sha256(pairing.profile_id))
        or not _same(evidence.profile_binding_sha256, pairing.profile_binding_sha256)
        or not _same(evidence.subject_binding_sha256, raw.subject_binding_sha256)
        or evidence.channel != pairing.channel_kind
        or not _same(evidence.channel_binding_sha256, pairing.channel_binding_sha256)
        or evidence.evidence_ref != expected_ref
        or evidence.evidence_revision != raw.pairing_revision
        or evidence.assurance_level not in {"substantial", "high"}
        or evidence.valid_until > float(raw.valid_until)
        or evidence.valid_until <= now
        or evidence.verified_at > now + 60
        or evidence.revoked
    ):
        raise PrivacyRightsIntakeConflict(
            "explicit identity assurance evidence is stale or misbound"
        )
    return evidence


def _validated_trust_authority(
    value: object,
    *,
    pairing: ConsentPairingContext,
    actor_sha256: str,
    client: PublicClientBinding,
    now: float,
) -> tuple[TrustCenterContext, TrustCenterCapabilityGrant]:
    if not isinstance(value, TrustCenterContext):
        raise PrivacyRightsIntakeConfigError("Trust Center authority is unavailable")
    expected_context_sha = ConsumerTrustCenterSourceAdapter.context_sha256(value)
    if (
        value.revoked
        or value.tenant_id != pairing.tenant_id
        or value.property_id != pairing.property_id
        or value.profile_id != pairing.profile_id
        or not _same(value.actor_sha256, actor_sha256)
        or value.server_origin != client.target_origin
        or value.server_bundle_id != client.target_bundle_id
        or value.server_platform != client.target_platform
        or value.valid_until <= now
        or value.retained_until <= now
        or not _same(value.context_sha256, expected_context_sha)
    ):
        raise PrivacyRightsIntakeConflict("Trust Center authority changed")
    rights_grants = tuple(
        grant
        for grant in value.capability_grants
        if isinstance(grant, TrustCenterCapabilityGrant) and grant.capability == "rights_cases"
    )
    if len(rights_grants) != 1:
        raise PrivacyRightsIntakeConflict("an active rights_cases grant is required")
    grant = rights_grants[0]
    if (
        grant.revoked
        or grant.valid_until <= now
        or grant.property_id != pairing.property_id
        or not _same(grant.tenant_sha256, _text_sha256(pairing.tenant_id))
        or not _same(grant.profile_sha256, _text_sha256(pairing.profile_id))
        or not _same(
            grant.grant_sha256,
            ConsumerTrustCenterSourceAdapter.capability_grant_sha256(grant),
        )
    ):
        raise PrivacyRightsIntakeConflict("rights_cases grant changed")
    return value, grant


def _public_dependencies(request: Request) -> PublicConsentDependencies:
    factory = getattr(
        request.app.state,
        "privacy_rights_intake_public_dependencies_factory",
        None,
    )
    value = factory(request=request) if callable(factory) else default_public_consent_dependencies()
    if not isinstance(value, PublicConsentDependencies):
        raise PrivacyRightsIntakeConfigError("public consent authority is unavailable")
    return value


def _identity_settings(
    request: Request,
    config: Mapping[str, Any],
) -> ConsentIdentitySettings:
    try:
        expected = load_consent_identity_settings(config).normalized()
    except Exception as exc:
        raise PrivacyRightsIntakeConfigError("OIDC identity authority is unavailable") from exc
    factory = getattr(
        request.app.state,
        "privacy_rights_intake_identity_settings_factory",
        None,
    )
    value = factory(request=request, config=config) if callable(factory) else expected
    if not isinstance(value, ConsentIdentitySettings):
        raise PrivacyRightsIntakeConfigError("OIDC identity authority is unavailable")
    normalized = value.normalized()
    if normalized != expected:
        raise PrivacyRightsIntakeConflict("tenant OIDC identity authority changed")
    return normalized


def _identity_store(request: Request, tenant_id: str) -> object:
    factory = getattr(
        request.app.state,
        "consent_identity_federation_store_factory",
        None,
    )
    if callable(factory):
        value = factory(tenant_id=tenant_id, request=request)
    else:
        value = default_consent_identity_federation_dependencies().pairing_store
    if not callable(getattr(value, "resolve_redeemed_identity_evidence", None)):
        raise PrivacyRightsIntakeConfigError("identity evidence authority is unavailable")
    return value


def _trust_store(
    request: Request,
    pairing: ConsentPairingContext,
    principal_ref: str,
) -> object:
    from .consumer_trust_center_authority_api import _default_store_for

    factory = getattr(
        request.app.state,
        "consumer_trust_center_authority_store_factory",
        None,
    )

    def principal_resolver() -> str:
        return principal_ref

    value = (
        factory(
            tenant_id=pairing.tenant_id,
            principal_ref=principal_ref,
            principal_resolver=principal_resolver,
            request=request,
        )
        if callable(factory)
        else _default_store_for(request, pairing.tenant_id, principal_ref)
    )
    if not callable(getattr(value, "make_context_resolver", None)):
        raise PrivacyRightsIntakeConfigError("Trust Center authority is unavailable")
    return value


def _rights_store(
    request: Request,
    pairing: ConsentPairingContext,
    principal_ref: str,
) -> object:
    from .privacy_rights_orchestration_api import _default_store_for

    factory = getattr(
        request.app.state,
        "privacy_rights_orchestration_store_factory",
        None,
    )

    def principal_resolver() -> str:
        return principal_ref

    return (
        factory(
            tenant_id=pairing.tenant_id,
            principal_ref=principal_ref,
            principal_resolver=principal_resolver,
            request=request,
        )
        if callable(factory)
        else _default_store_for(pairing.tenant_id, principal_ref)
    )


def _store_path(request: Request, tenant_id: str) -> Path:
    factory = getattr(request.app.state, "privacy_rights_intake_path_factory", None)
    value = (
        factory(tenant_id=tenant_id, request=request)
        if callable(factory)
        else data_dir(
            "privacy_automation",
            "privacy-rights-intake.sqlite3",
            tenant=tenant_id,
        )
    )
    if not isinstance(value, (str, Path)):
        raise PrivacyRightsIntakeConfigError("privacy-rights intake path is unavailable")
    return Path(value)


def _clock(request: Request) -> Callable[[], float]:
    value = getattr(request.app.state, "privacy_rights_intake_clock", None)
    return value if callable(value) else time.time


def _maintenance_authorizer(
    request: Request,
    *,
    tenant_id: str,
    principal_ref: str,
) -> Callable[[], bool]:
    factory = getattr(
        request.app.state,
        "privacy_rights_intake_maintenance_authorizer_factory",
        None,
    )
    if not callable(factory):
        return lambda: False
    value = factory(
        tenant_id=tenant_id,
        principal_ref=principal_ref,
        request=request,
    )
    if not callable(value):
        raise PrivacyRightsIntakeConfigError(
            "privacy-rights intake maintenance authority is unavailable"
        )
    return value


def _build_material(  # noqa: PLR0913 - mirrors the authenticated public API seam
    *,
    tenant_id: str,
    initial_client_binding: PublicClientBinding,
    initial_profile_binding: PublicProfileBinding,
    active_public_configuration: Mapping[str, Any],
    active_policy: Mapping[str, Any],
    public_authority_resolver: Callable[[], object],
    request: Request,
) -> PublicRightsIntakeMaterial:
    """Build one request-scoped bridge from independently resolved authorities."""

    try:
        tenant = canonical_tenant_id(tenant_id)
    except (TypeError, ValueError) as exc:
        raise PrivacyRightsIntakeConfigError("tenant authority is unavailable") from exc
    if (
        tenant != tenant_id
        or not isinstance(initial_client_binding, PublicClientBinding)
        or not isinstance(initial_profile_binding, PublicProfileBinding)
        or not isinstance(active_public_configuration, Mapping)
        or not isinstance(active_policy, Mapping)
        or not callable(public_authority_resolver)
    ):
        raise PrivacyRightsIntakeConfigError("public intake authority is incomplete")
    gate = getattr(request.app.state, "privacy_rights_intake_gate", None)
    if not callable(gate) or gate() is not True:
        raise PrivacyRightsIntakeConfigError("consumer rights intake is disabled")

    tenant_config = _load_tenant_config(tenant)
    composition_settings = _settings(tenant_config)
    identity_settings = _identity_settings(request, tenant_config)
    public = _public_dependencies(request)
    clock = _clock(request)

    def resolve_public() -> tuple[
        PublicClientBinding,
        PublicProfileBinding,
        PublicRequestContext,
        str,
        ConsentPairingContext,
    ]:
        current = public_authority_resolver()
        client, profile, context, actor = _validate_public_snapshot(
            current,
            tenant_id=tenant,
            initial_client=initial_client_binding,
            initial_profile=initial_profile_binding,
        )
        pairing = resolve_consent_pairing_context(public, client, profile).normalized()
        _validate_contract(pairing, active_public_configuration, active_policy)
        return client, profile, context, actor, pairing

    initial_client, _profile, _context, _actor, initial_pairing = resolve_public()
    principal_ref = _service_principal(initial_pairing)
    federation = _identity_store(request, tenant)
    trust_store = _trust_store(request, initial_pairing, principal_ref)
    rights_store = _rights_store(request, initial_pairing, principal_ref)
    context_ref = privacy_rights_intake_trust_context_ref(initial_pairing)
    trust_resolver = trust_store.make_context_resolver(context_ref)
    if not callable(trust_resolver):
        raise PrivacyRightsIntakeConfigError("Trust Center authority is unavailable")

    def resolve_raw_identity(pairing: ConsentPairingContext) -> object:
        try:
            return federation.resolve_redeemed_identity_evidence(pairing)
        except PrivacyRightsIntakeConfigError:
            raise
        except Exception as exc:
            raise PrivacyRightsIntakeConflict(
                "fresh independently verified identity evidence is unavailable"
            ) from exc

    def identity_evidence_resolver() -> ConsumerRightsIdentityEvidence:
        _client, _profile, _context, _actor, pairing = resolve_public()
        raw = resolve_raw_identity(pairing)
        return _bridged_identity_evidence(
            raw,
            pairing=pairing,
            settings=identity_settings,
            now=float(clock()),
            request=request,
        )

    def authority_resolver() -> ConsumerRightsIntakeAuthority:
        client, _profile, _context, actor, pairing = resolve_public()
        raw_identity = resolve_raw_identity(pairing)
        bridged_identity = _bridged_identity_evidence(
            raw_identity,
            pairing=pairing,
            settings=identity_settings,
            now=float(clock()),
            request=request,
        )
        try:
            raw_trust = trust_resolver()
        except Exception as exc:
            raise PrivacyRightsIntakeConflict("Trust Center authority is unavailable") from exc
        trust_context, grant = _validated_trust_authority(
            raw_trust,
            pairing=pairing,
            actor_sha256=actor,
            client=client,
            now=float(clock()),
        )
        valid_until = min(
            float(bridged_identity.valid_until),
            float(trust_context.valid_until),
            float(grant.valid_until),
        )
        if client.expires_at is not None:
            valid_until = min(valid_until, float(client.expires_at))
        return ConsumerRightsIntakeAuthority(
            tenant_id=tenant,
            property_sha256=pairing.property_sha256,
            property_revision=pairing.property_revision,
            profile_sha256=_text_sha256(pairing.profile_id),
            profile_credential_sha256=pairing.profile_credential_sha256,
            profile_binding_sha256=pairing.profile_binding_sha256,
            profile_revision=pairing.profile_revision,
            subject_binding_sha256=bridged_identity.subject_binding_sha256,
            client_credential_sha256=pairing.client_credential_sha256,
            client_record_sha256=pairing.client_record_sha256,
            client_revision=pairing.client_revision,
            publication_sha256=pairing.publication_sha256,
            publication_bundle_sha256=pairing.bundle_sha256,
            configuration_sha256=pairing.configuration_sha256,
            policy_sha256=pairing.policy_sha256,
            policy_version=pairing.policy_version,
            trust_context_sha256=trust_context.context_sha256,
            trust_context_revision=trust_context.revision,
            capability_grant_sha256=grant.grant_sha256,
            channel=pairing.channel_kind,
            channel_binding_sha256=pairing.channel_binding_sha256,
            identity_authority_sha256=bridged_identity.verification_authority_sha256,
            minimum_identity_assurance=bridged_identity.assurance_level,
            valid_until=valid_until,
            revoked=False,
        ).normalized()

    initial_authority = authority_resolver()
    if initial_client != initial_client_binding:
        raise PrivacyRightsIntakeConflict("public client authority changed")

    def require_gate() -> None:
        if gate() is not True:
            raise PrivacyRightsIntakeConfigError("consumer rights intake is disabled")

    constructor: dict[str, Any] = {
        "rights_store": rights_store,
        "authority_resolver": authority_resolver,
        "identity_evidence_resolver": identity_evidence_resolver,
        "request_ttl_seconds": composition_settings.request_ttl_seconds,
        "retention_seconds": composition_settings.retention_seconds,
        "max_active_requests": composition_settings.max_active_requests,
        "max_active_requests_per_subject": (composition_settings.max_active_requests_per_subject),
        "maintenance_authorizer": _maintenance_authorizer(
            request,
            tenant_id=tenant,
            principal_ref=principal_ref,
        ),
        "config_gate": require_gate,
        "clock": clock,
    }
    signing_key_resolver = getattr(
        request.app.state,
        "privacy_rights_intake_signing_key_resolver",
        None,
    )
    if signing_key_resolver is not None:
        if not callable(signing_key_resolver):
            raise PrivacyRightsIntakeConfigError(
                "privacy-rights intake signing authority is unavailable"
            )
        constructor["signing_key_resolver"] = signing_key_resolver
    store = PrivacyRightsIntakeStore(_store_path(request, tenant), **constructor)
    return PublicRightsIntakeMaterial(store=store, authority=initial_authority)


def attach_privacy_rights_intake_composition(app: FastAPI) -> None:
    """Install lazy production factories without opening any tenant storage."""

    state = app.state
    deployment_gate = getattr(state, "privacy_rights_intake_gate", None)

    def gate() -> bool:
        try:
            if privacy_rights_intake_composition_enabled() is not True:
                return False
            if not callable(
                getattr(
                    state,
                    "privacy_rights_intake_identity_assurance_resolver",
                    None,
                )
            ):
                return False
            return not callable(deployment_gate) or deployment_gate() is True
        except Exception:
            return False

    state.privacy_rights_intake_gate = gate
    existing_factory = getattr(state, "privacy_rights_intake_store_factory", None)
    if callable(existing_factory):
        return

    def store_factory(**kwargs: Any) -> PublicRightsIntakeMaterial:
        request = kwargs.get("request")
        if not isinstance(request, Request) or request.app is not app:
            raise PrivacyRightsIntakeConfigError("public request authority is unavailable")
        return _build_material(**kwargs)

    state.privacy_rights_intake_store_factory = store_factory


__all__ = [
    "PrivacyRightsIntakeCompositionSettings",
    "attach_privacy_rights_intake_composition",
    "privacy_rights_intake_composition_enabled",
    "privacy_rights_intake_trust_context_ref",
]
