"""Production composition for the configured Global Opt-Out application.

The administrative factory resolves a safe public-client identifier against
the live public consent registry and the active publication/policy stores.  The
public factory is called only after the existing consent router has admitted a
client and profile capability, resolved the active contract, and constructed a
profile-bound privacy-rights intake authority.

Installation is lazy and opens no tenant persistence during import or startup.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from maverick import consent_global_opt_out as opt_out
from maverick.paths import canonical_tenant_id, tenant_scope

from ._shared import authenticated_subject
from .auth import has_global_permission
from .consent_public_api import (
    PublicClientBinding,
    PublicConsentDependencies,
    PublicProfileBinding,
    PublicRightsIntakeMaterial,
    default_public_consent_dependencies,
)

_MAX_AUTHORITY_TIME = 99_999_999_999.0


class GlobalOptOutCompositionError(opt_out.GlobalOptOutError):
    """Deployment composition cannot resolve an exact dependency."""


@dataclass(frozen=True, slots=True)
class GlobalOptOutPublicMaterial:
    """Request-scoped material consumed by the isolated public route hook."""

    store: opt_out.GlobalOptOutStore
    authority: opt_out.GlobalOptOutPublicAuthority


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise GlobalOptOutCompositionError("Global Opt-Out authority is invalid") from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _request_for(app: FastAPI, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise GlobalOptOutCompositionError("Global Opt-Out request authority is unavailable")
    return request


def _principal_ref(request: Request, tenant_id: str) -> str:
    # The API's own subject resolution, so the local single-user operator and
    # a static dashboard token resolve to the same reference on both sides.
    try:
        subject = authenticated_subject(
            request, error_detail="authenticated Global Opt-Out principal is unavailable",
        )
    except HTTPException as exc:
        raise opt_out.GlobalOptOutPermissionDenied(
            "authenticated Global Opt-Out principal is unavailable"
        ) from exc
    digest = hashlib.sha256(
        f"lightwork.global-opt-out.identity.v1:{tenant_id}:{subject}".encode()
    ).hexdigest()
    return f"global-opt-out-admin-{digest[:32]}"


def _load_tenant_config(tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    try:
        from maverick import config as config_module

        with tenant_scope(tenant=tenant):
            config = config_module.load_config()
            errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise opt_out.GlobalOptOutDisabled(
            "Global Opt-Out tenant configuration is unavailable"
        ) from exc
    if errors or not isinstance(config, Mapping):
        raise opt_out.GlobalOptOutDisabled("Global Opt-Out tenant configuration is invalid")
    opt_out.require_global_opt_out_enabled(config)
    return config


def global_opt_out_composition_enabled(tenant_id: str | None = None) -> bool:
    """Side-effect-free code probe, or exact tenant gate when supplied."""

    if tenant_id is None:
        return True
    try:
        return opt_out.global_opt_out_enabled(_load_tenant_config(tenant_id)) is True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def _public_dependencies(app: FastAPI, request: Request) -> PublicConsentDependencies:
    factory = getattr(app.state, "global_opt_out_public_dependencies_factory", None)
    value = factory(request=request) if callable(factory) else default_public_consent_dependencies()
    if not isinstance(value, PublicConsentDependencies):
        raise GlobalOptOutCompositionError("public consent authority is unavailable")
    return value


def _active_policy(
    dependencies: PublicConsentDependencies,
    tenant_id: str,
    policy_id: str,
    policy_version: int,
    evaluated_at: float,
) -> Mapping[str, Any]:
    store = dependencies.preference_store_for(tenant_id)
    policy = store.get_active_policy(
        tenant_id, policy_id, version=policy_version, at=evaluated_at,
    )
    if not isinstance(policy, Mapping):
        raise opt_out.GlobalOptOutAuthorityStale("receipt policy authority changed")
    return policy


def _channel_binding_sha256(client: PublicClientBinding | Mapping[str, Any]) -> str:
    def field(name: str) -> object:
        return client.get(name) if isinstance(client, Mapping) else getattr(client, name)

    return _sha256(
        {
            "schema": "lightwork.global-opt-out-channel-binding.v1",
            "client_kind": field("client_kind"),
            "browser_origin": field("browser_origin"),
            "service_client_id": field("service_client_id"),
            "target_origin": field("target_origin"),
            "target_bundle_id": field("target_bundle_id"),
            "target_platform": field("target_platform"),
        }
    )


def _application_authority_from_contract(
    client: PublicClientBinding | Mapping[str, Any],
    configuration: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> opt_out.GlobalOptOutApplicationAuthority:
    def field(name: str) -> Any:
        return client.get(name) if isinstance(client, Mapping) else getattr(client, name)

    publication = configuration.get("publication")
    property_binding = configuration.get("property")
    if not isinstance(publication, Mapping) or not isinstance(property_binding, Mapping):
        raise opt_out.GlobalOptOutAuthorityStale("published configuration is unavailable")
    exact = (
        property_binding.get("property_id") == field("property_id")
        and property_binding.get("revision") == field("property_revision")
        and publication.get("property_revision") == field("property_revision")
        and _same(publication.get("publication_sha256"), field("publication_sha256"))
        and _same(publication.get("bundle_sha256"), field("bundle_sha256"))
        and policy.get("policy_id") == field("policy_id")
        and policy.get("version") == field("policy_version")
        and _same(policy.get("policy_sha256"), field("policy_sha256"))
    )
    if not exact:
        raise opt_out.GlobalOptOutAuthorityStale(
            "public client, publication, or policy authority changed"
        )
    content = configuration.get("configuration")
    purposes = content.get("purposes") if isinstance(content, Mapping) else None
    notice = content.get("notice") if isinstance(content, Mapping) else None
    if not isinstance(purposes, list) or not isinstance(notice, Mapping):
        raise opt_out.GlobalOptOutAuthorityStale(
            "published consent and receipt policy authority is incomplete"
        )
    published_purposes: dict[str, str] = {}
    for item in purposes:
        if not isinstance(item, Mapping):
            raise opt_out.GlobalOptOutAuthorityStale(
                "published consent and receipt policy authority is incomplete"
            )
        purpose_id = str(item.get("id", ""))
        if not purpose_id or purpose_id in published_purposes:
            raise opt_out.GlobalOptOutAuthorityStale(
                "published consent and receipt policy authority is incomplete"
            )
        published_purposes[purpose_id] = str(item.get("lawful_basis", ""))
    if published_purposes != policy.get("purposes") or not _same(
        notice.get("document_sha256"), policy.get("notice_sha256")
    ):
        raise opt_out.GlobalOptOutAuthorityStale(
            "published consent and receipt policy authority changed"
        )
    channel = "browser-origin" if field("client_kind") == "browser" else "service-client"
    expiry = field("expires_at")
    return opt_out.issue_application_authority(
        tenant_id=str(field("tenant_id")),
        application_ref=str(field("credential_id")),
        public_client_revision=int(field("revision")),
        public_client_record_sha256=str(field("record_sha256")),
        property_revision=int(field("property_revision")),
        property_sha256=str(field("property_sha256")),
        publication_sha256=str(field("publication_sha256")),
        publication_bundle_sha256=str(field("bundle_sha256")),
        configuration_sha256=str(configuration["configuration_sha256"]),
        policy_id=str(field("policy_id")),
        policy_version=int(field("policy_version")),
        policy_sha256=str(field("policy_sha256")),
        channel=channel,
        origin_or_service_sha256=_channel_binding_sha256(client),
        valid_until=float(expiry) if expiry is not None else _MAX_AUTHORITY_TIME,
        revoked=False,
    )


def _resolve_admin_application(
    app: FastAPI,
    *,
    tenant_id: str,
    principal_ref: str,
    application_ref: str,
    request: Request,
) -> opt_out.GlobalOptOutApplicationAuthority:
    tenant = canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)
    expected_principal = _principal_ref(selected, tenant)
    if not _same(principal_ref, expected_principal):
        raise opt_out.GlobalOptOutPermissionDenied("operator principal authority changed")
    dependencies = _public_dependencies(app, selected)
    listed = dependencies.credential_store.list_clients(tenant, limit=500)
    items = listed.get("items") if isinstance(listed, Mapping) else None
    if not isinstance(items, list) or listed.get("truncated") is not False:
        raise opt_out.GlobalOptOutAuthorityStale("public client authority is unavailable")
    matches = [
        item
        for item in items
        if isinstance(item, Mapping)
        and item.get("credential_id") == application_ref
        and item.get("status") == "active"
    ]
    if len(matches) != 1:
        raise opt_out.GlobalOptOutAuthorityStale("public client authority was not found")
    client = matches[0]
    now = float(dependencies.clock())
    publishing = dependencies.publishing_store_for(tenant)
    preview = publishing.preview(
        tenant,
        str(client["property_id"]),
        str(client["rule_group_id"]),
        int(client["rule_group_version"]),
    )
    preview_bundle = preview.get("bundle") if isinstance(preview, Mapping) else None
    preview_property = (
        preview_bundle.get("property") if isinstance(preview_bundle, Mapping) else None
    )
    if (
        not isinstance(preview_property, Mapping)
        or not _same(preview_property.get("record_sha256"), client.get("property_sha256"))
        or not _same(preview.get("bundle_sha256"), client.get("bundle_sha256"))
    ):
        raise opt_out.GlobalOptOutAuthorityStale("published configuration changed")
    configuration = publishing.resolve_public_configuration(
        tenant,
        str(client["property_id"]),
        server_origin=client.get("target_origin"),
        server_bundle_id=client.get("target_bundle_id"),
        server_platform=client.get("target_platform"),
        jurisdiction=str(client["jurisdiction"]),
        country_code=str(client["country_code"]),
        region_code=str(client["region_code"]),
        requested_locale=str(client["default_locale"]),
        evaluated_at=now,
    )
    if not isinstance(configuration, Mapping) or configuration.get("allowed") is not True:
        raise opt_out.GlobalOptOutAuthorityStale("published configuration is unavailable")
    policy = _active_policy(
        dependencies,
        tenant,
        str(client["policy_id"]),
        int(client["policy_version"]),
        now,
    )
    return _application_authority_from_contract(client, configuration, policy)


def _admin_resolver_factory(
    app: FastAPI,
    *,
    tenant_id: str,
    principal_ref: str,
    request: Request,
) -> opt_out.ApplicationAuthorityResolver:
    factory = getattr(app.state, "global_opt_out_application_authority_resolver_factory", None)
    if callable(factory):
        resolver = factory(tenant_id, request)
        if not callable(resolver):
            raise GlobalOptOutCompositionError(
                "Global Opt-Out application resolver is unavailable"
            )
        return resolver

    def resolve(
        requested_tenant: str,
        requested_principal: str,
        application_ref: str,
    ) -> opt_out.GlobalOptOutApplicationAuthority:
        return _resolve_admin_application(
            app,
            tenant_id=requested_tenant,
            principal_ref=requested_principal,
            application_ref=application_ref,
            request=request,
        )

    return resolve


def global_opt_out_admin_store_factory(
    app: FastAPI,
    *,
    tenant_id: str,
    principal_ref: str,
    request: object,
) -> opt_out.GlobalOptOutStore:
    tenant = canonical_tenant_id(tenant_id)
    selected = _request_for(app, request)
    expected = _principal_ref(selected, tenant)
    if not _same(principal_ref, expected):
        raise opt_out.GlobalOptOutPermissionDenied("operator principal authority changed")
    config = _load_tenant_config(tenant)
    limits = opt_out.load_global_opt_out_limits(config)

    def principal_resolver() -> str:
        current = _principal_ref(selected, tenant)
        if not _same(current, expected):
            raise opt_out.GlobalOptOutPermissionDenied("operator principal authority changed")
        return expected

    clock = getattr(app.state, "global_opt_out_clock", time.time)
    if not callable(clock):
        raise GlobalOptOutCompositionError("Global Opt-Out clock is unavailable")
    return opt_out.GlobalOptOutStore(
        tenant_id=tenant,
        principal_ref=expected,
        application_authority_resolver=_admin_resolver_factory(
            app,
            tenant_id=tenant,
            principal_ref=expected,
            request=selected,
        ),
        principal_resolver=principal_resolver,
        config_gate=lambda: _load_tenant_config(tenant),
        limits=limits,
        maintenance_authorizer=lambda: has_global_permission(selected, "admin") is True,
        clock=clock,
    )


def _validate_public_contract(
    client: PublicClientBinding,
    profile: PublicProfileBinding,
    configuration: Mapping[str, Any],
    policy: Mapping[str, Any],
    intake: object,
) -> None:
    normalized = getattr(intake, "normalized", None)
    if callable(normalized):
        intake = normalized()
    required = (
        getattr(intake, "tenant_id", None) == client.tenant_id == profile.tenant_id,
        getattr(intake, "property_revision", None) == client.property_revision,
        _same(getattr(intake, "property_sha256", None), client.property_sha256),
        getattr(intake, "client_revision", None) == client.revision,
        _same(getattr(intake, "client_record_sha256", None), client.record_sha256),
        _same(
            getattr(intake, "client_credential_sha256", None),
            client.credential_sha256,
        ),
        _same(
            getattr(intake, "profile_credential_sha256", None),
            profile.credential_sha256,
        ),
        _same(
            getattr(intake, "profile_binding_sha256", None),
            profile.binding_sha256,
        ),
        _same(
            getattr(intake, "publication_sha256", None),
            client.publication_sha256,
        ),
        _same(
            getattr(intake, "publication_bundle_sha256", None),
            client.bundle_sha256,
        ),
        _same(
            getattr(intake, "configuration_sha256", None),
            configuration.get("configuration_sha256"),
        ),
        getattr(intake, "policy_version", None) == client.policy_version,
        _same(getattr(intake, "policy_sha256", None), client.policy_sha256),
        getattr(intake, "revoked", None) is False,
    )
    if not all(required):
        raise opt_out.GlobalOptOutAuthorityStale(
            "public consent or privacy-rights authority changed"
        )
    _application_authority_from_contract(client, configuration, policy)


def _public_authority(
    client: PublicClientBinding,
    profile: PublicProfileBinding,
    configuration: Mapping[str, Any],
    policy: Mapping[str, Any],
    intake: object,
) -> opt_out.GlobalOptOutPublicAuthority:
    _validate_public_contract(client, profile, configuration, policy, intake)
    application = _application_authority_from_contract(client, configuration, policy)
    valid_until = min(
        application.valid_until,
        float(getattr(intake, "valid_until", application.valid_until)),
    )
    return opt_out.issue_public_authority(
        tenant_id=client.tenant_id,
        application_ref=client.credential_id,
        public_client_revision=client.revision,
        public_client_record_sha256=client.record_sha256,
        property_revision=client.property_revision,
        property_sha256=client.property_sha256,
        publication_sha256=client.publication_sha256,
        publication_bundle_sha256=client.bundle_sha256,
        configuration_sha256=str(configuration["configuration_sha256"]),
        policy_id=client.policy_id,
        policy_version=client.policy_version,
        policy_sha256=client.policy_sha256,
        channel=str(intake.channel),
        origin_or_service_sha256=application.origin_or_service_sha256,
        profile_sha256=str(intake.profile_sha256),
        profile_binding_sha256=profile.binding_sha256,
        profile_revision=int(intake.profile_revision),
        intake_authority_sha256=opt_out.authority_material_sha256(intake),
        valid_until=valid_until,
        revoked=False,
    )


def _privacy_rights_submitter(material: PublicRightsIntakeMaterial) -> opt_out.PrivacyRightsSubmitter:
    store = material.store

    def submit(
        authority: object,
        rights: Sequence[str],
        expected_revision: int,
        idempotency_key: str,
    ) -> opt_out.GlobalOptOutDSARResult:
        try:
            if tuple(rights) != ("opt_out",) or expected_revision != 0:
                raise opt_out.GlobalOptOutDSARUnavailable(
                    "Global Opt-Out may create only a new opt_out request"
                )
            status = store.create_request(
                authority,
                rights=["opt_out"],
                expected_revision=0,
                idempotency_key=idempotency_key,
            )
            verifier = getattr(store, "verify_signed_status", None)
            if not callable(verifier) or verifier(status) is not True:
                raise opt_out.GlobalOptOutDSARUnavailable(
                    "privacy-rights signed status could not be verified"
                )
            payload = getattr(status, "payload", None)
            case_id = payload.get("case_id") if isinstance(payload, Mapping) else None
            returned_rights = payload.get("rights") if isinstance(payload, Mapping) else None
            result_sha = getattr(status, "evidence_sha256", None)
            if (
                returned_rights != ["opt_out"]
                or not isinstance(case_id, str)
                or not isinstance(result_sha, str)
            ):
                raise opt_out.GlobalOptOutDSARUnavailable(
                    "privacy-rights intake returned an invalid opt_out result"
                )
            return opt_out.GlobalOptOutDSARResult(
                case_id=case_id,
                result_sha256=result_sha,
            ).normalized()
        except (opt_out.GlobalOptOutAuthorityStale, opt_out.GlobalOptOutDSARUnavailable):
            raise
        except Exception as exc:
            try:
                from maverick import privacy_rights_intake as intake_ops

                if isinstance(exc, intake_ops.PrivacyRightsIntakeConflict):
                    raise opt_out.GlobalOptOutAuthorityStale(
                        "privacy-rights intake authority changed"
                    ) from exc
            except opt_out.GlobalOptOutAuthorityStale:
                raise
            except Exception:
                pass
            raise opt_out.GlobalOptOutDSARUnavailable(
                "privacy-rights intake is unavailable"
            ) from exc

    return submit


def global_opt_out_public_material_factory(  # noqa: PLR0913
    app: FastAPI,
    *,
    tenant_id: str,
    initial_client_binding: PublicClientBinding,
    initial_profile_binding: PublicProfileBinding,
    active_public_configuration: Mapping[str, Any],
    active_policy: Mapping[str, Any],
    public_authority_resolver: Callable[[], object],
    rights_intake_material: PublicRightsIntakeMaterial,
    request: object,
) -> GlobalOptOutPublicMaterial:
    tenant = canonical_tenant_id(tenant_id)
    _request_for(app, request)
    config = _load_tenant_config(tenant)
    if (
        not isinstance(initial_client_binding, PublicClientBinding)
        or not isinstance(initial_profile_binding, PublicProfileBinding)
        or initial_client_binding.tenant_id != tenant
        or initial_profile_binding.tenant_id != tenant
        or not isinstance(active_public_configuration, Mapping)
        or not isinstance(active_policy, Mapping)
        or not callable(public_authority_resolver)
        or not isinstance(rights_intake_material, PublicRightsIntakeMaterial)
    ):
        raise opt_out.GlobalOptOutAuthorityStale("public Global Opt-Out material is invalid")
    intake = rights_intake_material.authority
    initial = _public_authority(
        initial_client_binding,
        initial_profile_binding,
        active_public_configuration,
        active_policy,
        intake,
    )

    def resolve_public() -> opt_out.GlobalOptOutPublicAuthority:
        try:
            resolved = public_authority_resolver()
        except Exception as exc:
            raise opt_out.GlobalOptOutAuthorityStale(
                "public consent authority is unavailable"
            ) from exc
        client = getattr(resolved, "binding", None)
        profile = getattr(resolved, "profile", None)
        if (
            not isinstance(client, PublicClientBinding)
            or not isinstance(profile, PublicProfileBinding)
            or client != initial_client_binding
            or profile != initial_profile_binding
        ):
            raise opt_out.GlobalOptOutAuthorityStale("public consent authority changed")
        return _public_authority(
            client,
            profile,
            active_public_configuration,
            active_policy,
            intake,
        )

    principal = f"global-opt-out-public-{initial.profile_sha256[:32]}"

    def application_resolver(
        requested_tenant: str,
        requested_principal: str,
        application_ref: str,
    ) -> opt_out.GlobalOptOutApplicationAuthority:
        current = resolve_public()
        if (
            requested_tenant != tenant
            or requested_principal != principal
            or application_ref != current.application_ref
        ):
            raise opt_out.GlobalOptOutAuthorityStale("application authority changed")
        return opt_out.issue_application_authority(
            tenant_id=current.tenant_id,
            application_ref=current.application_ref,
            public_client_revision=current.public_client_revision,
            public_client_record_sha256=current.public_client_record_sha256,
            property_revision=current.property_revision,
            property_sha256=current.property_sha256,
            publication_sha256=current.publication_sha256,
            publication_bundle_sha256=current.publication_bundle_sha256,
            configuration_sha256=current.configuration_sha256,
            policy_id=current.policy_id,
            policy_version=current.policy_version,
            policy_sha256=current.policy_sha256,
            channel=current.channel,
            origin_or_service_sha256=current.origin_or_service_sha256,
            valid_until=current.valid_until,
            revoked=current.revoked,
        )

    clock = getattr(app.state, "global_opt_out_clock", time.time)
    if not callable(clock):
        raise GlobalOptOutCompositionError("Global Opt-Out clock is unavailable")
    store = opt_out.GlobalOptOutStore(
        tenant_id=tenant,
        principal_ref=principal,
        application_authority_resolver=application_resolver,
        principal_resolver=lambda: principal,
        config_gate=lambda: _load_tenant_config(tenant),
        limits=opt_out.load_global_opt_out_limits(config),
        public_authority_resolver=resolve_public,
        intake_authority_resolver=lambda: rights_intake_material.authority,
        privacy_rights_submitter=_privacy_rights_submitter(rights_intake_material),
        clock=clock,
    )
    return GlobalOptOutPublicMaterial(store=store, authority=initial)


def global_opt_out_readiness(app: FastAPI, tenant_id: str) -> Mapping[str, Any]:
    """Closed readiness without opening tenant stores or claiming live acceptance."""

    try:
        tenant = canonical_tenant_id(tenant_id)
        _load_tenant_config(tenant)
        intake_gate = getattr(app.state, "privacy_rights_intake_gate", None)
        intake_factory = getattr(app.state, "privacy_rights_intake_store_factory", None)
        public_factory = getattr(app.state, "global_opt_out_public_material_factory", None)
        ready = (
            callable(intake_gate)
            and intake_gate() is True
            and callable(intake_factory)
            and callable(public_factory)
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        ready = False
    return {
        "ready": ready,
        "configured_authority": ready,
        "privacy_rights_intake_available": ready,
        "live_device_acceptance": False,
        "live_customer_acceptance": False,
    }


def attach_consent_global_opt_out_composition(app: FastAPI) -> None:
    """Install lazy admin/public factories and strict probes."""

    state = app.state
    state.global_opt_out_enabled_probe = global_opt_out_composition_enabled
    state.global_opt_out_readiness_probe = lambda tenant_id: global_opt_out_readiness(
        app, tenant_id
    )
    if not callable(getattr(state, "global_opt_out_admin_store_factory", None)):
        state.global_opt_out_admin_store_factory = lambda **kwargs: (
            global_opt_out_admin_store_factory(app, **kwargs)
        )
    if not callable(getattr(state, "global_opt_out_public_material_factory", None)):
        state.global_opt_out_public_material_factory = lambda **kwargs: (
            global_opt_out_public_material_factory(app, **kwargs)
        )


__all__ = [
    "GlobalOptOutCompositionError",
    "GlobalOptOutPublicMaterial",
    "attach_consent_global_opt_out_composition",
    "global_opt_out_admin_store_factory",
    "global_opt_out_composition_enabled",
    "global_opt_out_public_material_factory",
    "global_opt_out_readiness",
]
