"""Production composition for privacy-rights consumer package delivery.

The core delivery authority intentionally knows neither public identities nor
document bytes.  This module composes it with two *independent* authorities:

* the public consent API's already-authenticated client/profile resolver, plus
  a deployment-owned reauthentication verifier; and
* the privacy-rights orchestration store plus the encrypted governed-document
  vault used by the stock source-retrieval worker.

No subject identifier is inferred from a case or package.  Operator minting is
therefore unavailable until a deployment injects a tenant/principal-bound
``privacy_rights_consumer_delivery_operator_subject_binding_resolver_factory``.
Likewise, a public receipt is unusable until an independent verifier is
injected.  Installation is lazy and opens no tenant store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from maverick import administration_document_access as document_access
from maverick import privacy_rights_consumer_delivery as delivery
from maverick.paths import canonical_tenant_id, data_dir, tenant_scope

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_REF_RE = re.compile(
    r"(?:env|vault|secret):([A-Z][A-Z0-9_]{0,95})\Z"
)
_MAX_PUBLIC_PACKAGE_BYTES = 16 * 1024 * 1024
_MAX_REAUTHENTICATION_AGE_SECONDS = 5 * 60
_STOCK_RECORD_TYPES = frozenset(
    {"privacy_rights_source_retrieval", "privacy_rights_response_package"}
)


class PrivacyRightsConsumerDeliveryCompositionError(
    delivery.RightsConsumerDeliveryConfigError
):
    """A production authority is absent, inconsistent, or revoked."""


@dataclass(frozen=True, slots=True)
class PrivacyRightsConsumerDeliveryCompositionSettings:
    digest_key_ref: str
    export_signing_key_ref: str
    package_encryption_key_ref: str
    server_grant_ttl_seconds: int
    max_package_bytes: int
    config_sha256: str


@dataclass(frozen=True, slots=True)
class VerifiedRightsReauthentication:
    """Strict result from a deployment-owned identity reauthentication verifier."""

    tenant_id: str
    property_id: str
    profile_binding_sha256: str
    receipt_sha256: str
    identity_authority_sha256: str
    assurance_level: str
    verified_at: float
    valid_until: float
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class _PublicSnapshot:
    tenant_id: str
    property_id: str
    client_record_sha256: str
    profile_id: str
    profile_binding_sha256: str
    subject_binding_sha256: str


@dataclass(frozen=True, slots=True)
class _PackageSnapshot:
    authority: delivery.ResolvedRightsDeliveryAuthority
    package: object
    document: object


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery configuration is invalid"
        ) from exc
    if not 1 <= len(encoded) <= 256 * 1024:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery configuration is invalid"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise PrivacyRightsConsumerDeliveryCompositionError(f"{label} is unavailable")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise PrivacyRightsConsumerDeliveryCompositionError(f"{label} is unavailable")
    return value


def _key_ref(value: object, label: str) -> tuple[str, str]:
    if not isinstance(value, str):
        raise PrivacyRightsConsumerDeliveryCompositionError(f"{label} is unavailable")
    match = _KEY_REF_RE.fullmatch(value)
    if match is None:
        raise PrivacyRightsConsumerDeliveryCompositionError(f"{label} is unavailable")
    return value, match.group(1)


def _bounded_integer(
    value: object,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            f"{label} is outside its bound"
        )
    return value


def _clock(app: Any) -> Callable[[], float]:
    value = getattr(app.state, "privacy_rights_consumer_delivery_clock", time.time)
    if not callable(value):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery clock is unavailable"
        )
    return value


def _clock_value(app: Any) -> float:
    try:
        value = float(_clock(app)())
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery clock is unavailable"
        ) from exc
    if not math.isfinite(value) or value <= 0:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery clock is unavailable"
        )
    return value


def _request_for(app: Any, request: object) -> Request:
    if not isinstance(request, Request) or request.app is not app:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "public request authority is unavailable"
        )
    return request


def _load_tenant_config(app: Any, tenant_id: str) -> Mapping[str, Any]:
    tenant = canonical_tenant_id(tenant_id)
    factory = getattr(
        app.state,
        "privacy_rights_consumer_delivery_config_factory",
        None,
    )
    try:
        if callable(factory):
            value = factory(tenant_id=tenant)
            errors: object = ()
        else:
            from maverick import config as config_module

            with tenant_scope(tenant=tenant):
                value = config_module.load_config()
                errors = config_module.config_source_errors(include_tenant=True)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery tenant configuration is unavailable"
        ) from exc
    if errors or not isinstance(value, Mapping):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery tenant configuration is unavailable"
        )
    return value


def settings_for_tenant(
    app: Any,
    tenant_id: str,
) -> PrivacyRightsConsumerDeliveryCompositionSettings:
    config = _load_tenant_config(app, tenant_id)
    privacy = config.get("privacy_automation")
    orchestration = (
        privacy.get("rights_orchestration") if isinstance(privacy, Mapping) else None
    )
    table = (
        privacy.get("rights_consumer_delivery")
        if isinstance(privacy, Mapping)
        else None
    )
    if (
        not isinstance(privacy, Mapping)
        or privacy.get("enable") is not True
        or not isinstance(orchestration, Mapping)
        or orchestration.get("enable") is not True
        or not isinstance(table, Mapping)
        or table.get("enable") is not True
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights consumer delivery is disabled"
        )
    digest_ref, _ = _key_ref(table.get("digest_key_ref"), "digest key reference")
    signing_ref, _ = _key_ref(
        table.get("export_signing_key_ref"),
        "export signing key reference",
    )
    package_ref, _ = _key_ref(
        table.get("package_encryption_key_ref"),
        "package encryption key reference",
    )
    material = {
        "schema": "lightwork.privacy-rights-consumer-delivery-composition-config.v1",
        "tenant_id": canonical_tenant_id(tenant_id),
        "digest_key_ref": digest_ref,
        "export_signing_key_ref": signing_ref,
        "package_encryption_key_ref": package_ref,
        "server_grant_ttl_seconds": table.get("server_grant_ttl_seconds", 30),
        "max_package_bytes": table.get(
            "max_package_bytes", _MAX_PUBLIC_PACKAGE_BYTES
        ),
    }
    return PrivacyRightsConsumerDeliveryCompositionSettings(
        digest_key_ref=digest_ref,
        export_signing_key_ref=signing_ref,
        package_encryption_key_ref=package_ref,
        server_grant_ttl_seconds=_bounded_integer(
            material["server_grant_ttl_seconds"],
            "server grant TTL",
            minimum=5,
            maximum=120,
        ),
        max_package_bytes=_bounded_integer(
            material["max_package_bytes"],
            "maximum package bytes",
            minimum=1_024,
            maximum=_MAX_PUBLIC_PACKAGE_BYTES,
        ),
        config_sha256=_sha256(material),
    )


def _same_settings(
    app: Any,
    tenant_id: str,
    expected: PrivacyRightsConsumerDeliveryCompositionSettings,
) -> None:
    if settings_for_tenant(app, tenant_id).config_sha256 != expected.config_sha256:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery configuration changed"
        )


def _reference_present(ref: str) -> bool:
    _selected, name = _key_ref(ref, "key reference")
    if name in os.environ:
        return True
    raw_dir = os.environ.get("MAVERICK_SECRETS_DIR")
    if not raw_dir:
        return False
    base = Path(raw_dir).expanduser()
    return (base / name).is_file() or (base / name.lower()).is_file()


def _resolve_key(
    app: Any,
    *,
    tenant_id: str,
    key_ref: str,
    expected_ref: str,
    purpose: str,
) -> bytes:
    tenant = canonical_tenant_id(tenant_id)
    if not hmac.compare_digest(key_ref, expected_ref):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            f"privacy-rights {purpose} key authority changed"
        )
    custom = getattr(
        app.state,
        "privacy_rights_consumer_delivery_key_resolver",
        None,
    )
    try:
        if callable(custom):
            value = custom(
                tenant_id=tenant,
                key_ref=key_ref,
                purpose=purpose,
            )
        else:
            from maverick.secret_provider import get_secret

            _ref, name = _key_ref(key_ref, f"{purpose} key reference")
            raw = get_secret(name)
            value = None if raw is None else raw.encode("utf-8")
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            f"privacy-rights {purpose} key is unavailable"
        ) from exc
    if not isinstance(value, bytes) or len(value) < 32:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            f"privacy-rights {purpose} key is unavailable"
        )
    return value


def _orchestration_store(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: Request,
) -> object:
    tenant = canonical_tenant_id(tenant_id)
    principal = _identifier(principal_ref, "service principal")
    factory = getattr(
        app.state,
        "privacy_rights_consumer_delivery_orchestration_store_factory",
        None,
    )
    if factory is None:
        factory = getattr(app.state, "privacy_rights_orchestration_store_factory", None)
    try:
        if callable(factory):
            value = factory(
                tenant_id=tenant,
                principal_ref=principal,
                principal_resolver=lambda: principal,
                request=request,
            )
        else:
            from .privacy_rights_orchestration_api import _default_store_for

            value = _default_store_for(tenant, principal)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights orchestration authority is unavailable"
        ) from exc
    if not callable(getattr(value, "get_case", None)) or not callable(
        getattr(value, "get_response_package", None)
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights orchestration authority is unavailable"
        )
    return value


def _vault_store(app: Any, tenant_id: str) -> object:
    tenant = canonical_tenant_id(tenant_id)
    factory = getattr(
        app.state,
        "privacy_rights_consumer_delivery_vault_store_factory",
        None,
    )
    try:
        if callable(factory):
            value = factory(tenant_id=tenant)
        else:
            from .governed_document_vault_composition import (
                governed_document_vault_store,
            )

            value = governed_document_vault_store(
                tenant,
                clock=_clock(app),
            )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights package vault is unavailable"
        ) from exc
    required = (
        "get",
        "issue_delivery_grant",
        "consume_delivery_grant",
    )
    if any(not callable(getattr(value, name, None)) for name in required):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights package vault is unavailable"
        )
    return value


def _vault_record(
    vault: object,
    *,
    document_ref: str,
    package_sha256: str,
    maximum_bytes: int,
) -> object:
    try:
        record = vault.get(document_ref)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise delivery.RightsConsumerDeliveryDenied from exc
    if (
        getattr(record, "document_ref", None) != document_ref
        or getattr(record, "product_area", None) != "privacy_automation"
        or getattr(record, "record_type", None) not in _STOCK_RECORD_TYPES
        or getattr(record, "state", None) != "active"
        or getattr(record, "content_sha256", None) != package_sha256
        or isinstance(getattr(record, "byte_size", None), bool)
        or not isinstance(getattr(record, "byte_size", None), int)
        or not 1 <= record.byte_size <= maximum_bytes
        or not isinstance(getattr(record, "authority_revision", None), int)
        or record.authority_revision < 1
        or _DIGEST_RE.fullmatch(str(getattr(record, "authority_sha256", "")))
        is None
    ):
        raise delivery.RightsConsumerDeliveryDenied
    return record


def _authorization_resolver(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    request: Request,
    settings: PrivacyRightsConsumerDeliveryCompositionSettings,
) -> tuple[Callable[[str, str, str], delivery.ResolvedRightsDeliveryAuthority], object]:
    tenant = canonical_tenant_id(tenant_id)
    store = _orchestration_store(
        app,
        tenant_id=tenant,
        principal_ref=principal_ref,
        request=request,
    )
    vault = _vault_store(app, tenant)
    base = delivery.resolver_from_orchestration_store(store)

    def resolve(
        requested_tenant: str,
        case_id: str,
        package_id: str,
    ) -> delivery.ResolvedRightsDeliveryAuthority:
        _same_settings(app, tenant, settings)
        if canonical_tenant_id(requested_tenant) != tenant:
            raise delivery.RightsConsumerDeliveryDenied
        authority = base(tenant, case_id, package_id)
        package = store.get_response_package(tenant, package_id)
        if (
            getattr(package, "tenant_id", None) != tenant
            or getattr(package, "case_id", None) != case_id
            or getattr(package, "package_id", None) != package_id
            or getattr(package, "integrity_sha256", None)
            != authority.package_record_sha256
            or getattr(package, "package_sha256", None) != authority.package_sha256
            or getattr(package, "encryption_key_ref", None)
            != settings.package_encryption_key_ref
            or getattr(package, "delivery_performed", None) is not False
        ):
            raise delivery.RightsConsumerDeliveryDenied
        _vault_record(
            vault,
            document_ref=getattr(package, "object_ref", ""),
            package_sha256=authority.package_sha256,
            maximum_bytes=settings.max_package_bytes,
        )
        return authority

    return resolve, store


def _public_snapshot(
    public_authority_resolver: Callable[[], object],
    *,
    tenant_id: str,
    expected_subject_binding_sha256: str,
) -> _PublicSnapshot:
    try:
        current = public_authority_resolver()
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "public subject authority is unavailable"
        ) from exc
    binding = getattr(current, "binding", None)
    profile = getattr(current, "profile", None)
    tenant = canonical_tenant_id(tenant_id)
    try:
        snapshot = _PublicSnapshot(
            tenant_id=canonical_tenant_id(getattr(binding, "tenant_id", None)),
            property_id=_identifier(getattr(binding, "property_id", None), "property"),
            client_record_sha256=_digest(
                getattr(binding, "record_sha256", None),
                "public client binding",
            ),
            profile_id=_identifier(getattr(profile, "profile_id", None), "profile"),
            profile_binding_sha256=_digest(
                getattr(profile, "binding_sha256", None),
                "public profile binding",
            ),
            subject_binding_sha256=_digest(
                getattr(profile, "subject_binding_sha256", None),
                "public subject binding",
            ),
        )
    except (TypeError, ValueError) as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "public subject authority is unavailable"
        ) from exc
    expected = _digest(
        expected_subject_binding_sha256,
        "expected public subject binding",
    )
    if snapshot.tenant_id != tenant or not hmac.compare_digest(
        snapshot.subject_binding_sha256,
        expected,
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "public subject authority changed"
        )
    return snapshot


def _delivery_path(app: Any, tenant_id: str) -> Path:
    factory = getattr(
        app.state,
        "privacy_rights_consumer_delivery_path_factory",
        None,
    )
    value = (
        factory(tenant_id=tenant_id)
        if callable(factory)
        else data_dir(
            "privacy_automation",
            "privacy-rights-consumer-delivery.sqlite3",
            tenant=tenant_id,
        )
    )
    if not isinstance(value, (str, Path)):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights delivery path is unavailable"
        )
    return Path(value)


def _store(
    app: Any,
    *,
    tenant_id: str,
    principal_ref: str,
    binding_resolver: Callable[[], str | None],
    request: Request,
) -> delivery.RightsConsumerDeliveryStore:
    tenant = canonical_tenant_id(tenant_id)
    principal = _identifier(principal_ref, "service principal")
    settings = settings_for_tenant(app, tenant)
    authorization_resolver, _store_authority = _authorization_resolver(
        app,
        tenant_id=tenant,
        principal_ref=principal,
        request=request,
        settings=settings,
    )

    def require_current_config() -> None:
        _same_settings(app, tenant, settings)

    return delivery.RightsConsumerDeliveryStore(
        _delivery_path(app, tenant),
        authorization_resolver=authorization_resolver,
        current_consumer_binding_resolver=binding_resolver,
        config_gate=require_current_config,
        principal_resolver=lambda: principal,
        digest_key_resolver=lambda requested_tenant: _resolve_key(
            app,
            tenant_id=requested_tenant,
            key_ref=settings.digest_key_ref,
            expected_ref=settings.digest_key_ref,
            purpose="digest",
        ),
        signing_key_resolver=lambda requested_tenant, key_ref: _resolve_key(
            app,
            tenant_id=requested_tenant,
            key_ref=key_ref,
            expected_ref=settings.export_signing_key_ref,
            purpose="export signing",
        ),
        clock=_clock(app),
        server_grant_ttl_seconds=settings.server_grant_ttl_seconds,
    )


def public_store_factory(app: Any, **kwargs: Any) -> delivery.RightsConsumerDeliveryStore:
    request = _request_for(app, kwargs.get("request"))
    tenant = canonical_tenant_id(kwargs.get("tenant_id"))
    expected_subject = _digest(
        kwargs.get("consumer_subject_binding_sha256"),
        "public subject binding",
    )
    resolver = kwargs.get("public_authority_resolver")
    if not callable(resolver):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "public subject authority is unavailable"
        )
    initial = _public_snapshot(
        resolver,
        tenant_id=tenant,
        expected_subject_binding_sha256=expected_subject,
    )
    principal = "rights-delivery-public." + _sha256(
        {
            "schema": "lightwork.privacy-rights-delivery-public-principal.v1",
            "tenant_id": tenant,
            "property_id": initial.property_id,
            "profile_binding_sha256": initial.profile_binding_sha256,
        }
    )[:40]

    def binding() -> str:
        current = _public_snapshot(
            resolver,
            tenant_id=tenant,
            expected_subject_binding_sha256=expected_subject,
        )
        if current != initial:
            raise PrivacyRightsConsumerDeliveryCompositionError(
                "public subject authority changed"
            )
        return current.subject_binding_sha256

    return _store(
        app,
        tenant_id=tenant,
        principal_ref=principal,
        binding_resolver=binding,
        request=request,
    )


def operator_store_factory(app: Any, **kwargs: Any) -> delivery.RightsConsumerDeliveryStore:
    request = _request_for(app, kwargs.get("request"))
    tenant = canonical_tenant_id(kwargs.get("tenant_id"))
    principal = _identifier(kwargs.get("principal_ref"), "operator principal")
    resolver_factory = getattr(
        app.state,
        "privacy_rights_consumer_delivery_operator_subject_binding_resolver_factory",
        None,
    )
    if not callable(resolver_factory):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "independent operator-to-consumer identity mapping is unavailable"
        )
    resolver = resolver_factory(
        tenant_id=tenant,
        principal_ref=principal,
        request=request,
    )
    if not callable(resolver):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "independent operator-to-consumer identity mapping is unavailable"
        )

    def binding() -> str:
        return _digest(resolver(), "operator-resolved consumer binding")

    return _store(
        app,
        tenant_id=tenant,
        principal_ref=principal,
        binding_resolver=binding,
        request=request,
    )


def resolve_reauthentication(app: Any, **kwargs: Any) -> str:
    """Verify a receipt through an independent deployment identity authority."""

    request = _request_for(app, kwargs.get("request"))
    tenant = canonical_tenant_id(kwargs.get("tenant_id"))
    property_id = _identifier(kwargs.get("property_id"), "property")
    expected_profile = _digest(
        kwargs.get("profile_binding_sha256"),
        "public profile binding",
    )
    raw_receipt = kwargs.get("raw_receipt")
    public_resolver = kwargs.get("public_authority_resolver")
    verifier = getattr(
        app.state,
        "privacy_rights_consumer_delivery_reauthentication_verifier",
        None,
    )
    if (
        not isinstance(raw_receipt, str)
        or not raw_receipt
        or len(raw_receipt.encode("utf-8")) > 4_096
        or not callable(public_resolver)
        or not callable(verifier)
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "independent consumer reauthentication is unavailable"
        )
    before = _public_snapshot(
        public_resolver,
        tenant_id=tenant,
        expected_subject_binding_sha256=getattr(
            getattr(public_resolver(), "profile", None),
            "subject_binding_sha256",
            None,
        ),
    )
    if before.property_id != property_id or not hmac.compare_digest(
        before.profile_binding_sha256,
        expected_profile,
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "public reauthentication authority changed"
        )
    try:
        evidence = verifier(
            raw_receipt=raw_receipt,
            tenant_id=tenant,
            property_id=property_id,
            profile_binding_sha256=expected_profile,
            public_snapshot=before,
            request=request,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "independent consumer reauthentication is unavailable"
        ) from exc
    if type(evidence) is not VerifiedRightsReauthentication:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "independent consumer reauthentication is unavailable"
        )
    after = _public_snapshot(
        public_resolver,
        tenant_id=tenant,
        expected_subject_binding_sha256=before.subject_binding_sha256,
    )
    now = _clock_value(app)
    raw_sha256 = _text_sha256(raw_receipt)
    if (
        before != after
        or evidence.tenant_id != tenant
        or evidence.property_id != property_id
        or not hmac.compare_digest(evidence.profile_binding_sha256, expected_profile)
        or not hmac.compare_digest(
            _digest(evidence.receipt_sha256, "reauthentication receipt digest"),
            raw_sha256,
        )
        or _DIGEST_RE.fullmatch(evidence.identity_authority_sha256) is None
        or _ID_RE.fullmatch(str(evidence.assurance_level)) is None
        or not math.isfinite(float(evidence.verified_at))
        or not math.isfinite(float(evidence.valid_until))
        or not now - _MAX_REAUTHENTICATION_AGE_SECONDS
        <= evidence.verified_at
        <= now
        or evidence.valid_until <= now
        or evidence.revoked is not False
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "independent consumer reauthentication changed"
        )
    return evidence.receipt_sha256


def _claimed_matches(
    claimed: delivery.ClaimedServerDeliveryGrant,
    authority: delivery.ResolvedRightsDeliveryAuthority,
) -> bool:
    return (
        claimed.tenant_id == authority.tenant_id
        and claimed.case_id == authority.case_id
        and claimed.package_id == authority.package_id
        and claimed.case_revision == authority.case_revision
        and hmac.compare_digest(claimed.case_record_sha256, authority.case_record_sha256)
        and claimed.package_revision == authority.package_revision
        and hmac.compare_digest(
            claimed.package_record_sha256,
            authority.package_record_sha256,
        )
        and hmac.compare_digest(
            claimed.delivery_object_ref_sha256,
            authority.delivery_object_ref_sha256,
        )
        and hmac.compare_digest(claimed.package_sha256, authority.package_sha256)
        and hmac.compare_digest(claimed.authority_sha256, _sha256({
            "schema": delivery.AUTHORITY_SCHEMA,
            "tenant_id": authority.tenant_id,
            "case_id": authority.case_id,
            "package_id": authority.package_id,
            "consumer_subject_binding_sha256": authority.consumer_subject_binding_sha256,
            "case_revision": authority.case_revision,
            "case_record_sha256": authority.case_record_sha256,
            "package_revision": authority.package_revision,
            "package_record_sha256": authority.package_record_sha256,
            "identity_status": authority.identity_status,
            "identity_evidence_sha256": authority.identity_evidence_sha256,
            "completeness_ready": authority.completeness_ready,
            "redaction_ready": authority.redaction_ready,
            "closure_ready": authority.closure_ready,
            "delivery_object_ref_sha256": authority.delivery_object_ref_sha256,
            "package_sha256": authority.package_sha256,
            "package_expires_at": authority.package_expires_at,
            "case_retained_until": authority.case_retained_until,
            "orchestration_delivery_performed": authority.orchestration_delivery_performed,
        }))
    )


def _package_snapshot(
    app: Any,
    *,
    claimed: delivery.ClaimedServerDeliveryGrant,
    settings: PrivacyRightsConsumerDeliveryCompositionSettings,
    store: object,
    vault: object,
    resolver: Callable[[str, str, str], delivery.ResolvedRightsDeliveryAuthority],
) -> _PackageSnapshot:
    _same_settings(app, claimed.tenant_id, settings)
    authority = resolver(claimed.tenant_id, claimed.case_id, claimed.package_id)
    package = store.get_response_package(claimed.tenant_id, claimed.package_id)
    if (
        not _claimed_matches(claimed, authority)
        or getattr(package, "tenant_id", None) != claimed.tenant_id
        or getattr(package, "case_id", None) != claimed.case_id
        or getattr(package, "package_id", None) != claimed.package_id
        or getattr(package, "integrity_sha256", None)
        != claimed.package_record_sha256
        or getattr(package, "package_sha256", None) != claimed.package_sha256
        or getattr(package, "encryption_key_ref", None)
        != settings.package_encryption_key_ref
        or getattr(package, "delivery_performed", None) is not False
        or getattr(package, "expires_at", 0) <= _clock_value(app)
    ):
        raise delivery.RightsConsumerDeliveryDenied
    document = _vault_record(
        vault,
        document_ref=getattr(package, "object_ref", ""),
        package_sha256=claimed.package_sha256,
        maximum_bytes=settings.max_package_bytes,
    )
    return _PackageSnapshot(authority=authority, package=package, document=document)


def deliver_from_governed_vault(app: Any, **kwargs: Any) -> object:
    """Return exact package bytes only after orchestration/vault double-read."""

    request = _request_for(app, kwargs.get("request"))
    claimed = kwargs.get("claimed_grant")
    if type(claimed) is not delivery.ClaimedServerDeliveryGrant:
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "claimed server delivery grant is invalid"
        )
    tenant = canonical_tenant_id(claimed.tenant_id)
    settings = settings_for_tenant(app, tenant)
    if not _reference_ready(app, settings.package_encryption_key_ref, "package"):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights package key custody is unavailable"
        )
    principal = "rights-delivery-adapter." + _sha256(
        {
            "schema": "lightwork.privacy-rights-delivery-adapter-principal.v1",
            "tenant_id": tenant,
            "delivery_id": claimed.delivery_id,
        }
    )[:40]
    resolver, store = _authorization_resolver(
        app,
        tenant_id=tenant,
        principal_ref=principal,
        request=request,
        settings=settings,
    )
    vault = _vault_store(app, tenant)
    before = _package_snapshot(
        app,
        claimed=claimed,
        settings=settings,
        store=store,
        vault=vault,
        resolver=resolver,
    )
    document = before.document
    now = _clock_value(app)
    grant = vault.issue_delivery_grant(
        document_access.DeliveryClaim(
            tenant_id=tenant,
            principal_ref=principal,
            token_id="rights-package-token-" + _text_sha256(claimed.delivery_id)[:32],
            claim_id="rights-package-claim-" + _text_sha256(
                claimed.delivery_id + ":" + claimed.authority_sha256
            )[:32],
            document_ref=document.document_ref,
            product_area=document.product_area,
            record_type=document.record_type,
            safe_display_name=document.safe_display_name,
            media_type=document.media_type,
            byte_size=document.byte_size,
            content_sha256=document.content_sha256,
            authority_revision=document.authority_revision,
            authority_sha256=document.authority_sha256,
            grant_expires_at=min(float(before.package.expires_at), now + 30),
        )
    )
    if (
        type(grant) is not document_access.DeliveryGrant
        or not isinstance(grant.grant, str)
        or not math.isfinite(float(grant.expires_at))
        or not now < grant.expires_at <= min(float(before.package.expires_at), now + 30)
    ):
        raise PrivacyRightsConsumerDeliveryCompositionError(
            "privacy-rights package vault returned an invalid delivery grant"
        )
    middle = _package_snapshot(
        app,
        claimed=claimed,
        settings=settings,
        store=store,
        vault=vault,
        resolver=resolver,
    )
    if middle != before:
        raise delivery.RightsConsumerDeliveryDenied
    payload = vault.consume_delivery_grant(grant.grant, principal_ref=principal)
    after = _package_snapshot(
        app,
        claimed=claimed,
        settings=settings,
        store=store,
        vault=vault,
        resolver=resolver,
    )
    content = getattr(payload, "content", None)
    if (
        after != before
        or getattr(payload, "document_ref", None) != document.document_ref
        or getattr(payload, "content_sha256", None) != claimed.package_sha256
        or not isinstance(content, bytes)
        or not 1 <= len(content) <= settings.max_package_bytes
        or len(content) != document.byte_size
        or not hmac.compare_digest(hashlib.sha256(content).hexdigest(), claimed.package_sha256)
    ):
        raise delivery.RightsConsumerDeliveryDenied
    from .consent_public_api import PublicRightsPackageDownload

    return PublicRightsPackageDownload(
        content=content,
        package_sha256=claimed.package_sha256,
    )


def _reference_ready(app: Any, ref: str, purpose: str) -> bool:
    probe = getattr(
        app.state,
        "privacy_rights_consumer_delivery_key_reference_probe",
        None,
    )
    try:
        if callable(probe):
            return probe(key_ref=ref, purpose=purpose) is True
        if callable(
            getattr(app.state, "privacy_rights_consumer_delivery_key_resolver", None)
        ):
            return True
        return _reference_present(ref)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return False


def readiness(app: Any, tenant_id: str) -> Mapping[str, object]:
    """Return a storage-free configuration/readiness snapshot."""

    tenant = canonical_tenant_id(tenant_id)
    try:
        settings = settings_for_tenant(app, tenant)
        config_valid = True
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        settings = None
        config_valid = False
    key_refs = {
        "digest": settings.digest_key_ref if settings else None,
        "export_signing": settings.export_signing_key_ref if settings else None,
        "package": settings.package_encryption_key_ref if settings else None,
    }
    key_ready = {
        name: bool(ref and _reference_ready(app, ref, name))
        for name, ref in key_refs.items()
    }
    try:
        vault_probe = getattr(
            app.state,
            "privacy_rights_consumer_delivery_vault_enabled_probe",
            None,
        )
        if callable(vault_probe):
            vault_enabled = vault_probe(tenant) is True
        else:
            tenant_config = _load_tenant_config(app, tenant)
            vault_table = tenant_config.get("governed_document_vault")
            vault_enabled = (
                isinstance(vault_table, Mapping)
                and vault_table.get("enable") is True
            )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        vault_enabled = False
    independent_reauthentication = callable(
        getattr(
            app.state,
            "privacy_rights_consumer_delivery_reauthentication_verifier",
            None,
        )
    )
    operator_mapping = callable(
        getattr(
            app.state,
            "privacy_rights_consumer_delivery_operator_subject_binding_resolver_factory",
            None,
        )
    )
    public_factory = callable(
        getattr(app.state, "rights_consumer_delivery_store_factory", None)
    )
    package_adapter = callable(
        getattr(app.state, "rights_package_delivery_adapter", None)
    )
    public_ready = bool(
        config_valid
        and vault_enabled
        and all(key_ready.values())
        and independent_reauthentication
        and public_factory
        and package_adapter
    )
    return {
        "schema": "lightwork.privacy-rights-consumer-delivery-composition-status.v1",
        "tenant_id": tenant,
        "enabled": settings is not None,
        "config_valid": config_valid,
        "config_sha256": settings.config_sha256 if settings else None,
        "configured_key_refs": key_refs,
        "key_reference_ready": key_ready,
        "governed_document_vault_enabled": vault_enabled,
        "stock_vault_package_adapter_installed": package_adapter,
        "public_subject_binding_resolver_installed": public_factory,
        "independent_reauthentication_verifier_ready": independent_reauthentication,
        "operator_subject_mapping_ready": operator_mapping,
        "operator_mint_ready": public_ready and operator_mapping,
        "public_delivery_ready": public_ready,
        "ready": public_ready,
        "status_probe_opened_tenant_storage": False,
        "status_probe_resolved_secret_value": False,
        "identity_inferred_from_package": False,
        "raw_key_values_persisted": False,
        "live_idp_acceptance_verified": False,
        "live_customer_delivery_acceptance_verified": False,
        "external_object_store_acceptance_verified": False,
    }


def attach_privacy_rights_consumer_delivery_composition(app: FastAPI) -> None:
    """Install lazy public/operator stores, reauth, vault delivery and readiness."""

    state = app.state
    if getattr(state, "rights_consumer_delivery_store_factory", None) is None:
        state.rights_consumer_delivery_store_factory = (
            lambda **kwargs: public_store_factory(app, **kwargs)
        )
    if getattr(state, "privacy_rights_consumer_delivery_store_factory", None) is None:
        state.privacy_rights_consumer_delivery_store_factory = (
            lambda **kwargs: operator_store_factory(app, **kwargs)
        )
    if getattr(state, "rights_reauthentication_resolver", None) is None:
        state.rights_reauthentication_resolver = (
            lambda **kwargs: resolve_reauthentication(app, **kwargs)
        )
    if getattr(state, "rights_package_delivery_adapter", None) is None:
        state.rights_package_delivery_adapter = (
            lambda **kwargs: deliver_from_governed_vault(app, **kwargs)
        )
    if getattr(
        state,
        "privacy_rights_consumer_delivery_readiness_probe",
        None,
    ) is None:
        state.privacy_rights_consumer_delivery_readiness_probe = (
            lambda tenant_id, _request=None: readiness(app, tenant_id)
        )


__all__ = [
    "PrivacyRightsConsumerDeliveryCompositionError",
    "PrivacyRightsConsumerDeliveryCompositionSettings",
    "VerifiedRightsReauthentication",
    "attach_privacy_rights_consumer_delivery_composition",
    "deliver_from_governed_vault",
    "operator_store_factory",
    "public_store_factory",
    "readiness",
    "resolve_reauthentication",
    "settings_for_tenant",
]
