"""Tenant-local unified consumer trust-center read model.

All tenant, profile, property, origin/application, and capability authority is
resolved by a zero-argument server seam.  This module reads existing public
authority methods and emits structured privacy metadata only.  It never emits
raw subject identifiers, free text, legal prose, credentials, or provider/site
mutation authority, and it performs no network I/O.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .consent_profile_data import PublicProfileAuthority
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

TRUST_CENTER_SCHEMA = "lightwork.consumer-trust-center.v1"
TRUST_CENTER_EXPORT_SCHEMA = "lightwork.consumer-trust-center-export.v1"

_MAX_JSON_BYTES = 1024 * 1024
_MAX_HISTORY = 100
_MAX_RIGHTS_CASES = 50
_MAX_RETENTION = 10 * 366 * 86_400
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_LOCALE_RE = re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,2}\Z")
_THEME_COLOR_RE = re.compile(r"[0-9a-f]{6}\Z")
_UNSAFE_BRANDING_TEXT_RE = re.compile(
    r"(?:javascript|vbscript)\s*:|data\s*:\s*text/html",
    re.IGNORECASE,
)
_BRANDING_TEXT_KEYS = frozenset({"description", "display_name", "heading"})
_CAPABILITIES = frozenset({"active_publication", "consent_history", "profile_data", "rights_cases"})
_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "actor_sha256",
        "body",
        "closed_by",
        "context",
        "credential",
        "email",
        "free_text",
        "identity_evidence_ref",
        "legal_prose",
        "name",
        "opened_by",
        "phone",
        "profile_id",
        "prompt_interactions",
        "query_string",
        "raw_identity",
        "secret",
        "subject_sha256",
        "tenant_id",
        "title",
        "url",
    }
)
_SNAPSHOT_KEYS = frozenset(
    {
        "boundaries",
        "capabilities",
        "context_revision",
        "context_sha256",
        "generated_at",
        "profile_ref_sha256",
        "property_id",
        "retained_until",
        "schema",
        "sections",
        "source_pins",
        "tenant_sha256",
    }
)


class ConsumerTrustCenterError(RuntimeError):
    """Base trust-center failure."""


class TrustCenterDisabled(ConsumerTrustCenterError):
    """The exact trust-center gate is not enabled."""


class TrustCenterValidationError(ConsumerTrustCenterError, ValueError):
    """Trusted configuration or caller-safe operation metadata is invalid."""


class TrustCenterConflict(ConsumerTrustCenterError):
    """A source, grant, context, freshness, or idempotency precondition changed."""


class TrustCenterIntegrityError(ConsumerTrustCenterError):
    """Resolved or stored metadata failed exact integrity validation."""


@dataclass(frozen=True)
class TrustCenterCapabilityGrant:
    capability: str
    grant_ref: str
    tenant_sha256: str
    property_id: str
    profile_sha256: str
    approved_by_sha256: str
    second_approved_by_sha256: str
    valid_until: float
    grant_sha256: str
    revoked: bool = False


@dataclass(frozen=True)
class TrustCenterRightsAuthorization:
    case_id: str
    expected_case_sha256: str
    approved_by_sha256: str
    second_approved_by_sha256: str
    valid_until: float
    authorization_sha256: str
    revoked: bool = False


@dataclass(frozen=True)
class TrustCenterContext:
    tenant_id: str
    property_id: str
    profile_id: str
    actor_sha256: str
    requested_locale: str
    server_origin: str | None
    server_bundle_id: str | None
    server_platform: str | None
    jurisdiction: str
    country_code: str
    region_code: str
    profile_authority: PublicProfileAuthority | None
    capability_grants: tuple[TrustCenterCapabilityGrant, ...]
    rights_authorizations: tuple[TrustCenterRightsAuthorization, ...]
    publication_history_limit: int
    receipt_limit: int
    retained_until: float
    revision: int
    valid_until: float
    context_sha256: str
    revoked: bool = False


def trust_center_enabled() -> bool:
    """Require consent and ``consent_preferences.trust_center`` explicitly."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        loaded = load_config()
    except Exception:
        return False
    if not isinstance(loaded, Mapping):
        return False
    consent = loaded.get("consent_preferences")
    if not isinstance(consent, Mapping) or consent.get("enable") is not True:
        return False
    trust_center = consent.get("trust_center")
    return isinstance(trust_center, Mapping) and trust_center.get("enable") is True


def require_trust_center_enabled() -> None:
    if not trust_center_enabled():
        raise TrustCenterDisabled("consent_preferences.trust_center is not explicitly enabled")


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise TrustCenterValidationError("trust-center metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise TrustCenterValidationError("trust-center metadata exceeds its byte bound")
    return encoded


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


def _loads(value: object, label: str) -> Any:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= _MAX_JSON_BYTES:
        raise TrustCenterIntegrityError(f"stored {label} is invalid")
    try:
        return json.loads(value)
    except (TypeError, ValueError) as exc:
        raise TrustCenterIntegrityError(f"stored {label} is invalid") from exc


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or not _REF_RE.fullmatch(value):
        raise TrustCenterValidationError(f"{label} must be an opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise TrustCenterValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TrustCenterValidationError(f"{label} must be a finite timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise TrustCenterValidationError(f"{label} must be a finite timestamp")
    return normalized


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise TrustCenterValidationError(f"{label} is outside its bound")
    return value


def _brand_text(value: object, label: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise TrustCenterIntegrityError(f"{label} must be bounded plain text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise TrustCenterIntegrityError(f"{label} must be valid UTF-8") from exc
    if size > 512 or "<" in value or ">" in value:
        raise TrustCenterIntegrityError(f"{label} must be bounded plain text")
    if any(ord(character) < 32 or 0x7F <= ord(character) <= 0x9F for character in value):
        raise TrustCenterIntegrityError(f"{label} contains control data")
    if _UNSAFE_BRANDING_TEXT_RE.search(value):
        raise TrustCenterIntegrityError(f"{label} contains an executable URI")
    return value


def _theme_color(value: object, label: str) -> str:
    if not isinstance(value, str) or not _THEME_COLOR_RE.fullmatch(value):
        raise TrustCenterIntegrityError(f"{label} is invalid")
    return value


def _contrast_ratio(foreground: str, background: str) -> float:
    def luminance(color: str) -> float:
        channels = [int(color[index : index + 2], 16) / 255.0 for index in (0, 2, 4)]
        linear = [
            channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4
            for channel in channels
        ]
        return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]

    left = luminance(foreground)
    right = luminance(background)
    lighter, darker = max(left, right), min(left, right)
    return (lighter + 0.05) / (darker + 0.05)


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise TrustCenterValidationError("resolved tenant_id is invalid") from exc


def _idempotency(value: object) -> str:
    if not isinstance(value, str) or not _IDEM_RE.fullmatch(value):
        raise TrustCenterValidationError("idempotency_key is invalid")
    return _text_sha256(value)


def _export_request_sha(snapshot: Mapping[str, Any]) -> str:
    """Bind idempotency to authority and source state, not render time."""

    return _sha256(
        {
            "operation": "export",
            "tenant_sha256": snapshot.get("tenant_sha256"),
            "property_id": snapshot.get("property_id"),
            "profile_ref_sha256": snapshot.get("profile_ref_sha256"),
            "context_revision": snapshot.get("context_revision"),
            "context_sha256": snapshot.get("context_sha256"),
            "capabilities": snapshot.get("capabilities"),
            "source_pins": snapshot.get("source_pins"),
            "retained_until": snapshot.get("retained_until"),
        }
    )


def _privacy_safe_metadata(value: object) -> None:
    """Reject raw/free-text shapes even if a trusted resolver is miswired."""

    pending: list[tuple[object, tuple[str, ...]]] = [(value, ())]
    seen = 0
    while pending:
        item, path = pending.pop()
        seen += 1
        if seen > 25_000:
            raise TrustCenterIntegrityError("trust-center metadata exceeds its item bound")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if (
                    not isinstance(key, str)
                    or not _REF_RE.fullmatch(key)
                    or key in _FORBIDDEN_METADATA_KEYS
                ):
                    raise TrustCenterIntegrityError(
                        "trust-center metadata contains a forbidden raw field"
                    )
                pending.append((child, (*path, key)))
        elif isinstance(item, list):
            pending.extend((child, path) for child in item)
        elif isinstance(item, str):
            if len(path) >= 2 and path[-2] == "branding" and path[-1] in _BRANDING_TEXT_KEYS:
                _brand_text(item, f"branding {path[-1]}")
            elif not _REF_RE.fullmatch(item):
                raise TrustCenterIntegrityError("trust-center metadata contains non-closed text")
        elif isinstance(item, bool) or item is None:
            continue
        elif isinstance(item, (int, float)):
            if isinstance(item, float) and not math.isfinite(item):
                raise TrustCenterIntegrityError("trust-center metadata is not finite")
        else:
            raise TrustCenterIntegrityError("trust-center metadata has an invalid type")


def _closed_value(value: object) -> object:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str):
        if not _REF_RE.fullmatch(value):
            raise TrustCenterIntegrityError("profile data contains a non-closed value")
        return value
    if isinstance(value, list) and len(value) <= 64:
        if any(not isinstance(item, str) or not _REF_RE.fullmatch(item) for item in value):
            raise TrustCenterIntegrityError("profile data contains a non-closed value")
        normalized = list(value)
        if len(normalized) != len(set(normalized)):
            raise TrustCenterIntegrityError("profile value list contains duplicates")
        return normalized
    raise TrustCenterIntegrityError("profile data contains a non-closed value")


class ConsumerTrustCenterSourceAdapter:
    """Read and sanitize existing public authority methods."""

    def __init__(
        self,
        *,
        publishing_store: object,
        preference_store: object,
        profile_data_store: object | None,
        rights_store: object | None,
        context_resolver: Callable[[], TrustCenterContext],
        clock: Callable[[], float] = time.time,
    ) -> None:
        required = (
            (publishing_store, "resolve_public_configuration"),
            (publishing_store, "publication_history"),
            (preference_store, "export_profile"),
        )
        if any(not callable(getattr(store, method, None)) for store, method in required):
            raise TrustCenterValidationError("trust-center source adapter is incomplete")
        if not callable(context_resolver) or not callable(clock):
            raise TrustCenterValidationError("trust-center resolvers must be callable")
        self._publishing = publishing_store
        self._preferences = preference_store
        self._profile_data_store = profile_data_store
        self._rights_store = rights_store
        self._context_resolver = context_resolver
        self._clock = clock

    @staticmethod
    def product_boundaries() -> dict[str, bool]:
        return {
            "tenant_local_read_model": True,
            "public_authority_methods_only": True,
            "raw_identity_exposed": False,
            "free_text_exposed": False,
            "legal_prose_exposed": False,
            "network_io": False,
            "provider_write": False,
            "site_mutation": False,
            "native_identity_proof": False,
            "live_acceptance_verified": False,
        }

    @staticmethod
    def capability_grant_sha256(grant: TrustCenterCapabilityGrant) -> str:
        if not isinstance(grant, TrustCenterCapabilityGrant):
            raise TrustCenterValidationError("capability grant uses an invalid type")
        return _sha256(
            {
                "capability": grant.capability,
                "grant_ref": grant.grant_ref,
                "tenant_sha256": grant.tenant_sha256,
                "property_id": grant.property_id,
                "profile_sha256": grant.profile_sha256,
                "approved_by_sha256": grant.approved_by_sha256,
                "second_approved_by_sha256": grant.second_approved_by_sha256,
                "valid_until": grant.valid_until,
            }
        )

    @staticmethod
    def rights_authorization_sha256(auth: TrustCenterRightsAuthorization) -> str:
        if not isinstance(auth, TrustCenterRightsAuthorization):
            raise TrustCenterValidationError("rights authorization uses an invalid type")
        return _sha256(
            {
                "case_id": auth.case_id,
                "expected_case_sha256": auth.expected_case_sha256,
                "approved_by_sha256": auth.approved_by_sha256,
                "second_approved_by_sha256": auth.second_approved_by_sha256,
                "valid_until": auth.valid_until,
            }
        )

    @staticmethod
    def context_sha256(context: TrustCenterContext) -> str:
        if not isinstance(context, TrustCenterContext):
            raise TrustCenterValidationError("context uses an invalid type")
        body = asdict(context)
        body.pop("context_sha256", None)
        body.pop("revoked", None)
        body["tenant_id"] = _tenant(context.tenant_id)
        return _sha256(body)

    @staticmethod
    def _branding(raw: object) -> dict[str, Any]:
        if not isinstance(raw, Mapping):
            raise TrustCenterIntegrityError("published branding metadata is invalid")
        body = dict(raw)
        supplied = body.pop("branding_sha256", None)
        expected_keys = {
            "theme_token_id",
            "version",
            "resource_sha256",
            "display_name",
            "heading",
            "description",
            "primary_color",
            "primary_text_color",
            "surface_color",
            "text_color",
        }
        if set(body) != expected_keys or not _same(supplied, _sha256(body)):
            raise TrustCenterIntegrityError("published branding metadata failed integrity")
        result = {
            "theme_token_id": _ref(body["theme_token_id"], "theme_token_id"),
            "version": _integer(body["version"], "theme version", 1, 2**31 - 1),
            "resource_sha256": _digest(body["resource_sha256"], "theme resource_sha256"),
            "display_name": _brand_text(body["display_name"], "branding display_name"),
            "heading": _brand_text(body["heading"], "branding heading"),
            "description": _brand_text(body["description"], "branding description"),
            "primary_color": _theme_color(body["primary_color"], "primary_color"),
            "primary_text_color": _theme_color(body["primary_text_color"], "primary_text_color"),
            "surface_color": _theme_color(body["surface_color"], "surface_color"),
            "text_color": _theme_color(body["text_color"], "text_color"),
        }
        if _contrast_ratio(result["primary_text_color"], result["primary_color"]) < 4.5:
            raise TrustCenterIntegrityError("published primary branding contrast is unsafe")
        if _contrast_ratio(result["text_color"], result["surface_color"]) < 4.5:
            raise TrustCenterIntegrityError("published surface branding contrast is unsafe")
        return {**result, "branding_sha256": str(supplied)}

    @classmethod
    def _validated_context(cls, raw: object, now: float) -> TrustCenterContext:
        if not isinstance(raw, TrustCenterContext):
            raise TrustCenterIntegrityError("context resolver returned an invalid type")
        tenant = _tenant(raw.tenant_id)
        property_id = _ref(raw.property_id, "property_id")
        profile_id = _ref(raw.profile_id, "profile_id")
        actor = _digest(raw.actor_sha256, "actor_sha256")
        if not isinstance(raw.requested_locale, str) or not _LOCALE_RE.fullmatch(
            raw.requested_locale
        ):
            raise TrustCenterValidationError("requested_locale is invalid")
        _integer(raw.publication_history_limit, "publication_history_limit", 1, _MAX_HISTORY)
        _integer(raw.receipt_limit, "receipt_limit", 1, _MAX_HISTORY)
        revision = _integer(raw.revision, "context revision", 1, 2**31 - 1)
        retained = _timestamp(raw.retained_until, "retained_until")
        valid = _timestamp(raw.valid_until, "valid_until")
        if not isinstance(raw.revoked, bool) or raw.revoked or valid <= now:
            raise TrustCenterConflict("trust-center context is expired or revoked")
        if not now < retained <= now + _MAX_RETENTION:
            raise TrustCenterConflict("trust-center retention is outside its bound")
        grants: dict[str, TrustCenterCapabilityGrant] = {}
        for grant in raw.capability_grants:
            if not isinstance(grant, TrustCenterCapabilityGrant):
                raise TrustCenterIntegrityError("capability grant is invalid")
            if grant.capability not in _CAPABILITIES or grant.capability in grants:
                raise TrustCenterIntegrityError("capability grants are unsupported or duplicated")
            _ref(grant.grant_ref, "grant_ref")
            _digest(grant.tenant_sha256, "grant tenant_sha256")
            _ref(grant.property_id, "grant property_id")
            _digest(grant.profile_sha256, "grant profile_sha256")
            _digest(grant.approved_by_sha256, "grant approved_by_sha256")
            _digest(
                grant.second_approved_by_sha256,
                "grant second_approved_by_sha256",
            )
            grant_valid_until = _timestamp(grant.valid_until, "grant valid_until")
            if not isinstance(grant.revoked, bool):
                raise TrustCenterIntegrityError("capability grant revocation state is invalid")
            expected = cls.capability_grant_sha256(grant)
            if (
                grant.revoked
                or grant_valid_until <= now
                or not _same(grant.grant_sha256, expected)
                or not _same(grant.tenant_sha256, _text_sha256(tenant))
                or grant.property_id != property_id
                or not _same(grant.profile_sha256, _text_sha256(profile_id))
                or _same(grant.approved_by_sha256, grant.second_approved_by_sha256)
                or _same(actor, grant.approved_by_sha256)
                or _same(actor, grant.second_approved_by_sha256)
            ):
                raise TrustCenterConflict("capability grant is stale, revoked, or mismatched")
            grants[grant.capability] = grant
        if not grants:
            raise TrustCenterConflict("trust-center context has no approved capability")
        if not _same(raw.context_sha256, cls.context_sha256(raw)):
            raise TrustCenterIntegrityError("trust-center context digest is invalid")
        return TrustCenterContext(
            **{
                **asdict(raw),
                "tenant_id": tenant,
                "property_id": property_id,
                "profile_id": profile_id,
                "actor_sha256": actor,
                "revision": revision,
                "capability_grants": raw.capability_grants,
                "rights_authorizations": raw.rights_authorizations,
                "profile_authority": raw.profile_authority,
            }
        )

    @staticmethod
    def _publication(
        config: Mapping[str, Any],
        history: Mapping[str, Any],
        *,
        tenant_id: str,
        property_id: str,
        history_limit: int,
    ) -> dict[str, Any]:
        if config.get("allowed") is not True:
            raise TrustCenterConflict("active publication is unavailable or denied")
        publication = config.get("publication")
        property_data = config.get("property")
        rule = config.get("rule")
        configuration = config.get("configuration")
        items = history.get("items")
        if (
            not isinstance(publication, Mapping)
            or not isinstance(property_data, Mapping)
            or not isinstance(rule, Mapping)
            or not isinstance(configuration, Mapping)
            or not isinstance(items, list)
            or not items
            or len(items) > history_limit
            or history.get("truncated") not in {True, False}
            or not isinstance(items[0], Mapping)
            or items[0].get("publication_id") != publication.get("publication_id")
            or items[0].get("publication_sha256") != publication.get("publication_sha256")
        ):
            raise TrustCenterConflict("publication head/history binding is stale")
        notice = configuration.get("notice")
        if not isinstance(notice, Mapping):
            raise TrustCenterIntegrityError("published notice metadata is invalid")
        history_items = []
        for item in items:
            if not isinstance(item, Mapping):
                raise TrustCenterIntegrityError("publication history is invalid")
            item_body = dict(item)
            item_sha = item_body.pop("publication_sha256", None)
            if (
                item.get("property_id") != property_id
                or not _same(item.get("tenant_sha256"), _text_sha256(tenant_id))
                or not _same(item_sha, _sha256(item_body))
            ):
                raise TrustCenterConflict("publication history authority is mismatched")
            history_items.append(
                {
                    "publication_id": _ref(item.get("publication_id"), "publication_id"),
                    "publication_revision": _integer(
                        item.get("publication_revision"), "publication_revision", 1, 2**31 - 1
                    ),
                    "action": _ref(item.get("action"), "publication action"),
                    "publication_sha256": _digest(
                        item.get("publication_sha256"), "publication_sha256"
                    ),
                    "created_at": _timestamp(item.get("created_at"), "publication created_at"),
                }
            )
        locale = rule.get("locale")
        if not isinstance(locale, str) or not _LOCALE_RE.fullmatch(locale):
            raise TrustCenterIntegrityError("published locale is invalid")
        resolved_property_id = _ref(property_data.get("property_id"), "property_id")
        publication_body = dict(publication)
        supplied_publication_sha = publication_body.pop("publication_sha256", None)
        if (
            resolved_property_id != property_id
            or publication.get("property_id") != property_id
            or not _same(publication.get("tenant_sha256"), _text_sha256(tenant_id))
            or not _same(supplied_publication_sha, _sha256(publication_body))
        ):
            raise TrustCenterConflict("active publication authority is mismatched")
        property_revision = _integer(
            property_data.get("revision"), "property_revision", 1, 2**31 - 1
        )
        publication_sha = _digest(publication.get("publication_sha256"), "publication_sha256")
        rule_id = _ref(rule.get("rule_id"), "rule_id")
        rule_sha = _digest(rule.get("rule_sha256"), "rule_sha256")
        consent_group_id = _ref(property_data.get("consent_group_id"), "consent_group_id")
        configuration_sha = _digest(config.get("configuration_sha256"), "configuration_sha256")
        exact_configuration = {
            "publication_sha256": publication_sha,
            "property_id": resolved_property_id,
            "property_revision": property_revision,
            "consent_group_id": consent_group_id,
            "rule_id": rule_id,
            "rule_sha256": rule_sha,
            "locale": locale,
            "configuration": configuration,
        }
        if not _same(_sha256(exact_configuration), configuration_sha):
            raise TrustCenterIntegrityError("published configuration digest is invalid")
        branding = configuration.get("branding")
        result = {
            "property_id": resolved_property_id,
            "property_revision": _integer(
                property_data.get("revision"), "property_revision", 1, 2**31 - 1
            ),
            "publication_id": _ref(publication.get("publication_id"), "publication_id"),
            "publication_revision": _integer(
                publication.get("publication_revision"), "publication_revision", 1, 2**31 - 1
            ),
            "publication_sha256": publication_sha,
            "rule_id": rule_id,
            "rule_sha256": rule_sha,
            "locale": locale,
            "configuration_sha256": configuration_sha,
            "notice": {
                "id": _ref(notice.get("id"), "notice_id"),
                "version": _integer(notice.get("version"), "notice_version", 1, 2**31 - 1),
                "resource_sha256": _digest(notice.get("resource_sha256"), "notice resource_sha256"),
                "document_sha256": _digest(notice.get("document_sha256"), "notice document_sha256"),
            },
            "preference_counts": {
                key: len(configuration.get(key, []))
                for key in ("purposes", "topics", "custom_preferences")
                if isinstance(configuration.get(key), list)
            },
            "history": history_items,
            "history_truncated": history.get("truncated"),
        }
        if branding is not None:
            result["branding"] = ConsumerTrustCenterSourceAdapter._branding(branding)
        return {**result, "source_sha256": _sha256(result)}

    @staticmethod
    def _consent(
        export: Mapping[str, Any],
        *,
        tenant_id: str,
        profile_id: str,
        receipt_limit: int,
        now: float,
    ) -> dict[str, Any]:
        supplied_export_sha = _digest(export.get("export_sha256"), "consent export_sha256")
        exact_export = dict(export)
        exact_export.pop("export_sha256", None)
        if not _same(_sha256(exact_export), supplied_export_sha):
            raise TrustCenterIntegrityError("consent export digest is invalid")
        profiles = export.get("profiles")
        receipts = export.get("receipts")
        if (
            export.get("requested_profile_id") != profile_id
            or not isinstance(profiles, list)
            or not isinstance(receipts, list)
            or len(profiles) > _MAX_HISTORY
            or len(receipts) > receipt_limit
        ):
            raise TrustCenterIntegrityError("consent profile export is invalid")
        safe_profiles = []
        for profile in profiles:
            if not isinstance(profile, Mapping):
                raise TrustCenterIntegrityError("consent profile is invalid")
            safe_profiles.append(
                {
                    "profile_ref_sha256": _text_sha256(
                        _ref(profile.get("profile_id"), "profile_id")
                    ),
                    "revision": _integer(profile.get("revision"), "profile revision", 0, 2**31 - 1),
                    "created_at": _timestamp(profile.get("created_at"), "profile created_at"),
                }
            )
        safe_receipts = []
        for receipt in receipts:
            if not isinstance(receipt, Mapping):
                raise TrustCenterIntegrityError("consent receipt is invalid")
            if not _same(receipt.get("tenant_sha256"), _text_sha256(tenant_id)):
                raise TrustCenterConflict("consent receipt tenant authority is mismatched")
            choices = receipt.get("choices")
            if not isinstance(choices, list) or len(choices) > 1_000:
                raise TrustCenterIntegrityError("consent choices are invalid")
            safe_choices = []
            for choice in choices:
                if not isinstance(choice, Mapping):
                    raise TrustCenterIntegrityError("consent choice is invalid")
                expires_at = choice.get("expires_at")
                if expires_at is not None:
                    expires_at = _timestamp(expires_at, "choice expires_at")
                safe_choices.append(
                    {
                        "purpose_id": _ref(choice.get("purpose_id"), "purpose_id"),
                        "action": _ref(choice.get("action"), "choice action"),
                        "channel": _ref(choice.get("channel"), "choice channel"),
                        "vendor_id": _ref(choice.get("vendor_id"), "vendor_id"),
                        "expires_at": expires_at,
                    }
                )
            previous_sha = receipt.get("previous_receipt_sha256")
            if previous_sha is not None:
                previous_sha = _digest(previous_sha, "previous_receipt_sha256")
            retention_until = receipt.get("retention_until")
            if retention_until is not None:
                retention_until = _timestamp(retention_until, "receipt retention_until")
                if retention_until <= now:
                    raise TrustCenterConflict("consent receipt retention has expired")
            safe_receipts.append(
                {
                    "receipt_id": _ref(receipt.get("receipt_id"), "receipt_id"),
                    "profile_revision": _integer(
                        receipt.get("profile_revision"), "profile_revision", 1, 2**31 - 1
                    ),
                    "policy_id": _ref(receipt.get("policy_id"), "policy_id"),
                    "policy_version": _integer(
                        receipt.get("policy_version"), "policy_version", 1, 2**31 - 1
                    ),
                    "policy_sha256": _digest(receipt.get("policy_sha256"), "policy_sha256"),
                    "context_sha256": _digest(receipt.get("context_sha256"), "context_sha256"),
                    "choices": safe_choices,
                    "previous_receipt_sha256": previous_sha,
                    "receipt_sha256": _digest(receipt.get("receipt_sha256"), "receipt_sha256"),
                    "created_at": _timestamp(receipt.get("created_at"), "receipt created_at"),
                    "retention_until": retention_until,
                }
            )
        result = {
            "profiles": safe_profiles,
            "receipts": safe_receipts,
            "receipts_truncated": export.get("receipts_truncated") is True,
        }
        if _text_sha256(profile_id) not in {item["profile_ref_sha256"] for item in safe_profiles}:
            raise TrustCenterConflict("requested consent profile is absent")
        return {**result, "source_sha256": _sha256(result)}

    @staticmethod
    def _sanitize_profile_data(
        export: object,
        *,
        tenant_id: str,
        profile_id: str,
        now: float,
    ) -> dict[str, Any]:
        body = getattr(export, "body", None)
        export_sha = getattr(export, "export_sha256", None)
        if not isinstance(body, Mapping):
            raise TrustCenterIntegrityError("profile-data export is invalid")
        if (
            getattr(export, "tenant_id", None) != tenant_id
            or getattr(export, "profile_id", None) != profile_id
            or body.get("tenant_id") != tenant_id
            or body.get("profile_id") != profile_id
            or not _same(_digest(export_sha, "profile-data export_sha256"), _sha256(body))
        ):
            raise TrustCenterConflict("profile-data export authority is stale or mismatched")
        current = body.get("current_records")
        history = body.get("history")
        active = body.get("active_values")
        if (
            not isinstance(current, list)
            or not isinstance(history, list)
            or not isinstance(active, Mapping)
        ):
            raise TrustCenterIntegrityError("profile-data export shape is invalid")
        if len(current) > _MAX_HISTORY or len(history) > _MAX_HISTORY or len(active) > _MAX_HISTORY:
            raise TrustCenterConflict("profile-data export exceeds the trust-center bound")

        def record(item: object, *, historical: bool) -> dict[str, Any]:
            if not isinstance(item, Mapping):
                raise TrustCenterIntegrityError("profile-data record is invalid")
            result = {
                "preference_id": _ref(item.get("preference_id"), "preference_id"),
                "value_type": _ref(item.get("value_type"), "value_type"),
                "value": _closed_value(item.get("value")),
                "status": _ref(item.get("status"), "profile-data status"),
                "binding_sha256": _digest(item.get("binding_sha256"), "binding_sha256"),
                "integrity_sha256": _digest(item.get("integrity_sha256"), "integrity_sha256"),
            }
            retained_until = _timestamp(item.get("retained_until"), "retained_until")
            if retained_until <= now:
                raise TrustCenterConflict("profile-data retention has expired")
            expires_at = item.get("expires_at")
            if expires_at is not None:
                expires_at = _timestamp(expires_at, "profile-data expires_at")
            result["expires_at"] = expires_at
            result["retained_until"] = retained_until
            if historical:
                result["sequence"] = _integer(
                    item.get("sequence"), "history sequence", 1, 2**31 - 1
                )
                result["action"] = _ref(item.get("action"), "history action")
                result["occurred_at"] = _timestamp(item.get("occurred_at"), "occurred_at")
            else:
                result["revision"] = _integer(item.get("revision"), "value revision", 1, 2**31 - 1)
                result["updated_at"] = _timestamp(item.get("updated_at"), "updated_at")
            return result

        safe_current = [record(item, historical=False) for item in current]
        safe_history = [record(item, historical=True) for item in history]
        safe_active = {
            _ref(key, "active preference_id"): _closed_value(value) for key, value in active.items()
        }
        result = {
            "current_records": safe_current,
            "active_values": safe_active,
            "history": safe_history,
        }
        return {**result, "source_sha256": _sha256(result)}

    @classmethod
    def _sanitize_rights(
        cls,
        rights_store: object,
        context: TrustCenterContext,
        now: float,
    ) -> dict[str, Any]:
        if not callable(getattr(rights_store, "get_case", None)):
            raise TrustCenterConflict("privacy-rights authority is unavailable")
        if len(context.rights_authorizations) > _MAX_RIGHTS_CASES:
            raise TrustCenterIntegrityError("rights authorizations exceed their bound")
        summaries = []
        seen: set[str] = set()
        for auth in context.rights_authorizations:
            if not isinstance(auth, TrustCenterRightsAuthorization):
                raise TrustCenterIntegrityError("rights authorization is invalid")
            case_id = _ref(auth.case_id, "case_id")
            _digest(auth.expected_case_sha256, "expected_case_sha256")
            _digest(auth.approved_by_sha256, "rights approved_by_sha256")
            _digest(
                auth.second_approved_by_sha256,
                "rights second_approved_by_sha256",
            )
            auth_valid_until = _timestamp(auth.valid_until, "authorization valid_until")
            if not isinstance(auth.revoked, bool):
                raise TrustCenterIntegrityError("rights authorization revocation state is invalid")
            if case_id in seen:
                raise TrustCenterIntegrityError("rights authorization is duplicated")
            seen.add(case_id)
            if (
                auth.revoked
                or auth_valid_until <= now
                or not _same(auth.authorization_sha256, cls.rights_authorization_sha256(auth))
                or _same(auth.approved_by_sha256, auth.second_approved_by_sha256)
                or _same(context.actor_sha256, auth.approved_by_sha256)
                or _same(context.actor_sha256, auth.second_approved_by_sha256)
            ):
                raise TrustCenterConflict("rights authorization is expired, revoked, or invalid")
            case = rights_store.get_case(context.tenant_id, case_id)
            if (
                getattr(case, "tenant_id", None) != context.tenant_id
                or getattr(case, "case_id", None) != case_id
            ):
                raise TrustCenterConflict("authorized privacy-rights case authority mismatched")
            case_sha = _digest(getattr(case, "integrity_sha256", None), "case integrity_sha256")
            if not _same(case_sha, auth.expected_case_sha256):
                raise TrustCenterConflict("authorized privacy-rights case drifted")
            raw_rights = getattr(case, "rights", None)
            if not isinstance(raw_rights, tuple) or not 1 <= len(raw_rights) <= 32:
                raise TrustCenterIntegrityError("privacy-rights case rights are invalid")
            rights = [_ref(item, "case right") for item in raw_rights]
            if len(rights) != len(set(rights)):
                raise TrustCenterIntegrityError("privacy-rights case rights are duplicated")
            retained_until = _timestamp(
                getattr(case, "retained_until", None), "case retained_until"
            )
            if retained_until <= now:
                raise TrustCenterConflict("privacy-rights case retention has expired")
            summaries.append(
                {
                    "case_id": case_id,
                    "request_version": _integer(
                        getattr(case, "request_version", None), "request_version", 1, 2**31 - 1
                    ),
                    "rights": rights,
                    "identity_status": _ref(
                        getattr(case, "identity_status", None), "identity_status"
                    ),
                    "status": _ref(getattr(case, "status", None), "case status"),
                    "revision": _integer(
                        getattr(case, "revision", None), "case revision", 1, 2**31 - 1
                    ),
                    "created_at": _timestamp(getattr(case, "created_at", None), "case created_at"),
                    "updated_at": _timestamp(getattr(case, "updated_at", None), "case updated_at"),
                    "retained_until": retained_until,
                    "integrity_sha256": case_sha,
                }
            )
        result = {
            "cases": sorted(summaries, key=lambda item: item["case_id"]),
            "authorization_scope": "explicit_case_refs_only",
            "completeness_claimed": False,
        }
        return {**result, "source_sha256": _sha256(result)}

    def _read_once(self, context: TrustCenterContext, now: float) -> dict[str, Any]:
        capabilities = {grant.capability for grant in context.capability_grants}
        sections: dict[str, Any] = {}
        if "active_publication" in capabilities:
            config = self._publishing.resolve_public_configuration(
                context.tenant_id,
                context.property_id,
                server_origin=context.server_origin,
                server_bundle_id=context.server_bundle_id,
                server_platform=context.server_platform,
                jurisdiction=context.jurisdiction,
                country_code=context.country_code,
                region_code=context.region_code,
                requested_locale=context.requested_locale,
                evaluated_at=now,
            )
            history = self._publishing.publication_history(
                context.tenant_id,
                context.property_id,
                limit=context.publication_history_limit,
            )
            sections["publication"] = self._publication(
                config,
                history,
                tenant_id=context.tenant_id,
                property_id=context.property_id,
                history_limit=context.publication_history_limit,
            )
        if "consent_history" in capabilities:
            export = self._preferences.export_profile(
                context.tenant_id,
                context.profile_id,
                actor_sha256=context.actor_sha256,
                access_purpose="consumer_trust_center",
                receipt_limit=context.receipt_limit,
            )
            sections["consent"] = self._consent(
                export,
                tenant_id=context.tenant_id,
                profile_id=context.profile_id,
                receipt_limit=context.receipt_limit,
                now=now,
            )
        if "profile_data" in capabilities:
            if (
                self._profile_data_store is None
                or not callable(getattr(self._profile_data_store, "export_profile", None))
                or context.profile_authority is None
                or context.profile_authority.tenant_id != context.tenant_id
                or context.profile_authority.profile_id != context.profile_id
                or context.profile_authority.property_id != context.property_id
            ):
                raise TrustCenterConflict("profile-data public authority is unavailable or stale")
            sections["profile_data"] = self._sanitize_profile_data(
                self._profile_data_store.export_profile(context.profile_authority),
                tenant_id=context.tenant_id,
                profile_id=context.profile_id,
                now=now,
            )
        if "rights_cases" in capabilities:
            if self._rights_store is None:
                raise TrustCenterConflict("privacy-rights authority is unavailable")
            sections["rights"] = self._sanitize_rights(
                self._rights_store,
                context,
                now,
            )
        section_pins = {name: section["source_sha256"] for name, section in sections.items()}
        body = {
            "schema": TRUST_CENTER_SCHEMA,
            "tenant_sha256": _text_sha256(context.tenant_id),
            "property_id": context.property_id,
            "profile_ref_sha256": _text_sha256(context.profile_id),
            "context_revision": context.revision,
            "context_sha256": context.context_sha256,
            "capabilities": sorted(capabilities),
            "source_pins": section_pins,
            "sections": sections,
            "generated_at": now,
            "retained_until": context.retained_until,
            "boundaries": self.product_boundaries(),
        }
        _privacy_safe_metadata(body)
        return {**body, "snapshot_sha256": _sha256(body)}

    def __call__(self) -> dict[str, Any]:
        now = _timestamp(self._clock(), "trust-center clock")
        try:
            first_raw = self._context_resolver()
        except Exception as exc:
            raise TrustCenterIntegrityError("trust-center context resolver failed") from exc
        first_context = self._validated_context(first_raw, now)
        first = self._read_once(first_context, now)
        try:
            second_raw = self._context_resolver()
        except Exception as exc:
            raise TrustCenterIntegrityError("trust-center context resolver failed") from exc
        second_context = self._validated_context(second_raw, now)
        second = self._read_once(second_context, now)
        if first_context != second_context or first != second:
            raise TrustCenterConflict("trust-center authority drifted during snapshot resolution")
        return second


class ConsumerTrustCenterStore:
    """Persist signed metadata exports and an immutable tenant-local audit chain."""

    def __init__(
        self,
        path: Path,
        *,
        snapshot_resolver: Callable[[], Mapping[str, Any]],
        signing_key_resolver: Callable[[str, str], bytes],
        signing_key_ref: str = "local-trust-center-v1",
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
        gate: Callable[[], None] = require_trust_center_enabled,
    ) -> None:
        if not isinstance(path, Path):
            raise TrustCenterValidationError("path must be a pathlib.Path")
        if not all(
            callable(item) for item in (snapshot_resolver, signing_key_resolver, clock, gate)
        ):
            raise TrustCenterValidationError("trust-center store dependencies must be callable")
        self._path = path
        self._lock_path = path.with_suffix(path.suffix + ".lock")
        self._snapshot_resolver = snapshot_resolver
        self._key_resolver = signing_key_resolver
        self._key_ref = _ref(signing_key_ref, "signing_key_ref")
        self._clock = clock
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_hex(12)}")
        self._gate = gate
        ensure_private_directory(path.parent)
        self._initialize()
        ensure_private_file(path)

    @contextlib.contextmanager
    def _connect(self):
        with cross_process_lock(self._lock_path):
            connection = sqlite3.connect(self._path, timeout=30.0)
            try:
                connection.row_factory = sqlite3.Row
                yield connection
            finally:
                connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS trust_center_exports (
                    tenant_sha256 TEXT NOT NULL, export_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL, payload_sha256 TEXT NOT NULL,
                    signature_sha256 TEXT NOT NULL, retained_until REAL NOT NULL,
                    created_at REAL NOT NULL, PRIMARY KEY (tenant_sha256, export_id)
                );
                CREATE TABLE IF NOT EXISTS trust_center_idempotency (
                    tenant_sha256 TEXT NOT NULL, key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL, result_json TEXT NOT NULL,
                    export_id TEXT NOT NULL,
                    created_at REAL NOT NULL, PRIMARY KEY (tenant_sha256, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS trust_center_audit (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT, tenant_sha256 TEXT NOT NULL,
                    event_id TEXT NOT NULL, event_type TEXT NOT NULL, object_id TEXT NOT NULL,
                    payload_sha256 TEXT NOT NULL, previous_event_sha256 TEXT,
                    event_sha256 TEXT NOT NULL, created_at REAL NOT NULL,
                    UNIQUE (tenant_sha256, event_id)
                );
                CREATE TRIGGER IF NOT EXISTS trust_center_idempotency_no_update
                BEFORE UPDATE ON trust_center_idempotency
                BEGIN SELECT RAISE(ABORT, 'trust-center idempotency is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trust_center_audit_no_update
                BEFORE UPDATE ON trust_center_audit
                BEGIN SELECT RAISE(ABORT, 'trust-center audit is immutable'); END;
                CREATE TRIGGER IF NOT EXISTS trust_center_audit_no_delete
                BEFORE DELETE ON trust_center_audit
                BEGIN SELECT RAISE(ABORT, 'trust-center audit is immutable'); END;
                """
            )
            connection.commit()

    def _snapshot(self) -> dict[str, Any]:
        self._gate()
        try:
            raw = self._snapshot_resolver()
        except ConsumerTrustCenterError:
            raise
        except Exception as exc:
            raise TrustCenterIntegrityError("trust-center snapshot resolver failed") from exc
        if not isinstance(raw, Mapping):
            raise TrustCenterIntegrityError("trust-center snapshot is invalid")
        snapshot = dict(raw)
        supplied = snapshot.pop("snapshot_sha256", None)
        expected = _sha256(snapshot)
        source_pins = snapshot.get("source_pins")
        capabilities = snapshot.get("capabilities")
        sections = snapshot.get("sections")
        if (
            set(snapshot) != _SNAPSHOT_KEYS
            or snapshot.get("schema") != TRUST_CENTER_SCHEMA
            or not _same(supplied, expected)
            or not _DIGEST_RE.fullmatch(str(snapshot.get("tenant_sha256", "")))
            or not _DIGEST_RE.fullmatch(str(snapshot.get("profile_ref_sha256", "")))
            or not _DIGEST_RE.fullmatch(str(snapshot.get("context_sha256", "")))
            or not isinstance(source_pins, Mapping)
            or not isinstance(capabilities, list)
            or not isinstance(sections, Mapping)
            or capabilities != sorted(set(capabilities))
            or not set(capabilities).issubset(_CAPABILITIES)
            or set(source_pins)
            != {
                {
                    "active_publication": "publication",
                    "consent_history": "consent",
                    "profile_data": "profile_data",
                    "rights_cases": "rights",
                }.get(item)
                for item in capabilities
            }
            or set(sections)
            != {
                {
                    "active_publication": "publication",
                    "consent_history": "consent",
                    "profile_data": "profile_data",
                    "rights_cases": "rights",
                }.get(item)
                for item in capabilities
            }
            or snapshot.get("boundaries") != ConsumerTrustCenterSourceAdapter.product_boundaries()
        ):
            raise TrustCenterIntegrityError("trust-center snapshot failed integrity")
        for capability, section_name in {
            "active_publication": "publication",
            "consent_history": "consent",
            "profile_data": "profile_data",
            "rights_cases": "rights",
        }.items():
            if capability not in capabilities:
                continue
            section = sections.get(section_name)
            if not isinstance(section, Mapping) or not _same(
                section.get("source_sha256"), source_pins.get(section_name)
            ):
                raise TrustCenterIntegrityError("trust-center source pin failed integrity")
            section_body = dict(section)
            section_sha = section_body.pop("source_sha256", None)
            if not _same(_sha256(section_body), section_sha):
                raise TrustCenterIntegrityError("trust-center source section failed integrity")
            if section_name == "publication" and section.get("branding") is not None:
                ConsumerTrustCenterSourceAdapter._branding(section["branding"])
        _timestamp(snapshot.get("generated_at"), "snapshot generated_at")
        _timestamp(snapshot.get("retained_until"), "snapshot retained_until")
        _privacy_safe_metadata(snapshot)
        return {**snapshot, "snapshot_sha256": expected}

    def snapshot(self) -> dict[str, Any]:
        return self._snapshot()

    def _key(self, tenant_sha: str, key_ref: str) -> bytes:
        resolved_ref = _ref(key_ref, "signing_key_ref")
        try:
            key = self._key_resolver(tenant_sha, resolved_ref)
        except Exception as exc:
            raise TrustCenterIntegrityError("trust-center signing key resolver failed") from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise TrustCenterIntegrityError("trust-center signing key must be at least 32 bytes")
        return key

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_sha: str,
        event_type: str,
        object_id: str,
        payload: Mapping[str, Any],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT event_sha256 FROM trust_center_audit WHERE tenant_sha256=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_sha,),
        ).fetchone()
        previous_sha = str(previous["event_sha256"]) if previous else None
        body = {
            "event_id": _ref(self._id_factory("TC-AUD"), "event_id"),
            "event_type": _ref(event_type, "event_type"),
            "object_id": _ref(object_id, "object_id"),
            "payload_sha256": _sha256(payload),
            "previous_event_sha256": previous_sha,
            "created_at": now,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO trust_center_audit(tenant_sha256,event_id,event_type,object_id,"
            "payload_sha256,previous_event_sha256,event_sha256,created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                tenant_sha,
                body["event_id"],
                body["event_type"],
                body["object_id"],
                body["payload_sha256"],
                previous_sha,
                event_sha,
                now,
            ),
        )

    def export_signed(self, *, idempotency_key: str) -> dict[str, Any]:
        snapshot = self._snapshot()
        tenant_sha = _digest(snapshot["tenant_sha256"], "tenant_sha256")
        idem_sha = _idempotency(idempotency_key)
        request_sha = _export_request_sha(snapshot)
        now = _timestamp(self._clock(), "trust-center clock")
        if _timestamp(snapshot["retained_until"], "retained_until") <= now:
            raise TrustCenterConflict("trust-center snapshot retention has expired")
        key = self._key(tenant_sha, self._key_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT request_sha256,result_json FROM trust_center_idempotency "
                    "WHERE tenant_sha256=? AND key_sha256=?",
                    (tenant_sha, idem_sha),
                ).fetchone()
                if row is not None:
                    if not _same(row["request_sha256"], request_sha):
                        raise TrustCenterConflict("idempotency key was rebound")
                    result = _loads(row["result_json"], "trust-center idempotency result")
                    if not isinstance(result, dict):
                        raise TrustCenterIntegrityError("stored idempotency result is invalid")
                    connection.execute("COMMIT")
                    return result
                export_id = _ref(self._id_factory("TC-EXP"), "export_id")
                payload = {
                    "schema": TRUST_CENTER_EXPORT_SCHEMA,
                    "export_id": export_id,
                    "snapshot": snapshot,
                    "signing_key_ref": self._key_ref,
                    "created_at": now,
                    "retained_until": snapshot["retained_until"],
                }
                payload_bytes = _canonical(payload)
                payload_sha = hashlib.sha256(payload_bytes).hexdigest()
                signature = hmac.new(key, payload_bytes, hashlib.sha256).hexdigest()
                result = {
                    "payload": payload,
                    "payload_sha256": payload_sha,
                    "signature_sha256": signature,
                }
                connection.execute(
                    "INSERT INTO trust_center_exports VALUES (?,?,?,?,?,?,?)",
                    (
                        tenant_sha,
                        export_id,
                        payload_bytes.decode("ascii"),
                        payload_sha,
                        signature,
                        snapshot["retained_until"],
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO trust_center_idempotency VALUES (?,?,?,?,?,?)",
                    (
                        tenant_sha,
                        idem_sha,
                        request_sha,
                        _canonical(result).decode("ascii"),
                        export_id,
                        now,
                    ),
                )
                self._audit(
                    connection,
                    tenant_sha,
                    "trust_center.exported",
                    export_id,
                    {"payload_sha256": payload_sha, "snapshot_sha256": snapshot["snapshot_sha256"]},
                    now,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def verify_export(self, export: Mapping[str, Any]) -> bool:
        if not isinstance(export, Mapping) or set(export) != {
            "payload",
            "payload_sha256",
            "signature_sha256",
        }:
            return False
        payload = export.get("payload")
        if not isinstance(payload, Mapping):
            return False
        snapshot = payload.get("snapshot")
        if not isinstance(snapshot, Mapping):
            return False
        try:
            tenant_sha = _digest(snapshot.get("tenant_sha256"), "tenant_sha256")
            payload_sha = _digest(export.get("payload_sha256"), "payload_sha256")
            signature = _digest(export.get("signature_sha256"), "signature_sha256")
            signing_key_ref = _ref(payload.get("signing_key_ref"), "signing_key_ref")
            encoded = _canonical(payload)
            key = self._key(tenant_sha, signing_key_ref)
            snapshot_body = dict(snapshot)
            supplied_snapshot_sha = snapshot_body.pop("snapshot_sha256", None)
            valid_metadata = (
                payload.get("schema") == TRUST_CENTER_EXPORT_SCHEMA
                and snapshot.get("schema") == TRUST_CENTER_SCHEMA
                and _REF_RE.fullmatch(str(payload.get("export_id", ""))) is not None
                and _same(_sha256(snapshot_body), supplied_snapshot_sha)
            )
        except ConsumerTrustCenterError:
            return False
        return (
            valid_metadata
            and _same(hashlib.sha256(encoded).hexdigest(), payload_sha)
            and _same(hmac.new(key, encoded, hashlib.sha256).hexdigest(), signature)
        )

    def retention_due(self, *, before: float, limit: int = 100) -> dict[str, Any]:
        self._gate()
        cutoff = _timestamp(before, "before")
        page_size = _integer(limit, "limit", 1, _MAX_HISTORY)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT tenant_sha256,export_id,payload_sha256,retained_until FROM "
                "trust_center_exports WHERE retained_until<=? ORDER BY retained_until,export_id "
                "LIMIT ?",
                (cutoff, page_size + 1),
            ).fetchall()
        return {
            "items": [dict(row) for row in rows[:page_size]],
            "truncated": len(rows) > page_size,
        }

    def purge_expired(self, *, before: float, limit: int = 100) -> dict[str, Any]:
        self._gate()
        cutoff = _timestamp(before, "before")
        page_size = _integer(limit, "limit", 1, _MAX_HISTORY)
        now = _timestamp(self._clock(), "trust-center clock")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT tenant_sha256,export_id,payload_sha256 FROM trust_center_exports "
                    "WHERE retained_until<=? ORDER BY retained_until,export_id LIMIT ?",
                    (cutoff, page_size),
                ).fetchall()
                for row in rows:
                    connection.execute(
                        "DELETE FROM trust_center_idempotency "
                        "WHERE tenant_sha256=? AND export_id=?",
                        (row["tenant_sha256"], row["export_id"]),
                    )
                    connection.execute(
                        "DELETE FROM trust_center_exports WHERE tenant_sha256=? AND export_id=?",
                        (row["tenant_sha256"], row["export_id"]),
                    )
                    self._audit(
                        connection,
                        str(row["tenant_sha256"]),
                        "trust_center.export_purged",
                        str(row["export_id"]),
                        {"payload_sha256": row["payload_sha256"], "cutoff": cutoff},
                        now,
                    )
                connection.execute("COMMIT")
                return {"exports_deleted": len(rows), "cutoff": cutoff}
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def verify_integrity(self) -> dict[str, int]:
        self._gate()
        counts = {"exports": 0, "idempotency": 0, "audit_events": 0}
        with self._connect() as connection:
            for row in connection.execute("SELECT * FROM trust_center_exports"):
                payload = _loads(row["payload_json"], "trust-center export")
                encoded = _canonical(payload)
                snapshot = payload.get("snapshot") if isinstance(payload, Mapping) else None
                if not isinstance(snapshot, Mapping):
                    raise TrustCenterIntegrityError("stored trust-center export is invalid")
                signing_key_ref = _ref(payload.get("signing_key_ref"), "signing_key_ref")
                key = self._key(str(row["tenant_sha256"]), signing_key_ref)
                snapshot_body = dict(snapshot)
                supplied_snapshot_sha = snapshot_body.pop("snapshot_sha256", None)
                if (
                    not _same(_sha256(snapshot_body), supplied_snapshot_sha)
                    or not _same(hashlib.sha256(encoded).hexdigest(), row["payload_sha256"])
                    or not _same(
                        hmac.new(key, encoded, hashlib.sha256).hexdigest(), row["signature_sha256"]
                    )
                ):
                    raise TrustCenterIntegrityError("stored trust-center export failed integrity")
                counts["exports"] += 1
            for row in connection.execute("SELECT * FROM trust_center_idempotency"):
                if not _DIGEST_RE.fullmatch(str(row["key_sha256"])) or not _DIGEST_RE.fullmatch(
                    str(row["request_sha256"])
                ):
                    raise TrustCenterIntegrityError("stored trust-center idempotency is invalid")
                result = _loads(row["result_json"], "idempotency result")
                if not isinstance(result, dict) or not self.verify_export(result):
                    raise TrustCenterIntegrityError("stored idempotency result is invalid")
                payload = result.get("payload")
                snapshot = payload.get("snapshot") if isinstance(payload, Mapping) else None
                if (
                    not isinstance(snapshot, Mapping)
                    or payload.get("export_id") != row["export_id"]
                    or not _same(_export_request_sha(snapshot), row["request_sha256"])
                ):
                    raise TrustCenterIntegrityError("stored idempotency binding is invalid")
                export_row = connection.execute(
                    "SELECT payload_sha256,signature_sha256 FROM trust_center_exports "
                    "WHERE tenant_sha256=? AND export_id=?",
                    (row["tenant_sha256"], row["export_id"]),
                ).fetchone()
                if (
                    export_row is None
                    or not _same(export_row["payload_sha256"], result.get("payload_sha256"))
                    or not _same(export_row["signature_sha256"], result.get("signature_sha256"))
                ):
                    raise TrustCenterIntegrityError("stored idempotency export is missing")
                counts["idempotency"] += 1
            tenants = [
                str(row[0])
                for row in connection.execute(
                    "SELECT DISTINCT tenant_sha256 FROM trust_center_audit ORDER BY tenant_sha256"
                )
            ]
            active_audit_exports: set[tuple[str, str]] = set()
            for tenant_sha in tenants:
                previous = None
                for row in connection.execute(
                    "SELECT * FROM trust_center_audit WHERE tenant_sha256=? ORDER BY sequence",
                    (tenant_sha,),
                ):
                    body = {
                        "event_id": row["event_id"],
                        "event_type": row["event_type"],
                        "object_id": row["object_id"],
                        "payload_sha256": row["payload_sha256"],
                        "previous_event_sha256": row["previous_event_sha256"],
                        "created_at": row["created_at"],
                    }
                    expected = _sha256(body)
                    event_type = str(row["event_type"])
                    export_key = (tenant_sha, str(row["object_id"]))
                    invalid_transition = False
                    if event_type == "trust_center.exported":
                        invalid_transition = export_key in active_audit_exports
                        active_audit_exports.add(export_key)
                    elif event_type == "trust_center.export_purged":
                        invalid_transition = export_key not in active_audit_exports
                        active_audit_exports.discard(export_key)
                    else:
                        invalid_transition = True
                    if (
                        invalid_transition
                        or row["previous_event_sha256"] != previous
                        or not _same(expected, row["event_sha256"])
                    ):
                        raise TrustCenterIntegrityError(
                            "stored trust-center audit failed integrity"
                        )
                    previous = expected
                    counts["audit_events"] += 1
            stored_exports = {
                (str(row["tenant_sha256"]), str(row["export_id"]))
                for row in connection.execute(
                    "SELECT tenant_sha256,export_id FROM trust_center_exports"
                )
            }
            if stored_exports != active_audit_exports:
                raise TrustCenterIntegrityError("stored trust-center export audit state diverged")
        return counts
