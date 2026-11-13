"""Governed Global Opt-Out application and DSAR hand-off authority.

This module is deliberately transport and identity agnostic.  An operator may
configure one application only after a deployment resolver has independently
resolved its exact public-client, property, publication, policy, and channel
authority.  Public callers never select those facts: composition supplies a
profile-bound :class:`GlobalOptOutPublicAuthority` after authenticating the
existing public consent capabilities.

The durable record contains configuration text and authority digests.  A
successful submission retains only a SHA-256 digest of the privacy-rights case
identifier and a verified result digest.  Raw case identifiers, DSAR payloads,
identity values, credentials, origins, service identifiers, paths, and device
tokens are outside this persistence contract.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, is_dataclass
from typing import Any, Literal

from .constant_time import text_equals
from .governed_records import (
    GovernedRecordBackendError,
    GovernedRecordCapacityError,
    GovernedRecordStore,
)
from .paths import canonical_tenant_id, tenant_scope
from .privacy_ops import RecordConflict

SCHEMA_VERSION = 1
CONFIG_SCHEMA = "lightwork.consent-global-opt-out-config.v1"
SUBMISSION_SCHEMA = "lightwork.consent-global-opt-out-submission.v1"
PUBLIC_CONFIG_SCHEMA = "lightwork.public-global-opt-out-config.v1"
PUBLIC_SUBMISSION_SCHEMA = "lightwork.public-global-opt-out-submission.v1"

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{7,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_LOCALE_RE = re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8}){0,3}\Z")

_CHANNELS = frozenset({"browser-origin", "mobile-app", "service-client", "ott-ctv"})
_DEVICES = frozenset(
    {"android", "browser", "connected-tv", "fireos", "ios", "roku", "tizen", "tvos", "webos"}
)
_SERVICES = frozenset(
    {"connected-tv", "email", "mobile-app", "streaming-service", "website"}
)
_CONFIG_STATES = frozenset({"draft", "active", "revoked", "purged"})
_SUBMISSION_STATES = frozenset({"creating", "submitted", "purged"})
_UI_KEYS = frozenset({"body", "enabled", "submit_label", "success_message", "title"})
_MAX_TEXT = 2_048
_MAX_RECORDS = 100_000
_MAX_HISTORY = 128
_MIN_RETENTION_SECONDS = 3_600
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600


class GlobalOptOutError(RuntimeError):
    """Base error for the configured Global Opt-Out application."""

    code = "global_opt_out_unavailable"


class GlobalOptOutDisabled(GlobalOptOutError):
    """The nested feature gate is not exactly enabled."""

    code = "global_opt_out_disabled"


class GlobalOptOutNotConfigured(GlobalOptOutError):
    """No current active configuration matches the public authority."""

    code = "global_opt_out_not_configured"


class GlobalOptOutAuthorityStale(GlobalOptOutError):
    """A public client, publication, policy, profile, or channel changed."""

    code = "global_opt_out_authority_stale"


class GlobalOptOutDSARUnavailable(GlobalOptOutError):
    """The injected privacy-rights intake could not create a real case."""

    code = "global_opt_out_dsar_unavailable"


class GlobalOptOutValidationError(GlobalOptOutError, ValueError):
    """Input is outside the closed application contract."""

    code = "global_opt_out_invalid"


class GlobalOptOutConflict(GlobalOptOutError):
    """A CAS, idempotency, state, or lifecycle precondition failed."""

    code = "global_opt_out_conflict"


class GlobalOptOutNotFound(GlobalOptOutError):
    """A tenant-scoped configuration or submission does not exist."""

    code = "global_opt_out_not_found"


class GlobalOptOutPermissionDenied(GlobalOptOutError):
    """The authenticated operator principal is unavailable or changed."""

    code = "global_opt_out_permission_denied"


class GlobalOptOutIntegrityError(GlobalOptOutError):
    """A retained record or history chain failed verification."""

    code = "global_opt_out_integrity_failure"


@dataclass(frozen=True, slots=True)
class GlobalOptOutLimits:
    """Bounded tenant settings loaded from the nested feature table."""

    retention_seconds: int = 365 * 24 * 3_600
    submission_ttl_seconds: int = 15 * 60
    max_records: int = 10_000

    def __post_init__(self) -> None:
        _integer(
            self.retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        _integer(self.submission_ttl_seconds, "submission_ttl_seconds", 60, 86_400)
        _integer(self.max_records, "max_records", 1, _MAX_RECORDS)


@dataclass(frozen=True, slots=True)
class GlobalOptOutApplicationAuthority:
    """Exact server-resolved authority for one configurable application."""

    tenant_id: str
    application_ref: str
    public_client_revision: int
    public_client_record_sha256: str
    property_revision: int
    property_sha256: str
    publication_sha256: str
    publication_bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    channel: str
    origin_or_service_sha256: str
    valid_until: float
    revoked: bool
    authority_sha256: str

    def normalized(self) -> GlobalOptOutApplicationAuthority:
        body = {
            "tenant_id": _tenant(self.tenant_id),
            "application_ref": _ref(self.application_ref, "application_ref"),
            "public_client_revision": _integer(
                self.public_client_revision, "public_client_revision", 1, 2**31 - 1
            ),
            "public_client_record_sha256": _digest(
                self.public_client_record_sha256, "public_client_record_sha256"
            ),
            "property_revision": _integer(
                self.property_revision, "property_revision", 1, 2**31 - 1
            ),
            "property_sha256": _digest(self.property_sha256, "property_sha256"),
            "publication_sha256": _digest(
                self.publication_sha256, "publication_sha256"
            ),
            "publication_bundle_sha256": _digest(
                self.publication_bundle_sha256, "publication_bundle_sha256"
            ),
            "configuration_sha256": _digest(
                self.configuration_sha256, "configuration_sha256"
            ),
            "policy_id": _ref(self.policy_id, "policy_id"),
            "policy_version": _integer(self.policy_version, "policy_version", 1, 2**31 - 1),
            "policy_sha256": _digest(self.policy_sha256, "policy_sha256"),
            "channel": _choice(self.channel, "channel", _CHANNELS),
            "origin_or_service_sha256": _digest(
                self.origin_or_service_sha256, "origin_or_service_sha256"
            ),
            "valid_until": _timestamp(self.valid_until, "valid_until"),
            "revoked": _boolean(self.revoked, "revoked"),
        }
        expected = _sha256({"schema": "lightwork.global-opt-out-application-authority.v1", **body})
        if not _same(expected, self.authority_sha256):
            raise GlobalOptOutAuthorityStale("application authority digest is invalid")
        return GlobalOptOutApplicationAuthority(**body, authority_sha256=expected)


@dataclass(frozen=True, slots=True)
class GlobalOptOutPublicAuthority:
    """Application authority plus an exact anonymous public profile binding."""

    tenant_id: str
    application_ref: str
    public_client_revision: int
    public_client_record_sha256: str
    property_revision: int
    property_sha256: str
    publication_sha256: str
    publication_bundle_sha256: str
    configuration_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    channel: str
    origin_or_service_sha256: str
    profile_sha256: str
    profile_binding_sha256: str
    profile_revision: int
    intake_authority_sha256: str
    valid_until: float
    revoked: bool
    authority_sha256: str

    def normalized(self) -> GlobalOptOutPublicAuthority:
        body = {
            "tenant_id": _tenant(self.tenant_id),
            "application_ref": _ref(self.application_ref, "application_ref"),
            "public_client_revision": _integer(
                self.public_client_revision, "public_client_revision", 1, 2**31 - 1
            ),
            "public_client_record_sha256": _digest(
                self.public_client_record_sha256, "public_client_record_sha256"
            ),
            "property_revision": _integer(
                self.property_revision, "property_revision", 1, 2**31 - 1
            ),
            "property_sha256": _digest(self.property_sha256, "property_sha256"),
            "publication_sha256": _digest(
                self.publication_sha256, "publication_sha256"
            ),
            "publication_bundle_sha256": _digest(
                self.publication_bundle_sha256, "publication_bundle_sha256"
            ),
            "configuration_sha256": _digest(
                self.configuration_sha256, "configuration_sha256"
            ),
            "policy_id": _ref(self.policy_id, "policy_id"),
            "policy_version": _integer(self.policy_version, "policy_version", 1, 2**31 - 1),
            "policy_sha256": _digest(self.policy_sha256, "policy_sha256"),
            "channel": _choice(self.channel, "channel", _CHANNELS),
            "origin_or_service_sha256": _digest(
                self.origin_or_service_sha256, "origin_or_service_sha256"
            ),
            "profile_sha256": _digest(self.profile_sha256, "profile_sha256"),
            "profile_binding_sha256": _digest(
                self.profile_binding_sha256, "profile_binding_sha256"
            ),
            "profile_revision": _integer(self.profile_revision, "profile_revision", 1, 2**31 - 1),
            "intake_authority_sha256": _digest(
                self.intake_authority_sha256, "intake_authority_sha256"
            ),
            "valid_until": _timestamp(self.valid_until, "valid_until"),
            "revoked": _boolean(self.revoked, "revoked"),
        }
        expected = _sha256({"schema": "lightwork.global-opt-out-public-authority.v1", **body})
        if not _same(expected, self.authority_sha256):
            raise GlobalOptOutAuthorityStale("public authority digest is invalid")
        return GlobalOptOutPublicAuthority(**body, authority_sha256=expected)


@dataclass(frozen=True, slots=True)
class GlobalOptOutDSARResult:
    """Ephemeral verified result returned by the privacy-rights adapter."""

    case_id: str
    result_sha256: str

    def normalized(self) -> GlobalOptOutDSARResult:
        return GlobalOptOutDSARResult(
            case_id=_ref(self.case_id, "privacy-rights case_id"),
            result_sha256=_digest(self.result_sha256, "privacy-rights result_sha256"),
        )


ApplicationAuthorityResolver = Callable[
    [str, str, str], GlobalOptOutApplicationAuthority
]
PublicAuthorityResolver = Callable[[], GlobalOptOutPublicAuthority]
IntakeAuthorityResolver = Callable[[], object]
PrivacyRightsSubmitter = Callable[
    [object, Sequence[str], int, str], GlobalOptOutDSARResult
]


def global_opt_out_enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only for the exact parent and nested Global Opt-Out gates."""

    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                return False
            config = load_config()
        except Exception:
            return False
    if not isinstance(config, Mapping):
        return False
    consent = config.get("consent_preferences")
    global_opt_out = consent.get("global_opt_out") if isinstance(consent, Mapping) else None
    return (
        isinstance(consent, Mapping)
        and consent.get("enable") is True
        and isinstance(global_opt_out, Mapping)
        and global_opt_out.get("enable") is True
    )


def require_global_opt_out_enabled(config: Mapping[str, Any] | None = None) -> None:
    if not global_opt_out_enabled(config):
        raise GlobalOptOutDisabled(
            "Global Opt-Out requires consent_preferences and "
            "consent_preferences.global_opt_out"
        )


def load_global_opt_out_limits(config: Mapping[str, Any]) -> GlobalOptOutLimits:
    require_global_opt_out_enabled(config)
    consent = config["consent_preferences"]
    table = consent["global_opt_out"]
    return GlobalOptOutLimits(
        retention_seconds=_integer(
            table.get("retention_seconds", 365 * 24 * 3_600),
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        ),
        submission_ttl_seconds=_integer(
            table.get("submission_ttl_seconds", 15 * 60),
            "submission_ttl_seconds",
            60,
            86_400,
        ),
        max_records=_integer(
            table.get("max_records", 10_000), "max_records", 1, _MAX_RECORDS
        ),
    )


def issue_application_authority(**values: Any) -> GlobalOptOutApplicationAuthority:
    """Issue a self-digesting application authority from server-owned facts."""

    candidate = GlobalOptOutApplicationAuthority(authority_sha256="0" * 64, **values)
    body = asdict(candidate)
    body.pop("authority_sha256")
    digest = _sha256({"schema": "lightwork.global-opt-out-application-authority.v1", **body})
    return GlobalOptOutApplicationAuthority(**body, authority_sha256=digest).normalized()


def issue_public_authority(**values: Any) -> GlobalOptOutPublicAuthority:
    """Issue a self-digesting public authority from server-owned facts."""

    candidate = GlobalOptOutPublicAuthority(authority_sha256="0" * 64, **values)
    body = asdict(candidate)
    body.pop("authority_sha256")
    digest = _sha256({"schema": "lightwork.global-opt-out-public-authority.v1", **body})
    return GlobalOptOutPublicAuthority(**body, authority_sha256=digest).normalized()


def authority_material_sha256(value: object) -> str:
    """Digest a dataclass or closed mapping without persisting its raw facts."""

    if is_dataclass(value) and not isinstance(value, type):
        body = asdict(value)
    elif isinstance(value, Mapping):
        body = dict(value)
    else:
        attributes = getattr(value, "__dict__", None)
        if not isinstance(attributes, Mapping):
            raise GlobalOptOutAuthorityStale("privacy-rights authority is invalid")
        body = dict(attributes)
    return _sha256({"schema": "lightwork.global-opt-out-intake-authority.v1", "authority": body})


def _canonical(value: object, *, maximum: int = 512 * 1_024) -> bytes:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise GlobalOptOutValidationError("Global Opt-Out data must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise GlobalOptOutValidationError("Global Opt-Out data exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and text_equals(left, right)


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise GlobalOptOutValidationError("tenant_id is invalid") from exc


def _ref(value: object, label: str) -> str:
    if not isinstance(value, str) or _REF_RE.fullmatch(value) is None:
        raise GlobalOptOutValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise GlobalOptOutValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise GlobalOptOutValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise GlobalOptOutValidationError(f"{label} must be a positive timestamp")
    return float(value)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise GlobalOptOutValidationError(f"{label} must be boolean")
    return value


def _choice(value: object, label: str, choices: frozenset[str]) -> str:
    if not isinstance(value, str) or value not in choices:
        raise GlobalOptOutValidationError(f"{label} is invalid")
    return value


def _idempotency(value: object) -> str:
    if not isinstance(value, str) or _IDEMPOTENCY_RE.fullmatch(value) is None:
        raise GlobalOptOutValidationError("idempotency_key is invalid")
    return value


def _bounded_text(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_TEXT
        or any(ord(character) < 32 and character not in "\t\n\r" for character in value)
    ):
        raise GlobalOptOutValidationError(f"{label} is invalid")
    return value


def _locale(value: object) -> str:
    if not isinstance(value, str) or _LOCALE_RE.fullmatch(value) is None:
        raise GlobalOptOutValidationError("locale is invalid")
    return value


def _ui(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _UI_KEYS:
        raise GlobalOptOutValidationError(f"{label} has an invalid shape")
    enabled = _boolean(value["enabled"], f"{label}.enabled")
    return {
        "enabled": enabled,
        "title": _bounded_text(value["title"], f"{label}.title"),
        "body": _bounded_text(value["body"], f"{label}.body"),
        "submit_label": _bounded_text(
            value["submit_label"], f"{label}.submit_label"
        ),
        "success_message": _bounded_text(
            value["success_message"], f"{label}.success_message"
        ),
    }


def _choices(value: object, label: str, allowed: frozenset[str]) -> list[str]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, (str, bytes, bytearray))
        or not 1 <= len(value) <= len(allowed)
    ):
        raise GlobalOptOutValidationError(f"{label} is invalid")
    normalized = [_choice(item, label, allowed) for item in value]
    if len(set(normalized)) != len(normalized):
        raise GlobalOptOutValidationError(f"{label} contains duplicates")
    return sorted(normalized)


def _binding(authority: GlobalOptOutApplicationAuthority) -> dict[str, Any]:
    body = asdict(authority.normalized())
    body.pop("tenant_id")
    body.pop("valid_until")
    body.pop("revoked")
    # The resolver's validity horizon is checked on every operation but is not
    # part of the long-lived application binding.  Public profile/intake
    # authority is normally shorter lived than the enrolled client, so pinning
    # that horizon would make an otherwise unchanged configuration stale on
    # every public request.  All stable revisions and digests remain exact.
    body.pop("authority_sha256")
    body["binding_sha256"] = _sha256(
        {"schema": "lightwork.global-opt-out-application-binding.v1", **body}
    )
    return body


def _public_binding(authority: GlobalOptOutPublicAuthority) -> dict[str, Any]:
    body = asdict(authority.normalized())
    for key in (
        "tenant_id",
        "profile_sha256",
        "profile_binding_sha256",
        "profile_revision",
        "intake_authority_sha256",
        "valid_until",
        "revoked",
    ):
        body.pop(key)
    body.pop("authority_sha256")
    body["binding_sha256"] = _sha256(
        {"schema": "lightwork.global-opt-out-application-binding.v1", **body}
    )
    return body


def _configuration_id(tenant_id: str, application_ref: str) -> str:
    digest = _sha256(
        {
            "schema": "lightwork.global-opt-out-configuration-id.v1",
            "tenant_id": tenant_id,
            "application_ref": application_ref,
        }
    )
    return f"GOO-C{digest[:48]}"


def _submission_id(
    tenant_id: str,
    authority: GlobalOptOutPublicAuthority,
    idempotency_key: str,
) -> str:
    digest = _sha256(
        {
            "schema": "lightwork.global-opt-out-submission-id.v1",
            "tenant_id": tenant_id,
            "application_ref": authority.application_ref,
            "profile_sha256": authority.profile_sha256,
            "profile_binding_sha256": authority.profile_binding_sha256,
            "idempotency_key_sha256": _text_sha256(idempotency_key),
        }
    )
    return f"GOO-S{digest[:48]}"


def _record_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.items()
        if key
        not in {
            "_audit_pending",
            "created_at",
            "integrity_sha256",
            "revision",
            "updated_at",
        }
    }


def _integrity(record: Mapping[str, Any]) -> str:
    return _sha256(
        {
            "schema": "lightwork.global-opt-out-record-integrity.v1",
            "record": _record_payload(record),
        }
    )


def _append_history(record: dict[str, Any], action: str, actor_sha256: str, now: float) -> None:
    history = record.setdefault("history", [])
    if not isinstance(history, list) or len(history) >= _MAX_HISTORY:
        raise GlobalOptOutConflict("configuration history bound is exhausted")
    previous = history[-1]["event_sha256"] if history else "0" * 64
    event = {
        "sequence": len(history) + 1,
        "action": _ref(action, "history action"),
        "occurred_at": _timestamp(now, "history occurred_at"),
        "actor_sha256": _digest(actor_sha256, "history actor_sha256"),
        "previous_sha256": _digest(previous, "history previous_sha256"),
        "snapshot_sha256": _sha256(
            {
                key: value
                for key, value in record.items()
                if key not in {"history", "integrity_sha256"}
            }
        ),
    }
    event["event_sha256"] = _sha256(
        {"schema": "lightwork.global-opt-out-history-event.v1", **event}
    )
    history.append(event)


def _verify_record(record: Mapping[str, Any]) -> None:
    supplied = record.get("integrity_sha256")
    if not isinstance(supplied, str) or not _same(supplied, _integrity(record)):
        raise GlobalOptOutIntegrityError("Global Opt-Out record integrity failed")
    history = record.get("history")
    if not isinstance(history, list) or not history or len(history) > _MAX_HISTORY:
        raise GlobalOptOutIntegrityError("Global Opt-Out history is invalid")
    previous = "0" * 64
    for sequence, raw in enumerate(history, start=1):
        if not isinstance(raw, Mapping):
            raise GlobalOptOutIntegrityError("Global Opt-Out history is invalid")
        event = dict(raw)
        supplied_event = event.pop("event_sha256", None)
        if (
            event.get("sequence") != sequence
            or not _same(event.get("previous_sha256"), previous)
            or not isinstance(supplied_event, str)
            or not _same(
                supplied_event,
                _sha256({"schema": "lightwork.global-opt-out-history-event.v1", **event}),
            )
        ):
            raise GlobalOptOutIntegrityError("Global Opt-Out history chain failed")
        previous = supplied_event


class GlobalOptOutStore:
    """Tenant-bound durable authority for configuration and submissions."""

    def __init__(
        self,
        *,
        tenant_id: str,
        principal_ref: str,
        application_authority_resolver: ApplicationAuthorityResolver,
        principal_resolver: Callable[[], str],
        config_gate: Callable[[], object],
        limits: GlobalOptOutLimits | None = None,
        public_authority_resolver: PublicAuthorityResolver | None = None,
        intake_authority_resolver: IntakeAuthorityResolver | None = None,
        privacy_rights_submitter: PrivacyRightsSubmitter | None = None,
        maintenance_authorizer: Callable[[], bool] | None = None,
        record_store: GovernedRecordStore | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.tenant_id = _tenant(tenant_id)
        self._principal_ref = _ref(principal_ref, "principal_ref")
        if not callable(application_authority_resolver):
            raise GlobalOptOutValidationError("application authority resolver is unavailable")
        if not callable(principal_resolver) or not callable(config_gate):
            raise GlobalOptOutValidationError("operator authority is unavailable")
        if public_authority_resolver is not None and not callable(public_authority_resolver):
            raise GlobalOptOutValidationError("public authority resolver is unavailable")
        if intake_authority_resolver is not None and not callable(intake_authority_resolver):
            raise GlobalOptOutValidationError("intake authority resolver is unavailable")
        if privacy_rights_submitter is not None and not callable(privacy_rights_submitter):
            raise GlobalOptOutValidationError("privacy-rights submitter is unavailable")
        self._application_authority = application_authority_resolver
        self._principal = principal_resolver
        self._config_gate = config_gate
        self._public_authority = public_authority_resolver
        self._intake_authority = intake_authority_resolver
        self._privacy_rights_submitter = privacy_rights_submitter
        self._maintenance = maintenance_authorizer or (lambda: False)
        self.limits = limits or GlobalOptOutLimits()
        self._clock = clock
        self._records = record_store or GovernedRecordStore(
            "consent_global_opt_out",
            "GOO",
            "consent_global_opt_out",
            event_kind="consent_global_opt_out_changed",
        )

    def _require_enabled(self) -> None:
        try:
            result = self._config_gate()
            if isinstance(result, Mapping):
                require_global_opt_out_enabled(result)
            elif result is False:
                raise GlobalOptOutDisabled("Global Opt-Out is disabled")
        except GlobalOptOutDisabled:
            raise
        except Exception as exc:
            raise GlobalOptOutDisabled("Global Opt-Out configuration is unavailable") from exc

    def _actor_sha256(self) -> str:
        try:
            current = self._principal()
        except Exception as exc:
            raise GlobalOptOutPermissionDenied("operator principal is unavailable") from exc
        if not isinstance(current, str) or not _same(current, self._principal_ref):
            raise GlobalOptOutPermissionDenied("operator principal authority changed")
        return _text_sha256(f"global-opt-out\0{self.tenant_id}\0{current}")

    def _call(self, method: str, *args: Any, **kwargs: Any) -> Any:
        try:
            with tenant_scope(tenant=self.tenant_id):
                return getattr(self._records, method)(*args, **kwargs)
        except (GlobalOptOutError, KeyboardInterrupt, SystemExit):
            raise
        except GovernedRecordCapacityError as exc:
            raise GlobalOptOutConflict("Global Opt-Out record capacity is exhausted") from exc
        except RecordConflict as exc:
            raise GlobalOptOutConflict("Global Opt-Out state changed concurrently") from exc
        except GovernedRecordBackendError as exc:
            raise GlobalOptOutIntegrityError("Global Opt-Out durability is unavailable") from exc

    @property
    def backend_kind(self) -> str:
        try:
            with tenant_scope(tenant=self.tenant_id):
                return str(self._records.backend_kind)
        except GovernedRecordBackendError as exc:
            raise GlobalOptOutIntegrityError(
                "Global Opt-Out durability is unavailable"
            ) from exc

    def _resolve_application(self, application_ref: str) -> GlobalOptOutApplicationAuthority:
        ref = _ref(application_ref, "application_ref")
        actor = self._principal_ref
        try:
            first = self._application_authority(self.tenant_id, actor, ref).normalized()
            second = self._application_authority(self.tenant_id, actor, ref).normalized()
        except GlobalOptOutError:
            raise
        except Exception as exc:
            raise GlobalOptOutAuthorityStale("application authority is unavailable") from exc
        if first != second:
            raise GlobalOptOutAuthorityStale("application authority changed during resolution")
        now = _timestamp(self._clock(), "clock")
        if first.tenant_id != self.tenant_id or first.revoked or first.valid_until <= now:
            raise GlobalOptOutAuthorityStale("application authority is stale")
        return first

    def _resolve_public(self, expected: GlobalOptOutPublicAuthority | None = None) -> GlobalOptOutPublicAuthority:
        if self._public_authority is None:
            raise GlobalOptOutAuthorityStale("public authority is unavailable")
        try:
            first = self._public_authority().normalized()
            second = self._public_authority().normalized()
        except GlobalOptOutError:
            raise
        except Exception as exc:
            raise GlobalOptOutAuthorityStale("public authority is unavailable") from exc
        if first != second or (expected is not None and first != expected.normalized()):
            raise GlobalOptOutAuthorityStale("public authority changed during resolution")
        now = _timestamp(self._clock(), "clock")
        if first.tenant_id != self.tenant_id or first.revoked or first.valid_until <= now:
            raise GlobalOptOutAuthorityStale("public authority is stale")
        return first

    def create_configuration(
        self,
        application_ref: str,
        *,
        locale: str,
        mobile_ui: Mapping[str, Any],
        email_ui: Mapping[str, Any],
        supported_devices: Sequence[str],
        supported_services: Sequence[str],
        expires_at: float | None,
        expected_revision: Literal[0],
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require_enabled()
        actor = self._actor_sha256()
        if expected_revision != 0:
            raise GlobalOptOutConflict("new configuration expected_revision must be zero")
        authority = self._resolve_application(application_ref)
        key = _idempotency(idempotency_key)
        normalized = {
            "locale": _locale(locale),
            "mobile_ui": _ui(mobile_ui, "mobile_ui"),
            "email_ui": _ui(email_ui, "email_ui"),
            "supported_devices": _choices(supported_devices, "supported_devices", _DEVICES),
            "supported_services": _choices(supported_services, "supported_services", _SERVICES),
            "expires_at": (
                None if expires_at is None else _timestamp(expires_at, "expires_at")
            ),
        }
        now = _timestamp(self._clock(), "clock")
        if normalized["expires_at"] is not None and normalized["expires_at"] <= now:
            raise GlobalOptOutValidationError("expires_at must be in the future")
        configuration_id = _configuration_id(self.tenant_id, authority.application_ref)
        request_sha = _sha256(
            {
                "schema": "lightwork.global-opt-out-config-create.v1",
                "application_authority_sha256": authority.authority_sha256,
                **normalized,
            }
        )
        existing = self._call("get", configuration_id)
        if existing is not None:
            _verify_record(existing)
            if _same(existing.get("create_idempotency_sha256"), _text_sha256(key)) and _same(
                existing.get("create_request_sha256"), request_sha
            ):
                return self._configuration_view(existing)
            raise GlobalOptOutConflict("configuration already exists")
        record: dict[str, Any] = {
            "id": configuration_id,
            "schema": CONFIG_SCHEMA,
            "record_kind": "configuration",
            "tenant_sha256": _text_sha256(self.tenant_id),
            "owner_principal_sha256": actor,
            "application_ref": authority.application_ref,
            "application_binding": _binding(authority),
            "configuration_version": 1,
            "state": "draft",
            **normalized,
            "configuration_sha256": "",
            "create_idempotency_sha256": _text_sha256(key),
            "create_request_sha256": request_sha,
            "retained_until": now + self.limits.retention_seconds,
            "history": [],
        }
        record["configuration_sha256"] = self._configuration_digest(record)
        _append_history(record, "created", actor, now)
        record["integrity_sha256"] = _integrity(record)
        try:
            saved = self._call(
                "create",
                record,
                action="create_configuration",
                actor=actor,
                max_records=self.limits.max_records,
            )
        except Exception:
            existing = self._call("get", configuration_id)
            if existing is not None:
                _verify_record(existing)
                if _same(existing.get("create_idempotency_sha256"), _text_sha256(key)) and _same(
                    existing.get("create_request_sha256"), request_sha
                ):
                    return self._configuration_view(existing)
            raise
        return self._configuration_view(saved)

    @staticmethod
    def _configuration_digest(record: Mapping[str, Any]) -> str:
        return _sha256(
            {
                "schema": CONFIG_SCHEMA,
                "application_ref": record.get("application_ref"),
                "application_binding": record.get("application_binding"),
                "configuration_version": record.get("configuration_version"),
                "locale": record.get("locale"),
                "mobile_ui": record.get("mobile_ui"),
                "email_ui": record.get("email_ui"),
                "supported_devices": record.get("supported_devices"),
                "supported_services": record.get("supported_services"),
                "expires_at": record.get("expires_at"),
            }
        )

    def update_configuration(
        self,
        configuration_id: str,
        *,
        locale: str,
        mobile_ui: Mapping[str, Any],
        email_ui: Mapping[str, Any],
        supported_devices: Sequence[str],
        supported_services: Sequence[str],
        expires_at: float | None,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require_enabled()
        actor = self._actor_sha256()
        record_id = _ref(configuration_id, "configuration_id")
        current = self._call("get", record_id)
        if current is None or current.get("record_kind") != "configuration":
            raise GlobalOptOutNotFound("configuration was not found")
        _verify_record(current)
        if current.get("state") in {"revoked", "purged"}:
            raise GlobalOptOutConflict("configuration cannot be updated in its current state")
        authority = self._resolve_application(str(current["application_ref"]))
        key = _idempotency(idempotency_key)
        normalized = {
            "locale": _locale(locale),
            "mobile_ui": _ui(mobile_ui, "mobile_ui"),
            "email_ui": _ui(email_ui, "email_ui"),
            "supported_devices": _choices(supported_devices, "supported_devices", _DEVICES),
            "supported_services": _choices(supported_services, "supported_services", _SERVICES),
            "expires_at": (
                None if expires_at is None else _timestamp(expires_at, "expires_at")
            ),
        }
        now = _timestamp(self._clock(), "clock")
        if normalized["expires_at"] is not None and normalized["expires_at"] <= now:
            raise GlobalOptOutValidationError("expires_at must be in the future")
        request_sha = _sha256(
            {
                "schema": "lightwork.global-opt-out-config-update.v1",
                "configuration_id": record_id,
                "expected_revision": expected_revision,
                "application_authority_sha256": authority.authority_sha256,
                **normalized,
            }
        )
        receipt = current.get("last_operation")
        if isinstance(receipt, Mapping) and _same(
            receipt.get("idempotency_sha256"), _text_sha256(key)
        ):
            if _same(receipt.get("request_sha256"), request_sha):
                return self._configuration_view(current)
            raise GlobalOptOutConflict("idempotency key was reused with different input")

        def mutate(record: dict[str, Any]) -> None:
            if record.get("state") in {"revoked", "purged"}:
                raise GlobalOptOutConflict("configuration cannot be updated in its current state")
            record.update(normalized)
            record["application_binding"] = _binding(authority)
            record["configuration_version"] = int(record["configuration_version"]) + 1
            record["configuration_sha256"] = self._configuration_digest(record)
            record["last_operation"] = {
                "action": "updated",
                "idempotency_sha256": _text_sha256(key),
                "request_sha256": request_sha,
            }
            _append_history(record, "updated", actor, now)
            record["integrity_sha256"] = _integrity(record)

        saved = self._call(
            "update",
            record_id,
            mutate,
            expected_revision=_integer(expected_revision, "expected_revision", 1, 2**31 - 1),
            action="update_configuration",
            actor=actor,
        )
        if saved is None:
            raise GlobalOptOutNotFound("configuration was not found")
        return self._configuration_view(saved)

    def _state_change(
        self,
        configuration_id: str,
        *,
        target: Literal["active", "revoked"],
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require_enabled()
        actor = self._actor_sha256()
        record_id = _ref(configuration_id, "configuration_id")
        current = self._call("get", record_id)
        if current is None or current.get("record_kind") != "configuration":
            raise GlobalOptOutNotFound("configuration was not found")
        _verify_record(current)
        key = _idempotency(idempotency_key)
        if target == "active":
            authority = self._resolve_application(str(current["application_ref"]))
            if current.get("application_binding") != _binding(authority):
                raise GlobalOptOutAuthorityStale(
                    "configuration must be updated against the current authority"
                )
        request_sha = _sha256(
            {
                "schema": "lightwork.global-opt-out-state-change.v1",
                "configuration_id": record_id,
                "expected_revision": expected_revision,
                "target": target,
            }
        )
        receipt = current.get("last_operation")
        if isinstance(receipt, Mapping) and _same(
            receipt.get("idempotency_sha256"), _text_sha256(key)
        ):
            if _same(receipt.get("request_sha256"), request_sha):
                return self._configuration_view(current)
            raise GlobalOptOutConflict("idempotency key was reused with different input")
        now = _timestamp(self._clock(), "clock")

        def mutate(record: dict[str, Any]) -> None:
            state = record.get("state")
            if target == "active" and state not in {"draft", "active"}:
                raise GlobalOptOutConflict("configuration cannot be activated")
            if target == "revoked" and state == "purged":
                raise GlobalOptOutConflict("configuration is already purged")
            record["state"] = target
            if target == "revoked":
                record["retained_until"] = now + self.limits.retention_seconds
            record["last_operation"] = {
                "action": target,
                "idempotency_sha256": _text_sha256(key),
                "request_sha256": request_sha,
            }
            _append_history(record, target, actor, now)
            record["integrity_sha256"] = _integrity(record)

        saved = self._call(
            "update",
            record_id,
            mutate,
            expected_revision=_integer(expected_revision, "expected_revision", 1, 2**31 - 1),
            action=f"{target}_configuration",
            actor=actor,
        )
        if saved is None:
            raise GlobalOptOutNotFound("configuration was not found")
        return self._configuration_view(saved)

    def activate_configuration(
        self, configuration_id: str, *, expected_revision: int, idempotency_key: str
    ) -> dict[str, Any]:
        return self._state_change(
            configuration_id,
            target="active",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def revoke_configuration(
        self, configuration_id: str, *, expected_revision: int, idempotency_key: str
    ) -> dict[str, Any]:
        return self._state_change(
            configuration_id,
            target="revoked",
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def get_configuration(self, configuration_id: str) -> dict[str, Any]:
        self._require_enabled()
        self._actor_sha256()
        record = self._call("get", _ref(configuration_id, "configuration_id"))
        if record is None or record.get("record_kind") != "configuration":
            raise GlobalOptOutNotFound("configuration was not found")
        _verify_record(record)
        return self._configuration_view(record)

    def list_configurations(self, *, limit: int = 100) -> dict[str, Any]:
        self._require_enabled()
        self._actor_sha256()
        bounded = _integer(limit, "limit", 1, 500)
        records = self._call("list", limit=min(self.limits.max_records, 10_001))
        values = [
            self._configuration_view(record)
            for record in records
            if record.get("record_kind") == "configuration"
        ]
        values.sort(key=lambda item: (item["application_ref"], item["configuration_id"]))
        return {"items": values[:bounded], "truncated": len(values) > bounded}

    def configuration_history(self, configuration_id: str) -> dict[str, Any]:
        value = self.get_configuration(configuration_id)
        return {
            "configuration_id": value["configuration_id"],
            "configuration_version": value["configuration_version"],
            "revision": value["revision"],
            "history": value["history"],
        }

    @staticmethod
    def _configuration_view(record: Mapping[str, Any]) -> dict[str, Any]:
        _verify_record(record)
        return {
            "schema": CONFIG_SCHEMA,
            "configuration_id": record["id"],
            "application_ref": record["application_ref"],
            "application_binding": dict(record["application_binding"]),
            "configuration_version": record["configuration_version"],
            "configuration_sha256": record["configuration_sha256"],
            "locale": record["locale"],
            "mobile_ui": (
                dict(record["mobile_ui"])
                if isinstance(record.get("mobile_ui"), Mapping)
                else None
            ),
            "email_ui": (
                dict(record["email_ui"])
                if isinstance(record.get("email_ui"), Mapping)
                else None
            ),
            "supported_devices": list(record["supported_devices"]),
            "supported_services": list(record["supported_services"]),
            "expires_at": record["expires_at"],
            "state": record["state"],
            "retained_until": record["retained_until"],
            "revision": record["revision"],
            "created_at": record["created_at"],
            "updated_at": record["updated_at"],
            "history": [dict(item) for item in record["history"]],
            "integrity_sha256": record["integrity_sha256"],
        }

    def get_public_configuration(
        self, expected_authority: GlobalOptOutPublicAuthority | None = None
    ) -> dict[str, Any]:
        self._require_enabled()
        authority = self._resolve_public(expected_authority)
        record_id = _configuration_id(self.tenant_id, authority.application_ref)
        record = self._call("get", record_id)
        if record is None or record.get("record_kind") != "configuration":
            raise GlobalOptOutNotConfigured("Global Opt-Out is not configured")
        _verify_record(record)
        now = _timestamp(self._clock(), "clock")
        if record.get("state") != "active" or (
            record.get("expires_at") is not None and float(record["expires_at"]) <= now
        ):
            raise GlobalOptOutNotConfigured("Global Opt-Out is not configured")
        if record.get("application_binding") != _public_binding(authority):
            raise GlobalOptOutAuthorityStale("Global Opt-Out application authority changed")
        response = {
            "schema": PUBLIC_CONFIG_SCHEMA,
            "configuration_id": record["id"],
            "configuration_version": record["configuration_version"],
            "configuration_sha256": record["configuration_sha256"],
            "locale": record["locale"],
            "mobile_ui": dict(record["mobile_ui"]),
            "email_ui": dict(record["email_ui"]),
            "supported_devices": list(record["supported_devices"]),
            "supported_services": list(record["supported_services"]),
            "authority_revision": authority.public_client_revision,
            "authority_sha256": authority.authority_sha256,
            "expires_at": record["expires_at"],
        }
        return {**response, "response_sha256": _sha256(response)}

    def submit(
        self,
        expected_authority: GlobalOptOutPublicAuthority,
        *,
        configuration_version: int,
        configuration_sha256: str,
        authority_revision: int,
        authority_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._require_enabled()
        authority = self._resolve_public(expected_authority)
        public_config = self.get_public_configuration(authority)
        if (
            configuration_version != public_config["configuration_version"]
            or not _same(configuration_sha256, public_config["configuration_sha256"])
            or authority_revision != authority.public_client_revision
            or not _same(authority_sha256, authority.authority_sha256)
        ):
            raise GlobalOptOutAuthorityStale("Global Opt-Out submission authority changed")
        key = _idempotency(idempotency_key)
        submission_id = _submission_id(self.tenant_id, authority, key)
        request_sha = _sha256(
            {
                "schema": "lightwork.global-opt-out-submit.v1",
                "authority_sha256": authority.authority_sha256,
                "configuration_id": public_config["configuration_id"],
                "configuration_version": configuration_version,
                "configuration_sha256": configuration_sha256,
            }
        )
        record = self._call("get", submission_id)
        if record is not None:
            _verify_record(record)
            if not _same(record.get("idempotency_sha256"), _text_sha256(key)) or not _same(
                record.get("request_sha256"), request_sha
            ):
                raise GlobalOptOutConflict("idempotency key was reused with different input")
            if record.get("state") == "submitted":
                return self._submission_view(record)
            if record.get("state") == "purged":
                raise GlobalOptOutConflict("submission retention has ended")
        else:
            now = _timestamp(self._clock(), "clock")
            record = {
                "id": submission_id,
                "schema": SUBMISSION_SCHEMA,
                "record_kind": "submission",
                "tenant_sha256": _text_sha256(self.tenant_id),
                "application_ref": authority.application_ref,
                "profile_sha256": authority.profile_sha256,
                "profile_binding_sha256": authority.profile_binding_sha256,
                "public_authority_sha256": authority.authority_sha256,
                "intake_authority_sha256": authority.intake_authority_sha256,
                "configuration_id": public_config["configuration_id"],
                "configuration_version": configuration_version,
                "configuration_sha256": configuration_sha256,
                "idempotency_sha256": _text_sha256(key),
                "request_sha256": request_sha,
                "state": "creating",
                "case_reference_sha256": None,
                "dsar_result_sha256": None,
                "attempt_count": 0,
                "last_error_code": None,
                "expires_at": now + self.limits.submission_ttl_seconds,
                "retained_until": now + self.limits.retention_seconds,
                "history": [],
            }
            _append_history(record, "reserved", authority.profile_sha256, now)
            record["integrity_sha256"] = _integrity(record)
            try:
                record = self._call(
                    "create",
                    record,
                    action="reserve_submission",
                    actor=authority.profile_sha256,
                    max_records=self.limits.max_records,
                )
            except Exception:
                existing = self._call("get", submission_id)
                if existing is None:
                    raise
                _verify_record(existing)
                record = existing
        return self._complete_submission(record, authority)

    def _complete_submission(
        self, record: Mapping[str, Any], authority: GlobalOptOutPublicAuthority
    ) -> dict[str, Any]:
        if self._intake_authority is None or self._privacy_rights_submitter is None:
            raise GlobalOptOutDSARUnavailable("privacy-rights intake is unavailable")
        if record.get("state") == "creating":
            # A reservation is only good for submission_ttl_seconds; a missing
            # or malformed expiry is refused as well.
            expires_at = record.get("expires_at")
            if not isinstance(expires_at, (int, float)) or expires_at <= _timestamp(
                self._clock(), "clock"
            ):
                raise GlobalOptOutConflict("submission reservation has expired")
        current = self._resolve_public(authority)
        if not _same(current.authority_sha256, record.get("public_authority_sha256")):
            raise GlobalOptOutAuthorityStale("public authority changed before DSAR creation")
        try:
            intake_authority = self._intake_authority()
            actual_intake_sha = authority_material_sha256(intake_authority)
        except GlobalOptOutError:
            raise
        except Exception as exc:
            raise GlobalOptOutDSARUnavailable("privacy-rights intake is unavailable") from exc
        if not _same(actual_intake_sha, current.intake_authority_sha256) or not _same(
            actual_intake_sha, record.get("intake_authority_sha256")
        ):
            raise GlobalOptOutAuthorityStale("privacy-rights intake authority changed")
        case_idempotency = f"global-opt-out-{str(record['id']).split('-', 1)[-1]}"
        try:
            result = self._privacy_rights_submitter(
                intake_authority,
                ("opt_out",),
                0,
                case_idempotency,
            )
            if not isinstance(result, GlobalOptOutDSARResult):
                raise GlobalOptOutDSARUnavailable("privacy-rights intake result is invalid")
            normalized = result.normalized()
        except (GlobalOptOutAuthorityStale, GlobalOptOutDSARUnavailable):
            raise
        except Exception as exc:
            raise GlobalOptOutDSARUnavailable("privacy-rights intake is unavailable") from exc
        now = _timestamp(self._clock(), "clock")
        expected_revision = int(record["revision"])

        def mutate(current_record: dict[str, Any]) -> None:
            if current_record.get("state") == "submitted":
                return
            if current_record.get("state") != "creating":
                raise GlobalOptOutConflict("submission cannot be recovered")
            current_record["state"] = "submitted"
            current_record["case_reference_sha256"] = _text_sha256(normalized.case_id)
            current_record["dsar_result_sha256"] = normalized.result_sha256
            current_record["attempt_count"] = int(current_record.get("attempt_count", 0)) + 1
            current_record["last_error_code"] = None
            current_record["submitted_at"] = now
            current_record["retained_until"] = now + self.limits.retention_seconds
            _append_history(current_record, "submitted", authority.profile_sha256, now)
            current_record["integrity_sha256"] = _integrity(current_record)

        try:
            saved = self._call(
                "update",
                str(record["id"]),
                mutate,
                expected_revision=expected_revision,
                action="submit_opt_out_dsar",
                actor=authority.profile_sha256,
            )
        except Exception:
            replay = self._call("get", str(record["id"]))
            if replay is not None:
                _verify_record(replay)
                if replay.get("state") == "submitted" and _same(
                    replay.get("dsar_result_sha256"), normalized.result_sha256
                ):
                    return self._submission_view(replay)
            raise
        if saved is None:
            raise GlobalOptOutConflict("submission disappeared during DSAR creation")
        return self._submission_view(saved)

    def recover_submission(
        self,
        expected_authority: GlobalOptOutPublicAuthority,
        submission_id: str,
    ) -> dict[str, Any]:
        """Resume a reserved submission after a process or intake interruption."""

        self._require_enabled()
        authority = self._resolve_public(expected_authority)
        record = self._call("get", _ref(submission_id, "submission_id"))
        if record is None or record.get("record_kind") != "submission":
            raise GlobalOptOutNotFound("submission was not found")
        _verify_record(record)
        if not _same(record.get("profile_sha256"), authority.profile_sha256) or not _same(
            record.get("profile_binding_sha256"), authority.profile_binding_sha256
        ):
            raise GlobalOptOutNotFound("submission was not found")
        if record.get("state") == "submitted":
            return self._submission_view(record)
        if record.get("state") != "creating":
            raise GlobalOptOutConflict("submission cannot be recovered")
        return self._complete_submission(record, authority)

    @staticmethod
    def _submission_view(record: Mapping[str, Any]) -> dict[str, Any]:
        _verify_record(record)
        response = {
            "schema": PUBLIC_SUBMISSION_SCHEMA,
            "submission_id": record["id"],
            "state": record["state"],
            "configuration_id": record["configuration_id"],
            "configuration_version": record["configuration_version"],
            "case_reference_sha256": record["case_reference_sha256"],
            "dsar_result_sha256": record["dsar_result_sha256"],
            "submitted_at": record.get("submitted_at"),
            "retained_until": record["retained_until"],
            "revision": record["revision"],
        }
        return {**response, "response_sha256": _sha256(response)}

    def verify_integrity(self, *, limit: int = 10_000) -> dict[str, Any]:
        self._require_enabled()
        self._actor_sha256()
        bounded = _integer(limit, "limit", 1, 10_000)
        records = self._call("list", limit=bounded + 1)
        checked = 0
        for record in records[:bounded]:
            _verify_record(record)
            checked += 1
        return {
            "ok": True,
            "checked": checked,
            "truncated": len(records) > bounded,
            "backend": self.backend_kind,
        }

    def retry_pending_audit(self, *, limit: int = 100) -> dict[str, Any]:
        self._require_enabled()
        self._actor_sha256()
        if self._maintenance() is not True:
            raise GlobalOptOutPermissionDenied("maintenance authority is required")
        cleared = self._call("retry_pending", limit=_integer(limit, "limit", 1, 1_000))
        return {"cleared": cleared, "signed_audit_outbox": True}

    def purge_retained(self, *, limit: int = 100) -> dict[str, Any]:
        self._require_enabled()
        actor = self._actor_sha256()
        if self._maintenance() is not True:
            raise GlobalOptOutPermissionDenied("maintenance authority is required")
        bounded = _integer(limit, "limit", 1, 1_000)
        records = self._call("list", limit=min(self.limits.max_records, 10_001))
        now = _timestamp(self._clock(), "clock")
        purged = 0
        for current in records:
            if purged >= bounded or float(current.get("retained_until", math.inf)) > now:
                continue
            if current.get("state") == "purged":
                continue
            if current.get("record_kind") == "configuration" and current.get("state") != "revoked":
                continue
            if current.get("record_kind") == "submission" and current.get("state") not in {
                "creating",
                "submitted",
            }:
                continue

            def mutate(record: dict[str, Any]) -> None:
                record["state"] = "purged"
                if record.get("record_kind") == "configuration":
                    record["mobile_ui"] = None
                    record["email_ui"] = None
                    record["supported_devices"] = []
                    record["supported_services"] = []
                    record["configuration_sha256"] = None
                else:
                    record["case_reference_sha256"] = None
                    record["dsar_result_sha256"] = None
                _append_history(record, "purged", actor, now)
                record["integrity_sha256"] = _integrity(record)

            saved = self._call(
                "update",
                str(current["id"]),
                mutate,
                expected_revision=int(current["revision"]),
                action="purge_retained",
                actor=actor,
            )
            if saved is not None:
                purged += 1
        return {"purged": purged, "evaluated_at": now, "truncated": len(records) > 10_000}

    @staticmethod
    def product_boundaries() -> dict[str, bool]:
        return {
            "raw_case_identifiers_persisted": False,
            "raw_dsar_results_persisted": False,
            "raw_origins_or_service_ids_persisted": False,
            "device_tokens_persisted": False,
            "live_device_delivery_proven": False,
            "live_customer_acceptance_proven": False,
            "privacy_rights_intake_required": True,
            "signed_digest_audit": True,
        }


__all__ = [
    "ApplicationAuthorityResolver",
    "CONFIG_SCHEMA",
    "GlobalOptOutApplicationAuthority",
    "GlobalOptOutAuthorityStale",
    "GlobalOptOutConflict",
    "GlobalOptOutDSARResult",
    "GlobalOptOutDSARUnavailable",
    "GlobalOptOutDisabled",
    "GlobalOptOutError",
    "GlobalOptOutIntegrityError",
    "GlobalOptOutLimits",
    "GlobalOptOutNotConfigured",
    "GlobalOptOutNotFound",
    "GlobalOptOutPermissionDenied",
    "GlobalOptOutPublicAuthority",
    "GlobalOptOutStore",
    "GlobalOptOutValidationError",
    "PUBLIC_CONFIG_SCHEMA",
    "PUBLIC_SUBMISSION_SCHEMA",
    "SCHEMA_VERSION",
    "SUBMISSION_SCHEMA",
    "authority_material_sha256",
    "global_opt_out_enabled",
    "issue_application_authority",
    "issue_public_authority",
    "load_global_opt_out_limits",
    "require_global_opt_out_enabled",
]
