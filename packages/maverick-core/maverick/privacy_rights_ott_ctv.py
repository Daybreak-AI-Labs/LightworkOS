"""Digest-bound OTT/CTV intake for the existing privacy-rights authority.

This module is a local control-plane bridge.  It admits an already enrolled
service client and linked device profile, requires a current Consumer Trust
Center ``rights_cases`` grant, and then opens/plans the existing provider-
neutral rights orchestration case.  It never receives a device identifier,
OIDC token/subject, consumer selector, provider credential, or retrieved
payload.

The capability is closed unless all consent, identity, Trust Center, privacy
automation, rights-orchestration, and OTT/CTV bridge gates are explicitly on.
It performs no provider network operation and makes no native-SDK, live-
provider, response-delivery, or estate-completeness claim.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .consent_identity_federation import (
    MAX_PAIRING_TTL_SECONDS,
    ConsentIdentityEvidence,
    ConsentPairingContext,
)
from .consumer_trust_center import (
    ConsumerTrustCenterSourceAdapter,
    TrustCenterCapabilityGrant,
    TrustCenterContext,
)
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .privacy_rights_orchestration import CALLBACK_PHASES
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
STATUS_SCHEMA = "lightwork.privacy-rights-ott-ctv-status.v1"
AUTHORITY_SCHEMA = "lightwork.privacy-rights-ott-ctv-authority.v1"
NETWORK_IO = False
PROVIDER_WRITES = False
NATIVE_SDK_IMPLEMENTED = False
ESTATE_COMPLETENESS_CLAIMED = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False

_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_KEY_REF_RE = re.compile(r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 256 * 1024
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600
_OTT_CTV_PLATFORMS = frozenset({"android", "fireos", "roku", "tizen", "tvos", "webos"})
_RIGHTS = {"access": "access", "deletion": "erasure"}
_RIGHT_PHASES = {
    "access": ("discover", "retrieve", "redact"),
    "deletion": ("discover", "delete", "verify_delete"),
}


class OTTCTVPrivacyRightsError(RuntimeError):
    """Base error for the OTT/CTV privacy-rights bridge."""


class OTTCTVPrivacyRightsConfigError(OTTCTVPrivacyRightsError):
    """Configuration or injected signing authority is unavailable."""


class OTTCTVPrivacyRightsValidationError(OTTCTVPrivacyRightsError, ValueError):
    """Input is outside the closed bridge contract."""


class OTTCTVPrivacyRightsConflict(OTTCTVPrivacyRightsError):
    """Authority, idempotency, CAS, or orchestration state drifted."""


class OTTCTVPrivacyRightsNotFound(OTTCTVPrivacyRightsError):
    """A tenant-bound request does not exist or is deliberately undisclosed."""


class OTTCTVPrivacyRightsIntegrityError(OTTCTVPrivacyRightsError):
    """Persisted or signed bridge evidence failed integrity."""


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Require every parent authority and the narrow bridge gate."""

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
    privacy = config.get("privacy_automation")
    if not isinstance(consent, Mapping) or not isinstance(privacy, Mapping):
        return False
    required_consent = ("publishing", "public_api", "identity", "trust_center")
    required_privacy = ("rights_orchestration", "ott_ctv_rights")
    return (
        consent.get("enable") is True
        and privacy.get("enable") is True
        and all(
            isinstance(consent.get(name), Mapping)
            and consent[name].get("enable") is True
            for name in required_consent
        )
        and all(
            isinstance(privacy.get(name), Mapping)
            and privacy[name].get("enable") is True
            for name in required_privacy
        )
    )


def require_enabled() -> None:
    if not enabled():
        raise OTTCTVPrivacyRightsConfigError(
            "OTT/CTV privacy rights require consent publishing, public API, identity, "
            "Trust Center, privacy automation, rights orchestration, and ott_ctv_rights"
        )


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
        raise OTTCTVPrivacyRightsValidationError("bridge metadata must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise OTTCTVPrivacyRightsValidationError("bridge metadata exceeds its byte bound")
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


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except (TypeError, ValueError) as exc:
        raise OTTCTVPrivacyRightsValidationError("tenant authority is invalid") from exc


def _ref(value: object, label: str, pattern: re.Pattern[str] = _REF_RE) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise OTTCTVPrivacyRightsValidationError(f"{label} is not a closed reference")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise OTTCTVPrivacyRightsValidationError(f"{label} is not a SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise OTTCTVPrivacyRightsValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OTTCTVPrivacyRightsValidationError(f"{label} is not a finite timestamp")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0 < normalized < 100_000_000_000.0:
        raise OTTCTVPrivacyRightsValidationError(f"{label} is not a finite timestamp")
    return normalized


def _default_signing_key_resolver(tenant_id: str, key_ref: str) -> bytes:
    del tenant_id
    if key_ref != "env:MAVERICK_PRIVACY_RIGHTS_OTT_CTV_SIGNING_KEY":
        raise OTTCTVPrivacyRightsConfigError("OTT/CTV signing key reference is unavailable")
    value = os.environ.get("MAVERICK_PRIVACY_RIGHTS_OTT_CTV_SIGNING_KEY")
    if value is None or len(value.encode("utf-8")) < 32:
        raise OTTCTVPrivacyRightsConfigError(
            "MAVERICK_PRIVACY_RIGHTS_OTT_CTV_SIGNING_KEY is absent or too short"
        )
    return value.encode("utf-8")


@dataclass(frozen=True)
class OTTCTVServiceAuthority:
    """Digest-only snapshot of the exact admitted device/account authority."""

    tenant_id: str
    platform: str
    service_client_sha256: str
    target_bundle_sha256: str
    property_sha256: str
    profile_sha256: str
    account_binding_sha256: str
    pairing_context_sha256: str
    client_credential_sha256: str
    client_record_sha256: str
    client_revision: int
    profile_credential_sha256: str
    profile_binding_sha256: str
    profile_revision: int
    identity_evidence_sha256: str
    identity_evidence_revision: int
    identity_evidence_valid_until: float
    publication_sha256: str
    publication_bundle_sha256: str
    configuration_sha256: str
    policy_sha256: str
    policy_version: int
    trust_context_revision: int
    trust_context_sha256: str
    capability_grant_sha256: str
    valid_until: float

    def normalized(self) -> OTTCTVServiceAuthority:
        tenant = _tenant(self.tenant_id)
        if self.platform not in _OTT_CTV_PLATFORMS:
            raise OTTCTVPrivacyRightsValidationError("platform is not an OTT/CTV platform")
        for name in (
            "service_client_sha256",
            "target_bundle_sha256",
            "property_sha256",
            "profile_sha256",
            "account_binding_sha256",
            "pairing_context_sha256",
            "client_credential_sha256",
            "client_record_sha256",
            "profile_credential_sha256",
            "profile_binding_sha256",
            "identity_evidence_sha256",
            "publication_sha256",
            "publication_bundle_sha256",
            "configuration_sha256",
            "policy_sha256",
            "trust_context_sha256",
            "capability_grant_sha256",
        ):
            _digest(getattr(self, name), name)
        _integer(self.client_revision, "client_revision", 1, 2**31 - 1)
        _integer(self.profile_revision, "profile_revision", 1, 2**31 - 1)
        _integer(
            self.identity_evidence_revision,
            "identity_evidence_revision",
            1,
            2**31 - 1,
        )
        _integer(self.policy_version, "policy_version", 1, 2**31 - 1)
        _integer(self.trust_context_revision, "trust_context_revision", 1, 2**31 - 1)
        _timestamp(self.valid_until, "valid_until")
        _timestamp(
            self.identity_evidence_valid_until,
            "identity_evidence_valid_until",
        )
        if tenant != self.tenant_id:
            raise OTTCTVPrivacyRightsValidationError("tenant authority is not canonical")
        return self

    @property
    def authority_sha256(self) -> str:
        return _sha256({"schema": AUTHORITY_SCHEMA, **asdict(self.normalized())})


@dataclass(frozen=True)
class SignedOTTCTVRequestStatus:
    payload: Mapping[str, object]
    signing_key_ref: str
    signature: str
    evidence_sha256: str


def ott_ctv_trust_context_ref(pairing: ConsentPairingContext) -> str:
    """Derive the selector-free operator context reference for one device capability."""

    context = pairing.normalized()
    digest = _sha256(
        {
            "schema": "lightwork.privacy-rights-ott-ctv-context-ref.v1",
            "tenant_id": context.tenant_id,
            "client_credential_sha256": context.client_credential_sha256,
            "profile_credential_sha256": context.profile_credential_sha256,
            "channel_binding_sha256": context.channel_binding_sha256,
        }
    )
    return f"TCA-OTT-{digest[:32]}"


def build_service_authority(  # noqa: PLR0913 - all arguments are independent authority pins
    pairing: ConsentPairingContext,
    trust_context: TrustCenterContext,
    *,
    service_client_id: str,
    target_bundle_id: str,
    target_platform: str,
    account_binding_sha256: str,
    identity_evidence: ConsentIdentityEvidence,
    client_expires_at: float | None,
    now: float,
) -> OTTCTVServiceAuthority:
    """Join current pairing/public-client and Trust Center authority snapshots."""

    instant = _timestamp(now, "current time")
    context = pairing.normalized()
    service_client = _ref(service_client_id, "service_client_id")
    target_bundle = _ref(target_bundle_id, "target_bundle_id")
    if target_platform not in _OTT_CTV_PLATFORMS:
        raise OTTCTVPrivacyRightsValidationError("platform is not an OTT/CTV platform")
    if context.channel_kind != "service-client":
        raise OTTCTVPrivacyRightsConflict("only an enrolled service client is admitted")
    if not isinstance(identity_evidence, ConsentIdentityEvidence):
        raise OTTCTVPrivacyRightsConflict("fresh identity evidence is unavailable")
    identity_body = asdict(identity_evidence)
    identity_sha = identity_body.pop("evidence_sha256", None)
    if (
        identity_evidence.schema != "lightwork.consent.identity-evidence.v1"
        or identity_evidence.tenant_id != context.tenant_id
        or not _same(identity_evidence.target_fingerprint, context.fingerprint)
        or not _same(identity_sha, _sha256(identity_body))
        or identity_evidence.valid_until <= instant
    ):
        raise OTTCTVPrivacyRightsConflict("fresh identity evidence changed")
    expected_channel = _sha256(
        {
            "client_kind": "service",
            "browser_origin": None,
            "service_client_id": service_client,
            "target_origin": None,
            "target_bundle_id": target_bundle,
            "target_platform": target_platform,
        }
    )
    if not _same(context.channel_binding_sha256, expected_channel):
        raise OTTCTVPrivacyRightsConflict("service-client channel authority changed")
    if not isinstance(trust_context, TrustCenterContext):
        raise OTTCTVPrivacyRightsConflict("Trust Center authority is unavailable")
    if (
        trust_context.revoked
        or trust_context.tenant_id != context.tenant_id
        or trust_context.property_id != context.property_id
        or trust_context.profile_id != context.profile_id
        or trust_context.server_origin is not None
        or trust_context.server_bundle_id != target_bundle
        or trust_context.server_platform != target_platform
        or trust_context.valid_until <= instant
        or trust_context.retained_until <= instant
        or not _same(
            trust_context.context_sha256,
            ConsumerTrustCenterSourceAdapter.context_sha256(trust_context),
        )
    ):
        raise OTTCTVPrivacyRightsConflict("Trust Center device authority changed")
    rights_grants = tuple(
        grant
        for grant in trust_context.capability_grants
        if isinstance(grant, TrustCenterCapabilityGrant) and grant.capability == "rights_cases"
    )
    if len(rights_grants) != 1:
        raise OTTCTVPrivacyRightsConflict("an active rights_cases capability is required")
    grant = rights_grants[0]
    expected_grant = ConsumerTrustCenterSourceAdapter.capability_grant_sha256(grant)
    if (
        grant.revoked
        or grant.valid_until <= instant
        or grant.property_id != context.property_id
        or not _same(grant.tenant_sha256, _text_sha256(context.tenant_id))
        or not _same(grant.profile_sha256, _text_sha256(context.profile_id))
        or not _same(grant.grant_sha256, expected_grant)
    ):
        raise OTTCTVPrivacyRightsConflict("rights_cases capability changed")
    valid_until = min(
        trust_context.valid_until,
        grant.valid_until,
        identity_evidence.valid_until,
    )
    if client_expires_at is not None:
        valid_until = min(valid_until, _timestamp(client_expires_at, "client_expires_at"))
    if valid_until <= instant:
        raise OTTCTVPrivacyRightsConflict("service authority expired")
    return OTTCTVServiceAuthority(
        tenant_id=context.tenant_id,
        platform=target_platform,
        service_client_sha256=_text_sha256(service_client),
        target_bundle_sha256=_text_sha256(target_bundle),
        property_sha256=_text_sha256(context.property_id),
        profile_sha256=_text_sha256(context.profile_id),
        account_binding_sha256=_digest(account_binding_sha256, "account_binding_sha256"),
        pairing_context_sha256=context.fingerprint,
        client_credential_sha256=context.client_credential_sha256,
        client_record_sha256=context.client_record_sha256,
        client_revision=context.client_revision,
        profile_credential_sha256=context.profile_credential_sha256,
        profile_binding_sha256=context.profile_binding_sha256,
        profile_revision=context.profile_revision,
        identity_evidence_sha256=identity_evidence.evidence_sha256,
        identity_evidence_revision=identity_evidence.pairing_revision,
        identity_evidence_valid_until=identity_evidence.valid_until,
        publication_sha256=context.publication_sha256,
        publication_bundle_sha256=context.bundle_sha256,
        configuration_sha256=context.configuration_sha256,
        policy_sha256=context.policy_sha256,
        policy_version=context.policy_version,
        trust_context_revision=trust_context.revision,
        trust_context_sha256=trust_context.context_sha256,
        capability_grant_sha256=grant.grant_sha256,
        valid_until=valid_until,
    ).normalized()


class OTTCTVPrivacyRightsStore:
    """Recoverable digest-only bridge into ``PrivacyRightsOrchestrationStore``."""

    def __init__(  # noqa: PLR0913 - explicit trust seams are intentional
        self,
        path: str | Path,
        *,
        rights_store: object,
        authority_resolver: Callable[[OTTCTVServiceAuthority], OTTCTVServiceAuthority],
        signing_key_resolver: Callable[[str, str], bytes] = _default_signing_key_resolver,
        signing_key_ref: str = "env:MAVERICK_PRIVACY_RIGHTS_OTT_CTV_SIGNING_KEY",
        retention_seconds: int = 30 * 24 * 3_600,
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        required = (
            "open_case",
            "get_case",
            "set_identity_verification",
            "list_sources",
            "plan_source_tasks",
        )
        if any(not callable(getattr(rights_store, name, None)) for name in required):
            raise OTTCTVPrivacyRightsConfigError("rights orchestration authority is incomplete")
        if not all(
            callable(item)
            for item in (
                authority_resolver,
                signing_key_resolver,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise OTTCTVPrivacyRightsConfigError("bridge authority dependencies are incomplete")
        self.path = Path(path)
        self._rights = rights_store
        self._authority_resolver = authority_resolver
        self._signing_key_resolver = signing_key_resolver
        self._signing_key_ref = _ref(signing_key_ref, "signing_key_ref", _KEY_REF_RE)
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            60,
            _MAX_RETENTION_SECONDS,
        )
        self._maintenance_authorizer = maintenance_authorizer
        self._gate = config_gate
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ott_ctv_rights_requests(
                    tenant_id TEXT NOT NULL,case_id TEXT NOT NULL,state TEXT NOT NULL,
                    revision INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,case_id)
                );
                CREATE TABLE IF NOT EXISTS ott_ctv_rights_operations(
                    tenant_id TEXT NOT NULL,key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,case_id TEXT NOT NULL,
                    created_at REAL NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,key_sha256)
                );
                CREATE TRIGGER IF NOT EXISTS ott_ctv_rights_operations_no_update
                    BEFORE UPDATE ON ott_ctv_rights_operations
                    BEGIN SELECT RAISE(ABORT,'immutable OTT/CTV idempotency'); END;
                """
            )
            connection.execute(
                "DROP TRIGGER IF EXISTS ott_ctv_rights_operations_no_delete"
            )
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, SCHEMA_VERSION):
                raise OTTCTVPrivacyRightsConfigError(
                    f"unsupported OTT/CTV rights schema version {version}"
                )
            connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        ensure_private_file(self.path)

    def _now(self) -> float:
        return _timestamp(self._clock(), "current time")

    def _signing_key(self, tenant_id: str) -> bytes:
        try:
            key = self._signing_key_resolver(tenant_id, self._signing_key_ref)
        except OTTCTVPrivacyRightsError:
            raise
        except Exception as exc:
            raise OTTCTVPrivacyRightsConfigError("status signing key is unavailable") from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise OTTCTVPrivacyRightsConfigError("status signing key is unavailable")
        return key

    def _resolve(self, expected: OTTCTVServiceAuthority, now: float) -> OTTCTVServiceAuthority:
        expected = expected.normalized()
        if expected.valid_until <= now:
            raise OTTCTVPrivacyRightsConflict("service authority expired")
        try:
            first = self._authority_resolver(expected)
            second = self._authority_resolver(expected)
        except OTTCTVPrivacyRightsError:
            raise
        except Exception as exc:
            raise OTTCTVPrivacyRightsConflict("service authority is unavailable") from exc
        if not isinstance(first, OTTCTVServiceAuthority) or not isinstance(
            second, OTTCTVServiceAuthority
        ):
            raise OTTCTVPrivacyRightsConflict("service authority is unavailable")
        first = first.normalized()
        second = second.normalized()
        if (
            first.valid_until <= now
            or second.valid_until <= now
            or not _same(first.authority_sha256, expected.authority_sha256)
            or not _same(second.authority_sha256, expected.authority_sha256)
        ):
            raise OTTCTVPrivacyRightsConflict("service authority changed")
        return second

    @staticmethod
    def _idempotency(value: object) -> tuple[str, str]:
        raw = _ref(value, "idempotency_key")
        return raw, _text_sha256(raw)

    @staticmethod
    def _payload(row: sqlite3.Row) -> dict[str, Any]:
        raw = row["payload_json"]
        if not isinstance(raw, str) or not 1 <= len(raw.encode("utf-8")) <= _MAX_JSON_BYTES:
            raise OTTCTVPrivacyRightsIntegrityError("stored bridge request is invalid")
        try:
            payload = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise OTTCTVPrivacyRightsIntegrityError("stored bridge request is invalid") from exc
        if (
            not isinstance(payload, dict)
            or payload.get("tenant_id") != row["tenant_id"]
            or payload.get("case_id") != row["case_id"]
            or payload.get("state") != row["state"]
            or payload.get("revision") != row["revision"]
            or payload.get("retained_until") != row["retained_until"]
            or not _same(_sha256(payload), row["integrity_sha256"])
        ):
            raise OTTCTVPrivacyRightsIntegrityError("stored bridge request changed")
        return payload

    @staticmethod
    def _authority(payload: Mapping[str, Any]) -> OTTCTVServiceAuthority:
        value = payload.get("authority")
        if not isinstance(value, Mapping):
            raise OTTCTVPrivacyRightsIntegrityError("stored service authority is invalid")
        try:
            authority = OTTCTVServiceAuthority(**dict(value)).normalized()
        except (TypeError, OTTCTVPrivacyRightsError) as exc:
            raise OTTCTVPrivacyRightsIntegrityError(
                "stored service authority is invalid"
            ) from exc
        if not _same(payload.get("authority_sha256"), authority.authority_sha256):
            raise OTTCTVPrivacyRightsIntegrityError("stored service authority changed")
        return authority

    def _operation(
        self,
        tenant_id: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ott_ctv_rights_operations WHERE tenant_id=? AND key_sha256=?",
                (tenant_id, key_sha256),
            ).fetchone()
            if row is None:
                return None
            body = {
                "tenant_id": str(row["tenant_id"]),
                "key_sha256": str(row["key_sha256"]),
                "request_sha256": str(row["request_sha256"]),
                "case_id": str(row["case_id"]),
                "created_at": float(row["created_at"]),
            }
            if not _same(_sha256(body), row["integrity_sha256"]):
                raise OTTCTVPrivacyRightsIntegrityError("stored idempotency binding changed")
            if not _same(body["request_sha256"], request_sha256):
                raise OTTCTVPrivacyRightsConflict("idempotency key is bound to another request")
            request_row = connection.execute(
                "SELECT * FROM ott_ctv_rights_requests WHERE tenant_id=? AND case_id=?",
                (tenant_id, body["case_id"]),
            ).fetchone()
            if request_row is None:
                raise OTTCTVPrivacyRightsIntegrityError("idempotent bridge request is missing")
            return self._payload(request_row)

    def _source_plans(self, tenant_id: str, right: str) -> list[dict[str, object]]:
        required = _RIGHT_PHASES[right]
        try:
            sources = self._rights.list_sources(tenant_id, limit=1_000)
        except Exception as exc:
            raise OTTCTVPrivacyRightsConflict("rights source authority is unavailable") from exc
        plans: list[dict[str, object]] = []
        for source in sorted(sources, key=lambda item: str(getattr(item, "source_id", ""))):
            source_id = _ref(getattr(source, "source_id", None), "source_id")
            capabilities = getattr(source, "capabilities", None)
            if getattr(source, "tenant_id", None) != tenant_id or getattr(
                source, "state", None
            ) != "active" or not isinstance(capabilities, tuple):
                continue
            phases = [phase for phase in required if phase in capabilities]
            if phases:
                plans.append({"source_id": source_id, "phases": phases})
        return plans

    def _reserve(  # noqa: PLR0913 - explicit persistence pins
        self,
        authority: OTTCTVServiceAuthority,
        *,
        right: str,
        request_sha256: str,
        key_sha256: str,
        source_plans: Sequence[Mapping[str, object]],
        now: float,
    ) -> dict[str, Any]:
        tenant = authority.tenant_id
        case_digest = _sha256(
            {
                "schema": "lightwork.privacy-rights-ott-ctv-case-id.v1",
                "tenant_id": tenant,
                "operation_key_sha256": key_sha256,
                "authority_sha256": authority.authority_sha256,
                "right": right,
            }
        )
        case_id = f"CP-OTT-{case_digest[:32]}"
        retained_until = now + self._retention_seconds
        payload: dict[str, Any] = {
            "schema": "lightwork.privacy-rights-ott-ctv-binding.v1",
            "tenant_id": tenant,
            "case_id": case_id,
            "right": right,
            "orchestration_right": _RIGHTS[right],
            "authority": asdict(authority),
            "authority_sha256": authority.authority_sha256,
            "request_sha256": request_sha256,
            "operation_key_sha256": key_sha256,
            "source_plans": [dict(item) for item in source_plans],
            "identity_evidence_sha256": authority.identity_evidence_sha256,
            "state": "creating",
            "revision": 0,
            "created_case_revision": None,
            "created_case_sha256": None,
            "planned_source_count": 0,
            "planned_callback_count": 0,
            "created_at": now,
            "updated_at": now,
            "retained_until": retained_until,
        }
        operation = {
            "tenant_id": tenant,
            "key_sha256": key_sha256,
            "request_sha256": request_sha256,
            "case_id": case_id,
            "created_at": now,
        }
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO ott_ctv_rights_requests VALUES(?,?,?,?,?,?,?)",
                    (
                        tenant,
                        case_id,
                        "creating",
                        0,
                        retained_until,
                        _canonical(payload).decode("ascii"),
                        _sha256(payload),
                    ),
                )
                connection.execute(
                    "INSERT INTO ott_ctv_rights_operations VALUES(?,?,?,?,?,?)",
                    (
                        operation["tenant_id"],
                        operation["key_sha256"],
                        operation["request_sha256"],
                        operation["case_id"],
                        operation["created_at"],
                        _sha256(operation),
                    ),
                )
                connection.commit()
            return payload
        except sqlite3.IntegrityError:
            existing = self._operation(tenant, key_sha256, request_sha256)
            if existing is None:
                raise OTTCTVPrivacyRightsConflict(
                    "bridge request changed concurrently"
                ) from None
            return existing

    def _resume(self, payload: Mapping[str, Any], authority: OTTCTVServiceAuthority) -> None:
        stored = self._authority(payload)
        if not _same(stored.authority_sha256, authority.authority_sha256):
            raise OTTCTVPrivacyRightsConflict("request authority changed")
        if payload.get("state") == "active":
            return
        if payload.get("state") != "creating" or payload.get("revision") != 0:
            raise OTTCTVPrivacyRightsIntegrityError("bridge request state is invalid")
        tenant = authority.tenant_id
        case_id = _ref(payload.get("case_id"), "case_id")
        right = payload.get("right")
        if right not in _RIGHTS:
            raise OTTCTVPrivacyRightsIntegrityError("stored request right is invalid")
        case = self._rights.open_case(
            tenant,
            case_id,
            request_version=1,
            external_request_ref=f"{case_id}:{payload['request_sha256']}",
            subject_reference=authority.account_binding_sha256,
            rights=(_RIGHTS[right],),
            retained_until=float(payload["retained_until"]),
            idempotency_key=f"ott-open-{case_id}",
        )
        evidence_sha = _digest(
            payload.get("identity_evidence_sha256"), "identity_evidence_sha256"
        )
        evidence_ref = f"CONSENT-OIDC-{authority.identity_evidence_sha256[:32]}"
        if case.identity_status == "unverified":
            case = self._rights.set_identity_verification(
                tenant,
                case_id,
                status="verified",
                evidence_sha256=evidence_sha,
                evidence_ref=evidence_ref,
                expected_revision=1,
                idempotency_key=f"ott-idv-{case_id}",
            )
        elif (
            case.identity_status != "verified"
            or not _same(case.identity_evidence_sha256, evidence_sha)
            or case.identity_evidence_ref != evidence_ref
        ):
            raise OTTCTVPrivacyRightsConflict("rights-case identity authority changed")
        raw_plans = payload.get("source_plans")
        if not isinstance(raw_plans, list) or len(raw_plans) > 1_000:
            raise OTTCTVPrivacyRightsIntegrityError("stored source plans are invalid")
        callback_count = 0
        for index, raw in enumerate(raw_plans):
            if not isinstance(raw, Mapping):
                raise OTTCTVPrivacyRightsIntegrityError("stored source plan is invalid")
            source_id = _ref(raw.get("source_id"), "source_id")
            phases = raw.get("phases")
            if (
                not isinstance(phases, list)
                or not phases
                or phases != [phase for phase in _RIGHT_PHASES[right] if phase in phases]
            ):
                raise OTTCTVPrivacyRightsIntegrityError("stored source phases are invalid")
            callback_count += sum(phase in CALLBACK_PHASES for phase in phases)
            self._rights.plan_source_tasks(
                tenant,
                case_id,
                source_id,
                phases=tuple(phases),
                expected_case_revision=2 + index,
                idempotency_key=f"ott-plan-{case_id}-{index}",
            )
        case = self._rights.get_case(tenant, case_id)
        if case.revision != 2 + len(raw_plans):
            raise OTTCTVPrivacyRightsConflict("rights case changed during request creation")
        final = dict(payload)
        final.update(
            {
                "state": "active",
                "revision": 1,
                "created_case_revision": case.revision,
                "created_case_sha256": case.integrity_sha256,
                "planned_source_count": len(raw_plans),
                "planned_callback_count": callback_count,
                "updated_at": self._now(),
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE ott_ctv_rights_requests SET state='active',revision=1,payload_json=?,"
                "integrity_sha256=? WHERE tenant_id=? AND case_id=? AND state='creating' "
                "AND revision=0 AND integrity_sha256=?",
                (
                    _canonical(final).decode("ascii"),
                    _sha256(final),
                    tenant,
                    case_id,
                    _sha256(payload),
                ),
            )
            if updated.rowcount != 1:
                current = connection.execute(
                    "SELECT * FROM ott_ctv_rights_requests WHERE tenant_id=? AND case_id=?",
                    (tenant, case_id),
                ).fetchone()
                if current is None or self._payload(current) != final:
                    raise OTTCTVPrivacyRightsConflict("bridge finalization CAS failed")
            connection.commit()

    def create_request(
        self,
        authority: OTTCTVServiceAuthority,
        *,
        right: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> SignedOTTCTVRequestStatus:
        """Open and plan one access/deletion case with recoverable idempotency."""

        self._gate()
        now = self._now()
        authority = self._resolve(authority, now)
        if right not in _RIGHTS:
            raise OTTCTVPrivacyRightsValidationError("right must be access or deletion")
        if _integer(expected_revision, "expected_revision", 0, 0) != 0:
            raise OTTCTVPrivacyRightsConflict("new request CAS requires expected_revision zero")
        _raw_key, key_sha = self._idempotency(idempotency_key)
        request_sha = _sha256(
            {
                "action": "create_ott_ctv_rights_request",
                "right": right,
                "expected_revision": 0,
                "authority_sha256": authority.authority_sha256,
            }
        )
        payload = self._operation(authority.tenant_id, key_sha, request_sha)
        if payload is None:
            plans = self._source_plans(authority.tenant_id, right)
            payload = self._reserve(
                authority,
                right=right,
                request_sha256=request_sha,
                key_sha256=key_sha,
                source_plans=plans,
                now=now,
            )
        self._resume(payload, authority)
        return self.get_status(authority, str(payload["case_id"]))

    def _request_payload(
        self,
        tenant_id: str,
        case_id: str,
        *,
        now: float,
    ) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        case = _ref(case_id, "case_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM ott_ctv_rights_requests WHERE tenant_id=? AND case_id=?",
                (tenant, case),
            ).fetchone()
        if row is None:
            raise OTTCTVPrivacyRightsNotFound("OTT/CTV rights request was not found")
        payload = self._payload(row)
        if float(payload["retained_until"]) <= now:
            raise OTTCTVPrivacyRightsNotFound("OTT/CTV rights request was not found")
        if payload.get("state") != "active" or payload.get("revision") != 1:
            raise OTTCTVPrivacyRightsConflict("OTT/CTV rights request is not ready")
        return payload

    def _signed_status(
        self,
        bridge: Mapping[str, Any],
        case: object,
        *,
        now: float,
    ) -> SignedOTTCTVRequestStatus:
        authority = self._authority(bridge)
        payload: dict[str, object] = {
            "schema": STATUS_SCHEMA,
            "case_id": bridge["case_id"],
            "right": bridge["right"],
            "status": getattr(case, "status", None),
            "identity_status": getattr(case, "identity_status", None),
            "legal_hold": getattr(case, "legal_hold", None),
            "retention_blocks_deletion": getattr(case, "retention_blocks_deletion", None),
            "bridge_revision": bridge["revision"],
            "bridge_sha256": _sha256(dict(bridge)),
            "created_case_revision": bridge["created_case_revision"],
            "created_case_sha256": bridge["created_case_sha256"],
            "orchestration_revision": getattr(case, "revision", None),
            "orchestration_sha256": getattr(case, "integrity_sha256", None),
            "authority_sha256": authority.authority_sha256,
            "platform": authority.platform,
            "service_client_sha256": authority.service_client_sha256,
            "target_bundle_sha256": authority.target_bundle_sha256,
            "property_sha256": authority.property_sha256,
            "profile_sha256": authority.profile_sha256,
            "account_binding_sha256": authority.account_binding_sha256,
            "client_revision": authority.client_revision,
            "profile_revision": authority.profile_revision,
            "identity_evidence_sha256": authority.identity_evidence_sha256,
            "identity_evidence_revision": authority.identity_evidence_revision,
            "identity_evidence_valid_until": authority.identity_evidence_valid_until,
            "publication_sha256": authority.publication_sha256,
            "publication_bundle_sha256": authority.publication_bundle_sha256,
            "configuration_sha256": authority.configuration_sha256,
            "policy_sha256": authority.policy_sha256,
            "policy_version": authority.policy_version,
            "trust_context_revision": authority.trust_context_revision,
            "trust_context_sha256": authority.trust_context_sha256,
            "capability_grant_sha256": authority.capability_grant_sha256,
            "planned_source_count": bridge["planned_source_count"],
            "planned_callback_count": bridge["planned_callback_count"],
            "destructive_approval_required": bridge["right"] == "deletion",
            "retrieved_payload_included": False,
            "response_delivery_claimed": False,
            "provider_operations_verified": False,
            "estate_completeness_claimed": False,
            "native_sdk_implemented": False,
            "live_provider_acceptance_verified": False,
            "generated_at": now,
        }
        signature = hmac.new(
            self._signing_key(authority.tenant_id),
            _canonical(payload),
            hashlib.sha256,
        ).hexdigest()
        evidence = _sha256(
            {
                "payload": payload,
                "signing_key_ref": self._signing_key_ref,
                "signature": signature,
            }
        )
        return SignedOTTCTVRequestStatus(payload, self._signing_key_ref, signature, evidence)

    def get_status(
        self,
        authority: OTTCTVServiceAuthority,
        case_id: str,
    ) -> SignedOTTCTVRequestStatus:
        """Return signed digest-only status after exact authority re-resolution."""

        self._gate()
        now = self._now()
        authority = self._resolve(authority, now)
        bridge = self._request_payload(authority.tenant_id, case_id, now=now)
        stored = self._authority(bridge)
        if not _same(stored.authority_sha256, authority.authority_sha256):
            raise OTTCTVPrivacyRightsNotFound("OTT/CTV rights request was not found")
        try:
            case = self._rights.get_case(authority.tenant_id, str(bridge["case_id"]))
        except Exception as exc:
            raise OTTCTVPrivacyRightsConflict("rights case authority is unavailable") from exc
        if (
            getattr(case, "tenant_id", None) != authority.tenant_id
            or getattr(case, "case_id", None) != bridge["case_id"]
            or tuple(getattr(case, "rights", ())) != (bridge["orchestration_right"],)
        ):
            raise OTTCTVPrivacyRightsIntegrityError("rights case binding changed")
        return self._signed_status(bridge, case, now=now)

    def purge_expired(
        self,
        *,
        before: float | None = None,
        limit: int = 100,
    ) -> Mapping[str, int]:
        """Atomically purge expired bridge state and its idempotency binding."""

        self._gate()
        if self._maintenance_authorizer() is not True:
            raise OTTCTVPrivacyRightsConfigError("maintenance authority is unavailable")
        now = self._now()
        cutoff = now if before is None else min(now, _timestamp(before, "before"))
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT tenant_id,case_id FROM ott_ctv_rights_requests "
                "WHERE retained_until<=? ORDER BY retained_until,tenant_id,case_id LIMIT ?",
                (cutoff, bounded),
            ).fetchall()
            keys = [(str(row["tenant_id"]), str(row["case_id"])) for row in rows]
            for tenant_id, expired_case_id in keys:
                deleted_operation = connection.execute(
                    "DELETE FROM ott_ctv_rights_operations "
                    "WHERE tenant_id=? AND case_id=?",
                    (tenant_id, expired_case_id),
                )
                deleted_request = connection.execute(
                    "DELETE FROM ott_ctv_rights_requests "
                    "WHERE tenant_id=? AND case_id=?",
                    (tenant_id, expired_case_id),
                )
                if deleted_operation.rowcount != 1 or deleted_request.rowcount != 1:
                    raise OTTCTVPrivacyRightsIntegrityError(
                        "expired bridge binding is incomplete"
                    )
            connection.commit()
        return {"requests_deleted": len(keys), "operations_deleted": len(keys)}

    def verify_signed_status(self, status: SignedOTTCTVRequestStatus) -> bool:
        if not isinstance(status, SignedOTTCTVRequestStatus):
            return False
        tenant = None
        authority_sha = status.payload.get("authority_sha256")
        case_id = status.payload.get("case_id")
        if not isinstance(authority_sha, str) or not isinstance(case_id, str):
            return False
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM ott_ctv_rights_requests WHERE case_id=? LIMIT 2",
                (case_id,),
            ).fetchall()
        if len(rows) != 1:
            return False
        try:
            bridge = self._payload(rows[0])
            authority = self._authority(bridge)
            tenant = authority.tenant_id
        except OTTCTVPrivacyRightsError:
            return False
        try:
            expected_signature = hmac.new(
                self._signing_key(tenant),
                _canonical(status.payload),
                hashlib.sha256,
            ).hexdigest()
        except OTTCTVPrivacyRightsError:
            return False
        expected_evidence = _sha256(
            {
                "payload": status.payload,
                "signing_key_ref": status.signing_key_ref,
                "signature": status.signature,
            }
        )
        return (
            status.signing_key_ref == self._signing_key_ref
            and _same(status.signature, expected_signature)
            and _same(status.evidence_sha256, expected_evidence)
            and _same(authority.authority_sha256, authority_sha)
        )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "local_control_plane": True,
            "network_io": NETWORK_IO,
            "provider_writes": PROVIDER_WRITES,
            "raw_device_id_persisted": False,
            "raw_oidc_subject_or_token_persisted": False,
            "consumer_selector_persisted": False,
            "provider_credentials_persisted": False,
            "retrieved_payload_persisted": False,
            "fresh_identity_proof_required": True,
            "identity_proof_valid_until_pinned": True,
            "identity_proof_max_ttl_seconds": MAX_PAIRING_TTL_SECONDS,
            "native_sdk_implemented": NATIVE_SDK_IMPLEMENTED,
            "estate_completeness_claimed": ESTATE_COMPLETENESS_CLAIMED,
            "live_provider_acceptance_verified": LIVE_PROVIDER_ACCEPTANCE_VERIFIED,
        }


__all__ = [
    "AUTHORITY_SCHEMA",
    "ESTATE_COMPLETENESS_CLAIMED",
    "LIVE_PROVIDER_ACCEPTANCE_VERIFIED",
    "NATIVE_SDK_IMPLEMENTED",
    "NETWORK_IO",
    "OTTCTVPrivacyRightsConfigError",
    "OTTCTVPrivacyRightsConflict",
    "OTTCTVPrivacyRightsError",
    "OTTCTVPrivacyRightsIntegrityError",
    "OTTCTVPrivacyRightsNotFound",
    "OTTCTVPrivacyRightsStore",
    "OTTCTVPrivacyRightsValidationError",
    "OTTCTVServiceAuthority",
    "PROVIDER_WRITES",
    "STATUS_SCHEMA",
    "SignedOTTCTVRequestStatus",
    "build_service_authority",
    "enabled",
    "ott_ctv_trust_context_ref",
    "require_enabled",
]
