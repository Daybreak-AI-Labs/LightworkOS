"""Governed bridge from reviewed privacy discovery into data-use authority.

The bridge certifies one complete, bounded discovery report whose every
finding has a current, fresh, independently approved review.  It may update
only the ``observed_classification`` context of an already enrolled data-use
asset.  Business-purpose, regulatory, and consent contexts remain independent
and are never inferred from discovery transport or findings.

Only public reads from :mod:`privacy_data_discovery` and public reads/writes
from :mod:`data_use_governance` are used.  Source, report, finding, review,
asset, and context revisions and digests are pinned.  Discovery and target
authority are each read twice before a mutation.  The two stores cannot share
one transaction; the deterministic data-use idempotency key makes a completed
write recoverable if the bridge acknowledgement is interrupted.

No raw values, source origins, resource locations, finding locations,
credentials, reviewer identifiers, provider calls, or network writes are
persisted or returned by this module.
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

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
PROPOSAL_SCHEMA = "lightwork.privacy-discovery-data-use-proposal.v1"
APPLICATION_SCHEMA = "lightwork.privacy-discovery-data-use-application.v1"
HEAD_SCHEMA = "lightwork.privacy-discovery-data-use-head.v1"
HISTORY_SCHEMA = "lightwork.privacy-discovery-data-use-history.v1"
AUDIT_SCHEMA = "lightwork.privacy-discovery-data-use-audit.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
RAW_VALUES_PERSISTED = False
RAW_LOCATIONS_PERSISTED = False
RAW_CREDENTIALS_PERSISTED = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False
CROSS_STORE_ATOMICITY = False

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_CLASSIFICATIONS = 2_000
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 365 * 24 * 60 * 60
_ACTIONS = frozenset({"desired", "no_change", "reconcile", "rollback"})
_POSITIVE_DECISIONS = frozenset({"confirmed", "reclassified"})
_OBSERVED_CONTEXT = "observed_classification"

_ROW_BINDINGS: dict[str, tuple[tuple[str, str], ...]] = {
    "pddb_proposals": (
        ("tenant_id", "text"),
        ("proposal_id", "text"),
        ("bridge_id", "text"),
        ("action", "text"),
        ("retained_until", "real"),
    ),
    "pddb_applications": (
        ("tenant_id", "text"),
        ("application_id", "text"),
        ("proposal_id", "text"),
        ("bridge_id", "text"),
        ("bridge_revision", "integer"),
        ("retained_until", "real"),
    ),
    "pddb_heads": (
        ("tenant_id", "text"),
        ("bridge_id", "text"),
        ("revision", "integer"),
        ("retained_until", "real"),
    ),
    "pddb_history": (
        ("tenant_id", "text"),
        ("bridge_id", "text"),
        ("sequence", "integer"),
        ("retained_until", "real"),
    ),
    "pddb_operations": (
        ("tenant_id", "text"),
        ("namespace", "text"),
        ("key_sha256", "text"),
        ("request_sha256", "text"),
        ("result_kind", "text"),
        ("result_id", "text"),
    ),
    "pddb_audit": (
        ("tenant_id", "text"),
        ("bridge_id", "text"),
        ("sequence", "integer"),
        ("event_type", "text"),
    ),
}

_ROW_SCHEMAS: dict[str, str] = {
    "pddb_proposals": PROPOSAL_SCHEMA,
    "pddb_applications": APPLICATION_SCHEMA,
    "pddb_heads": HEAD_SCHEMA,
    "pddb_history": HISTORY_SCHEMA,
    "pddb_audit": AUDIT_SCHEMA,
}


class DiscoveryDataUseBridgeError(RuntimeError):
    """Base bridge error."""


class DiscoveryDataUseBridgeConfigError(DiscoveryDataUseBridgeError):
    """Feature gates, stores, principal, or digest-key authority are absent."""


class DiscoveryDataUseBridgeValidationError(DiscoveryDataUseBridgeError, ValueError):
    """Input is outside the closed digest-only bridge contract."""


class DiscoveryDataUseBridgeConflict(DiscoveryDataUseBridgeError):
    """A CAS, freshness, completeness, or drift precondition failed."""


class DiscoveryDataUseBridgeNotFound(DiscoveryDataUseBridgeError):
    """A tenant-scoped bridge record is absent."""


class DiscoveryDataUseBridgeIntegrityError(DiscoveryDataUseBridgeError):
    """Persisted or injected authority failed integrity validation."""


@dataclass(frozen=True)
class ClassificationPin:
    """Exact current finding and four-eyes review authority."""

    finding_id: str
    finding_revision: int
    finding_integrity_sha256: str
    review_id: str
    review_version: int
    review_integrity_sha256: str


def enabled() -> bool:
    """Require discovery, bridge, and data-use product gates explicitly."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    privacy = config.get("privacy_automation")
    discovery = privacy.get("data_discovery") if isinstance(privacy, Mapping) else None
    bridge = privacy.get("discovery_data_use_bridge") if isinstance(privacy, Mapping) else None
    data_use = config.get("data_use_governance")
    return (
        isinstance(privacy, Mapping)
        and privacy.get("enable") is True
        and isinstance(discovery, Mapping)
        and discovery.get("enable") is True
        and isinstance(bridge, Mapping)
        and bridge.get("enable") is True
        and isinstance(data_use, Mapping)
        and data_use.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise DiscoveryDataUseBridgeConfigError(
            "privacy discovery data-use bridge is disabled; explicitly enable "
            "privacy_automation, privacy_automation.data_discovery, "
            "privacy_automation.discovery_data_use_bridge, and data_use_governance"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _default_digest_key_resolver(tenant_id: str) -> bytes:
    del tenant_id
    value = os.environ.get("MAVERICK_PRIVACY_DISCOVERY_DATA_USE_BRIDGE_DIGEST_KEY")
    if value is None or len(value.encode("utf-8")) < 32:
        raise DiscoveryDataUseBridgeConfigError(
            "MAVERICK_PRIVACY_DISCOVERY_DATA_USE_BRIDGE_DIGEST_KEY is absent or too short"
        )
    return value.encode("utf-8")


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DiscoveryDataUseBridgeValidationError(
            "bridge state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise DiscoveryDataUseBridgeValidationError("bridge state exceeds its canonical byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _same(left: object, right: object) -> bool:
    return (
        isinstance(left, str)
        and isinstance(right, str)
        and hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))
    )


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise DiscoveryDataUseBridgeValidationError("tenant_id is invalid") from exc


def _token(
    value: object,
    label: str,
    *,
    idempotency: bool = False,
) -> str:
    pattern = _IDEMPOTENCY_RE if idempotency else _TOKEN_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DiscoveryDataUseBridgeValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DiscoveryDataUseBridgeValidationError(f"{label} must be a SHA-256 digest")
    return value


def _revision(value: object, label: str, *, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= 2**31 - 1:
        raise DiscoveryDataUseBridgeValidationError(f"{label} is outside its revision bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoveryDataUseBridgeValidationError(f"{label} must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise DiscoveryDataUseBridgeValidationError(f"{label} must be a finite timestamp")
    return result


def _retained_until(value: object, now: float) -> float:
    retained = _timestamp(value, "retained_until")
    if not now + _MIN_RETENTION_SECONDS <= retained <= now + _MAX_RETENTION_SECONDS:
        raise DiscoveryDataUseBridgeValidationError("retained_until is outside its bound")
    return retained


def _normalized_pin(value: object) -> ClassificationPin:
    if not isinstance(value, ClassificationPin):
        raise DiscoveryDataUseBridgeValidationError(
            "classification pins must use the closed ClassificationPin contract"
        )
    return ClassificationPin(
        finding_id=_token(value.finding_id, "finding_id"),
        finding_revision=_revision(
            value.finding_revision,
            "finding_revision",
            positive=True,
        ),
        finding_integrity_sha256=_digest(
            value.finding_integrity_sha256,
            "finding_integrity_sha256",
        ),
        review_id=_token(value.review_id, "review_id"),
        review_version=_revision(value.review_version, "review_version", positive=True),
        review_integrity_sha256=_digest(
            value.review_integrity_sha256,
            "review_integrity_sha256",
        ),
    )


class PrivacyDiscoveryDataUseBridgeStore:
    """Durable proposal, reconciliation, rollback, and evidence authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        discovery_store: object,
        data_use_store: object,
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        digest_key_resolver: Callable[[str], bytes] = _default_digest_key_resolver,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        discovery_methods = (
            "get_source",
            "get_report",
            "get_finding",
            "get_review",
            "list_reviews",
        )
        data_use_methods = (
            "get_record",
            "get_context_authority",
            "put_context_authority",
        )
        if any(not callable(getattr(discovery_store, name, None)) for name in discovery_methods):
            raise DiscoveryDataUseBridgeConfigError(
                "discovery_store must expose the required public read contract"
            )
        if any(not callable(getattr(data_use_store, name, None)) for name in data_use_methods):
            raise DiscoveryDataUseBridgeConfigError(
                "data_use_store must expose the required public context contract"
            )
        if not callable(principal_resolver) or not callable(digest_key_resolver):
            raise DiscoveryDataUseBridgeConfigError(
                "principal and digest-key resolvers must be callable"
            )
        self.path = Path(path)
        self._discovery = discovery_store
        self._data_use = data_use_store
        self._principal_resolver = principal_resolver
        self._digest_key_resolver = digest_key_resolver
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "source": "approved_privacy_data_discovery_public_api",
            "target": "data_use_observed_classification_context_only",
            "business_purpose_inferred": False,
            "regulatory_authority_inferred": False,
            "consent_authority_inferred": False,
            "estate_completeness_inferred": False,
            "complete_within_declared_scan_bounds_required": True,
            "all_report_findings_require_current_four_eyes_review": True,
            "double_read_drift_checks": True,
            "deterministic_no_change_reconcile_rollback": True,
            "cross_store_atomicity": CROSS_STORE_ATOMICITY,
            "network_io": NETWORK_IO,
            "provider_writes": PROVIDER_WRITES,
            "raw_values_persisted": RAW_VALUES_PERSISTED,
            "raw_locations_persisted": RAW_LOCATIONS_PERSISTED,
            "raw_credentials_persisted": RAW_CREDENTIALS_PERSISTED,
            "maximum_exact_findings": _MAX_CLASSIFICATIONS,
            "live_provider_acceptance_verified": LIVE_PROVIDER_ACCEPTANCE_VERIFIED,
        }

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "bridge clock")
        except (KeyboardInterrupt, SystemExit):
            raise
        except DiscoveryDataUseBridgeError:
            raise
        except Exception as exc:
            raise DiscoveryDataUseBridgeConfigError("bridge clock is unavailable") from exc

    def _key(self, tenant: str) -> bytes:
        try:
            key = self._digest_key_resolver(tenant)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DiscoveryDataUseBridgeConfigError("bridge digest-key resolver failed") from exc
        if not isinstance(key, bytes) or len(key) < 32:
            raise DiscoveryDataUseBridgeConfigError(
                "bridge digest key must contain at least 32 bytes"
            )
        return key

    def _actor_sha256(self, tenant: str) -> str:
        try:
            actor = self._principal_resolver()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise DiscoveryDataUseBridgeConfigError("principal resolver failed") from exc
        if not isinstance(actor, str) or not actor:
            raise DiscoveryDataUseBridgeConfigError(
                "an authenticated principal is required for the bridge"
            )
        return hmac.new(
            self._key(tenant),
            b"lightwork.privacy-discovery-data-use.actor.v1\0" + actor.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _reviewer_sha256(self, tenant: str, value: object) -> str:
        if not isinstance(value, str) or not value:
            raise DiscoveryDataUseBridgeIntegrityError(
                "approved review contains an invalid reviewer authority"
            )
        return hmac.new(
            self._key(tenant),
            b"lightwork.privacy-discovery-data-use.reviewer.v1\0" + value.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        ensure_private_directory(self.path.parent)
        if not self.path.exists():
            try:
                fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        ensure_private_file(self.path, 0o600)
        connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA secure_delete=ON")
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS pddb_meta(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pddb_proposals(
                    tenant_id TEXT NOT NULL,proposal_id TEXT NOT NULL,
                    bridge_id TEXT NOT NULL,action TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,proposal_id)
                );
                CREATE INDEX IF NOT EXISTS pddb_proposals_bridge
                    ON pddb_proposals(tenant_id,bridge_id,retained_until);
                CREATE TABLE IF NOT EXISTS pddb_applications(
                    tenant_id TEXT NOT NULL,application_id TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,bridge_id TEXT NOT NULL,
                    bridge_revision INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,application_id),
                    UNIQUE(tenant_id,proposal_id)
                );
                CREATE TABLE IF NOT EXISTS pddb_heads(
                    tenant_id TEXT NOT NULL,bridge_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,bridge_id)
                );
                CREATE TABLE IF NOT EXISTS pddb_history(
                    tenant_id TEXT NOT NULL,bridge_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,bridge_id,sequence)
                );
                CREATE TABLE IF NOT EXISTS pddb_operations(
                    tenant_id TEXT NOT NULL,namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,request_sha256 TEXT NOT NULL,
                    result_kind TEXT NOT NULL,result_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,namespace,key_sha256)
                );
                CREATE TABLE IF NOT EXISTS pddb_audit(
                    tenant_id TEXT NOT NULL,bridge_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,bridge_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS pddb_proposals_no_update
                    BEFORE UPDATE ON pddb_proposals
                    BEGIN SELECT RAISE(ABORT,'immutable bridge proposal'); END;
                CREATE TRIGGER IF NOT EXISTS pddb_applications_no_update
                    BEFORE UPDATE ON pddb_applications
                    BEGIN SELECT RAISE(ABORT,'immutable bridge application'); END;
                CREATE TRIGGER IF NOT EXISTS pddb_history_no_update
                    BEFORE UPDATE ON pddb_history
                    BEGIN SELECT RAISE(ABORT,'immutable bridge history'); END;
                CREATE TRIGGER IF NOT EXISTS pddb_operations_no_update
                    BEFORE UPDATE ON pddb_operations
                    BEGIN SELECT RAISE(ABORT,'immutable bridge operation'); END;
                CREATE TRIGGER IF NOT EXISTS pddb_operations_no_delete
                    BEFORE DELETE ON pddb_operations
                    BEGIN SELECT RAISE(ABORT,'immutable bridge operation'); END;
                CREATE TRIGGER IF NOT EXISTS pddb_audit_no_update
                    BEFORE UPDATE ON pddb_audit
                    BEGIN SELECT RAISE(ABORT,'immutable bridge audit'); END;
                CREATE TRIGGER IF NOT EXISTS pddb_audit_no_delete
                    BEFORE DELETE ON pddb_audit
                    BEGIN SELECT RAISE(ABORT,'immutable bridge audit'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO pddb_meta(key,value) VALUES('schema_version',?)",
                (str(SCHEMA_VERSION),),
            )
            for obsolete_trigger in (
                "pddb_proposals_no_delete",
                "pddb_applications_no_delete",
                "pddb_history_no_delete",
            ):
                connection.execute(f"DROP TRIGGER IF EXISTS {obsolete_trigger}")
            row = connection.execute(
                "SELECT value FROM pddb_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != str(SCHEMA_VERSION):
                raise DiscoveryDataUseBridgeConfigError("unsupported bridge schema")

    @staticmethod
    def _payload(
        row: sqlite3.Row,
        label: str,
        *,
        table: str | None = None,
    ) -> dict[str, Any]:
        try:
            value = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, UnicodeError) as exc:
            raise DiscoveryDataUseBridgeIntegrityError(f"{label} JSON is invalid") from exc
        if not isinstance(value, dict):
            raise DiscoveryDataUseBridgeIntegrityError(f"{label} must be an object")
        expected = _sha256(value)
        if not _same(expected, row["integrity_sha256"]):
            raise DiscoveryDataUseBridgeIntegrityError(f"{label} integrity check failed")
        if table is not None:
            PrivacyDiscoveryDataUseBridgeStore._assert_row_binding(
                row,
                value,
                label=label,
                table=table,
            )
        return {**value, "integrity_sha256": expected}

    @staticmethod
    def _assert_row_binding(
        row: sqlite3.Row,
        payload: Mapping[str, Any],
        *,
        label: str,
        table: str,
    ) -> None:
        bindings = _ROW_BINDINGS.get(table)
        if bindings is None:
            raise DiscoveryDataUseBridgeConfigError("unknown bridge persistence table")
        expected_schema = _ROW_SCHEMAS.get(table)
        if expected_schema is not None and payload.get("schema") != expected_schema:
            raise DiscoveryDataUseBridgeIntegrityError(f"{label} schema is invalid")
        for field, kind in bindings:
            signed = payload.get(field)
            stored = row[field]
            if kind == "text":
                valid = type(signed) is str and type(stored) is str and signed == stored
            elif kind == "integer":
                valid = type(signed) is int and type(stored) is int and signed == stored
            else:
                valid = (
                    type(signed) in {int, float}
                    and type(stored) in {int, float}
                    and math.isfinite(float(signed))
                    and math.isfinite(float(stored))
                    and float(signed) == float(stored)
                )
            if not valid:
                raise DiscoveryDataUseBridgeIntegrityError(
                    f"{label} {field} index binding is invalid"
                )

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        table: str,
        columns: Sequence[str],
        values: Sequence[object],
        payload: Mapping[str, Any],
    ) -> str:
        digest = _sha256(payload)
        names = ",".join((*columns, "payload_json", "integrity_sha256"))
        placeholders = ",".join("?" for _ in range(len(columns) + 2))
        connection.execute(
            f"INSERT INTO {table}({names}) VALUES({placeholders})",  # noqa: S608
            (*values, _canonical(payload).decode("ascii"), digest),
        )
        return digest

    @staticmethod
    def _idempotency(value: object) -> tuple[str, str]:
        key = _token(value, "idempotency_key", idempotency=True)
        return key, hashlib.sha256(key.encode("ascii")).hexdigest()

    def _operation(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> tuple[str, str] | None:
        row = connection.execute(
            "SELECT * FROM pddb_operations WHERE tenant_id=? AND namespace=? AND key_sha256=?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        payload = self._payload(row, "bridge operation", table="pddb_operations")
        if (
            payload.get("tenant_id") != tenant
            or payload.get("namespace") != namespace
            or payload.get("key_sha256") != key_sha256
            or payload.get("request_sha256") != request_sha256
        ):
            raise DiscoveryDataUseBridgeConflict(
                "idempotency key was already used for different content"
            )
        return str(payload["result_kind"]), str(payload["result_id"])

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        payload = {
            "tenant_id": tenant,
            "namespace": namespace,
            "key_sha256": key_sha256,
            "request_sha256": request_sha256,
            "result_kind": result_kind,
            "result_id": result_id,
        }
        self._insert(
            connection,
            "pddb_operations",
            (
                "tenant_id",
                "namespace",
                "key_sha256",
                "request_sha256",
                "result_kind",
                "result_id",
            ),
            (
                tenant,
                namespace,
                key_sha256,
                request_sha256,
                result_kind,
                result_id,
            ),
            payload,
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        bridge_id: str,
        event_type: str,
        object_id: str,
        actor_sha256: str,
        details: Mapping[str, object],
        occurred_at: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM pddb_audit "
            "WHERE tenant_id=? AND bridge_id=? ORDER BY sequence DESC LIMIT 1",
            (tenant, bridge_id),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else str(previous["integrity_sha256"])
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant,
            "bridge_id": bridge_id,
            "sequence": sequence,
            "event_type": _token(event_type, "event_type"),
            "object_sha256": _sha256({"object_id": object_id}),
            "actor_sha256": _digest(actor_sha256, "actor_sha256"),
            "details": dict(details),
            "occurred_at": occurred_at,
            "previous_integrity_sha256": previous_sha,
        }
        self._insert(
            connection,
            "pddb_audit",
            ("tenant_id", "bridge_id", "sequence", "event_type"),
            (tenant, bridge_id, sequence, event_type),
            payload,
        )

    @staticmethod
    def _safe_asset(value: object, tenant: str, asset_id: str) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise DiscoveryDataUseBridgeConflict("data-use asset authority is absent")
        try:
            result = {
                "tenant_id": _tenant(value.get("tenant_id")),
                "asset_id": _token(value.get("asset_id"), "asset_id"),
                "asset_type": _token(value.get("asset_type"), "asset_type"),
                "catalog_binding_sha256": _digest(
                    value.get("catalog_binding_sha256"),
                    "catalog_binding_sha256",
                ),
                "revision": _revision(value.get("revision"), "asset_revision", positive=True),
                "record_sha256": _digest(value.get("record_sha256"), "asset_record_sha256"),
            }
        except DiscoveryDataUseBridgeValidationError as exc:
            raise DiscoveryDataUseBridgeIntegrityError(
                "data-use asset authority shape is invalid"
            ) from exc
        if result["tenant_id"] != tenant or result["asset_id"] != asset_id:
            raise DiscoveryDataUseBridgeIntegrityError(
                "data-use asset authority identity is inconsistent"
            )
        return result

    @staticmethod
    def _safe_context(value: object, tenant: str, asset_id: str) -> dict[str, Any] | None:
        if value is None:
            return None
        if not isinstance(value, Mapping):
            raise DiscoveryDataUseBridgeIntegrityError(
                "data-use context authority shape is invalid"
            )
        values = value.get("values")
        if (
            isinstance(values, (str, bytes))
            or not isinstance(values, Sequence)
            or not values
            or len(values) > 256
        ):
            raise DiscoveryDataUseBridgeIntegrityError("data-use context values are invalid")
        try:
            result = {
                "tenant_id": _tenant(value.get("tenant_id")),
                "asset_id": _token(value.get("asset_id"), "asset_id"),
                "context_kind": _token(value.get("context_kind"), "context_kind"),
                "values": sorted({_token(item, "context value") for item in values}),
                "source_system": _token(value.get("source_system"), "source_system"),
                "source_revision": _revision(
                    value.get("source_revision"),
                    "source_revision",
                    positive=True,
                ),
                "source_authority_sha256": _digest(
                    value.get("source_authority_sha256"),
                    "source_authority_sha256",
                ),
                "evidence_sha256": _digest(
                    value.get("evidence_sha256"),
                    "evidence_sha256",
                ),
                "reviewer_id": _token(value.get("reviewer_id"), "reviewer_id"),
                "reviewer_authority_sha256": _digest(
                    value.get("reviewer_authority_sha256"),
                    "reviewer_authority_sha256",
                ),
                "observed_at": _timestamp(value.get("observed_at"), "observed_at"),
                "fresh_until": _timestamp(value.get("fresh_until"), "fresh_until"),
                "revision": _revision(
                    value.get("revision"),
                    "context_revision",
                    positive=True,
                ),
                "record_sha256": _digest(
                    value.get("record_sha256"),
                    "context_record_sha256",
                ),
            }
        except DiscoveryDataUseBridgeValidationError as exc:
            raise DiscoveryDataUseBridgeIntegrityError(
                "data-use context authority shape is invalid"
            ) from exc
        if (
            result["tenant_id"] != tenant
            or result["asset_id"] != asset_id
            or result["context_kind"] != _OBSERVED_CONTEXT
        ):
            raise DiscoveryDataUseBridgeIntegrityError(
                "data-use context authority identity is inconsistent"
            )
        return result

    def _read_target(self, tenant: str, asset_id: str) -> dict[str, Any]:
        try:
            asset = self._data_use.get_record(tenant, "asset", asset_id)
            context = self._data_use.get_context_authority(
                tenant,
                asset_id,
                _OBSERVED_CONTEXT,
            )
        except Exception as exc:
            raise DiscoveryDataUseBridgeConflict(
                "data-use target authority is unavailable"
            ) from exc
        result = {
            "asset": self._safe_asset(asset, tenant, asset_id),
            "context": self._safe_context(context, tenant, asset_id),
        }
        return {**result, "authority_sha256": _sha256(result)}

    def _classification_snapshot(
        self,
        tenant: str,
        source_id: str,
        report_id: str,
        pins: Sequence[ClassificationPin],
        *,
        expected_source_revision: int,
        expected_source_integrity_sha256: str,
        expected_report_revision: int,
        expected_report_integrity_sha256: str,
        now: float,
    ) -> dict[str, Any]:
        from .privacy_data_discovery import EnrolledSource, Finding, ReviewProposal, ScanReport

        if not 1 <= len(pins) <= _MAX_CLASSIFICATIONS:
            raise DiscoveryDataUseBridgeConflict(
                "complete report findings exceed the exact bridge bound or are absent"
            )
        normalized = tuple(_normalized_pin(item) for item in pins)
        if len({item.finding_id for item in normalized}) != len(normalized):
            raise DiscoveryDataUseBridgeValidationError("finding pins must be unique")
        if len({item.review_id for item in normalized}) != len(normalized):
            raise DiscoveryDataUseBridgeValidationError("review pins must be unique")
        try:
            source = self._discovery.get_source(tenant, source_id)
            report = self._discovery.get_report(tenant, report_id)
        except Exception as exc:
            raise DiscoveryDataUseBridgeConflict(
                "discovery source or report authority is unavailable"
            ) from exc
        if not isinstance(source, EnrolledSource) or not isinstance(report, ScanReport):
            raise DiscoveryDataUseBridgeIntegrityError(
                "discovery source or report returned an invalid contract"
            )
        if (
            source.tenant_id != tenant
            or source.source_id != source_id
            or source.state != "active"
            or source.revision != expected_source_revision
            or not _same(source.integrity_sha256, expected_source_integrity_sha256)
        ):
            raise DiscoveryDataUseBridgeConflict("discovery source pin drifted")
        if (
            report.tenant_id != tenant
            or report.source_id != source_id
            or report.report_id != report_id
            or expected_report_revision != 1
            or not _same(report.integrity_sha256, expected_report_integrity_sha256)
        ):
            raise DiscoveryDataUseBridgeConflict("discovery report pin drifted")
        if (
            report.completeness != "complete_within_declared_bounds"
            or report.truncation_reasons
            or report.error_codes
            or report.findings_count != len(normalized)
            or report.retention_until <= now
        ):
            raise DiscoveryDataUseBridgeConflict(
                "discovery report is incomplete, truncated, errored, expired, or not fully pinned"
            )
        classifications: list[dict[str, Any]] = []
        values: set[str] = set()
        fresh_until = float(report.retention_until)
        observed_at = float(report.finished_at)
        reviewer_material: list[dict[str, str]] = []
        for pin in sorted(normalized, key=lambda item: item.finding_id):
            try:
                finding = self._discovery.get_finding(tenant, pin.finding_id)
                review = self._discovery.get_review(tenant, pin.review_id)
                latest = self._discovery.list_reviews(
                    tenant,
                    finding_id=pin.finding_id,
                    limit=1,
                )
            except Exception as exc:
                raise DiscoveryDataUseBridgeConflict(
                    "discovery classification authority is unavailable"
                ) from exc
            if not isinstance(finding, Finding) or not isinstance(review, ReviewProposal):
                raise DiscoveryDataUseBridgeIntegrityError(
                    "discovery classification returned an invalid contract"
                )
            if (
                finding.tenant_id != tenant
                or finding.source_id != source_id
                or finding.report_id != report_id
                or finding.finding_id != pin.finding_id
                or finding.revision != pin.finding_revision
                or not _same(finding.integrity_sha256, pin.finding_integrity_sha256)
            ):
                raise DiscoveryDataUseBridgeConflict("discovery finding pin drifted")
            if (
                review.tenant_id != tenant
                or review.finding_id != pin.finding_id
                or review.review_id != pin.review_id
                or review.version != pin.review_version
                or not _same(review.integrity_sha256, pin.review_integrity_sha256)
                or review.status != "approved"
                or review.approved_by is None
                or review.approved_at is None
                or review.prepared_by == review.approved_by
                or not latest
                or latest[0].review_id != review.review_id
                or not _same(latest[0].integrity_sha256, review.integrity_sha256)
            ):
                raise DiscoveryDataUseBridgeConflict(
                    "classification review is not the current independent approval"
                )
            review_fresh_until = review.prepared_at + review.freshness_seconds
            if review.approved_at > review_fresh_until or review_fresh_until <= now:
                raise DiscoveryDataUseBridgeConflict("classification review is stale")
            if review.decision in _POSITIVE_DECISIONS:
                if review.effective_category is None:
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "positive classification review lacks a category"
                    )
                values.add(_token(review.effective_category, "classification category"))
            elif review.decision != "false_positive" or review.effective_category is not None:
                raise DiscoveryDataUseBridgeIntegrityError(
                    "classification review decision is invalid"
                )
            preparer_sha = self._reviewer_sha256(tenant, review.prepared_by)
            approver_sha = self._reviewer_sha256(tenant, review.approved_by)
            reviewer_material.append(
                {
                    "review_id": review.review_id,
                    "prepared_by_sha256": preparer_sha,
                    "approved_by_sha256": approver_sha,
                }
            )
            fresh_until = min(fresh_until, review_fresh_until)
            observed_at = max(observed_at, float(review.approved_at))
            classifications.append(
                {
                    **asdict(pin),
                    "decision": review.decision,
                    "category": review.effective_category,
                    "evidence_sha256": _digest(
                        review.evidence_sha256,
                        "review_evidence_sha256",
                    ),
                    "approved_at": float(review.approved_at),
                    "fresh_until": float(review_fresh_until),
                    "prepared_by_sha256": preparer_sha,
                    "approved_by_sha256": approver_sha,
                }
            )
        if not values:
            raise DiscoveryDataUseBridgeConflict(
                "complete reviewed report contains no positive classification; no context is inferred"
            )
        source_material = {
            "tenant_id": tenant,
            "source_id": source_id,
            "source_revision": source.revision,
            "source_integrity_sha256": source.integrity_sha256,
            "report_id": report_id,
            "report_revision": 1,
            "report_integrity_sha256": report.integrity_sha256,
            "report_findings_count": report.findings_count,
            "report_completeness": report.completeness,
            "report_retention_until": report.retention_until,
            "classifications": classifications,
            "values": sorted(values),
            "observed_at": observed_at,
            "fresh_until": fresh_until,
            "limitations_sha256": _sha256(list(report.limitations)),
            "completeness_scope": "complete_within_declared_scan_bounds_only",
            "estate_completeness_inferred": False,
        }
        classification_sha = _sha256(classifications)
        reviewer_authority_sha = _sha256(reviewer_material)
        evidence_sha = _sha256(
            {
                "report_integrity_sha256": report.integrity_sha256,
                "classification_sha256": classification_sha,
                "reviewer_authority_sha256": reviewer_authority_sha,
            }
        )
        authority_sha = _sha256(source_material)
        desired_context = {
            "values": sorted(values),
            "source_system": "privacy_data_discovery",
            "source_revision": source.revision,
            "source_authority_sha256": authority_sha,
            "evidence_sha256": evidence_sha,
            "reviewer_id": f"pddb-reviewer-{reviewer_authority_sha[:32]}",
            "reviewer_authority_sha256": reviewer_authority_sha,
            "observed_at": observed_at,
            "fresh_until": fresh_until,
        }
        return {
            **source_material,
            "classification_sha256": classification_sha,
            "reviewer_authority_sha256": reviewer_authority_sha,
            "evidence_sha256": evidence_sha,
            "authority_sha256": authority_sha,
            "desired_context": desired_context,
        }

    def _reread_discovery(self, snapshot: Mapping[str, Any], now: float) -> dict[str, Any]:
        try:
            pins = tuple(
                ClassificationPin(
                    finding_id=item["finding_id"],
                    finding_revision=item["finding_revision"],
                    finding_integrity_sha256=item["finding_integrity_sha256"],
                    review_id=item["review_id"],
                    review_version=item["review_version"],
                    review_integrity_sha256=item["review_integrity_sha256"],
                )
                for item in snapshot["classifications"]
            )
            current = self._classification_snapshot(
                str(snapshot["tenant_id"]),
                str(snapshot["source_id"]),
                str(snapshot["report_id"]),
                pins,
                expected_source_revision=int(snapshot["source_revision"]),
                expected_source_integrity_sha256=str(snapshot["source_integrity_sha256"]),
                expected_report_revision=int(snapshot["report_revision"]),
                expected_report_integrity_sha256=str(snapshot["report_integrity_sha256"]),
                now=now,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise DiscoveryDataUseBridgeIntegrityError(
                "stored discovery snapshot is malformed"
            ) from exc
        if not _same(current["authority_sha256"], snapshot.get("authority_sha256")):
            raise DiscoveryDataUseBridgeConflict("discovery authority drifted")
        return current

    @staticmethod
    def _context_matches_desired(
        context: Mapping[str, Any] | None,
        desired: Mapping[str, Any],
    ) -> bool:
        if context is None:
            return False
        keys = (
            "values",
            "source_system",
            "source_revision",
            "source_authority_sha256",
            "evidence_sha256",
            "reviewer_id",
            "reviewer_authority_sha256",
            "observed_at",
            "fresh_until",
        )
        return all(context.get(key) == desired.get(key) for key in keys)

    @staticmethod
    def _assert_target_pins(
        target: Mapping[str, Any],
        *,
        expected_asset_revision: int,
        expected_asset_record_sha256: str,
        expected_context_revision: int,
        expected_context_record_sha256: str | None,
    ) -> None:
        asset = target["asset"]
        context = target["context"]
        if asset["revision"] != expected_asset_revision or not _same(
            asset["record_sha256"], expected_asset_record_sha256
        ):
            raise DiscoveryDataUseBridgeConflict("data-use asset pin drifted")
        if expected_context_revision == 0:
            if expected_context_record_sha256 is not None or context is not None:
                raise DiscoveryDataUseBridgeConflict("data-use context presence drifted")
        elif (
            context is None
            or context["revision"] != expected_context_revision
            or expected_context_record_sha256 is None
            or not _same(context["record_sha256"], expected_context_record_sha256)
        ):
            raise DiscoveryDataUseBridgeConflict("data-use context pin drifted")

    def _head_row(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        bridge_id: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM pddb_heads WHERE tenant_id=? AND bridge_id=?",
            (tenant, bridge_id),
        ).fetchone()

    def _head_payload(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        bridge_id: str,
    ) -> dict[str, Any] | None:
        row = self._head_row(connection, tenant, bridge_id)
        return None if row is None else self._payload(row, "bridge head", table="pddb_heads")

    def _proposal_by_id(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        proposal_id: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM pddb_proposals WHERE tenant_id=? AND proposal_id=?",
            (tenant, proposal_id),
        ).fetchone()
        if row is None:
            raise DiscoveryDataUseBridgeNotFound("bridge proposal was not found")
        return self._payload(row, "bridge proposal", table="pddb_proposals")

    def _application_by_id(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        application_id: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM pddb_applications WHERE tenant_id=? AND application_id=?",
            (tenant, application_id),
        ).fetchone()
        if row is None:
            raise DiscoveryDataUseBridgeNotFound("bridge application was not found")
        return self._payload(row, "bridge application", table="pddb_applications")

    def _assert_bridge_revision(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        bridge_id: str,
        expected_revision: int,
        asset_id: str,
        source_id: str,
    ) -> dict[str, Any] | None:
        head = self._head_payload(connection, tenant, bridge_id)
        if head is None:
            if expected_revision != 0:
                raise DiscoveryDataUseBridgeConflict("bridge head revision drifted")
            return None
        if (
            head.get("revision") != expected_revision
            or head.get("asset_id") != asset_id
            or head.get("source_id") != source_id
        ):
            raise DiscoveryDataUseBridgeConflict("bridge head revision or binding drifted")
        return head

    def propose(
        self,
        tenant_id: str,
        bridge_id: str,
        asset_id: str,
        source_id: str,
        report_id: str,
        classification_pins: Sequence[ClassificationPin],
        *,
        expected_source_revision: int,
        expected_source_integrity_sha256: str,
        expected_report_revision: int,
        expected_report_integrity_sha256: str,
        expected_asset_revision: int,
        expected_asset_record_sha256: str,
        expected_context_revision: int,
        expected_context_record_sha256: str | None,
        expected_bridge_revision: int,
        retained_until: float,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Stage a deterministic desired, no-change, or reconcile proposal."""

        tenant = _tenant(tenant_id)
        bridge = _token(bridge_id, "bridge_id")
        asset = _token(asset_id, "asset_id")
        source = _token(source_id, "source_id")
        report = _token(report_id, "report_id")
        source_revision = _revision(
            expected_source_revision,
            "expected_source_revision",
            positive=True,
        )
        source_digest = _digest(
            expected_source_integrity_sha256,
            "expected_source_integrity_sha256",
        )
        report_revision = _revision(
            expected_report_revision,
            "expected_report_revision",
            positive=True,
        )
        report_digest = _digest(
            expected_report_integrity_sha256,
            "expected_report_integrity_sha256",
        )
        asset_revision = _revision(
            expected_asset_revision,
            "expected_asset_revision",
            positive=True,
        )
        asset_digest = _digest(
            expected_asset_record_sha256,
            "expected_asset_record_sha256",
        )
        context_revision = _revision(
            expected_context_revision,
            "expected_context_revision",
        )
        context_digest = (
            None
            if expected_context_record_sha256 is None
            else _digest(
                expected_context_record_sha256,
                "expected_context_record_sha256",
            )
        )
        bridge_revision = _revision(
            expected_bridge_revision,
            "expected_bridge_revision",
        )
        pins = tuple(_normalized_pin(item) for item in classification_pins)
        now = self._now()
        retained = _retained_until(retained_until, now)
        actor_sha = self._actor_sha256(tenant)
        _key, key_sha = self._idempotency(idempotency_key)
        request = {
            "action": "propose",
            "bridge_id": bridge,
            "asset_id": asset,
            "source_id": source,
            "report_id": report,
            "classification_pins": [asdict(item) for item in pins],
            "expected_source_revision": source_revision,
            "expected_source_integrity_sha256": source_digest,
            "expected_report_revision": report_revision,
            "expected_report_integrity_sha256": report_digest,
            "expected_asset_revision": asset_revision,
            "expected_asset_record_sha256": asset_digest,
            "expected_context_revision": context_revision,
            "expected_context_record_sha256": context_digest,
            "expected_bridge_revision": bridge_revision,
            "retained_until": retained,
            "actor_sha256": actor_sha,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            replay = self._operation(
                connection,
                tenant,
                "proposal.create",
                key_sha,
                request_sha,
            )
            if replay is not None:
                kind, result_id = replay
                if kind != "proposal":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "proposal idempotency result kind is invalid"
                    )
                return self._proposal_by_id(connection, tenant, result_id)
        first_source = self._classification_snapshot(
            tenant,
            source,
            report,
            pins,
            expected_source_revision=source_revision,
            expected_source_integrity_sha256=source_digest,
            expected_report_revision=report_revision,
            expected_report_integrity_sha256=report_digest,
            now=now,
        )
        second_source = self._reread_discovery(first_source, now)
        if not _same(first_source["authority_sha256"], second_source["authority_sha256"]):
            raise DiscoveryDataUseBridgeConflict("discovery authority drifted between reads")
        if retained > first_source["report_retention_until"]:
            raise DiscoveryDataUseBridgeValidationError(
                "bridge retention cannot outlive the source report"
            )
        first_target = self._read_target(tenant, asset)
        second_target = self._read_target(tenant, asset)
        if not _same(first_target["authority_sha256"], second_target["authority_sha256"]):
            raise DiscoveryDataUseBridgeConflict("data-use target drifted between reads")
        self._assert_target_pins(
            first_target,
            expected_asset_revision=asset_revision,
            expected_asset_record_sha256=asset_digest,
            expected_context_revision=context_revision,
            expected_context_record_sha256=context_digest,
        )
        desired = first_source["desired_context"]
        current_context = first_target["context"]
        action = (
            "desired"
            if current_context is None
            else (
                "no_change"
                if self._context_matches_desired(current_context, desired)
                else "reconcile"
            )
        )
        proposal_id = f"PDDB-{key_sha[:32]}"
        payload = {
            "schema": PROPOSAL_SCHEMA,
            "tenant_id": tenant,
            "proposal_id": proposal_id,
            "bridge_id": bridge,
            "action": action,
            "asset_id": asset,
            "source_id": source,
            "report_id": report,
            "source_snapshot": first_source,
            "desired_context": desired,
            "before_asset": first_target["asset"],
            "before_context": current_context,
            "expected_bridge_revision": bridge_revision,
            "rollback_target_bridge_revision": None,
            "retained_until": retained,
            "created_by_sha256": actor_sha,
            "created_at": now,
        }
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation(
                connection,
                tenant,
                "proposal.create",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                kind, result_id = replay
                if kind != "proposal":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "proposal idempotency result kind is invalid"
                    )
                return self.get_proposal(tenant, result_id)
            self._assert_bridge_revision(
                connection,
                tenant,
                bridge,
                bridge_revision,
                asset,
                source,
            )
            self._insert(
                connection,
                "pddb_proposals",
                ("tenant_id", "proposal_id", "bridge_id", "action", "retained_until"),
                (tenant, proposal_id, bridge, action, retained),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                "proposal.create",
                key_sha,
                request_sha,
                "proposal",
                proposal_id,
            )
            self._audit(
                connection,
                tenant,
                bridge,
                "proposal_created",
                proposal_id,
                actor_sha,
                {
                    "action": action,
                    "source_authority_sha256": first_source["authority_sha256"],
                    "classification_sha256": first_source["classification_sha256"],
                    "expected_context_revision": context_revision,
                },
                now,
            )
            connection.commit()
        return self.get_proposal(tenant, proposal_id)

    def _target_matches_proposal_before(
        self,
        target: Mapping[str, Any],
        proposal: Mapping[str, Any],
    ) -> bool:
        return (
            target["asset"] == proposal["before_asset"]
            and target["context"] == proposal["before_context"]
        )

    @staticmethod
    def _safe_written_context(
        value: object,
        tenant: str,
        asset_id: str,
    ) -> dict[str, Any]:
        result = PrivacyDiscoveryDataUseBridgeStore._safe_context(value, tenant, asset_id)
        if result is None:
            raise DiscoveryDataUseBridgeIntegrityError(
                "data-use context write returned no authority"
            )
        return result

    def reconcile(  # noqa: C901
        self,
        tenant_id: str,
        proposal_id: str,
        *,
        expected_proposal_integrity_sha256: str,
        expected_bridge_revision: int,
        idempotency_key: str,
        before_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Revalidate twice, apply once idempotently, and certify the result."""

        tenant = _tenant(tenant_id)
        proposal_key = _token(proposal_id, "proposal_id")
        proposal_digest = _digest(
            expected_proposal_integrity_sha256,
            "expected_proposal_integrity_sha256",
        )
        bridge_revision = _revision(
            expected_bridge_revision,
            "expected_bridge_revision",
        )
        actor_sha = self._actor_sha256(tenant)
        now = self._now()
        _key, key_sha = self._idempotency(idempotency_key)
        with self._connect() as connection:
            proposal = self._proposal_by_id(connection, tenant, proposal_key)
            request = {
                "action": "reconcile",
                "proposal_id": proposal_key,
                "proposal_integrity_sha256": proposal_digest,
                "expected_bridge_revision": bridge_revision,
                "actor_sha256": actor_sha,
            }
            request_sha = _sha256(request)
            replay = self._operation(
                connection,
                tenant,
                "proposal.reconcile",
                key_sha,
                request_sha,
            )
            if replay is not None:
                kind, result_id = replay
                if kind != "application":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "reconcile idempotency result kind is invalid"
                    )
                return self._application_by_id(connection, tenant, result_id)
            self._assert_bridge_revision(
                connection,
                tenant,
                proposal["bridge_id"],
                bridge_revision,
                proposal["asset_id"],
                proposal["source_id"],
            )
        if not _same(proposal["integrity_sha256"], proposal_digest):
            raise DiscoveryDataUseBridgeConflict("proposal integrity CAS failed")
        if proposal["expected_bridge_revision"] != bridge_revision:
            raise DiscoveryDataUseBridgeConflict("proposal bridge revision pin drifted")
        if proposal["retained_until"] <= now:
            raise DiscoveryDataUseBridgeConflict("bridge proposal retention expired")
        source_first = self._reread_discovery(proposal["source_snapshot"], now)
        source_second = self._reread_discovery(source_first, now)
        if not _same(source_first["authority_sha256"], source_second["authority_sha256"]):
            raise DiscoveryDataUseBridgeConflict("discovery authority drifted between reads")
        target_first = self._read_target(tenant, proposal["asset_id"])
        target_second = self._read_target(tenant, proposal["asset_id"])
        if not _same(target_first["authority_sha256"], target_second["authority_sha256"]):
            raise DiscoveryDataUseBridgeConflict("data-use target drifted between reads")
        desired = proposal["desired_context"]
        before_matches = self._target_matches_proposal_before(target_first, proposal)
        recovered_write = False
        if not before_matches:
            before_context = proposal["before_context"]
            expected_after_revision = (
                1 if before_context is None else int(before_context["revision"]) + 1
            )
            current = target_first["context"]
            recovered_write = (
                proposal["action"] != "no_change"
                and target_first["asset"] == proposal["before_asset"]
                and current is not None
                and current["revision"] == expected_after_revision
                and self._context_matches_desired(current, desired)
            )
            if not recovered_write:
                raise DiscoveryDataUseBridgeConflict(
                    "data-use target changed after proposal creation"
                )
        if proposal["action"] == "no_change":
            if before_write is not None:
                before_write()
            if not self._context_matches_desired(target_first["context"], desired):
                raise DiscoveryDataUseBridgeConflict("no-change target is no longer exact")
            written = target_first["context"]
            if written is None:
                raise DiscoveryDataUseBridgeIntegrityError("no-change context is absent")
            outcome = "no_change"
        else:
            before_context = proposal["before_context"]
            expected_context_revision = (
                0 if before_context is None else int(before_context["revision"])
            )
            mutation_key = f"pddb-reconcile-{proposal_digest[:32]}"
            writer_guard = {}
            if before_write is not None:
                writer_guard["before_write"] = before_write
            try:
                value = self._data_use.put_context_authority(
                    tenant,
                    proposal["asset_id"],
                    _OBSERVED_CONTEXT,
                    values=desired["values"],
                    source_system=desired["source_system"],
                    source_revision=desired["source_revision"],
                    source_authority_sha256=desired["source_authority_sha256"],
                    evidence_sha256=desired["evidence_sha256"],
                    reviewer_id=desired["reviewer_id"],
                    reviewer_authority_sha256=desired["reviewer_authority_sha256"],
                    observed_at=desired["observed_at"],
                    fresh_until=desired["fresh_until"],
                    expected_revision=expected_context_revision,
                    idempotency_key=mutation_key,
                    **writer_guard,
                )
            except Exception as exc:
                raise DiscoveryDataUseBridgeConflict(
                    "data-use context reconciliation failed"
                ) from exc
            written = self._safe_written_context(value, tenant, proposal["asset_id"])
            if not self._context_matches_desired(written, desired):
                raise DiscoveryDataUseBridgeIntegrityError(
                    "data-use context write does not match desired authority"
                )
            post = self._read_target(tenant, proposal["asset_id"])
            if post["asset"] != proposal["before_asset"] or post["context"] != written:
                raise DiscoveryDataUseBridgeConflict(
                    "data-use context drifted during reconciliation"
                )
            outcome = "recovered" if recovered_write else "applied"
        application_id = f"PDDA-{hashlib.sha256(proposal_key.encode()).hexdigest()[:32]}"
        with self._connect() as connection:
            self._begin(connection)
            if before_write is not None:
                before_write()
            replay = self._operation(
                connection,
                tenant,
                "proposal.reconcile",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                kind, result_id = replay
                if kind != "application":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "reconcile idempotency result kind is invalid"
                    )
                return self.get_application(tenant, result_id)
            existing = connection.execute(
                "SELECT * FROM pddb_applications WHERE tenant_id=? AND proposal_id=?",
                (tenant, proposal_key),
            ).fetchone()
            if existing is not None:
                raise DiscoveryDataUseBridgeConflict(
                    "proposal was already reconciled under another idempotency key"
                )
            head = self._assert_bridge_revision(
                connection,
                tenant,
                proposal["bridge_id"],
                bridge_revision,
                proposal["asset_id"],
                proposal["source_id"],
            )
            new_revision = bridge_revision + 1
            application = {
                "schema": APPLICATION_SCHEMA,
                "tenant_id": tenant,
                "application_id": application_id,
                "proposal_id": proposal_key,
                "bridge_id": proposal["bridge_id"],
                "bridge_revision": new_revision,
                "action": proposal["action"],
                "outcome": outcome,
                "source_authority_sha256": source_first["authority_sha256"],
                "classification_sha256": source_first["classification_sha256"],
                "before_context": proposal["before_context"],
                "after_context": written,
                "retained_until": proposal["retained_until"],
                "applied_by_sha256": actor_sha,
                "applied_at": now,
            }
            application_digest = self._insert(
                connection,
                "pddb_applications",
                (
                    "tenant_id",
                    "application_id",
                    "proposal_id",
                    "bridge_id",
                    "bridge_revision",
                    "retained_until",
                ),
                (
                    tenant,
                    application_id,
                    proposal_key,
                    proposal["bridge_id"],
                    new_revision,
                    proposal["retained_until"],
                ),
                application,
            )
            head_payload = {
                "schema": HEAD_SCHEMA,
                "tenant_id": tenant,
                "bridge_id": proposal["bridge_id"],
                "asset_id": proposal["asset_id"],
                "source_id": proposal["source_id"],
                "report_id": proposal["report_id"],
                "revision": new_revision,
                "proposal_id": proposal_key,
                "application_id": application_id,
                "application_integrity_sha256": application_digest,
                "asset_authority": proposal["before_asset"],
                "source_snapshot": source_first,
                "desired_context": desired,
                "context": written,
                "retained_until": proposal["retained_until"],
                "accepted_at": now,
            }
            head_digest = _sha256(head_payload)
            if head is None:
                connection.execute(
                    "INSERT INTO pddb_heads VALUES(?,?,?,?,?,?)",
                    (
                        tenant,
                        proposal["bridge_id"],
                        new_revision,
                        proposal["retained_until"],
                        _canonical(head_payload).decode("ascii"),
                        head_digest,
                    ),
                )
            else:
                changed = connection.execute(
                    "UPDATE pddb_heads SET revision=?,retained_until=?,payload_json=?,"
                    "integrity_sha256=? WHERE tenant_id=? AND bridge_id=? AND revision=?",
                    (
                        new_revision,
                        proposal["retained_until"],
                        _canonical(head_payload).decode("ascii"),
                        head_digest,
                        tenant,
                        proposal["bridge_id"],
                        bridge_revision,
                    ),
                ).rowcount
                if changed != 1:
                    raise DiscoveryDataUseBridgeConflict("bridge head CAS failed")
            history_payload = {
                "schema": HISTORY_SCHEMA,
                "tenant_id": tenant,
                "bridge_id": proposal["bridge_id"],
                "sequence": new_revision,
                "proposal_id": proposal_key,
                "application_id": application_id,
                "action": proposal["action"],
                "outcome": outcome,
                "asset_id": proposal["asset_id"],
                "asset_authority": proposal["before_asset"],
                "source_id": proposal["source_id"],
                "report_id": proposal["report_id"],
                "source_snapshot": source_first,
                "desired_context": desired,
                "before_context": proposal["before_context"],
                "after_context": written,
                "retained_until": proposal["retained_until"],
                "accepted_at": now,
            }
            self._insert(
                connection,
                "pddb_history",
                ("tenant_id", "bridge_id", "sequence", "retained_until"),
                (
                    tenant,
                    proposal["bridge_id"],
                    new_revision,
                    proposal["retained_until"],
                ),
                history_payload,
            )
            self._record_operation(
                connection,
                tenant,
                "proposal.reconcile",
                key_sha,
                request_sha,
                "application",
                application_id,
            )
            self._audit(
                connection,
                tenant,
                proposal["bridge_id"],
                "proposal_reconciled",
                application_id,
                actor_sha,
                {
                    "action": proposal["action"],
                    "outcome": outcome,
                    "bridge_revision": new_revision,
                    "context_revision": written["revision"],
                    "context_record_sha256": written["record_sha256"],
                },
                now,
            )
            connection.commit()
        return self.get_application(tenant, application_id)

    def propose_rollback(
        self,
        tenant_id: str,
        bridge_id: str,
        *,
        target_bridge_revision: int,
        expected_bridge_revision: int,
        expected_context_revision: int,
        expected_context_record_sha256: str,
        retained_until: float,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Stage restoration of one still-fresh previously accepted context."""

        tenant = _tenant(tenant_id)
        bridge = _token(bridge_id, "bridge_id")
        target_revision = _revision(
            target_bridge_revision,
            "target_bridge_revision",
            positive=True,
        )
        expected_revision = _revision(
            expected_bridge_revision,
            "expected_bridge_revision",
            positive=True,
        )
        context_revision = _revision(
            expected_context_revision,
            "expected_context_revision",
            positive=True,
        )
        context_digest = _digest(
            expected_context_record_sha256,
            "expected_context_record_sha256",
        )
        if target_revision >= expected_revision:
            raise DiscoveryDataUseBridgeValidationError(
                "rollback target must precede the current bridge revision"
            )
        now = self._now()
        retained = _retained_until(retained_until, now)
        actor_sha = self._actor_sha256(tenant)
        _key, key_sha = self._idempotency(idempotency_key)
        request = {
            "action": "rollback",
            "bridge_id": bridge,
            "target_bridge_revision": target_revision,
            "expected_bridge_revision": expected_revision,
            "expected_context_revision": context_revision,
            "expected_context_record_sha256": context_digest,
            "retained_until": retained,
            "actor_sha256": actor_sha,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            replay = self._operation(
                connection,
                tenant,
                "proposal.rollback",
                key_sha,
                request_sha,
            )
            if replay is not None:
                kind, result_id = replay
                if kind != "proposal":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "rollback idempotency result kind is invalid"
                    )
                return self._proposal_by_id(connection, tenant, result_id)
            head = self._head_payload(connection, tenant, bridge)
            row = connection.execute(
                "SELECT * FROM pddb_history WHERE tenant_id=? AND bridge_id=? AND sequence=?",
                (tenant, bridge, target_revision),
            ).fetchone()
            if head is None or row is None:
                raise DiscoveryDataUseBridgeNotFound(
                    "rollback head or target history was not found"
                )
            target = self._payload(
                row,
                "bridge rollback target",
                table="pddb_history",
            )
        if head["revision"] != expected_revision:
            raise DiscoveryDataUseBridgeConflict("rollback bridge head drifted")
        current_first = self._read_target(tenant, head["asset_id"])
        current_second = self._read_target(tenant, head["asset_id"])
        if not _same(current_first["authority_sha256"], current_second["authority_sha256"]):
            raise DiscoveryDataUseBridgeConflict("rollback target drifted between reads")
        if current_first["asset"] != head["asset_authority"]:
            raise DiscoveryDataUseBridgeConflict("rollback asset authority drifted")
        current_context = current_first["context"]
        if (
            current_context is None
            or current_context != head["context"]
            or current_context["revision"] != context_revision
            or not _same(current_context["record_sha256"], context_digest)
        ):
            raise DiscoveryDataUseBridgeConflict("rollback current context pin drifted")
        source_first = self._reread_discovery(target["source_snapshot"], now)
        source_second = self._reread_discovery(source_first, now)
        if not _same(source_first["authority_sha256"], source_second["authority_sha256"]):
            raise DiscoveryDataUseBridgeConflict("rollback source drifted between reads")
        if retained > source_first["report_retention_until"]:
            raise DiscoveryDataUseBridgeValidationError(
                "rollback retention cannot outlive the source report"
            )
        proposal_id = f"PDDR-{key_sha[:32]}"
        payload = {
            "schema": PROPOSAL_SCHEMA,
            "tenant_id": tenant,
            "proposal_id": proposal_id,
            "bridge_id": bridge,
            "action": "rollback",
            "asset_id": head["asset_id"],
            "source_id": target["source_id"],
            "report_id": target["report_id"],
            "source_snapshot": source_first,
            "desired_context": target["desired_context"],
            "before_asset": current_first["asset"],
            "before_context": current_context,
            "expected_bridge_revision": expected_revision,
            "rollback_target_bridge_revision": target_revision,
            "retained_until": retained,
            "created_by_sha256": actor_sha,
            "created_at": now,
        }
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation(
                connection,
                tenant,
                "proposal.rollback",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                kind, result_id = replay
                if kind != "proposal":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "rollback idempotency result kind is invalid"
                    )
                return self.get_proposal(tenant, result_id)
            self._assert_bridge_revision(
                connection,
                tenant,
                bridge,
                expected_revision,
                head["asset_id"],
                head["source_id"],
            )
            self._insert(
                connection,
                "pddb_proposals",
                ("tenant_id", "proposal_id", "bridge_id", "action", "retained_until"),
                (tenant, proposal_id, bridge, "rollback", retained),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                "proposal.rollback",
                key_sha,
                request_sha,
                "proposal",
                proposal_id,
            )
            self._audit(
                connection,
                tenant,
                bridge,
                "rollback_proposal_created",
                proposal_id,
                actor_sha,
                {
                    "target_bridge_revision": target_revision,
                    "classification_sha256": source_first["classification_sha256"],
                },
                now,
            )
            connection.commit()
        return self.get_proposal(tenant, proposal_id)

    def admit_application(
        self, tenant_id: str, proposal_id: str, *,
        expected_proposal_integrity_sha256: str, idempotency_key: str,
    ) -> bool:
        """Retain one UI application admission before the target writer runs.

        A repeated admission is an original-read opportunity, never permission
        to repeat an unsettled write. Existing reconciliation remains the only
        target writer; this marker uses the existing integrity-bound ledger.
        """
        tenant, proposal_key = _tenant(tenant_id), _token(proposal_id, "proposal_id")
        actor = self._actor_sha256(tenant)
        pin = _digest(expected_proposal_integrity_sha256, "proposal integrity")
        _, key_sha = self._idempotency(idempotency_key)
        request_sha = _sha256({"proposal_id": proposal_key, "proposal_sha256": pin, "actor": actor})
        with self._connect() as connection:
            self._begin(connection)
            proposal = self._proposal_by_id(connection, tenant, proposal_key)
            if not _same(proposal["integrity_sha256"], pin) or proposal["created_by_sha256"] != actor:
                raise DiscoveryDataUseBridgeConflict("review authority changed")
            replay = self._operation(connection, tenant, "application.admission", key_sha, request_sha)
            if replay is not None:
                if replay != ("proposal", proposal_key):
                    raise DiscoveryDataUseBridgeIntegrityError("application admission binding is invalid")
                return False
            if self._application_admitted_on(connection, tenant, proposal_key):
                raise DiscoveryDataUseBridgeConflict("this review already has an application attempt; read its original outcome")
            self._record_operation(connection, tenant, "application.admission", key_sha,
                                   request_sha, "proposal", proposal_key)
            self._audit(connection, tenant, proposal["bridge_id"], "application_admitted", proposal_key,
                        actor, {"proposal_integrity_sha256": pin}, self._now())
        return True

    def _application_admitted_on(self, connection, tenant: str, proposal_id: str) -> bool:
        rows = connection.execute(
            "SELECT * FROM pddb_operations WHERE tenant_id=? AND namespace=? AND result_id=?",
            (tenant, "application.admission", proposal_id),
        ).fetchall()
        for row in rows:
            payload = self._payload(row, "application admission", table="pddb_operations")
            if (payload["tenant_id"], payload["namespace"], payload["result_kind"], payload["result_id"]) != (
                tenant, "application.admission", "proposal", proposal_id,
            ):
                raise DiscoveryDataUseBridgeIntegrityError("application admission binding is invalid")
        return bool(rows)

    def application_admitted(self, tenant_id: str, proposal_id: str) -> bool:
        tenant, proposal = _tenant(tenant_id), _token(proposal_id, "proposal_id")
        with self._connect() as connection:
            return self._application_admitted_on(connection, tenant, proposal)

    def get_proposal(self, tenant_id: str, proposal_id: str) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        proposal = _token(proposal_id, "proposal_id")
        with self._connect() as connection:
            return self._proposal_by_id(connection, tenant, proposal)

    def get_application(self, tenant_id: str, application_id: str) -> dict[str, Any]:
        tenant = _tenant(tenant_id)
        application = _token(application_id, "application_id")
        with self._connect() as connection:
            return self._application_by_id(connection, tenant, application)

    def get_head(self, tenant_id: str, bridge_id: str) -> dict[str, Any] | None:
        tenant = _tenant(tenant_id)
        bridge = _token(bridge_id, "bridge_id")
        with self._connect() as connection:
            return self._head_payload(connection, tenant, bridge)

    def history(
        self,
        tenant_id: str,
        bridge_id: str,
        *,
        limit: int = 100,
    ) -> Mapping[str, object]:
        tenant = _tenant(tenant_id)
        bridge = _token(bridge_id, "bridge_id")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise DiscoveryDataUseBridgeValidationError("history limit is outside its bound")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pddb_history WHERE tenant_id=? AND bridge_id=? "
                "ORDER BY sequence DESC LIMIT ?",
                (tenant, bridge, limit + 1),
            ).fetchall()
        return {
            "items": [
                self._payload(row, "bridge history", table="pddb_history") for row in rows[:limit]
            ],
            "truncated": len(rows) > limit,
        }

    def purge_expired(
        self,
        tenant_id: str,
        *,
        cutoff: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        """Apply retention while preserving minimized immutable audit evidence."""

        tenant = _tenant(tenant_id)
        moment = _timestamp(cutoff, "cutoff")
        now = self._now()
        if moment > now:
            raise DiscoveryDataUseBridgeValidationError("retention cutoff cannot be in the future")
        actor_sha = self._actor_sha256(tenant)
        _key, key_sha = self._idempotency(idempotency_key)
        request = {
            "action": "purge_expired",
            "cutoff": moment,
            "actor_sha256": actor_sha,
        }
        request_sha = _sha256(request)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation(
                connection,
                tenant,
                "retention.purge",
                key_sha,
                request_sha,
            )
            if replay is not None:
                connection.rollback()
                kind, result_id = replay
                if kind != "purge":
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "retention idempotency result kind is invalid"
                    )
                parts = result_id.split(":")
                if len(parts) != 4 or any(not part.isdigit() for part in parts):
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "retention idempotency result is invalid"
                    )
                return {
                    "proposals": int(parts[0]),
                    "applications": int(parts[1]),
                    "history": int(parts[2]),
                    "heads": int(parts[3]),
                }
            proposal_count = connection.execute(
                "DELETE FROM pddb_proposals WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            application_count = connection.execute(
                "DELETE FROM pddb_applications WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            history_count = connection.execute(
                "DELETE FROM pddb_history WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            head_count = connection.execute(
                "DELETE FROM pddb_heads WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            result_id = f"{proposal_count}:{application_count}:{history_count}:{head_count}"
            self._record_operation(
                connection,
                tenant,
                "retention.purge",
                key_sha,
                request_sha,
                "purge",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "retention",
                "retention_purged",
                result_id,
                actor_sha,
                {
                    "cutoff": moment,
                    "proposals": proposal_count,
                    "applications": application_count,
                    "history": history_count,
                    "heads": head_count,
                },
                now,
            )
            connection.commit()
        return {
            "proposals": proposal_count,
            "applications": application_count,
            "history": history_count,
            "heads": head_count,
        }

    def verify_integrity(self, tenant_id: str) -> Mapping[str, int | str]:
        tenant = _tenant(tenant_id)
        counts = {
            "proposals": 0,
            "applications": 0,
            "heads": 0,
            "history": 0,
            "operations": 0,
            "audit_events": 0,
        }
        with self._connect() as connection:
            for table, key, label in (
                ("pddb_proposals", "proposals", "bridge proposal"),
                ("pddb_applications", "applications", "bridge application"),
                ("pddb_heads", "heads", "bridge head"),
                ("pddb_history", "history", "bridge history"),
                ("pddb_operations", "operations", "bridge operation"),
            ):
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload = self._payload(row, label, table=table)
                    if payload.get("tenant_id") != tenant:
                        raise DiscoveryDataUseBridgeIntegrityError(
                            f"{key} tenant binding is invalid"
                        )
                    counts[key] += 1
            heads = connection.execute(
                "SELECT * FROM pddb_heads WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in heads:
                head = self._payload(row, "bridge head", table="pddb_heads")
                latest = connection.execute(
                    "SELECT * FROM pddb_history WHERE tenant_id=? AND bridge_id=? "
                    "ORDER BY sequence DESC LIMIT 1",
                    (tenant, head["bridge_id"]),
                ).fetchone()
                if latest is None:
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "bridge head has no immutable history"
                    )
                history = self._payload(
                    latest,
                    "bridge history",
                    table="pddb_history",
                )
                if (
                    history["sequence"] != head["revision"]
                    or history["application_id"] != head["application_id"]
                    or history["after_context"] != head["context"]
                ):
                    raise DiscoveryDataUseBridgeIntegrityError(
                        "bridge head differs from latest history"
                    )
            audit_rows = connection.execute(
                "SELECT * FROM pddb_audit WHERE tenant_id=? ORDER BY bridge_id,sequence",
                (tenant,),
            ).fetchall()
            previous_by_bridge: dict[str, str] = {}
            sequence_by_bridge: dict[str, int] = {}
            terminal = "0" * 64
            for row in audit_rows:
                payload = self._payload(row, "bridge audit", table="pddb_audit")
                bridge = str(payload.get("bridge_id"))
                expected_sequence = sequence_by_bridge.get(bridge, 0) + 1
                previous = previous_by_bridge.get(bridge, "0" * 64)
                if (
                    payload.get("tenant_id") != tenant
                    or payload.get("sequence") != expected_sequence
                    or payload.get("previous_integrity_sha256") != previous
                ):
                    raise DiscoveryDataUseBridgeIntegrityError("bridge audit chain is invalid")
                terminal = str(row["integrity_sha256"])
                previous_by_bridge[bridge] = terminal
                sequence_by_bridge[bridge] = expected_sequence
                counts["audit_events"] += 1
        return {**counts, "terminal_audit_sha256": terminal}


__all__ = [
    "APPLICATION_SCHEMA",
    "AUDIT_SCHEMA",
    "ClassificationPin",
    "DiscoveryDataUseBridgeConfigError",
    "DiscoveryDataUseBridgeConflict",
    "DiscoveryDataUseBridgeError",
    "DiscoveryDataUseBridgeIntegrityError",
    "DiscoveryDataUseBridgeNotFound",
    "DiscoveryDataUseBridgeValidationError",
    "HEAD_SCHEMA",
    "HISTORY_SCHEMA",
    "PROPOSAL_SCHEMA",
    "PrivacyDiscoveryDataUseBridgeStore",
    "enabled",
    "require_enabled",
]
