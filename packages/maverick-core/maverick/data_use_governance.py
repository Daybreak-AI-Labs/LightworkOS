"""Tenant-explicit data-use authority for policy compilation.

This module is the provider-neutral authority plane for data-use governance.
It deliberately stores opaque identifiers, machine-readable policy, and
SHA-256 evidence bindings rather than raw personal data, credentials, SQL, or
provider secrets.  Every mutation is tenant-scoped, compare-and-swap (CAS)
protected, idempotent, and digest checked on read.

The four decision contexts are independent records: business purpose,
regulatory authority, consent authority, and observed classification.  A
caller cannot replace them with one self-asserted request payload.  Decisions
pin the exact asset, field, context, reviewed-label, policy, exception, and
request revisions used.  The companion compiler revalidates those bindings
before producing control intermediate representation (IR).

No provider adapter or credential surface is implemented here.  Consequently
``provider_writes_possible`` remains false for this authority.
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
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .data_use_sqlite import immediate_transaction, private_connection
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

SCHEMA_VERSION = 1
ASSET_SCHEMA = "lightwork.data-use.asset.v1"
FIELD_SCHEMA = "lightwork.data-use.field.v1"
LINEAGE_SCHEMA = "lightwork.data-use.lineage.v1"
CONTEXT_SCHEMA = "lightwork.data-use.context-authority.v1"
LABEL_SCHEMA = "lightwork.data-use.machine-label.v1"
LABEL_ASSIGNMENT_SCHEMA = "lightwork.data-use.label-assignment.v1"
POLICY_SCHEMA = "lightwork.data-use.policy.v1"
POLICY_VERSION_SCHEMA = "lightwork.data-use.policy-version.v1"
EXCEPTION_SCHEMA = "lightwork.data-use.policy-exception.v1"
REQUEST_SCHEMA = "lightwork.data-use.request.v1"
DECISION_SCHEMA = "lightwork.data-use.authorization-decision.v1"
AUTHORITY_BUNDLE_SCHEMA = "lightwork.data-use.compilation-authority.v1"

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SQL_COMMENT_RE = re.compile(r"(?:--|/\*|\*/|;)")

_MAX_JSON_BYTES = 512 * 1024
_MAX_LIST_ITEMS = 256
_MAX_FIELDS_PER_REQUEST = 256
_MAX_POLICY_CONTROLS = 128
_MAX_READ_LIMIT = 500
_MAX_EXCEPTION_SECONDS = 366 * 24 * 60 * 60

CONTEXT_KINDS = (
    "business_purpose",
    "regulatory",
    "consent",
    "observed_classification",
)
_CONTEXT_KINDS = frozenset(CONTEXT_KINDS)
_ASSET_TYPES = frozenset(
    {
        "table",
        "view",
        "file",
        "stream",
        "api",
        "dataset",
        "model_input",
        "model_output",
    }
)
FIELD_TYPES = frozenset(
    {
        "string",
        "integer",
        "number",
        "boolean",
        "date",
        "datetime",
        "uuid",
        "binary",
        "json",
        "object",
        "array",
    }
)
_ACTIONS = frozenset({"read", "export", "train", "analyze", "share", "write"})
CONTROL_EFFECTS = frozenset({"allow", "deny", "mask", "row_filter", "review"})
MASKING_METHODS = frozenset(
    {
        "redact",
        "null",
        "hash_sha256",
        "tokenize",
        "preserve_last4",
        "bucket",
        "generalize_date",
    }
)
_POLICY_STATES = frozenset({"draft", "active", "retired"})
_EXCEPTION_STATES = frozenset({"requested", "approved", "denied", "closed"})
_REQUEST_STATES = frozenset({"pending", "authorized", "denied", "review"})
_EFFECT_RANK = {"allow": 0, "mask": 1, "row_filter": 2, "review": 3, "deny": 4}
_MASK_RANK = {
    "preserve_last4": 0,
    "hash_sha256": 1,
    "tokenize": 2,
    "bucket": 3,
    "generalize_date": 3,
    "null": 4,
    "redact": 5,
}


class DataUseGovernanceError(RuntimeError):
    """Base error for data-use authority operations."""


class DataUseValidationError(DataUseGovernanceError, ValueError):
    """Input is outside the closed data-use contract."""


class DataUseConflict(DataUseGovernanceError):
    """A CAS precondition did not hold."""


class DataUseIdempotencyConflict(DataUseGovernanceError):
    """An idempotency key was rebound to different content."""


class DataUseNotFound(DataUseGovernanceError):
    """A tenant-scoped authority record does not exist."""


class DataUseMissingAuthority(DataUseGovernanceError):
    """One or more independently sourced authorities are absent."""


class DataUseStaleAuthority(DataUseGovernanceError):
    """A bound authority is expired or no longer current."""


class DataUseCorruptionError(DataUseGovernanceError):
    """Persisted authority or idempotency material failed validation."""


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
        raise DataUseValidationError("data-use material must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise DataUseValidationError("data-use material exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _strict_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DataUseCorruptionError("stored JSON contains duplicate object keys")
        result[key] = value
    return result


def _loads(value: object, label: str) -> Any:
    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_JSON_BYTES:
        raise DataUseCorruptionError(f"stored {label} is not bounded JSON")
    try:
        return json.loads(value, object_pairs_hook=_strict_object_pairs)
    except DataUseCorruptionError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise DataUseCorruptionError(f"stored {label} is invalid JSON") from exc


def _known_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise DataUseValidationError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DataUseValidationError(f"{label} must be an object")
    return value


def _token(value: object, label: str, *, idem: bool = False) -> str:
    pattern = _IDEMPOTENCY_RE if idem else _TOKEN_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DataUseValidationError(f"{label} is not a bounded opaque identifier")
    if _CONTROL_RE.search(value) or _SQL_COMMENT_RE.search(value):
        raise DataUseValidationError(f"{label} contains prohibited syntax")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise DataUseValidationError("tenant_id is invalid") from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DataUseValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


_LIMIT_BOUNDS = {
    "max_assets": (1, 1_000_000),
    "max_fields": (1, 10_000_000),
    "max_lineage_edges": (1, 20_000_000),
    "max_context_age_seconds": (60, 31_536_000),
}
_CAPPED_RECORDS = {"asset": "max_assets", "field": "max_fields", "lineage": "max_lineage_edges"}


def data_use_limits(config: Mapping[str, Any] | None = None) -> dict[str, int]:
    """``[data_use_governance.limits]`` values that are set.

    ``max_assets``, ``max_fields`` and ``max_lineage_edges`` cap how many of
    each a workspace may register; ``max_context_age_seconds`` is the oldest a
    decision context may be (it is stale after that even if declared fresher).
    Unset keeps the historical behaviour: no workspace caps, and contexts stay
    fresh until the time their source declared.
    """
    if config is None:
        from .config import load_config

        config = load_config() or {}
    root = config.get("data_use_governance") if isinstance(config, Mapping) else None
    section = root.get("limits") if isinstance(root, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    selected: dict[str, int] = {}
    for key, (lower, upper) in _LIMIT_BOUNDS.items():
        if key not in section:
            continue
        value = section[key]
        if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
            raise DataUseValidationError(
                f"data-use limit {key} must be between {lower} and {upper}"
            )
        selected[key] = value
    return selected


def context_expires_at(context: Mapping[str, Any], max_age: int | None) -> float:
    """When a context stops counting: its declared end or its age limit."""
    fresh_until = float(context["fresh_until"])
    if max_age is None:
        return fresh_until
    return min(fresh_until, float(context["observed_at"]) + max_age)


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise DataUseValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DataUseValidationError(f"{label} must be a non-negative integer")
    return value


def _positive_revision(value: object, label: str) -> int:
    result = _revision(value, label)
    if result < 1:
        raise DataUseValidationError(f"{label} must be positive")
    return result


def _bounded_tokens(
    value: object,
    label: str,
    *,
    maximum: int = _MAX_LIST_ITEMS,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise DataUseValidationError(f"{label} must be a list")
    if len(value) > maximum or (not value and not allow_empty):
        qualifier = "one or more" if not allow_empty else "zero or more"
        raise DataUseValidationError(f"{label} must contain {qualifier} bounded values")
    result = tuple(sorted({_token(item, f"{label} item") for item in value}))
    if not result and not allow_empty:
        raise DataUseValidationError(f"{label} cannot collapse to an empty set")
    return result


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise DataUseValidationError(f"{label} must be boolean")
    return value


def _normalize_scope(value: object) -> dict[str, list[str]]:
    scope = _mapping(value, "policy scope")
    allowed = frozenset({"asset_ids", "field_ids", "project_ids", "actions"})
    _known_keys(scope, allowed, "policy scope")
    result: dict[str, list[str]] = {}
    for key in ("asset_ids", "field_ids", "project_ids"):
        result[key] = list(_bounded_tokens(scope.get(key, ()), key, allow_empty=True))
    actions = _bounded_tokens(scope.get("actions", ()), "actions", allow_empty=True)
    unknown_actions = sorted(set(actions) - _ACTIONS)
    if unknown_actions:
        raise DataUseValidationError(
            "policy scope contains unsupported actions: " + ", ".join(unknown_actions)
        )
    result["actions"] = list(actions)
    return result


def _normalize_conditions(value: object) -> dict[str, list[str]]:
    conditions = _mapping(value, "policy conditions")
    allowed = frozenset(
        {
            "business_purpose_any",
            "regulatory_any",
            "consent_any",
            "observed_classification_any",
            "label_any",
        }
    )
    _known_keys(conditions, allowed, "policy conditions")
    return {
        key: list(_bounded_tokens(conditions.get(key, ()), key, allow_empty=True))
        for key in sorted(allowed)
    }


def _normalize_control(value: object) -> dict[str, Any]:
    control = _mapping(value, "policy control")
    allowed = frozenset({"control_id", "effect", "field_ids", "mask_method", "row_filter"})
    _known_keys(control, allowed, "policy control")
    control_id = _token(control.get("control_id"), "control_id")
    effect = _token(control.get("effect"), "effect")
    if effect not in CONTROL_EFFECTS:
        raise DataUseValidationError("control effect is unsupported")
    field_ids = list(
        _bounded_tokens(control.get("field_ids", ()), "control field_ids", allow_empty=True)
    )
    mask_method = control.get("mask_method")
    row_filter = control.get("row_filter")
    if effect == "mask":
        method = _token(mask_method, "mask_method")
        if method not in MASKING_METHODS:
            raise DataUseValidationError("masking method is unsupported")
        if row_filter is not None:
            raise DataUseValidationError("mask control cannot contain a row filter")
        mask_method = method
    elif mask_method is not None:
        raise DataUseValidationError("only mask controls may select a masking method")
    if effect == "row_filter":
        if not isinstance(row_filter, Mapping):
            raise DataUseValidationError("row_filter control requires a structured AST")
        # Compiler performs field/type-aware AST validation.  Reject obvious
        # raw-provider escape hatches before an active policy can be created.
        raw = _canonical(dict(row_filter)).decode("ascii")
        if _SQL_COMMENT_RE.search(raw) or re.search(r'"(?:sql|query|statement)"\s*:', raw):
            raise DataUseValidationError("row_filter must not contain raw SQL")
        row_filter = json.loads(raw)
    elif row_filter is not None:
        raise DataUseValidationError("only row_filter controls may contain an AST")
    return {
        "control_id": control_id,
        "effect": effect,
        "field_ids": field_ids,
        "mask_method": mask_method,
        "row_filter": row_filter,
    }


def normalize_policy_document(value: object) -> dict[str, Any]:
    """Return a closed, deterministic policy document."""

    document = _mapping(value, "policy document")
    _known_keys(
        document,
        frozenset({"scope", "conditions", "controls"}),
        "policy document",
    )
    controls_raw = document.get("controls")
    if isinstance(controls_raw, (str, bytes)) or not isinstance(controls_raw, Sequence):
        raise DataUseValidationError("policy controls must be a list")
    if not 1 <= len(controls_raw) <= _MAX_POLICY_CONTROLS:
        raise DataUseValidationError("policy controls are empty or exceed their bound")
    controls = [_normalize_control(item) for item in controls_raw]
    ids = [item["control_id"] for item in controls]
    if len(set(ids)) != len(ids):
        raise DataUseValidationError("policy control identifiers must be unique")
    controls.sort(key=lambda item: item["control_id"])
    return {
        "scope": _normalize_scope(document.get("scope", {})),
        "conditions": _normalize_conditions(document.get("conditions", {})),
        "controls": controls,
    }


def _record_material(
    tenant: str,
    record_type: str,
    record_id: str,
    revision: int,
    body: Mapping[str, Any],
    created_at: float,
    updated_at: float,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant,
        "record_type": record_type,
        "record_id": record_id,
        "revision": revision,
        "body": dict(body),
        "created_at": created_at,
        "updated_at": updated_at,
    }


def _public_record(row: sqlite3.Row, *, expected_tenant: str) -> dict[str, Any]:
    tenant = str(row["tenant_id"])
    if tenant != expected_tenant:
        raise DataUseCorruptionError("stored record crossed a tenant boundary")
    record_type = str(row["record_type"])
    record_id = str(row["record_id"])
    revision = int(row["revision"])
    created_at = float(row["created_at"])
    updated_at = float(row["updated_at"])
    body = _loads(row["body_json"], "record body")
    if not isinstance(body, dict) or body.get("tenant_id") != tenant:
        raise DataUseCorruptionError("stored record body has an invalid tenant binding")
    expected = _sha256(
        _record_material(
            tenant,
            record_type,
            record_id,
            revision,
            body,
            created_at,
            updated_at,
        )
    )
    actual = str(row["record_sha256"])
    if not _DIGEST_RE.fullmatch(actual) or not hmac.compare_digest(actual, expected):
        raise DataUseCorruptionError("stored record digest does not match")
    if body.get("record_id") != record_id or body.get("schema") is None:
        raise DataUseCorruptionError("stored record identity is malformed")
    return {
        **body,
        "revision": revision,
        "record_sha256": actual,
        "created_at": created_at,
        "updated_at": updated_at,
    }


class DataUseGovernanceStore:
    """SQLite-backed, explicit-tenant data-use authority.

    A store instance is safe to construct per request.  Each operation opens a
    new connection and uses ``BEGIN IMMEDIATE`` so CAS checks and idempotency
    claims share one durable transaction across processes.
    """

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        # Hex, never base64url: token_urlsafe can emit "--", which the
        # prohibited-syntax check treats as a SQL comment -- the store then
        # refused an id it minted itself (a ~0.5%-per-id CI flake and a
        # real production failure). Same 144 bits of entropy.
        self._id_factory = id_factory or (lambda prefix: f"{prefix}-{secrets.token_hex(18)}")
        self._initialize()

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "authority clock")
        except (KeyboardInterrupt, SystemExit):
            raise
        except DataUseValidationError:
            raise
        except Exception as exc:
            raise DataUseGovernanceError("authority clock is unavailable") from exc

    def _new_id(self, prefix: str) -> str:
        return _token(self._id_factory(prefix), f"{prefix} identifier")

    @staticmethod
    def _tenant(value: object) -> str:
        return _tenant_id(value)

    @staticmethod
    def _idem(value: object) -> tuple[str, str]:
        key = _token(value, "idempotency_key", idem=True)
        return key, hashlib.sha256(key.encode("ascii")).hexdigest()

    @contextlib.contextmanager
    def _connect(self):
        with private_connection(
            self.path, ensure_directory=ensure_private_directory, ensure_file=ensure_private_file,
        ) as conn:
            yield conn

    @contextlib.contextmanager
    def _transaction(self):
        with immediate_transaction(self._connect) as conn:
            yield conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS data_use_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS data_use_records (
                    tenant_id TEXT NOT NULL,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    body_json TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, record_type, record_id)
                );
                CREATE INDEX IF NOT EXISTS data_use_records_type
                    ON data_use_records(tenant_id, record_type, record_id);
                CREATE TABLE IF NOT EXISTS data_use_idempotency (
                    tenant_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, namespace, key_sha256)
                );
                CREATE TRIGGER IF NOT EXISTS data_use_immutable_records_no_update
                    BEFORE UPDATE ON data_use_records
                    WHEN OLD.record_type IN ('policy_version', 'label_version', 'decision')
                    BEGIN SELECT RAISE(ABORT, 'immutable data-use record'); END;
                CREATE TRIGGER IF NOT EXISTS data_use_immutable_records_no_delete
                    BEFORE DELETE ON data_use_records
                    WHEN OLD.record_type IN ('policy_version', 'label_version', 'decision')
                    BEGIN SELECT RAISE(ABORT, 'immutable data-use record'); END;
                CREATE TRIGGER IF NOT EXISTS data_use_idempotency_no_update
                    BEFORE UPDATE ON data_use_idempotency
                    BEGIN SELECT RAISE(ABORT, 'immutable data-use idempotency'); END;
                CREATE TRIGGER IF NOT EXISTS data_use_idempotency_no_delete
                    BEFORE DELETE ON data_use_idempotency
                    BEGIN SELECT RAISE(ABORT, 'immutable data-use idempotency'); END;
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO data_use_meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
            row = conn.execute(
                "SELECT value FROM data_use_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or str(row["value"]) != str(SCHEMA_VERSION):
                raise DataUseGovernanceError("unsupported data-use authority schema")

    @staticmethod
    def _idempotent_result(
        conn: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT request_sha256, result_json, result_sha256 "
            "FROM data_use_idempotency WHERE tenant_id = ? AND namespace = ? "
            "AND key_sha256 = ?",
            (tenant, namespace, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(str(row["request_sha256"]), request_sha256):
            raise DataUseIdempotencyConflict(
                "idempotency key was already used for different content"
            )
        result = _loads(row["result_json"], "idempotency result")
        if not isinstance(result, dict):
            raise DataUseCorruptionError("stored idempotency result is not an object")
        expected = _sha256(result)
        actual = str(row["result_sha256"])
        if not _DIGEST_RE.fullmatch(actual) or not hmac.compare_digest(actual, expected):
            raise DataUseCorruptionError("stored idempotency result digest does not match")
        return result

    @staticmethod
    def _save_idempotency(
        conn: sqlite3.Connection,
        *,
        tenant: str,
        namespace: str,
        key_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
        now: float,
    ) -> None:
        body = dict(result)
        conn.execute(
            "INSERT INTO data_use_idempotency(tenant_id, namespace, key_sha256, "
            "request_sha256, result_json, result_sha256, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                tenant,
                namespace,
                key_sha256,
                request_sha256,
                _canonical(body).decode("ascii"),
                _sha256(body),
                now,
            ),
        )

    def _run_idempotent(
        self,
        *,
        tenant: str,
        namespace: str,
        idempotency_key: object,
        request: Mapping[str, Any],
        mutate: Callable[[sqlite3.Connection, float], dict[str, Any]],
    ) -> dict[str, Any]:
        from .authority_effects import authority_effect_fence

        _key, key_sha256 = self._idem(idempotency_key)
        request_sha256 = _sha256(dict(request))
        # Use the same local control-plane fence held across research process
        # admission. A rights/consent/policy mutation that commits first is
        # observed by that admission; one that loses the fence cannot land
        # between the final authority read and the candidate effect boundary.
        with authority_effect_fence(), self._transaction() as conn:
            replay = self._idempotent_result(
                conn,
                tenant=tenant,
                namespace=namespace,
                key_sha256=key_sha256,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            now = self._now()
            result = mutate(conn, now)
            self._save_idempotency(
                conn,
                tenant=tenant,
                namespace=namespace,
                key_sha256=key_sha256,
                request_sha256=request_sha256,
                result=result,
                now=now,
            )
            return result

    @staticmethod
    def _row(
        conn: sqlite3.Connection,
        tenant: str,
        record_type: str,
        record_id: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM data_use_records WHERE tenant_id = ? "
            "AND record_type = ? AND record_id = ?",
            (tenant, record_type, record_id),
        ).fetchone()

    def _get_on(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        record_type: str,
        record_id: str,
        *,
        required: bool = True,
    ) -> dict[str, Any] | None:
        row = self._row(conn, tenant, record_type, record_id)
        if row is None:
            if required:
                raise DataUseNotFound(f"{record_type} does not exist for this tenant")
            return None
        return _public_record(row, expected_tenant=tenant)

    def _list_on(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        record_type: str,
        *,
        limit: int = _MAX_READ_LIMIT,
    ) -> list[dict[str, Any]]:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_READ_LIMIT
        ):
            raise DataUseValidationError("limit is outside the supported range")
        rows = conn.execute(
            "SELECT * FROM data_use_records WHERE tenant_id = ? AND record_type = ? "
            "ORDER BY record_id LIMIT ?",
            (tenant, record_type, limit),
        ).fetchall()
        return [_public_record(row, expected_tenant=tenant) for row in rows]

    def _complete_authority_list_on(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        record_type: str,
    ) -> list[dict[str, Any]]:
        """Read an authority set or fail instead of silently truncating it."""

        rows = conn.execute(
            "SELECT * FROM data_use_records WHERE tenant_id = ? AND record_type = ? "
            "ORDER BY record_id LIMIT ?",
            (tenant, record_type, _MAX_READ_LIMIT + 1),
        ).fetchall()
        if len(rows) > _MAX_READ_LIMIT:
            raise DataUseMissingAuthority(
                f"{record_type} authority exceeds the safe decision bound"
            )
        return [_public_record(row, expected_tenant=tenant) for row in rows]

    @staticmethod
    def _insert_on(
        conn: sqlite3.Connection,
        *,
        tenant: str,
        record_type: str,
        record_id: str,
        body: Mapping[str, Any],
        now: float,
    ) -> dict[str, Any]:
        material = dict(body)
        if material.get("tenant_id") != tenant or material.get("record_id") != record_id:
            raise DataUseValidationError("record body identity does not match")
        limit_key = _CAPPED_RECORDS.get(record_type)
        cap = data_use_limits().get(limit_key) if limit_key else None
        if cap is not None:
            (count,) = conn.execute(
                "SELECT COUNT(*) FROM data_use_records WHERE tenant_id = ? AND record_type = ?",
                (tenant, record_type),
            ).fetchone()
            if count >= cap:
                raise DataUseValidationError(
                    f"this workspace already has the most {record_type} records "
                    "this installation allows"
                )
        revision = 1
        digest = _sha256(
            _record_material(tenant, record_type, record_id, revision, material, now, now)
        )
        try:
            conn.execute(
                "INSERT INTO data_use_records(tenant_id, record_type, record_id, "
                "revision, body_json, record_sha256, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    record_type,
                    record_id,
                    revision,
                    _canonical(material).decode("ascii"),
                    digest,
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise DataUseConflict("record already exists") from exc
        return {
            **material,
            "revision": revision,
            "record_sha256": digest,
            "created_at": now,
            "updated_at": now,
        }

    def _update_on(
        self,
        conn: sqlite3.Connection,
        *,
        tenant: str,
        record_type: str,
        record_id: str,
        expected_revision: int,
        body: Mapping[str, Any],
        now: float,
    ) -> dict[str, Any]:
        expected = _revision(expected_revision)
        current = self._get_on(conn, tenant, record_type, record_id)
        assert current is not None
        if current["revision"] != expected:
            raise DataUseConflict("record revision changed")
        material = dict(body)
        if material.get("tenant_id") != tenant or material.get("record_id") != record_id:
            raise DataUseValidationError("record body identity does not match")
        revision = expected + 1
        created_at = float(current["created_at"])
        digest = _sha256(
            _record_material(
                tenant,
                record_type,
                record_id,
                revision,
                material,
                created_at,
                now,
            )
        )
        cursor = conn.execute(
            "UPDATE data_use_records SET revision = ?, body_json = ?, "
            "record_sha256 = ?, updated_at = ? WHERE tenant_id = ? "
            "AND record_type = ? AND record_id = ? AND revision = ?",
            (
                revision,
                _canonical(material).decode("ascii"),
                digest,
                now,
                tenant,
                record_type,
                record_id,
                expected,
            ),
        )
        if cursor.rowcount != 1:
            raise DataUseConflict("record revision changed")
        return {
            **material,
            "revision": revision,
            "record_sha256": digest,
            "created_at": created_at,
            "updated_at": now,
        }

    def get_record(self, tenant_id: str, record_type: str, record_id: str) -> dict[str, Any] | None:
        """Read one record without leaking whether another tenant owns the id."""

        tenant = self._tenant(tenant_id)
        kind = _token(record_type, "record_type")
        identity = _token(record_id, "record_id")
        with self._connect() as conn:
            return self._get_on(conn, tenant, kind, identity, required=False)

    def list_records(
        self, tenant_id: str, record_type: str, *, limit: int = 100
    ) -> list[dict[str, Any]]:
        tenant = self._tenant(tenant_id)
        kind = _token(record_type, "record_type")
        with self._connect() as conn:
            return self._list_on(conn, tenant, kind, limit=limit)

    def put_asset(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        asset_type: str,
        catalog_binding_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create or CAS-update an opaque catalog asset."""

        tenant = self._tenant(tenant_id)
        identity = _token(asset_id, "asset_id")
        kind = _token(asset_type, "asset_type")
        if kind not in _ASSET_TYPES:
            raise DataUseValidationError("asset_type is unsupported")
        catalog_digest = _digest(catalog_binding_sha256, "catalog_binding_sha256")
        expected = _revision(expected_revision)
        request = {
            "asset_id": identity,
            "asset_type": kind,
            "catalog_binding_sha256": catalog_digest,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            semantic = {
                "schema": ASSET_SCHEMA,
                "tenant_id": tenant,
                "record_id": identity,
                "asset_id": identity,
                "asset_type": kind,
                "catalog_binding_sha256": catalog_digest,
            }
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            current = self._get_on(conn, tenant, "asset", identity, required=False)
            if current is None:
                if expected != 0:
                    raise DataUseConflict("asset does not exist at expected revision")
                return self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="asset",
                    record_id=identity,
                    body=body,
                    now=now,
                )
            if expected == 0:
                raise DataUseConflict("asset already exists")
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="asset",
                record_id=identity,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="put_asset",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def put_field(
        self,
        tenant_id: str,
        asset_id: str,
        field_id: str,
        *,
        data_type: str,
        nullable: bool,
        catalog_binding_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create or CAS-update a field within a tenant asset."""

        tenant = self._tenant(tenant_id)
        asset = _token(asset_id, "asset_id")
        field = _token(field_id, "field_id")
        field_type = _token(data_type, "data_type")
        if field_type not in FIELD_TYPES:
            raise DataUseValidationError("field data_type is unsupported")
        permits_null = _bool(nullable, "nullable")
        catalog_digest = _digest(catalog_binding_sha256, "catalog_binding_sha256")
        expected = _revision(expected_revision)
        record_id = f"{asset}:{field}"
        request = {
            "asset_id": asset,
            "field_id": field,
            "data_type": field_type,
            "nullable": permits_null,
            "catalog_binding_sha256": catalog_digest,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            self._get_on(conn, tenant, "asset", asset)
            semantic = {
                "schema": FIELD_SCHEMA,
                "tenant_id": tenant,
                "record_id": record_id,
                "asset_id": asset,
                "field_id": field,
                "data_type": field_type,
                "nullable": permits_null,
                "catalog_binding_sha256": catalog_digest,
            }
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            current = self._get_on(conn, tenant, "field", record_id, required=False)
            if current is None:
                if expected != 0:
                    raise DataUseConflict("field does not exist at expected revision")
                return self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="field",
                    record_id=record_id,
                    body=body,
                    now=now,
                )
            if expected == 0:
                raise DataUseConflict("field already exists")
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="field",
                record_id=record_id,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="put_field",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def put_lineage(
        self,
        tenant_id: str,
        lineage_id: str,
        *,
        source_asset_id: str,
        source_field_id: str,
        target_asset_id: str,
        target_field_id: str,
        transformation_sha256: str,
        observed_at: float,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create or CAS-update a field-level lineage edge."""

        tenant = self._tenant(tenant_id)
        identity = _token(lineage_id, "lineage_id")
        source_asset = _token(source_asset_id, "source_asset_id")
        source_field = _token(source_field_id, "source_field_id")
        target_asset = _token(target_asset_id, "target_asset_id")
        target_field = _token(target_field_id, "target_field_id")
        transform = _digest(transformation_sha256, "transformation_sha256")
        observed = _timestamp(observed_at, "observed_at")
        expected = _revision(expected_revision)
        if source_asset == target_asset and source_field == target_field:
            raise DataUseValidationError("lineage cannot be self-referential")
        request = {
            "lineage_id": identity,
            "source_asset_id": source_asset,
            "source_field_id": source_field,
            "target_asset_id": target_asset,
            "target_field_id": target_field,
            "transformation_sha256": transform,
            "observed_at": observed,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            self._get_on(conn, tenant, "field", f"{source_asset}:{source_field}")
            self._get_on(conn, tenant, "field", f"{target_asset}:{target_field}")
            semantic = {
                "schema": LINEAGE_SCHEMA,
                "tenant_id": tenant,
                "record_id": identity,
                "lineage_id": identity,
                "source_asset_id": source_asset,
                "source_field_id": source_field,
                "target_asset_id": target_asset,
                "target_field_id": target_field,
                "transformation_sha256": transform,
                "observed_at": observed,
            }
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            current = self._get_on(conn, tenant, "lineage", identity, required=False)
            if current is None:
                if expected != 0:
                    raise DataUseConflict("lineage does not exist at expected revision")
                return self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="lineage",
                    record_id=identity,
                    body=body,
                    now=now,
                )
            if expected == 0:
                raise DataUseConflict("lineage already exists")
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="lineage",
                record_id=identity,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="put_lineage",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    @staticmethod
    def _context_record_id(asset_id: str, context_kind: str) -> str:
        suffix = hashlib.sha256(f"{asset_id}\0{context_kind}".encode("ascii")).hexdigest()[:32]
        return f"ctx-{suffix}"

    def get_context_authority(
        self,
        tenant_id: str,
        asset_id: str,
        context_kind: str,
    ) -> dict[str, Any] | None:
        """Read one exact tenant/asset context without exposing internal IDs.

        This method is non-authorizing: it returns the same integrity-checked
        public record as :meth:`get_record` and does not infer completeness or
        freshness.  Callers remain responsible for checking all four
        independent context authorities before making a data-use decision.
        """

        tenant = self._tenant(tenant_id)
        asset = _token(asset_id, "asset_id")
        kind = _token(context_kind, "context_kind")
        if kind not in _CONTEXT_KINDS:
            raise DataUseValidationError("context_kind is unsupported")
        record_id = self._context_record_id(asset, kind)
        with self._connect() as conn:
            record = self._get_on(
                conn,
                tenant,
                "context",
                record_id,
                required=False,
            )
        if record is None:
            return None
        if (
            record.get("tenant_id") != tenant
            or record.get("asset_id") != asset
            or record.get("context_kind") != kind
            or record.get("schema") != CONTEXT_SCHEMA
        ):
            raise DataUseCorruptionError("context authority identity is malformed")
        return record

    def put_context_authority(
        self,
        tenant_id: str,
        asset_id: str,
        context_kind: str,
        *,
        values: Sequence[str],
        source_system: str,
        source_revision: int,
        source_authority_sha256: str,
        evidence_sha256: str,
        reviewer_id: str,
        reviewer_authority_sha256: str,
        observed_at: float,
        fresh_until: float,
        expected_revision: int,
        idempotency_key: str,
        before_write: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        """Record one independently supplied, reviewed decision context."""

        tenant = self._tenant(tenant_id)
        asset = _token(asset_id, "asset_id")
        kind = _token(context_kind, "context_kind")
        if kind not in _CONTEXT_KINDS:
            raise DataUseValidationError("context_kind is unsupported")
        normalized_values = _bounded_tokens(values, "context values")
        source = _token(source_system, "source_system")
        source_rev = _positive_revision(source_revision, "source_revision")
        source_digest = _digest(source_authority_sha256, "source_authority_sha256")
        evidence_digest = _digest(evidence_sha256, "evidence_sha256")
        reviewer = _token(reviewer_id, "reviewer_id")
        reviewer_digest = _digest(reviewer_authority_sha256, "reviewer_authority_sha256")
        observed = _timestamp(observed_at, "observed_at")
        fresh = _timestamp(fresh_until, "fresh_until")
        if fresh <= observed:
            raise DataUseValidationError("fresh_until must be after observed_at")
        expected = _revision(expected_revision)
        record_id = self._context_record_id(asset, kind)
        request = {
            "asset_id": asset,
            "context_kind": kind,
            "values": normalized_values,
            "source_system": source,
            "source_revision": source_rev,
            "source_authority_sha256": source_digest,
            "evidence_sha256": evidence_digest,
            "reviewer_id": reviewer,
            "reviewer_authority_sha256": reviewer_digest,
            "observed_at": observed,
            "fresh_until": fresh,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            if before_write is not None:
                before_write()
            if observed > now:
                raise DataUseValidationError("observed_at cannot be in the future")
            if fresh <= now:
                raise DataUseStaleAuthority("context authority is already stale")
            max_age = data_use_limits().get("max_context_age_seconds")
            if max_age is not None and fresh - observed > max_age:
                raise DataUseValidationError(
                    "context freshness is longer than this installation allows"
                )
            self._get_on(conn, tenant, "asset", asset)
            semantic = {
                "schema": CONTEXT_SCHEMA,
                "tenant_id": tenant,
                "record_id": record_id,
                "asset_id": asset,
                "context_kind": kind,
                "values": list(normalized_values),
                "source_system": source,
                "source_revision": source_rev,
                "source_authority_sha256": source_digest,
                "evidence_sha256": evidence_digest,
                "reviewer_id": reviewer,
                "reviewer_authority_sha256": reviewer_digest,
                "observed_at": observed,
                "fresh_until": fresh,
            }
            body = {**semantic, "context_sha256": _sha256(semantic)}
            current = self._get_on(conn, tenant, "context", record_id, required=False)
            if current is None:
                if expected != 0:
                    raise DataUseConflict("context does not exist at expected revision")
                return self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="context",
                    record_id=record_id,
                    body=body,
                    now=now,
                )
            if expected == 0:
                raise DataUseConflict("context already exists")
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="context",
                record_id=record_id,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace=f"put_context:{kind}",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def publish_machine_label(
        self,
        tenant_id: str,
        label_id: str,
        *,
        version: int,
        taxonomy_id: str,
        sensitivity: int,
        definition_sha256: str,
        reviewer_id: str,
        reviewer_authority_sha256: str,
        reviewed_at: float,
        expected_current_version: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Publish an immutable, human-reviewed machine-label version."""

        tenant = self._tenant(tenant_id)
        label = _token(label_id, "label_id")
        label_version = _positive_revision(version, "version")
        taxonomy = _token(taxonomy_id, "taxonomy_id")
        if (
            isinstance(sensitivity, bool)
            or not isinstance(sensitivity, int)
            or not 0 <= sensitivity <= 100
        ):
            raise DataUseValidationError("sensitivity must be an integer from 0 to 100")
        definition = _digest(definition_sha256, "definition_sha256")
        reviewer = _token(reviewer_id, "reviewer_id")
        reviewer_digest = _digest(reviewer_authority_sha256, "reviewer_authority_sha256")
        reviewed = _timestamp(reviewed_at, "reviewed_at")
        expected_version = _revision(expected_current_version, "expected_current_version")
        expected = _revision(expected_revision)
        request = {
            "label_id": label,
            "version": label_version,
            "taxonomy_id": taxonomy,
            "sensitivity": sensitivity,
            "definition_sha256": definition,
            "reviewer_id": reviewer,
            "reviewer_authority_sha256": reviewer_digest,
            "reviewed_at": reviewed,
            "expected_current_version": expected_version,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            if reviewed > now:
                raise DataUseValidationError("reviewed_at cannot be in the future")
            current = self._get_on(conn, tenant, "label", label, required=False)
            if current is None:
                if expected != 0 or expected_version != 0 or label_version != 1:
                    raise DataUseConflict("first label version must start at one")
            else:
                if current["revision"] != expected:
                    raise DataUseConflict("label revision changed")
                if current["state"] == "retired":
                    raise DataUseConflict("retired labels cannot be republished")
                if current["current_version"] != expected_version:
                    raise DataUseConflict("label version changed")
                if label_version != expected_version + 1:
                    raise DataUseValidationError("label versions must be contiguous")
            version_record_id = f"{label}:{label_version}"
            version_semantic = {
                "schema": LABEL_SCHEMA,
                "tenant_id": tenant,
                "record_id": version_record_id,
                "label_id": label,
                "version": label_version,
                "taxonomy_id": taxonomy,
                "sensitivity": sensitivity,
                "definition_sha256": definition,
                "reviewer_id": reviewer,
                "reviewer_authority_sha256": reviewer_digest,
                "reviewed_at": reviewed,
            }
            version_body = {
                **version_semantic,
                "label_sha256": _sha256(version_semantic),
            }
            version_record = self._insert_on(
                conn,
                tenant=tenant,
                record_type="label_version",
                record_id=version_record_id,
                body=version_body,
                now=now,
            )
            pointer_semantic = {
                "schema": LABEL_SCHEMA,
                "tenant_id": tenant,
                "record_id": label,
                "label_id": label,
                "current_version": label_version,
                "current_label_sha256": version_record["label_sha256"],
                "state": "active",
            }
            pointer_body = {
                **pointer_semantic,
                "semantic_sha256": _sha256(pointer_semantic),
            }
            if current is None:
                pointer = self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="label",
                    record_id=label,
                    body=pointer_body,
                    now=now,
                )
            else:
                pointer = self._update_on(
                    conn,
                    tenant=tenant,
                    record_type="label",
                    record_id=label,
                    expected_revision=expected,
                    body=pointer_body,
                    now=now,
                )
            return {**pointer, "version_authority": version_record}

        return self._run_idempotent(
            tenant=tenant,
            namespace="publish_machine_label",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def retire_machine_label(
        self,
        tenant_id: str,
        label_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        label = _token(label_id, "label_id")
        expected = _revision(expected_revision)
        request = {"label_id": label, "expected_revision": expected}

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            current = self._get_on(conn, tenant, "label", label)
            assert current is not None
            body = {
                key: value
                for key, value in current.items()
                if key
                not in {"revision", "record_sha256", "created_at", "updated_at", "semantic_sha256"}
            }
            body["state"] = "retired"
            body["semantic_sha256"] = _sha256(body)
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="label",
                record_id=label,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="retire_machine_label",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def assign_machine_label(
        self,
        tenant_id: str,
        asset_id: str,
        field_id: str,
        label_id: str,
        *,
        label_version: int,
        assignment_evidence_sha256: str,
        reviewer_id: str,
        reviewer_authority_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Bind an exact reviewed label version to an exact field authority."""

        tenant = self._tenant(tenant_id)
        asset = _token(asset_id, "asset_id")
        field = _token(field_id, "field_id")
        label = _token(label_id, "label_id")
        version = _positive_revision(label_version, "label_version")
        evidence = _digest(assignment_evidence_sha256, "assignment_evidence_sha256")
        reviewer = _token(reviewer_id, "reviewer_id")
        reviewer_digest = _digest(reviewer_authority_sha256, "reviewer_authority_sha256")
        expected = _revision(expected_revision)
        record_id = hashlib.sha256(f"{asset}\0{field}\0{label}".encode("ascii")).hexdigest()[:40]
        record_id = f"las-{record_id}"
        request = {
            "asset_id": asset,
            "field_id": field,
            "label_id": label,
            "label_version": version,
            "assignment_evidence_sha256": evidence,
            "reviewer_id": reviewer,
            "reviewer_authority_sha256": reviewer_digest,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            field_record = self._get_on(conn, tenant, "field", f"{asset}:{field}")
            pointer = self._get_on(conn, tenant, "label", label)
            version_record = self._get_on(conn, tenant, "label_version", f"{label}:{version}")
            assert field_record is not None and pointer is not None and version_record is not None
            if pointer["state"] != "active" or pointer["current_version"] != version:
                raise DataUseStaleAuthority("label version is not current and active")
            semantic = {
                "schema": LABEL_ASSIGNMENT_SCHEMA,
                "tenant_id": tenant,
                "record_id": record_id,
                "asset_id": asset,
                "field_id": field,
                "field_revision": field_record["revision"],
                "field_sha256": field_record["record_sha256"],
                "label_id": label,
                "label_version": version,
                "label_pointer_revision": pointer["revision"],
                "label_pointer_sha256": pointer["record_sha256"],
                "label_sha256": version_record["label_sha256"],
                "assignment_evidence_sha256": evidence,
                "reviewer_id": reviewer,
                "reviewer_authority_sha256": reviewer_digest,
                "status": "active",
            }
            body = {**semantic, "assignment_sha256": _sha256(semantic)}
            current = self._get_on(conn, tenant, "label_assignment", record_id, required=False)
            if current is None:
                if expected != 0:
                    raise DataUseConflict("label assignment does not exist")
                return self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="label_assignment",
                    record_id=record_id,
                    body=body,
                    now=now,
                )
            if expected == 0:
                raise DataUseConflict("label assignment already exists")
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="label_assignment",
                record_id=record_id,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="assign_machine_label",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def put_policy_version(
        self,
        tenant_id: str,
        policy_id: str,
        *,
        version: int,
        document: Mapping[str, Any],
        author_id: str,
        author_authority_sha256: str,
        expected_current_version: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create an immutable draft policy version under CAS."""

        tenant = self._tenant(tenant_id)
        policy = _token(policy_id, "policy_id")
        policy_version = _positive_revision(version, "version")
        normalized = normalize_policy_document(document)
        semantic_digest = _sha256(normalized)
        author = _token(author_id, "author_id")
        author_digest = _digest(author_authority_sha256, "author_authority_sha256")
        expected_version = _revision(expected_current_version, "expected_current_version")
        expected = _revision(expected_revision)
        request = {
            "policy_id": policy,
            "version": policy_version,
            "document": normalized,
            "author_id": author,
            "author_authority_sha256": author_digest,
            "expected_current_version": expected_version,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            current = self._get_on(conn, tenant, "policy", policy, required=False)
            if current is None:
                if expected != 0 or expected_version != 0 or policy_version != 1:
                    raise DataUseConflict("first policy version must start at one")
                active_version: int | None = None
            else:
                if current["revision"] != expected:
                    raise DataUseConflict("policy revision changed")
                if current["state"] == "retired":
                    raise DataUseConflict("retired policies cannot be revised")
                if current["current_version"] != expected_version:
                    raise DataUseConflict("policy version changed")
                if policy_version != expected_version + 1:
                    raise DataUseValidationError("policy versions must be contiguous")
                active_version = current.get("active_version")
            version_record_id = f"{policy}:{policy_version}"
            version_semantic = {
                "schema": POLICY_VERSION_SCHEMA,
                "tenant_id": tenant,
                "record_id": version_record_id,
                "policy_id": policy,
                "version": policy_version,
                "document": normalized,
                "semantic_sha256": semantic_digest,
                "author_id": author,
                "author_authority_sha256": author_digest,
            }
            version_record = self._insert_on(
                conn,
                tenant=tenant,
                record_type="policy_version",
                record_id=version_record_id,
                body=version_semantic,
                now=now,
            )
            pointer_semantic = {
                "schema": POLICY_SCHEMA,
                "tenant_id": tenant,
                "record_id": policy,
                "policy_id": policy,
                "current_version": policy_version,
                "current_semantic_sha256": semantic_digest,
                "active_version": active_version,
                "state": "draft",
                "reviewer_id": None,
                "reviewer_authority_sha256": None,
                "reviewed_at": None,
            }
            pointer_body = {
                **pointer_semantic,
                "semantic_sha256": _sha256(pointer_semantic),
            }
            if current is None:
                pointer = self._insert_on(
                    conn,
                    tenant=tenant,
                    record_type="policy",
                    record_id=policy,
                    body=pointer_body,
                    now=now,
                )
            else:
                pointer = self._update_on(
                    conn,
                    tenant=tenant,
                    record_type="policy",
                    record_id=policy,
                    expected_revision=expected,
                    body=pointer_body,
                    now=now,
                )
            return {**pointer, "version_authority": version_record}

        return self._run_idempotent(
            tenant=tenant,
            namespace="put_policy_version",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def activate_policy(
        self,
        tenant_id: str,
        policy_id: str,
        *,
        version: int,
        reviewer_id: str,
        reviewer_authority_sha256: str,
        reviewed_at: float,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Activate the current draft after independent human review."""

        tenant = self._tenant(tenant_id)
        policy = _token(policy_id, "policy_id")
        target_version = _positive_revision(version, "version")
        reviewer = _token(reviewer_id, "reviewer_id")
        reviewer_digest = _digest(reviewer_authority_sha256, "reviewer_authority_sha256")
        reviewed = _timestamp(reviewed_at, "reviewed_at")
        expected = _revision(expected_revision)
        request = {
            "policy_id": policy,
            "version": target_version,
            "reviewer_id": reviewer,
            "reviewer_authority_sha256": reviewer_digest,
            "reviewed_at": reviewed,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            if reviewed > now:
                raise DataUseValidationError("reviewed_at cannot be in the future")
            current = self._get_on(conn, tenant, "policy", policy)
            version_record = self._get_on(
                conn, tenant, "policy_version", f"{policy}:{target_version}"
            )
            assert current is not None and version_record is not None
            if current["revision"] != expected:
                raise DataUseConflict("policy revision changed")
            if current["state"] != "draft" or current["current_version"] != target_version:
                raise DataUseConflict("only the current draft can be activated")
            if reviewer == version_record["author_id"]:
                raise DataUseValidationError("policy author and reviewer must differ")
            semantic = {
                "schema": POLICY_SCHEMA,
                "tenant_id": tenant,
                "record_id": policy,
                "policy_id": policy,
                "current_version": target_version,
                "current_semantic_sha256": version_record["semantic_sha256"],
                "active_version": target_version,
                "state": "active",
                "reviewer_id": reviewer,
                "reviewer_authority_sha256": reviewer_digest,
                "reviewed_at": reviewed,
            }
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="policy",
                record_id=policy,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="activate_policy",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def retire_policy(
        self,
        tenant_id: str,
        policy_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        policy = _token(policy_id, "policy_id")
        expected = _revision(expected_revision)
        request = {"policy_id": policy, "expected_revision": expected}

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            current = self._get_on(conn, tenant, "policy", policy)
            assert current is not None
            if current["revision"] != expected:
                raise DataUseConflict("policy revision changed")
            semantic = {
                "schema": POLICY_SCHEMA,
                "tenant_id": tenant,
                "record_id": policy,
                "policy_id": policy,
                "current_version": current["current_version"],
                "current_semantic_sha256": current["current_semantic_sha256"],
                "active_version": None,
                "state": "retired",
                "reviewer_id": current.get("reviewer_id"),
                "reviewer_authority_sha256": current.get("reviewer_authority_sha256"),
                "reviewed_at": current.get("reviewed_at"),
            }
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="policy",
                record_id=policy,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="retire_policy",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def request_policy_exception(
        self,
        tenant_id: str,
        exception_id: str,
        policy_id: str,
        *,
        scope: Mapping[str, Any],
        replacement_control: Mapping[str, Any],
        rationale_sha256: str,
        requester_id: str,
        requester_authority_sha256: str,
        expires_at: float,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Request an expiring replacement for one exact active policy version."""

        tenant = self._tenant(tenant_id)
        identity = _token(exception_id, "exception_id")
        policy = _token(policy_id, "policy_id")
        normalized_scope = _normalize_scope(scope)
        control = _normalize_control(replacement_control)
        rationale = _digest(rationale_sha256, "rationale_sha256")
        requester = _token(requester_id, "requester_id")
        requester_digest = _digest(requester_authority_sha256, "requester_authority_sha256")
        expiry = _timestamp(expires_at, "expires_at")
        request = {
            "exception_id": identity,
            "policy_id": policy,
            "scope": normalized_scope,
            "replacement_control": control,
            "rationale_sha256": rationale,
            "requester_id": requester,
            "requester_authority_sha256": requester_digest,
            "expires_at": expiry,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            if not now < expiry <= now + _MAX_EXCEPTION_SECONDS:
                raise DataUseValidationError("exception expiry is outside the allowed window")
            pointer = self._get_on(conn, tenant, "policy", policy)
            assert pointer is not None
            if pointer["state"] != "active" or pointer["active_version"] is None:
                raise DataUseStaleAuthority("exception requires an active policy")
            body_semantic = {
                "schema": EXCEPTION_SCHEMA,
                "tenant_id": tenant,
                "record_id": identity,
                "exception_id": identity,
                "policy_id": policy,
                "policy_version": pointer["active_version"],
                "policy_semantic_sha256": pointer["current_semantic_sha256"],
                "policy_pointer_revision": pointer["revision"],
                "policy_pointer_sha256": pointer["record_sha256"],
                "scope": normalized_scope,
                "replacement_control": control,
                "rationale_sha256": rationale,
                "requester_id": requester,
                "requester_authority_sha256": requester_digest,
                "reviewer_id": None,
                "reviewer_authority_sha256": None,
                "reviewed_at": None,
                "expires_at": expiry,
                "state": "requested",
            }
            body = {**body_semantic, "semantic_sha256": _sha256(body_semantic)}
            return self._insert_on(
                conn,
                tenant=tenant,
                record_type="exception",
                record_id=identity,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="request_policy_exception",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def review_policy_exception(
        self,
        tenant_id: str,
        exception_id: str,
        *,
        approve: bool,
        reviewer_id: str,
        reviewer_authority_sha256: str,
        reviewed_at: float,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        identity = _token(exception_id, "exception_id")
        approved = _bool(approve, "approve")
        reviewer = _token(reviewer_id, "reviewer_id")
        reviewer_digest = _digest(reviewer_authority_sha256, "reviewer_authority_sha256")
        reviewed = _timestamp(reviewed_at, "reviewed_at")
        expected = _revision(expected_revision)
        request = {
            "exception_id": identity,
            "approve": approved,
            "reviewer_id": reviewer,
            "reviewer_authority_sha256": reviewer_digest,
            "reviewed_at": reviewed,
            "expected_revision": expected,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            current = self._get_on(conn, tenant, "exception", identity)
            assert current is not None
            if current["revision"] != expected or current["state"] != "requested":
                raise DataUseConflict("exception is not at the requested revision")
            if reviewer == current["requester_id"]:
                raise DataUseValidationError("exception requester and reviewer must differ")
            if reviewed > now or current["expires_at"] <= now:
                raise DataUseStaleAuthority("exception review is stale")
            if approved:
                pointer = self._get_on(conn, tenant, "policy", current["policy_id"])
                assert pointer is not None
                if (
                    pointer["state"] != "active"
                    or pointer["active_version"] != current["policy_version"]
                    or pointer["current_semantic_sha256"] != current["policy_semantic_sha256"]
                    or pointer["record_sha256"] != current["policy_pointer_sha256"]
                ):
                    raise DataUseStaleAuthority("exception policy binding is stale")
            semantic = {
                key: value
                for key, value in current.items()
                if key
                not in {"revision", "record_sha256", "created_at", "updated_at", "semantic_sha256"}
            }
            semantic["state"] = "approved" if approved else "denied"
            semantic["reviewer_id"] = reviewer
            semantic["reviewer_authority_sha256"] = reviewer_digest
            semantic["reviewed_at"] = reviewed
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="exception",
                record_id=identity,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="review_policy_exception",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def close_policy_exception(
        self,
        tenant_id: str,
        exception_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = self._tenant(tenant_id)
        identity = _token(exception_id, "exception_id")
        expected = _revision(expected_revision)
        request = {"exception_id": identity, "expected_revision": expected}

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            current = self._get_on(conn, tenant, "exception", identity)
            assert current is not None
            if current["revision"] != expected:
                raise DataUseConflict("exception revision changed")
            semantic = {
                key: value
                for key, value in current.items()
                if key
                not in {"revision", "record_sha256", "created_at", "updated_at", "semantic_sha256"}
            }
            semantic["state"] = "closed"
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            return self._update_on(
                conn,
                tenant=tenant,
                record_type="exception",
                record_id=identity,
                expected_revision=expected,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="close_policy_exception",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    def create_data_use_request(
        self,
        tenant_id: str,
        request_id: str,
        *,
        project_id: str,
        asset_id: str,
        field_ids: Sequence[str],
        action: str,
        purpose_codes: Sequence[str],
        requester_id: str,
        requester_authority_sha256: str,
        request_evidence_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create an immutable-scope project request awaiting authorization."""

        tenant = self._tenant(tenant_id)
        identity = _token(request_id, "request_id")
        project = _token(project_id, "project_id")
        asset = _token(asset_id, "asset_id")
        fields = _bounded_tokens(field_ids, "field_ids", maximum=_MAX_FIELDS_PER_REQUEST)
        requested_action = _token(action, "action")
        if requested_action not in _ACTIONS:
            raise DataUseValidationError("request action is unsupported")
        purposes = _bounded_tokens(purpose_codes, "purpose_codes")
        requester = _token(requester_id, "requester_id")
        requester_digest = _digest(requester_authority_sha256, "requester_authority_sha256")
        evidence = _digest(request_evidence_sha256, "request_evidence_sha256")
        request = {
            "request_id": identity,
            "project_id": project,
            "asset_id": asset,
            "field_ids": fields,
            "action": requested_action,
            "purpose_codes": purposes,
            "requester_id": requester,
            "requester_authority_sha256": requester_digest,
            "request_evidence_sha256": evidence,
        }

        def mutate(conn: sqlite3.Connection, now: float) -> dict[str, Any]:
            asset_record = self._get_on(conn, tenant, "asset", asset)
            assert asset_record is not None
            field_bindings: list[dict[str, Any]] = []
            for field in fields:
                field_record = self._get_on(conn, tenant, "field", f"{asset}:{field}")
                assert field_record is not None
                field_bindings.append(
                    {
                        "field_id": field,
                        "revision": field_record["revision"],
                        "record_sha256": field_record["record_sha256"],
                    }
                )
            semantic = {
                "schema": REQUEST_SCHEMA,
                "tenant_id": tenant,
                "record_id": identity,
                "request_id": identity,
                "project_id": project,
                "asset_id": asset,
                "field_ids": list(fields),
                "action": requested_action,
                "purpose_codes": list(purposes),
                "requester_id": requester,
                "requester_authority_sha256": requester_digest,
                "request_evidence_sha256": evidence,
                "submitted_asset_revision": asset_record["revision"],
                "submitted_asset_sha256": asset_record["record_sha256"],
                "submitted_fields": field_bindings,
                "status": "pending",
                "decision_id": None,
            }
            body = {**semantic, "semantic_sha256": _sha256(semantic)}
            return self._insert_on(
                conn,
                tenant=tenant,
                record_type="request",
                record_id=identity,
                body=body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="create_data_use_request",
            idempotency_key=idempotency_key,
            request=request,
            mutate=mutate,
        )

    @staticmethod
    def _scope_matches(
        scope: Mapping[str, Any],
        *,
        asset_id: str,
        field_id: str,
        project_id: str,
        action: str,
    ) -> bool:
        checks = (
            ("asset_ids", asset_id),
            ("field_ids", field_id),
            ("project_ids", project_id),
            ("actions", action),
        )
        for key, candidate in checks:
            allowed = scope.get(key, [])
            if allowed and candidate not in allowed:
                return False
        return True

    @staticmethod
    def _conditions_match(
        conditions: Mapping[str, Any],
        *,
        context_values: Mapping[str, set[str]],
        label_ids: set[str],
    ) -> bool:
        dimensions = {
            "business_purpose_any": context_values.get("business_purpose", set()),
            "regulatory_any": context_values.get("regulatory", set()),
            "consent_any": context_values.get("consent", set()),
            "observed_classification_any": context_values.get("observed_classification", set()),
            "label_any": label_ids,
        }
        for condition, current in dimensions.items():
            required = set(conditions.get(condition, []))
            if required and not required.intersection(current):
                return False
        return True

    @staticmethod
    def _effective_controls(
        field_id: str, candidates: Sequence[Mapping[str, Any]]
    ) -> list[dict[str, Any]]:
        applicable = [
            dict(item)
            for item in candidates
            if not item.get("field_ids") or field_id in item.get("field_ids", [])
        ]
        if not applicable:
            return [
                {
                    "control_id": f"default-deny-{field_id}",
                    "effect": "deny",
                    "field_id": field_id,
                    "mask_method": None,
                    "row_filter": None,
                    "source_policy_id": None,
                    "source_policy_version": None,
                    "source_policy_sha256": None,
                    "source_exception_id": None,
                }
            ]
        denies = [item for item in applicable if item["effect"] == "deny"]
        if denies:
            selected = sorted(denies, key=_sha256)[0]
            return [{**selected, "field_id": field_id}]
        reviews = [item for item in applicable if item["effect"] == "review"]
        if reviews:
            selected = sorted(reviews, key=_sha256)[0]
            return [{**selected, "field_id": field_id}]
        row_filters = sorted(
            (item for item in applicable if item["effect"] == "row_filter"),
            key=_sha256,
        )
        masks = [item for item in applicable if item["effect"] == "mask"]
        selected: list[dict[str, Any]] = [{**item, "field_id": field_id} for item in row_filters]
        if masks:
            strongest = sorted(
                masks,
                key=lambda item: (
                    -_MASK_RANK[str(item["mask_method"])],
                    _sha256(item),
                ),
            )[0]
            selected.append({**strongest, "field_id": field_id})
        if selected:
            return selected
        allows = sorted(
            (item for item in applicable if item["effect"] == "allow"),
            key=lambda item: (
                item.get("source_exception_id") is None,
                _sha256(item),
            ),
        )
        if allows:
            return [{**allows[0], "field_id": field_id}]
        raise DataUseCorruptionError("applicable policy controls are malformed")

    def _authorization_authority(
        self,
        conn: sqlite3.Connection,
        tenant: str,
        request_record: Mapping[str, Any],
        *,
        now: float,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
        asset_id = str(request_record["asset_id"])
        asset = self._get_on(conn, tenant, "asset", asset_id)
        assert asset is not None
        fields: list[dict[str, Any]] = []
        for field_id in request_record["field_ids"]:
            field = self._get_on(conn, tenant, "field", f"{asset_id}:{field_id}")
            assert field is not None
            fields.append(field)

        contexts: list[dict[str, Any]] = []
        missing: list[str] = []
        stale: list[str] = []
        max_age = data_use_limits().get("max_context_age_seconds")
        for kind in CONTEXT_KINDS:
            record_id = self._context_record_id(asset_id, kind)
            context = self._get_on(conn, tenant, "context", record_id, required=False)
            if context is None:
                missing.append(kind)
            else:
                contexts.append(context)
                if context_expires_at(context, max_age) <= now:
                    stale.append(kind)
        reasons: list[str] = []
        if missing:
            reasons.append("missing_context:" + ",".join(sorted(missing)))
        if stale:
            reasons.append("stale_context:" + ",".join(sorted(stale)))
        source_roots = [item["source_authority_sha256"] for item in contexts]
        if len(source_roots) != len(set(source_roots)):
            reasons.append("contexts_not_independently_sourced")

        all_assignments = self._complete_authority_list_on(conn, tenant, "label_assignment")
        assignments = [
            item
            for item in all_assignments
            if item["asset_id"] == asset_id
            and item["field_id"] in request_record["field_ids"]
            and item["status"] == "active"
        ]
        labels: list[dict[str, Any]] = []
        for assignment in assignments:
            field = next(item for item in fields if item["field_id"] == assignment["field_id"])
            pointer = self._get_on(conn, tenant, "label", assignment["label_id"])
            version = self._get_on(
                conn,
                tenant,
                "label_version",
                f"{assignment['label_id']}:{assignment['label_version']}",
            )
            assert pointer is not None and version is not None
            label_entry = {
                "assignment": assignment,
                "pointer": pointer,
                "version": version,
            }
            labels.append(label_entry)
            if (
                assignment["field_revision"] != field["revision"]
                or assignment["field_sha256"] != field["record_sha256"]
                or assignment["label_pointer_revision"] != pointer["revision"]
                or assignment["label_pointer_sha256"] != pointer["record_sha256"]
                or assignment["label_sha256"] != version["label_sha256"]
                or pointer["state"] != "active"
                or pointer["current_version"] != assignment["label_version"]
            ):
                reasons.append(f"stale_label_assignment:{assignment['record_id']}")

        policies: list[dict[str, Any]] = []
        for pointer in self._complete_authority_list_on(conn, tenant, "policy"):
            if pointer["state"] != "active" or pointer["active_version"] is None:
                continue
            version = self._get_on(
                conn,
                tenant,
                "policy_version",
                f"{pointer['policy_id']}:{pointer['active_version']}",
            )
            assert version is not None
            if version["semantic_sha256"] != pointer["current_semantic_sha256"]:
                raise DataUseCorruptionError("active policy semantic binding is malformed")
            policies.append({"pointer": pointer, "version": version})

        exceptions = [
            item
            for item in self._complete_authority_list_on(conn, tenant, "exception")
            if item["state"] == "approved" and float(item["expires_at"]) > now
        ]
        authority = {
            "asset": asset,
            "fields": sorted(fields, key=lambda item: item["field_id"]),
            "contexts": sorted(contexts, key=lambda item: item["context_kind"]),
            "labels": sorted(labels, key=lambda item: item["assignment"]["record_id"]),
            "policies": sorted(policies, key=lambda item: item["pointer"]["policy_id"]),
            "exceptions": sorted(exceptions, key=lambda item: item["exception_id"]),
        }
        return authority, fields, sorted(set(reasons))

    def authorize_data_use_request(  # noqa: C901 - one fail-closed decision transaction
        self,
        tenant_id: str,
        request_id: str,
        *,
        authorizer_id: str,
        authorizer_authority_sha256: str,
        expected_request_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Create a fail-closed decision pinned to current independent authority."""

        tenant = self._tenant(tenant_id)
        identity = _token(request_id, "request_id")
        authorizer = _token(authorizer_id, "authorizer_id")
        authorizer_digest = _digest(authorizer_authority_sha256, "authorizer_authority_sha256")
        expected = _revision(expected_request_revision, "expected_request_revision")
        request_material = {
            "request_id": identity,
            "authorizer_id": authorizer,
            "authorizer_authority_sha256": authorizer_digest,
            "expected_request_revision": expected,
        }

        def mutate(  # noqa: C901 - keep authority evaluation and CAS commit atomic
            conn: sqlite3.Connection, now: float
        ) -> dict[str, Any]:
            request_record = self._get_on(conn, tenant, "request", identity)
            assert request_record is not None
            if request_record["revision"] != expected:
                raise DataUseConflict("data-use request revision changed")
            if request_record["status"] != "pending" or request_record["decision_id"] is not None:
                raise DataUseConflict("data-use request was already decided")
            if authorizer == request_record["requester_id"]:
                raise DataUseValidationError("requester and authorizer must differ")

            authority, fields, reasons = self._authorization_authority(
                conn, tenant, request_record, now=now
            )
            asset = authority["asset"]
            if (
                request_record["submitted_asset_revision"] != asset["revision"]
                or request_record["submitted_asset_sha256"] != asset["record_sha256"]
            ):
                reasons.append("request_asset_binding_stale")
            submitted_fields = {
                item["field_id"]: item for item in request_record["submitted_fields"]
            }
            for field in fields:
                submitted = submitted_fields.get(field["field_id"])
                if (
                    submitted is None
                    or submitted.get("revision") != field["revision"]
                    or submitted.get("record_sha256") != field["record_sha256"]
                ):
                    reasons.append(f"request_field_binding_stale:{field['field_id']}")

            context_values = {
                item["context_kind"]: set(item["values"]) for item in authority["contexts"]
            }
            if not set(request_record["purpose_codes"]).issubset(
                context_values.get("business_purpose", set())
            ):
                reasons.append("request_purpose_not_authorized")

            field_controls: list[dict[str, Any]] = []
            matched_policy_ids: set[str] = set()
            if not reasons:
                for field in fields:
                    field_id = str(field["field_id"])
                    label_ids = {
                        item["assignment"]["label_id"]
                        for item in authority["labels"]
                        if item["assignment"]["field_id"] == field_id
                    }
                    candidates: list[dict[str, Any]] = []
                    for policy_entry in authority["policies"]:
                        pointer = policy_entry["pointer"]
                        version = policy_entry["version"]
                        document = version["document"]
                        if not self._scope_matches(
                            document["scope"],
                            asset_id=request_record["asset_id"],
                            field_id=field_id,
                            project_id=request_record["project_id"],
                            action=request_record["action"],
                        ):
                            continue
                        if not self._conditions_match(
                            document["conditions"],
                            context_values=context_values,
                            label_ids=label_ids,
                        ):
                            continue
                        matched_policy_ids.add(pointer["policy_id"])
                        replacements: list[dict[str, Any]] = []
                        for exception in authority["exceptions"]:
                            if exception["policy_id"] != pointer["policy_id"]:
                                continue
                            if (
                                exception["policy_version"] != pointer["active_version"]
                                or exception["policy_semantic_sha256"]
                                != pointer["current_semantic_sha256"]
                                or exception["policy_pointer_revision"] != pointer["revision"]
                                or exception["policy_pointer_sha256"] != pointer["record_sha256"]
                            ):
                                reasons.append(f"stale_exception:{exception['exception_id']}")
                                continue
                            if self._scope_matches(
                                exception["scope"],
                                asset_id=request_record["asset_id"],
                                field_id=field_id,
                                project_id=request_record["project_id"],
                                action=request_record["action"],
                            ) and (
                                not exception["replacement_control"]["field_ids"]
                                or field_id in exception["replacement_control"]["field_ids"]
                            ):
                                replacements.append(
                                    {
                                        **exception["replacement_control"],
                                        "source_policy_id": pointer["policy_id"],
                                        "source_policy_version": pointer["active_version"],
                                        "source_policy_sha256": pointer["current_semantic_sha256"],
                                        "source_exception_id": exception["exception_id"],
                                    }
                                )
                        selected_controls = replacements or document["controls"]
                        for control in selected_controls:
                            if "source_policy_id" in control:
                                candidates.append(dict(control))
                            else:
                                candidates.append(
                                    {
                                        **control,
                                        "source_policy_id": pointer["policy_id"],
                                        "source_policy_version": pointer["active_version"],
                                        "source_policy_sha256": pointer["current_semantic_sha256"],
                                        "source_exception_id": None,
                                    }
                                )
                    field_controls.extend(self._effective_controls(field_id, candidates))

            if reasons:
                field_controls = [
                    {
                        "control_id": f"authority-deny-{field['field_id']}",
                        "effect": "deny",
                        "field_id": field["field_id"],
                        "mask_method": None,
                        "row_filter": None,
                        "source_policy_id": None,
                        "source_policy_version": None,
                        "source_policy_sha256": None,
                        "source_exception_id": None,
                    }
                    for field in fields
                ]
            elif not matched_policy_ids:
                reasons.append("default_deny_no_applicable_policy")

            field_controls.sort(
                key=lambda item: (
                    item["field_id"],
                    -_EFFECT_RANK[item["effect"]],
                    item["control_id"],
                    _sha256(item),
                )
            )
            outcome = max(
                (item["effect"] for item in field_controls),
                key=lambda effect: _EFFECT_RANK[effect],
            )
            status = {
                "allow": "authorized",
                "mask": "authorized",
                "row_filter": "authorized",
                "review": "review",
                "deny": "denied",
            }[outcome]
            decision_id = self._new_id("DUD")
            request_semantic = {
                key: value
                for key, value in request_record.items()
                if key
                not in {"revision", "record_sha256", "created_at", "updated_at", "semantic_sha256"}
            }
            request_semantic["status"] = status
            request_semantic["decision_id"] = decision_id
            request_body = {
                **request_semantic,
                "semantic_sha256": _sha256(request_semantic),
            }
            decided_request = self._update_on(
                conn,
                tenant=tenant,
                record_type="request",
                record_id=identity,
                expected_revision=expected,
                body=request_body,
                now=now,
            )
            complete_contexts = len(authority["contexts"]) == len(CONTEXT_KINDS)
            max_age = data_use_limits().get("max_context_age_seconds")
            expires_at = (
                min(context_expires_at(item, max_age) for item in authority["contexts"])
                if complete_contexts
                else now
            )
            bound_authority = {**authority, "request": decided_request}
            authority_sha256 = _sha256(bound_authority)
            decision_semantic = {
                "schema": DECISION_SCHEMA,
                "tenant_id": tenant,
                "record_id": decision_id,
                "decision_id": decision_id,
                "request_id": identity,
                "project_id": request_record["project_id"],
                "asset_id": request_record["asset_id"],
                "field_ids": list(request_record["field_ids"]),
                "action": request_record["action"],
                "outcome": outcome,
                "controls": field_controls,
                "reasons": sorted(set(reasons)),
                "matched_policy_ids": sorted(matched_policy_ids),
                "authority": bound_authority,
                "authority_sha256": authority_sha256,
                "authorizer_id": authorizer,
                "authorizer_authority_sha256": authorizer_digest,
                "decided_at": now,
                "expires_at": expires_at,
                "provider_writes_possible": False,
            }
            decision_body = {
                **decision_semantic,
                "decision_sha256": _sha256(decision_semantic),
            }
            return self._insert_on(
                conn,
                tenant=tenant,
                record_type="decision",
                record_id=decision_id,
                body=decision_body,
                now=now,
            )

        return self._run_idempotent(
            tenant=tenant,
            namespace="authorize_data_use_request",
            idempotency_key=idempotency_key,
            request=request_material,
            mutate=mutate,
        )

    def get_authorization_decision(self, tenant_id: str, decision_id: str) -> dict[str, Any] | None:
        tenant = self._tenant(tenant_id)
        identity = _token(decision_id, "decision_id")
        with self._connect() as conn:
            return self._get_on(conn, tenant, "decision", identity, required=False)

    def resolve_compilation_authority(self, tenant_id: str, decision_id: str) -> dict[str, Any]:
        """Return current records corresponding to an immutable decision.

        This resolver does not silently refresh a decision.  The compiler must
        compare every current record to the decision's exact binding and reject
        missing, stale, changed, or cross-tenant authority.
        """

        tenant = self._tenant(tenant_id)
        identity = _token(decision_id, "decision_id")
        with self._connect() as conn:
            decision = self._get_on(conn, tenant, "decision", identity)
            assert decision is not None
            request = self._get_on(conn, tenant, "request", decision["request_id"])
            assert request is not None
            try:
                current, _fields, reasons = self._authorization_authority(
                    conn, tenant, request, now=self._now()
                )
            except DataUseNotFound as exc:
                raise DataUseMissingAuthority("decision authority no longer resolves") from exc
            current = {**current, "request": request}
            bundle_semantic = {
                "schema": AUTHORITY_BUNDLE_SCHEMA,
                "tenant_id": tenant,
                "decision": decision,
                "current_authority": current,
                "current_authority_reasons": reasons,
                "resolved_at": self._now(),
                "provider_writes_possible": False,
            }
            return {
                **bundle_semantic,
                "bundle_sha256": _sha256(bundle_semantic),
            }

    def unified_audit_records(self, tenant_id: str):
        """Return a digest-only chain over the immutable mutation ledger.

        Every core authority mutation passes through ``_run_idempotent``.
        Provider-audit, compiler and external enforcement histories remain
        separate sources, so this is deliberately not full-suite coverage.
        """

        from .unified_audit import GENESIS_SHA256, build_source_record

        tenant = self._tenant(tenant_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT rowid,namespace,key_sha256,request_sha256,result_json,"
                "result_sha256,created_at FROM data_use_idempotency "
                "WHERE tenant_id=? ORDER BY rowid",
                (tenant,),
            ).fetchall()
        exact_namespaces = frozenset(
            {
                "put_asset",
                "put_field",
                "put_lineage",
                "publish_machine_label",
                "retire_machine_label",
                "assign_machine_label",
                "put_policy_version",
                "activate_policy",
                "retire_policy",
                "request_policy_exception",
                "review_policy_exception",
                "close_policy_exception",
                "create_data_use_request",
                "authorize_data_use_request",
            }
        )
        policy_namespaces = frozenset(
            {
                "put_policy_version",
                "activate_policy",
                "retire_policy",
                "request_policy_exception",
                "review_policy_exception",
                "close_policy_exception",
            }
        )
        actor_sha256 = hashlib.sha256(
            b"lightwork.data-use-governance.idempotency-authority.v1"
        ).hexdigest()
        previous = GENESIS_SHA256
        records = []
        for sequence, row in enumerate(rows, start=1):
            namespace = str(row["namespace"])
            if namespace not in exact_namespaces and not namespace.startswith(
                "put_context:"
            ):
                raise DataUseCorruptionError(
                    "stored mutation namespace is outside the closed authority"
                )
            result = _loads(row["result_json"], "idempotency result")
            if (
                not isinstance(result, dict)
                or _canonical(result).decode("ascii") != row["result_json"]
            ):
                raise DataUseCorruptionError(
                    "stored idempotency result is not canonical"
                )
            result_sha256 = str(row["result_sha256"])
            if not hmac.compare_digest(result_sha256, _sha256(result)):
                raise DataUseCorruptionError(
                    "stored idempotency result digest does not match"
                )
            key_sha256 = _digest(row["key_sha256"], "idempotency key digest")
            _digest(row["request_sha256"], "idempotency request digest")
            action = (
                "policy_changed"
                if namespace in policy_namespaces
                else "decision_recorded"
                if namespace == "authorize_data_use_request"
                else "request_submitted"
                if namespace == "create_data_use_request"
                else "record_changed"
            )
            record = build_source_record(
                sequence=sequence,
                occurred_at=float(row["created_at"]),
                action=action,
                actor_sha256=actor_sha256,
                resource_sha256=key_sha256,
                payload_sha256=result_sha256,
                previous_sha256=previous,
            )
            records.append(record)
            previous = record.record_sha256
        return tuple(records)

    def status(self) -> dict[str, Any]:
        return {
            "schema": "lightwork.data-use.governance-status.v1",
            "tenant_explicit": True,
            "context_authorities_required": list(CONTEXT_KINDS),
            "policy_default": "deny",
            "policy_states": sorted(_POLICY_STATES),
            "exception_states": sorted(_EXCEPTION_STATES),
            "request_states": sorted(_REQUEST_STATES),
            "provider_writes_possible": False,
            "native_adapter_attached": False,
            "live_provider_acceptance_verified": False,
        }


__all__ = [
    "AUTHORITY_BUNDLE_SCHEMA",
    "CONTEXT_KINDS",
    "CONTROL_EFFECTS",
    "DataUseConflict",
    "DataUseCorruptionError",
    "DataUseGovernanceError",
    "DataUseGovernanceStore",
    "DataUseIdempotencyConflict",
    "DataUseMissingAuthority",
    "DataUseNotFound",
    "DataUseStaleAuthority",
    "DataUseValidationError",
    "DECISION_SCHEMA",
    "FIELD_TYPES",
    "MASKING_METHODS",
    "normalize_policy_document",
]
