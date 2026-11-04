"""Controlled Snowflake and Databricks data-use enforcement adapters.

The adapters in this module consume only digest-verified, provider-neutral
control IR produced by :mod:`maverick.data_use_policy_compiler`.  Provider
identifiers and functions are enrolled in a tenant-scoped server-side binding;
callers cannot supply SQL, provider URLs, principals, policies, or functions at
execution time.

Credentials are acquired from an injected owner for one bounded request.  They
are never placed in binding records, operation receipts, request digests,
exceptions, reprs, or returned values.  The injected HTTP transport is the only
other component that observes the authorization header.

Provider writes remain default-off and require four explicit configuration
gates: the data-use root, compiler, enforcement, and selected provider.  No
default network transport is provided, so a deployment must deliberately
attach its credential and egress owners.

Digest-only statement references and provider-native correlation tags make
mutations addressable; they do not prove live tag propagation, audit delivery,
or provider-log completeness without provider contract tests.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, urlsplit

from .data_use_policy_compiler import _COMPILER_SHA256 as COMPILER_AUTHORITY_SHA256
from .data_use_policy_compiler import COMPILER_VERSION, CONTROL_IR_SCHEMA
from .data_use_sqlite import immediate_transaction, private_connection
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id

PROVIDER_BINDING_SCHEMA = "lightwork.data-use.provider-binding.v1"
PROVIDER_RESULT_SCHEMA = "lightwork.data-use.provider-reconciliation.v1"
PROVIDER_OPERATION_SCHEMA = "lightwork.data-use.provider-operation.v1"
PROVIDER_RESPONSE_SCHEMA = "lightwork.data-use.provider-http-response.v1"

_PROVIDERS = frozenset({"snowflake", "databricks"})
_EFFECTS = frozenset({"allow", "deny", "mask", "row_filter", "review"})
_OPERATIONS = frozenset({"apply_control_ir", "rollback_control_ir"})
_MASK_METHODS = frozenset(
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
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_IDEM_RE = re.compile(r"[0-9a-f]{64}\Z")
_DIGEST_RE = _IDEM_RE
_SNOWFLAKE_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_$]{0,254}\Z")
_SNOWFLAKE_ACCOUNT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,126}\Z")
_DATABRICKS_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,254}\Z")
_DATABRICKS_PRINCIPAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,254}\Z")
_WAREHOUSE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SQLISH_RE = re.compile(r"(?:--|/\*|\*/|;|'|\"|`)")
_MAX_JSON_BYTES = 512 * 1024
_MAX_RESPONSE_BYTES = 128 * 1024
_MAX_BINDING_FIELDS = 512
_MAX_STATEMENTS = 520
_MAX_OPERATIONS = 10_000
_SAFE_TRANSIENT_STATUS = frozenset({408, 425, 429, 502, 503, 504})
_MUTATION_ACCEPTED_STATUS = frozenset({200, 201, 202})
_PROVIDER_AUDIT_PROJECTION_SCHEMA = "lightwork.data-use.provider-audit-projection.v1"
_AUDIT_CHANGE_KINDS = frozenset({"grant", "masking_policy", "revoke", "row_filter", "state_anchor"})


class DataUseProviderError(RuntimeError):
    """Base error for provider binding and enforcement."""


class DataUseProviderConfigError(DataUseProviderError):
    """Provider enforcement is disabled or incompletely configured."""


class DataUseProviderValidationError(DataUseProviderError, ValueError):
    """Provider material is outside the closed adapter contract."""


class DataUseProviderConflict(DataUseProviderError):
    """A binding or idempotency CAS precondition failed."""


class DataUseProviderNotFound(DataUseProviderError):
    """A tenant-scoped provider binding does not exist."""


class DataUseProviderCredentialError(DataUseProviderError):
    """The credential lease is missing, stale, rotated, or revoked."""


class DataUseProviderProtocolError(DataUseProviderError):
    """A provider response violated the bounded response contract."""


class DataUseProviderUnavailable(DataUseProviderError):
    """A request known not to have been sent exhausted safe retries."""

    def __init__(
        self,
        message: str,
        *,
        evidence: Mapping[str, Any] | None = None,
        proved_no_effect: bool = False,
    ) -> None:
        super().__init__(message)
        self.evidence = dict(evidence or {})
        self.proved_no_effect = bool(proved_no_effect)


class DataUseProviderAmbiguousEffect(DataUseProviderError):
    """A mutation may have occurred and requires explicit reconciliation."""

    def __init__(self, message: str, *, evidence: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.evidence = dict(evidence or {})


class DataUseProviderRequestNotSent(DataUseProviderError):
    """The transport proves no bytes were dispatched; a bounded retry is safe."""


class DataUseProviderTransportAmbiguous(DataUseProviderError):
    """The transport cannot prove whether provider mutation occurred."""


@dataclass(frozen=True, slots=True)
class _PlannedStatement:
    """One server-generated mutation and its exact digest-only audit identity."""

    statement: str
    change_kind: str
    control_sha256: str
    state_sha256: str | None = None


def _canonical(value: object, *, maximum: int = _MAX_JSON_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise DataUseProviderValidationError("provider material must be finite JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise DataUseProviderValidationError("provider material exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _provider_audit_object_sha256(binding: Mapping[str, Any]) -> str:
    """Mirror the audit plane's closed provider-object projection."""

    keys = (
        "provider_id",
        "account_or_workspace_id",
        "catalog",
        "schema_name",
        "table",
    )
    if any(not isinstance(binding.get(key), str) for key in keys):
        raise DataUseProviderValidationError("provider binding target is incomplete")
    return _sha256({key: binding[key] for key in keys})


def _provider_audit_control_sha256(
    kind: str,
    base: Mapping[str, Any],
    material: Mapping[str, Any],
) -> str:
    """Mirror the authority outbox's exact expected-change control digest."""

    if kind not in _AUDIT_CHANGE_KINDS:
        raise DataUseProviderValidationError("provider audit change kind is unsupported")
    return _sha256({**base, **material})


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DataUseProviderValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(value: object, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise DataUseProviderValidationError(f"{label} is not a bounded opaque identifier")
    if _CONTROL_RE.search(value) or _SQLISH_RE.search(value):
        raise DataUseProviderValidationError(f"{label} contains prohibited syntax")
    return value


def _tenant_id(value: object) -> str:
    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise DataUseProviderValidationError("tenant_id is invalid") from exc


def _positive_revision(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DataUseProviderValidationError(f"{label} must be a positive integer")
    return value


def _expected_revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise DataUseProviderValidationError("expected_revision must be a non-negative integer")
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise DataUseProviderValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _strict_json(body: bytes, *, maximum: int, label: str) -> Any:
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise DataUseProviderProtocolError(f"{label} exceeds its byte bound")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON constant {value}")
            ),
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise DataUseProviderProtocolError(f"{label} is malformed JSON") from None


def _plain_json(value: object, label: str) -> Any:
    """Require the thawed dict/list/scalar shape, not MappingProxy/tuples."""

    if type(value) is dict:
        return {str(key): _plain_json(item, label) for key, item in value.items()}
    if type(value) is list:
        return [_plain_json(item, label) for item in value]
    if value is None or type(value) in {str, int, float, bool}:
        if isinstance(value, float) and not math.isfinite(value):
            raise DataUseProviderValidationError(f"{label} contains non-finite data")
        return value
    raise DataUseProviderValidationError(f"{label} must be thawed JSON")


def _exact_object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise DataUseProviderValidationError(f"{label} has an unsupported shape")
    return value


def _provider_identifier(provider: str, value: object, label: str) -> str:
    pattern = _SNOWFLAKE_ID_RE if provider == "snowflake" else _DATABRICKS_ID_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DataUseProviderValidationError(f"{label} is invalid for {provider}")
    if _CONTROL_RE.search(value) or _SQLISH_RE.search(value):
        raise DataUseProviderValidationError(f"{label} contains prohibited syntax")
    return value


def _principal(provider: str, value: object) -> str:
    pattern = _SNOWFLAKE_ID_RE if provider == "snowflake" else _DATABRICKS_PRINCIPAL_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise DataUseProviderValidationError("provider principal is invalid")
    if _CONTROL_RE.search(value) or _SQLISH_RE.search(value):
        raise DataUseProviderValidationError("provider principal contains prohibited syntax")
    return value


def _qualified_identifier(provider: str, value: object, label: str) -> tuple[str, str, str]:
    if not isinstance(value, str):
        raise DataUseProviderValidationError(f"{label} must be qualified")
    parts = value.split(".")
    if len(parts) != 3:
        raise DataUseProviderValidationError(f"{label} must contain three identifiers")
    return tuple(_provider_identifier(provider, part, f"{label} component") for part in parts)  # type: ignore[return-value]


def _quote_identifier(provider: str, value: str) -> str:
    # Grammar validation precedes quoting; replacement remains defense-in-depth.
    if provider == "snowflake":
        return '"' + value.replace('"', '""') + '"'
    return "`" + value.replace("`", "``") + "`"


def _quote_qualified(provider: str, value: Sequence[str]) -> str:
    return ".".join(_quote_identifier(provider, item) for item in value)


def _origin(provider: str, value: object) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise DataUseProviderValidationError("provider origin is invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise DataUseProviderValidationError("provider origin is invalid") from None
    host = (parsed.hostname or "").lower().rstrip(".")
    suffixes = (
        (".snowflakecomputing.com",)
        if provider == "snowflake"
        else (
            ".cloud.databricks.com",
            ".azuredatabricks.net",
            ".gcp.databricks.com",
        )
    )
    if (
        parsed.scheme != "https"
        or not any(host.endswith(suffix) and host != suffix[1:] for suffix in suffixes)
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise DataUseProviderValidationError(
            f"{provider} origin must be an exact supported HTTPS origin"
        )
    return f"https://{host}"


def provider_config_enabled(provider_id: str, config: Mapping[str, Any] | None = None) -> bool:
    """Require root, compiler, enforcement, and provider gates to be literal true."""

    provider = str(provider_id or "").strip().lower()
    if provider not in _PROVIDERS:
        return False
    if config is None:
        try:
            from .config import config_source_errors, load_config

            if config_source_errors():
                return False
            loaded = load_config()
        except Exception:
            return False
        if not isinstance(loaded, Mapping):
            return False
        config = loaded
    if not isinstance(config, Mapping):
        return False
    root = config.get("data_use_governance")
    if not isinstance(root, Mapping) or root.get("enable") is not True:
        return False
    if "providers" in root:
        return False
    compiler = root.get("compiler")
    enforcement = root.get("enforcement")
    selected = root.get(provider)
    return bool(
        isinstance(compiler, Mapping)
        and compiler.get("enable") is True
        and isinstance(enforcement, Mapping)
        and enforcement.get("enable") is True
        and isinstance(selected, Mapping)
        and selected.get("enable") is True
    )


@dataclass(frozen=True)
class ProviderLimits:
    timeout_seconds: float = 10.0
    max_response_bytes: int = 64 * 1024
    max_attempts: int = 3
    max_polls: int = 3
    # In-request wait before retrying a request that provably was not sent:
    # base * 2**(attempt-1), never more than retry_max_seconds.
    retry_base_seconds: float = 0.25
    retry_max_seconds: float = 1.0

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout_seconds, bool)
            or not isinstance(self.timeout_seconds, (int, float))
            or not math.isfinite(float(self.timeout_seconds))
            or not 0.1 <= float(self.timeout_seconds) <= 60.0
        ):
            raise DataUseProviderConfigError("provider timeout is outside its bound")
        if (
            isinstance(self.max_response_bytes, bool)
            or not isinstance(self.max_response_bytes, int)
            or not 1024 <= self.max_response_bytes <= _MAX_RESPONSE_BYTES
        ):
            raise DataUseProviderConfigError("provider response bound is outside its range")
        for name, value in (
            ("max_attempts", self.max_attempts),
            ("max_polls", self.max_polls),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 5:
                raise DataUseProviderConfigError(f"{name} is outside its range")
        for name, value, lower, upper in (
            ("retry_base_seconds", self.retry_base_seconds, 0.05, 10.0),
            ("retry_max_seconds", self.retry_max_seconds, 0.25, 60.0),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(float(value))
                or not lower <= float(value) <= upper
            ):
                raise DataUseProviderConfigError(f"{name} is outside its range")
        if float(self.retry_max_seconds) < float(self.retry_base_seconds):
            raise DataUseProviderConfigError("retry_max_seconds is below retry_base_seconds")
        object.__setattr__(self, "timeout_seconds", float(self.timeout_seconds))


@dataclass(frozen=True, repr=False)
class CredentialLease:
    """Ephemeral credential material owned outside the adapter persistence plane."""

    authorization: str = field(repr=False)
    key_id: str
    key_revision: int
    authority_sha256: str
    expires_at: float
    revoked: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.authorization, str)
            or not 1 <= len(self.authorization) <= 8192
            or _CONTROL_RE.search(self.authorization)
        ):
            raise DataUseProviderCredentialError("credential authorization is invalid")
        _token(self.key_id, "credential key_id")
        _positive_revision(self.key_revision, "credential key_revision")
        _digest(self.authority_sha256, "credential authority_sha256")
        _timestamp(self.expires_at, "credential expires_at")
        if not isinstance(self.revoked, bool):
            raise DataUseProviderCredentialError("credential revoked flag is invalid")


class ProviderCredentialOwner(Protocol):
    """Resolve one ephemeral lease without transferring credential ownership."""

    def lease(
        self,
        *,
        provider_id: str,
        tenant_id: str,
        binding_id: str,
    ) -> CredentialLease: ...


@dataclass(frozen=True, repr=False)
class ProviderHttpResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.status_code, bool)
            or not isinstance(self.status_code, int)
            or not 100 <= self.status_code <= 599
        ):
            raise DataUseProviderProtocolError("provider HTTP status is invalid")
        if not isinstance(self.headers, Mapping):
            raise DataUseProviderProtocolError("provider HTTP headers are invalid")
        if not isinstance(self.body, bytes):
            raise DataUseProviderProtocolError("provider HTTP body must be bytes")


class ProviderHttpTransport(Protocol):
    """Bounded exact-origin seam; implementations must never follow redirects."""

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
        max_response_bytes: int,
        allow_redirects: bool,
    ) -> ProviderHttpResponse:
        # Referencing keyword-named protocol parameters keeps static dead-code
        # checks from mistaking this structural transport contract for a stub.
        del url, timeout, allow_redirects
        raise NotImplementedError


class ProviderBindingStore:
    """Private SQLite authority for provider resources and operation claims."""

    def __init__(
        self,
        path: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path).expanduser()
        self._clock = clock
        self._initialize()

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "binding authority clock")
        except (KeyboardInterrupt, SystemExit):
            raise
        except DataUseProviderValidationError:
            raise
        except Exception as exc:
            raise DataUseProviderError("binding authority clock is unavailable") from exc

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
                CREATE TABLE IF NOT EXISTS data_use_provider_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS data_use_provider_bindings (
                    tenant_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK (revision > 0),
                    body_json TEXT NOT NULL,
                    binding_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, binding_id)
                );
                CREATE TABLE IF NOT EXISTS data_use_provider_idempotency (
                    tenant_id TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    result_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (tenant_id, namespace, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS data_use_provider_operations (
                    tenant_id TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    idempotency_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_json TEXT,
                    result_sha256 TEXT,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL,
                    PRIMARY KEY (
                        tenant_id, provider_id, binding_id, idempotency_sha256
                    )
                );
                CREATE INDEX IF NOT EXISTS data_use_provider_operations_status
                    ON data_use_provider_operations(
                        tenant_id, provider_id, binding_id, status
                    );
                CREATE TABLE IF NOT EXISTS data_use_provider_revocations (
                    tenant_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    binding_revision INTEGER NOT NULL CHECK (binding_revision > 0),
                    binding_sha256 TEXT NOT NULL,
                    reason_sha256 TEXT NOT NULL,
                    revoked_at REAL NOT NULL,
                    revocation_sha256 TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, binding_id),
                    FOREIGN KEY (tenant_id, binding_id)
                        REFERENCES data_use_provider_bindings(tenant_id, binding_id)
                );
                CREATE TRIGGER IF NOT EXISTS data_use_provider_idempotency_no_update
                    BEFORE UPDATE ON data_use_provider_idempotency
                    BEGIN SELECT RAISE(ABORT, 'immutable provider idempotency'); END;
                CREATE TRIGGER IF NOT EXISTS data_use_provider_idempotency_no_delete
                    BEFORE DELETE ON data_use_provider_idempotency
                    BEGIN SELECT RAISE(ABORT, 'immutable provider idempotency'); END;
                CREATE TRIGGER IF NOT EXISTS data_use_provider_revocations_no_update
                    BEFORE UPDATE ON data_use_provider_revocations
                    BEGIN SELECT RAISE(ABORT, 'immutable provider revocation'); END;
                CREATE TRIGGER IF NOT EXISTS data_use_provider_revocations_no_delete
                    BEFORE DELETE ON data_use_provider_revocations
                    BEGIN SELECT RAISE(ABORT, 'immutable provider revocation'); END;
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO data_use_provider_meta(key, value) "
                "VALUES ('schema_version', '1')"
            )
            row = conn.execute(
                "SELECT value FROM data_use_provider_meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is None or str(row["value"]) != "1":
                raise DataUseProviderError("unsupported provider binding schema")

    @staticmethod
    def _binding_material(
        body: Mapping[str, Any],
        revision: int,
        created_at: float,
        updated_at: float,
    ) -> dict[str, Any]:
        return {
            "body": dict(body),
            "revision": revision,
            "created_at": created_at,
            "updated_at": updated_at,
        }

    @classmethod
    def _binding_row(cls, row: sqlite3.Row, tenant: str) -> dict[str, Any]:
        if str(row["tenant_id"]) != tenant:
            raise DataUseProviderError("stored provider binding crossed a tenant boundary")
        raw = str(row["body_json"]).encode("utf-8")
        body = _strict_json(raw, maximum=_MAX_JSON_BYTES, label="provider binding")
        if not isinstance(body, dict) or body.get("tenant_id") != tenant:
            raise DataUseProviderError("stored provider binding is malformed")
        revision = int(row["revision"])
        created_at = float(row["created_at"])
        updated_at = float(row["updated_at"])
        expected = _sha256(cls._binding_material(body, revision, created_at, updated_at))
        actual = str(row["binding_sha256"])
        if not _DIGEST_RE.fullmatch(actual) or not hmac.compare_digest(actual, expected):
            raise DataUseProviderError("stored provider binding digest does not match")
        if (
            body.get("binding_id") != row["binding_id"]
            or body.get("provider_id") != row["provider_id"]
        ):
            raise DataUseProviderError("stored provider binding identity is malformed")
        return {
            **body,
            "revision": revision,
            "binding_sha256": actual,
            "created_at": created_at,
            "updated_at": updated_at,
        }

    @staticmethod
    def _normalize_map(
        provider: str,
        value: object,
        *,
        label: str,
        key_kind: str,
        value_kind: str,
        allow_empty: bool = False,
    ) -> dict[str, Any]:
        minimum = 0 if allow_empty else 1
        if not isinstance(value, Mapping) or not minimum <= len(value) <= _MAX_BINDING_FIELDS:
            raise DataUseProviderValidationError(f"{label} is outside its bound")
        result: dict[str, Any] = {}
        for raw_key, raw_value in value.items():
            if key_kind == "digest":
                key = _digest(raw_key, f"{label} key")
            elif key_kind == "mask_method":
                key = str(raw_key or "")
                if key not in _MASK_METHODS:
                    raise DataUseProviderValidationError(
                        f"{label} has an unsupported masking method"
                    )
            else:
                key = _token(raw_key, f"{label} key")
            if value_kind == "qualified":
                normalized: Any = list(_qualified_identifier(provider, raw_value, f"{label} value"))
            else:
                normalized = _provider_identifier(provider, raw_value, f"{label} value")
            if key in result:
                raise DataUseProviderValidationError(f"{label} contains duplicate keys")
            result[key] = normalized
        return dict(sorted(result.items()))

    def _enroll(
        self,
        tenant_id: str,
        binding_id: str,
        *,
        provider_id: str,
        origin: str,
        account_or_workspace_id: str,
        asset_id: str,
        catalog: str,
        schema: str,
        table: str,
        principal: str,
        compute_id: str,
        field_map: Mapping[str, str],
        mask_bindings: Mapping[str, str],
        row_filter_bindings: Mapping[str, str],
        state_anchor: str | None,
        catalog_snapshot_sha256: str,
        field_inventory_complete: bool,
        credential_key_id: str,
        credential_revision: int,
        credential_authority_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        tenant = _tenant_id(tenant_id)
        binding = _token(binding_id, "binding_id")
        provider = str(provider_id or "").lower()
        if provider not in _PROVIDERS:
            raise DataUseProviderValidationError("provider_id is unsupported")
        target_origin = _origin(provider, origin)
        asset = _token(asset_id, "asset_id")
        parsed_host = (urlsplit(target_origin).hostname or "").lower()
        account = (
            _provider_identifier(provider, account_or_workspace_id, "account/workspace")
            if provider == "databricks"
            else str(account_or_workspace_id or "")
        )
        if provider == "snowflake":
            if not _SNOWFLAKE_ACCOUNT_RE.fullmatch(account):
                raise DataUseProviderValidationError("Snowflake account identifier is invalid")
        if parsed_host.split(".", 1)[0] != account.lower():
            raise DataUseProviderValidationError(
                "provider origin does not match the enrolled account/workspace"
            )
        normalized_catalog = _provider_identifier(provider, catalog, "catalog/database")
        normalized_schema = _provider_identifier(provider, schema, "schema")
        normalized_table = _provider_identifier(provider, table, "table")
        normalized_principal = _principal(provider, principal)
        if not isinstance(compute_id, str) or not _WAREHOUSE_RE.fullmatch(compute_id):
            raise DataUseProviderValidationError("provider compute identifier is invalid")
        normalized_fields = self._normalize_map(
            provider,
            field_map,
            label="field_map",
            key_kind="token",
            value_kind="identifier",
        )
        normalized_masks = self._normalize_map(
            provider,
            mask_bindings,
            label="mask_bindings",
            key_kind="mask_method",
            value_kind="qualified",
            allow_empty=True,
        )
        normalized_rows = self._normalize_map(
            provider,
            row_filter_bindings,
            label="row_filter_bindings",
            key_kind="digest",
            value_kind="qualified",
            allow_empty=True,
        )
        if provider == "snowflake":
            if state_anchor is None:
                raise DataUseProviderValidationError("Snowflake state tag binding is required")
            normalized_anchor: list[str] | None = list(
                _qualified_identifier(provider, state_anchor, "state_anchor")
            )
        elif state_anchor is not None:
            raise DataUseProviderValidationError(
                "Databricks state anchor is fixed and must not be supplied"
            )
        else:
            normalized_anchor = None
        snapshot_digest = _digest(catalog_snapshot_sha256, "catalog_snapshot_sha256")
        if field_inventory_complete is not True:
            raise DataUseProviderValidationError(
                "provider field inventory must be explicitly complete"
            )
        key_id = _token(credential_key_id, "credential_key_id")
        key_id_sha256 = hashlib.sha256(key_id.encode("ascii")).hexdigest()
        key_revision = _positive_revision(credential_revision, "credential_revision")
        credential_digest = _digest(credential_authority_sha256, "credential_authority_sha256")
        expected = _expected_revision(expected_revision)
        idem = _token(idempotency_key, "idempotency_key")
        key_sha256 = hashlib.sha256(idem.encode("ascii")).hexdigest()
        semantic = {
            "schema": PROVIDER_BINDING_SCHEMA,
            "tenant_id": tenant,
            "binding_id": binding,
            "provider_id": provider,
            "origin": target_origin,
            "account_or_workspace_id": account,
            "asset_id": asset,
            "catalog": normalized_catalog,
            "schema_name": normalized_schema,
            "table": normalized_table,
            "principal": normalized_principal,
            "compute_id": compute_id,
            "field_map": normalized_fields,
            "mask_bindings": normalized_masks,
            "row_filter_bindings": normalized_rows,
            "state_anchor": normalized_anchor,
            "state_property": (None if provider == "snowflake" else "lightwork.data_use_digest"),
            "catalog_snapshot_sha256": snapshot_digest,
            "field_inventory_complete": True,
            "credential_key_id_sha256": key_id_sha256,
            "credential_revision": key_revision,
            "credential_authority_sha256": credential_digest,
            "semantic_sha256": "",
        }
        semantic["semantic_sha256"] = _sha256(
            {key: value for key, value in semantic.items() if key != "semantic_sha256"}
        )
        request_sha256 = _sha256({**semantic, "expected_revision": expected})
        namespace = f"enroll:{provider}"
        with self._transaction() as conn:
            replay = conn.execute(
                "SELECT request_sha256, result_json, result_sha256 "
                "FROM data_use_provider_idempotency WHERE tenant_id = ? "
                "AND namespace = ? AND key_sha256 = ?",
                (tenant, namespace, key_sha256),
            ).fetchone()
            if replay is not None:
                if not hmac.compare_digest(str(replay["request_sha256"]), request_sha256):
                    raise DataUseProviderConflict("binding idempotency key was rebound")
                result = _strict_json(
                    str(replay["result_json"]).encode("utf-8"),
                    maximum=_MAX_JSON_BYTES,
                    label="binding idempotency result",
                )
                if not isinstance(result, dict) or not hmac.compare_digest(
                    str(replay["result_sha256"]), _sha256(result)
                ):
                    raise DataUseProviderError("binding idempotency result is corrupted")
                return result
            row = conn.execute(
                "SELECT * FROM data_use_provider_bindings WHERE tenant_id = ? AND binding_id = ?",
                (tenant, binding),
            ).fetchone()
            now = self._now()
            if row is None:
                if expected != 0:
                    raise DataUseProviderConflict("provider binding does not exist")
                revision = 1
                created_at = now
            else:
                current = self._binding_row(row, tenant)
                if (
                    conn.execute(
                        "SELECT 1 FROM data_use_provider_revocations WHERE tenant_id = ? "
                        "AND binding_id = ?",
                        (tenant, binding),
                    ).fetchone()
                    is not None
                ):
                    raise DataUseProviderConflict("revoked provider binding cannot be re-enrolled")
                if current["revision"] != expected:
                    raise DataUseProviderConflict("provider binding revision changed")
                if current["provider_id"] != provider:
                    raise DataUseProviderConflict(
                        "provider binding cannot be rebound to another provider"
                    )
                revision = expected + 1
                created_at = float(current["created_at"])
            binding_sha256 = _sha256(self._binding_material(semantic, revision, created_at, now))
            if row is None:
                conn.execute(
                    "INSERT INTO data_use_provider_bindings(tenant_id, binding_id, "
                    "provider_id, revision, body_json, binding_sha256, created_at, "
                    "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        tenant,
                        binding,
                        provider,
                        revision,
                        _canonical(semantic).decode("ascii"),
                        binding_sha256,
                        created_at,
                        now,
                    ),
                )
            else:
                cursor = conn.execute(
                    "UPDATE data_use_provider_bindings SET revision = ?, body_json = ?, "
                    "binding_sha256 = ?, updated_at = ? WHERE tenant_id = ? "
                    "AND binding_id = ? AND revision = ?",
                    (
                        revision,
                        _canonical(semantic).decode("ascii"),
                        binding_sha256,
                        now,
                        tenant,
                        binding,
                        expected,
                    ),
                )
                if cursor.rowcount != 1:
                    raise DataUseProviderConflict("provider binding revision changed")
            result = {
                **semantic,
                "revision": revision,
                "binding_sha256": binding_sha256,
                "created_at": created_at,
                "updated_at": now,
            }
            conn.execute(
                "INSERT INTO data_use_provider_idempotency(tenant_id, namespace, "
                "key_sha256, request_sha256, result_json, result_sha256, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    namespace,
                    key_sha256,
                    request_sha256,
                    _canonical(result).decode("ascii"),
                    _sha256(result),
                    now,
                ),
            )
            return result

    def enroll_snowflake(
        self,
        tenant_id: str,
        binding_id: str,
        *,
        origin: str,
        account_or_workspace_id: str,
        asset_id: str,
        catalog: str,
        schema: str,
        table: str,
        principal: str,
        compute_id: str,
        field_map: Mapping[str, str],
        mask_bindings: Mapping[str, str],
        row_filter_bindings: Mapping[str, str],
        state_anchor: str,
        catalog_snapshot_sha256: str,
        field_inventory_complete: bool,
        credential_key_id: str,
        credential_revision: int,
        credential_authority_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._enroll(
            tenant_id,
            binding_id,
            provider_id="snowflake",
            origin=origin,
            account_or_workspace_id=account_or_workspace_id,
            asset_id=asset_id,
            catalog=catalog,
            schema=schema,
            table=table,
            principal=principal,
            compute_id=compute_id,
            field_map=field_map,
            mask_bindings=mask_bindings,
            row_filter_bindings=row_filter_bindings,
            state_anchor=state_anchor,
            catalog_snapshot_sha256=catalog_snapshot_sha256,
            field_inventory_complete=field_inventory_complete,
            credential_key_id=credential_key_id,
            credential_revision=credential_revision,
            credential_authority_sha256=credential_authority_sha256,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def enroll_databricks(
        self,
        tenant_id: str,
        binding_id: str,
        *,
        origin: str,
        account_or_workspace_id: str,
        asset_id: str,
        catalog: str,
        schema: str,
        table: str,
        principal: str,
        compute_id: str,
        field_map: Mapping[str, str],
        mask_bindings: Mapping[str, str],
        row_filter_bindings: Mapping[str, str],
        catalog_snapshot_sha256: str,
        field_inventory_complete: bool,
        credential_key_id: str,
        credential_revision: int,
        credential_authority_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._enroll(
            tenant_id,
            binding_id,
            provider_id="databricks",
            origin=origin,
            account_or_workspace_id=account_or_workspace_id,
            asset_id=asset_id,
            catalog=catalog,
            schema=schema,
            table=table,
            principal=principal,
            compute_id=compute_id,
            field_map=field_map,
            mask_bindings=mask_bindings,
            row_filter_bindings=row_filter_bindings,
            state_anchor=None,
            catalog_snapshot_sha256=catalog_snapshot_sha256,
            field_inventory_complete=field_inventory_complete,
            credential_key_id=credential_key_id,
            credential_revision=credential_revision,
            credential_authority_sha256=credential_authority_sha256,
            expected_revision=expected_revision,
            idempotency_key=idempotency_key,
        )

    def get_binding(self, tenant_id: str, binding_id: str) -> dict[str, Any] | None:
        tenant = _tenant_id(tenant_id)
        binding = _token(binding_id, "binding_id")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM data_use_provider_bindings WHERE tenant_id = ? AND binding_id = ?",
                (tenant, binding),
            ).fetchone()
            if row is None:
                return None
            result = self._binding_row(row, tenant)
            revocation = conn.execute(
                "SELECT * FROM data_use_provider_revocations WHERE tenant_id = ? "
                "AND binding_id = ?",
                (tenant, binding),
            ).fetchone()
            if revocation is None:
                return {**result, "revoked": False}
            material = {
                "tenant_id": tenant,
                "binding_id": binding,
                "binding_revision": int(revocation["binding_revision"]),
                "binding_sha256": str(revocation["binding_sha256"]),
                "reason_sha256": str(revocation["reason_sha256"]),
                "revoked_at": float(revocation["revoked_at"]),
            }
            actual = str(revocation["revocation_sha256"])
            if (
                not _DIGEST_RE.fullmatch(actual)
                or not hmac.compare_digest(actual, _sha256(material))
                or material["binding_revision"] != result["revision"]
                or not hmac.compare_digest(material["binding_sha256"], result["binding_sha256"])
            ):
                raise DataUseProviderError("provider revocation evidence is corrupted")
            return {
                **result,
                "revoked": True,
                "revoked_at": material["revoked_at"],
                "revocation_reason_sha256": material["reason_sha256"],
                "revocation_sha256": actual,
            }

    def list_bindings(
        self,
        tenant_id: str,
        *,
        provider_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        tenant = _tenant_id(tenant_id)
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
            raise DataUseProviderValidationError("binding list limit is outside its bound")
        provider = None if provider_id is None else str(provider_id or "").strip().lower()
        if provider is not None and provider not in _PROVIDERS:
            raise DataUseProviderValidationError("provider_id is unsupported")
        with self._connect() as conn:
            if provider is None:
                rows = conn.execute(
                    "SELECT binding_id FROM data_use_provider_bindings "
                    "WHERE tenant_id = ? ORDER BY updated_at DESC, binding_id LIMIT ?",
                    (tenant, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT binding_id FROM data_use_provider_bindings "
                    "WHERE tenant_id = ? AND provider_id = ? "
                    "ORDER BY updated_at DESC, binding_id LIMIT ?",
                    (tenant, provider, limit),
                ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = self.get_binding(tenant, str(row["binding_id"]))
            if item is None:
                raise DataUseProviderError("provider binding disappeared during listing")
            results.append(item)
        return results

    def revoke_binding(
        self,
        tenant_id: str,
        binding_id: str,
        *,
        expected_revision: int,
        reason_sha256: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Permanently revoke one binding without deleting its evidence."""

        tenant = _tenant_id(tenant_id)
        binding = _token(binding_id, "binding_id")
        expected = _positive_revision(expected_revision, "expected_revision")
        reason = _digest(reason_sha256, "reason_sha256")
        idem = _token(idempotency_key, "idempotency_key")
        key_sha256 = hashlib.sha256(idem.encode("ascii")).hexdigest()
        namespace = "revoke-binding"
        request_sha256 = _sha256(
            {
                "tenant_id": tenant,
                "binding_id": binding,
                "expected_revision": expected,
                "reason_sha256": reason,
            }
        )
        with self._transaction() as conn:
            replay = conn.execute(
                "SELECT request_sha256, result_json, result_sha256 "
                "FROM data_use_provider_idempotency WHERE tenant_id = ? "
                "AND namespace = ? AND key_sha256 = ?",
                (tenant, namespace, key_sha256),
            ).fetchone()
            if replay is not None:
                if not hmac.compare_digest(str(replay["request_sha256"]), request_sha256):
                    raise DataUseProviderConflict("revocation idempotency key was rebound")
                result = _strict_json(
                    str(replay["result_json"]).encode("utf-8"),
                    maximum=_MAX_JSON_BYTES,
                    label="revocation idempotency result",
                )
                if not isinstance(result, dict) or not hmac.compare_digest(
                    str(replay["result_sha256"]), _sha256(result)
                ):
                    raise DataUseProviderError("revocation idempotency result is corrupted")
                return result
            row = conn.execute(
                "SELECT * FROM data_use_provider_bindings WHERE tenant_id = ? AND binding_id = ?",
                (tenant, binding),
            ).fetchone()
            if row is None:
                raise DataUseProviderNotFound("provider binding does not exist")
            current = self._binding_row(row, tenant)
            if current["revision"] != expected:
                raise DataUseProviderConflict("provider binding revision changed")
            if (
                conn.execute(
                    "SELECT 1 FROM data_use_provider_revocations WHERE tenant_id = ? "
                    "AND binding_id = ?",
                    (tenant, binding),
                ).fetchone()
                is not None
            ):
                raise DataUseProviderConflict("provider binding is already revoked")
            now = self._now()
            material = {
                "tenant_id": tenant,
                "binding_id": binding,
                "binding_revision": expected,
                "binding_sha256": current["binding_sha256"],
                "reason_sha256": reason,
                "revoked_at": now,
            }
            revocation_sha256 = _sha256(material)
            conn.execute(
                "INSERT INTO data_use_provider_revocations(tenant_id, binding_id, "
                "binding_revision, binding_sha256, reason_sha256, revoked_at, "
                "revocation_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    binding,
                    expected,
                    current["binding_sha256"],
                    reason,
                    now,
                    revocation_sha256,
                ),
            )
            result = {
                "schema": "lightwork.data-use.provider-binding-revocation.v1",
                **material,
                "revocation_sha256": revocation_sha256,
                "revoked": True,
            }
            conn.execute(
                "INSERT INTO data_use_provider_idempotency(tenant_id, namespace, "
                "key_sha256, request_sha256, result_json, result_sha256, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    tenant,
                    namespace,
                    key_sha256,
                    request_sha256,
                    _canonical(result).decode("ascii"),
                    _sha256(result),
                    now,
                ),
            )
            return result

    def claim_operation(
        self,
        *,
        tenant_id: str,
        provider_id: str,
        binding_id: str,
        idempotency_sha256: str,
        request_sha256: str,
    ) -> dict[str, Any] | None:
        tenant = _tenant_id(tenant_id)
        provider = str(provider_id or "").lower()
        if provider not in _PROVIDERS:
            raise DataUseProviderValidationError("provider_id is unsupported")
        binding = _token(binding_id, "binding_id")
        idem = _digest(idempotency_sha256, "idempotency_sha256")
        request_digest = _digest(request_sha256, "request_sha256")
        with self._transaction() as conn:
            row = conn.execute(
                "SELECT * FROM data_use_provider_operations WHERE tenant_id = ? "
                "AND provider_id = ? AND binding_id = ? AND idempotency_sha256 = ?",
                (tenant, provider, binding, idem),
            ).fetchone()
            now = self._now()
            if row is not None:
                if not hmac.compare_digest(str(row["request_sha256"]), request_digest):
                    raise DataUseProviderConflict("operation idempotency digest was rebound")
                status = str(row["status"])
                if status == "complete":
                    result = _strict_json(
                        str(row["result_json"]).encode("utf-8"),
                        maximum=_MAX_JSON_BYTES,
                        label="provider operation result",
                    )
                    if not isinstance(result, dict) or not hmac.compare_digest(
                        str(row["result_sha256"]), _sha256(result)
                    ):
                        raise DataUseProviderError("provider operation result is corrupted")
                    return result
                if status in {"ambiguous", "in_progress"}:
                    raise DataUseProviderAmbiguousEffect(
                        "provider operation is in an ambiguous state; reconcile manually"
                    )
                if status != "failed_no_effect":
                    raise DataUseProviderError("provider operation state is invalid")
                conn.execute(
                    "UPDATE data_use_provider_operations SET status = 'in_progress', "
                    "result_json = NULL, result_sha256 = NULL, updated_at = ? "
                    "WHERE tenant_id = ? AND provider_id = ? AND binding_id = ? "
                    "AND idempotency_sha256 = ?",
                    (now, tenant, provider, binding, idem),
                )
                return None
            count = conn.execute(
                "SELECT COUNT(*) AS value FROM data_use_provider_operations WHERE tenant_id = ?",
                (tenant,),
            ).fetchone()
            if count is None or int(count["value"]) >= _MAX_OPERATIONS:
                raise DataUseProviderError("provider operation capacity is exhausted")
            conn.execute(
                "INSERT INTO data_use_provider_operations(tenant_id, provider_id, "
                "binding_id, idempotency_sha256, request_sha256, status, created_at, "
                "updated_at) VALUES (?, ?, ?, ?, ?, 'in_progress', ?, ?)",
                (tenant, provider, binding, idem, request_digest, now, now),
            )
            return None

    def finish_operation(
        self,
        *,
        tenant_id: str,
        provider_id: str,
        binding_id: str,
        idempotency_sha256: str,
        request_sha256: str,
        result: Mapping[str, Any],
    ) -> dict[str, Any]:
        tenant = _tenant_id(tenant_id)
        provider = str(provider_id or "").lower()
        binding = _token(binding_id, "binding_id")
        idem = _digest(idempotency_sha256, "idempotency_sha256")
        request_digest = _digest(request_sha256, "request_sha256")
        material = dict(result)
        encoded = _canonical(material)
        with self._transaction() as conn:
            now = self._now()
            cursor = conn.execute(
                "UPDATE data_use_provider_operations SET status = 'complete', "
                "result_json = ?, result_sha256 = ?, updated_at = ? "
                "WHERE tenant_id = ? AND provider_id = ? AND binding_id = ? "
                "AND idempotency_sha256 = ? AND request_sha256 = ? "
                "AND status = 'in_progress'",
                (
                    encoded.decode("ascii"),
                    _sha256(material),
                    now,
                    tenant,
                    provider,
                    binding,
                    idem,
                    request_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise DataUseProviderConflict("provider operation claim changed")
        return material

    def mark_operation(
        self,
        *,
        tenant_id: str,
        provider_id: str,
        binding_id: str,
        idempotency_sha256: str,
        request_sha256: str,
        status: str,
        evidence: Mapping[str, Any] | None = None,
    ) -> None:
        if status not in {"ambiguous", "failed_no_effect"}:
            raise DataUseProviderValidationError("provider terminal status is invalid")
        tenant = _tenant_id(tenant_id)
        provider = str(provider_id or "").lower()
        if provider not in _PROVIDERS:
            raise DataUseProviderValidationError("provider_id is unsupported")
        binding = _token(binding_id, "binding_id")
        idem = _digest(idempotency_sha256, "idempotency_sha256")
        request_digest = _digest(request_sha256, "request_sha256")
        evidence_json: str | None = None
        evidence_sha256: str | None = None
        if evidence is not None:
            material = _plain_json(dict(evidence), "operation evidence")
            if not isinstance(material, dict):
                raise DataUseProviderValidationError("operation evidence must be an object")
            evidence_json = _canonical(material).decode("ascii")
            evidence_sha256 = _sha256(material)
        with self._transaction() as conn:
            cursor = conn.execute(
                "UPDATE data_use_provider_operations SET status = ?, result_json = ?, "
                "result_sha256 = ?, updated_at = ? "
                "WHERE tenant_id = ? AND provider_id = ? AND binding_id = ? "
                "AND idempotency_sha256 = ? AND request_sha256 = ? "
                "AND status = 'in_progress'",
                (
                    status,
                    evidence_json,
                    evidence_sha256,
                    self._now(),
                    tenant,
                    provider,
                    binding,
                    idem,
                    request_digest,
                ),
            )
            if cursor.rowcount != 1:
                raise DataUseProviderConflict("provider operation claim changed")

    def get_operation(
        self,
        *,
        tenant_id: str,
        provider_id: str,
        binding_id: str,
        idempotency_sha256: str,
    ) -> dict[str, Any] | None:
        """Return tenant-scoped, credential-free operation evidence."""

        tenant = _tenant_id(tenant_id)
        provider = str(provider_id or "").lower()
        if provider not in _PROVIDERS:
            raise DataUseProviderValidationError("provider_id is unsupported")
        binding = _token(binding_id, "binding_id")
        idem = _digest(idempotency_sha256, "idempotency_sha256")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT request_sha256, status, result_json, result_sha256, "
                "created_at, updated_at FROM data_use_provider_operations "
                "WHERE tenant_id = ? AND provider_id = ? AND binding_id = ? "
                "AND idempotency_sha256 = ?",
                (tenant, provider, binding, idem),
            ).fetchone()
        if row is None:
            return None
        result: dict[str, Any] | None = None
        if row["result_json"] is not None:
            parsed = _strict_json(
                str(row["result_json"]).encode("utf-8"),
                maximum=_MAX_JSON_BYTES,
                label="provider operation evidence",
            )
            if not isinstance(parsed, dict) or not hmac.compare_digest(
                str(row["result_sha256"]), _sha256(parsed)
            ):
                raise DataUseProviderError("provider operation evidence is corrupted")
            result = parsed
        return {
            "tenant_id": tenant,
            "provider_id": provider,
            "binding_id": binding,
            "idempotency_sha256": idem,
            "request_sha256": str(row["request_sha256"]),
            "status": str(row["status"]),
            "evidence": result,
            "created_at": float(row["created_at"]),
            "updated_at": float(row["updated_at"]),
        }


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.casefold()
    for key, value in headers.items():
        if str(key).casefold() == wanted:
            return str(value)
    return None


def _safe_response_receipt(response: ProviderHttpResponse) -> dict[str, Any]:
    if len(response.body) > _MAX_RESPONSE_BYTES:
        raise DataUseProviderProtocolError("provider response exceeds its byte bound")
    selected: dict[str, str] = {}
    for name in ("content-type", "content-length", "retry-after"):
        value = _header(response.headers, name)
        if value is not None:
            if len(value) > 256 or _CONTROL_RE.search(value):
                raise DataUseProviderProtocolError("provider response header is invalid")
            selected[name] = value
    return {
        "schema": PROVIDER_RESPONSE_SCHEMA,
        "status_code": response.status_code,
        "headers": selected,
        "body_sha256": _sha256_bytes(response.body),
        "body_bytes": len(response.body),
    }


def _ast_fields(value: object) -> tuple[str, ...]:
    """Revalidate the normalized compiler AST without accepting provider code."""

    fields: set[str] = set()
    nodes = 0

    def visit(node: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if depth > 16 or nodes > 256 or not isinstance(node, Mapping):
            raise DataUseProviderValidationError("row-filter AST is malformed")
        if set(node) == {"field"}:
            fields.add(_token(node.get("field"), "row-filter field"))
            return
        if set(node) == {"function", "args"}:
            function = str(node.get("function") or "")
            if function not in {"lower", "upper", "date", "year"}:
                raise DataUseProviderValidationError(
                    "row-filter function is not compiler-controlled"
                )
            args = node.get("args")
            if type(args) is not list or len(args) != 1:
                raise DataUseProviderValidationError("row-filter function is malformed")
            visit(args[0], depth + 1)
            return
        operation = node.get("op")
        if operation in {"and", "or"} and set(node) == {"op", "args"}:
            args = node.get("args")
            if type(args) is not list or not 2 <= len(args) <= 32:
                raise DataUseProviderValidationError("logical row-filter is malformed")
            for item in args:
                visit(item, depth + 1)
            return
        if operation == "not" and set(node) == {"op", "arg"}:
            visit(node.get("arg"), depth + 1)
            return
        if operation in {"eq", "ne", "lt", "lte", "gt", "gte"} and set(node) == {
            "op",
            "left",
            "value",
        }:
            visit(node.get("left"), depth + 1)
            literal = node.get("value")
            if isinstance(literal, str) and _SQLISH_RE.search(literal):
                raise DataUseProviderValidationError(
                    "row-filter literal contains prohibited syntax"
                )
            return
        if operation == "in" and set(node) == {"op", "left", "values"}:
            visit(node.get("left"), depth + 1)
            values = node.get("values")
            if type(values) is not list or not 1 <= len(values) <= 128:
                raise DataUseProviderValidationError("row-filter set is malformed")
            if any(isinstance(item, str) and _SQLISH_RE.search(item) for item in values):
                raise DataUseProviderValidationError(
                    "row-filter literal contains prohibited syntax"
                )
            return
        if operation in {"is_null", "not_null"} and set(node) == {"op", "left"}:
            visit(node.get("left"), depth + 1)
            return
        raise DataUseProviderValidationError("row-filter AST contains an uncontrolled operation")

    visit(value, 0)
    return tuple(sorted(fields))


class _NativeProviderAdapter:
    provider_id = ""
    adapter_id = ""
    control_schema = CONTROL_IR_SCHEMA
    controlled_operations = _OPERATIONS

    def __init__(
        self,
        *,
        tenant_id: str,
        binding_id: str,
        adapter_authority_sha256: str,
        binding_store: ProviderBindingStore,
        credential_owner: ProviderCredentialOwner,
        transport: ProviderHttpTransport,
        config: Mapping[str, Any] | None = None,
        limits: ProviderLimits | None = None,
        clock: Callable[[], float] = time.time,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._tenant_id = _tenant_id(tenant_id)
        self._binding_id = _token(binding_id, "binding_id")
        self.adapter_authority_sha256 = _digest(
            adapter_authority_sha256, "adapter_authority_sha256"
        )
        if not isinstance(binding_store, ProviderBindingStore):
            raise DataUseProviderConfigError("binding_store is invalid")
        if not callable(getattr(credential_owner, "lease", None)):
            raise DataUseProviderConfigError("credential_owner is unavailable")
        if not callable(getattr(transport, "request", None)):
            raise DataUseProviderConfigError("provider transport is unavailable")
        self._bindings = binding_store
        self._credentials = credential_owner
        self._transport = transport
        self._config = config
        self._limits = limits or ProviderLimits()
        if self.provider_id == "databricks" and not 5.0 <= self._limits.timeout_seconds <= 50.0:
            raise DataUseProviderConfigError(
                "Databricks HTTP timeout must be between 5 and 50 seconds"
            )
        self._clock = clock
        self._sleep = sleeper
        self.supported_effects = _EFFECTS if self.provider_writes_possible else frozenset()

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "provider adapter clock")
        except (KeyboardInterrupt, SystemExit):
            raise
        except DataUseProviderValidationError:
            raise
        except Exception as exc:
            raise DataUseProviderError("provider adapter clock is unavailable") from exc

    def _binding(self) -> dict[str, Any]:
        binding = self._bindings.get_binding(self._tenant_id, self._binding_id)
        if binding is None:
            raise DataUseProviderNotFound("provider binding does not exist")
        if (
            binding["tenant_id"] != self._tenant_id
            or binding["provider_id"] != self.provider_id
            or binding["binding_id"] != self._binding_id
        ):
            raise DataUseProviderConflict("provider binding identity changed")
        if binding.get("revoked") is True:
            raise DataUseProviderCredentialError("provider binding is revoked")
        _origin(self.provider_id, binding["origin"])
        return binding

    def _ready_without_credential(self) -> bool:
        if not provider_config_enabled(self.provider_id, self._config):
            return False
        try:
            self._binding()
        except DataUseProviderError:
            return False
        return True

    @property
    def provider_writes_possible(self) -> bool:
        if not self._ready_without_credential():
            return False
        try:
            binding = self._binding()
            self._lease(binding)
        except DataUseProviderError:
            return False
        return bool(callable(getattr(self._transport, "request", None)))

    def status(self) -> dict[str, Any]:
        binding = self._bindings.get_binding(self._tenant_id, self._binding_id)
        enabled = provider_config_enabled(self.provider_id, self._config)
        available = self.provider_writes_possible
        return {
            "schema": "lightwork.data-use.provider-adapter-status.v1",
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "enabled": enabled,
            "binding_enrolled": binding is not None,
            "runtime_available": available,
            "provider_writes_possible": available,
            "default_mode": "off",
            "credentials_persisted": False,
            "arbitrary_sql_accepted": False,
            "rollback_mode": "compiled_safe_deny",
            "restores_prior_native_state": False,
            "live_provider_acceptance_verified": False,
        }

    def _lease(self, binding: Mapping[str, Any]) -> CredentialLease:
        try:
            lease = self._credentials.lease(
                provider_id=self.provider_id,
                tenant_id=self._tenant_id,
                binding_id=self._binding_id,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except DataUseProviderCredentialError:
            raise
        except Exception as exc:
            raise DataUseProviderCredentialError("credential owner is unavailable") from exc
        if not isinstance(lease, CredentialLease):
            raise DataUseProviderCredentialError("credential owner returned an invalid lease")
        if lease.revoked:
            raise DataUseProviderCredentialError("credential key is revoked")
        if lease.expires_at <= self._now():
            raise DataUseProviderCredentialError("credential lease is expired")
        expected = (
            binding["credential_key_id_sha256"],
            binding["credential_revision"],
            binding["credential_authority_sha256"],
        )
        observed = (
            hashlib.sha256(lease.key_id.encode("ascii")).hexdigest(),
            lease.key_revision,
            lease.authority_sha256,
        )
        if observed != expected:
            raise DataUseProviderCredentialError(
                "credential lease does not match the enrolled key authority"
            )
        return lease

    def _assert_current_binding(self, expected: Mapping[str, Any]) -> dict[str, Any]:
        if not provider_config_enabled(self.provider_id, self._config):
            raise DataUseProviderConfigError(
                "native provider enforcement was disabled during reconciliation"
            )
        current = self._binding()
        expected_identity = (
            expected.get("revision"),
            expected.get("binding_sha256"),
            expected.get("semantic_sha256"),
        )
        current_identity = (
            current.get("revision"),
            current.get("binding_sha256"),
            current.get("semantic_sha256"),
        )
        if current_identity != expected_identity:
            raise DataUseProviderConflict("provider binding changed during reconciliation")
        return current

    def _validate_compiler_bindings(  # noqa: C901 - closed binding-schema walk
        self,
        bindings: dict[str, Any],
        provider_binding: Mapping[str, Any],
    ) -> tuple[set[str], set[tuple[str, int, str]], dict[str, tuple[str, int]]]:
        _exact_object(
            bindings,
            {
                "decision",
                "request",
                "asset",
                "fields",
                "contexts",
                "policies",
                "labels",
                "exceptions",
            },
            "compiler bindings",
        )
        decision = _exact_object(
            bindings["decision"],
            {
                "decision_id",
                "decision_sha256",
                "record_revision",
                "record_sha256",
            },
            "decision binding",
        )
        _token(decision["decision_id"], "decision binding id")
        _digest(decision["decision_sha256"], "decision binding digest")
        _positive_revision(decision["record_revision"], "decision binding revision")
        _digest(decision["record_sha256"], "decision record digest")
        request = _exact_object(
            bindings["request"],
            {"request_id", "revision", "record_sha256"},
            "request binding",
        )
        _token(request["request_id"], "request binding id")
        _positive_revision(request["revision"], "request binding revision")
        _digest(request["record_sha256"], "request record digest")
        asset = _exact_object(
            bindings["asset"],
            {"asset_id", "revision", "record_sha256"},
            "asset binding",
        )
        asset_id = _token(asset["asset_id"], "asset binding id")
        if asset_id != provider_binding["asset_id"]:
            raise DataUseProviderConflict("control_ir asset binding does not match")
        _positive_revision(asset["revision"], "asset binding revision")
        _digest(asset["record_sha256"], "asset record digest")
        fields = bindings["fields"]
        if type(fields) is not list or not 1 <= len(fields) <= _MAX_BINDING_FIELDS:
            raise DataUseProviderValidationError("field bindings are outside their bound")
        field_ids: set[str] = set()
        for raw in fields:
            field = _exact_object(
                raw,
                {"field_id", "revision", "record_sha256"},
                "field binding",
            )
            field_id = _token(field["field_id"], "field binding id")
            if field_id in field_ids:
                raise DataUseProviderValidationError("field bindings contain duplicates")
            field_ids.add(field_id)
            _positive_revision(field["revision"], "field binding revision")
            _digest(field["record_sha256"], "field record digest")
        if field_ids != set(provider_binding["field_map"]):
            raise DataUseProviderConflict(
                "control_ir fields do not match the complete provider inventory"
            )
        contexts = bindings["contexts"]
        if type(contexts) is not list or len(contexts) != 4:
            raise DataUseProviderValidationError("all four compiler context bindings are required")
        context_kinds: set[str] = set()
        source_authorities: set[str] = set()
        for raw in contexts:
            context = _exact_object(
                raw,
                {
                    "context_kind",
                    "revision",
                    "record_sha256",
                    "context_sha256",
                    "source_revision",
                    "source_authority_sha256",
                    "reviewer_id",
                    "reviewer_authority_sha256",
                    "fresh_until",
                },
                "context binding",
            )
            kind = str(context["context_kind"] or "")
            if (
                kind
                not in {
                    "business_purpose",
                    "regulatory",
                    "consent",
                    "observed_classification",
                }
                or kind in context_kinds
            ):
                raise DataUseProviderValidationError(
                    "context bindings are incomplete or duplicated"
                )
            context_kinds.add(kind)
            _positive_revision(context["revision"], "context binding revision")
            _positive_revision(context["source_revision"], "context source revision")
            _digest(context["record_sha256"], "context record digest")
            _digest(context["context_sha256"], "context semantic digest")
            source_authority = _digest(
                context["source_authority_sha256"], "context source authority"
            )
            source_authorities.add(source_authority)
            _token(context["reviewer_id"], "context reviewer id")
            _digest(context["reviewer_authority_sha256"], "context reviewer authority")
            if _timestamp(context["fresh_until"], "context freshness") <= self._now():
                raise DataUseProviderValidationError("context binding is stale")
        if len(source_authorities) != 4:
            raise DataUseProviderValidationError("context bindings are not independently sourced")
        policies = bindings["policies"]
        if type(policies) is not list or len(policies) > _MAX_BINDING_FIELDS:
            raise DataUseProviderValidationError("policy bindings exceed their bound")
        policy_bindings: set[tuple[str, int, str]] = set()
        for raw in policies:
            policy = _exact_object(
                raw,
                {
                    "policy_id",
                    "version",
                    "pointer_revision",
                    "pointer_sha256",
                    "semantic_sha256",
                },
                "policy binding",
            )
            policy_id = _token(policy["policy_id"], "policy binding id")
            version = _positive_revision(policy["version"], "policy binding version")
            _positive_revision(policy["pointer_revision"], "policy pointer revision")
            _digest(policy["pointer_sha256"], "policy pointer digest")
            semantic = _digest(policy["semantic_sha256"], "policy semantic digest")
            item = (policy_id, version, semantic)
            if item in policy_bindings:
                raise DataUseProviderValidationError("policy bindings contain duplicates")
            policy_bindings.add(item)
        labels = bindings["labels"]
        if type(labels) is not list or len(labels) > _MAX_BINDING_FIELDS:
            raise DataUseProviderValidationError("label bindings exceed their bound")
        assignment_ids: set[str] = set()
        for raw in labels:
            label = _exact_object(
                raw,
                {
                    "assignment_id",
                    "assignment_revision",
                    "assignment_sha256",
                    "label_id",
                    "label_version",
                    "label_sha256",
                    "reviewer_id",
                    "reviewer_authority_sha256",
                },
                "label binding",
            )
            assignment = _token(label["assignment_id"], "label assignment id")
            if assignment in assignment_ids:
                raise DataUseProviderValidationError("label bindings contain duplicates")
            assignment_ids.add(assignment)
            _positive_revision(label["assignment_revision"], "label assignment revision")
            _digest(label["assignment_sha256"], "label assignment digest")
            _token(label["label_id"], "label id")
            _positive_revision(label["label_version"], "label version")
            _digest(label["label_sha256"], "label semantic digest")
            _token(label["reviewer_id"], "label reviewer id")
            _digest(label["reviewer_authority_sha256"], "label reviewer authority")
        exceptions = bindings["exceptions"]
        if type(exceptions) is not list or len(exceptions) > _MAX_BINDING_FIELDS:
            raise DataUseProviderValidationError("exception bindings exceed their bound")
        exception_bindings: dict[str, tuple[str, int]] = {}
        for raw in exceptions:
            exception = _exact_object(
                raw,
                {
                    "exception_id",
                    "revision",
                    "record_sha256",
                    "policy_id",
                    "policy_version",
                    "expires_at",
                },
                "exception binding",
            )
            exception_id = _token(exception["exception_id"], "exception binding id")
            if exception_id in exception_bindings:
                raise DataUseProviderValidationError("exception bindings contain duplicates")
            _positive_revision(exception["revision"], "exception binding revision")
            _digest(exception["record_sha256"], "exception record digest")
            policy_id = _token(exception["policy_id"], "exception policy id")
            version = _positive_revision(exception["policy_version"], "exception policy version")
            if _timestamp(exception["expires_at"], "exception expiry") <= self._now():
                raise DataUseProviderValidationError("exception binding is stale")
            exception_bindings[exception_id] = (policy_id, version)
        return field_ids, policy_bindings, exception_bindings

    def _validate_control_state(  # noqa: C901 - closed five-effect control walk
        self,
        state: object,
        *,
        rollback: bool,
        asset_id: str,
        field_ids: set[str],
        policy_bindings: set[tuple[str, int, str]],
        exception_bindings: Mapping[str, tuple[str, int]],
    ) -> list[dict[str, Any]]:
        if type(state) is not list or not state or len(state) > _MAX_STATEMENTS:
            raise DataUseProviderValidationError("control state is outside its bound")
        normalized: list[dict[str, Any]] = []
        controlled_fields: set[str] = set()
        for raw in state:
            control = _exact_object(
                raw,
                {
                    "operation",
                    "control_id",
                    "asset_id",
                    "field_id",
                    "parameters",
                    "source",
                },
                "control",
            )
            operation = str(control["operation"] or "")
            if operation not in _EFFECTS:
                raise DataUseProviderValidationError("control operation is unsupported")
            if rollback and operation != "deny":
                raise DataUseProviderValidationError(
                    "rollback state must be compiled safe-deny controls"
                )
            control_id = _token(control["control_id"], "control id")
            field_id = _token(control["field_id"], "control field id")
            if field_id not in field_ids or control["asset_id"] != asset_id:
                raise DataUseProviderConflict("control resource binding does not match")
            parameters = control["parameters"]
            if type(parameters) is not dict:
                raise DataUseProviderValidationError("control parameters are malformed")
            if operation == "mask":
                if set(parameters) != {"method"} or parameters["method"] not in _MASK_METHODS:
                    raise DataUseProviderValidationError("mask parameters are unsupported")
            elif operation == "row_filter":
                if set(parameters) != {"ast"}:
                    raise DataUseProviderValidationError("row-filter parameters are unsupported")
                ast_fields = set(_ast_fields(parameters["ast"]))
                if not ast_fields or not ast_fields.issubset(field_ids):
                    raise DataUseProviderConflict("row-filter references an unbound provider field")
            elif parameters:
                raise DataUseProviderValidationError("control operation has arbitrary parameters")
            source = _exact_object(
                control["source"],
                {"policy_id", "policy_version", "policy_sha256", "exception_id"},
                "control source",
            )
            if rollback:
                if any(value is not None for value in source.values()) or control_id != (
                    f"rollback-deny-{field_id}"
                ):
                    raise DataUseProviderValidationError(
                        "rollback control is not compiler-generated safe deny"
                    )
            elif source["policy_id"] is None:
                if any(value is not None for value in source.values()):
                    raise DataUseProviderValidationError("default-deny source binding is malformed")
                if operation != "deny":
                    raise DataUseProviderValidationError(
                        "non-deny control requires an active policy binding"
                    )
            else:
                policy_id = _token(source["policy_id"], "control policy id")
                version = _positive_revision(source["policy_version"], "control policy version")
                policy_digest = _digest(source["policy_sha256"], "control policy digest")
                if (policy_id, version, policy_digest) not in policy_bindings:
                    raise DataUseProviderConflict(
                        "control source does not match an exact policy binding"
                    )
                exception_id = source["exception_id"]
                if exception_id is not None:
                    exception = _token(exception_id, "control exception id")
                    if exception_bindings.get(exception) != (policy_id, version):
                        raise DataUseProviderConflict(
                            "control source does not match an exact exception binding"
                        )
            normalized.append(control)
            controlled_fields.add(field_id)
        if controlled_fields != field_ids:
            raise DataUseProviderValidationError(
                "control state does not govern every enrolled field"
            )
        expected_order = sorted(
            normalized,
            key=lambda item: (
                item["asset_id"],
                item["field_id"],
                item["operation"],
                item["control_id"],
                _sha256(item),
            ),
        )
        if normalized != expected_order:
            raise DataUseProviderValidationError(
                "control state is not in deterministic compiler order"
            )
        if rollback and len(normalized) != len(field_ids):
            raise DataUseProviderValidationError(
                "rollback state must contain one safe deny per field"
            )
        return normalized

    def _validate_ir(  # noqa: C901 - one complete compiler-IR trust-boundary walk
        self, control_ir: Mapping[str, Any], *, rollback: bool
    ) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], str]:
        value = _plain_json(control_ir, "control_ir")
        if not isinstance(value, dict):
            raise DataUseProviderValidationError("control_ir must be an object")
        required = {
            "schema",
            "tenant_id",
            "compiler",
            "bindings",
            "bindings_sha256",
            "desired_state",
            "desired_state_sha256",
            "rollback_state",
            "rollback_state_sha256",
            "native_adapter",
            "provider_writes_possible",
            "live_provider_acceptance_verified",
            "compilation_id",
            "ir_sha256",
        }
        if set(value) != required or value.get("schema") != CONTROL_IR_SCHEMA:
            raise DataUseProviderValidationError("control_ir schema or shape is unsupported")
        expected_ir = _sha256(
            {key: item for key, item in value.items() if key not in {"compilation_id", "ir_sha256"}}
        )
        if (
            not hmac.compare_digest(_digest(value.get("ir_sha256"), "ir_sha256"), expected_ir)
            or value.get("compilation_id") != f"duc-{expected_ir[:40]}"
        ):
            raise DataUseProviderValidationError("control_ir digest does not match")
        if value.get("tenant_id") != self._tenant_id:
            raise DataUseProviderConflict("control_ir tenant does not match the adapter")
        if value.get("compiler") != {
            "version": COMPILER_VERSION,
            "compiler_sha256": COMPILER_AUTHORITY_SHA256,
        }:
            raise DataUseProviderConflict("control_ir compiler binding does not match")
        if value.get("provider_writes_possible") is not True:
            raise DataUseProviderConfigError(
                "control_ir was not compiled with a controlled native adapter"
            )
        if value.get("live_provider_acceptance_verified") is not False:
            raise DataUseProviderValidationError(
                "control_ir contains an unsupported live-acceptance claim"
            )
        adapter = value.get("native_adapter")
        expected_adapter = {
            "adapter_id": self.adapter_id,
            "adapter_authority_sha256": self.adapter_authority_sha256,
            "control_schema": CONTROL_IR_SCHEMA,
            "supported_effects": sorted(_EFFECTS),
            "controlled_operations": sorted(_OPERATIONS),
        }
        if adapter != expected_adapter:
            raise DataUseProviderConflict("control_ir adapter binding does not match")
        bindings = value.get("bindings")
        if not isinstance(bindings, dict) or not hmac.compare_digest(
            _digest(value.get("bindings_sha256"), "bindings_sha256"),
            _sha256(bindings),
        ):
            raise DataUseProviderValidationError("control_ir bindings digest does not match")
        binding = self._binding()
        field_ids, policy_bindings, exception_bindings = self._validate_compiler_bindings(
            bindings, binding
        )
        controls_by_kind: dict[str, list[dict[str, Any]]] = {}
        digests_by_kind: dict[str, str] = {}
        for kind, state_key in (
            ("desired", "desired_state"),
            ("rollback", "rollback_state"),
        ):
            digest_key = f"{state_key}_sha256"
            state = value[state_key]
            state_digest = _digest(value[digest_key], digest_key)
            expected_state = _sha256(
                {
                    "kind": kind,
                    "bindings_sha256": value["bindings_sha256"],
                    "controls": state,
                }
            )
            if not hmac.compare_digest(state_digest, expected_state):
                raise DataUseProviderValidationError(f"{kind} control state digest does not match")
            controls_by_kind[kind] = self._validate_control_state(
                state,
                rollback=kind == "rollback",
                asset_id=binding["asset_id"],
                field_ids=field_ids,
                policy_bindings=policy_bindings,
                exception_bindings=exception_bindings,
            )
            digests_by_kind[kind] = state_digest
        selected = "rollback" if rollback else "desired"
        return value, binding, controls_by_kind[selected], digests_by_kind[selected]

    @staticmethod
    def _request_uuid(seed_sha256: str, phase: str, index: int) -> str:
        seed = _digest(seed_sha256, "request seed")
        material = hashlib.sha256(f"{seed}:{phase}:{index}".encode("ascii")).hexdigest()
        return str(uuid.UUID(material[:32]))

    def _http_request(  # noqa: C901 - explicit fail-closed transport state machine
        self,
        *,
        binding: Mapping[str, Any],
        method: str,
        path: str,
        body: Mapping[str, Any] | None,
        idempotency_sha256: str,
        safe_read: bool,
    ) -> tuple[ProviderHttpResponse, list[dict[str, Any]]]:
        if method not in {"GET", "POST"} or not path.startswith("/"):
            raise DataUseProviderValidationError("provider operation is uncontrolled")
        origin = _origin(self.provider_id, binding["origin"])
        if "#" in path or "@" in path or len(path) > 1024:
            raise DataUseProviderValidationError("provider operation path is invalid")
        encoded = None if body is None else _canonical(body, maximum=64 * 1024)
        receipts: list[dict[str, Any]] = []
        request_receipt = {
            "method": method,
            "body_sha256": (None if encoded is None else hashlib.sha256(encoded).hexdigest()),
            "idempotency_sha256": _digest(idempotency_sha256, "HTTP idempotency_sha256"),
            "timeout_seconds": self._limits.timeout_seconds,
            "max_response_bytes": self._limits.max_response_bytes,
            "safe_read": safe_read,
        }
        for attempt in range(1, self._limits.max_attempts + 1):
            attempt_path = self._request_path_for_attempt(path, method=method, attempt=attempt)
            attempt_receipt = {
                **request_receipt,
                "path_sha256": hashlib.sha256(attempt_path.encode("ascii")).hexdigest(),
                "attempt": attempt,
            }
            current = self._assert_current_binding(binding)
            active_lease = self._lease(current)
            headers = {
                "Accept": "application/json",
                "Authorization": active_lease.authorization,
                "Content-Type": "application/json",
                "Idempotency-Key": idempotency_sha256,
                "User-Agent": "Lightwork-DataUse-Control/1",
            }
            try:
                response = self._transport.request(
                    method,
                    f"{origin}{attempt_path}",
                    headers=headers,
                    body=encoded,
                    timeout=self._limits.timeout_seconds,
                    max_response_bytes=self._limits.max_response_bytes,
                    allow_redirects=False,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except DataUseProviderRequestNotSent:
                receipts.append(
                    {
                        "request": attempt_receipt,
                        "dispatch": "proved_not_sent",
                    }
                )
                if attempt < self._limits.max_attempts:
                    self._sleep(self._retry_delay(attempt))
                    continue
                raise DataUseProviderUnavailable(
                    "provider request was not sent after bounded retries",
                    evidence={"http_receipts": receipts},
                    proved_no_effect=True,
                ) from None
            except DataUseProviderTransportAmbiguous:
                if safe_read and attempt < self._limits.max_attempts:
                    receipts.append(
                        {
                            "request": attempt_receipt,
                            "dispatch": "transport_unknown_read_only",
                        }
                    )
                    self._sleep(self._retry_delay(attempt))
                    continue
                error_type = (
                    DataUseProviderUnavailable if safe_read else DataUseProviderAmbiguousEffect
                )
                raise error_type(
                    "provider transport outcome is unavailable",
                    evidence={"http_receipts": receipts},
                ) from None
            except Exception:
                if safe_read and attempt < self._limits.max_attempts:
                    receipts.append(
                        {
                            "request": attempt_receipt,
                            "dispatch": "transport_error_read_only",
                        }
                    )
                    self._sleep(self._retry_delay(attempt))
                    continue
                error_type = (
                    DataUseProviderUnavailable if safe_read else DataUseProviderAmbiguousEffect
                )
                raise error_type(
                    "provider transport outcome is unavailable",
                    evidence={"http_receipts": receipts},
                ) from None
            if not isinstance(response, ProviderHttpResponse):
                if safe_read:
                    raise DataUseProviderProtocolError(
                        "provider transport returned an invalid response"
                    )
                raise DataUseProviderAmbiguousEffect(
                    "provider returned an invalid response after mutation dispatch",
                    evidence={"http_receipts": receipts},
                )
            if len(response.body) > self._limits.max_response_bytes:
                receipt = {
                    "request": attempt_receipt,
                    "response": {
                        "status_code": response.status_code,
                        "body_sha256": _sha256_bytes(response.body),
                        "body_bytes": len(response.body),
                    },
                }
                receipts.append(receipt)
                if safe_read:
                    raise DataUseProviderProtocolError(
                        "provider response exceeds the configured byte bound"
                    )
                raise DataUseProviderAmbiguousEffect(
                    "provider mutation response exceeded its byte bound",
                    evidence={"http_receipts": receipts},
                )
            try:
                safe_response = _safe_response_receipt(response)
            except DataUseProviderProtocolError:
                if safe_read:
                    raise
                evidence_receipt = {
                    "request": attempt_receipt,
                    "response": {
                        "status_code": response.status_code,
                        "body_sha256": _sha256_bytes(response.body),
                        "body_bytes": len(response.body),
                    },
                }
                receipts.append(evidence_receipt)
                raise DataUseProviderAmbiguousEffect(
                    "provider mutation response metadata was malformed",
                    evidence={"http_receipts": receipts},
                ) from None
            receipt = {
                "request": attempt_receipt,
                "response": safe_response,
            }
            receipts.append(receipt)
            status = response.status_code
            if 300 <= status <= 399:
                if safe_read:
                    raise DataUseProviderProtocolError("provider redirects are prohibited")
                raise DataUseProviderAmbiguousEffect(
                    "provider redirected a mutation request",
                    evidence={"http_receipts": receipts},
                )
            if status in _SAFE_TRANSIENT_STATUS:
                snowflake_idempotent_retry = bool(
                    self.provider_id == "snowflake"
                    and not safe_read
                    and method == "POST"
                    and path.startswith("/api/v2/statements?requestId=")
                )
                if (
                    safe_read or snowflake_idempotent_retry
                ) and attempt < self._limits.max_attempts:
                    self._sleep(self._retry_delay(attempt))
                    continue
                if safe_read:
                    raise DataUseProviderUnavailable(
                        "provider exhausted bounded safe retries",
                        evidence={"http_receipts": receipts},
                    )
                raise DataUseProviderAmbiguousEffect(
                    "provider transient response left mutation outcome ambiguous",
                    evidence={"http_receipts": receipts},
                )
            if status >= 500:
                if safe_read:
                    raise DataUseProviderUnavailable(
                        "provider read endpoint is unavailable",
                        evidence={"http_receipts": receipts},
                    )
                raise DataUseProviderAmbiguousEffect(
                    "provider server error left mutation outcome ambiguous",
                    evidence={"http_receipts": receipts},
                )
            if not 200 <= status <= 299:
                raise DataUseProviderProtocolError("provider rejected the controlled request")
            return response, receipts
        raise DataUseProviderUnavailable("provider retry bound was exhausted")

    def _request_path_for_attempt(self, path: str, *, method: str, attempt: int) -> str:
        """Use Snowflake's documented retry flag without changing its request ID."""

        if (
            self.provider_id == "snowflake"
            and method == "POST"
            and attempt > 1
            and path.startswith("/api/v2/statements?requestId=")
            and "&" not in path
        ):
            return f"{path}&retry=true"
        return path

    def _statement_body(
        self,
        binding: Mapping[str, Any],
        statement: str,
        *,
        correlation_sha256: str | None,
        change_kind: str | None = None,
        control_sha256: str | None = None,
        object_sha256: str | None = None,
        state_sha256: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(statement, str) or not 1 <= len(statement) <= 64 * 1024:
            raise DataUseProviderValidationError("generated provider statement is invalid")
        if ";" in statement or "--" in statement or "/*" in statement:
            raise DataUseProviderValidationError(
                "generated provider statement contains uncontrolled syntax"
            )
        correlation = (
            None
            if correlation_sha256 is None
            else _digest(correlation_sha256, "provider statement correlation_sha256")
        )
        audit_values = (change_kind, control_sha256, object_sha256, state_sha256)
        if correlation is None:
            if any(value is not None for value in audit_values):
                raise DataUseProviderValidationError(
                    "provider observation cannot carry mutation audit metadata"
                )
            audit_metadata: tuple[str, str, str, str | None] | None = None
        else:
            kind = str(change_kind or "")
            if kind not in _AUDIT_CHANGE_KINDS:
                raise DataUseProviderValidationError(
                    "provider mutation audit change kind is unsupported"
                )
            state = _optional_digest(state_sha256, "provider mutation state_sha256")
            if (kind == "state_anchor") != (state is not None):
                raise DataUseProviderValidationError(
                    "provider mutation state-anchor metadata is invalid"
                )
            audit_metadata = (
                kind,
                _digest(control_sha256, "provider mutation control_sha256"),
                _digest(object_sha256, "provider mutation object_sha256"),
                state,
            )
        if self.provider_id == "snowflake":
            body: dict[str, Any] = {
                "statement": statement,
                "timeout": max(1, math.ceil(self._limits.timeout_seconds)),
                "database": binding["catalog"],
                "schema": binding["schema_name"],
                "warehouse": binding["compute_id"],
            }
            if correlation is not None and audit_metadata is not None:
                kind, control, object_sha, state = audit_metadata
                body["parameters"] = {
                    "query_tag": (f"lw2:{correlation}:{kind}:{control}:{object_sha}:{state or '-'}")
                }
            return body
        body = {
            "statement": statement,
            "warehouse_id": binding["compute_id"],
            # Return immediately and reconcile through the adapter's bounded
            # status polling.  This leaves the HTTP timeout as transport margin.
            "wait_timeout": "0s",
            "on_wait_timeout": "CONTINUE",
        }
        if correlation is not None and audit_metadata is not None:
            kind, control, object_sha, state = audit_metadata
            body["query_tags"] = [
                {"key": "lw_corr", "value": correlation},
                {"key": "lw_kind", "value": kind},
                {"key": "lw_ctrl", "value": control},
                {"key": "lw_obj", "value": object_sha},
                {"key": "lw_state", "value": state or "-"},
            ]
        return body

    def _submit_path(self, request_uuid: str) -> str:
        if self.provider_id == "snowflake":
            return "/api/v2/statements?requestId=" + quote(request_uuid, safe="")
        return "/api/2.0/sql/statements"

    def _poll_path(self, handle: str) -> str:
        controlled = _token(handle, "provider statement handle")
        if self.provider_id == "snowflake":
            return "/api/v2/statements/" + quote(controlled, safe="")
        return "/api/2.0/sql/statements/" + quote(controlled, safe="")

    @staticmethod
    def _observed_digest(data: object) -> str | None:
        if not isinstance(data, list) or not data:
            return None
        row = data[0]
        if not isinstance(row, list) or not row:
            return None
        candidates = [item for item in row if isinstance(item, str)]
        for candidate in reversed(candidates):
            if _DIGEST_RE.fullmatch(candidate):
                return candidate
        return None

    def _retry_delay(self, attempt: int) -> float:
        limits = self._limits
        return min(limits.retry_base_seconds * (2 ** (attempt - 1)), limits.retry_max_seconds)

    @staticmethod
    def _poll_delay(response: ProviderHttpResponse, poll_index: int) -> float:
        """Return one bounded status-poll delay from safe provider metadata."""

        raw = next(
            (value for key, value in response.headers.items() if str(key).lower() == "retry-after"),
            None,
        )
        if isinstance(raw, str):
            try:
                parsed = float(raw)
            except ValueError:
                parsed = -1.0
            if math.isfinite(parsed) and 0.1 <= parsed <= 5.0:
                return parsed
        return min(0.25 * (2 ** (poll_index - 1)), 2.0)

    @staticmethod
    def _record_statement_reference(
        receipts: Sequence[dict[str, Any]],
        handle: str | None,
        *,
        change_kind: str | None = None,
        control_sha256: str | None = None,
        object_sha256: str | None = None,
        state_sha256: str | None = None,
    ) -> None:
        """Attach only a one-way provider statement reference to the latest receipt."""

        if handle is None:
            return
        statement_sha256 = hashlib.sha256(handle.encode("utf-8")).hexdigest()
        for receipt in reversed(receipts):
            response = receipt.get("response")
            if isinstance(response, dict):
                response["provider_statement_sha256"] = statement_sha256
                if change_kind is not None:
                    response["audit_change_kind"] = change_kind
                    response["audit_control_sha256"] = _digest(
                        control_sha256, "provider mutation control_sha256"
                    )
                    response["audit_object_sha256"] = _digest(
                        object_sha256, "provider mutation object_sha256"
                    )
                    response["audit_state_sha256"] = _optional_digest(
                        state_sha256, "provider mutation state_sha256"
                    )
                return
        raise DataUseProviderError("provider statement response receipt is unavailable")

    def _parse_provider_outcome(
        self, response: ProviderHttpResponse, *, observation: bool
    ) -> tuple[str, str | None, str | None]:
        body = _strict_json(
            response.body,
            maximum=self._limits.max_response_bytes,
            label="provider statement response",
        )
        if not isinstance(body, dict):
            raise DataUseProviderProtocolError("provider statement response must be an object")
        if self.provider_id == "snowflake":
            handle_value = body.get("statementHandle")
            handle = (
                None if handle_value is None else _token(handle_value, "Snowflake statement handle")
            )
            data = body.get("data")
            if isinstance(data, list):
                return (
                    "succeeded",
                    handle,
                    self._observed_digest(data) if observation else None,
                )
            if handle is not None and response.status_code in _MUTATION_ACCEPTED_STATUS:
                return "pending", handle, None
            raise DataUseProviderProtocolError("Snowflake statement response is unsupported")
        handle_value = body.get("statement_id")
        handle = (
            None if handle_value is None else _token(handle_value, "Databricks statement handle")
        )
        status = body.get("status")
        if not isinstance(status, dict) or set(status) - {"state", "error"}:
            raise DataUseProviderProtocolError("Databricks statement status is unsupported")
        state = status.get("state")
        if state == "SUCCEEDED":
            result = body.get("result")
            data = result.get("data_array") if isinstance(result, dict) else None
            if data is not None and not isinstance(data, list):
                raise DataUseProviderProtocolError("Databricks statement result is malformed")
            return (
                "succeeded",
                handle,
                self._observed_digest(data) if observation else None,
            )
        if state in {"PENDING", "RUNNING"} and handle is not None:
            return "pending", handle, None
        if state in {"FAILED", "CANCELED", "CLOSED"}:
            return "rejected", handle, None
        raise DataUseProviderProtocolError("Databricks statement state is unsupported")

    def _run_statement(
        self,
        *,
        binding: Mapping[str, Any],
        statement: str,
        request_sha256: str,
        phase: str,
        index: int,
        observation: bool,
        correlation_sha256: str | None = None,
        change_kind: str | None = None,
        control_sha256: str | None = None,
        object_sha256: str | None = None,
        state_sha256: str | None = None,
    ) -> tuple[str | None, list[dict[str, Any]]]:
        if observation:
            if correlation_sha256 is not None:
                raise DataUseProviderValidationError(
                    "provider observation cannot carry a mutation correlation"
                )
            correlation = None
        else:
            correlation = _digest(correlation_sha256, "provider mutation correlation_sha256")
        request_uuid = self._request_uuid(request_sha256, phase, index)
        http_idem = hashlib.sha256(f"{request_sha256}:{phase}:{index}".encode("ascii")).hexdigest()
        response, receipts = self._http_request(
            binding=binding,
            method="POST",
            path=self._submit_path(request_uuid),
            body=self._statement_body(
                binding,
                statement,
                correlation_sha256=correlation,
                change_kind=change_kind,
                control_sha256=control_sha256,
                object_sha256=object_sha256,
                state_sha256=state_sha256,
            ),
            idempotency_sha256=http_idem,
            safe_read=observation,
        )
        try:
            state, handle, observed = self._parse_provider_outcome(
                response, observation=observation
            )
            if not observation and state == "succeeded" and handle is None:
                raise DataUseProviderProtocolError(
                    "provider mutation response lacks statement identity"
                )
            accepted_handle = handle
            self._record_statement_reference(
                receipts,
                handle,
                change_kind=change_kind,
                control_sha256=control_sha256,
                object_sha256=object_sha256,
                state_sha256=state_sha256,
            )
        except (DataUseProviderProtocolError, DataUseProviderValidationError):
            if observation:
                raise DataUseProviderProtocolError(
                    "provider observation response was malformed"
                ) from None
            raise DataUseProviderAmbiguousEffect(
                "provider mutation success response was malformed",
                evidence={"http_receipts": receipts},
            ) from None
        if state == "rejected":
            raise DataUseProviderProtocolError("provider rejected the generated statement")
        for poll_index in range(1, self._limits.max_polls + 1):
            if state != "pending":
                return observed, receipts
            if handle is None:
                break
            self._sleep(self._poll_delay(response, poll_index))
            poll_idem = hashlib.sha256(f"{http_idem}:poll:{poll_index}".encode("ascii")).hexdigest()
            try:
                response, poll_receipts = self._http_request(
                    binding=binding,
                    method="GET",
                    path=self._poll_path(handle),
                    body=None,
                    idempotency_sha256=poll_idem,
                    safe_read=True,
                )
                receipts.extend(poll_receipts)
                try:
                    state, polled_handle, observed = self._parse_provider_outcome(
                        response, observation=observation
                    )
                    if (
                        polled_handle is not None
                        and accepted_handle is not None
                        and not hmac.compare_digest(polled_handle, accepted_handle)
                    ):
                        raise DataUseProviderProtocolError(
                            "provider polling statement identity changed"
                        )
                    handle = accepted_handle
                    self._record_statement_reference(
                        receipts,
                        polled_handle or accepted_handle,
                        change_kind=change_kind,
                        control_sha256=control_sha256,
                        object_sha256=object_sha256,
                        state_sha256=state_sha256,
                    )
                except DataUseProviderValidationError:
                    raise DataUseProviderProtocolError(
                        "provider polling identifiers are malformed"
                    ) from None
            except DataUseProviderUnavailable as exc:
                receipts.extend(exc.evidence.get("http_receipts", []))
                if observation:
                    raise DataUseProviderUnavailable(
                        "provider observation polling is unavailable",
                        evidence={"http_receipts": receipts},
                    ) from None
                raise DataUseProviderAmbiguousEffect(
                    "provider mutation was accepted but could not be reconciled",
                    evidence={"http_receipts": receipts},
                ) from None
            except DataUseProviderProtocolError:
                if observation:
                    raise
                raise DataUseProviderAmbiguousEffect(
                    "provider mutation polling response was malformed",
                    evidence={"http_receipts": receipts},
                ) from None
            if state == "rejected":
                raise DataUseProviderProtocolError("provider rejected the generated statement")
        if observation:
            raise DataUseProviderUnavailable(
                "provider observation exceeded its polling bound",
                evidence={"http_receipts": receipts},
            )
        raise DataUseProviderAmbiguousEffect(
            "provider mutation exceeded its polling bound",
            evidence={"http_receipts": receipts},
        )

    def _observation_statement(self, binding: Mapping[str, Any]) -> str:
        table = _quote_qualified(
            self.provider_id,
            (binding["catalog"], binding["schema_name"], binding["table"]),
        )
        if self.provider_id == "snowflake":
            anchor = ".".join(binding["state_anchor"])
            target = ".".join((binding["catalog"], binding["schema_name"], binding["table"]))
            return f"SELECT SYSTEM$GET_TAG('{anchor}', '{target}', 'TABLE')"
        return f"SHOW TBLPROPERTIES {table} ('lightwork.data_use_digest')"

    def _plan_statements(
        self,
        binding: Mapping[str, Any],
        controls: Sequence[Mapping[str, Any]],
        state_sha256: str,
        *,
        ir_sha256: str,
        operation_idempotency_sha256: str,
        rollback: bool,
    ) -> list[_PlannedStatement]:
        table = _quote_qualified(
            self.provider_id,
            (binding["catalog"], binding["schema_name"], binding["table"]),
        )
        principal = _quote_identifier(self.provider_id, binding["principal"])
        ordered = sorted(
            controls,
            key=lambda item: (str(item["field_id"]), str(item["control_id"])),
        )
        effects = {str(item["operation"]) for item in ordered}
        deny_first = bool(effects & {"deny", "review"})
        state = _digest(state_sha256, "native state_sha256")
        base = {
            "schema": _PROVIDER_AUDIT_PROJECTION_SCHEMA,
            "provider_id": self.provider_id,
            "binding_sha256": _digest(binding["binding_sha256"], "binding_sha256"),
            "operation_idempotency_sha256": _digest(
                operation_idempotency_sha256,
                "operation_idempotency_sha256",
            ),
            "ir_sha256": _digest(ir_sha256, "ir_sha256"),
            "operation": "rollback" if rollback else "apply",
            "target_state_sha256": state,
        }
        statements: list[_PlannedStatement] = []

        def append(kind: str, statement: str, material: Mapping[str, Any]) -> None:
            statements.append(
                _PlannedStatement(
                    statement=statement,
                    change_kind=kind,
                    control_sha256=_provider_audit_control_sha256(kind, base, material),
                    state_sha256=(
                        str(material["state_sha256"]) if kind == "state_anchor" else None
                    ),
                )
            )

        if deny_first:
            append(
                "revoke",
                f"REVOKE SELECT ON TABLE {table} FROM ROLE {principal}"
                if self.provider_id == "snowflake"
                else f"REVOKE SELECT ON TABLE {table} FROM {principal}",
                {"action": "revoke", "control_state_sha256": state},
            )
        for control in ordered:
            effect = str(control["operation"])
            field_id = str(control["field_id"])
            field_material = {
                "action": "set" if effect == "mask" else "unset",
                "field_sha256": _text_sha256(field_id),
                "control": _sha256(control),
            }
            column = _quote_identifier(self.provider_id, str(binding["field_map"][field_id]))
            if effect == "mask":
                method = str(control["parameters"]["method"])
                policy_parts = binding["mask_bindings"].get(method)
                if not isinstance(policy_parts, list):
                    raise DataUseProviderConflict("mask method has no enrolled native binding")
                policy = _quote_qualified(self.provider_id, policy_parts)
                if self.provider_id == "snowflake":
                    append(
                        "masking_policy",
                        f"ALTER TABLE {table} MODIFY COLUMN {column} SET MASKING POLICY {policy}",
                        field_material,
                    )
                else:
                    append(
                        "masking_policy",
                        f"ALTER TABLE {table} ALTER COLUMN {column} SET MASK {policy}",
                        field_material,
                    )
            elif effect in {"allow", "row_filter"}:
                if self.provider_id == "snowflake":
                    append(
                        "masking_policy",
                        f"ALTER TABLE {table} MODIFY COLUMN {column} UNSET MASKING POLICY",
                        field_material,
                    )
                else:
                    append(
                        "masking_policy",
                        f"ALTER TABLE {table} ALTER COLUMN {column} DROP MASK",
                        field_material,
                    )
        row_digests = {
            _sha256(control["parameters"]["ast"])
            for control in ordered
            if control["operation"] == "row_filter"
        }
        if len(row_digests) > 1:
            raise DataUseProviderValidationError(
                "a table cannot bind multiple native row-filter policies"
            )
        if row_digests:
            row_digest = next(iter(row_digests))
            function_parts = binding["row_filter_bindings"].get(row_digest)
            if not isinstance(function_parts, list):
                raise DataUseProviderConflict("row-filter AST has no enrolled native binding")
            function = _quote_qualified(self.provider_id, function_parts)
            row_control = next(item for item in ordered if item["operation"] == "row_filter")
            columns = ", ".join(
                _quote_identifier(self.provider_id, binding["field_map"][field])
                for field in _ast_fields(row_control["parameters"]["ast"])
            )
            if self.provider_id == "snowflake":
                append(
                    "row_filter",
                    f"ALTER TABLE {table} ADD ROW ACCESS POLICY {function} ON ({columns})",
                    {"action": "set", "row_filter_sha256": row_digest},
                )
            else:
                append(
                    "row_filter",
                    f"ALTER TABLE {table} SET ROW FILTER {function} ON ({columns})",
                    {"action": "set", "row_filter_sha256": row_digest},
                )
        if not deny_first:
            append(
                "grant",
                f"GRANT SELECT ON TABLE {table} TO ROLE {principal}"
                if self.provider_id == "snowflake"
                else f"GRANT SELECT ON TABLE {table} TO {principal}",
                {"action": "grant", "control_state_sha256": state},
            )
        if self.provider_id == "snowflake":
            anchor = _quote_qualified(self.provider_id, binding["state_anchor"])
            append(
                "state_anchor",
                f"ALTER TABLE {table} SET TAG {anchor} = '{state}'",
                {"action": "set", "state_sha256": state},
            )
        else:
            append(
                "state_anchor",
                f"ALTER TABLE {table} SET TBLPROPERTIES ('lightwork.data_use_digest' = '{state}')",
                {"action": "set", "state_sha256": state},
            )
        if not 1 <= len(statements) <= _MAX_STATEMENTS:
            raise DataUseProviderValidationError(
                "generated provider statement plan exceeds its bound"
            )
        return statements

    @staticmethod
    def _receipt_digest(receipts: Sequence[Mapping[str, Any]]) -> str:
        return _sha256(list(receipts))

    @staticmethod
    def _compact_receipts(
        receipts: Sequence[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        """Bound persisted evidence while retaining every mutation identity."""

        original = [dict(item) for item in receipts]
        by_statement: dict[str, dict[str, Any]] = {}
        identities: dict[str, tuple[object, ...]] = {}
        for item in original:
            response = item.get("response")
            if not isinstance(response, dict) or "audit_change_kind" not in response:
                continue
            statement = _digest(
                response.get("provider_statement_sha256"),
                "provider_statement_sha256",
            )
            identity = (
                response.get("audit_change_kind"),
                response.get("audit_control_sha256"),
                response.get("audit_object_sha256"),
                response.get("audit_state_sha256"),
            )
            previous = identities.get(statement)
            if previous is not None and previous != identity:
                raise DataUseProviderAmbiguousEffect(
                    "provider statement identity mapped to multiple mutations"
                )
            identities[statement] = identity
            by_statement[statement] = item
        compacted = [by_statement[key] for key in sorted(by_statement)]
        if len(compacted) < _MAX_STATEMENTS:
            compacted.append(
                {
                    "summary": {
                        "http_receipts_sha256": _sha256(original),
                        "http_request_count": len(original),
                        "retained_statement_bindings": len(compacted),
                        "compacted": True,
                    }
                }
            )
        if len(compacted) > _MAX_STATEMENTS:
            raise DataUseProviderAmbiguousEffect(
                "provider evidence exceeds the persisted statement bound"
            )
        _canonical(compacted)
        return compacted

    def _operation_correlation_sha256(
        self,
        *,
        binding_sha256: str,
        operation_idempotency_sha256: str,
        operation_request_sha256: str,
    ) -> str:
        """Mirror the audit authority's closed operation-correlation material."""

        return _sha256(
            {
                "provider_id": self.provider_id,
                "binding_sha256": _digest(binding_sha256, "binding_sha256"),
                "operation_idempotency_sha256": _digest(
                    operation_idempotency_sha256,
                    "operation_idempotency_sha256",
                ),
                "operation_request_sha256": _digest(
                    operation_request_sha256,
                    "operation_request_sha256",
                ),
            }
        )

    def _operation_evidence(
        self,
        *,
        request_sha256: str,
        state_sha256: str,
        receipts: Sequence[Mapping[str, Any]],
        completed_statements: int,
        disposition: str,
    ) -> dict[str, Any]:
        compacted = self._compact_receipts(receipts)
        return {
            "schema": PROVIDER_OPERATION_SCHEMA,
            "request_sha256": request_sha256,
            "target_state_sha256": state_sha256,
            "http_receipts_sha256": self._receipt_digest(compacted),
            "http_request_count": len(receipts),
            "http_receipts": compacted,
            "completed_statements": completed_statements,
            "disposition": disposition,
            "credential_material_recorded": False,
            "live_provider_acceptance_verified": False,
        }

    def _result(
        self,
        *,
        control_ir: Mapping[str, Any],
        binding: Mapping[str, Any],
        idempotency_sha256: str,
        request_sha256: str,
        state_sha256: str,
        before_sha256: str | None,
        after_sha256: str,
        receipts: Sequence[Mapping[str, Any]],
        no_change: bool,
        rollback: bool,
    ) -> dict[str, Any]:
        compacted = self._compact_receipts(receipts)
        material: dict[str, Any] = {
            "schema": PROVIDER_RESULT_SCHEMA,
            "tenant_id": self._tenant_id,
            "provider_id": self.provider_id,
            "adapter_id": self.adapter_id,
            "binding_id": self._binding_id,
            "binding_revision": binding["revision"],
            "binding_sha256": binding["binding_sha256"],
            "compilation_id": control_ir["compilation_id"],
            "ir_sha256": control_ir["ir_sha256"],
            "operation": "rollback" if rollback else "apply",
            "idempotency_sha256": idempotency_sha256,
            "request_sha256": request_sha256,
            "target_state_sha256": state_sha256,
            "observed_before_sha256": before_sha256,
            "observed_after_sha256": after_sha256,
            "reconciliation": "no_change" if no_change else "converged",
            "no_change": no_change,
            "provider_writes_possible": True,
            "credential_material_recorded": False,
            "http_receipts": compacted,
            "http_receipts_sha256": self._receipt_digest(compacted),
            "rollback_mode": "compiled_safe_deny" if rollback else None,
            "restored_prior_native_state": False,
            "live_provider_acceptance_verified": False,
            "result_sha256": "",
        }
        material["result_sha256"] = _sha256(
            {key: value for key, value in material.items() if key != "result_sha256"}
        )
        return material

    def _execute(
        self,
        control_ir: Mapping[str, Any],
        idempotency_sha256: str,
        *,
        rollback: bool,
    ) -> Mapping[str, Any]:
        if not provider_config_enabled(self.provider_id, self._config):
            raise DataUseProviderConfigError("native provider enforcement is disabled")
        if not self.provider_writes_possible or self.supported_effects != _EFFECTS:
            raise DataUseProviderConfigError("native provider enforcement is not fully controlled")
        idem = _digest(idempotency_sha256, "idempotency_sha256")
        ir, binding, controls, state_sha256 = self._validate_ir(control_ir, rollback=rollback)
        request_sha256 = _sha256(
            {
                "provider_id": self.provider_id,
                "adapter_id": self.adapter_id,
                "adapter_authority_sha256": self.adapter_authority_sha256,
                "tenant_id": self._tenant_id,
                "binding_id": self._binding_id,
                "binding_revision": binding["revision"],
                "binding_sha256": binding["binding_sha256"],
                "ir_sha256": ir["ir_sha256"],
                "state_sha256": state_sha256,
                "operation": "rollback" if rollback else "apply",
                "idempotency_sha256": idem,
            }
        )
        correlation_sha256 = self._operation_correlation_sha256(
            binding_sha256=binding["binding_sha256"],
            operation_idempotency_sha256=idem,
            operation_request_sha256=request_sha256,
        )
        statements = self._plan_statements(
            binding,
            controls,
            state_sha256,
            ir_sha256=ir["ir_sha256"],
            operation_idempotency_sha256=idem,
            rollback=rollback,
        )
        object_sha256 = _provider_audit_object_sha256(binding)
        replay = self._bindings.claim_operation(
            tenant_id=self._tenant_id,
            provider_id=self.provider_id,
            binding_id=self._binding_id,
            idempotency_sha256=idem,
            request_sha256=request_sha256,
        )
        if replay is not None:
            return replay
        receipts: list[dict[str, Any]] = []
        completed_statements = 0
        mutation_started = False
        try:
            self._lease(binding)
            before_sha256, observed_receipts = self._run_statement(
                binding=binding,
                statement=self._observation_statement(binding),
                request_sha256=request_sha256,
                phase="observe-before",
                index=0,
                observation=True,
            )
            receipts.extend(observed_receipts)
            self._assert_current_binding(binding)
            if before_sha256 == state_sha256:
                result = self._result(
                    control_ir=ir,
                    binding=binding,
                    idempotency_sha256=idem,
                    request_sha256=request_sha256,
                    state_sha256=state_sha256,
                    before_sha256=before_sha256,
                    after_sha256=state_sha256,
                    receipts=receipts,
                    no_change=True,
                    rollback=rollback,
                )
                return self._bindings.finish_operation(
                    tenant_id=self._tenant_id,
                    provider_id=self.provider_id,
                    binding_id=self._binding_id,
                    idempotency_sha256=idem,
                    request_sha256=request_sha256,
                    result=result,
                )
            for index, planned in enumerate(statements, start=1):
                mutation_started = True
                _, statement_receipts = self._run_statement(
                    binding=binding,
                    statement=planned.statement,
                    request_sha256=request_sha256,
                    phase="rollback" if rollback else "apply",
                    index=index,
                    observation=False,
                    correlation_sha256=correlation_sha256,
                    change_kind=planned.change_kind,
                    control_sha256=planned.control_sha256,
                    object_sha256=object_sha256,
                    state_sha256=planned.state_sha256,
                )
                receipts.extend(statement_receipts)
                completed_statements += 1
            after_sha256, observed_receipts = self._run_statement(
                binding=binding,
                statement=self._observation_statement(binding),
                request_sha256=request_sha256,
                phase="observe-after",
                index=0,
                observation=True,
            )
            receipts.extend(observed_receipts)
            self._assert_current_binding(binding)
            if after_sha256 != state_sha256:
                raise DataUseProviderAmbiguousEffect(
                    "provider observed state does not match the desired digest",
                    evidence={"http_receipts": receipts},
                )
            result = self._result(
                control_ir=ir,
                binding=binding,
                idempotency_sha256=idem,
                request_sha256=request_sha256,
                state_sha256=state_sha256,
                before_sha256=before_sha256,
                after_sha256=after_sha256,
                receipts=receipts,
                no_change=False,
                rollback=rollback,
            )
            return self._bindings.finish_operation(
                tenant_id=self._tenant_id,
                provider_id=self.provider_id,
                binding_id=self._binding_id,
                idempotency_sha256=idem,
                request_sha256=request_sha256,
                result=result,
            )
        except DataUseProviderAmbiguousEffect as exc:
            extra = exc.evidence.get("http_receipts")
            if isinstance(extra, list) and extra is not receipts:
                receipts.extend(item for item in extra if item not in receipts)
            evidence = self._operation_evidence(
                request_sha256=request_sha256,
                state_sha256=state_sha256,
                receipts=receipts,
                completed_statements=completed_statements,
                disposition="ambiguous_fail_closed",
            )
            self._bindings.mark_operation(
                tenant_id=self._tenant_id,
                provider_id=self.provider_id,
                binding_id=self._binding_id,
                idempotency_sha256=idem,
                request_sha256=request_sha256,
                status="ambiguous",
                evidence=evidence,
            )
            raise DataUseProviderAmbiguousEffect(
                "provider mutation outcome is ambiguous; manual reconciliation is required",
                evidence=evidence,
            ) from None
        except DataUseProviderUnavailable as exc:
            extra = exc.evidence.get("http_receipts")
            if isinstance(extra, list):
                receipts.extend(item for item in extra if item not in receipts)
            ambiguous = completed_statements > 0 or (mutation_started and not exc.proved_no_effect)
            disposition = "ambiguous_fail_closed" if ambiguous else "proved_no_effect"
            evidence = self._operation_evidence(
                request_sha256=request_sha256,
                state_sha256=state_sha256,
                receipts=receipts,
                completed_statements=completed_statements,
                disposition=disposition,
            )
            self._bindings.mark_operation(
                tenant_id=self._tenant_id,
                provider_id=self.provider_id,
                binding_id=self._binding_id,
                idempotency_sha256=idem,
                request_sha256=request_sha256,
                status="ambiguous" if ambiguous else "failed_no_effect",
                evidence=evidence,
            )
            if ambiguous:
                raise DataUseProviderAmbiguousEffect(
                    "provider became unavailable after mutation dispatch",
                    evidence=evidence,
                ) from None
            raise DataUseProviderUnavailable(
                "provider is unavailable and no mutation was dispatched",
                evidence=evidence,
            ) from None
        except DataUseProviderError:
            ambiguous = completed_statements > 0
            evidence = self._operation_evidence(
                request_sha256=request_sha256,
                state_sha256=state_sha256,
                receipts=receipts,
                completed_statements=completed_statements,
                disposition=("ambiguous_fail_closed" if ambiguous else "proved_no_effect"),
            )
            self._bindings.mark_operation(
                tenant_id=self._tenant_id,
                provider_id=self.provider_id,
                binding_id=self._binding_id,
                idempotency_sha256=idem,
                request_sha256=request_sha256,
                status="ambiguous" if ambiguous else "failed_no_effect",
                evidence=evidence,
            )
            if ambiguous:
                raise DataUseProviderAmbiguousEffect(
                    "provider operation partially completed; reconciliation is required",
                    evidence=evidence,
                ) from None
            raise

    def apply_control_ir(
        self, control_ir: Mapping[str, Any], *, idempotency_sha256: str
    ) -> Mapping[str, Any]:
        """Reconcile the compiler's desired state using the enrolled native binding."""

        return self._execute(control_ir, idempotency_sha256, rollback=False)

    def rollback_control_ir(
        self, control_ir: Mapping[str, Any], *, idempotency_sha256: str
    ) -> Mapping[str, Any]:
        """Apply compiled safe-deny state; prior provider state is not restored."""

        return self._execute(control_ir, idempotency_sha256, rollback=True)


class SnowflakeDataUseControlAdapter(_NativeProviderAdapter):
    """Controlled Snowflake SQL API adapter for compiler-produced data-use IR."""

    provider_id = "snowflake"
    adapter_id = "snowflake-native"


class DatabricksDataUseControlAdapter(_NativeProviderAdapter):
    """Controlled Databricks Statement Execution adapter for data-use IR."""

    provider_id = "databricks"
    adapter_id = "databricks-native"


__all__ = [
    "CredentialLease",
    "DataUseProviderAmbiguousEffect",
    "DataUseProviderConfigError",
    "DataUseProviderConflict",
    "DataUseProviderCredentialError",
    "DataUseProviderError",
    "DataUseProviderNotFound",
    "DataUseProviderProtocolError",
    "DataUseProviderRequestNotSent",
    "DataUseProviderTransportAmbiguous",
    "DataUseProviderUnavailable",
    "DataUseProviderValidationError",
    "DatabricksDataUseControlAdapter",
    "PROVIDER_BINDING_SCHEMA",
    "PROVIDER_OPERATION_SCHEMA",
    "PROVIDER_RESPONSE_SCHEMA",
    "PROVIDER_RESULT_SCHEMA",
    "ProviderBindingStore",
    "ProviderCredentialOwner",
    "ProviderHttpResponse",
    "ProviderHttpTransport",
    "ProviderLimits",
    "SnowflakeDataUseControlAdapter",
    "provider_config_enabled",
]
