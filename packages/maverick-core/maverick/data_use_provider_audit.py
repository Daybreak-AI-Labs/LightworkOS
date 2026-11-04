"""Durable, digest-only native data-use provider audit reconciliation.

This module is intentionally a read-only evidence plane.  A trusted deployment
injects provider transport and ephemeral credential ownership; no public method
accepts raw Snowflake or Databricks audit payloads.  The transport returns one
of the two closed provider event dataclasses below.  Persisted state contains
only opaque references, closed codes, timestamps, counters, and SHA-256 pins --
never SQL text, provider principals, client addresses, credentials, or raw log
records.

Databricks ``system.query.history`` is the primary statement-correlation event
source in this contract.  ``system.access.audit`` remains a supplemental source;
neither source is treated as proof of audit-log completeness.

Local tests establish the control contract, not live provider compatibility or
the completeness of provider audit logs.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Protocol

from .config import load_config
from .data_use_provider_adapters import PROVIDER_RESULT_SCHEMA
from .file_lock import ensure_private_directory
from .sqlite_closing import ClosingConnection

EXPECTATION_SCHEMA = "lightwork.data-use.provider-audit-expectation.v1"
SNOWFLAKE_EVENT_SCHEMA = "lightwork.data-use.snowflake-audit-event.v2"
DATABRICKS_EVENT_SCHEMA = "lightwork.data-use.databricks-audit-event.v2"
AUDIT_BATCH_SCHEMA = "lightwork.data-use.provider-audit-batch.v2"
CLAIM_SCHEMA = "lightwork.data-use.provider-audit-claim.v1"
CONTROL_AUTHORITY_SCHEMA = "lightwork.data-use.provider-audit-control-authority.v1"
READ_AUTHORITY_SCHEMA = "lightwork.data-use.provider-audit-read-authority.v1"

NETWORK_IO = False
PROVIDER_WRITES = False
LIVE_PROVIDER_ACCEPTANCE = False

_PROVIDERS = frozenset({"snowflake", "databricks"})
_SNOWFLAKE_SOURCES = frozenset({"access_history", "query_history"})
_DATABRICKS_QUERY_SOURCE = "system.query.history"
_DATABRICKS_ACCESS_SOURCE = "system.access.audit"
_DATABRICKS_SOURCES = frozenset({_DATABRICKS_QUERY_SOURCE, _DATABRICKS_ACCESS_SOURCE})
_REFERENCE_KINDS = frozenset(
    {
        "databricks_request_id",
        "databricks_statement_id",
        "snowflake_query_id",
    }
)
_WATERMARK_KINDS = frozenset({"databricks_accepted_delivery", "snowflake_configured_latency"})
_CHANGE_KINDS = frozenset({"grant", "masking_policy", "revoke", "row_filter", "state_anchor"})
_OUTCOMES = frozenset({"failed", "succeeded"})
_OPERATIONS = frozenset({"apply", "rollback"})
_ACTIVE_STATES = frozenset({"queued", "leased"})
_TERMINAL_STATES = frozenset(
    {
        "ambiguous",
        "cancelled",
        "converged",
        "dead_letter",
        "drift",
        "extra",
        "missing",
        "no_change",
    }
)
_STATES = _ACTIVE_STATES | _TERMINAL_STATES
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_IDEM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_ERROR_RE = re.compile(r"[a-z][a-z0-9_]{0,47}\Z")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_EVENTS_PER_BATCH = 500
_MAX_EXPECTED_CHANGES = 520
_MAX_EXPECTATIONS = 100_000
_MAX_EVENTS = 1_000_000
_MAX_RETENTION_SECONDS = 10 * 366 * 86_400
_MAX_LEASE_SECONDS = 86_400
_MAX_BACKOFF_SECONDS = 86_400
_MAX_AUDIT_WINDOW_SECONDS = 7 * 86_400


class DataUseProviderAuditError(RuntimeError):
    """Base provider-audit error."""


class DataUseProviderAuditConfigError(DataUseProviderAuditError):
    """The audit plane is disabled or a server authority is unavailable."""


class DataUseProviderAuditValidationError(DataUseProviderAuditError, ValueError):
    """A closed audit contract is malformed."""


class DataUseProviderAuditConflict(DataUseProviderAuditError):
    """An exact revision, idempotency, or authority pin changed."""


class DataUseProviderAuditNotFound(DataUseProviderAuditError):
    """A tenant-local audit object is absent."""


class DataUseProviderAuditLeaseLost(DataUseProviderAuditError):
    """A worker lease is stale, expired, or forged."""


class DataUseProviderAuditIntegrityError(DataUseProviderAuditError):
    """Persisted audit state failed integrity validation."""


class DataUseProviderAuditRetryable(DataUseProviderAuditError):
    """A read-only provider fetch can be retried safely."""

    def __init__(self, error_code: str = "provider_temporarily_unavailable") -> None:
        self.error_code = _error_code(error_code)
        super().__init__(self.error_code)


class DataUseProviderAuditPermanent(DataUseProviderAuditError):
    """A provider fetch cannot succeed without operator intervention."""

    def __init__(self, error_code: str = "provider_contract_rejected") -> None:
        self.error_code = _error_code(error_code)
        super().__init__(self.error_code)


def enabled() -> bool:
    """Return true only for the exact default-off provider-audit gate."""

    try:
        config = load_config()
    except Exception:
        return False
    root = config.get("data_use_governance") if isinstance(config, Mapping) else None
    audit = root.get("provider_audit") if isinstance(root, Mapping) else None
    return bool(
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(audit, Mapping)
        and audit.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise DataUseProviderAuditConfigError(
            "provider audit is disabled; enable data_use_governance.provider_audit explicitly"
        )


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
        raise DataUseProviderAuditValidationError("audit value is not canonical JSON") from exc
    if len(encoded) > maximum:
        raise DataUseProviderAuditValidationError("audit value exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _same(left: object, right: object) -> bool:
    return isinstance(left, str) and isinstance(right, str) and hmac.compare_digest(left, right)


def _tenant(value: object) -> str:
    if not isinstance(value, str):
        raise DataUseProviderAuditValidationError("tenant_id must be text")
    normalized = unicodedata.normalize("NFC", value.strip())
    if not 1 <= len(normalized) <= 256 or any(ord(char) < 32 for char in normalized):
        raise DataUseProviderAuditValidationError("tenant_id is invalid")
    return normalized


def _provider(value: object) -> str:
    provider = str(value or "").strip().lower()
    if provider not in _PROVIDERS:
        raise DataUseProviderAuditValidationError("provider_id is unsupported")
    return provider


def _ref(value: object, label: str, *, idempotency: bool = False) -> str:
    pattern = _IDEM_RE if idempotency else _REF_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise DataUseProviderAuditValidationError(f"{label} is not a bounded opaque reference")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise DataUseProviderAuditValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(value: object, label: str) -> str | None:
    return None if value is None else _digest(value, label)


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise DataUseProviderAuditValidationError(f"{label} is outside its bound")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DataUseProviderAuditValidationError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise DataUseProviderAuditValidationError(f"{label} must be a positive finite timestamp")
    return result


def _optional_timestamp(value: object, label: str) -> float | None:
    return None if value is None else _timestamp(value, label)


def _error_code(value: object) -> str:
    if not isinstance(value, str) or _ERROR_RE.fullmatch(value) is None:
        raise DataUseProviderAuditValidationError("error_code is invalid")
    return value


def _now(clock: Callable[[], float]) -> float:
    return _timestamp(clock(), "clock")


def _privacy_safe(value: object) -> None:
    """Reject accidentally persisted raw provider/audit material."""

    forbidden = {
        "authorization",
        "client_ip",
        "credential",
        "email",
        "origin",
        "principal",
        "query_text",
        "raw_event",
        "sql",
        "statement",
        "token",
        "username",
    }

    def visit(item: object, depth: int) -> None:
        if depth > 16:
            raise DataUseProviderAuditValidationError("audit evidence nesting exceeds its bound")
        if isinstance(item, Mapping):
            for key, child in item.items():
                if not isinstance(key, str) or key.lower() in forbidden:
                    raise DataUseProviderAuditValidationError(
                        "raw provider or identity material cannot be persisted"
                    )
                visit(child, depth + 1)
        elif isinstance(item, (list, tuple)):
            if len(item) > _MAX_EVENTS_PER_BATCH:
                raise DataUseProviderAuditValidationError("audit collection exceeds its bound")
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str) and len(item) > 512:
            raise DataUseProviderAuditValidationError("audit text exceeds its bound")

    visit(value, 0)


@dataclass(frozen=True, slots=True)
class ProviderAuditExpectedChange:
    change_kind: str
    control_sha256: str
    change_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditStatementBinding:
    """Digest-only identity of one exact server-generated provider mutation."""

    provider_statement_sha256: str
    change_kind: str
    control_sha256: str
    object_sha256: str
    state_sha256: str | None = None


def expected_change_sha256(change_kind: str, control_sha256: str) -> str:
    kind = str(change_kind or "")
    if kind not in _CHANGE_KINDS:
        raise DataUseProviderAuditValidationError("expected change kind is unsupported")
    control = _digest(control_sha256, "control_sha256")
    return _sha256({"change_kind": kind, "control_sha256": control})


@dataclass(frozen=True, slots=True)
class ProviderAuditControlAuthority:
    tenant_id: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    operation_idempotency_sha256: str
    operation_request_sha256: str
    operation_result_sha256: str
    compilation_id: str
    ir_sha256: str
    operation: str
    target_state_sha256: str
    correlation_sha256: str
    expected_changes: tuple[ProviderAuditExpectedChange, ...]
    revision: int
    valid_until: float
    revoked: bool
    authority_sha256: str


def control_authority_sha256(authority: ProviderAuditControlAuthority) -> str:
    if type(authority) is not ProviderAuditControlAuthority:
        raise DataUseProviderAuditValidationError("control authority is invalid")
    body = asdict(authority)
    body.pop("authority_sha256")
    body["schema"] = CONTROL_AUTHORITY_SCHEMA
    return _sha256(body)


@dataclass(frozen=True, slots=True)
class ProviderAuditReadAuthority:
    tenant_id: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    credential_key_id_sha256: str
    credential_revision: int
    credential_authority_sha256: str
    capability: str
    capability_revision: int
    valid_until: float
    revoked: bool
    authority_sha256: str


def read_authority_sha256(authority: ProviderAuditReadAuthority) -> str:
    if type(authority) is not ProviderAuditReadAuthority:
        raise DataUseProviderAuditValidationError("read authority is invalid")
    body = asdict(authority)
    body.pop("authority_sha256")
    body["schema"] = READ_AUTHORITY_SCHEMA
    return _sha256(body)


@dataclass(frozen=True, slots=True, repr=False)
class ProviderAuditCredentialLease:
    authorization: str = field(repr=False)
    credential_key_id_sha256: str
    credential_revision: int
    credential_authority_sha256: str
    expires_at: float
    revoked: bool = False


class ProviderAuditCredentialOwner(Protocol):
    def lease(
        self, *, provider_id: str, tenant_id: str, binding_id: str
    ) -> ProviderAuditCredentialLease: ...


@dataclass(frozen=True, slots=True)
class ProviderAuditCursor:
    occurred_at: float
    event_id_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditAcceptedWatermark:
    """Trusted delivery coverage supplied by an injected operator authority."""

    tenant_sha256: str
    watermark_kind: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    covered_until: float
    authority_sha256: str
    expires_at: float
    revoked: bool = False


def accepted_watermark_sha256(value: ProviderAuditAcceptedWatermark) -> str:
    if type(value) is not ProviderAuditAcceptedWatermark:
        raise DataUseProviderAuditValidationError("provider audit accepted watermark is invalid")
    body = asdict(value)
    body.pop("authority_sha256")
    return _sha256(body)


@dataclass(frozen=True, slots=True)
class SnowflakeAuditEvent:
    source_view: str
    event_id_sha256: str
    query_id_sha256: str
    occurred_at: float
    correlation_sha256: str | None
    object_sha256: str
    change_kind: str
    control_sha256: str
    outcome: str
    state_sha256: str | None = None
    object_change_corroborated: bool = False


@dataclass(frozen=True, slots=True)
class DatabricksAuditEvent:
    source_table: str
    event_id_sha256: str
    request_id_sha256: str | None
    occurred_at: float
    correlation_sha256: str | None
    object_sha256: str
    change_kind: str
    control_sha256: str
    outcome: str
    state_sha256: str | None = None
    statement_id_sha256: str | None = None


ProviderAuditEvent = SnowflakeAuditEvent | DatabricksAuditEvent


@dataclass(frozen=True, slots=True)
class ProviderAuditBatch:
    events: tuple[ProviderAuditEvent, ...]
    next_cursor: ProviderAuditCursor
    covered_until: float
    complete: bool
    provider_receipt_sha256: str
    watermark: ProviderAuditAcceptedWatermark | None = None


@dataclass(frozen=True, slots=True)
class ProviderAuditReadRequest:
    schema: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    operation_idempotency_sha256: str
    correlation_sha256: str
    object_sha256: str
    statement_bindings: tuple[ProviderAuditStatementBinding, ...]
    cursor: ProviderAuditCursor
    audit_deadline: float
    event_limit: int
    request_sha256: str


class ProviderAuditTransport(Protocol):
    def read(
        self,
        request: ProviderAuditReadRequest,
        credential: ProviderAuditCredentialLease,
    ) -> ProviderAuditBatch: ...


@dataclass(frozen=True, slots=True)
class ProviderAuditExpectation:
    expectation_id: str
    tenant_sha256: str
    provider_id: str
    binding_id: str
    binding_revision: int
    binding_sha256: str
    object_sha256: str
    credential_key_id_sha256: str
    credential_revision: int
    credential_authority_sha256: str
    capability_revision: int
    read_authority_sha256: str
    control_authority_revision: int
    control_authority_sha256: str
    operation_idempotency_sha256: str
    operation_request_sha256: str
    operation_result_sha256: str
    compilation_id: str
    ir_sha256: str
    operation: str
    target_state_sha256: str
    correlation_sha256: str
    expected_changes: tuple[ProviderAuditExpectedChange, ...]
    statement_bindings: tuple[ProviderAuditStatementBinding, ...]
    no_change: bool
    state: str
    cursor_occurred_at: float
    cursor_event_id_sha256: str
    audit_deadline: float
    attempts: int
    max_attempts: int
    next_attempt_at: float
    lease_owner_sha256: str | None
    lease_token_sha256: str | None
    lease_until: float | None
    matched_count: int
    unrelated_count: int
    issue_count: int
    last_error_code: str | None
    provider_receipt_sha256: str | None
    created_at: float
    updated_at: float
    completed_at: float | None
    retained_until: float
    revision: int
    previous_integrity_sha256: str | None
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderAuditClaim:
    schema: str
    expectation_id: str
    work_revision: int
    lease_owner_sha256: str
    lease_token: str
    provider_id: str
    binding_id: str
    binding_sha256: str
    operation_idempotency_sha256: str
    correlation_sha256: str
    cursor: ProviderAuditCursor
    audit_deadline: float


@dataclass(frozen=True, slots=True)
class ProviderAuditWorkerResult:
    claimed: int
    converged: int
    no_change: int
    findings: int
    retried: int
    dead_lettered: int
    cancelled: int


@dataclass(frozen=True, slots=True)
class ProviderAuditIntegrityVerification:
    expectations: int
    history_records: int
    event_records: int
    operation_records: int
    audit_events: int
    terminal_audit_sha256: str


def _expected_changes(value: object) -> tuple[ProviderAuditExpectedChange, ...]:
    if not isinstance(value, (list, tuple)) or not len(value) <= _MAX_EXPECTED_CHANGES:
        raise DataUseProviderAuditValidationError("expected changes exceed their bound")
    result: list[ProviderAuditExpectedChange] = []
    seen: set[str] = set()
    for item in value:
        if isinstance(item, ProviderAuditExpectedChange):
            change = item
        elif isinstance(item, Mapping) and set(item) == {
            "change_kind",
            "control_sha256",
            "change_sha256",
        }:
            change = ProviderAuditExpectedChange(**item)
        else:
            raise DataUseProviderAuditValidationError("expected change is invalid")
        kind = str(change.change_kind or "")
        if kind not in _CHANGE_KINDS:
            raise DataUseProviderAuditValidationError("expected change kind is unsupported")
        control = _digest(change.control_sha256, "control_sha256")
        expected = expected_change_sha256(kind, control)
        if not _same(change.change_sha256, expected) or expected in seen:
            raise DataUseProviderAuditValidationError(
                "expected changes are duplicated or failed integrity"
            )
        seen.add(expected)
        result.append(ProviderAuditExpectedChange(kind, control, expected))
    return tuple(sorted(result, key=lambda item: item.change_sha256))


def _statement_bindings(
    value: object,
    *,
    expected_changes: tuple[ProviderAuditExpectedChange, ...],
    object_sha256: str,
    target_state_sha256: str,
    no_change: bool,
) -> tuple[ProviderAuditStatementBinding, ...]:
    """Validate exact digest-only mutation references from operation receipts."""

    if not isinstance(value, (list, tuple)) or len(value) > _MAX_EXPECTED_CHANGES:
        raise DataUseProviderAuditValidationError("provider statement bindings exceed their bound")
    expected = {(change.change_kind, change.control_sha256): change for change in expected_changes}
    result: list[ProviderAuditStatementBinding] = []
    seen_statements: dict[str, ProviderAuditStatementBinding] = {}
    seen_changes: set[tuple[str, str]] = set()
    for item in value:
        if isinstance(item, ProviderAuditStatementBinding):
            binding = item
        elif isinstance(item, Mapping) and set(item) == {
            "provider_statement_sha256",
            "change_kind",
            "control_sha256",
            "object_sha256",
            "state_sha256",
        }:
            binding = ProviderAuditStatementBinding(**item)
        else:
            raise DataUseProviderAuditValidationError("provider statement binding is invalid")
        statement = _digest(
            binding.provider_statement_sha256,
            "provider_statement_sha256",
        )
        kind = str(binding.change_kind or "")
        control = _digest(binding.control_sha256, "statement control_sha256")
        object_sha = _digest(binding.object_sha256, "statement object_sha256")
        state = _optional_digest(binding.state_sha256, "statement state_sha256")
        change_key = (kind, control)
        if (
            change_key not in expected
            or not _same(object_sha, object_sha256)
            or (kind == "state_anchor") != (state is not None)
            or (state is not None and not _same(state, target_state_sha256))
        ):
            raise DataUseProviderAuditValidationError(
                "provider statement binding does not match expected change authority"
            )
        normalized = ProviderAuditStatementBinding(
            provider_statement_sha256=statement,
            change_kind=kind,
            control_sha256=control,
            object_sha256=object_sha,
            state_sha256=state,
        )
        previous = seen_statements.get(statement)
        if previous is not None and previous != normalized:
            raise DataUseProviderAuditValidationError(
                "provider statement reference maps to multiple expected changes"
            )
        if previous is None:
            if change_key in seen_changes:
                raise DataUseProviderAuditValidationError(
                    "expected change maps to multiple provider statements"
                )
            seen_statements[statement] = normalized
            seen_changes.add(change_key)
            result.append(normalized)
    if no_change:
        if result or expected_changes:
            raise DataUseProviderAuditValidationError(
                "no-change operation cannot carry mutation statement bindings"
            )
    elif seen_changes != set(expected):
        raise DataUseProviderAuditValidationError(
            "provider statement bindings do not cover every expected change"
        )
    return tuple(sorted(result, key=lambda item: item.provider_statement_sha256))


def _operation_statement_bindings(
    result: Mapping[str, Any],
    *,
    expected_changes: tuple[ProviderAuditExpectedChange, ...],
    object_sha256: str,
    target_state_sha256: str,
    no_change: bool,
) -> tuple[ProviderAuditStatementBinding, ...]:
    receipts = result.get("http_receipts")
    if not isinstance(receipts, list):
        raise DataUseProviderAuditConflict("provider operation receipts are unavailable")
    raw: list[dict[str, Any]] = []
    for receipt in receipts:
        if not isinstance(receipt, Mapping):
            continue
        response = receipt.get("response")
        if not isinstance(response, Mapping) or "audit_change_kind" not in response:
            continue
        required = {
            "provider_statement_sha256",
            "audit_change_kind",
            "audit_control_sha256",
            "audit_object_sha256",
            "audit_state_sha256",
        }
        if not required <= set(response):
            raise DataUseProviderAuditConflict(
                "provider mutation receipt lacks statement binding authority"
            )
        raw.append(
            {
                "provider_statement_sha256": response["provider_statement_sha256"],
                "change_kind": response["audit_change_kind"],
                "control_sha256": response["audit_control_sha256"],
                "object_sha256": response["audit_object_sha256"],
                "state_sha256": response["audit_state_sha256"],
            }
        )
    try:
        return _statement_bindings(
            raw,
            expected_changes=expected_changes,
            object_sha256=object_sha256,
            target_state_sha256=target_state_sha256,
            no_change=no_change,
        )
    except DataUseProviderAuditValidationError as exc:
        raise DataUseProviderAuditConflict(
            "provider operation statement bindings are incomplete or ambiguous"
        ) from exc


def _object_sha256(binding: Mapping[str, Any]) -> str:
    required = (
        "provider_id",
        "account_or_workspace_id",
        "catalog",
        "schema_name",
        "table",
    )
    if any(not isinstance(binding.get(key), str) for key in required):
        raise DataUseProviderAuditValidationError("provider binding target is incomplete")
    return _sha256({key: binding[key] for key in required})


def operation_correlation_sha256(
    *,
    provider_id: str,
    binding_sha256: str,
    operation_idempotency_sha256: str,
    operation_request_sha256: str,
) -> str:
    return _sha256(
        {
            "provider_id": _provider(provider_id),
            "binding_sha256": _digest(binding_sha256, "binding_sha256"),
            "operation_idempotency_sha256": _digest(
                operation_idempotency_sha256, "operation_idempotency_sha256"
            ),
            "operation_request_sha256": _digest(
                operation_request_sha256, "operation_request_sha256"
            ),
        }
    )


def _validated_read_authority(
    value: object,
    *,
    tenant_id: str,
    provider_id: str,
    binding: Mapping[str, Any],
    now: float,
) -> ProviderAuditReadAuthority:
    if type(value) is not ProviderAuditReadAuthority:
        raise DataUseProviderAuditConfigError("provider audit read authority is unavailable")
    authority = value
    if (
        _tenant(authority.tenant_id) != tenant_id
        or _provider(authority.provider_id) != provider_id
        or _ref(authority.binding_id, "binding_id") != binding["binding_id"]
        or _integer(authority.binding_revision, "binding_revision", 1, 2**31 - 1)
        != binding["revision"]
        or not _same(_digest(authority.binding_sha256, "binding_sha256"), binding["binding_sha256"])
        or authority.capability != "provider_audit_read"
        or _integer(authority.capability_revision, "capability_revision", 1, 2**31 - 1) < 1
        or _integer(authority.credential_revision, "credential_revision", 1, 2**31 - 1)
        != binding["credential_revision"]
        or not _same(
            _digest(authority.credential_key_id_sha256, "credential_key_id_sha256"),
            binding["credential_key_id_sha256"],
        )
        or not _same(
            _digest(authority.credential_authority_sha256, "credential_authority_sha256"),
            binding["credential_authority_sha256"],
        )
        or authority.revoked is not False
        or _timestamp(authority.valid_until, "read authority valid_until") <= now
        or not _same(
            _digest(authority.authority_sha256, "read authority_sha256"),
            read_authority_sha256(authority),
        )
    ):
        raise DataUseProviderAuditConflict("provider audit read authority is stale or revoked")
    return authority


def _validated_control_authority(
    value: object,
    *,
    tenant_id: str,
    tenant_sha256: str,
    provider_id: str,
    binding: Mapping[str, Any],
    operation: Mapping[str, Any],
    result: Mapping[str, Any],
    operation_idempotency_sha256: str,
    now: float,
) -> ProviderAuditControlAuthority:
    if type(value) is not ProviderAuditControlAuthority:
        raise DataUseProviderAuditConfigError("provider audit control authority is unavailable")
    authority = value
    changes = _expected_changes(authority.expected_changes)
    operation_result_sha = _sha256(result)
    correlation = operation_correlation_sha256(
        provider_id=provider_id,
        binding_sha256=binding["binding_sha256"],
        operation_idempotency_sha256=operation_idempotency_sha256,
        operation_request_sha256=operation["request_sha256"],
    )
    if (
        _text_sha256(_tenant(authority.tenant_id)) != tenant_sha256
        or _tenant(authority.tenant_id) != tenant_id
        or _provider(authority.provider_id) != provider_id
        or _ref(authority.binding_id, "binding_id") != binding["binding_id"]
        or authority.binding_revision != binding["revision"]
        or not _same(authority.binding_sha256, binding["binding_sha256"])
        or not _same(authority.operation_idempotency_sha256, operation_idempotency_sha256)
        or not _same(authority.operation_request_sha256, operation["request_sha256"])
        or not _same(authority.operation_result_sha256, operation_result_sha)
        or _ref(authority.compilation_id, "compilation_id") != result["compilation_id"]
        or not _same(_digest(authority.ir_sha256, "ir_sha256"), result["ir_sha256"])
        or authority.operation != result["operation"]
        or not _same(authority.target_state_sha256, result["target_state_sha256"])
        or not _same(authority.correlation_sha256, correlation)
        or authority.expected_changes != changes
        or _integer(authority.revision, "control authority revision", 1, 2**31 - 1) < 1
        or authority.revoked is not False
        or _timestamp(authority.valid_until, "control authority valid_until") <= now
        or not _same(
            _digest(authority.authority_sha256, "control authority_sha256"),
            control_authority_sha256(authority),
        )
    ):
        raise DataUseProviderAuditConflict("provider audit control authority is stale or invalid")
    if result["no_change"] is True and changes:
        raise DataUseProviderAuditConflict("no-change operation cannot expect provider mutations")
    if result["no_change"] is False and not changes:
        raise DataUseProviderAuditConflict("provider mutation has no exact audit expectations")
    return authority


def _validated_operation(
    value: object,
    *,
    tenant_id: str,
    provider_id: str,
    binding: Mapping[str, Any],
    operation_idempotency_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not isinstance(value, Mapping):
        raise DataUseProviderAuditNotFound("provider operation does not exist")
    operation = dict(value)
    required = {
        "tenant_id",
        "provider_id",
        "binding_id",
        "idempotency_sha256",
        "request_sha256",
        "status",
        "evidence",
        "created_at",
        "updated_at",
    }
    if set(operation) != required:
        raise DataUseProviderAuditConflict("provider operation projection changed schema")
    if (
        _tenant(operation["tenant_id"]) != tenant_id
        or _provider(operation["provider_id"]) != provider_id
        or _ref(operation["binding_id"], "binding_id") != binding["binding_id"]
        or not _same(
            _digest(operation["idempotency_sha256"], "operation idempotency_sha256"),
            operation_idempotency_sha256,
        )
        or operation["status"] != "complete"
    ):
        raise DataUseProviderAuditConflict("provider operation is not exact and complete")
    request_sha = _digest(operation["request_sha256"], "operation request_sha256")
    created_at = _timestamp(operation["created_at"], "operation created_at")
    updated_at = _timestamp(operation["updated_at"], "operation updated_at")
    if created_at > updated_at:
        raise DataUseProviderAuditConflict("provider operation timestamps are invalid")
    raw_result = operation["evidence"]
    if not isinstance(raw_result, Mapping):
        raise DataUseProviderAuditConflict("provider operation result is unavailable")
    result = dict(raw_result)
    required_result = {
        "schema",
        "tenant_id",
        "provider_id",
        "adapter_id",
        "binding_id",
        "binding_revision",
        "binding_sha256",
        "compilation_id",
        "ir_sha256",
        "operation",
        "idempotency_sha256",
        "request_sha256",
        "target_state_sha256",
        "observed_before_sha256",
        "observed_after_sha256",
        "reconciliation",
        "no_change",
        "provider_writes_possible",
        "credential_material_recorded",
        "http_receipts",
        "http_receipts_sha256",
        "rollback_mode",
        "restored_prior_native_state",
        "live_provider_acceptance_verified",
        "result_sha256",
    }
    if set(result) != required_result:
        raise DataUseProviderAuditConflict("provider reconciliation result changed schema")
    result_without_digest = {key: item for key, item in result.items() if key != "result_sha256"}
    if (
        result["schema"] != PROVIDER_RESULT_SCHEMA
        or _tenant(result["tenant_id"]) != tenant_id
        or _provider(result["provider_id"]) != provider_id
        or _ref(result["binding_id"], "binding_id") != binding["binding_id"]
        or result["binding_revision"] != binding["revision"]
        or not _same(result["binding_sha256"], binding["binding_sha256"])
        or result["operation"] not in _OPERATIONS
        or not _same(result["idempotency_sha256"], operation_idempotency_sha256)
        or not _same(result["request_sha256"], request_sha)
        or result["reconciliation"] not in {"converged", "no_change"}
        or not isinstance(result["no_change"], bool)
        or result["provider_writes_possible"] is not True
        or result["credential_material_recorded"] is not False
        or result["live_provider_acceptance_verified"] is not False
        or result["restored_prior_native_state"] is not False
        or not _same(
            _digest(result["result_sha256"], "provider result_sha256"),
            _sha256(result_without_digest),
        )
        or not _same(
            _digest(result["http_receipts_sha256"], "http_receipts_sha256"),
            _sha256(result["http_receipts"]),
        )
        or not _same(
            _digest(result["target_state_sha256"], "target_state_sha256"),
            _digest(result["observed_after_sha256"], "observed_after_sha256"),
        )
    ):
        raise DataUseProviderAuditConflict("provider reconciliation result failed integrity")
    _ref(result["compilation_id"], "compilation_id")
    _digest(result["ir_sha256"], "ir_sha256")
    _optional_digest(result["observed_before_sha256"], "observed_before_sha256")
    return operation, result


def _expectation_payload(value: ProviderAuditExpectation) -> dict[str, Any]:
    payload = asdict(value)
    payload.pop("integrity_sha256")
    payload["schema"] = EXPECTATION_SCHEMA
    _privacy_safe(payload)
    return payload


class DataUseProviderAuditStore:
    """Tenant-bound SQLite authority for audit expectations and evidence."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        binding_store: object,
        control_authority_resolver: Callable[
            [str, str, str, Mapping[str, Any]], ProviderAuditControlAuthority
        ],
        read_authority_resolver: Callable[[str, str], ProviderAuditReadAuthority],
        watermark_authority_resolver: Callable[
            [str, str, float], ProviderAuditAcceptedWatermark | None
        ]
        | None = None,
        config_gate: Callable[[], None] = require_enabled,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        if not callable(getattr(binding_store, "get_binding", None)) or not callable(
            getattr(binding_store, "get_operation", None)
        ):
            raise DataUseProviderAuditConfigError(
                "provider binding/operation authority is unavailable"
            )
        if not callable(control_authority_resolver) or not callable(read_authority_resolver):
            raise DataUseProviderAuditConfigError("provider audit resolvers are unavailable")
        self.path = Path(path)
        ensure_private_directory(self.path.parent)
        self._tenant_id = _tenant(tenant_id)
        self._tenant_sha256 = _text_sha256(self._tenant_id)
        self._binding_store = binding_store
        self._control_authority_resolver = control_authority_resolver
        self._read_authority_resolver = read_authority_resolver
        self._watermark_authority_resolver = watermark_authority_resolver
        self._config_gate = config_gate
        self._clock = clock
        self._retention = threading.local()
        self._initialize()

    def _check_gate(self) -> None:
        try:
            self._config_gate()
        except DataUseProviderAuditError:
            raise
        except Exception as exc:
            raise DataUseProviderAuditConfigError("provider audit gate rejected access") from exc

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.create_function(
            "provider_audit_retention_authorized",
            0,
            lambda: 1 if bool(getattr(self._retention, "authorized", False)) else 0,
        )
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS provider_audit_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS provider_audit_expectations(
                    expectation_id TEXT PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    binding_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    next_attempt_at REAL NOT NULL,
                    lease_until REAL,
                    retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS provider_audit_ready_idx
                    ON provider_audit_expectations(
                        tenant_sha256, state, next_attempt_at, expectation_id
                    );
                CREATE TABLE IF NOT EXISTS provider_audit_history(
                    expectation_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    tenant_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(expectation_id, revision)
                );
                CREATE TABLE IF NOT EXISTS provider_audit_events(
                    tenant_sha256 TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    event_id_sha256 TEXT NOT NULL,
                    expectation_id TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256, provider_id, event_id_sha256)
                );
                CREATE TABLE IF NOT EXISTS provider_audit_operations(
                    tenant_sha256 TEXT NOT NULL,
                    key_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    expectation_id TEXT NOT NULL,
                    result_integrity_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256, key_sha256)
                );
                CREATE TABLE IF NOT EXISTS provider_audit_chain(
                    sequence INTEGER PRIMARY KEY,
                    tenant_sha256 TEXT NOT NULL,
                    action TEXT NOT NULL,
                    object_ref TEXT NOT NULL,
                    detail_sha256 TEXT NOT NULL,
                    occurred_at REAL NOT NULL,
                    previous_event_sha256 TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE TRIGGER IF NOT EXISTS provider_audit_history_no_update
                    BEFORE UPDATE ON provider_audit_history
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit history'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_events_no_update
                    BEFORE UPDATE ON provider_audit_events
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit event'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_operations_no_update
                    BEFORE UPDATE ON provider_audit_operations
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit operation'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_chain_no_update
                    BEFORE UPDATE ON provider_audit_chain
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit chain'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_chain_no_delete
                    BEFORE DELETE ON provider_audit_chain
                    BEGIN SELECT RAISE(ABORT, 'immutable provider audit chain'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_expectations_guard_delete
                    BEFORE DELETE ON provider_audit_expectations
                    WHEN provider_audit_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_history_guard_delete
                    BEFORE DELETE ON provider_audit_history
                    WHEN provider_audit_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_events_guard_delete
                    BEFORE DELETE ON provider_audit_events
                    WHEN provider_audit_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit retention authority required'); END;
                CREATE TRIGGER IF NOT EXISTS provider_audit_operations_guard_delete
                    BEFORE DELETE ON provider_audit_operations
                    WHEN provider_audit_retention_authorized() != 1
                    BEGIN SELECT RAISE(ABORT, 'provider audit retention authority required'); END;
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO provider_audit_meta(key,value) VALUES('schema_version','1')"
            )
            row = connection.execute(
                "SELECT value FROM provider_audit_meta WHERE key='schema_version'"
            ).fetchone()
            if row is None or row["value"] != "1":
                raise DataUseProviderAuditIntegrityError(
                    "unsupported provider audit schema version"
                )

    @staticmethod
    def _row_payload(row: sqlite3.Row, label: str) -> tuple[dict[str, Any], str]:
        try:
            payload = json.loads(str(row["payload_json"]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise DataUseProviderAuditIntegrityError(f"stored {label} is invalid") from exc
        if not isinstance(payload, dict):
            raise DataUseProviderAuditIntegrityError(f"stored {label} is invalid")
        integrity = str(row["integrity_sha256"])
        if not _DIGEST_RE.fullmatch(integrity) or not _same(integrity, _sha256(payload)):
            raise DataUseProviderAuditIntegrityError(f"stored {label} failed integrity")
        _privacy_safe(payload)
        return payload, integrity

    def _validated_expectation(  # noqa: C901 - one complete persisted-state validator
        self, payload: Mapping[str, Any], integrity_sha256: str
    ) -> ProviderAuditExpectation:
        body = dict(payload)
        if body.pop("schema", None) != EXPECTATION_SCHEMA:
            raise DataUseProviderAuditIntegrityError("expectation schema is invalid")
        expected = set(ProviderAuditExpectation.__dataclass_fields__) - {"integrity_sha256"}
        if set(body) != expected:
            raise DataUseProviderAuditIntegrityError("expectation fields are invalid")
        try:
            body["expected_changes"] = _expected_changes(body["expected_changes"])
            body["statement_bindings"] = _statement_bindings(
                body["statement_bindings"],
                expected_changes=body["expected_changes"],
                object_sha256=str(body.get("object_sha256") or ""),
                target_state_sha256=str(body.get("target_state_sha256") or ""),
                no_change=body.get("no_change") is True,
            )
            value = ProviderAuditExpectation(**body, integrity_sha256=integrity_sha256)
            if not _same(value.tenant_sha256, self._tenant_sha256):
                raise DataUseProviderAuditIntegrityError("expectation crossed a tenant boundary")
            _ref(value.expectation_id, "expectation_id")
            _provider(value.provider_id)
            _ref(value.binding_id, "binding_id")
            _integer(value.binding_revision, "binding_revision", 1, 2**31 - 1)
            _digest(value.binding_sha256, "binding_sha256")
            _digest(value.object_sha256, "object_sha256")
            _digest(value.credential_key_id_sha256, "credential_key_id_sha256")
            _integer(value.credential_revision, "credential_revision", 1, 2**31 - 1)
            _digest(value.credential_authority_sha256, "credential_authority_sha256")
            _integer(value.capability_revision, "capability_revision", 1, 2**31 - 1)
            _digest(value.read_authority_sha256, "read_authority_sha256")
            _integer(
                value.control_authority_revision,
                "control_authority_revision",
                1,
                2**31 - 1,
            )
            _digest(value.control_authority_sha256, "control_authority_sha256")
            _digest(value.operation_idempotency_sha256, "operation_idempotency_sha256")
            _digest(value.operation_request_sha256, "operation_request_sha256")
            _digest(value.operation_result_sha256, "operation_result_sha256")
            _ref(value.compilation_id, "compilation_id")
            _digest(value.ir_sha256, "ir_sha256")
            if value.operation not in _OPERATIONS:
                raise DataUseProviderAuditIntegrityError("expectation operation is invalid")
            _digest(value.target_state_sha256, "target_state_sha256")
            _digest(value.correlation_sha256, "correlation_sha256")
            if not isinstance(value.no_change, bool) or value.no_change == bool(
                value.expected_changes
            ):
                raise DataUseProviderAuditIntegrityError(
                    "expectation no-change authority is inconsistent"
                )
            if value.state not in _STATES:
                raise DataUseProviderAuditIntegrityError("expectation state is invalid")
            _timestamp(value.cursor_occurred_at, "cursor occurred_at")
            _digest(value.cursor_event_id_sha256, "cursor event_id_sha256")
            _timestamp(value.audit_deadline, "audit_deadline")
            _integer(value.attempts, "attempts", 0, 20)
            _integer(value.max_attempts, "max_attempts", 1, 20)
            if value.attempts > value.max_attempts:
                raise DataUseProviderAuditIntegrityError("expectation attempts are invalid")
            _timestamp(value.next_attempt_at, "next_attempt_at")
            _integer(value.matched_count, "matched_count", 0, _MAX_EXPECTED_CHANGES)
            _integer(value.unrelated_count, "unrelated_count", 0, _MAX_EVENTS)
            _integer(value.issue_count, "issue_count", 0, _MAX_EVENTS)
            if value.matched_count > len(value.expected_changes):
                raise DataUseProviderAuditIntegrityError("expectation match count is invalid")
            if value.last_error_code is not None:
                _error_code(value.last_error_code)
            _optional_digest(value.provider_receipt_sha256, "provider_receipt_sha256")
            created = _timestamp(value.created_at, "created_at")
            updated = _timestamp(value.updated_at, "updated_at")
            retained = _timestamp(value.retained_until, "retained_until")
            completed = _optional_timestamp(value.completed_at, "completed_at")
            _integer(value.revision, "revision", 1, 2**31 - 1)
            previous = _optional_digest(
                value.previous_integrity_sha256, "previous_integrity_sha256"
            )
            if not created <= updated <= retained or value.audit_deadline > retained:
                raise DataUseProviderAuditIntegrityError("expectation retention is invalid")
            if value.revision == 1 and previous is not None:
                raise DataUseProviderAuditIntegrityError(
                    "initial expectation has previous integrity"
                )
            if value.revision > 1 and previous is None:
                raise DataUseProviderAuditIntegrityError("expectation history link is absent")
            lease_values = (
                value.lease_owner_sha256,
                value.lease_token_sha256,
                value.lease_until,
            )
            if value.state == "queued" and any(item is not None for item in lease_values):
                raise DataUseProviderAuditIntegrityError("queued expectation contains a lease")
            if value.state == "leased" and any(item is None for item in lease_values):
                raise DataUseProviderAuditIntegrityError("leased expectation lacks authority")
            if value.state in _TERMINAL_STATES and any(item is not None for item in lease_values):
                raise DataUseProviderAuditIntegrityError("terminal expectation contains a lease")
            if value.lease_owner_sha256 is not None:
                _digest(value.lease_owner_sha256, "lease_owner_sha256")
                _digest(value.lease_token_sha256, "lease_token_sha256")
                lease_until = _timestamp(value.lease_until, "lease_until")
                if lease_until > retained:
                    raise DataUseProviderAuditIntegrityError("lease exceeds retention")
            if value.state in _TERMINAL_STATES:
                if completed is None:
                    raise DataUseProviderAuditIntegrityError(
                        "terminal expectation lacks completion"
                    )
            elif completed is not None:
                raise DataUseProviderAuditIntegrityError("active expectation is completed")
            expected_integrity = _sha256(_expectation_payload(value))
            if not _same(expected_integrity, integrity_sha256):
                raise DataUseProviderAuditIntegrityError("expectation integrity is invalid")
            return value
        except DataUseProviderAuditIntegrityError:
            raise
        except DataUseProviderAuditError as exc:
            raise DataUseProviderAuditIntegrityError("expectation is malformed") from exc
        except (TypeError, ValueError) as exc:
            raise DataUseProviderAuditIntegrityError("expectation is malformed") from exc

    def _get_row(
        self, connection: sqlite3.Connection, expectation_id: str
    ) -> ProviderAuditExpectation:
        ref = _ref(expectation_id, "expectation_id")
        row = connection.execute(
            "SELECT * FROM provider_audit_expectations WHERE expectation_id=? AND tenant_sha256=?",
            (ref, self._tenant_sha256),
        ).fetchone()
        if row is None:
            raise DataUseProviderAuditNotFound("provider audit expectation does not exist")
        payload, integrity = self._row_payload(row, "expectation")
        value = self._validated_expectation(payload, integrity)
        if (
            row["provider_id"] != value.provider_id
            or row["binding_id"] != value.binding_id
            or row["state"] != value.state
            or int(row["revision"]) != value.revision
            or float(row["next_attempt_at"]) != value.next_attempt_at
            or (None if row["lease_until"] is None else float(row["lease_until"]))
            != value.lease_until
            or float(row["retained_until"]) != value.retained_until
        ):
            raise DataUseProviderAuditIntegrityError("expectation index is inconsistent")
        return value

    @staticmethod
    def _operation_key(value: object) -> str:
        key = _ref(value, "idempotency_key", idempotency=True)
        return _text_sha256(key)

    def _operation_replay(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
    ) -> ProviderAuditExpectation | None:
        row = connection.execute(
            "SELECT * FROM provider_audit_operations WHERE tenant_sha256=? AND key_sha256=?",
            (self._tenant_sha256, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if row["action"] != action or not _same(row["request_sha256"], request_sha256):
            raise DataUseProviderAuditConflict("provider audit idempotency key was rebound")
        value = self._get_row(connection, str(row["expectation_id"]))
        if not _same(row["result_integrity_sha256"], value.integrity_sha256):
            raise DataUseProviderAuditConflict("provider audit replay result changed")
        return value

    def _save_operation(
        self,
        connection: sqlite3.Connection,
        *,
        key_sha256: str,
        action: str,
        request_sha256: str,
        result: ProviderAuditExpectation,
        now: float,
    ) -> None:
        connection.execute(
            "INSERT INTO provider_audit_operations VALUES(?,?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                key_sha256,
                action,
                request_sha256,
                result.expectation_id,
                result.integrity_sha256,
                now,
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        *,
        action: str,
        object_ref: str,
        detail_sha256: str,
        now: float,
    ) -> None:
        action_ref = _ref(action, "audit action")
        object_id = _ref(object_ref, "audit object")
        detail = _digest(detail_sha256, "audit detail_sha256")
        row = connection.execute(
            "SELECT sequence,event_sha256 FROM provider_audit_chain "
            "WHERE tenant_sha256=? ORDER BY sequence DESC LIMIT 1",
            (self._tenant_sha256,),
        ).fetchone()
        previous = "0" * 64 if row is None else str(row["event_sha256"])
        sequence = int(
            connection.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM provider_audit_chain"
            ).fetchone()[0]
        )
        body = {
            "sequence": sequence,
            "tenant_sha256": self._tenant_sha256,
            "action": action_ref,
            "object_ref": object_id,
            "detail_sha256": detail,
            "occurred_at": now,
            "previous_event_sha256": previous,
        }
        event_sha = _sha256(body)
        connection.execute(
            "INSERT INTO provider_audit_chain VALUES(?,?,?,?,?,?,?,?)",
            (
                sequence,
                self._tenant_sha256,
                action_ref,
                object_id,
                detail,
                now,
                previous,
                event_sha,
            ),
        )

    def _insert_history(
        self, connection: sqlite3.Connection, value: ProviderAuditExpectation
    ) -> None:
        payload = _expectation_payload(value)
        connection.execute(
            "INSERT INTO provider_audit_history VALUES(?,?,?,?,?)",
            (
                value.expectation_id,
                value.revision,
                self._tenant_sha256,
                _canonical(payload).decode("ascii"),
                value.integrity_sha256,
            ),
        )

    def _insert_expectation(
        self, connection: sqlite3.Connection, value: ProviderAuditExpectation
    ) -> None:
        payload = _expectation_payload(value)
        connection.execute(
            "INSERT INTO provider_audit_expectations VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                value.expectation_id,
                self._tenant_sha256,
                value.provider_id,
                value.binding_id,
                value.state,
                value.revision,
                value.next_attempt_at,
                value.lease_until,
                value.retained_until,
                _canonical(payload).decode("ascii"),
                value.integrity_sha256,
            ),
        )

    def _replace_expectation(
        self,
        connection: sqlite3.Connection,
        current: ProviderAuditExpectation,
        **changes: object,
    ) -> ProviderAuditExpectation:
        candidate = replace(
            current,
            **changes,
            revision=current.revision + 1,
            previous_integrity_sha256=current.integrity_sha256,
            integrity_sha256="0" * 64,
        )
        integrity = _sha256(_expectation_payload(candidate))
        candidate = replace(candidate, integrity_sha256=integrity)
        self._validated_expectation(_expectation_payload(candidate), integrity)
        payload = _expectation_payload(candidate)
        cursor = connection.execute(
            "UPDATE provider_audit_expectations SET state=?,revision=?,next_attempt_at=?,"
            "lease_until=?,retained_until=?,payload_json=?,integrity_sha256=? "
            "WHERE expectation_id=? AND tenant_sha256=? AND revision=? AND integrity_sha256=?",
            (
                candidate.state,
                candidate.revision,
                candidate.next_attempt_at,
                candidate.lease_until,
                candidate.retained_until,
                _canonical(payload).decode("ascii"),
                integrity,
                current.expectation_id,
                self._tenant_sha256,
                current.revision,
                current.integrity_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise DataUseProviderAuditConflict("provider audit expectation changed")
        self._insert_history(connection, candidate)
        return candidate

    def _binding(self, provider_id: str, binding_id: str) -> dict[str, Any]:
        raw = self._binding_store.get_binding(self._tenant_id, binding_id)
        if not isinstance(raw, Mapping):
            raise DataUseProviderAuditNotFound("provider binding does not exist")
        binding = dict(raw)
        if (
            _tenant(binding.get("tenant_id")) != self._tenant_id
            or _provider(binding.get("provider_id")) != provider_id
            or _ref(binding.get("binding_id"), "binding_id") != binding_id
            or binding.get("revoked") is not False
            or _integer(binding.get("revision"), "binding revision", 1, 2**31 - 1) < 1
        ):
            raise DataUseProviderAuditConflict("provider binding is stale or revoked")
        for binding_field in (
            "binding_sha256",
            "credential_key_id_sha256",
            "credential_authority_sha256",
        ):
            _digest(binding.get(binding_field), binding_field)
        _integer(binding.get("credential_revision"), "credential_revision", 1, 2**31 - 1)
        return binding

    def _authorities(
        self,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
        now: float,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        ProviderAuditControlAuthority,
        ProviderAuditReadAuthority,
    ]:
        binding = self._binding(provider_id, binding_id)
        raw_operation = self._binding_store.get_operation(
            tenant_id=self._tenant_id,
            provider_id=provider_id,
            binding_id=binding_id,
            idempotency_sha256=operation_idempotency_sha256,
        )
        operation, result = _validated_operation(
            raw_operation,
            tenant_id=self._tenant_id,
            provider_id=provider_id,
            binding=binding,
            operation_idempotency_sha256=operation_idempotency_sha256,
        )
        control = _validated_control_authority(
            self._control_authority_resolver(
                provider_id,
                binding_id,
                operation_idempotency_sha256,
                result,
            ),
            tenant_id=self._tenant_id,
            tenant_sha256=self._tenant_sha256,
            provider_id=provider_id,
            binding=binding,
            operation=operation,
            result=result,
            operation_idempotency_sha256=operation_idempotency_sha256,
            now=now,
        )
        read = _validated_read_authority(
            self._read_authority_resolver(provider_id, binding_id),
            tenant_id=self._tenant_id,
            provider_id=provider_id,
            binding=binding,
            now=now,
        )
        return binding, operation, result, control, read

    @staticmethod
    def _authority_fingerprint(
        values: tuple[
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            ProviderAuditControlAuthority,
            ProviderAuditReadAuthority,
        ],
    ) -> str:
        binding, operation, result, control, read = values
        return _sha256(
            {
                "binding_sha256": binding["binding_sha256"],
                "binding_revision": binding["revision"],
                "operation_request_sha256": operation["request_sha256"],
                "operation_result_sha256": _sha256(result),
                "control_authority_sha256": control.authority_sha256,
                "read_authority_sha256": read.authority_sha256,
            }
        )

    def register_operation(
        self,
        *,
        provider_id: str,
        binding_id: str,
        operation_idempotency_sha256: str,
        audit_deadline: float,
        retained_until: float,
        idempotency_key: str,
        max_attempts: int = 5,
    ) -> ProviderAuditExpectation:
        """Pin one complete native operation to a durable audit expectation."""

        self._check_gate()
        provider = _provider(provider_id)
        binding_ref = _ref(binding_id, "binding_id")
        operation_idem = _digest(operation_idempotency_sha256, "operation_idempotency_sha256")
        attempts = _integer(max_attempts, "max_attempts", 1, 20)
        now = _now(self._clock)
        deadline = _timestamp(audit_deadline, "audit_deadline")
        retained = _timestamp(retained_until, "retained_until")
        if not now <= deadline <= now + _MAX_AUDIT_WINDOW_SECONDS:
            raise DataUseProviderAuditValidationError("audit deadline is outside its bound")
        if not deadline <= retained <= now + _MAX_RETENTION_SECONDS:
            raise DataUseProviderAuditValidationError("audit retention is outside its bound")
        first = self._authorities(provider, binding_ref, operation_idem, now)
        second = self._authorities(provider, binding_ref, operation_idem, now)
        if not _same(self._authority_fingerprint(first), self._authority_fingerprint(second)):
            raise DataUseProviderAuditConflict("provider audit authority drifted during enrollment")
        binding, operation, result, control, read = second
        object_sha256 = _object_sha256(binding)
        statement_bindings = _operation_statement_bindings(
            result,
            expected_changes=control.expected_changes,
            object_sha256=object_sha256,
            target_state_sha256=control.target_state_sha256,
            no_change=bool(result["no_change"]),
        )
        start_cursor = ProviderAuditCursor(
            occurred_at=max(0.001, float(operation["created_at"]) - 60.0),
            event_id_sha256="0" * 64,
        )
        request = {
            "action": "register_operation",
            "provider_id": provider,
            "binding_id": binding_ref,
            "operation_idempotency_sha256": operation_idem,
            "audit_deadline": deadline,
            "retained_until": retained,
            "max_attempts": attempts,
            "authority_fingerprint": self._authority_fingerprint(second),
        }
        request_sha = _sha256(request)
        key_sha = self._operation_key(idempotency_key)
        expectation_id = f"DUA-{_sha256(request)[:32]}"
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="register_operation",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM provider_audit_expectations WHERE tenant_sha256=?",
                    (self._tenant_sha256,),
                ).fetchone()[0]
            )
            if count >= _MAX_EXPECTATIONS:
                raise DataUseProviderAuditConflict("provider audit expectation capacity exhausted")
            existing = connection.execute(
                "SELECT expectation_id FROM provider_audit_expectations WHERE expectation_id=?",
                (expectation_id,),
            ).fetchone()
            if existing is not None:
                raise DataUseProviderAuditConflict("provider audit expectation already exists")
            value = ProviderAuditExpectation(
                expectation_id=expectation_id,
                tenant_sha256=self._tenant_sha256,
                provider_id=provider,
                binding_id=binding_ref,
                binding_revision=int(binding["revision"]),
                binding_sha256=str(binding["binding_sha256"]),
                object_sha256=object_sha256,
                credential_key_id_sha256=str(binding["credential_key_id_sha256"]),
                credential_revision=int(binding["credential_revision"]),
                credential_authority_sha256=str(binding["credential_authority_sha256"]),
                capability_revision=read.capability_revision,
                read_authority_sha256=read.authority_sha256,
                control_authority_revision=control.revision,
                control_authority_sha256=control.authority_sha256,
                operation_idempotency_sha256=operation_idem,
                operation_request_sha256=str(operation["request_sha256"]),
                operation_result_sha256=_sha256(result),
                compilation_id=control.compilation_id,
                ir_sha256=control.ir_sha256,
                operation=control.operation,
                target_state_sha256=control.target_state_sha256,
                correlation_sha256=control.correlation_sha256,
                expected_changes=control.expected_changes,
                statement_bindings=statement_bindings,
                no_change=bool(result["no_change"]),
                state="queued",
                cursor_occurred_at=start_cursor.occurred_at,
                cursor_event_id_sha256=start_cursor.event_id_sha256,
                audit_deadline=deadline,
                attempts=0,
                max_attempts=attempts,
                next_attempt_at=now,
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                matched_count=0,
                unrelated_count=0,
                issue_count=0,
                last_error_code=None,
                provider_receipt_sha256=None,
                created_at=now,
                updated_at=now,
                completed_at=None,
                retained_until=retained,
                revision=1,
                previous_integrity_sha256=None,
                integrity_sha256="0" * 64,
            )
            value = replace(value, integrity_sha256=_sha256(_expectation_payload(value)))
            self._validated_expectation(_expectation_payload(value), value.integrity_sha256)
            self._insert_expectation(connection, value)
            self._insert_history(connection, value)
            self._audit(
                connection,
                action="audit_expectation_registered",
                object_ref=expectation_id,
                detail_sha256=value.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="register_operation",
                request_sha256=request_sha,
                result=value,
                now=now,
            )
            connection.commit()
            return value

    def get_expectation(self, expectation_id: str) -> ProviderAuditExpectation:
        self._check_gate()
        with self._connect() as connection:
            return self._get_row(connection, expectation_id)

    def get_expectation_for_registration(
        self,
        idempotency_key: str,
    ) -> ProviderAuditExpectation:
        """Resolve the current expectation created by one registration key.

        Registration recovery must not recompute an expired audit deadline just
        to discover whether the original registration committed.  The durable
        operation record pins the original result; its historical integrity is
        verified before the current revision is returned.
        """

        self._check_gate()
        key_sha256 = self._operation_key(idempotency_key)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT action,expectation_id,result_integrity_sha256 "
                "FROM provider_audit_operations "
                "WHERE tenant_sha256=? AND key_sha256=?",
                (self._tenant_sha256, key_sha256),
            ).fetchone()
            if row is None:
                raise DataUseProviderAuditNotFound("provider audit registration does not exist")
            if row["action"] != "register_operation":
                raise DataUseProviderAuditConflict(
                    "provider audit idempotency key is not a registration"
                )
            expectation_id = str(row["expectation_id"])
            historical = connection.execute(
                "SELECT 1 FROM provider_audit_history "
                "WHERE tenant_sha256=? AND expectation_id=? "
                "AND integrity_sha256=?",
                (
                    self._tenant_sha256,
                    expectation_id,
                    str(row["result_integrity_sha256"]),
                ),
            ).fetchone()
            if historical is None:
                raise DataUseProviderAuditIntegrityError(
                    "provider audit registration lost its result evidence"
                )
            return self._get_row(connection, expectation_id)

    def list_expectations(
        self, *, state: str | None = None, limit: int = 100
    ) -> tuple[ProviderAuditExpectation, ...]:
        self._check_gate()
        bounded = _integer(limit, "limit", 1, 500)
        if state is not None and state not in _STATES:
            raise DataUseProviderAuditValidationError("expectation state is invalid")
        with self._connect() as connection:
            if state is None:
                rows = connection.execute(
                    "SELECT expectation_id FROM provider_audit_expectations "
                    "WHERE tenant_sha256=? ORDER BY expectation_id LIMIT ?",
                    (self._tenant_sha256, bounded),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT expectation_id FROM provider_audit_expectations "
                    "WHERE tenant_sha256=? AND state=? "
                    "ORDER BY next_attempt_at,expectation_id LIMIT ?",
                    (self._tenant_sha256, state, bounded),
                ).fetchall()
            return tuple(self._get_row(connection, str(row["expectation_id"])) for row in rows)

    @staticmethod
    def _claim(value: ProviderAuditExpectation, lease_token: str) -> ProviderAuditClaim:
        if value.state != "leased" or value.lease_owner_sha256 is None:
            raise DataUseProviderAuditLeaseLost("provider audit expectation is not leased")
        return ProviderAuditClaim(
            schema=CLAIM_SCHEMA,
            expectation_id=value.expectation_id,
            work_revision=value.revision,
            lease_owner_sha256=value.lease_owner_sha256,
            lease_token=lease_token,
            provider_id=value.provider_id,
            binding_id=value.binding_id,
            binding_sha256=value.binding_sha256,
            operation_idempotency_sha256=value.operation_idempotency_sha256,
            correlation_sha256=value.correlation_sha256,
            cursor=ProviderAuditCursor(
                value.cursor_occurred_at,
                value.cursor_event_id_sha256,
            ),
            audit_deadline=value.audit_deadline,
        )

    def _recover_expired(self, connection: sqlite3.Connection, *, now: float, limit: int) -> None:
        rows = connection.execute(
            "SELECT expectation_id FROM provider_audit_expectations "
            "WHERE tenant_sha256=? AND state='leased' AND lease_until<=? "
            "ORDER BY lease_until,expectation_id LIMIT ?",
            (self._tenant_sha256, now, limit),
        ).fetchall()
        for row in rows:
            current = self._get_row(connection, str(row["expectation_id"]))
            if (
                current.state != "leased"
                or current.lease_until is None
                or current.lease_until > now
            ):
                continue
            terminal = current.attempts >= current.max_attempts
            updated = self._replace_expectation(
                connection,
                current,
                state="dead_letter" if terminal else "queued",
                next_attempt_at=now,
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code="lease_recovery_exhausted" if terminal else "lease_expired",
                updated_at=now,
                completed_at=now if terminal else None,
            )
            self._audit(
                connection,
                action=(
                    "audit_expectation_dead_lettered"
                    if terminal
                    else "audit_expectation_lease_recovered"
                ),
                object_ref=updated.expectation_id,
                detail_sha256=updated.integrity_sha256,
                now=now,
            )

    def claim_ready(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
    ) -> tuple[ProviderAuditClaim, ...]:
        self._check_gate()
        worker = _ref(worker_id, "worker_id")
        bounded = _integer(limit, "limit", 1, 100)
        lease_for = _integer(lease_seconds, "lease_seconds", 1, _MAX_LEASE_SECONDS)
        now = _now(self._clock)
        owner_sha = _text_sha256(worker)
        claims: list[ProviderAuditClaim] = []
        with self._connect() as connection:
            self._begin(connection)
            self._recover_expired(connection, now=now, limit=bounded * 2)
            rows = connection.execute(
                "SELECT expectation_id FROM provider_audit_expectations "
                "WHERE tenant_sha256=? AND state='queued' AND next_attempt_at<=? "
                "AND retained_until>? ORDER BY next_attempt_at,expectation_id LIMIT ?",
                (self._tenant_sha256, now, now, bounded),
            ).fetchall()
            for row in rows:
                current = self._get_row(connection, str(row["expectation_id"]))
                if current.attempts >= current.max_attempts:
                    updated = self._replace_expectation(
                        connection,
                        current,
                        state="dead_letter",
                        last_error_code="attempt_limit_exhausted",
                        updated_at=now,
                        completed_at=now,
                    )
                    self._audit(
                        connection,
                        action="audit_expectation_dead_lettered",
                        object_ref=updated.expectation_id,
                        detail_sha256=updated.integrity_sha256,
                        now=now,
                    )
                    continue
                token = secrets.token_urlsafe(32)
                leased = self._replace_expectation(
                    connection,
                    current,
                    state="leased",
                    attempts=current.attempts + 1,
                    lease_owner_sha256=owner_sha,
                    lease_token_sha256=_text_sha256(token),
                    lease_until=min(now + lease_for, current.retained_until),
                    last_error_code=None,
                    updated_at=now,
                )
                claims.append(self._claim(leased, token))
                self._audit(
                    connection,
                    action="audit_expectation_leased",
                    object_ref=leased.expectation_id,
                    detail_sha256=leased.integrity_sha256,
                    now=now,
                )
            connection.commit()
        return tuple(claims)

    def _work_for_claim(
        self,
        connection: sqlite3.Connection,
        claim: ProviderAuditClaim,
        *,
        now: float,
    ) -> ProviderAuditExpectation:
        if type(claim) is not ProviderAuditClaim or claim.schema != CLAIM_SCHEMA:
            raise DataUseProviderAuditLeaseLost("provider audit claim is invalid")
        current = self._get_row(connection, claim.expectation_id)
        if (
            current.state != "leased"
            or current.revision != claim.work_revision
            or current.lease_owner_sha256 != claim.lease_owner_sha256
            or current.lease_token_sha256 is None
            or not _same(current.lease_token_sha256, _text_sha256(claim.lease_token))
            or current.lease_until is None
            or current.lease_until <= now
            or self._claim(current, claim.lease_token) != claim
        ):
            raise DataUseProviderAuditLeaseLost("provider audit lease no longer authorizes work")
        return current

    @staticmethod
    def _same_pins(
        value: ProviderAuditExpectation,
        authorities: tuple[
            dict[str, Any],
            dict[str, Any],
            dict[str, Any],
            ProviderAuditControlAuthority,
            ProviderAuditReadAuthority,
        ],
    ) -> bool:
        binding, operation, result, control, read = authorities
        try:
            statement_bindings = _operation_statement_bindings(
                result,
                expected_changes=control.expected_changes,
                object_sha256=value.object_sha256,
                target_state_sha256=value.target_state_sha256,
                no_change=value.no_change,
            )
        except DataUseProviderAuditError:
            return False
        return bool(
            binding["revision"] == value.binding_revision
            and _same(binding["binding_sha256"], value.binding_sha256)
            and _same(binding["credential_key_id_sha256"], value.credential_key_id_sha256)
            and binding["credential_revision"] == value.credential_revision
            and _same(
                binding["credential_authority_sha256"],
                value.credential_authority_sha256,
            )
            and read.capability_revision == value.capability_revision
            and _same(read.authority_sha256, value.read_authority_sha256)
            and control.revision == value.control_authority_revision
            and _same(control.authority_sha256, value.control_authority_sha256)
            and _same(operation["request_sha256"], value.operation_request_sha256)
            and _same(_sha256(result), value.operation_result_sha256)
            and control.expected_changes == value.expected_changes
            and statement_bindings == value.statement_bindings
        )

    def validate_claim_authority(self, claim: ProviderAuditClaim) -> ProviderAuditExpectation:
        """Re-read exact binding, operation, control, and capability pins."""

        self._check_gate()
        now = _now(self._clock)
        with self._connect() as connection:
            current = self._work_for_claim(connection, claim, now=now)
        authorities = self._authorities(
            current.provider_id,
            current.binding_id,
            current.operation_idempotency_sha256,
            now,
        )
        if not self._same_pins(current, authorities):
            raise DataUseProviderAuditConflict("provider audit authority changed after claim")
        return current

    @staticmethod
    def validate_credential(
        value: ProviderAuditExpectation,
        credential: object,
        *,
        now: float,
    ) -> ProviderAuditCredentialLease:
        if type(credential) is not ProviderAuditCredentialLease:
            raise DataUseProviderAuditConfigError("provider audit credential lease is unavailable")
        lease = credential
        if (
            not isinstance(lease.authorization, str)
            or not 1 <= len(lease.authorization) <= 8192
            or any(character in lease.authorization for character in "\r\n")
            or not _same(lease.credential_key_id_sha256, value.credential_key_id_sha256)
            or lease.credential_revision != value.credential_revision
            or not _same(
                lease.credential_authority_sha256,
                value.credential_authority_sha256,
            )
            or lease.revoked is not False
            or _timestamp(lease.expires_at, "credential expires_at") <= now
        ):
            raise DataUseProviderAuditConflict("provider audit credential is stale or revoked")
        return lease

    def read_request(
        self, claim: ProviderAuditClaim, *, event_limit: int = 100
    ) -> ProviderAuditReadRequest:
        current = self.validate_claim_authority(claim)
        bounded = _integer(event_limit, "event_limit", 1, _MAX_EVENTS_PER_BATCH)
        body = {
            "schema": AUDIT_BATCH_SCHEMA,
            "provider_id": current.provider_id,
            "binding_id": current.binding_id,
            "binding_revision": current.binding_revision,
            "binding_sha256": current.binding_sha256,
            "operation_idempotency_sha256": current.operation_idempotency_sha256,
            "correlation_sha256": current.correlation_sha256,
            "object_sha256": current.object_sha256,
            "statement_bindings": [asdict(item) for item in current.statement_bindings],
            "cursor": {
                "occurred_at": current.cursor_occurred_at,
                "event_id_sha256": current.cursor_event_id_sha256,
            },
            "audit_deadline": current.audit_deadline,
            "event_limit": bounded,
        }
        return ProviderAuditReadRequest(
            schema=AUDIT_BATCH_SCHEMA,
            provider_id=current.provider_id,
            binding_id=current.binding_id,
            binding_revision=current.binding_revision,
            binding_sha256=current.binding_sha256,
            operation_idempotency_sha256=current.operation_idempotency_sha256,
            correlation_sha256=current.correlation_sha256,
            object_sha256=current.object_sha256,
            statement_bindings=current.statement_bindings,
            cursor=ProviderAuditCursor(**body["cursor"]),
            audit_deadline=current.audit_deadline,
            event_limit=bounded,
            request_sha256=_sha256(body),
        )

    @staticmethod
    def _normalized_event(provider_id: str, value: object) -> tuple[dict[str, Any], str]:
        provider = _provider(provider_id)
        if provider == "snowflake":
            if type(value) is not SnowflakeAuditEvent:
                raise DataUseProviderAuditValidationError(
                    "Snowflake audit transport returned an invalid event"
                )
            event = value
            if event.source_view not in _SNOWFLAKE_SOURCES:
                raise DataUseProviderAuditValidationError("Snowflake audit source is unsupported")
            provider_reference = _digest(event.query_id_sha256, "query_id_sha256")
            provider_reference_kind = "snowflake_query_id"
            source = event.source_view
            schema = SNOWFLAKE_EVENT_SCHEMA
            if not isinstance(event.object_change_corroborated, bool):
                raise DataUseProviderAuditValidationError(
                    "Snowflake object-change corroboration is invalid"
                )
            object_change_corroborated: bool | None = event.object_change_corroborated
        else:
            if type(value) is not DatabricksAuditEvent:
                raise DataUseProviderAuditValidationError(
                    "Databricks audit transport returned an invalid event"
                )
            event = value
            if event.source_table not in _DATABRICKS_SOURCES:
                raise DataUseProviderAuditValidationError("Databricks audit source is unsupported")
            if event.source_table == _DATABRICKS_QUERY_SOURCE:
                if event.request_id_sha256 is not None:
                    raise DataUseProviderAuditValidationError(
                        "Databricks query-history event cannot include request_id_sha256"
                    )
                provider_reference = _digest(
                    event.statement_id_sha256,
                    "statement_id_sha256",
                )
                provider_reference_kind = "databricks_statement_id"
            else:
                if event.statement_id_sha256 is not None:
                    raise DataUseProviderAuditValidationError(
                        "Databricks access-audit event cannot include statement_id_sha256"
                    )
                provider_reference = _digest(event.request_id_sha256, "request_id_sha256")
                provider_reference_kind = "databricks_request_id"
            source = event.source_table
            schema = DATABRICKS_EVENT_SCHEMA
            object_change_corroborated = None
        if provider_reference_kind not in _REFERENCE_KINDS:  # pragma: no cover - closed branches
            raise DataUseProviderAuditValidationError(
                "provider audit reference kind is unsupported"
            )
        event_id = _digest(event.event_id_sha256, "event_id_sha256")
        occurred_at = _timestamp(event.occurred_at, "event occurred_at")
        correlation = _optional_digest(event.correlation_sha256, "event correlation_sha256")
        object_sha = _digest(event.object_sha256, "event object_sha256")
        kind = str(event.change_kind or "")
        if kind not in _CHANGE_KINDS:
            raise DataUseProviderAuditValidationError("provider audit change kind is unsupported")
        control = _digest(event.control_sha256, "event control_sha256")
        outcome = str(event.outcome or "")
        if outcome not in _OUTCOMES:
            raise DataUseProviderAuditValidationError("provider audit outcome is unsupported")
        state = _optional_digest(event.state_sha256, "event state_sha256")
        if (kind == "state_anchor") != (state is not None):
            raise DataUseProviderAuditValidationError(
                "state-anchor audit evidence has an invalid state digest"
            )
        payload = {
            "schema": schema,
            "provider_id": provider,
            "source": source,
            "event_id_sha256": event_id,
            "provider_reference_kind": provider_reference_kind,
            "provider_reference_sha256": provider_reference,
            "occurred_at": occurred_at,
            "correlation_sha256": correlation,
            "object_sha256": object_sha,
            "change_kind": kind,
            "control_sha256": control,
            "outcome": outcome,
            "state_sha256": state,
        }
        if object_change_corroborated is not None:
            payload["object_change_corroborated"] = object_change_corroborated
        _privacy_safe(payload)
        return payload, _sha256(payload)

    def _validated_batch(
        self,
        provider_id: str,
        batch: object,
        *,
        current: ProviderAuditExpectation,
        event_limit: int,
        now: float,
    ) -> tuple[
        tuple[tuple[dict[str, Any], str], ...],
        ProviderAuditCursor,
        float,
        bool,
        str,
    ]:
        if type(batch) is not ProviderAuditBatch:
            raise DataUseProviderAuditValidationError(
                "provider audit transport returned an invalid batch"
            )
        if not isinstance(batch.events, tuple) or len(batch.events) > event_limit:
            raise DataUseProviderAuditValidationError("provider audit batch exceeds its bound")
        if type(batch.next_cursor) is not ProviderAuditCursor:
            raise DataUseProviderAuditValidationError("provider audit cursor is invalid")
        cursor_time = _timestamp(batch.next_cursor.occurred_at, "cursor occurred_at")
        cursor_event = _digest(batch.next_cursor.event_id_sha256, "cursor event_id_sha256")
        current_cursor = (current.cursor_occurred_at, current.cursor_event_id_sha256)
        next_cursor_pair = (cursor_time, cursor_event)
        if next_cursor_pair < current_cursor:
            raise DataUseProviderAuditValidationError("provider audit cursor moved backwards")
        covered = _timestamp(batch.covered_until, "covered_until")
        if covered < cursor_time or covered > current.retained_until:
            raise DataUseProviderAuditValidationError("provider audit coverage is invalid")
        if not isinstance(batch.complete, bool):
            raise DataUseProviderAuditValidationError("provider audit completeness flag is invalid")
        watermark = batch.watermark
        if watermark is not None:
            if type(watermark) is not ProviderAuditAcceptedWatermark:
                raise DataUseProviderAuditValidationError(
                    "provider audit watermark proof is invalid"
                )
            expected_watermark = (
                "snowflake_configured_latency"
                if provider_id == "snowflake"
                else "databricks_accepted_delivery"
            )
            if (
                watermark.watermark_kind not in _WATERMARK_KINDS
                or watermark.watermark_kind != expected_watermark
                or not _same(watermark.tenant_sha256, current.tenant_sha256)
                or _provider(watermark.provider_id) != current.provider_id
                or _ref(watermark.binding_id, "watermark binding_id") != current.binding_id
                or _integer(
                    watermark.binding_revision,
                    "watermark binding_revision",
                    1,
                    2**31 - 1,
                )
                != current.binding_revision
                or not _same(watermark.binding_sha256, current.binding_sha256)
                or _timestamp(watermark.covered_until, "watermark covered_until") != covered
                or _timestamp(watermark.expires_at, "watermark expires_at") <= now
                or watermark.revoked is not False
                or not _same(
                    _digest(watermark.authority_sha256, "watermark authority_sha256"),
                    accepted_watermark_sha256(watermark),
                )
            ):
                raise DataUseProviderAuditValidationError(
                    "provider audit watermark authority is stale or invalid"
                )
            if not callable(self._watermark_authority_resolver):
                raise DataUseProviderAuditValidationError(
                    "provider audit watermark authority resolver is unavailable"
                )
            try:
                resolved = self._watermark_authority_resolver(
                    current.provider_id,
                    current.binding_id,
                    covered,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                raise DataUseProviderAuditValidationError(
                    "provider audit watermark authority resolution failed"
                ) from exc
            if type(resolved) is not ProviderAuditAcceptedWatermark or resolved != watermark:
                raise DataUseProviderAuditValidationError(
                    "provider audit watermark is not independently authorized"
                )
        if batch.complete and watermark is None:
            raise DataUseProviderAuditValidationError(
                "complete provider audit coverage requires explicit watermark proof"
            )
        receipt = _digest(batch.provider_receipt_sha256, "provider_receipt_sha256")
        events = tuple(
            DataUseProviderAuditStore._normalized_event(provider_id, event)
            for event in batch.events
        )
        ordered = tuple(
            sorted(
                events, key=lambda item: (float(item[0]["occurred_at"]), item[0]["event_id_sha256"])
            )
        )
        if events != ordered:
            raise DataUseProviderAuditValidationError(
                "provider audit events are not in canonical cursor order"
            )
        if events:
            last = events[-1][0]
            if (float(last["occurred_at"]), str(last["event_id_sha256"])) > next_cursor_pair:
                raise DataUseProviderAuditValidationError(
                    "provider audit cursor does not cover returned events"
                )
        return (
            events,
            ProviderAuditCursor(cursor_time, cursor_event),
            covered,
            batch.complete,
            receipt,
        )

    @staticmethod
    def _event_relation(
        current: ProviderAuditExpectation,
        payload: Mapping[str, Any],
        matched: set[str],
    ) -> tuple[str, str | None]:
        if not (
            current.cursor_occurred_at - 60.0
            <= float(payload["occurred_at"])
            <= current.audit_deadline
        ):
            return "unrelated", None
        correlation = payload["correlation_sha256"]
        if correlation is None:
            if _same(payload["object_sha256"], current.object_sha256):
                return "ambiguous", None
            return "unrelated", None
        if not _same(correlation, current.correlation_sha256):
            return "unrelated", None
        if not _same(payload["object_sha256"], current.object_sha256):
            return "drift", None
        if current.provider_id == "snowflake" and (
            payload["source"] != "query_history"
            or payload.get("object_change_corroborated") is not True
        ):
            return "ambiguous", None
        if current.provider_id == "databricks" and payload["source"] != _DATABRICKS_QUERY_SOURCE:
            return "ambiguous", None
        if payload["outcome"] != "succeeded":
            return "drift", None
        statement_matches = [
            item
            for item in current.statement_bindings
            if _same(
                item.provider_statement_sha256,
                payload["provider_reference_sha256"],
            )
        ]
        if len(statement_matches) != 1:
            return "ambiguous", None
        statement = statement_matches[0]
        if (
            statement.change_kind != payload["change_kind"]
            or not _same(statement.control_sha256, payload["control_sha256"])
            or not _same(statement.object_sha256, payload["object_sha256"])
            or (
                statement.state_sha256 != payload["state_sha256"]
                and not _same(statement.state_sha256, payload["state_sha256"])
            )
        ):
            return "drift", None
        candidates = [
            change
            for change in current.expected_changes
            if change.change_kind == payload["change_kind"]
        ]
        exact = [
            change
            for change in candidates
            if _same(change.control_sha256, payload["control_sha256"])
        ]
        if len(exact) > 1:
            return "ambiguous", None
        if len(exact) == 1:
            change = exact[0]
            if change.change_sha256 in matched:
                return "ambiguous", None
            if payload["change_kind"] == "state_anchor" and not _same(
                payload["state_sha256"], current.target_state_sha256
            ):
                return "drift", None
            return "matched", change.change_sha256
        if candidates:
            return "drift", None
        return "extra", None

    def _existing_event(
        self,
        connection: sqlite3.Connection,
        *,
        provider_id: str,
        event_id_sha256: str,
    ) -> sqlite3.Row | None:
        return connection.execute(
            "SELECT * FROM provider_audit_events WHERE tenant_sha256=? AND provider_id=? "
            "AND event_id_sha256=?",
            (self._tenant_sha256, provider_id, event_id_sha256),
        ).fetchone()

    def _matched_change_ids(self, connection: sqlite3.Connection, expectation_id: str) -> set[str]:
        rows = connection.execute(
            "SELECT payload_json,integrity_sha256 FROM provider_audit_events "
            "WHERE tenant_sha256=? AND expectation_id=?",
            (self._tenant_sha256, expectation_id),
        ).fetchall()
        result: set[str] = set()
        for row in rows:
            payload, _integrity = self._row_payload(row, "provider audit event")
            if payload.get("relation") == "matched":
                result.add(_digest(payload.get("matched_change_sha256"), "matched change"))
        return result

    def record_batch(
        self,
        claim: ProviderAuditClaim,
        batch: ProviderAuditBatch,
        *,
        event_limit: int = 100,
    ) -> ProviderAuditExpectation:
        """Persist one typed provider batch and reconcile it fail closed."""

        self._check_gate()
        bounded = _integer(event_limit, "event_limit", 1, _MAX_EVENTS_PER_BATCH)
        now = _now(self._clock)
        preview = self.get_expectation(claim.expectation_id)
        parsed = self._validated_batch(
            preview.provider_id,
            batch,
            current=preview,
            event_limit=bounded,
            now=now,
        )
        events, cursor, covered_until, complete, receipt = parsed
        request_sha = _sha256(
            {
                "action": "record_batch",
                "expectation_id": claim.expectation_id,
                "claim_revision": claim.work_revision,
                "events": [integrity for _payload, integrity in events],
                "cursor": asdict(cursor),
                "covered_until": covered_until,
                "complete": complete,
                "provider_receipt_sha256": receipt,
                "watermark": None if batch.watermark is None else asdict(batch.watermark),
            }
        )
        key_sha = _text_sha256("record_batch:" + claim.lease_token)
        with self._connect() as replay_connection:
            replay = self._operation_replay(
                replay_connection,
                key_sha256=key_sha,
                action="record_batch",
                request_sha256=request_sha,
            )
            if replay is not None:
                return replay
        preview = self.validate_claim_authority(claim)
        parsed = self._validated_batch(
            preview.provider_id,
            batch,
            current=preview,
            event_limit=bounded,
            now=now,
        )
        events, cursor, covered_until, complete, receipt = parsed
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="record_batch",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            current = self._work_for_claim(connection, claim, now=now)
            matched = self._matched_change_ids(connection, current.expectation_id)
            unrelated = 0
            issues: list[str] = []
            event_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM provider_audit_events WHERE tenant_sha256=?",
                    (self._tenant_sha256,),
                ).fetchone()[0]
            )
            for payload, integrity in events:
                relation, matched_change = self._event_relation(current, payload, matched)
                if relation == "unrelated":
                    unrelated += 1
                    continue
                existing = self._existing_event(
                    connection,
                    provider_id=current.provider_id,
                    event_id_sha256=str(payload["event_id_sha256"]),
                )
                event_payload = {
                    **payload,
                    "expectation_id": current.expectation_id,
                    "relation": relation,
                    "matched_change_sha256": matched_change,
                    "source_integrity_sha256": integrity,
                }
                event_integrity = _sha256(event_payload)
                if existing is not None:
                    prior, prior_integrity = self._row_payload(existing, "provider audit event")
                    if (
                        existing["expectation_id"] != current.expectation_id
                        or not _same(prior_integrity, event_integrity)
                        or prior != event_payload
                    ):
                        issues.append("ambiguous")
                    elif relation == "matched" and matched_change is not None:
                        matched.add(matched_change)
                    continue
                if event_count >= _MAX_EVENTS:
                    raise DataUseProviderAuditConflict("provider audit event capacity exhausted")
                connection.execute(
                    "INSERT INTO provider_audit_events VALUES(?,?,?,?,?,?,?)",
                    (
                        self._tenant_sha256,
                        current.provider_id,
                        payload["event_id_sha256"],
                        current.expectation_id,
                        payload["occurred_at"],
                        _canonical(event_payload).decode("ascii"),
                        event_integrity,
                    ),
                )
                event_count += 1
                if relation == "matched" and matched_change is not None:
                    matched.add(matched_change)
                else:
                    issues.append(relation)
                self._audit(
                    connection,
                    action="provider_audit_event_recorded",
                    object_ref=current.expectation_id,
                    detail_sha256=event_integrity,
                    now=now,
                )
            terminal_state: str | None = None
            error_code: str | None = None
            if "ambiguous" in issues:
                terminal_state, error_code = "ambiguous", "ambiguous_event_match"
            elif "drift" in issues:
                terminal_state, error_code = "drift", "provider_control_drift"
            elif "extra" in issues:
                terminal_state, error_code = "extra", "unexpected_provider_change"
            elif complete and covered_until >= current.audit_deadline:
                missing = len(current.expected_changes) - len(matched)
                if missing:
                    terminal_state, error_code = "missing", "expected_provider_change_missing"
                elif current.no_change:
                    terminal_state = "no_change"
                else:
                    terminal_state = "converged"
            state = terminal_state or "queued"
            updated = self._replace_expectation(
                connection,
                current,
                state=state,
                cursor_occurred_at=cursor.occurred_at,
                cursor_event_id_sha256=cursor.event_id_sha256,
                # A valid partial audit checkpoint is progress, not a failed
                # provider attempt.  Source delivery latency must not exhaust
                # the transport failure budget before a watermark can mature.
                attempts=(current.attempts if terminal_state is not None else 0),
                next_attempt_at=now,
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                matched_count=len(matched),
                unrelated_count=current.unrelated_count + unrelated,
                issue_count=current.issue_count + len(issues),
                last_error_code=error_code,
                provider_receipt_sha256=receipt,
                updated_at=now,
                completed_at=now if terminal_state is not None else None,
            )
            self._audit(
                connection,
                action=(
                    "provider_audit_batch_reconciled"
                    if terminal_state is not None
                    else "provider_audit_batch_checkpointed"
                ),
                object_ref=updated.expectation_id,
                detail_sha256=updated.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="record_batch",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def fail_claim(
        self,
        claim: ProviderAuditClaim,
        *,
        error_code: str,
        retryable: bool,
        backoff_seconds: int = 30,
    ) -> ProviderAuditExpectation:
        """Release one read-only claim with bounded retry or dead-letter state."""

        self._check_gate()
        code = _error_code(error_code)
        if not isinstance(retryable, bool):
            raise DataUseProviderAuditValidationError("retryable must be boolean")
        backoff = _integer(backoff_seconds, "backoff_seconds", 0, _MAX_BACKOFF_SECONDS)
        now = _now(self._clock)
        request_sha = _sha256(
            {
                "action": "fail_claim",
                "expectation_id": claim.expectation_id,
                "claim_revision": claim.work_revision,
                "error_code": code,
                "retryable": retryable,
                "backoff_seconds": backoff,
            }
        )
        key_sha = _text_sha256("fail_claim:" + claim.lease_token)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="fail_claim",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            current = self._work_for_claim(connection, claim, now=now)
            dead = not retryable or current.attempts >= current.max_attempts
            updated = self._replace_expectation(
                connection,
                current,
                state="dead_letter" if dead else "queued",
                next_attempt_at=min(now + backoff, current.retained_until),
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code=code,
                updated_at=now,
                completed_at=now if dead else None,
            )
            self._audit(
                connection,
                action=(
                    "audit_expectation_dead_lettered"
                    if dead
                    else "audit_expectation_retry_scheduled"
                ),
                object_ref=updated.expectation_id,
                detail_sha256=updated.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="fail_claim",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def cancel_claim(
        self,
        claim: ProviderAuditClaim,
        *,
        reason_code: str,
    ) -> ProviderAuditExpectation:
        """Fail closed when a claimed binding/key/capability authority drifts."""

        self._check_gate()
        reason = _error_code(reason_code)
        now = _now(self._clock)
        request_sha = _sha256(
            {
                "action": "cancel_claim",
                "expectation_id": claim.expectation_id,
                "claim_revision": claim.work_revision,
                "reason_code": reason,
            }
        )
        key_sha = _text_sha256("cancel_claim:" + claim.lease_token)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="cancel_claim",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            current = self._work_for_claim(connection, claim, now=now)
            updated = self._replace_expectation(
                connection,
                current,
                state="cancelled",
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code=reason,
                updated_at=now,
                completed_at=now,
            )
            self._audit(
                connection,
                action="audit_expectation_cancelled",
                object_ref=updated.expectation_id,
                detail_sha256=updated.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="cancel_claim",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def cancel_expectation(
        self,
        expectation_id: str,
        *,
        expected_revision: int,
        reason_code: str,
        idempotency_key: str,
    ) -> ProviderAuditExpectation:
        self._check_gate()
        ref = _ref(expectation_id, "expectation_id")
        revision = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        reason = _error_code(reason_code)
        now = _now(self._clock)
        request_sha = _sha256(
            {
                "action": "cancel_expectation",
                "expectation_id": ref,
                "expected_revision": revision,
                "reason_code": reason,
            }
        )
        key_sha = self._operation_key(idempotency_key)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="cancel_expectation",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            current = self._get_row(connection, ref)
            if current.revision != revision or current.state not in _ACTIVE_STATES:
                raise DataUseProviderAuditConflict("expectation is no longer cancellable")
            updated = self._replace_expectation(
                connection,
                current,
                state="cancelled",
                lease_owner_sha256=None,
                lease_token_sha256=None,
                lease_until=None,
                last_error_code=reason,
                updated_at=now,
                completed_at=now,
            )
            self._audit(
                connection,
                action="audit_expectation_cancelled",
                object_ref=updated.expectation_id,
                detail_sha256=updated.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="cancel_expectation",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def replay_dead_letter(
        self,
        expectation_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ProviderAuditExpectation:
        """Re-certify exact authorities before replaying dead-lettered read work."""

        self._check_gate()
        ref = _ref(expectation_id, "expectation_id")
        revision = _integer(expected_revision, "expected_revision", 1, 2**31 - 1)
        now = _now(self._clock)
        with self._connect() as connection:
            current = self._get_row(connection, ref)
        if current.revision != revision or current.state != "dead_letter":
            raise DataUseProviderAuditConflict("expectation is not replayable")
        authorities = self._authorities(
            current.provider_id,
            current.binding_id,
            current.operation_idempotency_sha256,
            now,
        )
        if not self._same_pins(current, authorities):
            raise DataUseProviderAuditConflict("provider audit authority changed before replay")
        request_sha = _sha256(
            {
                "action": "replay_dead_letter",
                "expectation_id": ref,
                "expected_revision": revision,
                "authority_fingerprint": self._authority_fingerprint(authorities),
            }
        )
        key_sha = self._operation_key(idempotency_key)
        with self._connect() as connection:
            self._begin(connection)
            replay = self._operation_replay(
                connection,
                key_sha256=key_sha,
                action="replay_dead_letter",
                request_sha256=request_sha,
            )
            if replay is not None:
                connection.commit()
                return replay
            current = self._get_row(connection, ref)
            if current.revision != revision or current.state != "dead_letter":
                raise DataUseProviderAuditConflict("expectation changed before replay")
            updated = self._replace_expectation(
                connection,
                current,
                state="queued",
                attempts=0,
                next_attempt_at=now,
                last_error_code=None,
                completed_at=None,
                updated_at=now,
            )
            self._audit(
                connection,
                action="audit_expectation_replayed",
                object_ref=updated.expectation_id,
                detail_sha256=updated.integrity_sha256,
                now=now,
            )
            self._save_operation(
                connection,
                key_sha256=key_sha,
                action="replay_dead_letter",
                request_sha256=request_sha,
                result=updated,
                now=now,
            )
            connection.commit()
            return updated

    def state_counts(self) -> Mapping[str, int]:
        self._check_gate()
        counts = dict.fromkeys(sorted(_STATES), 0)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT state,COUNT(*) AS value FROM provider_audit_expectations "
                "WHERE tenant_sha256=? GROUP BY state",
                (self._tenant_sha256,),
            ).fetchall()
        for row in rows:
            state = str(row["state"])
            if state not in counts:
                raise DataUseProviderAuditIntegrityError("stored expectation state is invalid")
            counts[state] = int(row["value"])
        return {**counts, "total": sum(counts.values())}

    def purge_expired(self, *, cutoff: float, limit: int = 100) -> int:
        """Purge expired digest-only payloads while retaining audit tombstones."""

        self._check_gate()
        before = _timestamp(cutoff, "cutoff")
        bounded = _integer(limit, "limit", 1, 500)
        now = _now(self._clock)
        purged = 0
        self._retention.authorized = True
        try:
            with self._connect() as connection:
                self._begin(connection)
                rows = connection.execute(
                    "SELECT expectation_id,integrity_sha256 FROM provider_audit_expectations "
                    "WHERE tenant_sha256=? AND retained_until<=? "
                    "ORDER BY retained_until,expectation_id LIMIT ?",
                    (self._tenant_sha256, before, bounded),
                ).fetchall()
                for row in rows:
                    expectation_id = str(row["expectation_id"])
                    tombstone = _sha256(
                        {
                            "expectation_id": expectation_id,
                            "final_integrity_sha256": str(row["integrity_sha256"]),
                            "purged_at": now,
                        }
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_events WHERE tenant_sha256=? "
                        "AND expectation_id=?",
                        (self._tenant_sha256, expectation_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_history WHERE tenant_sha256=? "
                        "AND expectation_id=?",
                        (self._tenant_sha256, expectation_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_operations WHERE tenant_sha256=? "
                        "AND expectation_id=?",
                        (self._tenant_sha256, expectation_id),
                    )
                    connection.execute(
                        "DELETE FROM provider_audit_expectations WHERE tenant_sha256=? "
                        "AND expectation_id=?",
                        (self._tenant_sha256, expectation_id),
                    )
                    self._audit(
                        connection,
                        action="audit_expectation_purged",
                        object_ref=expectation_id,
                        detail_sha256=tombstone,
                        now=now,
                    )
                    purged += 1
                connection.commit()
        finally:
            self._retention.authorized = False
        return purged

    def list_event_evidence(
        self, expectation_id: str, *, limit: int = 100
    ) -> tuple[Mapping[str, Any], ...]:
        """Return bounded normalized digest-only evidence for one expectation."""

        self._check_gate()
        ref = _ref(expectation_id, "expectation_id")
        bounded = _integer(limit, "limit", 1, 500)
        with self._connect() as connection:
            self._get_row(connection, ref)
            rows = connection.execute(
                "SELECT * FROM provider_audit_events WHERE tenant_sha256=? "
                "AND expectation_id=? ORDER BY occurred_at,event_id_sha256 LIMIT ?",
                (self._tenant_sha256, ref, bounded),
            ).fetchall()
            results: list[Mapping[str, Any]] = []
            for row in rows:
                payload, integrity = self._row_payload(row, "provider audit event")
                if (
                    row["provider_id"] != payload.get("provider_id")
                    or row["event_id_sha256"] != payload.get("event_id_sha256")
                    or row["expectation_id"] != payload.get("expectation_id")
                    or float(row["occurred_at"]) != payload.get("occurred_at")
                ):
                    raise DataUseProviderAuditIntegrityError(
                        "provider audit event index is inconsistent"
                    )
                results.append({**payload, "integrity_sha256": integrity})
            return tuple(results)

    def verify_integrity(self) -> ProviderAuditIntegrityVerification:
        self._check_gate()
        with self._connect() as connection:
            current_rows = connection.execute(
                "SELECT expectation_id FROM provider_audit_expectations "
                "WHERE tenant_sha256=? ORDER BY expectation_id",
                (self._tenant_sha256,),
            ).fetchall()
            current: dict[str, ProviderAuditExpectation] = {
                str(row["expectation_id"]): self._get_row(connection, str(row["expectation_id"]))
                for row in current_rows
            }
            history_rows = connection.execute(
                "SELECT * FROM provider_audit_history WHERE tenant_sha256=? "
                "ORDER BY expectation_id,revision",
                (self._tenant_sha256,),
            ).fetchall()
            history_count = 0
            histories: dict[str, list[ProviderAuditExpectation]] = {}
            for row in history_rows:
                payload, integrity = self._row_payload(row, "provider audit history")
                value = self._validated_expectation(payload, integrity)
                if (
                    row["expectation_id"] != value.expectation_id
                    or int(row["revision"]) != value.revision
                ):
                    raise DataUseProviderAuditIntegrityError(
                        "provider audit history index is inconsistent"
                    )
                histories.setdefault(value.expectation_id, []).append(value)
                history_count += 1
            for expectation_id, value in current.items():
                rows = histories.get(expectation_id, [])
                if not rows or rows[-1] != value:
                    raise DataUseProviderAuditIntegrityError(
                        "provider audit current/history head is inconsistent"
                    )
                previous: str | None = None
                for expected_revision, item in enumerate(rows, 1):
                    if (
                        item.revision != expected_revision
                        or item.previous_integrity_sha256 != previous
                    ):
                        raise DataUseProviderAuditIntegrityError(
                            "provider audit history chain is invalid"
                        )
                    previous = item.integrity_sha256
            event_rows = connection.execute(
                "SELECT * FROM provider_audit_events WHERE tenant_sha256=? "
                "ORDER BY provider_id,event_id_sha256",
                (self._tenant_sha256,),
            ).fetchall()
            for row in event_rows:
                payload, _integrity = self._row_payload(row, "provider audit event")
                if (
                    payload.get("expectation_id") not in current
                    or row["provider_id"] != payload.get("provider_id")
                    or row["event_id_sha256"] != payload.get("event_id_sha256")
                    or row["expectation_id"] != payload.get("expectation_id")
                    or payload.get("relation") not in {"matched", "extra", "drift", "ambiguous"}
                ):
                    raise DataUseProviderAuditIntegrityError(
                        "provider audit event binding is invalid"
                    )
            operation_rows = connection.execute(
                "SELECT * FROM provider_audit_operations WHERE tenant_sha256=? ORDER BY key_sha256",
                (self._tenant_sha256,),
            ).fetchall()
            history_integrities = {
                expectation_id: {item.integrity_sha256 for item in items}
                for expectation_id, items in histories.items()
            }
            for row in operation_rows:
                expectation_id = str(row["expectation_id"])
                if (
                    _DIGEST_RE.fullmatch(str(row["key_sha256"])) is None
                    or _DIGEST_RE.fullmatch(str(row["request_sha256"])) is None
                    or expectation_id not in history_integrities
                    or str(row["result_integrity_sha256"])
                    not in history_integrities[expectation_id]
                    or row["action"]
                    not in {
                        "register_operation",
                        "record_batch",
                        "fail_claim",
                        "cancel_claim",
                        "cancel_expectation",
                        "replay_dead_letter",
                    }
                ):
                    raise DataUseProviderAuditIntegrityError(
                        "provider audit idempotency evidence is invalid"
                    )
            audit_rows = connection.execute(
                "SELECT * FROM provider_audit_chain WHERE tenant_sha256=? ORDER BY sequence",
                (self._tenant_sha256,),
            ).fetchall()
            previous = "0" * 64
            terminal = previous
            for row in audit_rows:
                body = {
                    "sequence": int(row["sequence"]),
                    "tenant_sha256": str(row["tenant_sha256"]),
                    "action": str(row["action"]),
                    "object_ref": str(row["object_ref"]),
                    "detail_sha256": str(row["detail_sha256"]),
                    "occurred_at": float(row["occurred_at"]),
                    "previous_event_sha256": str(row["previous_event_sha256"]),
                }
                if not _same(body["previous_event_sha256"], previous) or not _same(
                    str(row["event_sha256"]), _sha256(body)
                ):
                    raise DataUseProviderAuditIntegrityError(
                        "provider audit chain failed integrity"
                    )
                previous = str(row["event_sha256"])
                terminal = previous
            return ProviderAuditIntegrityVerification(
                expectations=len(current_rows),
                history_records=history_count,
                event_records=len(event_rows),
                operation_records=len(operation_rows),
                audit_events=len(audit_rows),
                terminal_audit_sha256=terminal,
            )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "default_off": True,
            "tenant_bound": True,
            "provider_sources": {
                "snowflake": ["ACCESS_HISTORY", "QUERY_HISTORY"],
                "databricks": ["system.query.history", "system.access.audit"],
            },
            "provider_source_roles": {
                "databricks": {
                    "primary": "system.query.history",
                    "supplemental": ["system.access.audit"],
                }
            },
            "raw_provider_events_persisted": False,
            "raw_sql_persisted": False,
            "provider_principals_persisted": False,
            "client_addresses_persisted": False,
            "credential_material_persisted": False,
            "provider_writes": PROVIDER_WRITES,
            "built_in_network_transport": NETWORK_IO,
            "ambiguous_matches_fail_closed": True,
            "audit_log_completeness_claim": False,
            "live_provider_acceptance": LIVE_PROVIDER_ACCEPTANCE,
        }


class DataUseProviderAuditWorker:
    """Bounded worker over injected credential ownership and provider transport."""

    def __init__(
        self,
        store: DataUseProviderAuditStore,
        *,
        credential_owner: ProviderAuditCredentialOwner,
        transport: ProviderAuditTransport,
    ) -> None:
        if not isinstance(store, DataUseProviderAuditStore):
            raise DataUseProviderAuditConfigError("provider audit store is unavailable")
        if not callable(getattr(credential_owner, "lease", None)) or not callable(
            getattr(transport, "read", None)
        ):
            raise DataUseProviderAuditConfigError(
                "provider audit credential owner or transport is unavailable"
            )
        self.store = store
        self._credential_owner = credential_owner
        self._transport = transport

    def run_once(
        self,
        *,
        worker_id: str,
        limit: int = 10,
        lease_seconds: int = 60,
        event_limit: int = 100,
        backoff_seconds: int = 30,
    ) -> ProviderAuditWorkerResult:
        bounded_claims = _integer(limit, "limit", 1, 100)
        bounded_events = _integer(event_limit, "event_limit", 1, _MAX_EVENTS_PER_BATCH)
        backoff = _integer(backoff_seconds, "backoff_seconds", 0, _MAX_BACKOFF_SECONDS)
        # A network reader consumes most of one claim lease.  Claim only the
        # item being processed so later work does not expire behind it.
        claim_limit = (
            1 if callable(getattr(self._transport, "read_with_deadline", None)) else bounded_claims
        )
        claims = self.store.claim_ready(
            worker_id=worker_id,
            limit=claim_limit,
            lease_seconds=lease_seconds,
        )
        counters = {
            "converged": 0,
            "no_change": 0,
            "findings": 0,
            "retried": 0,
            "dead_lettered": 0,
            "cancelled": 0,
        }
        for claim in claims:
            try:
                current = self.store.validate_claim_authority(claim)
                request = self.store.read_request(claim, event_limit=bounded_events)
                preview = getattr(self._transport, "read_without_credential", None)
                batch = preview(request) if callable(preview) else None
                if batch is None:
                    credential = self._credential_owner.lease(
                        provider_id=current.provider_id,
                        tenant_id=self.store._tenant_id,
                        binding_id=current.binding_id,
                    )
                    lease = self.store.validate_credential(
                        current,
                        credential,
                        now=_now(self.store._clock),
                    )
                    bounded_reader = getattr(
                        self._transport,
                        "read_with_deadline",
                        None,
                    )
                    if callable(bounded_reader):
                        if current.lease_until is None:
                            raise DataUseProviderAuditLeaseLost(
                                "provider audit lease deadline is unavailable"
                            )
                        batch = bounded_reader(
                            request,
                            lease,
                            deadline=current.lease_until - 5.0,
                        )
                    else:
                        batch = self._transport.read(request, lease)
                result = self.store.record_batch(
                    claim,
                    batch,
                    event_limit=bounded_events,
                )
                if result.state == "converged":
                    counters["converged"] += 1
                elif result.state == "no_change":
                    counters["no_change"] += 1
                elif result.state in {"ambiguous", "drift", "extra", "missing"}:
                    counters["findings"] += 1
                elif result.state == "dead_letter":
                    counters["dead_lettered"] += 1
                else:
                    counters["retried"] += 1
            except (DataUseProviderAuditConflict, DataUseProviderAuditLeaseLost):
                try:
                    self.store.cancel_claim(claim, reason_code="authority_changed")
                    counters["cancelled"] += 1
                except DataUseProviderAuditError:
                    counters["cancelled"] += 1
            except DataUseProviderAuditPermanent as exc:
                result = self.store.fail_claim(
                    claim,
                    error_code=exc.error_code,
                    retryable=False,
                    backoff_seconds=backoff,
                )
                counters["dead_lettered"] += result.state == "dead_letter"
            except DataUseProviderAuditRetryable as exc:
                result = self.store.fail_claim(
                    claim,
                    error_code=exc.error_code,
                    retryable=True,
                    backoff_seconds=backoff,
                )
                if result.state == "dead_letter":
                    counters["dead_lettered"] += 1
                else:
                    counters["retried"] += 1
            except (DataUseProviderAuditValidationError, DataUseProviderAuditIntegrityError):
                result = self.store.fail_claim(
                    claim,
                    error_code="provider_audit_contract_invalid",
                    retryable=False,
                    backoff_seconds=backoff,
                )
                counters["dead_lettered"] += result.state == "dead_letter"
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                result = self.store.fail_claim(
                    claim,
                    error_code="provider_audit_read_failed",
                    retryable=True,
                    backoff_seconds=backoff,
                )
                if result.state == "dead_letter":
                    counters["dead_lettered"] += 1
                else:
                    counters["retried"] += 1
        return ProviderAuditWorkerResult(claimed=len(claims), **counters)


__all__ = [
    "AUDIT_BATCH_SCHEMA",
    "CLAIM_SCHEMA",
    "CONTROL_AUTHORITY_SCHEMA",
    "DATABRICKS_EVENT_SCHEMA",
    "DataUseProviderAuditConfigError",
    "DataUseProviderAuditConflict",
    "DataUseProviderAuditError",
    "DataUseProviderAuditIntegrityError",
    "DataUseProviderAuditLeaseLost",
    "DataUseProviderAuditNotFound",
    "DataUseProviderAuditPermanent",
    "DataUseProviderAuditRetryable",
    "DataUseProviderAuditStore",
    "DataUseProviderAuditValidationError",
    "DataUseProviderAuditWorker",
    "DatabricksAuditEvent",
    "EXPECTATION_SCHEMA",
    "LIVE_PROVIDER_ACCEPTANCE",
    "NETWORK_IO",
    "PROVIDER_WRITES",
    "ProviderAuditBatch",
    "ProviderAuditAcceptedWatermark",
    "ProviderAuditClaim",
    "ProviderAuditControlAuthority",
    "ProviderAuditCredentialLease",
    "ProviderAuditCredentialOwner",
    "ProviderAuditCursor",
    "ProviderAuditExpectedChange",
    "ProviderAuditExpectation",
    "ProviderAuditIntegrityVerification",
    "ProviderAuditReadAuthority",
    "ProviderAuditReadRequest",
    "ProviderAuditStatementBinding",
    "ProviderAuditTransport",
    "ProviderAuditWorkerResult",
    "READ_AUTHORITY_SCHEMA",
    "SNOWFLAKE_EVENT_SCHEMA",
    "SnowflakeAuditEvent",
    "accepted_watermark_sha256",
    "control_authority_sha256",
    "enabled",
    "expected_change_sha256",
    "operation_correlation_sha256",
    "read_authority_sha256",
    "require_enabled",
]
