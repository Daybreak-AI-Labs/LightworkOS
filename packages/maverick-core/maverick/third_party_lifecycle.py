"""Governed conditional assessments and third-party lifecycle control plane.

The authority is deliberately provider-neutral.  It stores opaque references,
digests, decisions, and delivery intent, but contains no vendor corpus, raw PII,
credentials, provider origin, network client, or external-write implementation.
An API adapter must bind an authenticated principal before every write.  Client
payloads can never supply or override that actor.

The capability is default-off and uses the exact lifecycle gates::

    [third_party_management]
    enable = true
    [third_party_management.lifecycle]
    enable = true
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.third-party-lifecycle-audit.v1"
EXPORT_SCHEMA = "lightwork.third-party-lifecycle-export.v1"
LIVE_PROVIDER_OPERATIONS = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_LIST = 1_000
_MIN_RETENTION_SECONDS = 24 * 60 * 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
_MAX_LEASE_SECONDS = 60 * 60
_MAX_BACKOFF_SECONDS = 7 * 24 * 60 * 60

ASSESSMENT_DOMAINS = frozenset({"security", "privacy", "ethics", "compliance", "operational", "ai"})
RESPONSE_TYPES = frozenset({"boolean", "single_choice", "multi_choice", "integer", "text_ref"})
CONDITION_OPERATORS = frozenset(
    {"equals", "not_equals", "contains", "in", "greater_or_equal", "less_or_equal"}
)
SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
TEMPLATE_STATES = frozenset({"pending_approval", "approved", "retired"})
ASSESSMENT_ROUTES = frozenset(
    {
        "not_evaluated",
        "incomplete",
        "owner_review",
        "remediation_required",
        "escalation_required",
    }
)
ASSESSMENT_TASK_STATES = frozenset({"open", "completed", "waived"})
LIFECYCLE_STAGES = frozenset({"onboarding", "active", "suspended", "offboarding", "offboarded"})
DEPENDENCY_KINDS = frozenset({"system", "access", "data", "contract"})
OFFBOARDING_TASK_STATES = frozenset({"open", "completed", "blocked"})
CALLBACK_ACTIONS = frozenset(
    {
        "revoke_access",
        "deprovision_account",
        "terminate_integration",
        "archive_data",
        "notify_owner",
    }
)
CALLBACK_STATES = frozenset({"pending", "leased", "delivered", "dead_letter", "cancelled"})


class ThirdPartyLifecycleError(RuntimeError):
    """Base error for lifecycle and conditional-assessment operations."""


class ThirdPartyLifecycleConfigError(ThirdPartyLifecycleError):
    """The governing feature gate is not enabled."""


class ThirdPartyLifecycleValidationError(ThirdPartyLifecycleError, ValueError):
    """Input is outside the authority's closed and bounded schemas."""


class ThirdPartyLifecycleConflict(ThirdPartyLifecycleError):
    """A CAS, idempotency, lease, or state precondition failed."""


class ThirdPartyLifecycleNotFound(ThirdPartyLifecycleError):
    """A tenant-scoped record is absent or deliberately undisclosed."""


class ThirdPartyLifecyclePermissionDenied(ThirdPartyLifecycleError):
    """Authenticated authority or four-eyes separation is insufficient."""


class ThirdPartyLifecycleIntegrityError(ThirdPartyLifecycleError):
    """Persisted state or the tenant audit chain failed verification."""


def enabled() -> bool:
    """Return true only for the exact parent and lifecycle gates."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    third_party = config.get("third_party_management")
    lifecycle = third_party.get("lifecycle") if isinstance(third_party, Mapping) else None
    return (
        isinstance(third_party, Mapping)
        and third_party.get("enable") is True
        and isinstance(lifecycle, Mapping)
        and lifecycle.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless both lifecycle-management gates are true."""

    if not enabled():
        raise ThirdPartyLifecycleConfigError(
            "third-party lifecycle is disabled; explicitly enable "
            "third_party_management and third_party_management.lifecycle"
        )


def _runtime_principal() -> str | None:
    """Resolve dispatch-bound identity lazily and fail closed on context errors."""

    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


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
        raise ThirdPartyLifecycleValidationError(
            "lifecycle state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ThirdPartyLifecycleValidationError("lifecycle state exceeds its canonical byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ThirdPartyLifecycleValidationError("tenant_id is invalid") from exc


def _id(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ThirdPartyLifecycleValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ThirdPartyLifecycleValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ThirdPartyLifecycleValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or not 0 < float(value) < 100_000_000_000.0
    ):
        raise ThirdPartyLifecycleValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _retention(value: object) -> int:
    return _integer(
        value,
        "retention_seconds",
        _MIN_RETENTION_SECONDS,
        _MAX_RETENTION_SECONDS,
    )


def _closed_mapping(
    value: object,
    label: str,
    keys: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ThirdPartyLifecycleValidationError(f"{label} schema is closed")
    return value


def _sequence(value: object, label: str, minimum: int = 0) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ThirdPartyLifecycleValidationError(f"{label} must be a list")
    if not minimum <= len(value) <= _MAX_LIST:
        raise ThirdPartyLifecycleValidationError(
            f"{label} must contain between {minimum} and {_MAX_LIST} values"
        )
    return value


def _ids(value: object, label: str, *, minimum: int = 0) -> tuple[str, ...]:
    values = tuple(_id(item, label) for item in _sequence(value, label, minimum))
    if len(set(values)) != len(values):
        raise ThirdPartyLifecycleValidationError(f"{label} contains duplicates")
    return values


def _validate_json_scalar(value: object, label: str) -> object:
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value.encode("utf-8")) > 512:
            raise ThirdPartyLifecycleValidationError(f"{label} is too large")
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if not -1_000_000_000 <= value <= 1_000_000_000:
            raise ThirdPartyLifecycleValidationError(f"{label} is out of bounds")
        return value
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        values = tuple(_validate_json_scalar(item, label) for item in value)
        if not 1 <= len(values) <= 100:
            raise ThirdPartyLifecycleValidationError(f"{label} list is out of bounds")
        return list(values)
    raise ThirdPartyLifecycleValidationError(f"{label} must be a bounded JSON value")


def _validate_condition(
    value: object,
    prior_ids: frozenset[str],
) -> dict[str, object] | None:
    if value is None:
        return None
    item = _closed_mapping(
        value,
        "question condition",
        frozenset({"question_id", "operator", "value"}),
    )
    question_id = _id(item["question_id"], "condition question_id")
    if question_id not in prior_ids:
        raise ThirdPartyLifecycleValidationError(
            "conditions may reference only an earlier question"
        )
    operator = item["operator"]
    if operator not in CONDITION_OPERATORS:
        raise ThirdPartyLifecycleValidationError("condition operator is unsupported")
    return {
        "question_id": question_id,
        "operator": operator,
        "value": _validate_json_scalar(item["value"], "condition value"),
    }


def _validate_risk_rule(value: object) -> dict[str, object]:
    item = _closed_mapping(
        value,
        "risk rule",
        frozenset({"operator", "value", "severity", "reason_code"}),
    )
    if item["operator"] not in CONDITION_OPERATORS:
        raise ThirdPartyLifecycleValidationError("risk-rule operator is unsupported")
    if item["severity"] not in SEVERITIES:
        raise ThirdPartyLifecycleValidationError("risk-rule severity is unsupported")
    return {
        "operator": item["operator"],
        "value": _validate_json_scalar(item["value"], "risk-rule value"),
        "severity": item["severity"],
        "reason_code": _id(item["reason_code"], "reason_code"),
    }


def _validate_question(
    value: object,
    prior_ids: frozenset[str],
) -> dict[str, object]:
    item = _closed_mapping(
        value,
        "assessment question",
        frozenset(
            {
                "question_id",
                "domain",
                "prompt_ref",
                "response_type",
                "required",
                "options",
                "condition",
                "risk_rules",
            }
        ),
    )
    question_id = _id(item["question_id"], "question_id")
    if question_id in prior_ids:
        raise ThirdPartyLifecycleValidationError("question IDs must be unique")
    domain = item["domain"]
    if domain not in ASSESSMENT_DOMAINS:
        raise ThirdPartyLifecycleValidationError("question domain is unsupported")
    response_type = item["response_type"]
    if response_type not in RESPONSE_TYPES:
        raise ThirdPartyLifecycleValidationError("response type is unsupported")
    if not isinstance(item["required"], bool):
        raise ThirdPartyLifecycleValidationError("question required must be boolean")
    options = _ids(item["options"], "question option")
    if response_type in {"single_choice", "multi_choice"} and not options:
        raise ThirdPartyLifecycleValidationError("choice questions require options")
    if response_type not in {"single_choice", "multi_choice"} and options:
        raise ThirdPartyLifecycleValidationError("non-choice questions cannot define options")
    risk_rules = tuple(
        _validate_risk_rule(rule) for rule in _sequence(item["risk_rules"], "risk_rules")
    )
    reason_codes = tuple(rule["reason_code"] for rule in risk_rules)
    if len(set(reason_codes)) != len(reason_codes):
        raise ThirdPartyLifecycleValidationError("question risk reason codes must be unique")
    return {
        "question_id": question_id,
        "domain": domain,
        "prompt_ref": _id(item["prompt_ref"], "prompt_ref"),
        "response_type": response_type,
        "required": item["required"],
        "options": list(options),
        "condition": _validate_condition(item["condition"], prior_ids),
        "risk_rules": list(risk_rules),
    }


def _validate_questions(value: object) -> tuple[dict[str, object], ...]:
    raw = _sequence(value, "questions", 1)
    questions: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in raw:
        question = _validate_question(item, frozenset(seen))
        seen.add(str(question["question_id"]))
        questions.append(question)
    domains = {question["domain"] for question in questions}
    if not domains.issubset(ASSESSMENT_DOMAINS):
        raise ThirdPartyLifecycleValidationError("assessment domains are invalid")
    return tuple(questions)


def _validate_mitigation(value: object) -> dict[str, str]:
    item = _closed_mapping(
        value,
        "mitigation rule",
        frozenset({"reason_code", "recommendation_code", "task_code", "minimum_severity"}),
    )
    if item["minimum_severity"] not in SEVERITIES:
        raise ThirdPartyLifecycleValidationError("mitigation minimum severity is unsupported")
    return {
        "reason_code": _id(item["reason_code"], "reason_code"),
        "recommendation_code": _id(item["recommendation_code"], "recommendation_code"),
        "task_code": _id(item["task_code"], "task_code"),
        "minimum_severity": str(item["minimum_severity"]),
    }


def _condition_matches(actual: object, operator: str, expected: object) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        return isinstance(actual, list) and expected in actual
    if operator == "in":
        return isinstance(expected, list) and actual in expected
    if operator == "greater_or_equal":
        return (
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and isinstance(expected, int)
            and not isinstance(expected, bool)
            and actual >= expected
        )
    if operator == "less_or_equal":
        return (
            isinstance(actual, int)
            and not isinstance(actual, bool)
            and isinstance(expected, int)
            and not isinstance(expected, bool)
            and actual <= expected
        )
    raise ThirdPartyLifecycleIntegrityError("persisted condition operator is invalid")


def _validate_response(question: Mapping[str, object], value: object) -> object:
    response_type = question["response_type"]
    if response_type == "boolean":
        if not isinstance(value, bool):
            raise ThirdPartyLifecycleValidationError("response must be boolean")
        return value
    if response_type == "integer":
        return _integer(value, "response", -1_000_000_000, 1_000_000_000)
    if response_type == "text_ref":
        return _id(value, "response reference")
    options = tuple(question["options"])  # type: ignore[arg-type]
    if response_type == "single_choice":
        answer = _id(value, "response option")
        if answer not in options:
            raise ThirdPartyLifecycleValidationError("response option is not allowed")
        return answer
    answers = _ids(value, "response option", minimum=1)
    if not set(answers).issubset(options):
        raise ThirdPartyLifecycleValidationError("response options are not allowed")
    return list(answers)


def _dependency(value: object) -> dict[str, str]:
    item = _closed_mapping(
        value,
        "dependency",
        frozenset({"dependency_id", "kind", "reference", "evidence_sha256"}),
    )
    if item["kind"] not in DEPENDENCY_KINDS:
        raise ThirdPartyLifecycleValidationError("dependency kind is unsupported")
    return {
        "dependency_id": _id(item["dependency_id"], "dependency_id"),
        "kind": str(item["kind"]),
        "reference": _id(item["reference"], "dependency reference"),
        "evidence_sha256": _digest(item["evidence_sha256"], "dependency evidence_sha256"),
    }


def _offboarding_task(value: object, dependencies: Mapping[str, str]) -> dict[str, object]:
    item = _closed_mapping(
        value,
        "offboarding task",
        frozenset({"task_id", "dependency_id", "action", "assignee_ref", "callback_required"}),
    )
    dependency_id = _id(item["dependency_id"], "dependency_id")
    if dependency_id not in dependencies:
        raise ThirdPartyLifecycleValidationError("offboarding task dependency is unknown")
    action = item["action"]
    if action not in CALLBACK_ACTIONS:
        raise ThirdPartyLifecycleValidationError("offboarding task action is unsupported")
    if not isinstance(item["callback_required"], bool):
        raise ThirdPartyLifecycleValidationError("callback_required must be boolean")
    if dependencies[dependency_id] == "access" and not item["callback_required"]:
        raise ThirdPartyLifecycleValidationError(
            "access dependencies require a revocation callback"
        )
    if dependencies[dependency_id] == "access" and action not in {
        "revoke_access",
        "deprovision_account",
    }:
        raise ThirdPartyLifecycleValidationError(
            "access dependencies require a revocation or deprovision action"
        )
    return {
        "task_id": _id(item["task_id"], "task_id"),
        "dependency_id": dependency_id,
        "action": action,
        "assignee_ref": _id(item["assignee_ref"], "assignee_ref"),
        "callback_required": item["callback_required"],
        "status": "open",
        "evidence_sha256": None,
        "attestation_ref": None,
        "updated_by": None,
        "updated_at": None,
    }


@dataclass(frozen=True)
class AssessmentTemplate:
    tenant_id: str
    template_id: str
    version: int
    title_ref: str
    questions: tuple[Mapping[str, object], ...]
    mitigation_rules: tuple[Mapping[str, str], ...]
    state: str
    revision: int
    authored_by: str
    approved_by: str | None
    retained_until: float
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class Assessment:
    tenant_id: str
    assessment_id: str
    vendor_ref: str
    template_id: str
    template_version: int
    owner_ref: str
    assignments: Mapping[str, str]
    responses: Mapping[str, Mapping[str, object]]
    tasks: tuple[Mapping[str, object], ...]
    route: str
    highest_severity: str | None
    reason_codes: tuple[str, ...]
    recommendations: tuple[Mapping[str, str], ...]
    revision: int
    retained_until: float
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class AssessmentEvaluation:
    assessment: Assessment
    active_questions: tuple[str, ...]
    required_questions: tuple[str, ...]
    missing_questions: tuple[str, ...]
    route: str
    highest_severity: str | None
    reason_codes: tuple[str, ...]
    recommendations: tuple[Mapping[str, str], ...]


@dataclass(frozen=True)
class AssessmentResponseBatchReceipt:
    """Immutable receipt for one atomically recorded attested response batch."""

    tenant_id: str
    assessment_id: str
    assessment_revision: int
    assessment_integrity_sha256: str
    question_ids: tuple[str, ...]
    attestation_sha256: str


@dataclass(frozen=True)
class LifecycleRecord:
    tenant_id: str
    lifecycle_id: str
    vendor_ref: str
    owner_ref: str
    stage: str
    dependencies: tuple[Mapping[str, str], ...]
    offboarding_plan_id: str | None
    revision: int
    retained_until: float
    created_at: float
    updated_at: float
    integrity_sha256: str
    activation_assessment: Mapping[str, object] | None = None


@dataclass(frozen=True)
class OffboardingPlan:
    tenant_id: str
    plan_id: str
    lifecycle_id: str
    state: str
    legal_hold: bool
    legal_hold_evidence_ref: str | None
    tasks: tuple[Mapping[str, object], ...]
    blockers: tuple[str, ...]
    initiated_by: str
    completed_by: str | None
    completion_attestation_ref: str | None
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class CallbackItem:
    tenant_id: str
    callback_id: str
    plan_id: str
    lifecycle_id: str
    task_id: str
    action: str
    dependency_ref: str
    destination_ref: str
    state: str
    attempt: int
    maximum_attempts: int
    next_attempt_at: float
    lease_token: str | None
    lease_until: float | None
    last_error_code: str | None
    delivery_evidence_sha256: str | None
    revision: int
    integrity_sha256: str


@dataclass(frozen=True)
class EvidenceExport:
    tenant_id: str
    export_id: str
    subject_kind: str
    subject_id: str
    schema: str
    body: Mapping[str, object]
    retained_until: float
    created_by: str
    created_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class IntegrityVerification:
    tenant_id: str
    verified_records: int
    audit_events: int
    terminal_audit_sha256: str


class ThirdPartyLifecycleStore:
    """Durable tenant-isolated lifecycle and assessment authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[], str] = lambda: f"lease:{secrets.token_urlsafe(32)}",
    ) -> None:
        config_gate()
        self.path = Path(path)
        self._principal_resolver = principal_resolver
        self._clock = clock
        self._token_factory = token_factory
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise ThirdPartyLifecyclePermissionDenied(
                "an authenticated runtime principal is required"
            )
        return _id(actor, "authenticated principal")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                BEGIN IMMEDIATE;
                CREATE TABLE IF NOT EXISTS metadata(
                    key TEXT PRIMARY KEY,value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS templates(
                    tenant_id TEXT NOT NULL,template_id TEXT NOT NULL,version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,template_id,version)
                );
                CREATE TABLE IF NOT EXISTS assessments(
                    tenant_id TEXT NOT NULL,assessment_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,assessment_id)
                );
                CREATE TABLE IF NOT EXISTS lifecycles(
                    tenant_id TEXT NOT NULL,lifecycle_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,lifecycle_id)
                );
                CREATE TABLE IF NOT EXISTS offboarding_plans(
                    tenant_id TEXT NOT NULL,plan_id TEXT NOT NULL,lifecycle_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,plan_id),
                    UNIQUE(tenant_id,lifecycle_id)
                );
                CREATE TABLE IF NOT EXISTS callbacks(
                    tenant_id TEXT NOT NULL,callback_id TEXT NOT NULL,plan_id TEXT NOT NULL,
                    state TEXT NOT NULL,next_attempt_at REAL NOT NULL,lease_until REAL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,callback_id)
                );
                CREATE INDEX IF NOT EXISTS callback_claim
                    ON callbacks(tenant_id,state,next_attempt_at,lease_until);
                CREATE TABLE IF NOT EXISTS exports(
                    tenant_id TEXT NOT NULL,export_id TEXT NOT NULL,subject_kind TEXT NOT NULL,
                    subject_id TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,export_id)
                );
                CREATE INDEX IF NOT EXISTS export_retention
                    ON exports(tenant_id,retained_until);
                CREATE TABLE IF NOT EXISTS operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,result_id TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise ThirdPartyLifecycleIntegrityError(
                    "third-party lifecycle database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _payload(row: sqlite3.Row, label: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ThirdPartyLifecycleIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if not isinstance(payload, dict) or _sha256(payload) != row["integrity_sha256"]:
            raise ThirdPartyLifecycleIntegrityError(
                f"persisted {label} failed integrity verification"
            )
        return payload

    @staticmethod
    def _get(
        connection: sqlite3.Connection,
        table: str,
        tenant_id: str,
        id_column: str,
        object_id: str,
        label: str,
    ) -> tuple[dict[str, Any], str]:
        row = connection.execute(
            f"SELECT * FROM {table} WHERE tenant_id=? AND {id_column}=?",  # noqa: S608
            (tenant_id, object_id),
        ).fetchone()
        if row is None:
            raise ThirdPartyLifecycleNotFound(f"{label} was not found")
        return ThirdPartyLifecycleStore._payload(row, label), row["integrity_sha256"]

    @staticmethod
    def _write(
        connection: sqlite3.Connection,
        table: str,
        tenant_id: str,
        id_column: str,
        object_id: str,
        payload: Mapping[str, object],
    ) -> str:
        digest = _sha256(dict(payload))
        result = connection.execute(
            f"UPDATE {table} SET payload_json=?,integrity_sha256=? "  # noqa: S608
            f"WHERE tenant_id=? AND {id_column}=?",
            (_canonical(dict(payload)).decode("ascii"), digest, tenant_id, object_id),
        )
        if result.rowcount != 1:
            raise ThirdPartyLifecycleNotFound(f"{table} record was not found")
        return digest

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha256 = hashlib.sha256(key.encode()).hexdigest()
        request_sha256 = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha256),
        ).fetchone()
        if row is not None:
            binding = {
                "tenant_id": row["tenant_id"],
                "operation_sha256": row["operation_sha256"],
                "request_sha256": row["request_sha256"],
                "result_kind": row["result_kind"],
                "result_id": row["result_id"],
            }
            if _sha256(binding) != row["integrity_sha256"]:
                raise ThirdPartyLifecycleIntegrityError(
                    "persisted idempotency binding failed integrity verification"
                )
            if row["request_sha256"] != request_sha256:
                raise ThirdPartyLifecycleConflict(
                    "idempotency key is bound to different canonical content"
                )
        return request_sha256, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha256: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        binding = {
            "tenant_id": tenant_id,
            "operation_sha256": hashlib.sha256(idempotency_key.encode()).hexdigest(),
            "request_sha256": request_sha256,
            "result_kind": result_kind,
            "result_id": result_id,
        }
        connection.execute(
            "INSERT INTO operations VALUES(?,?,?,?,?,?)",
            (
                tenant_id,
                binding["operation_sha256"],
                request_sha256,
                result_kind,
                result_id,
                _sha256(binding),
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        subject: str,
        actor_ref: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM audit_events WHERE tenant_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        previous_sha = "0" * 64 if previous is None else previous["integrity_sha256"]
        payload = {
            "schema": AUDIT_SCHEMA,
            "tenant_id": tenant_id,
            "sequence": sequence,
            "action": _id(action, "audit action"),
            "subject_sha256": hashlib.sha256(subject.encode()).hexdigest(),
            "actor_ref": _id(actor_ref, "authenticated principal"),
            "details": dict(details),
            "occurred_at": now,
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO audit_events VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _template_from(payload: Mapping[str, Any], digest: str) -> AssessmentTemplate:
        values = dict(payload)
        values["questions"] = tuple(dict(item) for item in values["questions"])
        values["mitigation_rules"] = tuple(dict(item) for item in values["mitigation_rules"])
        return AssessmentTemplate(**values, integrity_sha256=digest)

    @staticmethod
    def _assessment_from(payload: Mapping[str, Any], digest: str) -> Assessment:
        values = dict(payload)
        values["assignments"] = dict(values["assignments"])
        values["responses"] = {key: dict(item) for key, item in values["responses"].items()}
        values["tasks"] = tuple(dict(item) for item in values["tasks"])
        values["reason_codes"] = tuple(values["reason_codes"])
        values["recommendations"] = tuple(dict(item) for item in values["recommendations"])
        return Assessment(**values, integrity_sha256=digest)

    @staticmethod
    def _lifecycle_from(payload: Mapping[str, Any], digest: str) -> LifecycleRecord:
        values = dict(payload)
        values["dependencies"] = tuple(dict(item) for item in values["dependencies"])
        return LifecycleRecord(**values, integrity_sha256=digest)

    @staticmethod
    def _plan_from(payload: Mapping[str, Any], digest: str) -> OffboardingPlan:
        values = dict(payload)
        values["tasks"] = tuple(dict(item) for item in values["tasks"])
        values["blockers"] = tuple(values["blockers"])
        return OffboardingPlan(**values, integrity_sha256=digest)

    @staticmethod
    def _callback_from(payload: Mapping[str, Any], digest: str) -> CallbackItem:
        return CallbackItem(**dict(payload), integrity_sha256=digest)

    @staticmethod
    def _export_from(payload: Mapping[str, Any], digest: str) -> EvidenceExport:
        values = dict(payload)
        values["body"] = dict(values["body"])
        return EvidenceExport(**values, integrity_sha256=digest)

    def create_template_version(
        self,
        tenant_id: str,
        template_id: str,
        *,
        title_ref: str,
        questions: Sequence[Mapping[str, object]],
        mitigation_rules: Sequence[Mapping[str, object]],
        expected_latest_version: int,
        idempotency_key: str,
    ) -> AssessmentTemplate:
        """Create an immutable pending template version under a latest-version CAS."""

        tenant = _tenant(tenant_id)
        template = _id(template_id, "template_id")
        title = _id(title_ref, "title_ref")
        validated_questions = _validate_questions(questions)
        validated_mitigations = tuple(
            _validate_mitigation(item) for item in _sequence(mitigation_rules, "mitigation_rules")
        )
        if len({item["reason_code"] for item in validated_mitigations}) != len(
            validated_mitigations
        ):
            raise ThirdPartyLifecycleValidationError("mitigation reason codes must be unique")
        expected = _integer(expected_latest_version, "expected_latest_version", 0, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "create_template_version",
            "template_id": template,
            "title_ref": title,
            "questions": list(validated_questions),
            "mitigation_rules": list(validated_mitigations),
            "expected_latest_version": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                stored_template, raw_version = operation["result_id"].rsplit("@", 1)
                if stored_template != template:
                    raise ThirdPartyLifecycleIntegrityError(
                        "template idempotency result is inconsistent"
                    )
                return self._get_template(connection, tenant, template, int(raw_version))
            latest_row = connection.execute(
                "SELECT MAX(version) AS latest FROM templates WHERE tenant_id=? AND template_id=?",
                (tenant, template),
            ).fetchone()
            latest = (
                0
                if latest_row is None or latest_row["latest"] is None
                else int(latest_row["latest"])
            )
            if latest != expected:
                raise ThirdPartyLifecycleConflict(
                    f"template latest-version CAS failed: expected {expected}, found {latest}"
                )
            version = latest + 1
            payload = {
                "tenant_id": tenant,
                "template_id": template,
                "version": version,
                "title_ref": title,
                "questions": list(validated_questions),
                "mitigation_rules": list(validated_mitigations),
                "state": "pending_approval",
                "revision": 1,
                "authored_by": actor,
                "approved_by": None,
                "retained_until": now + _MAX_RETENTION_SECONDS,
                "created_at": now,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO templates VALUES(?,?,?,?,?)",
                (
                    tenant,
                    template,
                    version,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            result_id = f"{template}@{version}"
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "template",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "template_created",
                result_id,
                actor,
                {"version": version, "question_count": len(validated_questions)},
                now,
            )
            return self._template_from(payload, digest)

    def _get_template(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        template_id: str,
        version: int,
    ) -> AssessmentTemplate:
        row = connection.execute(
            "SELECT * FROM templates WHERE tenant_id=? AND template_id=? AND version=?",
            (tenant_id, template_id, version),
        ).fetchone()
        if row is None:
            raise ThirdPartyLifecycleNotFound("assessment template was not found")
        return self._template_from(
            self._payload(row, "assessment template"), row["integrity_sha256"]
        )

    def get_template_version(
        self,
        tenant_id: str,
        template_id: str,
        version: int,
    ) -> AssessmentTemplate:
        tenant = _tenant(tenant_id)
        template = _id(template_id, "template_id")
        selected_version = _integer(version, "version", 1, 1_000_000)
        with self._connect() as connection:
            return self._get_template(connection, tenant, template, selected_version)

    def list_templates(
        self,
        tenant_id: str,
        *,
        limit: int = 200,
    ) -> tuple[AssessmentTemplate, ...]:
        """Return every stored template version (newest first), integrity-checked.

        Read-only: listing never creates, approves or changes a version.
        """

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM templates WHERE tenant_id=? "
                "ORDER BY template_id, version DESC LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        values = tuple(
            self._template_from(
                self._payload(row, "assessment template"),
                row["integrity_sha256"],
            )
            for row in rows
        )
        return tuple(sorted(values, key=lambda item: (-item.updated_at, item.template_id, -item.version)))

    def approve_template_version(
        self,
        tenant_id: str,
        template_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> AssessmentTemplate:
        """Approve a template version with mandatory author/approver separation."""

        tenant = _tenant(tenant_id)
        template = _id(template_id, "template_id")
        selected_version = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_template_version",
            "template_id": template,
            "version": selected_version,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        result_id = f"{template}@{selected_version}"
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                return self._get_template(connection, tenant, template, selected_version)
            record = self._get_template(connection, tenant, template, selected_version)
            if record.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"template revision CAS failed: expected {expected}, found {record.revision}"
                )
            if record.state != "pending_approval":
                raise ThirdPartyLifecycleConflict("template is not pending approval")
            if record.authored_by == actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "template authors cannot approve their own version"
                )
            payload = {
                key: value for key, value in record.__dict__.items() if key != "integrity_sha256"
            }
            payload.update(
                {
                    "state": "approved",
                    "revision": record.revision + 1,
                    "approved_by": actor,
                    "updated_at": now,
                    "questions": [dict(item) for item in record.questions],
                    "mitigation_rules": [dict(item) for item in record.mitigation_rules],
                }
            )
            digest = _sha256(payload)
            connection.execute(
                "UPDATE templates SET payload_json=?,integrity_sha256=? "
                "WHERE tenant_id=? AND template_id=? AND version=?",
                (
                    _canonical(payload).decode("ascii"),
                    digest,
                    tenant,
                    template,
                    selected_version,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "template",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "template_approved",
                result_id,
                actor,
                {"version": selected_version},
                now,
            )
            return self._template_from(payload, digest)

    def create_assessment(
        self,
        tenant_id: str,
        assessment_id: str,
        *,
        vendor_ref: str,
        template_id: str,
        template_version: int,
        owner_ref: str,
        respondent_assignments: Mapping[str, str],
        retention_seconds: int,
        idempotency_key: str,
        effect_guard: Callable[[], None] | None = None,
    ) -> Assessment:
        """Create an assessment only from an independently approved version."""

        tenant = _tenant(tenant_id)
        assessment = _id(assessment_id, "assessment_id")
        vendor = _id(vendor_ref, "vendor_ref")
        template = _id(template_id, "template_id")
        version = _integer(template_version, "template_version", 1, 1_000_000)
        owner = _id(owner_ref, "owner_ref")
        if not isinstance(respondent_assignments, Mapping):
            raise ThirdPartyLifecycleValidationError("respondent_assignments must be a mapping")
        assignments = {
            _id(question_id, "assignment question_id"): _id(respondent, "respondent_ref")
            for question_id, respondent in respondent_assignments.items()
        }
        retention = _retention(retention_seconds)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "create_assessment",
            "assessment_id": assessment,
            "vendor_ref": vendor,
            "template_id": template,
            "template_version": version,
            "owner_ref": owner,
            "assignments": assignments,
            "retention_seconds": retention,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                payload, digest = self._get(
                    connection,
                    "assessments",
                    tenant,
                    "assessment_id",
                    assessment,
                    "assessment",
                )
                return self._assessment_from(payload, digest)
            if effect_guard is not None:
                effect_guard()
            self._registered_vendor(tenant, vendor)
            selected = self._get_template(connection, tenant, template, version)
            if selected.state != "approved":
                raise ThirdPartyLifecyclePermissionDenied(
                    "assessment template version is not independently approved"
                )
            question_ids = {str(item["question_id"]) for item in selected.questions}
            if set(assignments) != question_ids:
                raise ThirdPartyLifecycleValidationError(
                    "respondent assignments must exactly cover all template questions"
                )
            payload = {
                "tenant_id": tenant,
                "assessment_id": assessment,
                "vendor_ref": vendor,
                "template_id": template,
                "template_version": version,
                "owner_ref": owner,
                "assignments": assignments,
                "responses": {},
                "tasks": [],
                "route": "not_evaluated",
                "highest_severity": None,
                "reason_codes": [],
                "recommendations": [],
                "revision": 1,
                "retained_until": now + retention,
                "created_at": now,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO assessments VALUES(?,?,?,?)",
                (
                    tenant,
                    assessment,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "assessment",
                assessment,
            )
            self._audit(
                connection,
                tenant,
                "assessment_created",
                assessment,
                actor,
                {"template_id": template, "template_version": version},
                now,
            )
            return self._assessment_from(payload, digest)

    def get_assessment(self, tenant_id: str, assessment_id: str) -> Assessment:
        tenant = _tenant(tenant_id)
        assessment = _id(assessment_id, "assessment_id")
        with self._connect() as connection:
            payload, digest = self._get(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment,
                "assessment",
            )
            return self._assessment_from(payload, digest)

    def list_assessments(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> tuple[Assessment, ...]:
        """Return one bounded, integrity-verified tenant snapshot."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assessments WHERE tenant_id=? "
                "ORDER BY assessment_id LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        values = tuple(
            self._assessment_from(
                self._payload(row, "assessment"),
                row["integrity_sha256"],
            )
            for row in rows
        )
        return tuple(sorted(values, key=lambda item: (-item.updated_at, item.assessment_id)))

    @staticmethod
    def _question_state(
        template: AssessmentTemplate,
        assessment: Assessment,
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        active: list[str] = []
        required: list[str] = []
        for question in template.questions:
            question_id = str(question["question_id"])
            condition = question["condition"]
            is_active = condition is None
            if isinstance(condition, Mapping):
                controlling = assessment.responses.get(str(condition["question_id"]))
                is_active = controlling is not None and _condition_matches(
                    controlling["value"],
                    str(condition["operator"]),
                    condition["value"],
                )
            if is_active:
                active.append(question_id)
                if question["required"] is True:
                    required.append(question_id)
        missing = [item for item in required if item not in assessment.responses]
        return tuple(active), tuple(required), tuple(missing)

    def required_questions(
        self,
        tenant_id: str,
        assessment_id: str,
    ) -> tuple[str, ...]:
        tenant = _tenant(tenant_id)
        assessment = self.get_assessment(tenant, assessment_id)
        template = self.get_template_version(
            tenant, assessment.template_id, assessment.template_version
        )
        return self._question_state(template, assessment)[1]

    def record_response(
        self,
        tenant_id: str,
        assessment_id: str,
        question_id: str,
        *,
        value: object,
        evidence_sha256: str,
        evidence_refs: Sequence[str],
        expected_revision: int,
        idempotency_key: str,
    ) -> Assessment:
        """Record evidence from the exact authenticated assigned respondent."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        question_key = _id(question_id, "question_id")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        references = _ids(evidence_refs, "evidence_ref", minimum=1)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "record_response",
            "assessment_id": assessment_key,
            "question_id": question_key,
            "value": _validate_json_scalar(value, "response"),
            "evidence_sha256": evidence,
            "evidence_refs": list(references),
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                payload, digest = self._get(
                    connection,
                    "assessments",
                    tenant,
                    "assessment_id",
                    assessment_key,
                    "assessment",
                )
                return self._assessment_from(payload, digest)
            raw, _ = self._get(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            assessment = self._assessment_from(raw, _sha256(raw))
            if assessment.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"assessment revision CAS failed: expected {expected}, "
                    f"found {assessment.revision}"
                )
            if assessment.assignments.get(question_key) != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "authenticated principal is not the assigned respondent"
                )
            template = self._get_template(
                connection,
                tenant,
                assessment.template_id,
                assessment.template_version,
            )
            questions = {str(item["question_id"]): item for item in template.questions}
            question = questions.get(question_key)
            if question is None:
                raise ThirdPartyLifecycleNotFound("assessment question was not found")
            active = self._question_state(template, assessment)[0]
            if question_key not in active:
                raise ThirdPartyLifecycleConflict(
                    "conditional question is not active for current responses"
                )
            response = _validate_response(question, value)
            payload = dict(raw)
            responses = {key: dict(item) for key, item in assessment.responses.items()}
            responses[question_key] = {
                "value": response,
                "evidence_sha256": evidence,
                "evidence_refs": list(references),
                "respondent_ref": actor,
                "responded_at": now,
            }
            payload.update(
                {
                    "responses": responses,
                    "route": "not_evaluated",
                    "highest_severity": None,
                    "reason_codes": [],
                    "recommendations": [],
                    "revision": assessment.revision + 1,
                    "updated_at": now,
                }
            )
            digest = self._write(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "assessment",
                assessment_key,
            )
            self._audit(
                connection,
                tenant,
                "assessment_response_recorded",
                assessment_key,
                actor,
                {"question_id": question_key, "evidence_sha256": evidence},
                now,
            )
            return self._assessment_from(payload, digest)

    @staticmethod
    def _batch_receipt(value: object) -> AssessmentResponseBatchReceipt:
        item = _closed_mapping(
            value,
            "assessment response batch receipt",
            frozenset(
                {
                    "tenant_id",
                    "assessment_id",
                    "assessment_revision",
                    "assessment_integrity_sha256",
                    "question_ids",
                    "attestation_sha256",
                }
            ),
        )
        return AssessmentResponseBatchReceipt(
            tenant_id=_tenant(item["tenant_id"]),
            assessment_id=_id(item["assessment_id"], "assessment_id"),
            assessment_revision=_integer(
                item["assessment_revision"],
                "assessment_revision",
                1,
                1_000_000,
            ),
            assessment_integrity_sha256=_digest(
                item["assessment_integrity_sha256"],
                "assessment_integrity_sha256",
            ),
            question_ids=_ids(item["question_ids"], "question_id", minimum=1),
            attestation_sha256=_digest(
                item["attestation_sha256"],
                "attestation_sha256",
            ),
        )

    def record_response_batch(
        self,
        tenant_id: str,
        assessment_id: str,
        *,
        responses: Mapping[str, Mapping[str, object]],
        attestation_sha256: str,
        expected_revision: int,
        expected_assessment_sha256: str,
        expected_template_revision: int,
        expected_template_sha256: str,
        idempotency_key: str,
    ) -> AssessmentResponseBatchReceipt:
        """Atomically record one exact, evidence-bound attested response batch.

        This is an answer-persistence primitive, not an assessment, score, risk
        conclusion, approval, or verification of the respondent's claims.  The
        authenticated runtime principal must be the assigned respondent for
        every submitted question.  Conditions are recomputed in template order
        inside the same write transaction so a client cannot activate a hidden
        question by asserting that it is visible.
        """

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        expected_assessment_digest = _digest(
            expected_assessment_sha256,
            "expected_assessment_sha256",
        )
        expected_template_rev = _integer(
            expected_template_revision,
            "expected_template_revision",
            1,
            1_000_000,
        )
        expected_template_digest = _digest(
            expected_template_sha256,
            "expected_template_sha256",
        )
        attestation = _digest(attestation_sha256, "attestation_sha256")
        if not isinstance(responses, Mapping) or not 1 <= len(responses) <= _MAX_LIST:
            raise ThirdPartyLifecycleValidationError(
                "responses must be a non-empty bounded mapping"
            )
        normalized_input: dict[str, dict[str, object]] = {}
        for raw_question_id, raw_response in responses.items():
            question_id = _id(raw_question_id, "question_id")
            item = _closed_mapping(
                raw_response,
                f"response {question_id}",
                frozenset({"value", "evidence_sha256", "evidence_refs"}),
            )
            normalized_input[question_id] = {
                "value": _validate_json_scalar(item["value"], "response"),
                "evidence_sha256": _digest(
                    item["evidence_sha256"],
                    "evidence_sha256",
                ),
                "evidence_refs": list(_ids(item["evidence_refs"], "evidence_ref", minimum=1)),
            }
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "record_response_batch",
            "assessment_id": assessment_key,
            "responses": normalized_input,
            "attestation_sha256": attestation,
            "expected_revision": expected,
            "expected_assessment_sha256": expected_assessment_digest,
            "expected_template_revision": expected_template_rev,
            "expected_template_sha256": expected_template_digest,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection,
                tenant,
                idempotency_key,
                request,
            )
            if operation is not None:
                if operation["result_kind"] != "assessment_response_batch":
                    raise ThirdPartyLifecycleIntegrityError(
                        "response batch idempotency result kind is inconsistent"
                    )
                try:
                    receipt_value = json.loads(operation["result_id"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ThirdPartyLifecycleIntegrityError(
                        "response batch idempotency receipt is invalid"
                    ) from exc
                receipt = self._batch_receipt(receipt_value)
                if (
                    receipt.tenant_id != tenant
                    or receipt.assessment_id != assessment_key
                    or receipt.attestation_sha256 != attestation
                ):
                    raise ThirdPartyLifecycleIntegrityError(
                        "response batch idempotency receipt is inconsistent"
                    )
                return receipt

            raw, stored_digest = self._get(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            assessment = self._assessment_from(raw, stored_digest)
            if assessment.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"assessment revision CAS failed: expected {expected}, "
                    f"found {assessment.revision}"
                )
            if stored_digest != expected_assessment_digest:
                raise ThirdPartyLifecycleConflict("assessment authority digest changed")
            template = self._get_template(
                connection,
                tenant,
                assessment.template_id,
                assessment.template_version,
            )
            if (
                template.revision != expected_template_rev
                or template.integrity_sha256 != expected_template_digest
            ):
                raise ThirdPartyLifecycleConflict("assessment template authority changed")
            if template.state != "approved":
                raise ThirdPartyLifecyclePermissionDenied(
                    "assessment template is not independently approved"
                )

            questions = {str(item["question_id"]): item for item in template.questions}
            unknown = set(normalized_input) - set(questions)
            if unknown:
                raise ThirdPartyLifecycleNotFound("one or more assessment questions were not found")
            for question_id in normalized_input:
                if assessment.assignments.get(question_id) != actor:
                    raise ThirdPartyLifecyclePermissionDenied(
                        "authenticated principal is not the assigned respondent "
                        "for every submitted question"
                    )

            merged_values = {
                question_id: item["value"] for question_id, item in assessment.responses.items()
            }
            submitted: dict[str, dict[str, object]] = {}
            visible: set[str] = set()
            for question in template.questions:
                question_id = str(question["question_id"])
                condition = question["condition"]
                is_active = condition is None
                if isinstance(condition, Mapping):
                    controlling = merged_values.get(str(condition["question_id"]))
                    is_active = controlling is not None and _condition_matches(
                        controlling,
                        str(condition["operator"]),
                        condition["value"],
                    )
                if not is_active:
                    continue
                visible.add(question_id)
                if question_id not in normalized_input:
                    continue
                incoming = normalized_input[question_id]
                value = _validate_response(question, incoming["value"])
                merged_values[question_id] = value
                submitted[question_id] = {
                    "value": value,
                    "evidence_sha256": incoming["evidence_sha256"],
                    "evidence_refs": list(incoming["evidence_refs"]),
                    "respondent_ref": actor,
                    "responded_at": now,
                    "attestation_sha256": attestation,
                    "evidence_status": "respondent_attestation_unverified",
                }
            hidden = set(normalized_input) - visible
            if hidden:
                raise ThirdPartyLifecycleConflict(
                    "one or more submitted assessment questions are not active"
                )
            if set(submitted) != set(normalized_input):
                raise ThirdPartyLifecycleIntegrityError(
                    "response batch visibility evaluation was inconsistent"
                )

            payload = dict(raw)
            stored_responses = {key: dict(item) for key, item in assessment.responses.items()}
            stored_responses.update(submitted)
            payload.update(
                {
                    "responses": stored_responses,
                    "route": "not_evaluated",
                    "highest_severity": None,
                    "reason_codes": [],
                    "recommendations": [],
                    "revision": assessment.revision + 1,
                    "updated_at": now,
                }
            )
            digest = self._write(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                payload,
            )
            receipt_value = {
                "tenant_id": tenant,
                "assessment_id": assessment_key,
                "assessment_revision": assessment.revision + 1,
                "assessment_integrity_sha256": digest,
                "question_ids": sorted(submitted),
                "attestation_sha256": attestation,
            }
            result_id = _canonical(receipt_value).decode("ascii")
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "assessment_response_batch",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "assessment_response_batch_recorded",
                assessment_key,
                actor,
                {
                    "question_ids": sorted(submitted),
                    "attestation_sha256": attestation,
                    "evidence_status": "respondent_attestation_unverified",
                },
                now,
            )
            return self._batch_receipt(receipt_value)

    @staticmethod
    def _evaluation(
        template: AssessmentTemplate,
        assessment: Assessment,
    ) -> tuple[
        tuple[str, ...],
        tuple[str, ...],
        tuple[str, ...],
        str,
        str | None,
        tuple[str, ...],
        tuple[dict[str, str], ...],
    ]:
        active, required, missing = ThirdPartyLifecycleStore._question_state(template, assessment)
        reasons: list[tuple[str, str]] = []
        questions = {str(item["question_id"]): item for item in template.questions}
        for question_id in active:
            response = assessment.responses.get(question_id)
            if response is None:
                continue
            for rule in questions[question_id]["risk_rules"]:  # type: ignore[index]
                if _condition_matches(response["value"], str(rule["operator"]), rule["value"]):
                    reasons.append((str(rule["reason_code"]), str(rule["severity"])))
        highest = None
        if reasons:
            highest = max((severity for _, severity in reasons), key=SEVERITY_ORDER.get)
        if missing:
            route = "incomplete"
        elif highest == "critical":
            route = "escalation_required"
        elif highest == "high":
            route = "remediation_required"
        else:
            route = "owner_review"
        reason_codes = tuple(dict.fromkeys(reason for reason, _ in reasons))
        severity_by_reason = {reason: severity for reason, severity in reasons}
        recommendations = tuple(
            dict(rule)
            for rule in template.mitigation_rules
            if rule["reason_code"] in severity_by_reason
            and SEVERITY_ORDER[severity_by_reason[rule["reason_code"]]]
            >= SEVERITY_ORDER[rule["minimum_severity"]]
        )
        return (
            active,
            required,
            missing,
            route,
            highest,
            reason_codes,
            recommendations,
        )

    def evaluate_assessment(
        self,
        tenant_id: str,
        assessment_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> AssessmentEvaluation:
        """Persist a deterministic completeness/risk route and exact reason codes."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "evaluate_assessment",
            "assessment_id": assessment_key,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            assessment = self._assessment_from(raw, stored_digest)
            template = self._get_template(
                connection,
                tenant,
                assessment.template_id,
                assessment.template_version,
            )
            if operation is not None:
                values = self._evaluation(template, assessment)
                return AssessmentEvaluation(assessment, *values)
            if assessment.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"assessment revision CAS failed: expected {expected}, "
                    f"found {assessment.revision}"
                )
            if assessment.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated assessment owner can route the result"
                )
            values = self._evaluation(template, assessment)
            active, required, missing, route, highest, reasons, recommendations = values
            payload = dict(raw)
            payload.update(
                {
                    "route": route,
                    "highest_severity": highest,
                    "reason_codes": list(reasons),
                    "recommendations": [dict(item) for item in recommendations],
                    "revision": assessment.revision + 1,
                    "updated_at": now,
                }
            )
            digest = self._write(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "assessment",
                assessment_key,
            )
            self._audit(
                connection,
                tenant,
                "assessment_evaluated",
                assessment_key,
                actor,
                {
                    "route": route,
                    "missing_count": len(missing),
                    "reason_codes": list(reasons),
                },
                now,
            )
            updated = self._assessment_from(payload, digest)
            return AssessmentEvaluation(
                updated,
                active,
                required,
                missing,
                route,
                highest,
                reasons,
                recommendations,
            )

    def set_assessment_task(
        self,
        tenant_id: str,
        assessment_id: str,
        task_id: str,
        *,
        status: str,
        reason_code: str,
        assignee_ref: str,
        evidence_sha256: str | None,
        evidence_ref: str | None,
        due_at: float,
        expected_revision: int,
        idempotency_key: str,
    ) -> Assessment:
        """Create or update an owner-governed remediation task."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        task_key = _id(task_id, "task_id")
        if status not in ASSESSMENT_TASK_STATES:
            raise ThirdPartyLifecycleValidationError("assessment task status is unsupported")
        reason = _id(reason_code, "reason_code")
        assignee = _id(assignee_ref, "assignee_ref")
        due = _timestamp(due_at, "due_at")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        evidence = None if evidence_sha256 is None else _digest(evidence_sha256, "evidence_sha256")
        evidence_reference = None if evidence_ref is None else _id(evidence_ref, "evidence_ref")
        if status in {"completed", "waived"} and (evidence is None or evidence_reference is None):
            raise ThirdPartyLifecycleValidationError(
                "completed or waived tasks require evidence and an evidence reference"
            )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "set_assessment_task",
            "assessment_id": assessment_key,
            "task_id": task_key,
            "status": status,
            "reason_code": reason,
            "assignee_ref": assignee,
            "evidence_sha256": evidence,
            "evidence_ref": evidence_reference,
            "due_at": due,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            if operation is not None:
                return self._assessment_from(raw, stored_digest)
            assessment = self._assessment_from(raw, stored_digest)
            if assessment.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"assessment revision CAS failed: expected {expected}, "
                    f"found {assessment.revision}"
                )
            if assessment.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated assessment owner can govern tasks"
                )
            tasks = [dict(item) for item in assessment.tasks]
            task = {
                "task_id": task_key,
                "status": status,
                "reason_code": reason,
                "assignee_ref": assignee,
                "evidence_sha256": evidence,
                "evidence_ref": evidence_reference,
                "due_at": due,
                "updated_by": actor,
                "updated_at": now,
            }
            for index, existing in enumerate(tasks):
                if existing["task_id"] == task_key:
                    tasks[index] = task
                    break
            else:
                if len(tasks) >= _MAX_LIST:
                    raise ThirdPartyLifecycleValidationError("assessment task bound is exhausted")
                tasks.append(task)
            payload = dict(raw)
            payload.update(
                {
                    "tasks": tasks,
                    "revision": assessment.revision + 1,
                    "updated_at": now,
                }
            )
            digest = self._write(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "assessment",
                assessment_key,
            )
            self._audit(
                connection,
                tenant,
                "assessment_task_set",
                assessment_key,
                actor,
                {"task_id": task_key, "status": status, "reason_code": reason},
                now,
            )
            return self._assessment_from(payload, digest)

    def create_lifecycle(
        self,
        tenant_id: str,
        lifecycle_id: str,
        *,
        vendor_ref: str,
        owner_ref: str,
        dependencies: Sequence[Mapping[str, object]],
        retention_seconds: int,
        idempotency_key: str,
        effect_guard: Callable[[], None] | None = None,
    ) -> LifecycleRecord:
        """Create an onboarding lifecycle with only opaque dependency evidence."""

        tenant = _tenant(tenant_id)
        lifecycle = _id(lifecycle_id, "lifecycle_id")
        vendor = _id(vendor_ref, "vendor_ref")
        owner = _id(owner_ref, "owner_ref")
        dependency_items = tuple(
            _dependency(item) for item in _sequence(dependencies, "dependencies")
        )
        dependency_ids = tuple(item["dependency_id"] for item in dependency_items)
        if len(set(dependency_ids)) != len(dependency_ids):
            raise ThirdPartyLifecycleValidationError("dependency IDs must be unique")
        retention = _retention(retention_seconds)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "create_lifecycle",
            "lifecycle_id": lifecycle,
            "vendor_ref": vendor,
            "owner_ref": owner,
            "dependencies": list(dependency_items),
            "retention_seconds": retention,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                payload, digest = self._get(
                    connection,
                    "lifecycles",
                    tenant,
                    "lifecycle_id",
                    lifecycle,
                    "lifecycle",
                )
                return self._lifecycle_from(payload, digest)
            if effect_guard is not None:
                effect_guard()
            self._registered_vendor(tenant, vendor)
            payload = {
                "tenant_id": tenant,
                "lifecycle_id": lifecycle,
                "vendor_ref": vendor,
                "owner_ref": owner,
                "stage": "onboarding",
                "dependencies": list(dependency_items),
                "offboarding_plan_id": None,
                "revision": 1,
                "retained_until": now + retention,
                "created_at": now,
                "updated_at": now,
            }
            digest = _sha256(payload)
            connection.execute(
                "INSERT INTO lifecycles VALUES(?,?,?,?)",
                (
                    tenant,
                    lifecycle,
                    _canonical(payload).decode("ascii"),
                    digest,
                ),
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "lifecycle",
                lifecycle,
            )
            self._audit(
                connection,
                tenant,
                "lifecycle_created",
                lifecycle,
                actor,
                {"dependency_count": len(dependency_items)},
                now,
            )
            return self._lifecycle_from(payload, digest)

    @staticmethod
    def _registered_vendor(tenant, vendor):
        # Legacy opaque references remain readable. New register selections
        # carry the actual master ID, never a slug or name-derived match.
        if vendor.startswith("VMR-"):
            from . import vendor_management
            from .paths import current_tenant_id_strict
            if current_tenant_id_strict() != tenant or vendor_management.get_vendor(vendor) is None:
                raise ThirdPartyLifecycleConflict("The selected registered vendor is no longer available in this workspace.")

    def get_lifecycle(self, tenant_id: str, lifecycle_id: str) -> LifecycleRecord:
        tenant = _tenant(tenant_id)
        lifecycle = _id(lifecycle_id, "lifecycle_id")
        with self._connect() as connection:
            payload, digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle,
                "lifecycle",
            )
            return self._lifecycle_from(payload, digest)

    def list_lifecycles(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> tuple[LifecycleRecord, ...]:
        """Return current lifecycle heads without creating another authority."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM lifecycles WHERE tenant_id=? "
                "ORDER BY lifecycle_id LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        values = tuple(
            self._lifecycle_from(
                self._payload(row, "lifecycle"),
                row["integrity_sha256"],
            )
            for row in rows
        )
        return tuple(sorted(values, key=lambda item: (-item.updated_at, item.lifecycle_id)))

    def transition_lifecycle(
        self,
        tenant_id: str,
        lifecycle_id: str,
        target_stage: str,
        *,
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
        assessment_id: str | None = None,
        assessment_revision: int | None = None,
        effect_guard: Callable[[], None] | None = None,
    ) -> LifecycleRecord:
        """Apply ordinary stage transitions; offboarding has a dedicated workflow."""

        tenant = _tenant(tenant_id)
        lifecycle = _id(lifecycle_id, "lifecycle_id")
        if target_stage not in LIFECYCLE_STAGES:
            raise ThirdPartyLifecycleValidationError("lifecycle stage is unsupported")
        if target_stage in {"offboarding", "offboarded"}:
            raise ThirdPartyLifecycleConflict(
                "offboarding stages require the governed offboarding workflow"
            )
        reason = _id(reason_code, "reason_code")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "transition_lifecycle",
            "lifecycle_id": lifecycle,
            "target_stage": target_stage,
            "reason_code": reason,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        if assessment_id is not None:
            request["assessment_id"] = assessment_id
        if assessment_revision is not None:
            request["assessment_revision"] = assessment_revision
        allowed = {
            "onboarding": frozenset({"active", "suspended"}),
            "active": frozenset({"suspended"}),
            "suspended": frozenset({"active"}),
            "offboarding": frozenset(),
            "offboarded": frozenset(),
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle,
                "lifecycle",
            )
            if operation is not None:
                return self._lifecycle_from(raw, stored_digest)
            if effect_guard is not None:
                effect_guard()
            record = self._lifecycle_from(raw, stored_digest)
            if record.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"lifecycle revision CAS failed: expected {expected}, found {record.revision}"
                )
            if record.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated lifecycle owner can change its stage"
                )
            if target_stage not in allowed[record.stage]:
                raise ThirdPartyLifecycleConflict(
                    f"lifecycle transition {record.stage} -> {target_stage} is prohibited"
                )
            activation = None
            if target_stage == "active":
                activation = self._activation_assessment(
                    connection, tenant, record.vendor_ref,
                    assessment_id=assessment_id, assessment_revision=assessment_revision,
                )
            payload = dict(raw)
            payload.update(
                {
                    "stage": target_stage,
                    "revision": record.revision + 1,
                    "updated_at": now,
                }
            )
            if activation is not None:
                payload["activation_assessment"] = activation
            if effect_guard is not None:
                effect_guard()
            digest = self._write(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle,
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "lifecycle",
                lifecycle,
            )
            self._audit(
                connection,
                tenant,
                "lifecycle_transitioned",
                lifecycle,
                actor,
                {"from": record.stage, "to": target_stage, "reason_code": reason},
                now,
            )
            return self._lifecycle_from(payload, digest)

    def _activation_assessment(self, connection, tenant, vendor_ref, *, assessment_id=None, assessment_revision=None):
        """Use the latest actual evaluation; an older passing result cannot hide a newer concern."""
        rows = connection.execute("SELECT * FROM assessments WHERE tenant_id=?", (tenant,)).fetchall()
        candidates = [self._assessment_from(self._payload(row, "assessment"), row["integrity_sha256"]) for row in rows]
        candidates = sorted((row for row in candidates if row.vendor_ref == vendor_ref), key=lambda row: (row.updated_at, row.assessment_id), reverse=True)
        if not candidates:
            raise ThirdPartyLifecycleConflict("Complete and evaluate this registered vendor's assessment before marking it active.")
        selected = candidates[0]
        if ((assessment_id is not None and selected.assessment_id != assessment_id)
                or (assessment_revision is not None and selected.revision != assessment_revision)):
            raise ThirdPartyLifecycleConflict("The current vendor assessment changed. Review its latest evaluation.")
        template = self._get_template(connection, tenant, selected.template_id, selected.template_version)
        evaluation = self._evaluation(template, selected)
        if (selected.retained_until <= self._clock() or template.state != "approved"
                or selected.route != "owner_review" or evaluation[3] != selected.route
                or any(task["status"] == "open" for task in selected.tasks)):
            raise ThirdPartyLifecycleConflict("The latest vendor assessment must be evaluated, complete, ready for owner review, and have no open tasks before activation.")
        return {"assessment_id": selected.assessment_id, "revision": selected.revision,
                "integrity_sha256": selected.integrity_sha256, "route": selected.route,
                "highest_severity": selected.highest_severity}

    def activation_assessment(self, tenant_id, vendor_ref, *, assessment_id=None, assessment_revision=None):
        tenant = _tenant(tenant_id)
        with self._connect() as connection:
            return self._activation_assessment(connection, tenant, _id(vendor_ref, "vendor_ref"),
                assessment_id=assessment_id, assessment_revision=assessment_revision)

    @contextlib.contextmanager
    def activation_scope(self, tenant_id, vendor_ref):
        """Keep actual assessment writers waiting until a dependent native status commits."""
        tenant = _tenant(tenant_id)
        with self._connect() as connection:
            self._begin(connection)
            yield self._activation_assessment(connection, tenant, _id(vendor_ref, "vendor_ref"))

    @staticmethod
    def _derive_blockers(
        connection: sqlite3.Connection,
        tenant_id: str,
        plan_payload: Mapping[str, object],
        lifecycle_payload: Mapping[str, object],
    ) -> tuple[str, ...]:
        blockers: list[str] = []
        if plan_payload["legal_hold"] is True:
            blockers.append("legal_hold_active")
        for task in plan_payload["tasks"]:  # type: ignore[union-attr]
            if task["status"] == "open":
                blockers.append(f"task_open:{task['task_id']}")
            elif task["status"] == "blocked":
                blockers.append(f"task_blocked:{task['task_id']}")
        rows = connection.execute(
            "SELECT * FROM callbacks WHERE tenant_id=? AND plan_id=? ORDER BY callback_id",
            (tenant_id, plan_payload["plan_id"]),
        ).fetchall()
        callback_by_task: dict[str, dict[str, Any]] = {}
        for row in rows:
            callback = ThirdPartyLifecycleStore._payload(row, "callback")
            callback_by_task[str(callback["task_id"])] = callback
            if callback["state"] != "delivered":
                blocker = (
                    "callback_dead_letter"
                    if callback["state"] == "dead_letter"
                    else "callback_pending"
                )
                blockers.append(f"{blocker}:{callback['callback_id']}")
        dependencies = {
            str(item["dependency_id"]): str(item["kind"])
            for item in lifecycle_payload["dependencies"]  # type: ignore[union-attr]
        }
        for task in plan_payload["tasks"]:  # type: ignore[union-attr]
            if dependencies[str(task["dependency_id"])] != "access":
                continue
            callback = callback_by_task.get(str(task["task_id"]))
            if task["status"] != "completed" or (
                callback is None or callback["state"] != "delivered"
            ):
                blockers.append(f"access_open:{task['dependency_id']}")
        return tuple(dict.fromkeys(blockers))

    def _refresh_plan_blockers(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        plan_id: str,
    ) -> OffboardingPlan:
        plan_raw, _ = self._get(
            connection,
            "offboarding_plans",
            tenant_id,
            "plan_id",
            plan_id,
            "offboarding plan",
        )
        lifecycle_raw, _ = self._get(
            connection,
            "lifecycles",
            tenant_id,
            "lifecycle_id",
            str(plan_raw["lifecycle_id"]),
            "lifecycle",
        )
        blockers = self._derive_blockers(connection, tenant_id, plan_raw, lifecycle_raw)
        if list(blockers) != plan_raw["blockers"]:
            plan_raw["blockers"] = list(blockers)
            digest = self._write(
                connection,
                "offboarding_plans",
                tenant_id,
                "plan_id",
                plan_id,
                plan_raw,
            )
        else:
            digest = _sha256(plan_raw)
        return self._plan_from(plan_raw, digest)

    def begin_offboarding(
        self,
        tenant_id: str,
        lifecycle_id: str,
        plan_id: str,
        *,
        tasks: Sequence[Mapping[str, object]],
        legal_hold: bool,
        legal_hold_evidence_ref: str | None,
        maximum_callback_attempts: int,
        expected_lifecycle_revision: int,
        idempotency_key: str,
    ) -> OffboardingPlan:
        """Start a complete dependency plan and enqueue callback intent only."""

        tenant = _tenant(tenant_id)
        lifecycle = _id(lifecycle_id, "lifecycle_id")
        plan = _id(plan_id, "plan_id")
        if not isinstance(legal_hold, bool):
            raise ThirdPartyLifecycleValidationError("legal_hold must be boolean")
        hold_evidence = (
            None
            if legal_hold_evidence_ref is None
            else _id(legal_hold_evidence_ref, "legal_hold_evidence_ref")
        )
        if legal_hold and hold_evidence is None:
            raise ThirdPartyLifecycleValidationError(
                "an active legal hold requires an evidence reference"
            )
        if not legal_hold and hold_evidence is not None:
            raise ThirdPartyLifecycleValidationError(
                "inactive legal hold cannot retain a legal-hold evidence reference"
            )
        maximum_attempts = _integer(maximum_callback_attempts, "maximum_callback_attempts", 1, 20)
        expected = _integer(
            expected_lifecycle_revision,
            "expected_lifecycle_revision",
            1,
            1_000_000,
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            lifecycle_raw, lifecycle_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle,
                "lifecycle",
            )
            record = self._lifecycle_from(lifecycle_raw, lifecycle_digest)
            dependency_kinds = {
                str(item["dependency_id"]): str(item["kind"]) for item in record.dependencies
            }
            task_items = tuple(
                _offboarding_task(item, dependency_kinds)
                for item in _sequence(tasks, "offboarding tasks", len(dependency_kinds))
            )
            task_ids = tuple(str(item["task_id"]) for item in task_items)
            task_dependencies = tuple(str(item["dependency_id"]) for item in task_items)
            if len(set(task_ids)) != len(task_ids):
                raise ThirdPartyLifecycleValidationError("offboarding task IDs must be unique")
            if len(set(task_dependencies)) != len(task_dependencies) or set(
                task_dependencies
            ) != set(dependency_kinds):
                raise ThirdPartyLifecycleValidationError(
                    "offboarding tasks must exactly cover every dependency once"
                )
            request = {
                "action": "begin_offboarding",
                "lifecycle_id": lifecycle,
                "plan_id": plan,
                "tasks": list(task_items),
                "legal_hold": legal_hold,
                "legal_hold_evidence_ref": hold_evidence,
                "maximum_callback_attempts": maximum_attempts,
                "expected_lifecycle_revision": expected,
                "actor_ref": actor,
            }
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                stored, digest = self._get(
                    connection,
                    "offboarding_plans",
                    tenant,
                    "plan_id",
                    plan,
                    "offboarding plan",
                )
                return self._plan_from(stored, digest)
            if record.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"lifecycle revision CAS failed: expected {expected}, found {record.revision}"
                )
            if record.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated lifecycle owner can start offboarding"
                )
            if record.stage == "offboarded":
                raise ThirdPartyLifecycleConflict(
                    "an offboarded lifecycle cannot be reopened or activated"
                )
            if record.stage == "offboarding" or record.offboarding_plan_id is not None:
                raise ThirdPartyLifecycleConflict("offboarding is already in progress")
            plan_payload = {
                "tenant_id": tenant,
                "plan_id": plan,
                "lifecycle_id": lifecycle,
                "state": "in_progress",
                "legal_hold": legal_hold,
                "legal_hold_evidence_ref": hold_evidence,
                "tasks": list(task_items),
                "blockers": [],
                "initiated_by": actor,
                "completed_by": None,
                "completion_attestation_ref": None,
                "revision": 1,
                "created_at": now,
                "updated_at": now,
            }
            plan_digest = _sha256(plan_payload)
            connection.execute(
                "INSERT INTO offboarding_plans VALUES(?,?,?,?,?)",
                (
                    tenant,
                    plan,
                    lifecycle,
                    _canonical(plan_payload).decode("ascii"),
                    plan_digest,
                ),
            )
            dependencies = {str(item["dependency_id"]): dict(item) for item in record.dependencies}
            for task in task_items:
                if task["callback_required"] is not True:
                    continue
                callback_id = (
                    "cb-"
                    + hashlib.sha256(f"{tenant}\0{plan}\0{task['task_id']}".encode()).hexdigest()[
                        :40
                    ]
                )
                dependency = dependencies[str(task["dependency_id"])]
                callback_payload = {
                    "tenant_id": tenant,
                    "callback_id": callback_id,
                    "plan_id": plan,
                    "lifecycle_id": lifecycle,
                    "task_id": task["task_id"],
                    "action": task["action"],
                    "dependency_ref": dependency["reference"],
                    "destination_ref": dependency["reference"],
                    "state": "pending",
                    "attempt": 0,
                    "maximum_attempts": maximum_attempts,
                    "next_attempt_at": now,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": None,
                    "delivery_evidence_sha256": None,
                    "revision": 1,
                }
                callback_digest = _sha256(callback_payload)
                connection.execute(
                    "INSERT INTO callbacks VALUES(?,?,?,?,?,?,?,?)",
                    (
                        tenant,
                        callback_id,
                        plan,
                        "pending",
                        now,
                        None,
                        _canonical(callback_payload).decode("ascii"),
                        callback_digest,
                    ),
                )
            lifecycle_payload = dict(lifecycle_raw)
            lifecycle_payload.update(
                {
                    "stage": "offboarding",
                    "offboarding_plan_id": plan,
                    "revision": record.revision + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle,
                lifecycle_payload,
            )
            refreshed = self._refresh_plan_blockers(connection, tenant, plan)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "offboarding_plan",
                plan,
            )
            self._audit(
                connection,
                tenant,
                "offboarding_started",
                lifecycle,
                actor,
                {
                    "plan_id": plan,
                    "task_count": len(task_items),
                    "callback_count": sum(item["callback_required"] is True for item in task_items),
                    "legal_hold": legal_hold,
                },
                now,
            )
            return refreshed

    @staticmethod
    def _write_callback(
        connection: sqlite3.Connection,
        payload: Mapping[str, object],
    ) -> str:
        digest = _sha256(dict(payload))
        result = connection.execute(
            "UPDATE callbacks SET state=?,next_attempt_at=?,lease_until=?,"
            "payload_json=?,integrity_sha256=? WHERE tenant_id=? AND callback_id=?",
            (
                payload["state"],
                payload["next_attempt_at"],
                payload["lease_until"],
                _canonical(dict(payload)).decode("ascii"),
                digest,
                payload["tenant_id"],
                payload["callback_id"],
            ),
        )
        if result.rowcount != 1:
            raise ThirdPartyLifecycleNotFound("callback was not found")
        return digest

    def get_callback(self, tenant_id: str, callback_id: str) -> CallbackItem:
        tenant = _tenant(tenant_id)
        callback = _id(callback_id, "callback_id")
        with self._connect() as connection:
            payload, digest = self._get(
                connection,
                "callbacks",
                tenant,
                "callback_id",
                callback,
                "callback",
            )
            return self._callback_from(payload, digest)

    def claim_callbacks(
        self,
        tenant_id: str,
        *,
        limit: int,
        lease_seconds: int,
    ) -> tuple[CallbackItem, ...]:
        """Lease due callback intent, recovering expired leases atomically."""

        tenant = _tenant(tenant_id)
        selected_limit = _integer(limit, "limit", 1, 100)
        lease = _integer(lease_seconds, "lease_seconds", 1, _MAX_LEASE_SECONDS)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        claimed: list[CallbackItem] = []
        affected_plans: set[str] = set()
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM callbacks WHERE tenant_id=? AND "
                "((state='pending' AND next_attempt_at<=?) OR "
                "(state='leased' AND lease_until<=?)) ORDER BY next_attempt_at,callback_id "
                "LIMIT ?",
                (tenant, now, now, selected_limit * 2),
            ).fetchall()
            for row in rows:
                payload = self._payload(row, "callback")
                affected_plans.add(str(payload["plan_id"]))
                if int(payload["attempt"]) >= int(payload["maximum_attempts"]):
                    payload.update(
                        {
                            "state": "dead_letter",
                            "lease_token": None,
                            "lease_until": None,
                            "last_error_code": "lease_expired_attempts_exhausted",
                            "revision": int(payload["revision"]) + 1,
                        }
                    )
                    self._write_callback(connection, payload)
                    continue
                token = _id(self._token_factory(), "lease token", _OP_RE)
                payload.update(
                    {
                        "state": "leased",
                        "attempt": int(payload["attempt"]) + 1,
                        "lease_token": token,
                        "lease_until": now + lease,
                        "revision": int(payload["revision"]) + 1,
                    }
                )
                digest = self._write_callback(connection, payload)
                claimed.append(self._callback_from(payload, digest))
                if len(claimed) >= selected_limit:
                    break
            for plan in affected_plans:
                self._refresh_plan_blockers(connection, tenant, plan)
            if claimed:
                self._audit(
                    connection,
                    tenant,
                    "callbacks_claimed",
                    "callback_batch",
                    actor,
                    {
                        "callback_ids": [item.callback_id for item in claimed],
                        "lease_seconds": lease,
                    },
                    now,
                )
        return tuple(claimed)

    def fail_callback(
        self,
        tenant_id: str,
        callback_id: str,
        *,
        lease_token: str,
        error_code: str,
        retry_after_seconds: int,
        expected_revision: int,
        idempotency_key: str,
    ) -> CallbackItem:
        """Nack a leased callback into deterministic retry or dead letter."""

        tenant = _tenant(tenant_id)
        callback = _id(callback_id, "callback_id")
        token = _id(lease_token, "lease_token", _OP_RE)
        error = _id(error_code, "error_code")
        retry_after = _integer(retry_after_seconds, "retry_after_seconds", 1, _MAX_BACKOFF_SECONDS)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "fail_callback",
            "callback_id": callback,
            "lease_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "error_code": error,
            "retry_after_seconds": retry_after,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "callbacks",
                tenant,
                "callback_id",
                callback,
                "callback",
            )
            if operation is not None:
                return self._callback_from(raw, stored_digest)
            item = self._callback_from(raw, stored_digest)
            self._require_live_lease(item, token, expected, now)
            exhausted = item.attempt >= item.maximum_attempts
            raw.update(
                {
                    "state": "dead_letter" if exhausted else "pending",
                    "next_attempt_at": now if exhausted else now + retry_after,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": error,
                    "revision": item.revision + 1,
                }
            )
            digest = self._write_callback(connection, raw)
            self._refresh_plan_blockers(connection, tenant, item.plan_id)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "callback",
                callback,
            )
            self._audit(
                connection,
                tenant,
                "callback_failed",
                callback,
                actor,
                {"error_code": error, "state": raw["state"]},
                now,
            )
            return self._callback_from(raw, digest)

    @staticmethod
    def _require_live_lease(
        item: CallbackItem,
        lease_token: str,
        expected_revision: int,
        now: float,
    ) -> None:
        if item.revision != expected_revision:
            raise ThirdPartyLifecycleConflict(
                f"callback revision CAS failed: expected {expected_revision}, found {item.revision}"
            )
        if (
            item.state != "leased"
            or item.lease_token != lease_token
            or item.lease_until is None
            or item.lease_until <= now
        ):
            raise ThirdPartyLifecycleConflict("callback lease is absent, stale, or invalid")

    def acknowledge_callback(
        self,
        tenant_id: str,
        callback_id: str,
        *,
        lease_token: str,
        delivery_evidence_sha256: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> CallbackItem:
        """Acknowledge adapter-reported delivery evidence; perform no external write."""

        tenant = _tenant(tenant_id)
        callback = _id(callback_id, "callback_id")
        token = _id(lease_token, "lease_token", _OP_RE)
        evidence = _digest(delivery_evidence_sha256, "delivery_evidence_sha256")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "acknowledge_callback",
            "callback_id": callback,
            "lease_token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "delivery_evidence_sha256": evidence,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "callbacks",
                tenant,
                "callback_id",
                callback,
                "callback",
            )
            if operation is not None:
                return self._callback_from(raw, stored_digest)
            item = self._callback_from(raw, stored_digest)
            self._require_live_lease(item, token, expected, now)
            raw.update(
                {
                    "state": "delivered",
                    "next_attempt_at": now,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": None,
                    "revision": item.revision + 1,
                }
            )
            # The digest is audit evidence, not a credential or provider response body.
            raw["delivery_evidence_sha256"] = evidence
            digest = self._write_callback(connection, raw)
            self._refresh_plan_blockers(connection, tenant, item.plan_id)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "callback",
                callback,
            )
            self._audit(
                connection,
                tenant,
                "callback_acknowledged",
                callback,
                actor,
                {"delivery_evidence_sha256": evidence},
                now,
            )
            return self._callback_from(raw, digest)

    def requeue_dead_letter(
        self,
        tenant_id: str,
        callback_id: str,
        *,
        reason_code: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> CallbackItem:
        """Explicitly recover a dead-letter callback under lifecycle-owner control."""

        tenant = _tenant(tenant_id)
        callback = _id(callback_id, "callback_id")
        reason = _id(reason_code, "reason_code")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "requeue_dead_letter",
            "callback_id": callback,
            "reason_code": reason,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "callbacks",
                tenant,
                "callback_id",
                callback,
                "callback",
            )
            if operation is not None:
                return self._callback_from(raw, stored_digest)
            item = self._callback_from(raw, stored_digest)
            if item.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"callback revision CAS failed: expected {expected}, found {item.revision}"
                )
            if item.state != "dead_letter":
                raise ThirdPartyLifecycleConflict("callback is not dead-lettered")
            lifecycle_raw, lifecycle_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                item.lifecycle_id,
                "lifecycle",
            )
            lifecycle = self._lifecycle_from(lifecycle_raw, lifecycle_digest)
            if lifecycle.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the lifecycle owner can requeue a dead letter"
                )
            raw.update(
                {
                    "state": "pending",
                    "attempt": 0,
                    "next_attempt_at": now,
                    "lease_token": None,
                    "lease_until": None,
                    "last_error_code": None,
                    "revision": item.revision + 1,
                }
            )
            raw["delivery_evidence_sha256"] = None
            digest = self._write_callback(connection, raw)
            self._refresh_plan_blockers(connection, tenant, item.plan_id)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "callback",
                callback,
            )
            self._audit(
                connection,
                tenant,
                "callback_requeued",
                callback,
                actor,
                {"reason_code": reason},
                now,
            )
            return self._callback_from(raw, digest)

    def approve_offboarding_completion(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        completion_attestation_ref: str,
        expected_plan_revision: int,
        expected_lifecycle_revision: int,
        idempotency_key: str,
    ) -> OffboardingPlan:
        """Complete offboarding only after independent, blocker-free approval."""

        tenant = _tenant(tenant_id)
        plan = _id(plan_id, "plan_id")
        attestation = _id(completion_attestation_ref, "completion_attestation_ref")
        expected_plan = _integer(expected_plan_revision, "expected_plan_revision", 1, 1_000_000)
        expected_lifecycle = _integer(
            expected_lifecycle_revision,
            "expected_lifecycle_revision",
            1,
            1_000_000,
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "approve_offboarding_completion",
            "plan_id": plan,
            "completion_attestation_ref": attestation,
            "expected_plan_revision": expected_plan,
            "expected_lifecycle_revision": expected_lifecycle,
            "actor_ref": actor,
        }
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                raw, digest = self._get(
                    connection,
                    "offboarding_plans",
                    tenant,
                    "plan_id",
                    plan,
                    "offboarding plan",
                )
                return self._plan_from(raw, digest)
            current = self._refresh_plan_blockers(connection, tenant, plan)
            lifecycle_raw, lifecycle_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                current.lifecycle_id,
                "lifecycle",
            )
            lifecycle = self._lifecycle_from(lifecycle_raw, lifecycle_digest)
            if current.revision != expected_plan:
                raise ThirdPartyLifecycleConflict(
                    f"offboarding plan revision CAS failed: expected {expected_plan}, "
                    f"found {current.revision}"
                )
            if lifecycle.revision != expected_lifecycle:
                raise ThirdPartyLifecycleConflict(
                    f"lifecycle revision CAS failed: expected {expected_lifecycle}, "
                    f"found {lifecycle.revision}"
                )
            if current.state != "in_progress" or lifecycle.stage != "offboarding":
                raise ThirdPartyLifecycleConflict("offboarding is not in progress")
            if lifecycle.offboarding_plan_id != plan:
                raise ThirdPartyLifecycleIntegrityError(
                    "lifecycle and offboarding plan association is inconsistent"
                )
            if actor == current.initiated_by:
                raise ThirdPartyLifecyclePermissionDenied(
                    "offboarding initiators cannot approve completion"
                )
            if current.blockers:
                raise ThirdPartyLifecycleConflict(
                    "offboarding cannot complete while blockers remain: "
                    + ",".join(current.blockers)
                )
            if any(task["status"] != "completed" for task in current.tasks):
                raise ThirdPartyLifecycleConflict(
                    "offboarding cannot complete with open or blocked tasks"
                )
            plan_payload = {
                key: value for key, value in current.__dict__.items() if key != "integrity_sha256"
            }
            plan_payload.update(
                {
                    "tasks": [dict(item) for item in current.tasks],
                    "blockers": [],
                    "state": "completed",
                    "completed_by": actor,
                    "completion_attestation_ref": attestation,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            plan_digest = self._write(
                connection,
                "offboarding_plans",
                tenant,
                "plan_id",
                plan,
                plan_payload,
            )
            lifecycle_payload = dict(lifecycle_raw)
            lifecycle_payload.update(
                {
                    "stage": "offboarded",
                    "revision": lifecycle.revision + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle.lifecycle_id,
                lifecycle_payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "offboarding_plan",
                plan,
            )
            self._audit(
                connection,
                tenant,
                "offboarding_completed",
                lifecycle.lifecycle_id,
                actor,
                {"plan_id": plan, "completion_attestation_ref": attestation},
                now,
            )
            return self._plan_from(plan_payload, plan_digest)

    @staticmethod
    def _audit_head(connection: sqlite3.Connection, tenant_id: str) -> str:
        row = connection.execute(
            "SELECT integrity_sha256 FROM audit_events WHERE tenant_id=? "
            "ORDER BY sequence DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        return "0" * 64 if row is None else str(row["integrity_sha256"])

    def _store_export(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        export_id: str,
        subject_kind: str,
        subject_id: str,
        body: Mapping[str, object],
        retention_seconds: int,
        actor: str,
        now: float,
        idempotency_key: str,
        request_sha256: str,
    ) -> EvidenceExport:
        payload = {
            "tenant_id": tenant_id,
            "export_id": export_id,
            "subject_kind": subject_kind,
            "subject_id": subject_id,
            "schema": EXPORT_SCHEMA,
            "body": dict(body),
            "retained_until": now + retention_seconds,
            "created_by": actor,
            "created_at": now,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO exports VALUES(?,?,?,?,?,?,?)",
            (
                tenant_id,
                export_id,
                subject_kind,
                subject_id,
                payload["retained_until"],
                _canonical(payload).decode("ascii"),
                digest,
            ),
        )
        self._record_operation(
            connection,
            tenant_id,
            idempotency_key,
            request_sha256,
            "export",
            export_id,
        )
        self._audit(
            connection,
            tenant_id,
            "evidence_export_created",
            export_id,
            actor,
            {
                "subject_kind": subject_kind,
                "subject_id_sha256": hashlib.sha256(subject_id.encode()).hexdigest(),
                "body_sha256": _sha256(body),
            },
            now,
        )
        return self._export_from(payload, digest)

    def get_export(self, tenant_id: str, export_id: str) -> EvidenceExport:
        tenant = _tenant(tenant_id)
        export = _id(export_id, "export_id")
        with self._connect() as connection:
            payload, digest = self._get(
                connection,
                "exports",
                tenant,
                "export_id",
                export,
                "evidence export",
            )
            return self._export_from(payload, digest)

    def export_assessment(
        self,
        tenant_id: str,
        assessment_id: str,
        export_id: str,
        *,
        retention_seconds: int,
        idempotency_key: str,
    ) -> EvidenceExport:
        """Create a tenant-scoped evidence report with source record digests."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        export = _id(export_id, "export_id")
        retention = _retention(retention_seconds)
        actor = self._actor()
        request = {
            "action": "export_assessment",
            "assessment_id": assessment_key,
            "export_id": export,
            "retention_seconds": retention,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                payload, digest = self._get(
                    connection,
                    "exports",
                    tenant,
                    "export_id",
                    export,
                    "evidence export",
                )
                return self._export_from(payload, digest)
            assessment_raw, assessment_digest = self._get(
                connection,
                "assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            assessment = self._assessment_from(assessment_raw, assessment_digest)
            if assessment.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated assessment owner can export it"
                )
            template_row = connection.execute(
                "SELECT * FROM templates WHERE tenant_id=? AND template_id=? AND version=?",
                (tenant, assessment.template_id, assessment.template_version),
            ).fetchone()
            if template_row is None:
                raise ThirdPartyLifecycleIntegrityError("assessment template evidence is missing")
            template_raw = self._payload(template_row, "assessment template")
            now = _timestamp(self._clock(), "current time")
            body = {
                "kind": "assessment",
                "tenant_id": tenant,
                "subject_id": assessment_key,
                "assessment": assessment_raw,
                "assessment_integrity_sha256": assessment_digest,
                "template": template_raw,
                "template_integrity_sha256": template_row["integrity_sha256"],
                "audit_head_sha256": self._audit_head(connection, tenant),
                "generated_at": now,
                "limitations": [
                    "control_plane_evidence_only",
                    "no_live_provider_operation",
                    "no_external_acceptance_claim",
                ],
            }
            return self._store_export(
                connection,
                tenant,
                export,
                "assessment",
                assessment_key,
                body,
                retention,
                actor,
                now,
                idempotency_key,
                request_sha,
            )

    def export_lifecycle(
        self,
        tenant_id: str,
        lifecycle_id: str,
        export_id: str,
        *,
        retention_seconds: int,
        idempotency_key: str,
    ) -> EvidenceExport:
        """Export lifecycle, plan, task, and callback evidence without provider data."""

        tenant = _tenant(tenant_id)
        lifecycle_key = _id(lifecycle_id, "lifecycle_id")
        export = _id(export_id, "export_id")
        retention = _retention(retention_seconds)
        actor = self._actor()
        request = {
            "action": "export_lifecycle",
            "lifecycle_id": lifecycle_key,
            "export_id": export,
            "retention_seconds": retention,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                payload, digest = self._get(
                    connection,
                    "exports",
                    tenant,
                    "export_id",
                    export,
                    "evidence export",
                )
                return self._export_from(payload, digest)
            lifecycle_raw, lifecycle_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                lifecycle_key,
                "lifecycle",
            )
            lifecycle = self._lifecycle_from(lifecycle_raw, lifecycle_digest)
            if lifecycle.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated lifecycle owner can export it"
                )
            plan_evidence: dict[str, object] | None = None
            callback_evidence: list[dict[str, object]] = []
            if lifecycle.offboarding_plan_id is not None:
                plan_raw, plan_digest = self._get(
                    connection,
                    "offboarding_plans",
                    tenant,
                    "plan_id",
                    lifecycle.offboarding_plan_id,
                    "offboarding plan",
                )
                plan_evidence = {
                    "record": plan_raw,
                    "integrity_sha256": plan_digest,
                }
                rows = connection.execute(
                    "SELECT * FROM callbacks WHERE tenant_id=? AND plan_id=? ORDER BY callback_id",
                    (tenant, lifecycle.offboarding_plan_id),
                ).fetchall()
                for row in rows:
                    stored_callback = self._payload(row, "callback")
                    exported_callback = dict(stored_callback)
                    lease_token = exported_callback.pop("lease_token", None)
                    exported_callback["lease_token_sha256"] = (
                        hashlib.sha256(str(lease_token).encode()).hexdigest()
                        if lease_token is not None
                        else None
                    )
                    callback_evidence.append(
                        {
                            "record": exported_callback,
                            "stored_record_integrity_sha256": row["integrity_sha256"],
                            "export_record_sha256": _sha256(exported_callback),
                            "redactions": (["lease_token"] if lease_token is not None else []),
                        }
                    )
            now = _timestamp(self._clock(), "current time")
            body = {
                "kind": "lifecycle",
                "tenant_id": tenant,
                "subject_id": lifecycle_key,
                "lifecycle": lifecycle_raw,
                "lifecycle_integrity_sha256": lifecycle_digest,
                "offboarding_plan": plan_evidence,
                "callbacks": callback_evidence,
                "audit_head_sha256": self._audit_head(connection, tenant),
                "generated_at": now,
                "limitations": [
                    "control_plane_evidence_only",
                    "callbacks_are_delivery_intent_not_external_writes",
                    "no_live_provider_operation",
                    "no_external_acceptance_claim",
                ],
            }
            return self._store_export(
                connection,
                tenant,
                export,
                "lifecycle",
                lifecycle_key,
                body,
                retention,
                actor,
                now,
                idempotency_key,
                request_sha,
            )

    def purge_expired(
        self,
        tenant_id: str,
        *,
        before: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        """Apply bounded retention while preserving the immutable audit evidence."""

        tenant = _tenant(tenant_id)
        cutoff = _timestamp(before, "before")
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "purge_expired",
            "before": cutoff,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is not None:
                try:
                    result = json.loads(operation["result_id"])
                except (TypeError, json.JSONDecodeError) as exc:
                    raise ThirdPartyLifecycleIntegrityError(
                        "purge idempotency result is invalid"
                    ) from exc
                if not isinstance(result, dict):
                    raise ThirdPartyLifecycleIntegrityError("purge idempotency result is invalid")
                return {str(key): int(value) for key, value in result.items()}
            exports = connection.execute(
                "DELETE FROM exports WHERE tenant_id=? AND retained_until<=?",
                (tenant, cutoff),
            ).rowcount
            assessment_rows = connection.execute(
                "SELECT assessment_id FROM assessments WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.retained_until')<=?",
                (tenant, cutoff),
            ).fetchall()
            assessment_ids = [str(row["assessment_id"]) for row in assessment_rows]
            for assessment_id in assessment_ids:
                connection.execute(
                    "DELETE FROM assessments WHERE tenant_id=? AND assessment_id=?",
                    (tenant, assessment_id),
                )
                connection.execute(
                    "DELETE FROM operations WHERE tenant_id=? AND result_kind='assessment' "
                    "AND result_id=?",
                    (tenant, assessment_id),
                )
            lifecycle_rows = connection.execute(
                "SELECT lifecycle_id,payload_json FROM lifecycles WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.stage')='offboarded' "
                "AND json_extract(payload_json,'$.retained_until')<=?",
                (tenant, cutoff),
            ).fetchall()
            lifecycle_ids = [str(row["lifecycle_id"]) for row in lifecycle_rows]
            plans = 0
            callbacks = 0
            for lifecycle_id in lifecycle_ids:
                plan_rows = connection.execute(
                    "SELECT plan_id FROM offboarding_plans WHERE tenant_id=? AND lifecycle_id=?",
                    (tenant, lifecycle_id),
                ).fetchall()
                for plan_row in plan_rows:
                    plan_id = str(plan_row["plan_id"])
                    callbacks += connection.execute(
                        "DELETE FROM callbacks WHERE tenant_id=? AND plan_id=?",
                        (tenant, plan_id),
                    ).rowcount
                    plans += connection.execute(
                        "DELETE FROM offboarding_plans WHERE tenant_id=? AND plan_id=?",
                        (tenant, plan_id),
                    ).rowcount
                connection.execute(
                    "DELETE FROM lifecycles WHERE tenant_id=? AND lifecycle_id=?",
                    (tenant, lifecycle_id),
                )
                connection.execute(
                    "DELETE FROM operations WHERE tenant_id=? AND result_id=? "
                    "AND result_kind IN ('lifecycle','offboarding_plan','callback')",
                    (tenant, lifecycle_id),
                )
            template_rows = connection.execute(
                "SELECT template_id,version FROM templates WHERE tenant_id=? "
                "AND json_extract(payload_json,'$.retained_until')<=?",
                (tenant, cutoff),
            ).fetchall()
            templates = 0
            for template_row in template_rows:
                referenced = connection.execute(
                    "SELECT 1 FROM assessments WHERE tenant_id=? "
                    "AND json_extract(payload_json,'$.template_id')=? "
                    "AND json_extract(payload_json,'$.template_version')=? LIMIT 1",
                    (
                        tenant,
                        template_row["template_id"],
                        template_row["version"],
                    ),
                ).fetchone()
                if referenced is None:
                    templates += connection.execute(
                        "DELETE FROM templates WHERE tenant_id=? AND template_id=? AND version=?",
                        (
                            tenant,
                            template_row["template_id"],
                            template_row["version"],
                        ),
                    ).rowcount
            result = {
                "exports": exports,
                "assessments": len(assessment_ids),
                "lifecycles": len(lifecycle_ids),
                "offboarding_plans": plans,
                "callbacks": callbacks,
                "templates": templates,
            }
            encoded_result = json.dumps(result, sort_keys=True, separators=(",", ":"))
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "purge",
                encoded_result,
            )
            self._audit(
                connection,
                tenant,
                "retention_purged",
                "retention",
                actor,
                {"before": cutoff, "counts": result},
                now,
            )
            return result

    def unified_audit_records(self, tenant_id: str):
        """Return the lifecycle audit chain without raw vendor/detail values."""

        from .unified_audit import GENESIS_SHA256, build_source_record

        tenant = _tenant(tenant_id)
        self.verify_integrity(tenant)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
        previous_integrity = GENESIS_SHA256
        previous_record = GENESIS_SHA256
        records = []
        for expected_sequence, row in enumerate(rows, start=1):
            payload = self._payload(row, "audit event")
            action_name = str(payload.get("action") or "")
            if (
                payload.get("schema") != AUDIT_SCHEMA
                or payload.get("tenant_id") != tenant
                or payload.get("sequence") != expected_sequence
                or int(row["sequence"]) != expected_sequence
                or payload.get("previous_sha256") != previous_integrity
            ):
                raise ThirdPartyLifecycleIntegrityError(
                    "tenant audit hash chain is inconsistent"
                )
            integrity = str(row["integrity_sha256"])
            subject_sha256 = _digest(
                payload.get("subject_sha256"),
                "audit subject digest",
            )
            actor_ref = _id(
                payload.get("actor_ref"),
                "authenticated principal",
            )
            source_action = (
                "approval_granted"
                if "approved" in action_name
                else "approval_denied"
                if "revoked" in action_name
                else "evidence_recorded"
                if "export" in action_name
                else "risk_changed"
                if any(token in action_name for token in ("risk", "assessment"))
                else "status_changed"
            )
            record = build_source_record(
                sequence=expected_sequence,
                occurred_at=float(payload["occurred_at"]),
                action=source_action,
                actor_sha256=hashlib.sha256(actor_ref.encode("utf-8")).hexdigest(),
                resource_sha256=subject_sha256,
                payload_sha256=integrity,
                previous_sha256=previous_record,
            )
            records.append(record)
            previous_integrity = integrity
            previous_record = record.record_sha256
        return tuple(records)

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        """Verify every tenant row, index projection, operation, and audit link."""

        tenant = _tenant(tenant_id)
        verified = 0
        with self._connect() as connection:
            tables = (
                "templates",
                "assessments",
                "lifecycles",
                "offboarding_plans",
                "callbacks",
                "exports",
            )
            for table in tables:
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload = self._payload(row, table)
                    if payload.get("tenant_id") != tenant:
                        raise ThirdPartyLifecycleIntegrityError(
                            f"persisted {table} tenant binding is inconsistent"
                        )
                    if table == "callbacks" and (
                        payload.get("state") != row["state"]
                        or payload.get("next_attempt_at") != row["next_attempt_at"]
                        or payload.get("lease_until") != row["lease_until"]
                    ):
                        raise ThirdPartyLifecycleIntegrityError(
                            "callback claim index is inconsistent"
                        )
                    if table == "exports" and (
                        payload.get("subject_kind") != row["subject_kind"]
                        or payload.get("subject_id") != row["subject_id"]
                        or payload.get("retained_until") != row["retained_until"]
                    ):
                        raise ThirdPartyLifecycleIntegrityError(
                            "export retention index is inconsistent"
                        )
                    verified += 1
            operation_rows = connection.execute(
                "SELECT * FROM operations WHERE tenant_id=? ORDER BY operation_sha256",
                (tenant,),
            ).fetchall()
            for row in operation_rows:
                binding = {
                    "tenant_id": row["tenant_id"],
                    "operation_sha256": row["operation_sha256"],
                    "request_sha256": row["request_sha256"],
                    "result_kind": row["result_kind"],
                    "result_id": row["result_id"],
                }
                if _sha256(binding) != row["integrity_sha256"]:
                    raise ThirdPartyLifecycleIntegrityError(
                        "idempotency binding failed integrity verification"
                    )
                verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            expected_sequence = 1
            for row in audit_rows:
                payload = self._payload(row, "audit event")
                if (
                    row["sequence"] != expected_sequence
                    or payload.get("tenant_id") != tenant
                    or payload.get("sequence") != expected_sequence
                    or payload.get("previous_sha256") != previous
                    or payload.get("schema") != AUDIT_SCHEMA
                ):
                    raise ThirdPartyLifecycleIntegrityError(
                        "tenant audit hash chain is inconsistent"
                    )
                previous = row["integrity_sha256"]
                expected_sequence += 1
                verified += 1
            return IntegrityVerification(
                tenant_id=tenant,
                verified_records=verified,
                audit_events=len(audit_rows),
                terminal_audit_sha256=previous,
            )

    def get_offboarding_plan(
        self,
        tenant_id: str,
        plan_id: str,
    ) -> OffboardingPlan:
        tenant = _tenant(tenant_id)
        plan = _id(plan_id, "plan_id")
        with self._connect() as connection:
            payload, digest = self._get(
                connection,
                "offboarding_plans",
                tenant,
                "plan_id",
                plan,
                "offboarding plan",
            )
            return self._plan_from(payload, digest)

    def list_offboarding_plans(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> tuple[OffboardingPlan, ...]:
        """Return current, integrity-verified offboarding plan heads."""

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM offboarding_plans WHERE tenant_id=? "
                "ORDER BY plan_id LIMIT ?",
                (tenant, bounded),
            ).fetchall()
        values = tuple(
            self._plan_from(
                self._payload(row, "offboarding plan"),
                row["integrity_sha256"],
            )
            for row in rows
        )
        return tuple(sorted(values, key=lambda item: (-item.updated_at, item.plan_id)))

    def context_record_counts(self, tenant_id: str) -> Mapping[str, int]:
        """Return exact current-head counts for bounded context disclosure."""

        tenant = _tenant(tenant_id)
        tables = ("assessments", "lifecycles", "offboarding_plans")
        with self._connect() as connection:
            return {
                table: int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {table} WHERE tenant_id=?",  # noqa: S608
                        (tenant,),
                    ).fetchone()[0]
                )
                for table in tables
            }

    def set_legal_hold(
        self,
        tenant_id: str,
        plan_id: str,
        *,
        active: bool,
        evidence_ref: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> OffboardingPlan:
        """Set or release a legal hold with explicit evidence and plan CAS."""

        tenant = _tenant(tenant_id)
        plan = _id(plan_id, "plan_id")
        if not isinstance(active, bool):
            raise ThirdPartyLifecycleValidationError("active must be boolean")
        evidence = _id(evidence_ref, "legal-hold evidence_ref")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "set_legal_hold",
            "plan_id": plan,
            "active": active,
            "evidence_ref": evidence,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "offboarding_plans",
                tenant,
                "plan_id",
                plan,
                "offboarding plan",
            )
            if operation is not None:
                return self._plan_from(raw, stored_digest)
            current = self._plan_from(raw, stored_digest)
            if current.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"offboarding plan revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            lifecycle_raw, lifecycle_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                current.lifecycle_id,
                "lifecycle",
            )
            lifecycle = self._lifecycle_from(lifecycle_raw, lifecycle_digest)
            if lifecycle.owner_ref != actor:
                raise ThirdPartyLifecyclePermissionDenied(
                    "only the authenticated lifecycle owner can govern legal holds"
                )
            if current.state != "in_progress":
                raise ThirdPartyLifecycleConflict("offboarding plan is not in progress")
            payload = dict(raw)
            payload.update(
                {
                    "legal_hold": active,
                    "legal_hold_evidence_ref": evidence,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "offboarding_plans",
                tenant,
                "plan_id",
                plan,
                payload,
            )
            refreshed = self._refresh_plan_blockers(connection, tenant, plan)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "offboarding_plan",
                plan,
            )
            self._audit(
                connection,
                tenant,
                "legal_hold_set",
                plan,
                actor,
                {"active": active, "evidence_ref": evidence},
                now,
            )
            return refreshed

    def set_offboarding_task(
        self,
        tenant_id: str,
        plan_id: str,
        task_id: str,
        *,
        status: str,
        evidence_sha256: str | None,
        attestation_ref: str | None,
        expected_revision: int,
        idempotency_key: str,
    ) -> OffboardingPlan:
        """Record explicit task evidence; callback delivery never completes a task."""

        tenant = _tenant(tenant_id)
        plan = _id(plan_id, "plan_id")
        task_key = _id(task_id, "task_id")
        if status not in OFFBOARDING_TASK_STATES:
            raise ThirdPartyLifecycleValidationError("offboarding task status is unsupported")
        evidence = None if evidence_sha256 is None else _digest(evidence_sha256, "evidence_sha256")
        attestation = None if attestation_ref is None else _id(attestation_ref, "attestation_ref")
        if status == "completed" and (evidence is None or attestation is None):
            raise ThirdPartyLifecycleValidationError(
                "completed tasks require evidence and an attestation reference"
            )
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "set_offboarding_task",
            "plan_id": plan,
            "task_id": task_key,
            "status": status,
            "evidence_sha256": evidence,
            "attestation_ref": attestation,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with contextlib.closing(self._connect()) as connection, connection:
            self._begin(connection)
            request_sha, operation = self._operation(connection, tenant, idempotency_key, request)
            raw, stored_digest = self._get(
                connection,
                "offboarding_plans",
                tenant,
                "plan_id",
                plan,
                "offboarding plan",
            )
            if operation is not None:
                return self._plan_from(raw, stored_digest)
            current = self._plan_from(raw, stored_digest)
            if current.revision != expected:
                raise ThirdPartyLifecycleConflict(
                    f"offboarding plan revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            if current.state != "in_progress":
                raise ThirdPartyLifecycleConflict("offboarding plan is not in progress")
            tasks = [dict(item) for item in current.tasks]
            selected = next((item for item in tasks if item["task_id"] == task_key), None)
            if selected is None:
                raise ThirdPartyLifecycleNotFound("offboarding task was not found")
            lifecycle_raw, lifecycle_digest = self._get(
                connection,
                "lifecycles",
                tenant,
                "lifecycle_id",
                current.lifecycle_id,
                "lifecycle",
            )
            lifecycle = self._lifecycle_from(lifecycle_raw, lifecycle_digest)
            if actor not in {lifecycle.owner_ref, selected["assignee_ref"]}:
                raise ThirdPartyLifecyclePermissionDenied(
                    "authenticated principal is not the task assignee or lifecycle owner"
                )
            selected.update(
                {
                    "status": status,
                    "evidence_sha256": evidence,
                    "attestation_ref": attestation,
                    "updated_by": actor,
                    "updated_at": now,
                }
            )
            payload = dict(raw)
            payload.update(
                {
                    "tasks": tasks,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "offboarding_plans",
                tenant,
                "plan_id",
                plan,
                payload,
            )
            refreshed = self._refresh_plan_blockers(connection, tenant, plan)
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "offboarding_plan",
                plan,
            )
            self._audit(
                connection,
                tenant,
                "offboarding_task_set",
                plan,
                actor,
                {"task_id": task_key, "status": status},
                now,
            )
            return refreshed
