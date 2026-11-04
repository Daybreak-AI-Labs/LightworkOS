"""Local, provider-neutral technology-risk and compliance scoping authority.

The module stores opaque references, enumerated answers, evidence digests, and
deterministic rule outputs.  It contains no licensed framework text, arbitrary
rule evaluation, free-text evidence, external discovery, network client, legal
advice, certification logic, or live-provider acceptance claim.

The capability is closed unless both exact gates are explicitly enabled::

    [tech_risk_compliance]
    enable = true
    [tech_risk_compliance.scoping]
    enable = true
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constant_time import text_equals
from .file_lock import ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUDIT_SCHEMA = "lightwork.compliance-scoping-audit.v1"
EXPORT_SCHEMA = "lightwork.compliance-scope-export.v1"
LIVE_EXTERNAL_DISCOVERY = False
LIVE_ACCEPTANCE_VERIFIED = False

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_REF_RE = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z")
_EVIDENCE_RE = re.compile(r"evidence:[A-Za-z0-9][A-Za-z0-9_.:-]{0,114}\Z")
_KEY_REF_RE = re.compile(
    r"(?:env|vault|secret):[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}\Z"
)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_QUESTIONS = 256
_MAX_RULES = 512
_MAX_OPTIONS = 64
_MAX_CONDITIONS = 32
_MAX_CONTROLS = 256
_MAX_OVERLAPS = 256
_MAX_LIST = 1_000
_MIN_RETENTION_SECONDS = 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 3_600

SCOPING_DOMAINS = frozenset(
    {
        "organization",
        "industry",
        "jurisdiction",
        "data",
        "system",
        "vendor",
        "ai",
        "operational",
    }
)
ANSWER_TYPES = frozenset(
    {"boolean", "single_choice", "multi_choice", "integer", "opaque_ref"}
)
CONDITION_OPERATORS = frozenset(
    {"equals", "not_equals", "contains", "in", "greater_or_equal", "less_or_equal"}
)
RESPONSIBILITY_ROLES = frozenset(
    {"first_line", "second_line", "control_owner", "evidence_owner"}
)


class ComplianceScopingError(RuntimeError):
    """Base local scoping error."""


class ComplianceScopingConfigError(ComplianceScopingError):
    """The exact two-level feature gate is not enabled."""


class ComplianceScopingValidationError(ComplianceScopingError, ValueError):
    """Input is outside the closed, bounded scoping contract."""


class ComplianceScopingConflict(ComplianceScopingError):
    """A CAS, state, or idempotency precondition failed."""


class ComplianceScopingNotFound(ComplianceScopingError):
    """A tenant-scoped record is absent or deliberately undisclosed."""


class ComplianceScopingPermissionDenied(ComplianceScopingError):
    """Authentication or four-eyes separation is insufficient."""


class ComplianceScopingIntegrityError(ComplianceScopingError):
    """Persisted state, signature, or audit chain failed verification."""


def enabled() -> bool:
    """Return true only when both exact scoping gates are true."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    root = config.get("tech_risk_compliance")
    scoping = root.get("scoping") if isinstance(root, Mapping) else None
    return (
        isinstance(root, Mapping)
        and root.get("enable") is True
        and isinstance(scoping, Mapping)
        and scoping.get("enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise ComplianceScopingConfigError(
            "compliance scoping is disabled; explicitly enable "
            "tech_risk_compliance and tech_risk_compliance.scoping"
        )


def _runtime_principal() -> str | None:
    try:
        from .connections import current_principal

        return current_principal()
    except Exception:
        return None


def _default_signing_key_resolver(tenant_id: str, key_ref: str) -> bytes:
    del tenant_id
    if not key_ref.startswith("env:"):
        raise ComplianceScopingConfigError(
            "the default signing resolver accepts only env: references"
        )
    value = os.environ.get(key_ref.removeprefix("env:"))
    if value is None or len(value.encode("utf-8")) < 32:
        raise ComplianceScopingConfigError(
            "the compliance-scope signing key is absent or shorter than 32 bytes"
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
        raise ComplianceScopingValidationError(
            "scoping state must be finite canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise ComplianceScopingValidationError(
            "scoping state exceeds its canonical byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ComplianceScopingValidationError("tenant_id is invalid") from exc


def _id(
    value: object,
    label: str,
    pattern: re.Pattern[str] = _ID_RE,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ComplianceScopingValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ComplianceScopingValidationError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ComplianceScopingValidationError(
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
        raise ComplianceScopingValidationError(
            f"{label} must be a positive finite timestamp"
        )
    return float(value)


def _retained_until(value: object, now: float) -> float:
    retained = _timestamp(value, "retained_until")
    if not _MIN_RETENTION_SECONDS <= retained - now <= _MAX_RETENTION_SECONDS:
        raise ComplianceScopingValidationError(
            "retained_until must be between 60 seconds and 10 years from now"
        )
    return retained


def _closed_mapping(
    value: object,
    label: str,
    keys: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ComplianceScopingValidationError(
            f"{label} must contain exactly {','.join(sorted(keys))}"
        )
    return dict(value)


def _sequence(value: object, label: str, *, minimum: int, maximum: int) -> list[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ComplianceScopingValidationError(f"{label} must be a sequence")
    items = list(value)
    if not minimum <= len(items) <= maximum:
        raise ComplianceScopingValidationError(f"{label} has an invalid item count")
    return items


def _opaque_list(
    value: object,
    label: str,
    *,
    maximum: int,
) -> tuple[str, ...]:
    items = tuple(
        _id(item, f"{label} item")
        for item in _sequence(value, label, minimum=0, maximum=maximum)
    )
    if len(set(items)) != len(items):
        raise ComplianceScopingValidationError(f"{label} must not contain duplicates")
    return tuple(sorted(items))


def _validate_condition(
    value: object,
    *,
    known_questions: Mapping[str, Mapping[str, object]],
    label: str,
) -> dict[str, object]:
    condition = _closed_mapping(
        value,
        label,
        frozenset({"question_id", "operator", "value"}),
    )
    question_id = _id(condition["question_id"], f"{label}.question_id")
    if question_id not in known_questions:
        raise ComplianceScopingValidationError(
            f"{label} must reference an earlier known question"
        )
    operator = condition["operator"]
    if not isinstance(operator, str) or operator not in CONDITION_OPERATORS:
        raise ComplianceScopingValidationError(f"{label} operator is unsupported")
    answer_type = known_questions[question_id]["answer_type"]
    if operator == "contains" and answer_type != "multi_choice":
        raise ComplianceScopingValidationError(
            f"{label} contains is valid only for multi_choice"
        )
    if operator == "in" and answer_type not in {"single_choice", "opaque_ref"}:
        raise ComplianceScopingValidationError(
            f"{label} in is valid only for single_choice or opaque_ref"
        )
    if operator in {"greater_or_equal", "less_or_equal"} and answer_type != "integer":
        raise ComplianceScopingValidationError(
            f"{label} comparison is valid only for integer"
        )
    if operator == "contains":
        expected = _id(condition["value"], f"{label}.value")
        if expected not in known_questions[question_id]["options"]:
            raise ComplianceScopingValidationError(
                f"{label} contains value is not a declared option"
            )
    elif operator == "in":
        candidates = _sequence(
            condition["value"], f"{label}.value", minimum=1, maximum=_MAX_OPTIONS
        )
        expected = [
            _validate_answer(known_questions[question_id], candidate)
            for candidate in candidates
        ]
    else:
        expected = _validate_answer(known_questions[question_id], condition["value"])
    return {"question_id": question_id, "operator": operator, "value": expected}


def _validate_question(
    value: object,
    known_questions: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    question = _closed_mapping(
        value,
        "question",
        frozenset(
            {
                "question_id",
                "question_ref",
                "domain",
                "answer_type",
                "options",
                "required",
                "condition",
            }
        ),
    )
    question_id = _id(question["question_id"], "question_id")
    question_ref = _id(question["question_ref"], "question_ref", _REF_RE)
    domain = question["domain"]
    if not isinstance(domain, str) or domain not in SCOPING_DOMAINS:
        raise ComplianceScopingValidationError("question domain is unsupported")
    answer_type = question["answer_type"]
    if not isinstance(answer_type, str) or answer_type not in ANSWER_TYPES:
        raise ComplianceScopingValidationError("question answer_type is unsupported")
    options = _opaque_list(
        question["options"], "question options", maximum=_MAX_OPTIONS
    )
    if answer_type in {"single_choice", "multi_choice"} and not options:
        raise ComplianceScopingValidationError("choice questions require options")
    if answer_type not in {"single_choice", "multi_choice"} and options:
        raise ComplianceScopingValidationError(
            "non-choice questions cannot define options"
        )
    required = question["required"]
    if not isinstance(required, bool):
        raise ComplianceScopingValidationError("question required must be boolean")
    condition = question["condition"]
    if condition is not None:
        condition = _validate_condition(
            condition,
            known_questions=known_questions,
            label="question condition",
        )
    return {
        "question_id": question_id,
        "question_ref": question_ref,
        "domain": domain,
        "answer_type": answer_type,
        "options": list(options),
        "required": required,
        "condition": condition,
    }


def _validate_answer(question: Mapping[str, object], value: object) -> object:
    answer_type = question["answer_type"]
    options = set(question["options"])  # type: ignore[arg-type]
    if answer_type == "boolean":
        if not isinstance(value, bool):
            raise ComplianceScopingValidationError("boolean answer is required")
        return value
    if answer_type == "integer":
        return _integer(value, "integer answer", 0, 1_000_000_000)
    if answer_type == "single_choice":
        if not isinstance(value, str) or value not in options:
            raise ComplianceScopingValidationError("single_choice answer is unsupported")
        return value
    if answer_type == "multi_choice":
        selected = _opaque_list(value, "multi_choice answer", maximum=_MAX_OPTIONS)
        if not set(selected).issubset(options):
            raise ComplianceScopingValidationError("multi_choice answer is unsupported")
        return list(selected)
    return _id(value, "opaque_ref answer", _REF_RE)


def _evaluate_condition(condition: Mapping[str, object], answers: Mapping[str, object]) -> bool:
    question_id = condition["question_id"]
    if question_id not in answers:
        return False
    actual = answers[question_id]
    expected = condition["value"]
    operator = condition["operator"]
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "contains":
        return isinstance(actual, list) and expected in actual
    if operator == "in":
        return actual in expected if isinstance(expected, list) else actual == expected
    if operator == "greater_or_equal":
        return isinstance(actual, int) and isinstance(expected, int) and actual >= expected
    if operator == "less_or_equal":
        return isinstance(actual, int) and isinstance(expected, int) and actual <= expected
    raise ComplianceScopingIntegrityError("persisted condition operator is unsupported")


def _validate_rule(
    value: object,
    questions: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    rule = _closed_mapping(
        value,
        "applicability rule",
        frozenset(
            {
                "rule_id",
                "conditions",
                "framework_ref",
                "control_refs",
                "overlap_refs",
                "reason_code",
            }
        ),
    )
    conditions = tuple(
        _validate_condition(
            item,
            known_questions=questions,
            label="rule condition",
        )
        for item in _sequence(
            rule["conditions"],
            "rule conditions",
            minimum=0,
            maximum=_MAX_CONDITIONS,
        )
    )
    controls = _opaque_list(
        rule["control_refs"], "control_refs", maximum=_MAX_CONTROLS
    )
    if not controls:
        raise ComplianceScopingValidationError("rules require at least one control_ref")
    return {
        "rule_id": _id(rule["rule_id"], "rule_id"),
        "conditions": list(conditions),
        "framework_ref": _id(rule["framework_ref"], "framework_ref"),
        "control_refs": list(controls),
        "overlap_refs": list(
            _opaque_list(rule["overlap_refs"], "overlap_refs", maximum=_MAX_OVERLAPS)
        ),
        "reason_code": _id(rule["reason_code"], "reason_code"),
    }


@dataclass(frozen=True)
class ScopingQuestion:
    question_id: str
    question_ref: str
    domain: str
    answer_type: str
    options: tuple[str, ...]
    required: bool
    condition: Mapping[str, object] | None


def _display_names(value, questionnaire_id, questions, rules):
    """Optional short customer labels, bound to the immutable closed definition."""
    if value is None:
        return {}
    if not isinstance(value, Mapping) or len(value) > 4096:
        raise ComplianceScopingValidationError("questionnaire names must be a bounded object")
    allowed = {questionnaire_id}
    for question in questions:
        allowed.update((question["question_id"], question["question_ref"]))
        allowed.update(question["options"])
    for rule in rules:
        allowed.update((rule["rule_id"], rule["framework_ref"], rule["reason_code"]))
        allowed.update(rule["control_refs"])
        allowed.update(rule["overlap_refs"])
    names = {}
    for key, name in value.items():
        if (key not in allowed or not isinstance(name, str) or not name.strip()
                or name != name.strip() or len(name) > 120
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise ComplianceScopingValidationError("questionnaire names must be short labels for declared items")
        names[key] = name
    return names


def _studio_source(value):
    """Retained source provenance; callers still enforce actual source authority."""
    if value is None:
        return {}
    source = _closed_mapping(value, "studio source", frozenset({"studio_id", "form_id", "version",
        "pointer_sha256", "blueprint_sha256"}))
    return {"studio_id": _id(source["studio_id"], "studio_id"), "form_id": _id(source["form_id"], "form_id"),
            "version": _integer(source["version"], "studio version", 1, 2_147_483_647),
            "pointer_sha256": _digest(source["pointer_sha256"], "studio pointer"),
            "blueprint_sha256": _digest(source["blueprint_sha256"], "studio blueprint")}


def _creation_material(questionnaire_id, questions, rules, expected_latest_version,
                       actor, display_names=None, expected_latest_integrity=None, studio_source=None):
    questionnaire = _id(questionnaire_id, "questionnaire_id")
    expected = _integer(expected_latest_version, "expected_latest_version", 0, 1_000_000)
    known = {}
    validated_questions = []
    for item in _sequence(questions, "questions", minimum=len(SCOPING_DOMAINS), maximum=_MAX_QUESTIONS):
        question = _validate_question(item, known)
        if question["question_id"] in known:
            raise ComplianceScopingValidationError("question_id must be unique")
        known[str(question["question_id"])] = question
        validated_questions.append(question)
    if {str(item["domain"]) for item in validated_questions} != SCOPING_DOMAINS:
        raise ComplianceScopingValidationError("questionnaire must cover every required scoping domain")
    validated_rules = [_validate_rule(item, known)
                       for item in _sequence(rules, "rules", minimum=1, maximum=_MAX_RULES)]
    if len({item["rule_id"] for item in validated_rules}) != len(validated_rules):
        raise ComplianceScopingValidationError("rule_id must be unique")
    names = _display_names(display_names, questionnaire, validated_questions, validated_rules)
    request = {"action": "create_questionnaire_version", "questionnaire_id": questionnaire,
               "questions": validated_questions, "rules": validated_rules,
               "expected_latest_version": expected, "actor_ref": actor}
    if names:
        request["display_names"] = names
    source = _studio_source(studio_source)
    if source:
        request["studio_source"] = source
    if expected_latest_integrity is not None:
        request["expected_latest_integrity"] = _digest(expected_latest_integrity, "latest questionnaire")
        if expected == 0:
            raise ComplianceScopingValidationError("a new questionnaire has no previous revision")
    return request


@dataclass(frozen=True)
class QuestionnaireVersion:
    tenant_id: str
    questionnaire_id: str
    version: int
    questions: tuple[Mapping[str, object], ...]
    rules: tuple[Mapping[str, object], ...]
    definition_sha256: str
    status: str
    created_by: str
    reviewed_by: str | None
    revision: int
    created_at: float
    reviewed_at: float | None
    integrity_sha256: str
    display_names: Mapping[str, str] = field(default_factory=dict)
    studio_source: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class ScopingAssessment:
    tenant_id: str
    assessment_id: str
    questionnaire_id: str
    questionnaire_version: int
    questionnaire_sha256: str
    answers: Mapping[str, Mapping[str, object]]
    status: str
    retained_until: float
    created_by: str
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class ScopeResult:
    tenant_id: str
    scope_id: str
    assessment_id: str
    questionnaire_id: str
    questionnaire_version: int
    applicable_frameworks: tuple[str, ...]
    control_applicability: tuple[Mapping[str, object], ...]
    responsibility_assignments: Mapping[str, str]
    overlaps: tuple[Mapping[str, object], ...]
    crosswalks: tuple[Mapping[str, object], ...]
    reason_codes: tuple[str, ...]
    status: str
    retained_until: float
    computed_by: str
    approved_by: str | None
    finalized_by: str | None
    revision: int
    created_at: float
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True)
class SignedScopeExport:
    tenant_id: str
    export_id: str
    scope_id: str
    schema: str
    body: Mapping[str, object]
    body_sha256: str
    signing_key_ref: str
    signature_hmac_sha256: str
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


class ComplianceScopingStore:
    """Private SQLite authority for local compliance scoping decisions."""

    def __init__(
        self,
        path: str | Path,
        *,
        config_gate: Callable[[], None] = require_enabled,
        principal_resolver: Callable[[], str | None] = _runtime_principal,
        signing_key_resolver: Callable[[str, str], bytes] = _default_signing_key_resolver,
        clock: Callable[[], float] = time.time,
    ) -> None:
        config_gate()
        self.path = Path(path)
        self._principal_resolver = principal_resolver
        self._signing_key_resolver = signing_key_resolver
        self._clock = clock
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _actor(self) -> str:
        actor = self._principal_resolver()
        if actor is None or actor == "":
            raise ComplianceScopingPermissionDenied(
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
                CREATE TABLE IF NOT EXISTS scope_questionnaires(
                    tenant_id TEXT NOT NULL,questionnaire_id TEXT NOT NULL,
                    version INTEGER NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,questionnaire_id,version)
                );
                CREATE TABLE IF NOT EXISTS scope_publications(
                    tenant_id TEXT NOT NULL,questionnaire_id TEXT NOT NULL,
                    version INTEGER NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,questionnaire_id,version),
                    FOREIGN KEY(tenant_id,questionnaire_id,version)
                        REFERENCES scope_questionnaires(tenant_id,questionnaire_id,version)
                );
                CREATE TABLE IF NOT EXISTS scope_assessments(
                    tenant_id TEXT NOT NULL,assessment_id TEXT NOT NULL,
                    status TEXT NOT NULL,retained_until REAL NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,assessment_id)
                );
                CREATE INDEX IF NOT EXISTS scope_assessment_retention
                    ON scope_assessments(tenant_id,status,retained_until);
                CREATE TABLE IF NOT EXISTS scope_results(
                    tenant_id TEXT NOT NULL,scope_id TEXT NOT NULL,
                    assessment_id TEXT NOT NULL,status TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,scope_id),
                    UNIQUE(tenant_id,assessment_id),
                    FOREIGN KEY(tenant_id,assessment_id)
                        REFERENCES scope_assessments(tenant_id,assessment_id)
                            ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS scope_result_retention
                    ON scope_results(tenant_id,status,retained_until);
                CREATE TABLE IF NOT EXISTS scope_exports(
                    tenant_id TEXT NOT NULL,export_id TEXT NOT NULL,scope_id TEXT NOT NULL,
                    retained_until REAL NOT NULL,payload_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,export_id)
                );
                CREATE INDEX IF NOT EXISTS scope_export_retention
                    ON scope_exports(tenant_id,retained_until);
                CREATE TABLE IF NOT EXISTS scope_operations(
                    tenant_id TEXT NOT NULL,operation_sha256 TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,result_kind TEXT NOT NULL,
                    result_id TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,operation_sha256)
                );
                CREATE TABLE IF NOT EXISTS scope_audit_events(
                    tenant_id TEXT NOT NULL,sequence INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,integrity_sha256 TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,sequence)
                );
                CREATE TRIGGER IF NOT EXISTS scope_questionnaire_no_update
                    BEFORE UPDATE ON scope_questionnaires
                    BEGIN SELECT RAISE(ABORT, 'immutable scoping questionnaire'); END;
                CREATE TRIGGER IF NOT EXISTS scope_questionnaire_no_delete
                    BEFORE DELETE ON scope_questionnaires
                    BEGIN SELECT RAISE(ABORT, 'immutable scoping questionnaire'); END;
                CREATE TRIGGER IF NOT EXISTS scope_audit_no_update
                    BEFORE UPDATE ON scope_audit_events
                    BEGIN SELECT RAISE(ABORT, 'immutable scoping audit'); END;
                CREATE TRIGGER IF NOT EXISTS scope_audit_no_delete
                    BEFORE DELETE ON scope_audit_events
                    BEGIN SELECT RAISE(ABORT, 'immutable scoping audit'); END;
                INSERT OR IGNORE INTO metadata(key,value) VALUES('schema_version','1');
                COMMIT;
                """
            )
            version = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            if version is None or version["value"] != str(SCHEMA_VERSION):
                raise ComplianceScopingIntegrityError(
                    "compliance scoping database schema is unsupported"
                )
        ensure_private_file(self.path)

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    @staticmethod
    def _payload(row: sqlite3.Row, label: str, tenant_id: str) -> dict[str, Any]:
        try:
            payload = json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise ComplianceScopingIntegrityError(
                f"persisted {label} is not canonical JSON"
            ) from exc
        if (
            not isinstance(payload, dict)
            or _sha256(payload) != row["integrity_sha256"]
            or row["tenant_id"] != tenant_id
            or payload.get("tenant_id") != tenant_id
        ):
            raise ComplianceScopingIntegrityError(
                f"persisted {label} failed tenant or content integrity"
            )
        return payload

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        table: str,
        columns: tuple[str, ...],
        indexes: tuple[object, ...],
        payload: Mapping[str, object],
    ) -> str:
        digest = _sha256(dict(payload))
        names = ",".join(columns + ("payload_json", "integrity_sha256"))
        placeholders = ",".join("?" for _ in range(len(columns) + 2))
        connection.execute(
            f"INSERT INTO {table}({names}) VALUES({placeholders})",  # noqa: S608
            indexes + (_canonical(dict(payload)).decode("ascii"), digest),
        )
        return digest

    @staticmethod
    def _write(
        connection: sqlite3.Connection,
        table: str,
        tenant_id: str,
        id_column: str,
        object_id: str,
        payload: Mapping[str, object],
        *,
        version: int | None = None,
        index_updates: Mapping[str, object] | None = None,
    ) -> str:
        digest = _sha256(dict(payload))
        assignments = ["payload_json=?", "integrity_sha256=?"]
        values: list[object] = [_canonical(dict(payload)).decode("ascii"), digest]
        for column, value in (index_updates or {}).items():
            assignments.append(f"{column}=?")
            values.append(value)
        where = f"tenant_id=? AND {id_column}=?"
        values.extend((tenant_id, object_id))
        if version is not None:
            where += " AND version=?"
            values.append(version)
        result = connection.execute(
            f"UPDATE {table} SET {','.join(assignments)} WHERE {where}",  # noqa: S608
            tuple(values),
        )
        if result.rowcount != 1:
            raise ComplianceScopingNotFound(f"{table} record was not found")
        return digest

    @staticmethod
    def _get(
        connection: sqlite3.Connection,
        table: str,
        tenant_id: str,
        id_column: str,
        object_id: str,
        label: str,
        *,
        version: int | None = None,
    ) -> tuple[dict[str, Any], str]:
        where = f"tenant_id=? AND {id_column}=?"
        values: list[object] = [tenant_id, object_id]
        if version is not None:
            where += " AND version=?"
            values.append(version)
        row = connection.execute(
            f"SELECT * FROM {table} WHERE {where}",  # noqa: S608
            tuple(values),
        ).fetchone()
        if row is None:
            raise ComplianceScopingNotFound(f"{label} was not found")
        return ComplianceScopingStore._payload(row, label, tenant_id), row[
            "integrity_sha256"
        ]

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request: Mapping[str, object],
    ) -> tuple[str, sqlite3.Row | None]:
        key = _id(idempotency_key, "idempotency_key", _OP_RE)
        operation_sha = hashlib.sha256(key.encode()).hexdigest()
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM scope_operations WHERE tenant_id=? AND operation_sha256=?",
            (tenant_id, operation_sha),
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
                raise ComplianceScopingIntegrityError(
                    "persisted idempotency binding failed integrity verification"
                )
            if row["request_sha256"] != request_sha:
                raise ComplianceScopingConflict(
                    "idempotency key is bound to different canonical content"
                )
        return request_sha, row

    @staticmethod
    def _record_operation(
        connection: sqlite3.Connection,
        tenant_id: str,
        idempotency_key: str,
        request_sha: str,
        result_kind: str,
        result_id: str,
    ) -> None:
        binding = {
            "tenant_id": tenant_id,
            "operation_sha256": hashlib.sha256(idempotency_key.encode()).hexdigest(),
            "request_sha256": request_sha,
            "result_kind": _id(result_kind, "result_kind"),
            "result_id": _id(result_id, "result_id"),
        }
        connection.execute(
            "INSERT INTO scope_operations VALUES(?,?,?,?,?,?)",
            (
                tenant_id,
                binding["operation_sha256"],
                request_sha,
                binding["result_kind"],
                binding["result_id"],
                _sha256(binding),
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: str,
        action: str,
        subject: str,
        actor: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        previous = connection.execute(
            "SELECT sequence,integrity_sha256 FROM scope_audit_events "
            "WHERE tenant_id=? ORDER BY sequence DESC LIMIT 1",
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
            "actor_ref": _id(actor, "authenticated principal"),
            "details": dict(details),
            "occurred_at": now,
            "previous_sha256": previous_sha,
        }
        digest = _sha256(payload)
        connection.execute(
            "INSERT INTO scope_audit_events VALUES(?,?,?,?)",
            (tenant_id, sequence, _canonical(payload).decode("ascii"), digest),
        )

    @staticmethod
    def _questionnaire(
        definition: Mapping[str, Any],
        publication: Mapping[str, Any],
        definition_digest: str,
        publication_digest: str,
    ) -> QuestionnaireVersion:
        return QuestionnaireVersion(
            studio_source=_studio_source(definition.get("studio_source")),
            display_names=_display_names(definition.get("display_names"), definition["questionnaire_id"],
                                         definition["questions"], definition["rules"]),
            tenant_id=definition["tenant_id"],
            questionnaire_id=definition["questionnaire_id"],
            version=definition["version"],
            questions=tuple(dict(item) for item in definition["questions"]),
            rules=tuple(dict(item) for item in definition["rules"]),
            definition_sha256=definition_digest,
            status=publication["status"],
            created_by=definition["created_by"],
            reviewed_by=publication["reviewed_by"],
            revision=publication["revision"],
            created_at=definition["created_at"],
            reviewed_at=publication["reviewed_at"],
            integrity_sha256=_sha256(
                {
                    "definition_sha256": definition_digest,
                    "publication_sha256": publication_digest,
                }
            ),
        )

    @staticmethod
    def _assessment(
        payload: Mapping[str, Any], digest: str
    ) -> ScopingAssessment:
        values = dict(payload)
        values["answers"] = {
            key: dict(answer) for key, answer in values["answers"].items()
        }
        return ScopingAssessment(**values, integrity_sha256=digest)

    @staticmethod
    def _scope(payload: Mapping[str, Any], digest: str) -> ScopeResult:
        values = dict(payload)
        values["applicable_frameworks"] = tuple(values["applicable_frameworks"])
        values["control_applicability"] = tuple(
            dict(item) for item in values["control_applicability"]
        )
        values["responsibility_assignments"] = dict(
            values["responsibility_assignments"]
        )
        values["overlaps"] = tuple(dict(item) for item in values["overlaps"])
        values["crosswalks"] = tuple(dict(item) for item in values["crosswalks"])
        values["reason_codes"] = tuple(values["reason_codes"])
        return ScopeResult(**values, integrity_sha256=digest)

    @staticmethod
    def _export(payload: Mapping[str, Any], digest: str) -> SignedScopeExport:
        values = dict(payload)
        values["body"] = dict(values["body"])
        return SignedScopeExport(**values, integrity_sha256=digest)

    def _get_questionnaire(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        questionnaire_id: str,
        version: int,
    ) -> QuestionnaireVersion:
        definition, definition_digest = self._get(
            connection,
            "scope_questionnaires",
            tenant,
            "questionnaire_id",
            questionnaire_id,
            "questionnaire definition",
            version=version,
        )
        publication, publication_digest = self._get(
            connection,
            "scope_publications",
            tenant,
            "questionnaire_id",
            questionnaire_id,
            "questionnaire publication",
            version=version,
        )
        if publication["definition_sha256"] != definition_digest:
            raise ComplianceScopingIntegrityError(
                "questionnaire publication is not bound to its immutable definition"
            )
        return self._questionnaire(
            definition, publication, definition_digest, publication_digest
        )

    def create_questionnaire_version(
        self,
        tenant_id: str,
        questionnaire_id: str,
        *,
        questions: Sequence[Mapping[str, object]],
        rules: Sequence[Mapping[str, object]],
        expected_latest_version: int,
        idempotency_key: str,
        display_names: Mapping[str, str] | None = None,
        expected_latest_integrity: str | None = None,
        studio_source: Mapping[str, object] | None = None,
        effect_guard: Callable[[], object] | None = None,
    ) -> QuestionnaireVersion:
        """Append an immutable questionnaire definition pending independent review."""

        tenant = _tenant(tenant_id)
        actor = self._actor()
        request = _creation_material(questionnaire_id, questions, rules, expected_latest_version,
                                     actor, display_names, expected_latest_integrity, studio_source)
        questionnaire = request["questionnaire_id"]
        expected = request["expected_latest_version"]
        validated_questions, validated_rules = request["questions"], request["rules"]
        now = _timestamp(self._clock(), "current time")
        version = expected + 1
        with self._connect() as connection:
            self._begin(connection)
            if effect_guard is not None:
                effect_guard()
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                return self._get_questionnaire(
                    connection, tenant, questionnaire, version
                )
            latest_row = connection.execute(
                "SELECT MAX(version) AS latest FROM scope_questionnaires "
                "WHERE tenant_id=? AND questionnaire_id=?",
                (tenant, questionnaire),
            ).fetchone()
            latest = 0 if latest_row["latest"] is None else int(latest_row["latest"])
            if latest != expected:
                raise ComplianceScopingConflict(
                    f"latest questionnaire CAS failed: expected {expected}, found {latest}"
                )
            if expected_latest_integrity is not None:
                current = self._get_questionnaire(connection, tenant, questionnaire, latest)
                if current.integrity_sha256 != expected_latest_integrity:
                    raise ComplianceScopingConflict("the reviewed questionnaire changed before saving")
            definition = {
                "tenant_id": tenant,
                "questionnaire_id": questionnaire,
                "version": version,
                "questions": validated_questions,
                "rules": list(validated_rules),
                "created_by": actor,
                "created_at": now,
            }
            if request.get("display_names"):
                definition["display_names"] = request["display_names"]
            if request.get("studio_source"):
                definition["studio_source"] = request["studio_source"]
            definition_digest = self._insert(
                connection,
                "scope_questionnaires",
                ("tenant_id", "questionnaire_id", "version"),
                (tenant, questionnaire, version),
                definition,
            )
            publication = {
                "tenant_id": tenant,
                "questionnaire_id": questionnaire,
                "version": version,
                "definition_sha256": definition_digest,
                "status": "pending_review",
                "reviewed_by": None,
                "revision": 1,
                "reviewed_at": None,
            }
            publication_digest = self._insert(
                connection,
                "scope_publications",
                ("tenant_id", "questionnaire_id", "version"),
                (tenant, questionnaire, version),
                publication,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "questionnaire",
                f"{questionnaire}:{version}",
            )
            self._audit(
                connection,
                tenant,
                "questionnaire_version_created",
                f"{questionnaire}:{version}",
                actor,
                {"version": version, "question_count": len(validated_questions),
                 **({"studio_source_sha256": _sha256(request["studio_source"])} if request.get("studio_source") else {})},
                now,
            )
            if effect_guard is not None:
                effect_guard()
            return self._questionnaire(
                definition, publication, definition_digest, publication_digest
            )

    def latest_questionnaire(self, tenant_id: str, questionnaire_id: str) -> QuestionnaireVersion | None:
        """Read the exact latest source; list pagination is not a source guard."""
        tenant, questionnaire = _tenant(tenant_id), _id(questionnaire_id, "questionnaire_id")
        self._actor()
        with self._connect() as connection:
            row = connection.execute("SELECT MAX(version) AS latest FROM scope_questionnaires "
                                     "WHERE tenant_id=? AND questionnaire_id=?", (tenant, questionnaire)).fetchone()
            return None if row["latest"] is None else self._get_questionnaire(connection, tenant, questionnaire, int(row["latest"]))

    def questionnaire_creation_receipt(self, tenant_id: str, questionnaire_id: str, *,
                                       questions, rules, expected_latest_version: int,
                                       idempotency_key: str, display_names=None,
                                       expected_latest_integrity=None, studio_source=None) -> QuestionnaireVersion | None:
        """Read only the original actor's atomically accepted operation, never replay it."""
        tenant = _tenant(tenant_id)
        request = _creation_material(questionnaire_id, questions, rules, expected_latest_version,
                                     self._actor(), display_names, expected_latest_integrity, studio_source)
        with self._connect() as connection:
            _digest_value, operation = self._operation(connection, tenant, idempotency_key, request)
            if operation is None:
                return None
            expected_id = f"{questionnaire_id}:{expected_latest_version + 1}"
            if operation["result_kind"] != "questionnaire" or operation["result_id"] != expected_id:
                raise ComplianceScopingIntegrityError("questionnaire receipt result binding failed")
            return self._get_questionnaire(connection, tenant, questionnaire_id, expected_latest_version + 1)

    def publish_questionnaire(
        self,
        tenant_id: str,
        questionnaire_id: str,
        version: int,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> QuestionnaireVersion:
        """Independently review and publish an immutable questionnaire version."""

        tenant = _tenant(tenant_id)
        questionnaire = _id(questionnaire_id, "questionnaire_id")
        questionnaire_version = _integer(version, "version", 1, 1_000_000)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "publish_questionnaire",
            "questionnaire_id": questionnaire,
            "version": questionnaire_version,
            "expected_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            current = self._get_questionnaire(
                connection, tenant, questionnaire, questionnaire_version
            )
            if operation is not None:
                return current
            if current.revision != expected:
                raise ComplianceScopingConflict(
                    f"publication revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            if current.status != "pending_review":
                raise ComplianceScopingConflict("questionnaire is not pending review")
            if current.created_by == actor:
                raise ComplianceScopingPermissionDenied(
                    "questionnaire publication requires a reviewer distinct from its creator"
                )
            publication, _digest_value = self._get(
                connection,
                "scope_publications",
                tenant,
                "questionnaire_id",
                questionnaire,
                "questionnaire publication",
                version=questionnaire_version,
            )
            payload = dict(publication)
            payload.update(
                {
                    "status": "published",
                    "reviewed_by": actor,
                    "revision": current.revision + 1,
                    "reviewed_at": now,
                }
            )
            self._write(
                connection,
                "scope_publications",
                tenant,
                "questionnaire_id",
                questionnaire,
                payload,
                version=questionnaire_version,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "questionnaire",
                f"{questionnaire}:{questionnaire_version}",
            )
            self._audit(
                connection,
                tenant,
                "questionnaire_published",
                f"{questionnaire}:{questionnaire_version}",
                actor,
                {"creator_ref": current.created_by},
                now,
            )
            return self._get_questionnaire(
                connection, tenant, questionnaire, questionnaire_version
            )

    def get_questionnaire(
        self, tenant_id: str, questionnaire_id: str, version: int
    ) -> QuestionnaireVersion:
        tenant = _tenant(tenant_id)
        questionnaire = _id(questionnaire_id, "questionnaire_id")
        questionnaire_version = _integer(version, "version", 1, 1_000_000)
        self._actor()
        with self._connect() as connection:
            return self._get_questionnaire(
                connection, tenant, questionnaire, questionnaire_version
            )

    def create_assessment(
        self,
        tenant_id: str,
        assessment_id: str,
        *,
        questionnaire_id: str,
        questionnaire_version: int,
        retained_until: float,
        idempotency_key: str,
    ) -> ScopingAssessment:
        """Create an assessment pinned to one published immutable definition."""

        tenant = _tenant(tenant_id)
        assessment = _id(assessment_id, "assessment_id")
        questionnaire = _id(questionnaire_id, "questionnaire_id")
        version = _integer(
            questionnaire_version, "questionnaire_version", 1, 1_000_000
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        request = {
            "action": "create_assessment",
            "assessment_id": assessment,
            "questionnaire_id": questionnaire,
            "questionnaire_version": version,
            "retained_until": retained,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                raw, digest_value = self._get(
                    connection,
                    "scope_assessments",
                    tenant,
                    "assessment_id",
                    assessment,
                    "assessment",
                )
                return self._assessment(raw, digest_value)
            selected = self._get_questionnaire(
                connection, tenant, questionnaire, version
            )
            if selected.status != "published":
                raise ComplianceScopingConflict(
                    "assessment requires a published questionnaire version"
                )
            payload = {
                "tenant_id": tenant,
                "assessment_id": assessment,
                "questionnaire_id": questionnaire,
                "questionnaire_version": version,
                "questionnaire_sha256": selected.definition_sha256,
                "answers": {},
                "status": "open",
                "retained_until": retained,
                "created_by": actor,
                "revision": 1,
                "created_at": now,
                "updated_at": now,
            }
            digest_value = self._insert(
                connection,
                "scope_assessments",
                ("tenant_id", "assessment_id", "status", "retained_until"),
                (tenant, assessment, "open", retained),
                payload,
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
                {"questionnaire_id": questionnaire, "version": version},
                now,
            )
            return self._assessment(payload, digest_value)

    def get_assessment(
        self, tenant_id: str, assessment_id: str
    ) -> ScopingAssessment:
        tenant = _tenant(tenant_id)
        assessment = _id(assessment_id, "assessment_id")
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "scope_assessments",
                tenant,
                "assessment_id",
                assessment,
                "assessment",
            )
            return self._assessment(raw, digest_value)

    def _questions_for_assessment(
        self,
        connection: sqlite3.Connection,
        tenant: str,
        assessment: ScopingAssessment,
    ) -> tuple[dict[str, object], ...]:
        questionnaire = self._get_questionnaire(
            connection,
            tenant,
            assessment.questionnaire_id,
            assessment.questionnaire_version,
        )
        if questionnaire.definition_sha256 != assessment.questionnaire_sha256:
            raise ComplianceScopingIntegrityError(
                "assessment questionnaire pin failed integrity verification"
            )
        return tuple(dict(item) for item in questionnaire.questions)

    @staticmethod
    def _answer_values(assessment: ScopingAssessment) -> dict[str, object]:
        return {
            question_id: answer["value"]
            for question_id, answer in assessment.answers.items()
        }

    def _required_questions(
        self,
        questions: Sequence[Mapping[str, object]],
        assessment: ScopingAssessment,
    ) -> tuple[ScopingQuestion, ...]:
        answers = self._answer_values(assessment)
        required: list[ScopingQuestion] = []
        for raw in questions:
            condition = raw["condition"]
            active = condition is None or _evaluate_condition(condition, answers)
            if raw["required"] and active and raw["question_id"] not in answers:
                required.append(
                    ScopingQuestion(
                        question_id=str(raw["question_id"]),
                        question_ref=str(raw["question_ref"]),
                        domain=str(raw["domain"]),
                        answer_type=str(raw["answer_type"]),
                        options=tuple(raw["options"]),  # type: ignore[arg-type]
                        required=True,
                        condition=(
                            None if condition is None else dict(condition)  # type: ignore[arg-type]
                        ),
                    )
                )
        return tuple(required)

    def next_required_questions(
        self,
        tenant_id: str,
        assessment_id: str,
        *,
        limit: int = 100,
    ) -> tuple[ScopingQuestion, ...]:
        """Return active unanswered required questions in immutable definition order."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        bounded_limit = _integer(limit, "limit", 1, _MAX_LIST)
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "scope_assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            assessment = self._assessment(raw, digest_value)
            questions = self._questions_for_assessment(connection, tenant, assessment)
            return self._required_questions(questions, assessment)[:bounded_limit]

    def record_response(
        self,
        tenant_id: str,
        assessment_id: str,
        question_id: str,
        *,
        value: object,
        evidence_sha256: str,
        evidence_ref: str,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopingAssessment:
        """CAS-record an enumerated/opaque answer plus evidence digest and ref."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        question_key = _id(question_id, "question_id")
        evidence = _digest(evidence_sha256, "evidence_sha256")
        reference = _id(evidence_ref, "evidence_ref", _EVIDENCE_RE)
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        with self._connect() as connection:
            self._begin(connection)
            raw, stored_digest = self._get(
                connection,
                "scope_assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            current = self._assessment(raw, stored_digest)
            questions = self._questions_for_assessment(connection, tenant, current)
            question = next(
                (item for item in questions if item["question_id"] == question_key), None
            )
            if question is None:
                raise ComplianceScopingNotFound("question was not found")
            validated_value = _validate_answer(question, value)
            request = {
                "action": "record_response",
                "assessment_id": assessment_key,
                "question_id": question_key,
                "value": validated_value,
                "evidence_sha256": evidence,
                "evidence_ref": reference,
                "expected_revision": expected,
                "actor_ref": actor,
            }
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                return current
            if current.revision != expected:
                raise ComplianceScopingConflict(
                    f"assessment revision CAS failed: expected {expected}, "
                    f"found {current.revision}"
                )
            if current.status != "open":
                raise ComplianceScopingConflict("assessment is not open")
            condition = question["condition"]
            if condition is not None and not _evaluate_condition(
                condition, self._answer_values(current)
            ):
                raise ComplianceScopingConflict("conditional question is not active")
            answers = {key: dict(answer) for key, answer in current.answers.items()}
            answers[question_key] = {
                "value": validated_value,
                "evidence_sha256": evidence,
                "evidence_ref": reference,
                "recorded_by": actor,
                "recorded_at": now,
            }
            payload = dict(raw)
            payload.update(
                {
                    "answers": answers,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write(
                connection,
                "scope_assessments",
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
                {"question_id": question_key, "revision": current.revision + 1},
                now,
            )
            return self._assessment(payload, digest_value)

    @staticmethod
    def _responsibilities(value: object) -> dict[str, str]:
        mapping = _closed_mapping(
            value, "responsibility_assignments", RESPONSIBILITY_ROLES
        )
        validated = {
            role: _id(mapping[role], f"{role} assignment", _REF_RE)
            for role in sorted(RESPONSIBILITY_ROLES)
        }
        if validated["first_line"] == validated["second_line"]:
            raise ComplianceScopingValidationError(
                "first_line and second_line assignments must be distinct"
            )
        return validated

    def compute_scope(
        self,
        tenant_id: str,
        assessment_id: str,
        scope_id: str,
        *,
        responsibility_assignments: Mapping[str, str],
        expected_assessment_revision: int,
        idempotency_key: str,
    ) -> ScopeResult:
        """Evaluate closed rules deterministically and create a draft scope."""

        tenant = _tenant(tenant_id)
        assessment_key = _id(assessment_id, "assessment_id")
        scope_key = _id(scope_id, "scope_id")
        responsibilities = self._responsibilities(responsibility_assignments)
        expected = _integer(
            expected_assessment_revision,
            "expected_assessment_revision",
            1,
            1_000_000,
        )
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        request = {
            "action": "compute_scope",
            "assessment_id": assessment_key,
            "scope_id": scope_key,
            "responsibility_assignments": responsibilities,
            "expected_assessment_revision": expected,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                raw, digest_value = self._get(
                    connection,
                    "scope_results",
                    tenant,
                    "scope_id",
                    scope_key,
                    "scope result",
                )
                return self._scope(raw, digest_value)
            assessment_raw, assessment_digest = self._get(
                connection,
                "scope_assessments",
                tenant,
                "assessment_id",
                assessment_key,
                "assessment",
            )
            assessment = self._assessment(assessment_raw, assessment_digest)
            if assessment.revision != expected:
                raise ComplianceScopingConflict(
                    f"assessment revision CAS failed: expected {expected}, "
                    f"found {assessment.revision}"
                )
            if assessment.status != "open":
                raise ComplianceScopingConflict("assessment is not open")
            questions = self._questions_for_assessment(connection, tenant, assessment)
            if self._required_questions(questions, assessment):
                raise ComplianceScopingConflict(
                    "all active required questions must be answered"
                )
            questionnaire = self._get_questionnaire(
                connection,
                tenant,
                assessment.questionnaire_id,
                assessment.questionnaire_version,
            )
            answers = self._answer_values(assessment)
            matching_rules = [
                dict(rule)
                for rule in questionnaire.rules
                if all(
                    _evaluate_condition(condition, answers)
                    for condition in rule["conditions"]  # type: ignore[union-attr]
                )
            ]
            frameworks = sorted({str(rule["framework_ref"]) for rule in matching_rules})
            control_reasons: dict[tuple[str, str], set[str]] = {}
            overlaps: list[dict[str, object]] = []
            for rule in matching_rules:
                framework = str(rule["framework_ref"])
                reason = str(rule["reason_code"])
                for control in rule["control_refs"]:  # type: ignore[union-attr]
                    key = (framework, str(control))
                    control_reasons.setdefault(key, set()).add(reason)
                    for overlap in rule["overlap_refs"]:  # type: ignore[union-attr]
                        overlaps.append(
                            {
                                "framework_ref": framework,
                                "control_ref": str(control),
                                "overlap_ref": str(overlap),
                                "reason_code": reason,
                            }
                        )
            controls = [
                {
                    "framework_ref": framework,
                    "control_ref": control,
                    "reason_codes": sorted(reasons),
                    "responsibilities": responsibilities,
                }
                for (framework, control), reasons in sorted(control_reasons.items())
            ]
            overlaps = sorted(
                overlaps,
                key=lambda item: (
                    item["framework_ref"],
                    item["control_ref"],
                    item["overlap_ref"],
                    item["reason_code"],
                ),
            )
            reason_codes = sorted(
                {str(rule["reason_code"]) for rule in matching_rules}
                or {"no_rule_matched"}
            )
            scope_payload = {
                "tenant_id": tenant,
                "scope_id": scope_key,
                "assessment_id": assessment_key,
                "questionnaire_id": assessment.questionnaire_id,
                "questionnaire_version": assessment.questionnaire_version,
                "applicable_frameworks": frameworks,
                "control_applicability": controls,
                "responsibility_assignments": responsibilities,
                "overlaps": overlaps,
                "crosswalks": overlaps,
                "reason_codes": reason_codes,
                "status": "draft",
                "retained_until": assessment.retained_until,
                "computed_by": actor,
                "approved_by": None,
                "finalized_by": None,
                "revision": 1,
                "created_at": now,
                "updated_at": now,
            }
            scope_digest = self._insert(
                connection,
                "scope_results",
                ("tenant_id", "scope_id", "assessment_id", "status", "retained_until"),
                (
                    tenant,
                    scope_key,
                    assessment_key,
                    "draft",
                    assessment.retained_until,
                ),
                scope_payload,
            )
            assessment_payload = dict(assessment_raw)
            assessment_payload.update(
                {
                    "status": "scoped",
                    "revision": assessment.revision + 1,
                    "updated_at": now,
                }
            )
            self._write(
                connection,
                "scope_assessments",
                tenant,
                "assessment_id",
                assessment_key,
                assessment_payload,
                index_updates={"status": "scoped"},
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "scope",
                scope_key,
            )
            self._audit(
                connection,
                tenant,
                "scope_computed",
                scope_key,
                actor,
                {
                    "framework_count": len(frameworks),
                    "control_count": len(controls),
                    "rule_count": len(matching_rules),
                },
                now,
            )
            return self._scope(scope_payload, scope_digest)

    def _transition_scope(
        self,
        tenant: str,
        scope_key: str,
        *,
        action: str,
        expected_state: str,
        next_state: str,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
        now: float,
    ) -> ScopeResult:
        request = {
            "action": action,
            "scope_id": scope_key,
            "expected_revision": expected_revision,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            raw, stored_digest = self._get(
                connection,
                "scope_results",
                tenant,
                "scope_id",
                scope_key,
                "scope result",
            )
            if operation is not None:
                return self._scope(raw, stored_digest)
            current = self._scope(raw, stored_digest)
            if current.revision != expected_revision:
                raise ComplianceScopingConflict(
                    f"scope revision CAS failed: expected {expected_revision}, "
                    f"found {current.revision}"
                )
            if current.status != expected_state:
                raise ComplianceScopingConflict(
                    f"scope must be {expected_state} before {next_state}"
                )
            payload = dict(raw)
            if next_state == "approved":
                if actor == current.computed_by:
                    raise ComplianceScopingPermissionDenied(
                        "scope approval requires a principal distinct from its computer"
                    )
                payload["approved_by"] = actor
            else:
                if actor != current.computed_by:
                    raise ComplianceScopingPermissionDenied(
                        "only the scope computer can finalize an independently approved scope"
                    )
                if current.approved_by is None or current.approved_by == actor:
                    raise ComplianceScopingPermissionDenied(
                        "independent scope approval is required before finalization"
                    )
                payload["finalized_by"] = actor
            payload.update(
                {
                    "status": next_state,
                    "revision": current.revision + 1,
                    "updated_at": now,
                }
            )
            digest_value = self._write(
                connection,
                "scope_results",
                tenant,
                "scope_id",
                scope_key,
                payload,
                index_updates={"status": next_state},
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "scope",
                scope_key,
            )
            self._audit(
                connection,
                tenant,
                action,
                scope_key,
                actor,
                {"revision": current.revision + 1},
                now,
            )
            return self._scope(payload, digest_value)

    def approve_scope(
        self,
        tenant_id: str,
        scope_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeResult:
        tenant = _tenant(tenant_id)
        scope_key = _id(scope_id, "scope_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        return self._transition_scope(
            tenant,
            scope_key,
            action="scope_approved",
            expected_state="draft",
            next_state="approved",
            expected_revision=expected,
            idempotency_key=idempotency_key,
            actor=self._actor(),
            now=_timestamp(self._clock(), "current time"),
        )

    def finalize_scope(
        self,
        tenant_id: str,
        scope_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ScopeResult:
        tenant = _tenant(tenant_id)
        scope_key = _id(scope_id, "scope_id")
        expected = _integer(expected_revision, "expected_revision", 1, 1_000_000)
        return self._transition_scope(
            tenant,
            scope_key,
            action="scope_finalized",
            expected_state="approved",
            next_state="finalized",
            expected_revision=expected,
            idempotency_key=idempotency_key,
            actor=self._actor(),
            now=_timestamp(self._clock(), "current time"),
        )

    def get_scope(self, tenant_id: str, scope_id: str) -> ScopeResult:
        tenant = _tenant(tenant_id)
        scope_key = _id(scope_id, "scope_id")
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "scope_results",
                tenant,
                "scope_id",
                scope_key,
                "scope result",
            )
            return self._scope(raw, digest_value)

    def export_scope(
        self,
        tenant_id: str,
        scope_id: str,
        export_id: str,
        *,
        signing_key_ref: str,
        retained_until: float,
        idempotency_key: str,
    ) -> SignedScopeExport:
        """Create an HMAC-signed, integrity-bound local finalized-scope export."""

        tenant = _tenant(tenant_id)
        scope_key = _id(scope_id, "scope_id")
        export_key = _id(export_id, "export_id")
        key_ref = _id(signing_key_ref, "signing_key_ref", _KEY_REF_RE)
        actor = self._actor()
        now = _timestamp(self._clock(), "current time")
        retained = _retained_until(retained_until, now)
        request = {
            "action": "export_scope",
            "scope_id": scope_key,
            "export_id": export_key,
            "signing_key_ref": key_ref,
            "retained_until": retained,
            "actor_ref": actor,
        }
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                raw, digest_value = self._get(
                    connection,
                    "scope_exports",
                    tenant,
                    "export_id",
                    export_key,
                    "scope export",
                )
                return self._export(raw, digest_value)
            scope_raw, scope_digest = self._get(
                connection,
                "scope_results",
                tenant,
                "scope_id",
                scope_key,
                "scope result",
            )
            scope = self._scope(scope_raw, scope_digest)
            if scope.status != "finalized":
                raise ComplianceScopingConflict("only finalized scopes can be exported")
            assessment_raw, assessment_digest = self._get(
                connection,
                "scope_assessments",
                tenant,
                "assessment_id",
                scope.assessment_id,
                "assessment",
            )
            body = {
                "scope": scope_raw,
                "scope_integrity_sha256": scope_digest,
                "assessment": assessment_raw,
                "assessment_integrity_sha256": assessment_digest,
                "limitations": self.product_boundaries(),
            }
            body_sha = _sha256(body)
            key = self._signing_key_resolver(tenant, key_ref)
            if not isinstance(key, bytes) or len(key) < 32:
                raise ComplianceScopingConfigError(
                    "scope export signing key must contain at least 32 bytes"
                )
            signature = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
            payload = {
                "tenant_id": tenant,
                "export_id": export_key,
                "scope_id": scope_key,
                "schema": EXPORT_SCHEMA,
                "body": body,
                "body_sha256": body_sha,
                "signing_key_ref": key_ref,
                "signature_hmac_sha256": signature,
                "retained_until": min(retained, scope.retained_until),
                "created_by": actor,
                "created_at": now,
            }
            digest_value = self._insert(
                connection,
                "scope_exports",
                ("tenant_id", "export_id", "scope_id", "retained_until"),
                (tenant, export_key, scope_key, payload["retained_until"]),
                payload,
            )
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "export",
                export_key,
            )
            self._audit(
                connection,
                tenant,
                "scope_export_signed",
                export_key,
                actor,
                {"scope_id": scope_key, "body_sha256": body_sha},
                now,
            )
            return self._export(payload, digest_value)

    def get_export(self, tenant_id: str, export_id: str) -> SignedScopeExport:
        tenant = _tenant(tenant_id)
        export_key = _id(export_id, "export_id")
        self._actor()
        with self._connect() as connection:
            raw, digest_value = self._get(
                connection,
                "scope_exports",
                tenant,
                "export_id",
                export_key,
                "scope export",
            )
            export = self._export(raw, digest_value)
            self._verify_export_signature(export)
            return export

    def _verify_export_signature(self, export: SignedScopeExport) -> None:
        if _sha256(export.body) != export.body_sha256:
            raise ComplianceScopingIntegrityError("scope export body digest is invalid")
        key = self._signing_key_resolver(export.tenant_id, export.signing_key_ref)
        expected = hmac.new(key, _canonical(export.body), hashlib.sha256).hexdigest()
        if not text_equals(expected, str(export.signature_hmac_sha256)):
            raise ComplianceScopingIntegrityError("scope export signature is invalid")

    def purge_expired(
        self,
        tenant_id: str,
        *,
        cutoff: float,
        idempotency_key: str,
    ) -> Mapping[str, int]:
        tenant = _tenant(tenant_id)
        moment = _timestamp(cutoff, "cutoff")
        actor = self._actor()
        request = {"action": "purge_expired", "cutoff": moment, "actor_ref": actor}
        with self._connect() as connection:
            self._begin(connection)
            request_sha, operation = self._operation(
                connection, tenant, idempotency_key, request
            )
            if operation is not None:
                parts = operation["result_id"].split(":")
                if len(parts) != 2 or any(not item.isdigit() for item in parts):
                    raise ComplianceScopingIntegrityError("purge result is invalid")
                return {"exports": int(parts[0]), "assessments": int(parts[1])}
            exports = connection.execute(
                "DELETE FROM scope_exports WHERE tenant_id=? AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            assessments = connection.execute(
                "DELETE FROM scope_assessments WHERE tenant_id=? AND status='scoped' "
                "AND retained_until<=?",
                (tenant, moment),
            ).rowcount
            result_id = f"{exports}:{assessments}"
            self._record_operation(
                connection,
                tenant,
                idempotency_key,
                request_sha,
                "purge_result",
                result_id,
            )
            self._audit(
                connection,
                tenant,
                "retention_purge_completed",
                idempotency_key,
                actor,
                {"exports": exports, "assessments": assessments},
                moment,
            )
            return {"exports": exports, "assessments": assessments}

    def list_records(self, tenant_id: str, *, limit: int = 200) -> dict[str, tuple]:
        """Read-only, newest-first listing of every record kind for one tenant.

        Each row is loaded through the same integrity-checked readers as the
        single-record getters. Export signatures are not re-verified here (the
        single export getter does that); listings only surface identity.
        """

        tenant = _tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, _MAX_LIST)
        self._actor()
        with self._connect() as connection:
            questionnaires = tuple(
                self._get_questionnaire(connection, tenant, row[0], int(row[1]))
                for row in connection.execute(
                    "SELECT questionnaire_id, version FROM scope_questionnaires "
                    "WHERE tenant_id=? ORDER BY questionnaire_id, version DESC LIMIT ?",
                    (tenant, bounded),
                ).fetchall()
            )

            def load(table: str, column: str, label: str, parse) -> tuple:
                ids = connection.execute(
                    f"SELECT {column} FROM {table} WHERE tenant_id=? "  # noqa: S608
                    f"ORDER BY rowid DESC LIMIT ?",
                    (tenant, bounded),
                ).fetchall()
                return tuple(
                    parse(*self._get(connection, table, tenant, column, row[0], label))
                    for row in ids
                )

            return {
                "questionnaires": questionnaires,
                "assessments": load(
                    "scope_assessments", "assessment_id", "assessment", self._assessment
                ),
                "scopes": load("scope_results", "scope_id", "scope result", self._scope),
                "exports": load("scope_exports", "export_id", "scope export", self._export),
            }

    def verify_integrity(self, tenant_id: str) -> IntegrityVerification:
        tenant = _tenant(tenant_id)
        self._actor()
        verified = 0
        tables = (
            ("scope_questionnaires", "questionnaire definition"),
            ("scope_publications", "questionnaire publication"),
            ("scope_assessments", "assessment"),
            ("scope_results", "scope result"),
            ("scope_exports", "scope export"),
        )
        with self._connect() as connection:
            for table, label in tables:
                rows = connection.execute(
                    f"SELECT * FROM {table} WHERE tenant_id=?",  # noqa: S608
                    (tenant,),
                ).fetchall()
                for row in rows:
                    payload = self._payload(row, label, tenant)
                    for column in (
                        "questionnaire_id",
                        "version",
                        "assessment_id",
                        "scope_id",
                        "export_id",
                        "status",
                        "retained_until",
                    ):
                        if column in row.keys() and payload.get(column) != row[column]:
                            raise ComplianceScopingIntegrityError(
                                f"persisted {label} index binding is invalid"
                            )
                    if table == "scope_exports":
                        self._verify_export_signature(
                            self._export(payload, row["integrity_sha256"])
                        )
                    verified += 1
            publication_rows = connection.execute(
                "SELECT * FROM scope_publications WHERE tenant_id=?",
                (tenant,),
            ).fetchall()
            for row in publication_rows:
                publication = self._payload(row, "questionnaire publication", tenant)
                definition = connection.execute(
                    "SELECT integrity_sha256 FROM scope_questionnaires "
                    "WHERE tenant_id=? AND questionnaire_id=? AND version=?",
                    (tenant, row["questionnaire_id"], row["version"]),
                ).fetchone()
                if (
                    definition is None
                    or publication["definition_sha256"] != definition["integrity_sha256"]
                ):
                    raise ComplianceScopingIntegrityError(
                        "publication definition binding is invalid"
                    )
            operation_rows = connection.execute(
                "SELECT * FROM scope_operations WHERE tenant_id=?",
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
                if row["tenant_id"] != tenant or _sha256(binding) != row["integrity_sha256"]:
                    raise ComplianceScopingIntegrityError(
                        "persisted idempotency binding is invalid"
                    )
                verified += 1
            audit_rows = connection.execute(
                "SELECT * FROM scope_audit_events WHERE tenant_id=? ORDER BY sequence",
                (tenant,),
            ).fetchall()
            previous = "0" * 64
            terminal = previous
            for expected_sequence, row in enumerate(audit_rows, start=1):
                payload = self._payload(row, "audit event", tenant)
                if (
                    row["sequence"] != expected_sequence
                    or payload["sequence"] != expected_sequence
                    or payload["previous_sha256"] != previous
                ):
                    raise ComplianceScopingIntegrityError(
                        "compliance scoping audit chain is discontinuous"
                    )
                previous = row["integrity_sha256"]
                terminal = previous
                verified += 1
            return IntegrityVerification(
                tenant_id=tenant,
                verified_records=verified,
                audit_events=len(audit_rows),
                terminal_audit_sha256=terminal,
            )

    @staticmethod
    def product_boundaries() -> Mapping[str, object]:
        return {
            "provider_neutral": True,
            "licensed_framework_text_included": False,
            "legal_advice": False,
            "automatic_external_discovery": False,
            "certification": False,
            "live_provider_acceptance_verified": False,
            "free_text_evidence_persisted": False,
            "secret_values_persisted": False,
            "rules_use_arbitrary_evaluation": False,
        }


__all__ = [
    "ANSWER_TYPES",
    "CONDITION_OPERATORS",
    "LIVE_ACCEPTANCE_VERIFIED",
    "LIVE_EXTERNAL_DISCOVERY",
    "RESPONSIBILITY_ROLES",
    "SCOPING_DOMAINS",
    "ComplianceScopingConfigError",
    "ComplianceScopingConflict",
    "ComplianceScopingError",
    "ComplianceScopingIntegrityError",
    "ComplianceScopingNotFound",
    "ComplianceScopingPermissionDenied",
    "ComplianceScopingStore",
    "ComplianceScopingValidationError",
    "IntegrityVerification",
    "QuestionnaireVersion",
    "ScopeResult",
    "ScopingAssessment",
    "ScopingQuestion",
    "SignedScopeExport",
    "enabled",
    "require_enabled",
]
