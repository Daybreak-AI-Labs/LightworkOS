"""Tenant-bound Contract and Engagement lifecycle authority.

This module is provider neutral and contains no licensed questionnaire, clause,
template, or scoring content.  Domain extensions use caller-defined opaque
labels, closed field types and a small deterministic formula AST; arbitrary
expressions and executable code are never accepted.

The capability is deliberately default-off behind both exact gates::

    [third_party_management]
    enable = true
    [third_party_management.contracts]
    enable = true

Vendor identity is deployment-owned.  Every create and mutation resolves an
exact tenant/vendor/revision authority twice and fails closed on drift,
revocation, expiry or metadata mismatch.
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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from .constant_time import text_equals
from .file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 1
AUTHORITY_SCHEMA = "lightwork.third-party-vendor-authority.v1"
RECORD_SCHEMA = "lightwork.third-party-contract-engagement.v1"
HISTORY_SCHEMA = "lightwork.third-party-contract-engagement-history.v1"
TOMBSTONE_SCHEMA = "lightwork.third-party-contract-engagement-tombstone.v1"
INTEGRITY_SCHEMA = "lightwork.third-party-contract-engagement-integrity.v1"
RECOVERY_SCHEMA = "lightwork.third-party-contract-engagement-recovery.v1"
LICENSED_TEMPLATE_CONTENT_INCLUDED = False
LIVE_PROVIDER_OPERATIONS = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False

RECORD_KINDS = frozenset({"contract", "engagement"})
VENDOR_TYPES = frozenset(
    {
        "consultant",
        "data_processor",
        "other",
        "partner",
        "reseller",
        "service_provider",
        "subprocessor",
        "supplier",
    }
)
CRITICALITIES = frozenset({"low", "medium", "high", "critical"})
CONTRACT_STATUSES = frozenset(
    {"draft", "negotiation", "active", "suspended", "expired", "terminated", "archived"}
)
ENGAGEMENT_STATUSES = frozenset(
    {"planned", "active", "paused", "completed", "cancelled", "terminated", "archived"}
)
ARCHIVED_STATUS = "archived"
_CONTRACT_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "draft": frozenset({"negotiation", "active", "terminated", "archived"}),
    "negotiation": frozenset({"draft", "active", "terminated", "archived"}),
    "active": frozenset({"suspended", "expired", "terminated", "archived"}),
    "suspended": frozenset({"active", "terminated", "archived"}),
    "expired": frozenset({"terminated", "archived"}),
    "terminated": frozenset({"archived"}),
    "archived": frozenset(),
}
_ENGAGEMENT_TRANSITIONS: Mapping[str, frozenset[str]] = {
    "planned": frozenset({"active", "cancelled", "archived"}),
    "active": frozenset({"paused", "completed", "terminated", "archived"}),
    "paused": frozenset({"active", "terminated", "archived"}),
    "completed": frozenset({"archived"}),
    "cancelled": frozenset({"archived"}),
    "terminated": frozenset({"archived"}),
    "archived": frozenset(),
}
CONTRACT_TYPES = frozenset(
    {
        "data_processing",
        "license",
        "master_services",
        "nda",
        "other",
        "statement_of_work",
        "subscription",
    }
)
ENGAGEMENT_TYPES = frozenset(
    {"consulting", "data_processing", "other", "outsourcing", "service", "software"}
)
RENEWAL_MODES = frozenset({"none", "manual", "automatic"})
DATA_ACCESS_LEVELS = frozenset({"none", "metadata", "confidential", "restricted"})
HOSTING_MODELS = frozenset(
    {"none", "vendor_cloud", "customer_cloud", "on_premises", "hybrid"}
)
FIELD_TYPES = frozenset(
    {
        "boolean",
        "decimal",
        "digest",
        "integer",
        "multi_choice",
        "single_choice",
        "text_ref",
        "timestamp",
    }
)
SENSITIVITIES = frozenset({"public", "internal", "confidential", "restricted"})
FORMULA_OPERATORS = frozenset({"add", "subtract", "multiply", "divide", "minimum", "maximum", "count"})

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")
_MAX_JSON_BYTES = 2 * 1024 * 1024
_MAX_RECORDS = 1_000_000
_MAX_FIELDS = 128
_MAX_FORMULAS = 64
_MAX_OPTIONS = 256
_MIN_RETENTION_SECONDS = 24 * 60 * 60
_MAX_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
_MAX_NUMBER = 1_000_000_000_000.0


class ThirdPartyContractError(RuntimeError):
    """Base error for Contract and Engagement lifecycle operations."""


class ThirdPartyContractConfigError(ThirdPartyContractError):
    """The capability or one of its deployment dependencies is unavailable."""


class ThirdPartyContractValidationError(ThirdPartyContractError, ValueError):
    """Input is outside a closed and bounded schema."""


class ThirdPartyContractConflict(ThirdPartyContractError):
    """A CAS, idempotency, relationship, authority or state precondition failed."""


class ThirdPartyContractNotFound(ThirdPartyContractError):
    """A tenant-scoped record is absent or deliberately undisclosed."""


class ThirdPartyContractPermissionDenied(ThirdPartyContractError):
    """Authenticated or maintenance authority is insufficient."""


class ThirdPartyContractIntegrityError(ThirdPartyContractError):
    """Persisted state or immutable history failed verification."""


def enabled() -> bool:
    """Return true only when the exact parent and child gates are enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    parent = config.get("third_party_management")
    child = parent.get("contracts") if isinstance(parent, Mapping) else None
    return (
        isinstance(parent, Mapping)
        and parent.get("enable") is True
        and isinstance(child, Mapping)
        and child.get("enable") is True
    )


def require_enabled() -> None:
    """Fail closed unless both Contract and Engagement gates are true."""

    if not enabled():
        raise ThirdPartyContractConfigError(
            "Contract and Engagement lifecycle is disabled; explicitly enable "
            "third_party_management and third_party_management.contracts"
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
        raise ThirdPartyContractValidationError("state must be finite canonical JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise ThirdPartyContractValidationError("state exceeds its canonical byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ThirdPartyContractValidationError("tenant_id is invalid") from exc


def _id(value: object, label: str, *, operation: bool = False) -> str:
    pattern = _OP_RE if operation else _ID_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ThirdPartyContractValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _optional_id(value: object, label: str) -> str | None:
    return None if value is None else _id(value, label)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ThirdPartyContractValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ThirdPartyContractValidationError(
            f"{label} must be an integer between {minimum} and {maximum}"
        )
    return value


def _number(value: object, label: str) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ThirdPartyContractValidationError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number) or abs(number) > _MAX_NUMBER:
        raise ThirdPartyContractValidationError(f"{label} is outside its finite bound")
    return value


def _timestamp(value: object, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    number = _number(value, label)
    if not 0 < float(number) < 100_000_000_000.0:
        raise ThirdPartyContractValidationError(f"{label} must be a positive timestamp")
    return float(number)


def _sequence(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 1_000,
) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ThirdPartyContractValidationError(f"{label} must be a list")
    if not minimum <= len(value) <= maximum:
        raise ThirdPartyContractValidationError(
            f"{label} must contain between {minimum} and {maximum} values"
        )
    return value


def _ids(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 1_000,
) -> tuple[str, ...]:
    values = tuple(_id(item, label) for item in _sequence(value, label, minimum=minimum, maximum=maximum))
    if len(set(values)) != len(values):
        raise ThirdPartyContractValidationError(f"{label} contains duplicates")
    return values


def _closed(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise ThirdPartyContractValidationError(f"{label} schema is closed")
    if any(not isinstance(key, str) for key in value):
        raise ThirdPartyContractValidationError(f"{label} keys must be strings")
    return value


@dataclass(frozen=True)
class VendorAuthority:
    schema: str
    tenant_id: str
    vendor_id: str
    vendor_revision: int
    vendor_type: str
    criticality: str
    jurisdiction_codes: tuple[str, ...]
    classification_refs: tuple[str, ...]
    issuer_ref: str
    issued_at: float
    valid_until: float
    revoked: bool
    authority_sha256: str

    def normalized(self) -> VendorAuthority:
        if self.schema != AUTHORITY_SCHEMA or type(self.revoked) is not bool:
            raise ThirdPartyContractValidationError("vendor authority schema is invalid")
        jurisdictions = tuple(
            str(item)
            for item in _sequence(
                self.jurisdiction_codes,
                "jurisdiction_codes",
                maximum=128,
            )
        )
        if any(not _COUNTRY_RE.fullmatch(item) for item in jurisdictions):
            raise ThirdPartyContractValidationError("jurisdiction_codes must be ISO alpha-2 codes")
        if len(set(jurisdictions)) != len(jurisdictions):
            raise ThirdPartyContractValidationError("jurisdiction_codes contains duplicates")
        vendor_type = _id(self.vendor_type, "vendor_type")
        criticality = _id(self.criticality, "criticality")
        if vendor_type not in VENDOR_TYPES or criticality not in CRITICALITIES:
            raise ThirdPartyContractValidationError("vendor authority metadata is outside policy")
        body = {
            "schema": AUTHORITY_SCHEMA,
            "tenant_id": _tenant(self.tenant_id),
            "vendor_id": _id(self.vendor_id, "vendor_id"),
            "vendor_revision": _integer(
                self.vendor_revision, "vendor_revision", 1, 2_147_483_647
            ),
            "vendor_type": vendor_type,
            "criticality": criticality,
            "jurisdiction_codes": tuple(sorted(jurisdictions)),
            "classification_refs": tuple(sorted(
                _ids(
                    self.classification_refs,
                    "classification_ref",
                    maximum=128,
                )
            )),
            "issuer_ref": _id(self.issuer_ref, "issuer_ref"),
            "issued_at": _timestamp(self.issued_at, "issued_at"),
            "valid_until": _timestamp(self.valid_until, "valid_until"),
            "revoked": self.revoked,
        }
        if body["valid_until"] <= body["issued_at"]:  # type: ignore[operator]
            raise ThirdPartyContractValidationError("vendor authority lifetime is invalid")
        expected = _sha256(body)
        if not hmac.compare_digest(_digest(self.authority_sha256, "authority_sha256"), expected):
            raise ThirdPartyContractValidationError("vendor authority digest changed")
        return VendorAuthority(**body, authority_sha256=expected)


def issue_vendor_authority(
    *,
    tenant_id: str,
    vendor_id: str,
    vendor_revision: int,
    vendor_type: str,
    criticality: str,
    jurisdiction_codes: Sequence[str],
    classification_refs: Sequence[str],
    issuer_ref: str,
    issued_at: float,
    valid_until: float,
    revoked: bool = False,
) -> VendorAuthority:
    """Issue a self-consistent exact authority for an enrolled vendor revision."""

    # Ordering is normalized so semantically identical metadata signs identically.
    jurisdictions = tuple(sorted(str(item) for item in jurisdiction_codes))
    classifications = tuple(sorted(str(item) for item in classification_refs))
    body = {
        "schema": AUTHORITY_SCHEMA,
        "tenant_id": _tenant(tenant_id),
        "vendor_id": _id(vendor_id, "vendor_id"),
        "vendor_revision": _integer(vendor_revision, "vendor_revision", 1, 2_147_483_647),
        "vendor_type": _id(vendor_type, "vendor_type"),
        "criticality": _id(criticality, "criticality"),
        "jurisdiction_codes": jurisdictions,
        "classification_refs": classifications,
        "issuer_ref": _id(issuer_ref, "issuer_ref"),
        "issued_at": _timestamp(issued_at, "issued_at"),
        "valid_until": _timestamp(valid_until, "valid_until"),
        "revoked": revoked,
    }
    return VendorAuthority(**body, authority_sha256=_sha256(body)).normalized()


def _field_definition(value: object) -> dict[str, object]:
    item = _closed(
        value,
        "custom field",
        frozenset({"field_id", "label_ref", "field_type", "required", "sensitivity", "options"}),
    )
    field_type = _id(item["field_type"], "field_type")
    sensitivity = _id(item["sensitivity"], "sensitivity")
    if field_type not in FIELD_TYPES or sensitivity not in SENSITIVITIES:
        raise ThirdPartyContractValidationError("custom field type or sensitivity is unsupported")
    if type(item["required"]) is not bool:
        raise ThirdPartyContractValidationError("custom field required must be boolean")
    options = _ids(item["options"], "custom field option", maximum=_MAX_OPTIONS)
    if field_type in {"single_choice", "multi_choice"} and not options:
        raise ThirdPartyContractValidationError("choice fields require options")
    if field_type not in {"single_choice", "multi_choice"} and options:
        raise ThirdPartyContractValidationError("non-choice fields cannot define options")
    return {
        "field_id": _id(item["field_id"], "field_id"),
        "label_ref": _id(item["label_ref"], "label_ref"),
        "field_type": field_type,
        "required": item["required"],
        "sensitivity": sensitivity,
        "options": list(options),
    }


def _field_schema(value: object) -> tuple[dict[str, object], ...]:
    fields = tuple(
        _field_definition(item)
        for item in _sequence(value, "custom fields", maximum=_MAX_FIELDS)
    )
    ids = tuple(str(item["field_id"]) for item in fields)
    if len(set(ids)) != len(ids):
        raise ThirdPartyContractValidationError("custom field IDs must be unique")
    return fields


def _field_value(definition: Mapping[str, object], value: object) -> object:
    field_type = definition["field_type"]
    if field_type == "boolean":
        if type(value) is not bool:
            raise ThirdPartyContractValidationError("boolean custom field is invalid")
        return value
    if field_type == "integer":
        return _integer(value, "integer custom field", -1_000_000_000, 1_000_000_000)
    if field_type == "decimal":
        return _number(value, "decimal custom field")
    if field_type == "timestamp":
        return _timestamp(value, "timestamp custom field")
    if field_type == "text_ref":
        return _id(value, "text_ref custom field")
    if field_type == "digest":
        return _digest(value, "digest custom field")
    options = tuple(definition["options"])  # type: ignore[arg-type]
    if field_type == "single_choice":
        selected = _id(value, "custom field option")
        if selected not in options:
            raise ThirdPartyContractValidationError("custom field option is not allowed")
        return selected
    selected_values = _ids(value, "custom field option", maximum=_MAX_OPTIONS)
    if not set(selected_values).issubset(options):
        raise ThirdPartyContractValidationError("custom field options are not allowed")
    return list(selected_values)


def _field_values(
    value: object,
    fields: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ThirdPartyContractValidationError("custom values must be an object")
    definitions = {str(item["field_id"]): item for item in fields}
    unknown = set(value) - set(definitions)
    if unknown:
        raise ThirdPartyContractValidationError("custom values contain unknown fields")
    missing = {
        field_id
        for field_id, definition in definitions.items()
        if definition["required"] is True and field_id not in value
    }
    if missing:
        raise ThirdPartyContractValidationError("required custom values are missing")
    return {
        field_id: _field_value(definitions[field_id], raw)
        for field_id, raw in sorted(value.items())
    }


def _formula_operand(
    value: object,
    fields: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    item = _closed(value, "formula operand", frozenset({"source", "field_id", "value"}))
    source = item["source"]
    if source == "field":
        field_id = _id(item["field_id"], "formula field_id")
        if item["value"] is not None or field_id not in fields:
            raise ThirdPartyContractValidationError("formula field operand is invalid")
        if fields[field_id]["field_type"] not in {"integer", "decimal", "multi_choice"}:
            raise ThirdPartyContractValidationError("formula fields must be numeric or countable")
        return {"source": "field", "field_id": field_id, "value": None}
    if source == "literal":
        if item["field_id"] is not None:
            raise ThirdPartyContractValidationError("literal formula operand cannot name a field")
        return {"source": "literal", "field_id": None, "value": _number(item["value"], "formula literal")}
    raise ThirdPartyContractValidationError("formula operand source is unsupported")


def _formula_definitions(
    value: object,
    fields: Sequence[Mapping[str, object]],
) -> tuple[dict[str, object], ...]:
    by_id = {str(item["field_id"]): item for item in fields}
    formulas: list[dict[str, object]] = []
    for raw in _sequence(value, "formulas", maximum=_MAX_FORMULAS):
        item = _closed(
            raw,
            "formula",
            frozenset({"formula_id", "operator", "operands", "round_digits"}),
        )
        formula_id = _id(item["formula_id"], "formula_id")
        operator = _id(item["operator"], "formula operator")
        if operator not in FORMULA_OPERATORS:
            raise ThirdPartyContractValidationError("formula operator is unsupported")
        operands = tuple(
            _formula_operand(operand, by_id)
            for operand in _sequence(item["operands"], "formula operands", minimum=1, maximum=16)
        )
        if operator in {"subtract", "divide"} and len(operands) != 2:
            raise ThirdPartyContractValidationError("subtract and divide require two operands")
        if operator == "count" and (
            len(operands) != 1
            or operands[0]["source"] != "field"
            or by_id[str(operands[0]["field_id"])]["field_type"] != "multi_choice"
        ):
            raise ThirdPartyContractValidationError("count requires one multi-choice field")
        formulas.append(
            {
                "formula_id": formula_id,
                "operator": operator,
                "operands": list(operands),
                "round_digits": _integer(item["round_digits"], "round_digits", 0, 8),
            }
        )
    ids = tuple(str(item["formula_id"]) for item in formulas)
    if len(set(ids)) != len(ids) or set(ids).intersection(by_id):
        raise ThirdPartyContractValidationError("formula IDs must be unique and distinct from fields")
    return tuple(formulas)


def _computed_values(
    formulas: Sequence[Mapping[str, object]],
    values: Mapping[str, object],
) -> dict[str, int | float]:
    computed: dict[str, int | float] = {}
    for formula in formulas:
        resolved: list[int | float] = []
        for operand in formula["operands"]:  # type: ignore[union-attr]
            if operand["source"] == "literal":
                resolved.append(operand["value"])
            else:
                field_value = values.get(str(operand["field_id"]))
                if isinstance(field_value, list):
                    resolved.append(len(field_value))
                elif isinstance(field_value, (int, float)) and not isinstance(field_value, bool):
                    resolved.append(field_value)
                else:
                    raise ThirdPartyContractValidationError("formula input value is missing or invalid")
        operator = formula["operator"]
        if operator == "add":
            result = sum(resolved)
        elif operator == "subtract":
            result = resolved[0] - resolved[1]
        elif operator == "multiply":
            result = 1
            for number in resolved:
                result *= number
        elif operator == "divide":
            if resolved[1] == 0:
                raise ThirdPartyContractValidationError("formula division by zero is invalid")
            result = resolved[0] / resolved[1]
        elif operator == "minimum":
            result = min(resolved)
        elif operator == "maximum":
            result = max(resolved)
        else:
            result = resolved[0]
        result = round(float(_number(result, "computed formula result")), int(formula["round_digits"]))
        computed[str(formula["formula_id"])] = result
    return computed


def _contract_lifecycle(value: object) -> dict[str, object]:
    item = _closed(
        value,
        "contract lifecycle",
        frozenset(
            {
                "agreement_type",
                "agreement_ref",
                "effective_at",
                "expires_at",
                "renewal_mode",
                "notice_period_days",
                "governing_law_ref",
                "parent_contract_id",
            }
        ),
    )
    agreement_type = _id(item["agreement_type"], "agreement_type")
    renewal_mode = _id(item["renewal_mode"], "renewal_mode")
    if agreement_type not in CONTRACT_TYPES or renewal_mode not in RENEWAL_MODES:
        raise ThirdPartyContractValidationError("contract lifecycle option is unsupported")
    effective = _timestamp(item["effective_at"], "effective_at", optional=True)
    expires = _timestamp(item["expires_at"], "expires_at", optional=True)
    if effective is not None and expires is not None and expires <= effective:
        raise ThirdPartyContractValidationError("contract expiry must follow its effective time")
    return {
        "agreement_type": agreement_type,
        "agreement_ref": _id(item["agreement_ref"], "agreement_ref"),
        "effective_at": effective,
        "expires_at": expires,
        "renewal_mode": renewal_mode,
        "notice_period_days": _integer(item["notice_period_days"], "notice_period_days", 0, 3_650),
        "governing_law_ref": _optional_id(item["governing_law_ref"], "governing_law_ref"),
        "parent_contract_id": _optional_id(item["parent_contract_id"], "parent_contract_id"),
    }


def _engagement_lifecycle(value: object) -> dict[str, object]:
    item = _closed(
        value,
        "engagement lifecycle",
        frozenset(
            {
                "engagement_type",
                "service_category_ref",
                "start_at",
                "end_at",
                "operational_criticality",
                "data_access",
                "hosting_model",
                "linked_contract_ids",
                "business_owner_ref",
            }
        ),
    )
    engagement_type = _id(item["engagement_type"], "engagement_type")
    criticality = _id(item["operational_criticality"], "operational_criticality")
    data_access = _id(item["data_access"], "data_access")
    hosting = _id(item["hosting_model"], "hosting_model")
    if (
        engagement_type not in ENGAGEMENT_TYPES
        or criticality not in CRITICALITIES
        or data_access not in DATA_ACCESS_LEVELS
        or hosting not in HOSTING_MODELS
    ):
        raise ThirdPartyContractValidationError("engagement lifecycle option is unsupported")
    start = _timestamp(item["start_at"], "start_at", optional=True)
    end = _timestamp(item["end_at"], "end_at", optional=True)
    if start is not None and end is not None and end <= start:
        raise ThirdPartyContractValidationError("engagement end must follow its start time")
    return {
        "engagement_type": engagement_type,
        "service_category_ref": _id(item["service_category_ref"], "service_category_ref"),
        "start_at": start,
        "end_at": end,
        "operational_criticality": criticality,
        "data_access": data_access,
        "hosting_model": hosting,
        "linked_contract_ids": list(
            _ids(item["linked_contract_ids"], "linked_contract_id", maximum=128)
        ),
        "business_owner_ref": _id(item["business_owner_ref"], "business_owner_ref"),
    }


def _lifecycle(kind: str, value: object) -> dict[str, object]:
    return _contract_lifecycle(value) if kind == "contract" else _engagement_lifecycle(value)


@dataclass(frozen=True)
class ThirdPartyRecord:
    schema: str
    tenant_id: str
    record_id: str
    record_kind: str
    vendor_id: str
    vendor_revision: int
    vendor_type: str
    vendor_criticality: str
    vendor_jurisdiction_codes: tuple[str, ...]
    vendor_classification_refs: tuple[str, ...]
    vendor_issuer_ref: str
    vendor_authority_sha256: str
    title_ref: str
    owner_ref: str
    status: str
    lifecycle: Mapping[str, object]
    field_schema: tuple[Mapping[str, object], ...]
    field_values: Mapping[str, object]
    formulas: tuple[Mapping[str, object], ...]
    computed_values: Mapping[str, int | float]
    sensitive_field_ids: tuple[str, ...]
    created_by_ref: str
    created_at: float
    updated_at: float
    archived_at: float | None
    retained_until: float
    revision: int
    previous_integrity_sha256: str | None
    integrity_sha256: str


@dataclass(frozen=True)
class ThirdPartyRecordHistory:
    schema: str
    record_id: str
    revision: int
    event_type: str
    actor_ref: str
    changed_fields: tuple[str, ...]
    record: ThirdPartyRecord
    created_at: float
    previous_event_sha256: str | None
    event_sha256: str


@dataclass(frozen=True)
class ThirdPartyRecordTombstone:
    schema: str
    tenant_id: str
    record_id: str
    record_kind: str
    vendor_id: str
    last_revision: int
    last_integrity_sha256: str
    last_event_sha256: str
    deleted_by_ref: str
    deleted_at: float
    integrity_sha256: str


def _record_body(record: ThirdPartyRecord) -> dict[str, object]:
    body = asdict(record)
    body.pop("integrity_sha256", None)
    return body


def _record_integrity(record: ThirdPartyRecord) -> str:
    return _sha256(_record_body(record))


def _normalize_record(record: ThirdPartyRecord) -> ThirdPartyRecord:
    if not isinstance(record, ThirdPartyRecord) or record.schema != RECORD_SCHEMA:
        raise ThirdPartyContractIntegrityError("stored Contract or Engagement shape is invalid")
    try:
        kind = _id(record.record_kind, "record_kind")
        if kind not in RECORD_KINDS:
            raise ThirdPartyContractValidationError("record_kind is unsupported")
        fields = _field_schema(record.field_schema)
        values = _field_values(record.field_values, fields)
        formulas = _formula_definitions(record.formulas, fields)
        computed = _computed_values(formulas, values)
        expected_sensitive = tuple(
            sorted(
                str(item["field_id"])
                for item in fields
                if item["sensitivity"] in {"confidential", "restricted"}
            )
        )
        status = _id(record.status, "status")
        statuses = CONTRACT_STATUSES if kind == "contract" else ENGAGEMENT_STATUSES
        if status not in statuses:
            raise ThirdPartyContractValidationError("record status is unsupported")
        normalized = replace(
            record,
            tenant_id=_tenant(record.tenant_id),
            record_id=_id(record.record_id, "record_id"),
            record_kind=kind,
            vendor_id=_id(record.vendor_id, "vendor_id"),
            vendor_revision=_integer(record.vendor_revision, "vendor_revision", 1, 2_147_483_647),
            vendor_type=_id(record.vendor_type, "vendor_type"),
            vendor_criticality=_id(record.vendor_criticality, "vendor_criticality"),
            vendor_jurisdiction_codes=tuple(record.vendor_jurisdiction_codes),
            vendor_classification_refs=_ids(
                record.vendor_classification_refs,
                "vendor_classification_ref",
                maximum=128,
            ),
            vendor_issuer_ref=_id(record.vendor_issuer_ref, "vendor_issuer_ref"),
            vendor_authority_sha256=_digest(record.vendor_authority_sha256, "vendor_authority_sha256"),
            title_ref=_id(record.title_ref, "title_ref"),
            owner_ref=_id(record.owner_ref, "owner_ref"),
            status=status,
            lifecycle=_lifecycle(kind, record.lifecycle),
            field_schema=tuple(fields),
            field_values=values,
            formulas=tuple(formulas),
            computed_values=computed,
            sensitive_field_ids=expected_sensitive,
            created_by_ref=_id(record.created_by_ref, "created_by_ref"),
            created_at=float(_timestamp(record.created_at, "created_at")),
            updated_at=float(_timestamp(record.updated_at, "updated_at")),
            archived_at=_timestamp(record.archived_at, "archived_at", optional=True),
            retained_until=float(_timestamp(record.retained_until, "retained_until")),
            revision=_integer(record.revision, "revision", 1, 2_147_483_647),
            previous_integrity_sha256=(
                _digest(record.previous_integrity_sha256, "previous_integrity_sha256")
                if record.previous_integrity_sha256 is not None
                else None
            ),
            integrity_sha256=_digest(record.integrity_sha256, "integrity_sha256"),
        )
    except ThirdPartyContractValidationError as exc:
        raise ThirdPartyContractIntegrityError("stored Contract or Engagement is invalid") from exc
    if normalized.vendor_type not in VENDOR_TYPES or normalized.vendor_criticality not in CRITICALITIES:
        raise ThirdPartyContractIntegrityError("stored vendor metadata is invalid")
    if any(not _COUNTRY_RE.fullmatch(item) for item in normalized.vendor_jurisdiction_codes):
        raise ThirdPartyContractIntegrityError("stored vendor jurisdictions are invalid")
    if len(set(normalized.vendor_jurisdiction_codes)) != len(
        normalized.vendor_jurisdiction_codes
    ):
        raise ThirdPartyContractIntegrityError("stored vendor jurisdictions contain duplicates")
    if normalized.revision == 1 and normalized.previous_integrity_sha256 is not None:
        raise ThirdPartyContractIntegrityError("initial record has a previous digest")
    if normalized.revision > 1 and normalized.previous_integrity_sha256 is None:
        raise ThirdPartyContractIntegrityError("revised record lacks a previous digest")
    if normalized.updated_at < normalized.created_at or normalized.retained_until <= normalized.updated_at:
        raise ThirdPartyContractIntegrityError("stored record time order is invalid")
    if normalized.status == ARCHIVED_STATUS:
        if normalized.archived_at != normalized.updated_at:
            raise ThirdPartyContractIntegrityError("archived record time is invalid")
    elif normalized.archived_at is not None:
        raise ThirdPartyContractIntegrityError("active record has an archived time")
    if normalized.computed_values != record.computed_values:
        raise ThirdPartyContractIntegrityError("stored formula results changed")
    if not hmac.compare_digest(normalized.integrity_sha256, _record_integrity(normalized)):
        raise ThirdPartyContractIntegrityError("stored Contract or Engagement integrity changed")
    return normalized


def _history_body(event: ThirdPartyRecordHistory) -> dict[str, object]:
    body = asdict(event)
    body.pop("event_sha256", None)
    return body


def _normalize_history(event: ThirdPartyRecordHistory) -> ThirdPartyRecordHistory:
    if not isinstance(event, ThirdPartyRecordHistory) or event.schema != HISTORY_SCHEMA:
        raise ThirdPartyContractIntegrityError("stored lifecycle history shape is invalid")
    record = _normalize_record(event.record)
    changed_fields = tuple(sorted(_ids(event.changed_fields, "changed_field", maximum=32)))
    normalized = replace(
        event,
        record_id=_id(event.record_id, "record_id"),
        revision=_integer(event.revision, "revision", 1, 2_147_483_647),
        event_type=_id(event.event_type, "event_type"),
        actor_ref=_id(event.actor_ref, "actor_ref"),
        changed_fields=changed_fields,
        record=record,
        created_at=float(_timestamp(event.created_at, "created_at")),
        previous_event_sha256=(
            _digest(event.previous_event_sha256, "previous_event_sha256")
            if event.previous_event_sha256 is not None
            else None
        ),
        event_sha256=_digest(event.event_sha256, "event_sha256"),
    )
    if normalized.record_id != record.record_id or normalized.revision != record.revision:
        raise ThirdPartyContractIntegrityError("history does not bind its record revision")
    if normalized.created_at != record.updated_at:
        raise ThirdPartyContractIntegrityError("history and record timestamps differ")
    if normalized.revision == 1 and normalized.previous_event_sha256 is not None:
        raise ThirdPartyContractIntegrityError("initial history has a previous event")
    if normalized.revision > 1 and normalized.previous_event_sha256 is None:
        raise ThirdPartyContractIntegrityError("revised history lacks a previous event")
    if not hmac.compare_digest(normalized.event_sha256, _sha256(_history_body(normalized))):
        raise ThirdPartyContractIntegrityError("stored lifecycle history changed")
    return normalized


def _tombstone_body(tombstone: ThirdPartyRecordTombstone) -> dict[str, object]:
    body = asdict(tombstone)
    body.pop("integrity_sha256", None)
    return body


def _normalize_tombstone(tombstone: ThirdPartyRecordTombstone) -> ThirdPartyRecordTombstone:
    if not isinstance(tombstone, ThirdPartyRecordTombstone) or tombstone.schema != TOMBSTONE_SCHEMA:
        raise ThirdPartyContractIntegrityError("stored tombstone shape is invalid")
    normalized = replace(
        tombstone,
        tenant_id=_tenant(tombstone.tenant_id),
        record_id=_id(tombstone.record_id, "record_id"),
        record_kind=_id(tombstone.record_kind, "record_kind"),
        vendor_id=_id(tombstone.vendor_id, "vendor_id"),
        last_revision=_integer(tombstone.last_revision, "last_revision", 1, 2_147_483_647),
        last_integrity_sha256=_digest(tombstone.last_integrity_sha256, "last_integrity_sha256"),
        last_event_sha256=_digest(tombstone.last_event_sha256, "last_event_sha256"),
        deleted_by_ref=_id(tombstone.deleted_by_ref, "deleted_by_ref"),
        deleted_at=float(_timestamp(tombstone.deleted_at, "deleted_at")),
        integrity_sha256=_digest(tombstone.integrity_sha256, "integrity_sha256"),
    )
    if normalized.record_kind not in RECORD_KINDS:
        raise ThirdPartyContractIntegrityError("stored tombstone kind is invalid")
    if not hmac.compare_digest(normalized.integrity_sha256, _sha256(_tombstone_body(normalized))):
        raise ThirdPartyContractIntegrityError("stored tombstone integrity changed")
    return normalized


def redacted_record(record: ThirdPartyRecord, *, include_sensitive: bool = False) -> dict[str, object]:
    """Return an API-safe projection and explicitly report applied redaction."""

    normalized = _normalize_record(record)
    result = asdict(normalized)
    sensitive = set(normalized.sensitive_field_ids)
    if not include_sensitive:
        result["field_values"] = {
            key: ({"redacted": True} if key in sensitive else value)
            for key, value in normalized.field_values.items()
        }
    result["redaction"] = {
        "applied": bool(sensitive and not include_sensitive),
        "sensitive_field_ids": sorted(sensitive),
        "sensitive_values_included": bool(include_sensitive),
        "raw_documents_stored": False,
        "licensed_template_content_included": False,
    }
    return result


class ThirdPartyContractStore:
    """Durable tenant-local Contract/Engagement and tombstone authority."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        vendor_authority_resolver: Callable[[str, str, int], VendorAuthority],
        principal_resolver: Callable[[], str | None],
        maintenance_authorizer: Callable[[], bool] = lambda: False,
        config_gate: Callable[[], None] = require_enabled,
        retention_seconds: int = 365 * 24 * 3_600,
        max_records: int = 100_000,
        clock: Callable[[], float] = time.time,
        id_factory: Callable[[str], str] | None = None,
    ) -> None:
        dependencies = (
            vendor_authority_resolver,
            principal_resolver,
            maintenance_authorizer,
            config_gate,
            clock,
        )
        if not all(callable(item) for item in dependencies):
            raise ThirdPartyContractConfigError("Contract lifecycle dependencies are incomplete")
        try:
            config_gate()
        except ThirdPartyContractError:
            raise
        except Exception as exc:
            raise ThirdPartyContractConfigError("Contract lifecycle configuration is unavailable") from exc
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self._tenant_sha256 = hashlib.sha256(self.tenant_id.encode()).hexdigest()
        self._authority_resolver = vendor_authority_resolver
        self._principal_resolver = principal_resolver
        self._maintenance_authorizer = maintenance_authorizer
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        self._max_records = _integer(max_records, "max_records", 1, _MAX_RECORDS)
        self._clock = clock
        self._id_factory = id_factory or (
            lambda kind: f"{'CTR' if kind == 'contract' else 'ENG'}-{secrets.token_hex(16)}"
        )
        self._maintenance = threading.local()
        ensure_private_directory(self.path.parent)
        with cross_process_lock(self.path, strict=True):
            self._initialize()

    def _now(self) -> float:
        return float(_timestamp(self._clock(), "clock"))

    def _actor(self) -> str:
        try:
            actor = self._principal_resolver()
        except Exception as exc:
            raise ThirdPartyContractPermissionDenied("authenticated principal is unavailable") from exc
        if actor is None:
            raise ThirdPartyContractPermissionDenied("authenticated principal is required")
        return _id(actor, "authenticated principal")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA secure_delete=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.create_function(
            "third_party_contract_maintenance_authorized",
            0,
            lambda: 1 if bool(getattr(self._maintenance, "authorized", False)) else 0,
        )
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS third_party_contract_meta(
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS third_party_contract_records(
                    tenant_sha256 TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    record_kind TEXT NOT NULL,
                    vendor_id TEXT NOT NULL,
                    owner_ref TEXT NOT NULL,
                    status TEXT NOT NULL,
                    updated_at REAL NOT NULL,
                    retained_until REAL NOT NULL,
                    revision INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    PRIMARY KEY(tenant_sha256,record_id)
                );
                CREATE INDEX IF NOT EXISTS third_party_contract_vendor_idx
                    ON third_party_contract_records(tenant_sha256,vendor_id,record_kind,updated_at,record_id);
                CREATE INDEX IF NOT EXISTS third_party_contract_retention_idx
                    ON third_party_contract_records(tenant_sha256,status,retained_until,record_id);
                CREATE TABLE IF NOT EXISTS third_party_contract_history(
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_sha256 TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    event_json TEXT NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    UNIQUE(tenant_sha256,record_id,revision),
                    FOREIGN KEY(tenant_sha256,record_id)
                        REFERENCES third_party_contract_records(tenant_sha256,record_id)
                        ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS third_party_contract_operations(
                    tenant_sha256 TEXT NOT NULL,
                    idempotency_sha256 TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,idempotency_sha256)
                );
                CREATE TABLE IF NOT EXISTS third_party_contract_tombstones(
                    tenant_sha256 TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    tombstone_json TEXT NOT NULL,
                    integrity_sha256 TEXT NOT NULL,
                    deleted_at REAL NOT NULL,
                    PRIMARY KEY(tenant_sha256,record_id)
                );
                CREATE TRIGGER IF NOT EXISTS third_party_contract_history_no_update
                    BEFORE UPDATE ON third_party_contract_history
                    BEGIN SELECT RAISE(ABORT,'immutable Contract history'); END;
                CREATE TRIGGER IF NOT EXISTS third_party_contract_operation_no_update
                    BEFORE UPDATE ON third_party_contract_operations
                    BEGIN SELECT RAISE(ABORT,'immutable Contract operation'); END;
                CREATE TRIGGER IF NOT EXISTS third_party_contract_tombstone_no_update
                    BEFORE UPDATE ON third_party_contract_tombstones
                    BEGIN SELECT RAISE(ABORT,'immutable Contract tombstone'); END;
                CREATE TRIGGER IF NOT EXISTS third_party_contract_record_no_delete
                    BEFORE DELETE ON third_party_contract_records
                    WHEN third_party_contract_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'Contract maintenance required'); END;
                CREATE TRIGGER IF NOT EXISTS third_party_contract_history_no_delete
                    BEFORE DELETE ON third_party_contract_history
                    WHEN third_party_contract_maintenance_authorized() != 1
                    BEGIN SELECT RAISE(ABORT,'Contract maintenance required'); END;
                """
            )
            version = connection.execute(
                "SELECT value FROM third_party_contract_meta WHERE key='schema_version'"
            ).fetchone()
            if version is None:
                connection.execute(
                    "INSERT INTO third_party_contract_meta(key,value) VALUES('schema_version',?)",
                    (str(SCHEMA_VERSION),),
                )
            elif version["value"] != str(SCHEMA_VERSION):
                raise ThirdPartyContractConfigError(
                    f"unsupported Contract lifecycle schema version {version['value']}"
                )
            tenant = connection.execute(
                "SELECT value FROM third_party_contract_meta WHERE key='tenant_sha256'"
            ).fetchone()
            if tenant is None:
                connection.execute(
                    "INSERT INTO third_party_contract_meta(key,value) VALUES('tenant_sha256',?)",
                    (self._tenant_sha256,),
                )
            elif not hmac.compare_digest(str(tenant["value"]), self._tenant_sha256):
                raise ThirdPartyContractIntegrityError("Contract database belongs to another tenant")
        ensure_private_file(self.path)

    def _require_tenant(self, tenant_id: object) -> None:
        if not text_equals(_tenant(tenant_id), self.tenant_id):
            raise ThirdPartyContractNotFound("Contract or Engagement was not found")

    def _resolve_vendor(self, vendor_id: str, vendor_revision: int) -> VendorAuthority:
        vendor = _id(vendor_id, "vendor_id")
        revision = _integer(vendor_revision, "vendor_revision", 1, 2_147_483_647)
        try:
            first = self._authority_resolver(self.tenant_id, vendor, revision)
            second = self._authority_resolver(self.tenant_id, vendor, revision)
            if not isinstance(first, VendorAuthority) or not isinstance(second, VendorAuthority):
                raise TypeError("vendor authority type is invalid")
            left = first.normalized()
            right = second.normalized()
        except ThirdPartyContractError:
            raise
        except Exception as exc:
            raise ThirdPartyContractConflict("vendor authority is unavailable") from exc
        if left != right:
            raise ThirdPartyContractConflict("vendor authority changed during resolution")
        now = self._now()
        if (
            left.tenant_id != self.tenant_id
            or left.vendor_id != vendor
            or left.vendor_revision != revision
            or left.revoked
            or not left.issued_at <= now < left.valid_until
        ):
            raise ThirdPartyContractConflict("vendor authority is not current")
        return left

    @staticmethod
    def _row_record(row: sqlite3.Row | None) -> ThirdPartyRecord:
        if row is None:
            raise ThirdPartyContractNotFound("Contract or Engagement was not found")
        try:
            payload = json.loads(row["record_json"])
            payload["vendor_jurisdiction_codes"] = tuple(payload["vendor_jurisdiction_codes"])
            payload["vendor_classification_refs"] = tuple(payload["vendor_classification_refs"])
            payload["field_schema"] = tuple(payload["field_schema"])
            payload["formulas"] = tuple(payload["formulas"])
            payload["sensitive_field_ids"] = tuple(payload["sensitive_field_ids"])
            return _normalize_record(ThirdPartyRecord(**payload))
        except ThirdPartyContractError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyContractIntegrityError("stored Contract or Engagement is invalid") from exc

    @staticmethod
    def _row_tombstone(row: sqlite3.Row | None) -> ThirdPartyRecordTombstone:
        if row is None:
            raise ThirdPartyContractNotFound("Contract or Engagement tombstone was not found")
        try:
            payload = json.loads(row["tombstone_json"])
            return _normalize_tombstone(ThirdPartyRecordTombstone(**payload))
        except ThirdPartyContractError:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ThirdPartyContractIntegrityError("stored tombstone is invalid") from exc

    def _existing_operation(
        self,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        operation_type: str,
        request_sha256: str,
    ) -> ThirdPartyRecord | ThirdPartyRecordTombstone | None:
        key = _id(idempotency_key, "idempotency_key", operation=True)
        key_sha256 = _sha256({"schema": "lightwork.third-party-contract-idempotency.v1", "key": key})
        row = connection.execute(
            "SELECT operation_type,request_sha256,record_id FROM third_party_contract_operations "
            "WHERE tenant_sha256=? AND idempotency_sha256=?",
            (self._tenant_sha256, key_sha256),
        ).fetchone()
        if row is None:
            return None
        if row["operation_type"] != operation_type or not hmac.compare_digest(
            str(row["request_sha256"]), request_sha256
        ):
            raise ThirdPartyContractConflict("idempotency key is bound to another operation")
        record = connection.execute(
            "SELECT record_json FROM third_party_contract_records WHERE tenant_sha256=? AND record_id=?",
            (self._tenant_sha256, row["record_id"]),
        ).fetchone()
        if record is not None:
            return self._row_record(record)
        tombstone = connection.execute(
            "SELECT tombstone_json FROM third_party_contract_tombstones WHERE tenant_sha256=? AND record_id=?",
            (self._tenant_sha256, row["record_id"]),
        ).fetchone()
        return self._row_tombstone(tombstone)

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        *,
        idempotency_key: str,
        operation_type: str,
        request_sha256: str,
        record_id: str,
        created_at: float,
    ) -> None:
        key_sha256 = _sha256(
            {"schema": "lightwork.third-party-contract-idempotency.v1", "key": idempotency_key}
        )
        connection.execute(
            "INSERT INTO third_party_contract_operations VALUES(?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                key_sha256,
                operation_type,
                request_sha256,
                record_id,
                created_at,
            ),
        )

    def _insert_history(
        self,
        connection: sqlite3.Connection,
        *,
        record: ThirdPartyRecord,
        event_type: str,
        actor_ref: str,
        changed_fields: Sequence[str],
        previous_event_sha256: str | None,
    ) -> ThirdPartyRecordHistory:
        event = ThirdPartyRecordHistory(
            schema=HISTORY_SCHEMA,
            record_id=record.record_id,
            revision=record.revision,
            event_type=_id(event_type, "event_type"),
            actor_ref=_id(actor_ref, "actor_ref"),
            changed_fields=tuple(sorted(_ids(changed_fields, "changed_field", maximum=32))),
            record=record,
            created_at=record.updated_at,
            previous_event_sha256=previous_event_sha256,
            event_sha256="0" * 64,
        )
        event = replace(event, event_sha256=_sha256(_history_body(event)))
        normalized = _normalize_history(event)
        connection.execute(
            "INSERT INTO third_party_contract_history(tenant_sha256,record_id,revision,event_json,event_sha256,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                self._tenant_sha256,
                record.record_id,
                record.revision,
                _canonical(asdict(normalized)).decode("ascii"),
                normalized.event_sha256,
                normalized.created_at,
            ),
        )
        return normalized

    def _validate_relationships(
        self,
        connection: sqlite3.Connection,
        *,
        kind: str,
        vendor_id: str,
        lifecycle: Mapping[str, object],
        record_id: str | None = None,
    ) -> None:
        references: tuple[str, ...]
        if kind == "contract":
            parent = lifecycle["parent_contract_id"]
            references = (str(parent),) if parent is not None else ()
        else:
            references = tuple(lifecycle["linked_contract_ids"])  # type: ignore[arg-type]
        if record_id is not None and record_id in references:
            raise ThirdPartyContractConflict("a record cannot reference itself")
        for reference in references:
            row = connection.execute(
                "SELECT record_json FROM third_party_contract_records WHERE tenant_sha256=? AND record_id=?",
                (self._tenant_sha256, reference),
            ).fetchone()
            linked = self._row_record(row)
            if linked.record_kind != "contract" or linked.vendor_id != vendor_id:
                raise ThirdPartyContractConflict("linked contracts must belong to the exact vendor")

    def _live_references(
        self,
        connection: sqlite3.Connection,
        record: ThirdPartyRecord,
    ) -> tuple[str, ...]:
        """Return the mutable records that still name this contract.

        Deleting such a contract would leave a reference that fails
        :meth:`_validate_relationships` on every later update or archive of
        the referencing record. Archived records are immutable and are never
        re-validated, so they do not hold a contract back.
        """

        if record.record_kind != "contract":
            return ()
        rows = connection.execute(
            "SELECT record_json FROM third_party_contract_records "
            "WHERE tenant_sha256=? AND vendor_id=? AND status<>? AND record_id<>? "
            "ORDER BY record_id",
            (self._tenant_sha256, record.vendor_id, ARCHIVED_STATUS, record.record_id),
        ).fetchall()
        referencing: list[str] = []
        for row in rows:
            other = self._row_record(row)
            if other.record_kind == "contract":
                references: tuple[object, ...] = (other.lifecycle["parent_contract_id"],)
            else:
                references = tuple(other.lifecycle["linked_contract_ids"])  # type: ignore[arg-type]
            if record.record_id in references:
                referencing.append(other.record_id)
        return tuple(referencing)

    def _create(
        self,
        tenant_id: str,
        *,
        kind: str,
        vendor_id: str,
        vendor_revision: int,
        title_ref: str,
        owner_ref: str,
        status: str,
        lifecycle: Mapping[str, object],
        field_schema: Sequence[Mapping[str, object]],
        field_values: Mapping[str, object],
        formulas: Sequence[Mapping[str, object]],
        idempotency_key: str,
        record_id: str | None = None,
    ) -> ThirdPartyRecord:
        self._require_tenant(tenant_id)
        if kind not in RECORD_KINDS:
            raise ThirdPartyContractValidationError("record kind is unsupported")
        actor = self._actor()
        authority = self._resolve_vendor(vendor_id, vendor_revision)
        statuses = CONTRACT_STATUSES if kind == "contract" else ENGAGEMENT_STATUSES
        initial = "draft" if kind == "contract" else "planned"
        if status not in statuses or status not in {initial, "active"}:
            raise ThirdPartyContractValidationError("initial lifecycle status is not allowed")
        normalized_lifecycle = _lifecycle(kind, lifecycle)
        fields = _field_schema(field_schema)
        values = _field_values(field_values, fields)
        normalized_formulas = _formula_definitions(formulas, fields)
        computed = _computed_values(normalized_formulas, values)
        identifier = _id(record_id or self._id_factory(kind), "record_id")
        title = _id(title_ref, "title_ref")
        owner = _id(owner_ref, "owner_ref")
        key = _id(idempotency_key, "idempotency_key", operation=True)
        request = {
            "schema": "lightwork.third-party-contract-create-request.v1",
            "kind": kind,
            "record_id": identifier,
            "vendor_id": authority.vendor_id,
            "vendor_revision": authority.vendor_revision,
            "title_ref": title,
            "owner_ref": owner,
            "status": status,
            "lifecycle": normalized_lifecycle,
            "field_schema": list(fields),
            "field_values": values,
            "formulas": list(normalized_formulas),
        }
        request_sha256 = _sha256(request)
        now = self._now()
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._existing_operation(
                connection,
                idempotency_key=key,
                operation_type=f"create_{kind}",
                request_sha256=request_sha256,
            )
            if replay is not None:
                if not isinstance(replay, ThirdPartyRecord):
                    raise ThirdPartyContractConflict("idempotent create result was deleted")
                return replay
            count = connection.execute(
                "SELECT COUNT(*) AS count FROM third_party_contract_records WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchone()["count"]
            if int(count) >= self._max_records:
                raise ThirdPartyContractConflict("Contract and Engagement quota is exhausted")
            if connection.execute(
                "SELECT 1 FROM third_party_contract_records WHERE tenant_sha256=? AND record_id=? "
                "UNION SELECT 1 FROM third_party_contract_tombstones WHERE tenant_sha256=? AND record_id=?",
                (self._tenant_sha256, identifier, self._tenant_sha256, identifier),
            ).fetchone() is not None:
                raise ThirdPartyContractConflict("record identifier already exists or was tombstoned")
            self._validate_relationships(
                connection,
                kind=kind,
                vendor_id=authority.vendor_id,
                lifecycle=normalized_lifecycle,
                record_id=identifier,
            )
            sensitive = tuple(
                sorted(
                    str(item["field_id"])
                    for item in fields
                    if item["sensitivity"] in {"confidential", "restricted"}
                )
            )
            record = ThirdPartyRecord(
                schema=RECORD_SCHEMA,
                tenant_id=self.tenant_id,
                record_id=identifier,
                record_kind=kind,
                vendor_id=authority.vendor_id,
                vendor_revision=authority.vendor_revision,
                vendor_type=authority.vendor_type,
                vendor_criticality=authority.criticality,
                vendor_jurisdiction_codes=authority.jurisdiction_codes,
                vendor_classification_refs=authority.classification_refs,
                vendor_issuer_ref=authority.issuer_ref,
                vendor_authority_sha256=authority.authority_sha256,
                title_ref=title,
                owner_ref=owner,
                status=status,
                lifecycle=normalized_lifecycle,
                field_schema=tuple(fields),
                field_values=values,
                formulas=tuple(normalized_formulas),
                computed_values=computed,
                sensitive_field_ids=sensitive,
                created_by_ref=actor,
                created_at=now,
                updated_at=now,
                archived_at=None,
                retained_until=now + self._retention_seconds,
                revision=1,
                previous_integrity_sha256=None,
                integrity_sha256="0" * 64,
            )
            record = replace(record, integrity_sha256=_record_integrity(record))
            record = _normalize_record(record)
            connection.execute(
                "INSERT INTO third_party_contract_records VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    self._tenant_sha256,
                    record.record_id,
                    record.record_kind,
                    record.vendor_id,
                    record.owner_ref,
                    record.status,
                    record.updated_at,
                    record.retained_until,
                    record.revision,
                    _canonical(asdict(record)).decode("ascii"),
                ),
            )
            self._insert_history(
                connection,
                record=record,
                event_type=f"{kind}_created",
                actor_ref=actor,
                changed_fields=(
                    "field_schema",
                    "field_values",
                    "formulas",
                    "lifecycle",
                    "owner_ref",
                    "status",
                    "title_ref",
                ),
                previous_event_sha256=None,
            )
            self._record_operation(
                connection,
                idempotency_key=key,
                operation_type=f"create_{kind}",
                request_sha256=request_sha256,
                record_id=record.record_id,
                created_at=now,
            )
            connection.commit()
        return record

    def create_contract(self, tenant_id: str, **kwargs: object) -> ThirdPartyRecord:
        return self._create(tenant_id, kind="contract", **kwargs)  # type: ignore[arg-type]

    def create_engagement(self, tenant_id: str, **kwargs: object) -> ThirdPartyRecord:
        return self._create(tenant_id, kind="engagement", **kwargs)  # type: ignore[arg-type]

    def get_record(
        self,
        tenant_id: str,
        record_id: str,
        *,
        record_kind: str | None = None,
    ) -> ThirdPartyRecord:
        self._require_tenant(tenant_id)
        identifier = _id(record_id, "record_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM third_party_contract_records "
                "WHERE tenant_sha256=? AND record_id=?",
                (self._tenant_sha256, identifier),
            ).fetchone()
        record = self._row_record(row)
        if record_kind is not None and record.record_kind != _id(record_kind, "record_kind"):
            raise ThirdPartyContractNotFound("Contract or Engagement was not found")
        return record

    def get_tombstone(
        self,
        tenant_id: str,
        record_id: str,
    ) -> ThirdPartyRecordTombstone:
        self._require_tenant(tenant_id)
        identifier = _id(record_id, "record_id")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT tombstone_json FROM third_party_contract_tombstones "
                "WHERE tenant_sha256=? AND record_id=?",
                (self._tenant_sha256, identifier),
            ).fetchone()
        return self._row_tombstone(row)

    def list_records(
        self,
        tenant_id: str,
        *,
        record_kind: str | None = None,
        vendor_id: str | None = None,
        status: str | None = None,
        owner_ref: str | None = None,
        limit: int = 100,
    ) -> tuple[ThirdPartyRecord, ...]:
        self._require_tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        clauses = ["tenant_sha256=?"]
        values: list[object] = [self._tenant_sha256]
        if record_kind is not None:
            kind = _id(record_kind, "record_kind")
            if kind not in RECORD_KINDS:
                raise ThirdPartyContractValidationError("record_kind is unsupported")
            clauses.append("record_kind=?")
            values.append(kind)
        if vendor_id is not None:
            clauses.append("vendor_id=?")
            values.append(_id(vendor_id, "vendor_id"))
        if status is not None:
            selected_status = _id(status, "status")
            if selected_status not in CONTRACT_STATUSES | ENGAGEMENT_STATUSES:
                raise ThirdPartyContractValidationError("status is unsupported")
            clauses.append("status=?")
            values.append(selected_status)
        if owner_ref is not None:
            clauses.append("owner_ref=?")
            values.append(_id(owner_ref, "owner_ref"))
        query = (
            "SELECT record_json FROM third_party_contract_records WHERE "
            + " AND ".join(clauses)
            + " ORDER BY updated_at DESC,record_id LIMIT ?"
        )
        values.append(bounded)
        with self._connect() as connection:
            rows = connection.execute(query, tuple(values)).fetchall()
        return tuple(self._row_record(row) for row in rows)

    def context_record_count(self, tenant_id: str) -> int:
        """Return the tenant-exact current-head count for bounded projections."""

        self._require_tenant(tenant_id)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM third_party_contract_records "
                "WHERE tenant_sha256=?",
                (self._tenant_sha256,),
            ).fetchone()
        if row is None or not isinstance(row[0], int) or row[0] < 0:
            raise ThirdPartyContractIntegrityError(
                "contract record count is invalid"
            )
        return int(row[0])

    def history(
        self,
        tenant_id: str,
        record_id: str,
    ) -> tuple[ThirdPartyRecordHistory, ...]:
        record = self.get_record(tenant_id, record_id)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_json FROM third_party_contract_history "
                "WHERE tenant_sha256=? AND record_id=? ORDER BY revision",
                (self._tenant_sha256, record.record_id),
            ).fetchall()
        events: list[ThirdPartyRecordHistory] = []
        for row in rows:
            try:
                payload = json.loads(row["event_json"])
                nested = payload["record"]
                nested["vendor_jurisdiction_codes"] = tuple(nested["vendor_jurisdiction_codes"])
                nested["vendor_classification_refs"] = tuple(nested["vendor_classification_refs"])
                nested["field_schema"] = tuple(nested["field_schema"])
                nested["formulas"] = tuple(nested["formulas"])
                nested["sensitive_field_ids"] = tuple(nested["sensitive_field_ids"])
                payload["record"] = ThirdPartyRecord(**nested)
                payload["changed_fields"] = tuple(payload["changed_fields"])
                events.append(_normalize_history(ThirdPartyRecordHistory(**payload)))
            except ThirdPartyContractError:
                raise
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ThirdPartyContractIntegrityError("stored lifecycle history is invalid") from exc
        if not events or events[-1].record.integrity_sha256 != record.integrity_sha256:
            raise ThirdPartyContractIntegrityError("lifecycle history does not end at current state")
        previous: str | None = None
        for expected_revision, event in enumerate(events, 1):
            if event.revision != expected_revision or event.previous_event_sha256 != previous:
                raise ThirdPartyContractIntegrityError("lifecycle history chain is discontinuous")
            previous = event.event_sha256
        return tuple(events)

    @staticmethod
    def _authority_matches(record: ThirdPartyRecord, authority: VendorAuthority) -> bool:
        return (
            record.vendor_id == authority.vendor_id
            and record.vendor_revision == authority.vendor_revision
            and record.vendor_type == authority.vendor_type
            and record.vendor_criticality == authority.criticality
            and record.vendor_jurisdiction_codes == authority.jurisdiction_codes
            and record.vendor_classification_refs == authority.classification_refs
            and record.vendor_issuer_ref == authority.issuer_ref
        )

    def update_record(
        self,
        tenant_id: str,
        record_id: str,
        *,
        expected_revision: int,
        changes: Mapping[str, object],
        idempotency_key: str,
    ) -> ThirdPartyRecord:
        self._require_tenant(tenant_id)
        identifier = _id(record_id, "record_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2_147_483_647)
        key = _id(idempotency_key, "idempotency_key", operation=True)
        allowed = frozenset(
            {"title_ref", "owner_ref", "status", "lifecycle", "field_schema", "field_values", "formulas"}
        )
        if not isinstance(changes, Mapping) or not changes or not set(changes).issubset(allowed):
            raise ThirdPartyContractValidationError("record update schema is closed and non-empty")
        if any(not isinstance(name, str) for name in changes):
            raise ThirdPartyContractValidationError("record update keys must be strings")
        actor = self._actor()
        now = self._now()
        request_sha256 = _sha256(
            {
                "schema": "lightwork.third-party-contract-update-request.v1",
                "record_id": identifier,
                "expected_revision": expected,
                "changes": changes,
            }
        )
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._existing_operation(
                connection,
                idempotency_key=key,
                operation_type="update_record",
                request_sha256=request_sha256,
            )
            if replay is not None:
                if not isinstance(replay, ThirdPartyRecord):
                    raise ThirdPartyContractConflict("idempotent update result was deleted")
                return replay
            current = self._row_record(
                connection.execute(
                    "SELECT record_json FROM third_party_contract_records "
                    "WHERE tenant_sha256=? AND record_id=?",
                    (self._tenant_sha256, identifier),
                ).fetchone()
            )
            if current.revision != expected:
                raise ThirdPartyContractConflict("expected revision does not match")
            if current.status == ARCHIVED_STATUS:
                raise ThirdPartyContractConflict("archived records are immutable")
            authority = self._resolve_vendor(current.vendor_id, current.vendor_revision)
            if not self._authority_matches(current, authority):
                raise ThirdPartyContractConflict("persisted vendor authority metadata no longer matches")
            title = _id(changes.get("title_ref", current.title_ref), "title_ref")
            owner = _id(changes.get("owner_ref", current.owner_ref), "owner_ref")
            status = _id(changes.get("status", current.status), "status")
            transitions = (
                _CONTRACT_TRANSITIONS
                if current.record_kind == "contract"
                else _ENGAGEMENT_TRANSITIONS
            )
            if status != current.status and status not in transitions[current.status]:
                raise ThirdPartyContractConflict("lifecycle status transition is not allowed")
            lifecycle = _lifecycle(
                current.record_kind,
                changes.get("lifecycle", current.lifecycle),
            )
            fields = _field_schema(changes.get("field_schema", current.field_schema))
            values = _field_values(changes.get("field_values", current.field_values), fields)
            formulas = _formula_definitions(changes.get("formulas", current.formulas), fields)
            computed = _computed_values(formulas, values)
            self._validate_relationships(
                connection,
                kind=current.record_kind,
                vendor_id=current.vendor_id,
                lifecycle=lifecycle,
                record_id=current.record_id,
            )
            sensitive = tuple(
                sorted(
                    str(item["field_id"])
                    for item in fields
                    if item["sensitivity"] in {"confidential", "restricted"}
                )
            )
            archived_at = now if status == ARCHIVED_STATUS else None
            updated = replace(
                current,
                title_ref=title,
                owner_ref=owner,
                status=status,
                lifecycle=lifecycle,
                field_schema=tuple(fields),
                field_values=values,
                formulas=tuple(formulas),
                computed_values=computed,
                sensitive_field_ids=sensitive,
                updated_at=now,
                archived_at=archived_at,
                retained_until=now + self._retention_seconds,
                revision=current.revision + 1,
                previous_integrity_sha256=current.integrity_sha256,
                integrity_sha256="0" * 64,
            )
            updated = replace(updated, integrity_sha256=_record_integrity(updated))
            updated = _normalize_record(updated)
            previous_event = connection.execute(
                "SELECT event_sha256 FROM third_party_contract_history "
                "WHERE tenant_sha256=? AND record_id=? ORDER BY revision DESC LIMIT 1",
                (self._tenant_sha256, identifier),
            ).fetchone()
            if previous_event is None:
                raise ThirdPartyContractIntegrityError("current record lacks immutable history")
            changed = tuple(
                sorted(
                    name
                    for name in changes
                    if getattr(current, name) != getattr(updated, name)
                )
            )
            if not changed:
                raise ThirdPartyContractConflict("record update makes no change")
            connection.execute(
                "UPDATE third_party_contract_records SET owner_ref=?,status=?,updated_at=?,retained_until=?,"
                "revision=?,record_json=? WHERE tenant_sha256=? AND record_id=? AND revision=?",
                (
                    updated.owner_ref,
                    updated.status,
                    updated.updated_at,
                    updated.retained_until,
                    updated.revision,
                    _canonical(asdict(updated)).decode("ascii"),
                    self._tenant_sha256,
                    identifier,
                    expected,
                ),
            )
            self._insert_history(
                connection,
                record=updated,
                event_type=(
                    f"{updated.record_kind}_archived"
                    if updated.status == ARCHIVED_STATUS
                    else f"{updated.record_kind}_updated"
                ),
                actor_ref=actor,
                changed_fields=changed,
                previous_event_sha256=str(previous_event["event_sha256"]),
            )
            self._record_operation(
                connection,
                idempotency_key=key,
                operation_type="update_record",
                request_sha256=request_sha256,
                record_id=identifier,
                created_at=now,
            )
            connection.commit()
        return updated

    def archive_record(
        self,
        tenant_id: str,
        record_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ThirdPartyRecord:
        return self.update_record(
            tenant_id,
            record_id,
            expected_revision=expected_revision,
            changes={"status": ARCHIVED_STATUS},
            idempotency_key=idempotency_key,
        )

    def _delete_in_connection(
        self,
        connection: sqlite3.Connection,
        *,
        record: ThirdPartyRecord,
        actor: str,
        now: float,
    ) -> ThirdPartyRecordTombstone:
        if record.status != ARCHIVED_STATUS:
            raise ThirdPartyContractConflict("only archived records can be deleted")
        terminal = connection.execute(
            "SELECT event_sha256 FROM third_party_contract_history "
            "WHERE tenant_sha256=? AND record_id=? ORDER BY revision DESC LIMIT 1",
            (self._tenant_sha256, record.record_id),
        ).fetchone()
        if terminal is None:
            raise ThirdPartyContractIntegrityError("record lacks terminal history")
        tombstone = ThirdPartyRecordTombstone(
            schema=TOMBSTONE_SCHEMA,
            tenant_id=self.tenant_id,
            record_id=record.record_id,
            record_kind=record.record_kind,
            vendor_id=record.vendor_id,
            last_revision=record.revision,
            last_integrity_sha256=record.integrity_sha256,
            last_event_sha256=str(terminal["event_sha256"]),
            deleted_by_ref=actor,
            deleted_at=now,
            integrity_sha256="0" * 64,
        )
        tombstone = replace(tombstone, integrity_sha256=_sha256(_tombstone_body(tombstone)))
        tombstone = _normalize_tombstone(tombstone)
        connection.execute(
            "INSERT INTO third_party_contract_tombstones VALUES(?,?,?,?,?)",
            (
                self._tenant_sha256,
                record.record_id,
                _canonical(asdict(tombstone)).decode("ascii"),
                tombstone.integrity_sha256,
                tombstone.deleted_at,
            ),
        )
        self._maintenance.authorized = True
        try:
            removed = connection.execute(
                "DELETE FROM third_party_contract_records WHERE tenant_sha256=? AND record_id=?",
                (self._tenant_sha256, record.record_id),
            ).rowcount
        finally:
            self._maintenance.authorized = False
        if removed != 1:
            raise ThirdPartyContractConflict("record changed during deletion")
        return tombstone

    def delete_record(
        self,
        tenant_id: str,
        record_id: str,
        *,
        expected_revision: int,
        idempotency_key: str,
    ) -> ThirdPartyRecordTombstone:
        self._require_tenant(tenant_id)
        identifier = _id(record_id, "record_id")
        expected = _integer(expected_revision, "expected_revision", 1, 2_147_483_647)
        key = _id(idempotency_key, "idempotency_key", operation=True)
        actor = self._actor()
        request_sha256 = _sha256(
            {
                "schema": "lightwork.third-party-contract-delete-request.v1",
                "record_id": identifier,
                "expected_revision": expected,
            }
        )
        now = self._now()
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            replay = self._existing_operation(
                connection,
                idempotency_key=key,
                operation_type="delete_record",
                request_sha256=request_sha256,
            )
            if replay is not None:
                if not isinstance(replay, ThirdPartyRecordTombstone):
                    raise ThirdPartyContractConflict("idempotent delete has inconsistent state")
                return replay
            current = self._row_record(
                connection.execute(
                    "SELECT record_json FROM third_party_contract_records "
                    "WHERE tenant_sha256=? AND record_id=?",
                    (self._tenant_sha256, identifier),
                ).fetchone()
            )
            if current.revision != expected:
                raise ThirdPartyContractConflict("expected revision does not match")
            # Verify the exact current vendor authority before irreversible deletion.
            authority = self._resolve_vendor(current.vendor_id, current.vendor_revision)
            if not self._authority_matches(current, authority):
                raise ThirdPartyContractConflict("persisted vendor authority metadata no longer matches")
            self._verify_record_history(connection, current)
            if self._live_references(connection, current):
                raise ThirdPartyContractConflict(
                    "contract is still linked from an Engagement or a child Contract; "
                    "remove the link or archive that record first"
                )
            tombstone = self._delete_in_connection(
                connection,
                record=current,
                actor=actor,
                now=now,
            )
            self._record_operation(
                connection,
                idempotency_key=key,
                operation_type="delete_record",
                request_sha256=request_sha256,
                record_id=identifier,
                created_at=now,
            )
            connection.commit()
        return tombstone

    def retention_due(
        self,
        tenant_id: str,
        *,
        limit: int = 100,
    ) -> tuple[ThirdPartyRecord, ...]:
        self._require_tenant(tenant_id)
        bounded = _integer(limit, "limit", 1, 1_000)
        now = self._now()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM third_party_contract_records "
                "WHERE tenant_sha256=? AND status=? AND retained_until<=? "
                "ORDER BY retained_until,record_id LIMIT ?",
                (self._tenant_sha256, ARCHIVED_STATUS, now, bounded),
            ).fetchall()
        return tuple(self._row_record(row) for row in rows)

    def purge_expired(self, tenant_id: str, *, limit: int = 100) -> int:
        self._require_tenant(tenant_id)
        try:
            authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise ThirdPartyContractPermissionDenied("maintenance authority is unavailable") from exc
        if authorized is not True:
            raise ThirdPartyContractPermissionDenied("maintenance authority is required")
        actor = self._actor()
        bounded = _integer(limit, "limit", 1, 1_000)
        now = self._now()
        removed = 0
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT record_json FROM third_party_contract_records "
                "WHERE tenant_sha256=? AND status=? AND retained_until<=? "
                "ORDER BY retained_until,record_id LIMIT ?",
                (self._tenant_sha256, ARCHIVED_STATUS, now, bounded),
            ).fetchall()
            for row in rows:
                record = self._row_record(row)
                self._verify_record_history(connection, record)
                if self._live_references(connection, record):
                    # Still linked from a live record; it stays due and is
                    # purged once the link is removed.
                    continue
                self._delete_in_connection(connection, record=record, actor=actor, now=now)
                removed += 1
            connection.commit()
        return removed

    def _verify_record_history(
        self,
        connection: sqlite3.Connection,
        record: ThirdPartyRecord,
    ) -> int:
        rows = connection.execute(
            "SELECT event_json FROM third_party_contract_history "
            "WHERE tenant_sha256=? AND record_id=? ORDER BY revision",
            (self._tenant_sha256, record.record_id),
        ).fetchall()
        previous: str | None = None
        terminal: ThirdPartyRecordHistory | None = None
        for expected_revision, row in enumerate(rows, 1):
            try:
                payload = json.loads(row["event_json"])
                nested = payload["record"]
                nested["vendor_jurisdiction_codes"] = tuple(nested["vendor_jurisdiction_codes"])
                nested["vendor_classification_refs"] = tuple(nested["vendor_classification_refs"])
                nested["field_schema"] = tuple(nested["field_schema"])
                nested["formulas"] = tuple(nested["formulas"])
                nested["sensitive_field_ids"] = tuple(nested["sensitive_field_ids"])
                payload["record"] = ThirdPartyRecord(**nested)
                payload["changed_fields"] = tuple(payload["changed_fields"])
                event = _normalize_history(ThirdPartyRecordHistory(**payload))
            except ThirdPartyContractError:
                raise
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ThirdPartyContractIntegrityError("stored lifecycle history is invalid") from exc
            if event.revision != expected_revision or event.previous_event_sha256 != previous:
                raise ThirdPartyContractIntegrityError("lifecycle history chain is discontinuous")
            previous = event.event_sha256
            terminal = event
        if terminal is None or terminal.record.integrity_sha256 != record.integrity_sha256:
            raise ThirdPartyContractIntegrityError("lifecycle history does not end at current state")
        return len(rows)

    def verify_integrity(self, tenant_id: str) -> dict[str, object]:
        self._require_tenant(tenant_id)
        records = 0
        events = 0
        tombstones = 0
        terminal_digests: list[str] = []
        try:
            with self._connect() as connection:
                quick = connection.execute("PRAGMA quick_check").fetchone()
                if quick is None or quick[0] != "ok":
                    raise ThirdPartyContractIntegrityError("SQLite quick_check failed")
                rows = connection.execute(
                    "SELECT record_json FROM third_party_contract_records "
                    "WHERE tenant_sha256=? ORDER BY record_id",
                    (self._tenant_sha256,),
                ).fetchall()
                for row in rows:
                    record = self._row_record(row)
                    events += self._verify_record_history(connection, record)
                    records += 1
                    terminal_digests.append(record.integrity_sha256)
                rows = connection.execute(
                    "SELECT tombstone_json FROM third_party_contract_tombstones "
                    "WHERE tenant_sha256=? ORDER BY record_id",
                    (self._tenant_sha256,),
                ).fetchall()
                for row in rows:
                    tombstone = self._row_tombstone(row)
                    tombstones += 1
                    terminal_digests.append(tombstone.integrity_sha256)
                operation_rows = connection.execute(
                    "SELECT idempotency_sha256,operation_type,request_sha256,record_id,created_at "
                    "FROM third_party_contract_operations WHERE tenant_sha256=?",
                    (self._tenant_sha256,),
                ).fetchall()
                for row in operation_rows:
                    _digest(row["idempotency_sha256"], "idempotency_sha256")
                    _id(row["operation_type"], "operation_type")
                    _digest(row["request_sha256"], "request_sha256")
                    operation_record = _id(row["record_id"], "record_id")
                    _timestamp(row["created_at"], "operation created_at")
                    if connection.execute(
                        "SELECT 1 FROM third_party_contract_records "
                        "WHERE tenant_sha256=? AND record_id=? UNION ALL "
                        "SELECT 1 FROM third_party_contract_tombstones "
                        "WHERE tenant_sha256=? AND record_id=?",
                        (
                            self._tenant_sha256,
                            operation_record,
                            self._tenant_sha256,
                            operation_record,
                        ),
                    ).fetchone() is None:
                        raise ThirdPartyContractIntegrityError(
                            "idempotent operation result is unavailable"
                        )
        except ThirdPartyContractError:
            raise
        except (sqlite3.DatabaseError, OSError) as exc:
            raise ThirdPartyContractIntegrityError("Contract database verification failed") from exc
        return {
            "schema": INTEGRITY_SCHEMA,
            "tenant_id": self.tenant_id,
            "records_verified": records,
            "history_events_verified": events,
            "tombstones_verified": tombstones,
            "operations_verified": len(operation_rows),
            "terminal_set_sha256": _sha256(sorted(terminal_digests)),
            "verified": True,
        }

    def create_recovery_backup(
        self,
        tenant_id: str,
        destination: str | Path,
    ) -> dict[str, object]:
        """Create and verify a SQLite hot backup under maintenance authority."""

        self._require_tenant(tenant_id)
        try:
            authorized = self._maintenance_authorizer()
        except Exception as exc:
            raise ThirdPartyContractPermissionDenied("maintenance authority is unavailable") from exc
        if authorized is not True:
            raise ThirdPartyContractPermissionDenied("maintenance authority is required")
        self.verify_integrity(tenant_id)
        target = Path(destination).resolve()
        source = self.path.resolve()
        if target == source or target.exists() or target.parent == source.parent and target.name == source.name:
            raise ThirdPartyContractValidationError("recovery destination must be a new distinct file")
        ensure_private_directory(target.parent)
        try:
            with cross_process_lock(self.path, strict=True), self._connect() as source_connection:
                with sqlite3.connect(target, factory=ClosingConnection) as destination_connection:
                    source_connection.backup(destination_connection)
                    check = destination_connection.execute("PRAGMA quick_check").fetchone()
                    if check is None or check[0] != "ok":
                        raise ThirdPartyContractIntegrityError("recovery backup verification failed")
            ensure_private_file(target)
            with open(target, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
        except (ThirdPartyContractIntegrityError, OSError, sqlite3.DatabaseError) as exc:
            try:
                target.unlink(missing_ok=True)
            except OSError:
                pass
            raise ThirdPartyContractIntegrityError("recovery backup creation failed") from exc
        return {
            "schema": RECOVERY_SCHEMA,
            "tenant_id": self.tenant_id,
            "backup_path": str(target),
            "backup_sha256": digest,
            "created_at": self._now(),
            "source_integrity_verified": True,
        }


__all__ = [
    "AUTHORITY_SCHEMA",
    "CONTRACT_STATUSES",
    "CONTRACT_TYPES",
    "CRITICALITIES",
    "ENGAGEMENT_STATUSES",
    "ENGAGEMENT_TYPES",
    "FIELD_TYPES",
    "FORMULA_OPERATORS",
    "HISTORY_SCHEMA",
    "HOSTING_MODELS",
    "INTEGRITY_SCHEMA",
    "LICENSED_TEMPLATE_CONTENT_INCLUDED",
    "LIVE_PROVIDER_ACCEPTANCE_VERIFIED",
    "LIVE_PROVIDER_OPERATIONS",
    "RECORD_KINDS",
    "RECORD_SCHEMA",
    "RECOVERY_SCHEMA",
    "RENEWAL_MODES",
    "SCHEMA_VERSION",
    "SENSITIVITIES",
    "TOMBSTONE_SCHEMA",
    "VENDOR_TYPES",
    "ThirdPartyContractConfigError",
    "ThirdPartyContractConflict",
    "ThirdPartyContractError",
    "ThirdPartyContractIntegrityError",
    "ThirdPartyContractNotFound",
    "ThirdPartyContractPermissionDenied",
    "ThirdPartyContractStore",
    "ThirdPartyContractValidationError",
    "ThirdPartyRecord",
    "ThirdPartyRecordHistory",
    "ThirdPartyRecordTombstone",
    "VendorAuthority",
    "enabled",
    "issue_vendor_authority",
    "redacted_record",
    "require_enabled",
]
