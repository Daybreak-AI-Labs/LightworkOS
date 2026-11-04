"""Tenant-private no-code GRC configuration authority.

The studio accepts one closed declarative language for objects, fields, forms,
rules, continuous-evidence bindings and report views.  It deliberately cannot
carry executable code, expressions, templates, HTML, CSS, URLs, credentials or
provider configuration.  Published definitions are immutable content-addressed
authorities; runtime consumers receive a projection only after an independently
resolved target authority is bound to the exact published blueprint digest.

Lifecycle transitions are compare-and-swap and idempotent::

    draft -> in_review -> reviewed -> approved -> published -> superseded
                         -> rejected

Review and approval require three distinct principals: author, reviewer and
approver.  A rollback changes the active pointer to an already-approved
historical release; it never accepts or synthesizes new definition content.
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
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .file_lock import (
    atomic_create_bytes,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import canonical_tenant_id
from .sqlite_closing import ClosingConnection

SCHEMA_VERSION = 2
BLUEPRINT_SCHEMA = "lightwork.no-code-grc-blueprint.v1"
VERSION_SCHEMA = "lightwork.no-code-grc-version.v1"
ACTIVE_SCHEMA = "lightwork.no-code-grc-active-pointer.v1"
EXPORT_SCHEMA = "lightwork.no-code-grc-export.v1"
RECOVERY_SCHEMA = "lightwork.no-code-grc-recovery.v1"
TARGET_AUTHORITY_SCHEMA = "lightwork.no-code-grc-target-authority.v1"
PROJECTION_SCHEMA = "lightwork.no-code-grc-runtime-projection.v1"
APPLY_RECEIPT_SCHEMA = "lightwork.no-code-grc-apply-receipt.v1"

ARBITRARY_CODE_SUPPORTED = False
ARBITRARY_HTML_CSS_SUPPORTED = False
CALLER_URLS_SUPPORTED = False
LIVE_PROVIDER_ACCEPTANCE_VERIFIED = False

STATES = frozenset(
    {"draft", "in_review", "reviewed", "rejected", "approved", "published", "superseded"}
)
OBJECT_KINDS = frozenset(
    {"asset", "assessment", "control", "evidence", "issue", "policy", "risk", "vendor", "custom"}
)
FIELD_TYPES = frozenset(
    {
        "boolean",
        "date",
        "decimal",
        "digest",
        "evidence_ref",
        "integer",
        "multi_choice",
        "record_ref",
        "single_choice",
        "text_ref",
        "timestamp",
    }
)
SENSITIVITIES = frozenset({"public", "internal", "confidential", "restricted"})
CONDITION_OPERATORS = frozenset(
    {
        "equals",
        "not_equals",
        "greater_than",
        "greater_or_equal",
        "less_than",
        "less_or_equal",
        "contains",
        "is_set",
    }
)
ACTION_TYPES = frozenset(
    {"set_default", "set_required", "set_visibility", "set_severity", "emit_task_ref"}
)
TARGET_KINDS = frozenset({"questionnaire", "collector", "report"})
PROJECTION_KINDS = TARGET_KINDS

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_OP_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_JSON_BYTES = 1024 * 1024
_MAX_IMPORT_BYTES = 2 * 1024 * 1024
_MAX_OBJECTS = 256
_MAX_FIELDS = 512
_MAX_FORMS = 256
_MAX_SECTIONS = 128
_MAX_RULES = 512
_MAX_CONDITIONS = 64
_MAX_ACTIONS = 64
_MAX_BINDINGS = 256
_MAX_MAPPINGS = 256
_MAX_REPORTS = 256
_MAX_STUDIOS = 10_000
_MIN_RETENTION_SECONDS = 86_400
_MAX_RETENTION_SECONDS = 315_360_000


class GRCStudioError(RuntimeError):
    """Base error for the no-code GRC studio."""


class GRCStudioConfigError(GRCStudioError):
    """The capability or a deployment-owned dependency is unavailable."""


class GRCStudioValidationError(GRCStudioError, ValueError):
    """Caller input is outside the closed bounded DSL."""


class GRCStudioConflict(GRCStudioError):
    """A compare-and-swap, idempotency, or lifecycle precondition failed."""


class GRCStudioNotFound(GRCStudioError):
    """A tenant-private definition is absent or deliberately undisclosed."""


class GRCStudioPermissionDenied(GRCStudioError):
    """Current principal or maintenance authority is insufficient."""


class GRCStudioIntegrityError(GRCStudioError):
    """Persisted or supplied integrity evidence failed verification."""


def enabled(config: Mapping[str, Any] | None = None) -> bool:
    """Return true only for the exact parent and child config gates."""

    try:
        if config is None:
            from .config import config_source_errors, load_config

            if config_source_errors():
                return False
            config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    parent = config.get("tech_risk_compliance")
    child = parent.get("grc_studio") if isinstance(parent, Mapping) else None
    return (
        isinstance(parent, Mapping)
        and parent.get("enable") is True
        and isinstance(child, Mapping)
        and child.get("enable") is True
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
        raise GRCStudioValidationError("value must be finite canonical JSON") from exc
    if not 1 <= len(encoded) <= maximum:
        raise GRCStudioValidationError("canonical JSON exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise GRCStudioValidationError("tenant_id is invalid") from exc


def _id(value: object, label: str, *, operation: bool = False) -> str:
    pattern = _OP_RE if operation else _ID_RE
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise GRCStudioValidationError(f"{label} must be a bounded opaque identifier")
    return value


def _optional_id(value: object, label: str) -> str | None:
    return None if value is None else _id(value, label)


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise GRCStudioValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise GRCStudioValidationError(f"{label} must be between {lower} and {upper}")
    return value


def _timestamp(value: object, label: str, *, optional: bool = False) -> float | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GRCStudioValidationError(f"{label} must be a timestamp")
    number = float(value)
    if not math.isfinite(number) or not 0 < number < 100_000_000_000:
        raise GRCStudioValidationError(f"{label} must be a positive finite timestamp")
    return number


def _sequence(value: object, label: str, *, maximum: int, minimum: int = 0) -> Sequence[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise GRCStudioValidationError(f"{label} must be a list")
    if not minimum <= len(value) <= maximum:
        raise GRCStudioValidationError(f"{label} is outside its item bound")
    return value


def _closed(value: object, label: str, keys: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise GRCStudioValidationError(f"{label} must be an object")
    if set(value) != keys:
        raise GRCStudioValidationError(f"{label} schema is closed")
    return value


def _ids(value: object, label: str, *, maximum: int, minimum: int = 0) -> tuple[str, ...]:
    values = tuple(
        _id(item, label) for item in _sequence(value, label, maximum=maximum, minimum=minimum)
    )
    if len(set(values)) != len(values):
        raise GRCStudioValidationError(f"{label} contains duplicates")
    return values


def _literal(value: object, label: str) -> bool | int | float | str | None:
    if value is None or type(value) is bool:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 1_000_000_000_000:
            raise GRCStudioValidationError(f"{label} integer is outside its bound")
        return value
    if isinstance(value, float):
        if not math.isfinite(value) or abs(value) > 1_000_000_000_000:
            raise GRCStudioValidationError(f"{label} decimal is outside its bound")
        return value
    if isinstance(value, str):
        return _id(value, label)
    raise GRCStudioValidationError(f"{label} literal type is unsupported")


def _validate_field_literal(
    field: Mapping[str, object],
    literal: bool | int | float | str | None,
    label: str,
    *,
    collection_member: bool = False,
) -> None:
    """Reject declarative values that cannot be consumed by the target field."""

    field_type = str(field["field_type"])
    if literal is None:
        return
    if field_type == "boolean" and type(literal) is not bool:
        raise GRCStudioValidationError(f"{label} is incompatible with a boolean field")
    if field_type == "integer" and type(literal) is not int:
        raise GRCStudioValidationError(f"{label} is incompatible with an integer field")
    if field_type == "decimal" and not (
        isinstance(literal, (int, float)) and not isinstance(literal, bool)
    ):
        raise GRCStudioValidationError(f"{label} is incompatible with a decimal field")
    if field_type == "timestamp":
        _timestamp(literal, label)
    if field_type in {
        "date",
        "digest",
        "evidence_ref",
        "record_ref",
        "single_choice",
        "text_ref",
    } and not isinstance(literal, str):
        raise GRCStudioValidationError(f"{label} requires an opaque string value")
    if field_type == "digest" and isinstance(literal, str):
        _digest(literal, label)
    if field_type == "single_choice" and literal not in field["options"]:
        raise GRCStudioValidationError(f"{label} is outside the field options")
    if field_type == "multi_choice":
        if not collection_member or not isinstance(literal, str):
            raise GRCStudioValidationError(
                f"{label} requires a bounded collection-member operation"
            )
        if literal not in field["options"]:
            raise GRCStudioValidationError(f"{label} is outside the field options")


def _validate_condition_literal(
    field: Mapping[str, object],
    operator: str,
    literal: bool | int | float | str | None,
    label: str,
) -> None:
    if operator == "is_set":
        if literal is not None:
            raise GRCStudioValidationError(f"{label} is_set value must be null")
        return
    if literal is None:
        raise GRCStudioValidationError(f"{label} requires a bounded literal")
    field_type = str(field["field_type"])
    if operator == "contains":
        if field_type != "multi_choice":
            raise GRCStudioValidationError(f"{label} contains is limited to multi-choice fields")
        _validate_field_literal(field, literal, label, collection_member=True)
        return
    if operator in {"greater_than", "greater_or_equal", "less_than", "less_or_equal"}:
        if field_type not in {"integer", "decimal", "timestamp"}:
            raise GRCStudioValidationError(
                f"{label} ordering requires a numeric or timestamp field"
            )
    if field_type == "multi_choice":
        raise GRCStudioValidationError(f"{label} multi-choice fields require contains or is_set")
    _validate_field_literal(field, literal, label)


def _field(value: object) -> dict[str, object]:
    item = _closed(
        value,
        "field",
        frozenset(
            {
                "field_id",
                "label_ref",
                "field_type",
                "required",
                "sensitivity",
                "options",
                "reference_kind",
                "default",
            }
        ),
    )
    field_type = _id(item["field_type"], "field_type")
    sensitivity = _id(item["sensitivity"], "sensitivity")
    if field_type not in FIELD_TYPES or sensitivity not in SENSITIVITIES:
        raise GRCStudioValidationError("field type or sensitivity is unsupported")
    if type(item["required"]) is not bool:
        raise GRCStudioValidationError("field required must be boolean")
    options = _ids(item["options"], "field option", maximum=256)
    reference_kind = _optional_id(item["reference_kind"], "reference_kind")
    if field_type in {"single_choice", "multi_choice"}:
        if not options:
            raise GRCStudioValidationError("choice fields require options")
    elif options:
        raise GRCStudioValidationError("non-choice fields cannot carry options")
    if field_type in {"record_ref", "evidence_ref"}:
        if reference_kind is None:
            raise GRCStudioValidationError("reference fields require reference_kind")
    elif reference_kind is not None:
        raise GRCStudioValidationError("only reference fields accept reference_kind")
    default = _literal(item["default"], "field default")
    if default is not None:
        if field_type == "boolean" and type(default) is not bool:
            raise GRCStudioValidationError("boolean default is invalid")
        if field_type == "integer" and (type(default) is not int):
            raise GRCStudioValidationError("integer default is invalid")
        if field_type == "decimal" and not (
            isinstance(default, (int, float)) and not isinstance(default, bool)
        ):
            raise GRCStudioValidationError("decimal default is invalid")
        if field_type in {
            "single_choice",
            "text_ref",
            "digest",
            "record_ref",
            "evidence_ref",
            "date",
        }:
            if not isinstance(default, str):
                raise GRCStudioValidationError("reference-like default is invalid")
            if field_type == "single_choice" and default not in options:
                raise GRCStudioValidationError("choice default is outside options")
        if field_type in {"multi_choice", "timestamp"}:
            raise GRCStudioValidationError(f"{field_type} fields cannot carry a scalar default")
        if field_type == "digest":
            _digest(default, "digest default")
    return {
        "field_id": _id(item["field_id"], "field_id"),
        "label_ref": _id(item["label_ref"], "field label_ref"),
        "field_type": field_type,
        "required": item["required"],
        "sensitivity": sensitivity,
        "options": list(options),
        "reference_kind": reference_kind,
        "default": default,
    }


def validate_blueprint(  # noqa: C901
    value: object, *, expected_studio_id: str | None = None
) -> dict[str, object]:
    """Validate and normalize the complete closed no-code DSL."""

    root = _closed(
        value,
        "blueprint",
        frozenset(
            {
                "schema",
                "studio_id",
                "name_ref",
                "description_ref",
                "objects",
                "forms",
                "rules",
                "collector_bindings",
                "report_views",
            }
        ),
    )
    if root["schema"] != BLUEPRINT_SCHEMA:
        raise GRCStudioValidationError("blueprint schema is unsupported")
    studio_id = _id(root["studio_id"], "studio_id")
    if expected_studio_id is not None and studio_id != _id(expected_studio_id, "studio_id"):
        raise GRCStudioValidationError("blueprint studio_id does not match its authority")

    objects: list[dict[str, object]] = []
    field_indexes: dict[str, dict[str, dict[str, object]]] = {}
    for raw in _sequence(root["objects"], "objects", maximum=_MAX_OBJECTS, minimum=1):
        item = _closed(
            raw,
            "object definition",
            frozenset({"object_id", "kind", "label_ref", "description_ref", "fields"}),
        )
        object_id = _id(item["object_id"], "object_id")
        kind = _id(item["kind"], "object kind")
        if kind not in OBJECT_KINDS:
            raise GRCStudioValidationError("object kind is unsupported")
        fields = [
            _field(field)
            for field in _sequence(item["fields"], "fields", maximum=_MAX_FIELDS, minimum=1)
        ]
        ids = [str(field["field_id"]) for field in fields]
        if len(set(ids)) != len(ids):
            raise GRCStudioValidationError("field_id must be unique within an object")
        if object_id in field_indexes:
            raise GRCStudioValidationError("object_id must be unique")
        field_indexes[object_id] = {str(field["field_id"]): field for field in fields}
        objects.append(
            {
                "object_id": object_id,
                "kind": kind,
                "label_ref": _id(item["label_ref"], "object label_ref"),
                "description_ref": _optional_id(item["description_ref"], "object description_ref"),
                "fields": fields,
            }
        )

    forms: list[dict[str, object]] = []
    form_ids: set[str] = set()
    for raw in _sequence(root["forms"], "forms", maximum=_MAX_FORMS):
        item = _closed(raw, "form", frozenset({"form_id", "object_id", "title_ref", "sections"}))
        form_id = _id(item["form_id"], "form_id")
        object_id = _id(item["object_id"], "form object_id")
        if form_id in form_ids or object_id not in field_indexes:
            raise GRCStudioValidationError("form identity or object reference is invalid")
        form_ids.add(form_id)
        sections: list[dict[str, object]] = []
        seen_sections: set[str] = set()
        covered: set[str] = set()
        for section_raw in _sequence(
            item["sections"], "form sections", maximum=_MAX_SECTIONS, minimum=1
        ):
            section = _closed(
                section_raw, "form section", frozenset({"section_id", "label_ref", "field_ids"})
            )
            section_id = _id(section["section_id"], "section_id")
            field_ids = _ids(
                section["field_ids"], "section field_id", maximum=_MAX_FIELDS, minimum=1
            )
            if section_id in seen_sections or any(
                field not in field_indexes[object_id] for field in field_ids
            ):
                raise GRCStudioValidationError(
                    "form section identity or field reference is invalid"
                )
            if covered.intersection(field_ids):
                raise GRCStudioValidationError("form field appears in more than one section")
            seen_sections.add(section_id)
            covered.update(field_ids)
            sections.append(
                {
                    "section_id": section_id,
                    "label_ref": _id(section["label_ref"], "section label_ref"),
                    "field_ids": list(field_ids),
                }
            )
        forms.append(
            {
                "form_id": form_id,
                "object_id": object_id,
                "title_ref": _id(item["title_ref"], "form title_ref"),
                "sections": sections,
            }
        )

    rules: list[dict[str, object]] = []
    rule_ids: set[str] = set()
    for raw in _sequence(root["rules"], "rules", maximum=_MAX_RULES):
        item = _closed(raw, "rule", frozenset({"rule_id", "object_id", "when", "then"}))
        rule_id = _id(item["rule_id"], "rule_id")
        object_id = _id(item["object_id"], "rule object_id")
        if rule_id in rule_ids or object_id not in field_indexes:
            raise GRCStudioValidationError("rule identity or object reference is invalid")
        rule_ids.add(rule_id)
        when = _closed(item["when"], "rule condition group", frozenset({"mode", "conditions"}))
        mode = _id(when["mode"], "condition mode")
        if mode not in {"all", "any"}:
            raise GRCStudioValidationError("condition mode is unsupported")
        conditions: list[dict[str, object]] = []
        for condition_raw in _sequence(
            when["conditions"], "conditions", maximum=_MAX_CONDITIONS, minimum=1
        ):
            condition = _closed(
                condition_raw, "condition", frozenset({"field_id", "operator", "value"})
            )
            field_id = _id(condition["field_id"], "condition field_id")
            operator = _id(condition["operator"], "condition operator")
            if field_id not in field_indexes[object_id] or operator not in CONDITION_OPERATORS:
                raise GRCStudioValidationError("condition field or operator is unsupported")
            literal = _literal(condition["value"], "condition value")
            _validate_condition_literal(
                field_indexes[object_id][field_id],
                operator,
                literal,
                "condition value",
            )
            conditions.append({"field_id": field_id, "operator": operator, "value": literal})
        actions: list[dict[str, object]] = []
        action_ids: set[str] = set()
        for action_raw in _sequence(item["then"], "actions", maximum=_MAX_ACTIONS, minimum=1):
            action = _closed(
                action_raw,
                "action",
                frozenset({"action_id", "action_type", "target_field_id", "value"}),
            )
            action_id = _id(action["action_id"], "action_id")
            action_type = _id(action["action_type"], "action_type")
            target_field_id = _optional_id(action["target_field_id"], "target_field_id")
            if action_id in action_ids or action_type not in ACTION_TYPES:
                raise GRCStudioValidationError("action identity or type is unsupported")
            action_ids.add(action_id)
            if action_type == "emit_task_ref":
                if target_field_id is not None:
                    raise GRCStudioValidationError("emit_task_ref cannot target a field")
            elif target_field_id not in field_indexes[object_id]:
                raise GRCStudioValidationError("action target field is invalid")
            literal = _literal(action["value"], "action value")
            if action_type in {"set_required", "set_visibility"} and type(literal) is not bool:
                raise GRCStudioValidationError("boolean action requires a boolean value")
            if action_type in {"set_severity", "emit_task_ref"} and not isinstance(literal, str):
                raise GRCStudioValidationError("reference action requires an opaque reference")
            if action_type == "set_default":
                assert target_field_id is not None
                _validate_field_literal(
                    field_indexes[object_id][target_field_id],
                    literal,
                    "default action value",
                )
            actions.append(
                {
                    "action_id": action_id,
                    "action_type": action_type,
                    "target_field_id": target_field_id,
                    "value": literal,
                }
            )
        rules.append(
            {
                "rule_id": rule_id,
                "object_id": object_id,
                "when": {"mode": mode, "conditions": conditions},
                "then": actions,
            }
        )

    bindings: list[dict[str, object]] = []
    binding_ids: set[str] = set()
    for raw in _sequence(root["collector_bindings"], "collector_bindings", maximum=_MAX_BINDINGS):
        item = _closed(
            raw,
            "collector binding",
            frozenset(
                {
                    "binding_id",
                    "collector_id",
                    "collector_version",
                    "collector_integrity_sha256",
                    "object_id",
                    "field_mappings",
                    "control_refs",
                }
            ),
        )
        binding_id = _id(item["binding_id"], "binding_id")
        object_id = _id(item["object_id"], "binding object_id")
        if binding_id in binding_ids or object_id not in field_indexes:
            raise GRCStudioValidationError("collector binding identity or object is invalid")
        binding_ids.add(binding_id)
        mappings: list[dict[str, object]] = []
        targets: set[str] = set()
        for map_raw in _sequence(
            item["field_mappings"], "field_mappings", maximum=_MAX_MAPPINGS, minimum=1
        ):
            mapping = _closed(
                map_raw, "field mapping", frozenset({"source_path", "target_field_id", "mode"})
            )
            target = _id(mapping["target_field_id"], "mapping target_field_id")
            mode = _id(mapping["mode"], "mapping mode")
            source_path = _ids(mapping["source_path"], "source path segment", maximum=16, minimum=1)
            if (
                target not in field_indexes[object_id]
                or target in targets
                or mode not in {"replace", "append"}
            ):
                raise GRCStudioValidationError("collector field mapping is invalid")
            targets.add(target)
            mappings.append(
                {"source_path": list(source_path), "target_field_id": target, "mode": mode}
            )
        bindings.append(
            {
                "binding_id": binding_id,
                "collector_id": _id(item["collector_id"], "collector_id"),
                "collector_version": _integer(
                    item["collector_version"], "collector_version", 1, 2_147_483_647
                ),
                "collector_integrity_sha256": _digest(
                    item["collector_integrity_sha256"], "collector_integrity_sha256"
                ),
                "object_id": object_id,
                "field_mappings": mappings,
                "control_refs": list(
                    _ids(item["control_refs"], "control_ref", maximum=512, minimum=1)
                ),
            }
        )

    reports: list[dict[str, object]] = []
    report_ids: set[str] = set()
    for raw in _sequence(root["report_views"], "report_views", maximum=_MAX_REPORTS):
        item = _closed(
            raw,
            "report view",
            frozenset(
                {"view_id", "object_id", "title_ref", "columns", "filters", "group_by", "sort"}
            ),
        )
        view_id = _id(item["view_id"], "view_id")
        object_id = _id(item["object_id"], "report object_id")
        if view_id in report_ids or object_id not in field_indexes:
            raise GRCStudioValidationError("report identity or object reference is invalid")
        report_ids.add(view_id)
        columns = _ids(item["columns"], "report column", maximum=_MAX_FIELDS, minimum=1)
        if any(column not in field_indexes[object_id] for column in columns):
            raise GRCStudioValidationError("report column does not exist")
        filters: list[dict[str, object]] = []
        for filter_raw in _sequence(item["filters"], "report filters", maximum=_MAX_CONDITIONS):
            report_filter = _closed(
                filter_raw, "report filter", frozenset({"field_id", "operator", "value"})
            )
            field_id = _id(report_filter["field_id"], "report filter field_id")
            operator = _id(report_filter["operator"], "report filter operator")
            if field_id not in field_indexes[object_id] or operator not in CONDITION_OPERATORS:
                raise GRCStudioValidationError("report filter is invalid")
            literal = _literal(report_filter["value"], "report filter value")
            _validate_condition_literal(
                field_indexes[object_id][field_id],
                operator,
                literal,
                "report filter value",
            )
            filters.append({"field_id": field_id, "operator": operator, "value": literal})
        group_by = _ids(item["group_by"], "report group_by", maximum=16)
        if any(field not in field_indexes[object_id] for field in group_by):
            raise GRCStudioValidationError("report group_by field does not exist")
        sort: list[dict[str, object]] = []
        sort_fields: set[str] = set()
        for sort_raw in _sequence(item["sort"], "report sort", maximum=16):
            sort_item = _closed(sort_raw, "report sort item", frozenset({"field_id", "direction"}))
            field_id = _id(sort_item["field_id"], "sort field_id")
            direction = _id(sort_item["direction"], "sort direction")
            if (
                field_id not in field_indexes[object_id]
                or field_id in sort_fields
                or direction not in {"ascending", "descending"}
            ):
                raise GRCStudioValidationError("report sort is invalid")
            sort_fields.add(field_id)
            sort.append({"field_id": field_id, "direction": direction})
        reports.append(
            {
                "view_id": view_id,
                "object_id": object_id,
                "title_ref": _id(item["title_ref"], "report title_ref"),
                "columns": list(columns),
                "filters": filters,
                "group_by": list(group_by),
                "sort": sort,
            }
        )

    normalized = {
        "schema": BLUEPRINT_SCHEMA,
        "studio_id": studio_id,
        "name_ref": _id(root["name_ref"], "name_ref"),
        "description_ref": _optional_id(root["description_ref"], "description_ref"),
        "objects": objects,
        "forms": forms,
        "rules": rules,
        "collector_bindings": bindings,
        "report_views": reports,
    }
    _canonical(normalized)
    return normalized


@dataclass(frozen=True, slots=True)
class StudioVersion:
    schema: str
    tenant_id: str
    studio_id: str
    version: int
    revision: int
    state: str
    blueprint: Mapping[str, object]
    blueprint_sha256: str
    created_by_ref: str
    reviewed_by_ref: str | None
    approved_by_ref: str | None
    published_by_ref: str | None
    created_at: float
    updated_at: float
    reviewed_at: float | None
    approved_at: float | None
    published_at: float | None
    retention_due_at: float | None
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class ActivePointer:
    schema: str
    tenant_id: str
    studio_id: str
    active_version: int
    active_blueprint_sha256: str
    revision: int
    updated_at: float
    integrity_sha256: str


@dataclass(frozen=True, slots=True)
class RuntimeTargetAuthority:
    schema: str
    tenant_id: str
    target_kind: str
    target_id: str
    target_revision: int
    target_integrity_sha256: str
    allowed_blueprint_sha256: str
    valid_until: float
    authority_sha256: str

    def normalized(self) -> RuntimeTargetAuthority:
        body = {
            "schema": TARGET_AUTHORITY_SCHEMA,
            "tenant_id": _tenant(self.tenant_id),
            "target_kind": _id(self.target_kind, "target_kind"),
            "target_id": _id(self.target_id, "target_id"),
            "target_revision": _integer(self.target_revision, "target_revision", 1, 2_147_483_647),
            "target_integrity_sha256": _digest(
                self.target_integrity_sha256, "target_integrity_sha256"
            ),
            "allowed_blueprint_sha256": _digest(
                self.allowed_blueprint_sha256, "allowed_blueprint_sha256"
            ),
            "valid_until": _timestamp(self.valid_until, "valid_until"),
        }
        if body["target_kind"] not in TARGET_KINDS:
            raise GRCStudioValidationError("target kind is unsupported")
        expected = _sha256(body)
        if not hmac.compare_digest(_digest(self.authority_sha256, "authority_sha256"), expected):
            raise GRCStudioIntegrityError("runtime target authority digest changed")
        return RuntimeTargetAuthority(**body, authority_sha256=expected)


def issue_runtime_target_authority(
    *,
    tenant_id: str,
    target_kind: str,
    target_id: str,
    target_revision: int,
    target_integrity_sha256: str,
    allowed_blueprint_sha256: str,
    valid_until: float,
) -> RuntimeTargetAuthority:
    body = {
        "schema": TARGET_AUTHORITY_SCHEMA,
        "tenant_id": _tenant(tenant_id),
        "target_kind": _id(target_kind, "target_kind"),
        "target_id": _id(target_id, "target_id"),
        "target_revision": _integer(target_revision, "target_revision", 1, 2_147_483_647),
        "target_integrity_sha256": _digest(target_integrity_sha256, "target_integrity_sha256"),
        "allowed_blueprint_sha256": _digest(allowed_blueprint_sha256, "allowed_blueprint_sha256"),
        "valid_until": _timestamp(valid_until, "valid_until"),
    }
    return RuntimeTargetAuthority(**body, authority_sha256=_sha256(body)).normalized()


class GRCStudioStore:
    """Private per-tenant SQLite authority for governed no-code definitions."""

    def __init__(
        self,
        path: str | Path,
        *,
        tenant_id: str,
        integrity_key: bytes,
        principal_resolver: Callable[[], str],
        maintenance_authorizer: Callable[[], bool],
        config_gate: Callable[[], None],
        clock: Callable[[], float] = time.time,
        max_studios: int = _MAX_STUDIOS,
        retention_seconds: int = 31_536_000,
        max_import_bytes: int = _MAX_IMPORT_BYTES,
        recovery_directory: str | Path | None = None,
    ) -> None:
        if not all(
            callable(item)
            for item in (principal_resolver, maintenance_authorizer, config_gate, clock)
        ):
            raise GRCStudioConfigError("studio dependencies must be callable")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise GRCStudioConfigError("studio integrity key must contain at least 32 bytes")
        self.tenant_id = _tenant(tenant_id)
        self.path = Path(path)
        self._integrity_key = bytes(integrity_key)
        self._principal_resolver = principal_resolver
        self._maintenance_authorizer = maintenance_authorizer
        self._config_gate = config_gate
        self._clock = clock
        self._max_studios = _integer(max_studios, "max_studios", 1, _MAX_STUDIOS)
        self._retention_seconds = _integer(
            retention_seconds,
            "retention_seconds",
            _MIN_RETENTION_SECONDS,
            _MAX_RETENTION_SECONDS,
        )
        self._max_import_bytes = _integer(
            max_import_bytes,
            "max_import_bytes",
            1_024,
            _MAX_IMPORT_BYTES,
        )
        self._recovery_directory = None if recovery_directory is None else Path(recovery_directory)
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._thread_lock = threading.RLock()
        self._initialize()

    def _gate(self) -> None:
        try:
            self._config_gate()
        except (KeyboardInterrupt, SystemExit):
            raise
        except GRCStudioError:
            raise
        except Exception as exc:
            raise GRCStudioConfigError("studio feature gate is unavailable") from exc

    def _actor(self) -> str:
        try:
            actor = self._principal_resolver()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise GRCStudioPermissionDenied("studio principal authority is unavailable") from exc
        return _id(actor, "principal_ref")

    def _now(self) -> float:
        return float(_timestamp(self._clock(), "current time"))

    def _mac(self, value: object) -> str:
        return hmac.new(self._integrity_key, _canonical(value), hashlib.sha256).hexdigest()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, factory=ClosingConnection
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def _begin(connection: sqlite3.Connection) -> None:
        connection.execute("BEGIN IMMEDIATE")

    def _initialize(self) -> None:
        ensure_private_directory(self.path.parent)
        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                self._begin(connection)
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS grc_meta(
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS grc_versions(
                        tenant_id TEXT NOT NULL,
                        studio_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        revision INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        blueprint_json TEXT NOT NULL,
                        blueprint_sha256 TEXT NOT NULL,
                        created_by_ref TEXT NOT NULL,
                        reviewed_by_ref TEXT,
                        approved_by_ref TEXT,
                        published_by_ref TEXT,
                        created_at REAL NOT NULL,
                        updated_at REAL NOT NULL,
                        reviewed_at REAL,
                        approved_at REAL,
                        published_at REAL,
                        retention_due_at REAL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,studio_id,version)
                    );
                    CREATE INDEX IF NOT EXISTS grc_versions_state_idx
                    ON grc_versions(tenant_id,state,retention_due_at);
                    CREATE TABLE IF NOT EXISTS grc_active(
                        tenant_id TEXT NOT NULL,
                        studio_id TEXT NOT NULL,
                        active_version INTEGER NOT NULL,
                        active_blueprint_sha256 TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        updated_at REAL NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,studio_id)
                    );
                    CREATE TABLE IF NOT EXISTS grc_history(
                        tenant_id TEXT NOT NULL,
                        studio_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        event_seq INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        snapshot_json TEXT NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,studio_id,version,event_seq)
                    );
                    CREATE TABLE IF NOT EXISTS grc_operations(
                        tenant_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,operation_id)
                    );
                    CREATE TABLE IF NOT EXISTS grc_audit(
                        tenant_id TEXT NOT NULL,
                        seq INTEGER NOT NULL,
                        event_type TEXT NOT NULL,
                        object_ref TEXT NOT NULL,
                        actor_ref TEXT NOT NULL,
                        event_json TEXT NOT NULL,
                        previous_sha256 TEXT NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,seq)
                    );
                    CREATE TABLE IF NOT EXISTS grc_tombstones(
                        tenant_id TEXT NOT NULL,
                        studio_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        blueprint_sha256 TEXT NOT NULL,
                        purged_at REAL NOT NULL,
                        last_integrity_sha256 TEXT NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,studio_id,version)
                    );
                    CREATE TRIGGER IF NOT EXISTS grc_history_immutable_update
                    BEFORE UPDATE ON grc_history BEGIN
                      SELECT RAISE(ABORT,'grc history is immutable');
                    END;
                    DROP TRIGGER IF EXISTS grc_history_immutable_delete;
                    CREATE TRIGGER IF NOT EXISTS grc_audit_immutable_update
                    BEFORE UPDATE ON grc_audit BEGIN
                      SELECT RAISE(ABORT,'grc audit is immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS grc_audit_immutable_delete
                    BEFORE DELETE ON grc_audit BEGIN
                      SELECT RAISE(ABORT,'grc audit is immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS grc_tombstone_immutable_update
                    BEFORE UPDATE ON grc_tombstones BEGIN
                      SELECT RAISE(ABORT,'grc tombstones are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS grc_tombstone_immutable_delete
                    BEFORE DELETE ON grc_tombstones BEGIN
                      SELECT RAISE(ABORT,'grc tombstones are immutable');
                    END;
                    """
                )
                row = connection.execute(
                    "SELECT value FROM grc_meta WHERE key='schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO grc_meta(key,value) VALUES('schema_version',?)",
                        (str(SCHEMA_VERSION),),
                    )
                elif row["value"] != str(SCHEMA_VERSION):
                    raise GRCStudioIntegrityError("studio schema version is unsupported")
                connection.commit()
            ensure_private_file(self.path)

    def _version_body(self, version: StudioVersion) -> dict[str, object]:
        return {
            "schema": VERSION_SCHEMA,
            "tenant_id": version.tenant_id,
            "studio_id": version.studio_id,
            "version": version.version,
            "revision": version.revision,
            "state": version.state,
            "blueprint": dict(version.blueprint),
            "blueprint_sha256": version.blueprint_sha256,
            "created_by_ref": version.created_by_ref,
            "reviewed_by_ref": version.reviewed_by_ref,
            "approved_by_ref": version.approved_by_ref,
            "published_by_ref": version.published_by_ref,
            "created_at": version.created_at,
            "updated_at": version.updated_at,
            "reviewed_at": version.reviewed_at,
            "approved_at": version.approved_at,
            "published_at": version.published_at,
            "retention_due_at": version.retention_due_at,
        }

    def _seal_version(self, version: StudioVersion) -> StudioVersion:
        body = self._version_body(version)
        return replace(version, integrity_sha256=self._mac(body))

    def _version(self, row: sqlite3.Row) -> StudioVersion:
        try:
            blueprint_raw = json.loads(row["blueprint_json"])
            blueprint = validate_blueprint(blueprint_raw, expected_studio_id=row["studio_id"])
            version = StudioVersion(
                schema=VERSION_SCHEMA,
                tenant_id=_tenant(row["tenant_id"]),
                studio_id=_id(row["studio_id"], "studio_id"),
                version=_integer(row["version"], "version", 1, 2_147_483_647),
                revision=_integer(row["revision"], "revision", 1, 2_147_483_647),
                state=_id(row["state"], "state"),
                blueprint=blueprint,
                blueprint_sha256=_digest(row["blueprint_sha256"], "blueprint_sha256"),
                created_by_ref=_id(row["created_by_ref"], "created_by_ref"),
                reviewed_by_ref=_optional_id(row["reviewed_by_ref"], "reviewed_by_ref"),
                approved_by_ref=_optional_id(row["approved_by_ref"], "approved_by_ref"),
                published_by_ref=_optional_id(row["published_by_ref"], "published_by_ref"),
                created_at=float(_timestamp(row["created_at"], "created_at")),
                updated_at=float(_timestamp(row["updated_at"], "updated_at")),
                reviewed_at=_timestamp(row["reviewed_at"], "reviewed_at", optional=True),
                approved_at=_timestamp(row["approved_at"], "approved_at", optional=True),
                published_at=_timestamp(row["published_at"], "published_at", optional=True),
                retention_due_at=_timestamp(
                    row["retention_due_at"], "retention_due_at", optional=True
                ),
                integrity_sha256=_digest(row["integrity_sha256"], "integrity_sha256"),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise GRCStudioIntegrityError("studio version is unreadable") from exc
        if version.state not in STATES or version.tenant_id != self.tenant_id:
            raise GRCStudioIntegrityError("studio version identity or state is invalid")
        if not hmac.compare_digest(version.blueprint_sha256, _sha256(blueprint)):
            raise GRCStudioIntegrityError("studio blueprint digest changed")
        expected = self._seal_version(replace(version, integrity_sha256="")).integrity_sha256
        if not hmac.compare_digest(version.integrity_sha256, expected):
            raise GRCStudioIntegrityError("studio version integrity changed")
        reviewed_states = {"reviewed", "rejected", "approved", "published", "superseded"}
        approved_states = {"approved", "published", "superseded"}
        published_states = {"published", "superseded"}
        has_review = version.reviewed_by_ref is not None and version.reviewed_at is not None
        has_approval = version.approved_by_ref is not None and version.approved_at is not None
        has_publish = version.published_by_ref is not None and version.published_at is not None
        if (version.state in reviewed_states) != has_review:
            raise GRCStudioIntegrityError("review lifecycle authority is inconsistent")
        if (version.state in approved_states) != has_approval:
            raise GRCStudioIntegrityError("approval lifecycle authority is inconsistent")
        if (version.state in published_states) != has_publish:
            raise GRCStudioIntegrityError("publish lifecycle authority is inconsistent")
        if (version.state == "rejected") != (version.retention_due_at is not None):
            raise GRCStudioIntegrityError("retention lifecycle authority is inconsistent")
        if has_review and hmac.compare_digest(version.created_by_ref, str(version.reviewed_by_ref)):
            raise GRCStudioIntegrityError("reviewer authority is not independent")
        if has_approval and (
            hmac.compare_digest(version.created_by_ref, str(version.approved_by_ref))
            or hmac.compare_digest(str(version.reviewed_by_ref), str(version.approved_by_ref))
        ):
            raise GRCStudioIntegrityError("approver authority is not independent")
        if version.updated_at < version.created_at:
            raise GRCStudioIntegrityError("studio lifecycle timestamps are inconsistent")
        if has_review and float(version.reviewed_at) < version.created_at:
            raise GRCStudioIntegrityError("studio review timestamp is inconsistent")
        if has_approval and float(version.approved_at) < float(version.reviewed_at):
            raise GRCStudioIntegrityError("studio approval timestamp is inconsistent")
        if has_publish and float(version.published_at) < float(version.approved_at):
            raise GRCStudioIntegrityError("studio publish timestamp is inconsistent")
        if version.retention_due_at is not None and version.retention_due_at <= float(
            version.reviewed_at
        ):
            raise GRCStudioIntegrityError("studio retention timestamp is inconsistent")
        return version

    def _get_version(
        self, connection: sqlite3.Connection, studio_id: str, version: int
    ) -> StudioVersion:
        row = connection.execute(
            "SELECT * FROM grc_versions WHERE tenant_id=? AND studio_id=? AND version=?",
            (
                self.tenant_id,
                _id(studio_id, "studio_id"),
                _integer(version, "version", 1, 2_147_483_647),
            ),
        ).fetchone()
        if row is None:
            raise GRCStudioNotFound("studio version not found")
        return self._version(row)

    def _active_body(self, pointer: ActivePointer) -> dict[str, object]:
        return {
            "schema": ACTIVE_SCHEMA,
            "tenant_id": pointer.tenant_id,
            "studio_id": pointer.studio_id,
            "active_version": pointer.active_version,
            "active_blueprint_sha256": pointer.active_blueprint_sha256,
            "revision": pointer.revision,
            "updated_at": pointer.updated_at,
        }

    def _active(self, row: sqlite3.Row) -> ActivePointer:
        pointer = ActivePointer(
            schema=ACTIVE_SCHEMA,
            tenant_id=_tenant(row["tenant_id"]),
            studio_id=_id(row["studio_id"], "studio_id"),
            active_version=_integer(row["active_version"], "active_version", 1, 2_147_483_647),
            active_blueprint_sha256=_digest(
                row["active_blueprint_sha256"], "active_blueprint_sha256"
            ),
            revision=_integer(row["revision"], "pointer revision", 1, 2_147_483_647),
            updated_at=float(_timestamp(row["updated_at"], "updated_at")),
            integrity_sha256=_digest(row["integrity_sha256"], "pointer integrity_sha256"),
        )
        if pointer.tenant_id != self.tenant_id or not hmac.compare_digest(
            pointer.integrity_sha256, self._mac(self._active_body(pointer))
        ):
            raise GRCStudioIntegrityError("active studio pointer integrity changed")
        return pointer

    def _get_active(
        self, connection: sqlite3.Connection, studio_id: str, *, optional: bool = False
    ) -> ActivePointer | None:
        row = connection.execute(
            "SELECT * FROM grc_active WHERE tenant_id=? AND studio_id=?",
            (self.tenant_id, _id(studio_id, "studio_id")),
        ).fetchone()
        if row is None:
            if optional:
                return None
            raise GRCStudioNotFound("active studio version not found")
        pointer = self._active(row)
        selected = self._get_version(connection, pointer.studio_id, pointer.active_version)
        if selected.state != "published" or not hmac.compare_digest(
            selected.blueprint_sha256, pointer.active_blueprint_sha256
        ):
            raise GRCStudioIntegrityError("active pointer is not bound to a published version")
        return pointer

    def _insert_version(
        self, connection: sqlite3.Connection, version: StudioVersion
    ) -> StudioVersion:
        stored = self._seal_version(version)
        connection.execute(
            "INSERT INTO grc_versions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                stored.tenant_id,
                stored.studio_id,
                stored.version,
                stored.revision,
                stored.state,
                _canonical(dict(stored.blueprint)).decode("ascii"),
                stored.blueprint_sha256,
                stored.created_by_ref,
                stored.reviewed_by_ref,
                stored.approved_by_ref,
                stored.published_by_ref,
                stored.created_at,
                stored.updated_at,
                stored.reviewed_at,
                stored.approved_at,
                stored.published_at,
                stored.retention_due_at,
                stored.integrity_sha256,
            ),
        )
        return stored

    def _update_version(
        self,
        connection: sqlite3.Connection,
        current: StudioVersion,
        candidate: StudioVersion,
    ) -> StudioVersion:
        stored = self._seal_version(candidate)
        cursor = connection.execute(
            "UPDATE grc_versions SET revision=?,state=?,blueprint_json=?,blueprint_sha256=?,"
            "created_by_ref=?,reviewed_by_ref=?,approved_by_ref=?,published_by_ref=?,created_at=?,"
            "updated_at=?,reviewed_at=?,approved_at=?,published_at=?,retention_due_at=?,integrity_sha256=? "
            "WHERE tenant_id=? AND studio_id=? AND version=? AND revision=? AND integrity_sha256=?",
            (
                stored.revision,
                stored.state,
                _canonical(dict(stored.blueprint)).decode("ascii"),
                stored.blueprint_sha256,
                stored.created_by_ref,
                stored.reviewed_by_ref,
                stored.approved_by_ref,
                stored.published_by_ref,
                stored.created_at,
                stored.updated_at,
                stored.reviewed_at,
                stored.approved_at,
                stored.published_at,
                stored.retention_due_at,
                stored.integrity_sha256,
                self.tenant_id,
                stored.studio_id,
                stored.version,
                current.revision,
                current.integrity_sha256,
            ),
        )
        if cursor.rowcount != 1:
            raise GRCStudioConflict("studio version changed")
        return stored

    def _history(
        self,
        connection: sqlite3.Connection,
        version: StudioVersion,
        event_type: str,
    ) -> None:
        row = connection.execute(
            "SELECT COALESCE(MAX(event_seq),0)+1 AS next FROM grc_history "
            "WHERE tenant_id=? AND studio_id=? AND version=?",
            (self.tenant_id, version.studio_id, version.version),
        ).fetchone()
        seq = int(row["next"])
        snapshot = asdict(version)
        body = {
            "tenant_id": self.tenant_id,
            "studio_id": version.studio_id,
            "version": version.version,
            "event_seq": seq,
            "event_type": _id(event_type, "event_type"),
            "snapshot": snapshot,
        }
        connection.execute(
            "INSERT INTO grc_history VALUES(?,?,?,?,?,?,?)",
            (
                self.tenant_id,
                version.studio_id,
                version.version,
                seq,
                event_type,
                _canonical(snapshot).decode("ascii"),
                self._mac(body),
            ),
        )

    def _audit(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        object_ref: str,
        actor_ref: str,
        details: Mapping[str, object],
        now: float,
    ) -> None:
        row = connection.execute(
            "SELECT seq,integrity_sha256 FROM grc_audit WHERE tenant_id=? ORDER BY seq DESC LIMIT 1",
            (self.tenant_id,),
        ).fetchone()
        seq = 1 if row is None else int(row["seq"]) + 1
        previous = (
            "0" * 64 if row is None else _digest(row["integrity_sha256"], "previous audit digest")
        )
        event = {
            "schema": "lightwork.no-code-grc-audit-event.v1",
            "tenant_id": self.tenant_id,
            "seq": seq,
            "event_type": _id(event_type, "event_type"),
            "object_ref": _id(object_ref, "object_ref", operation=True),
            "actor_ref": _id(actor_ref, "actor_ref"),
            "details": dict(details),
            "recorded_at": now,
            "previous_sha256": previous,
        }
        digest = self._mac(event)
        connection.execute(
            "INSERT INTO grc_audit VALUES(?,?,?,?,?,?,?,?)",
            (
                self.tenant_id,
                seq,
                event_type,
                object_ref,
                actor_ref,
                _canonical(event).decode("ascii"),
                previous,
                digest,
            ),
        )

    def _operation(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        request: Mapping[str, object],
    ) -> Mapping[str, object] | None:
        operation = _id(operation_id, "operation_id", operation=True)
        request_sha = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM grc_operations WHERE tenant_id=? AND operation_id=?",
            (self.tenant_id, operation),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["request_sha256"], request_sha):
            raise GRCStudioConflict("operation_id was reused with a different request")
        operation_body = {
            "tenant_id": self.tenant_id,
            "operation_id": operation,
            "request_sha256": row["request_sha256"],
            "result_json": row["result_json"],
            "created_at": row["created_at"],
        }
        if not hmac.compare_digest(row["integrity_sha256"], self._mac(operation_body)):
            raise GRCStudioIntegrityError("operation replay integrity changed")
        try:
            result = json.loads(row["result_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise GRCStudioIntegrityError("operation replay is unreadable") from exc
        if not isinstance(result, Mapping):
            raise GRCStudioIntegrityError("operation replay is invalid")
        return result

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        operation_id: str,
        request: Mapping[str, object],
        result: Mapping[str, object],
        now: float,
    ) -> None:
        selected_operation = _id(operation_id, "operation_id", operation=True)
        request_sha = _sha256(dict(request))
        result_json = _canonical(dict(result)).decode("ascii")
        body = {
            "tenant_id": self.tenant_id,
            "operation_id": selected_operation,
            "request_sha256": request_sha,
            "result_json": result_json,
            "created_at": now,
        }
        connection.execute(
            "INSERT INTO grc_operations VALUES(?,?,?,?,?,?)",
            (self.tenant_id, selected_operation, request_sha, result_json, now, self._mac(body)),
        )

    @staticmethod
    def _version_result(version: StudioVersion) -> dict[str, object]:
        return asdict(version)

    def _result_version(self, result: Mapping[str, object]) -> StudioVersion:
        expected = frozenset(StudioVersion.__dataclass_fields__)
        if set(result) != expected:
            raise GRCStudioIntegrityError("operation result schema is invalid")
        blueprint = validate_blueprint(
            result["blueprint"], expected_studio_id=str(result["studio_id"])
        )
        version = StudioVersion(**{**dict(result), "blueprint": blueprint})  # type: ignore[arg-type]
        if version.tenant_id != self.tenant_id or version.state not in STATES:
            raise GRCStudioIntegrityError("operation result identity is invalid")
        if not hmac.compare_digest(version.blueprint_sha256, _sha256(blueprint)):
            raise GRCStudioIntegrityError("operation result blueprint digest changed")
        if not hmac.compare_digest(
            version.integrity_sha256,
            self._seal_version(replace(version, integrity_sha256="")).integrity_sha256,
        ):
            raise GRCStudioIntegrityError("operation result version integrity changed")
        return version

    def create_version(
        self,
        tenant_id: str,
        studio_id: str,
        *,
        blueprint: Mapping[str, object],
        expected_latest_version: int,
        operation_id: str,
        before_write: Callable[[], None] | None = None,
    ) -> StudioVersion:
        """Append a new editable draft under exact latest-version CAS."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        studio = _id(studio_id, "studio_id")
        normalized = validate_blueprint(blueprint, expected_studio_id=studio)
        expected = _integer(expected_latest_version, "expected_latest_version", 0, 2_147_483_646)
        actor = self._actor()
        now = self._now()
        request = {
            "action": "create_version",
            "studio_id": studio,
            "blueprint": normalized,
            "expected_latest_version": expected,
            "actor_ref": actor,
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            self._gate()
            if not hmac.compare_digest(self._actor(), actor):
                raise GRCStudioPermissionDenied("draft author changed during admission")
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return self._result_version(replay)
            row = connection.execute(
                "SELECT MAX(version) AS latest FROM ("
                "SELECT version FROM grc_versions WHERE tenant_id=? AND studio_id=? "
                "UNION ALL SELECT version FROM grc_tombstones WHERE tenant_id=? AND studio_id=?"
                ")",
                (self.tenant_id, studio, self.tenant_id, studio),
            ).fetchone()
            latest = 0 if row["latest"] is None else int(row["latest"])
            if latest != expected:
                raise GRCStudioConflict("latest studio version changed")
            if latest == 0:
                count = connection.execute(
                    "SELECT COUNT(DISTINCT studio_id) AS count FROM grc_versions WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()["count"]
                if int(count) >= self._max_studios:
                    raise GRCStudioConflict("tenant studio capacity is exhausted")
            if before_write is not None:
                before_write()
            now = self._now()
            version = StudioVersion(
                schema=VERSION_SCHEMA,
                tenant_id=self.tenant_id,
                studio_id=studio,
                version=expected + 1,
                revision=1,
                state="draft",
                blueprint=normalized,
                blueprint_sha256=_sha256(normalized),
                created_by_ref=actor,
                reviewed_by_ref=None,
                approved_by_ref=None,
                published_by_ref=None,
                created_at=now,
                updated_at=now,
                reviewed_at=None,
                approved_at=None,
                published_at=None,
                retention_due_at=None,
                integrity_sha256="",
            )
            stored = self._insert_version(connection, version)
            self._history(connection, stored, "version_created")
            self._audit(
                connection,
                "version_created",
                f"{studio}:{stored.version}",
                actor,
                {"blueprint_sha256": stored.blueprint_sha256},
                now,
            )
            result = self._version_result(stored)
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return stored

    def replace_draft(
        self,
        tenant_id: str,
        studio_id: str,
        version: int,
        *,
        blueprint: Mapping[str, object],
        expected_revision: int,
        expected_integrity_sha256: str,
        operation_id: str,
        before_write: Callable[[], None] | None = None,
    ) -> StudioVersion:
        """Replace the complete draft DSL; submitted versions are immutable."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        studio = _id(studio_id, "studio_id")
        selected_version = _integer(version, "version", 1, 2_147_483_647)
        normalized = validate_blueprint(blueprint, expected_studio_id=studio)
        expected_revision = _integer(expected_revision, "expected_revision", 1, 2_147_483_647)
        expected_integrity = _digest(expected_integrity_sha256, "expected_integrity_sha256")
        actor = self._actor()
        now = self._now()
        request = {
            "action": "replace_draft",
            "studio_id": studio,
            "version": selected_version,
            "blueprint": normalized,
            "expected_revision": expected_revision,
            "expected_integrity_sha256": expected_integrity,
            "actor_ref": actor,
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            self._gate()
            if not hmac.compare_digest(self._actor(), actor):
                raise GRCStudioPermissionDenied("draft author changed during admission")
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return self._result_version(replay)
            current = self._get_version(connection, studio, selected_version)
            if current.revision != expected_revision or not hmac.compare_digest(
                current.integrity_sha256, expected_integrity
            ):
                raise GRCStudioConflict("draft changed")
            if current.state != "draft":
                raise GRCStudioConflict("only a draft can be replaced")
            if not hmac.compare_digest(current.created_by_ref, actor):
                raise GRCStudioPermissionDenied("only the draft author can replace it")
            if before_write is not None:
                before_write()
            now = self._now()
            stored = self._update_version(
                connection,
                current,
                replace(
                    current,
                    revision=current.revision + 1,
                    blueprint=normalized,
                    blueprint_sha256=_sha256(normalized),
                    updated_at=now,
                ),
            )
            self._history(connection, stored, "draft_replaced")
            self._audit(
                connection,
                "draft_replaced",
                f"{studio}:{selected_version}",
                actor,
                {"blueprint_sha256": stored.blueprint_sha256},
                now,
            )
            result = self._version_result(stored)
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return stored

    def admit_draft_save(
        self, tenant_id: str, operation_id: str, request: Mapping[str, object],
        *, before_write: Callable[[], None],
    ) -> bool:
        """Reserve one reviewed attempt; uncertain attempts never redispatch."""
        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("original draft admission not found")
        actor = self._actor()
        if request.get("actor_ref") != actor:
            raise GRCStudioPermissionDenied("original draft belongs to another author")
        admission = "draft-admission:" + _id(operation_id, "operation_id", operation=True)
        material = {"action": "reviewed_draft_admission", "draft_request_sha256": _sha256(dict(request)), "actor_ref": actor}
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            self._gate()
            if self._actor() != actor:
                raise GRCStudioPermissionDenied("draft author changed during admission")
            if self._operation(connection, admission, material) is not None:
                connection.rollback()
                return False
            count = connection.execute("SELECT COUNT(*) FROM grc_operations WHERE tenant_id=? AND operation_id LIKE 'draft-admission:%'", (self.tenant_id,)).fetchone()[0]
            if count >= 10_000:
                raise GRCStudioConflict("retained draft admission capacity is exhausted")
            before_write()
            target = request.get("version", int(request.get("expected_latest_version", 0)) + 1)
            self._record_operation(connection, admission, material, {"state": "reserved", "actor_ref": actor,
                "studio_id": request.get("studio_id"), "version": target}, self._now())
            connection.commit()
            return True

    def draft_result(
        self, tenant_id: str, operation_id: str, request: Mapping[str, object]
    ) -> StudioVersion | None:
        """Read an exact original draft receipt without writing or replaying work."""
        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("original draft result not found")
        material = dict(request)
        action = material.get("action")
        expected_keys = {"action", "studio_id", "blueprint", "actor_ref"}
        if action == "create_version":
            expected_keys.add("expected_latest_version")
            _integer(material.get("expected_latest_version"), "expected_latest_version", 0, 2_147_483_646)
        elif action == "replace_draft":
            expected_keys.update({"version", "expected_revision", "expected_integrity_sha256"})
            _integer(material.get("version"), "version", 1, 2_147_483_647)
            _integer(material.get("expected_revision"), "expected_revision", 1, 2_147_483_647)
            _digest(material.get("expected_integrity_sha256"), "expected_integrity_sha256")
        else:
            raise GRCStudioValidationError("choose an original draft operation")
        if set(material) != expected_keys:
            raise GRCStudioValidationError("original draft request fields changed")
        studio = _id(material["studio_id"], "studio_id")
        material["blueprint"] = validate_blueprint(material["blueprint"], expected_studio_id=studio)
        actor = self._actor()
        if material["actor_ref"] != actor:
            raise GRCStudioPermissionDenied("original draft belongs to another author")
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._gate()
            if self._actor() != actor:
                raise GRCStudioPermissionDenied("original draft author changed")
            result = self._operation(connection, operation_id, material)
            return None if result is None else self._result_version(result)

    def _transition(
        self,
        *,
        tenant_id: str,
        studio_id: str,
        version: int,
        expected_revision: int,
        expected_integrity_sha256: str,
        operation_id: str,
        action: str,
        required_state: str,
        next_state: str,
        authorize: Callable[[StudioVersion, str], None] | None = None,
        update: Callable[[StudioVersion, str, float], StudioVersion] | None = None,
        details: Mapping[str, object] | None = None,
    ) -> StudioVersion:
        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        studio = _id(studio_id, "studio_id")
        selected_version = _integer(version, "version", 1, 2_147_483_647)
        revision = _integer(expected_revision, "expected_revision", 1, 2_147_483_647)
        integrity = _digest(expected_integrity_sha256, "expected_integrity_sha256")
        actor = self._actor()
        now = self._now()
        request = {
            "action": action,
            "studio_id": studio,
            "version": selected_version,
            "expected_revision": revision,
            "expected_integrity_sha256": integrity,
            "actor_ref": actor,
            "details": dict(details or {}),
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return self._result_version(replay)
            current = self._get_version(connection, studio, selected_version)
            if current.revision != revision or not hmac.compare_digest(
                current.integrity_sha256, integrity
            ):
                raise GRCStudioConflict("studio version changed")
            if current.state != required_state:
                raise GRCStudioConflict(f"studio version is not {required_state}")
            if authorize is not None:
                authorize(current, actor)
            candidate = replace(
                current,
                revision=current.revision + 1,
                state=next_state,
                updated_at=now,
            )
            if update is not None:
                candidate = update(candidate, actor, now)
            stored = self._update_version(connection, current, candidate)
            self._history(connection, stored, action)
            self._audit(
                connection, action, f"{studio}:{selected_version}", actor, details or {}, now
            )
            result = self._version_result(stored)
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return stored

    def submit_for_review(
        self,
        tenant_id: str,
        studio_id: str,
        version: int,
        *,
        expected_revision: int,
        expected_integrity_sha256: str,
        operation_id: str,
    ) -> StudioVersion:
        return self._transition(
            tenant_id=tenant_id,
            studio_id=studio_id,
            version=version,
            expected_revision=expected_revision,
            expected_integrity_sha256=expected_integrity_sha256,
            operation_id=operation_id,
            action="submitted_for_review",
            required_state="draft",
            next_state="in_review",
            authorize=lambda current, actor: (
                None
                if hmac.compare_digest(current.created_by_ref, actor)
                else (_ for _ in ()).throw(
                    GRCStudioPermissionDenied("only the author can submit the draft")
                )
            ),
        )

    def review(
        self,
        tenant_id: str,
        studio_id: str,
        version: int,
        *,
        accepted: bool,
        rationale_ref: str,
        expected_revision: int,
        expected_integrity_sha256: str,
        operation_id: str,
    ) -> StudioVersion:
        if type(accepted) is not bool:
            raise GRCStudioValidationError("accepted must be boolean")
        rationale = _id(rationale_ref, "rationale_ref")

        def authorize(current: StudioVersion, actor: str) -> None:
            if hmac.compare_digest(current.created_by_ref, actor):
                raise GRCStudioPermissionDenied(
                    "review requires a principal distinct from the author"
                )

        def update(candidate: StudioVersion, actor: str, now: float) -> StudioVersion:
            return replace(
                candidate,
                reviewed_by_ref=actor,
                reviewed_at=now,
                retention_due_at=(None if accepted else now + self._retention_seconds),
            )

        return self._transition(
            tenant_id=tenant_id,
            studio_id=studio_id,
            version=version,
            expected_revision=expected_revision,
            expected_integrity_sha256=expected_integrity_sha256,
            operation_id=operation_id,
            action="review_accepted" if accepted else "review_rejected",
            required_state="in_review",
            next_state="reviewed" if accepted else "rejected",
            authorize=authorize,
            update=update,
            details={"rationale_ref": rationale},
        )

    def approve(
        self,
        tenant_id: str,
        studio_id: str,
        version: int,
        *,
        approval_ref: str,
        expected_revision: int,
        expected_integrity_sha256: str,
        operation_id: str,
    ) -> StudioVersion:
        approval = _id(approval_ref, "approval_ref")

        def authorize(current: StudioVersion, actor: str) -> None:
            if hmac.compare_digest(current.created_by_ref, actor):
                raise GRCStudioPermissionDenied(
                    "approval requires a principal distinct from the author"
                )
            if current.reviewed_by_ref is None or hmac.compare_digest(
                current.reviewed_by_ref, actor
            ):
                raise GRCStudioPermissionDenied(
                    "approval requires a principal distinct from the reviewer"
                )

        return self._transition(
            tenant_id=tenant_id,
            studio_id=studio_id,
            version=version,
            expected_revision=expected_revision,
            expected_integrity_sha256=expected_integrity_sha256,
            operation_id=operation_id,
            action="version_approved",
            required_state="reviewed",
            next_state="approved",
            authorize=authorize,
            update=lambda candidate, actor, now: replace(
                candidate, approved_by_ref=actor, approved_at=now
            ),
            details={"approval_ref": approval},
        )

    def publish(
        self,
        tenant_id: str,
        studio_id: str,
        version: int,
        *,
        expected_revision: int,
        expected_integrity_sha256: str,
        expected_active_version: int,
        expected_active_blueprint_sha256: str | None,
        expected_pointer_revision: int,
        operation_id: str,
    ) -> StudioVersion:
        """Publish an approved version and atomically CAS the active pointer."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        studio = _id(studio_id, "studio_id")
        selected_version = _integer(version, "version", 1, 2_147_483_647)
        revision = _integer(expected_revision, "expected_revision", 1, 2_147_483_647)
        integrity = _digest(expected_integrity_sha256, "expected_integrity_sha256")
        active_version = _integer(
            expected_active_version, "expected_active_version", 0, 2_147_483_647
        )
        active_digest = (
            None
            if expected_active_blueprint_sha256 is None
            else _digest(expected_active_blueprint_sha256, "expected_active_blueprint_sha256")
        )
        pointer_revision = _integer(
            expected_pointer_revision, "expected_pointer_revision", 0, 2_147_483_647
        )
        if active_version == 0 and (active_digest is not None or pointer_revision != 0):
            raise GRCStudioValidationError("absent active pointer CAS is inconsistent")
        if active_version > 0 and (active_digest is None or pointer_revision < 1):
            raise GRCStudioValidationError("active pointer CAS is incomplete")
        actor = self._actor()
        now = self._now()
        request = {
            "action": "version_published",
            "studio_id": studio,
            "version": selected_version,
            "expected_revision": revision,
            "expected_integrity_sha256": integrity,
            "expected_active_version": active_version,
            "expected_active_blueprint_sha256": active_digest,
            "expected_pointer_revision": pointer_revision,
            "actor_ref": actor,
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return self._result_version(replay)
            current = self._get_version(connection, studio, selected_version)
            if current.revision != revision or not hmac.compare_digest(
                current.integrity_sha256, integrity
            ):
                raise GRCStudioConflict("studio version changed")
            if current.state != "approved":
                raise GRCStudioConflict("studio version is not approved")
            pointer = self._get_active(connection, studio, optional=True)
            if pointer is None:
                if active_version != 0:
                    raise GRCStudioConflict("active studio pointer changed")
            elif (
                pointer.active_version != active_version
                or pointer.revision != pointer_revision
                or active_digest is None
                or not hmac.compare_digest(pointer.active_blueprint_sha256, active_digest)
            ):
                raise GRCStudioConflict("active studio pointer changed")
            if pointer is not None:
                prior = self._get_version(connection, studio, pointer.active_version)
                prior_stored = self._update_version(
                    connection,
                    prior,
                    replace(prior, revision=prior.revision + 1, state="superseded", updated_at=now),
                )
                self._history(connection, prior_stored, "version_superseded")
            stored = self._update_version(
                connection,
                current,
                replace(
                    current,
                    revision=current.revision + 1,
                    state="published",
                    published_by_ref=actor,
                    published_at=now,
                    updated_at=now,
                ),
            )
            pointer_candidate = ActivePointer(
                schema=ACTIVE_SCHEMA,
                tenant_id=self.tenant_id,
                studio_id=studio,
                active_version=stored.version,
                active_blueprint_sha256=stored.blueprint_sha256,
                revision=1 if pointer is None else pointer.revision + 1,
                updated_at=now,
                integrity_sha256="",
            )
            pointer_candidate = replace(
                pointer_candidate, integrity_sha256=self._mac(self._active_body(pointer_candidate))
            )
            if pointer is None:
                connection.execute(
                    "INSERT INTO grc_active VALUES(?,?,?,?,?,?,?)",
                    (
                        self.tenant_id,
                        studio,
                        stored.version,
                        stored.blueprint_sha256,
                        pointer_candidate.revision,
                        now,
                        pointer_candidate.integrity_sha256,
                    ),
                )
            else:
                cursor = connection.execute(
                    "UPDATE grc_active SET active_version=?,active_blueprint_sha256=?,revision=?,updated_at=?,integrity_sha256=? "
                    "WHERE tenant_id=? AND studio_id=? AND revision=? AND integrity_sha256=?",
                    (
                        stored.version,
                        stored.blueprint_sha256,
                        pointer_candidate.revision,
                        now,
                        pointer_candidate.integrity_sha256,
                        self.tenant_id,
                        studio,
                        pointer.revision,
                        pointer.integrity_sha256,
                    ),
                )
                if cursor.rowcount != 1:
                    raise GRCStudioConflict("active studio pointer changed")
            self._history(connection, stored, "version_published")
            self._audit(
                connection,
                "version_published",
                f"{studio}:{selected_version}",
                actor,
                {
                    "blueprint_sha256": stored.blueprint_sha256,
                    "pointer_revision": pointer_candidate.revision,
                },
                now,
            )
            result = self._version_result(stored)
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return stored

    def rollback(
        self,
        tenant_id: str,
        studio_id: str,
        *,
        target_version: int,
        expected_target_blueprint_sha256: str,
        expected_active_version: int,
        expected_active_blueprint_sha256: str,
        expected_pointer_revision: int,
        rationale_ref: str,
        operation_id: str,
    ) -> StudioVersion:
        """Atomically reactivate one exact previously published release."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        studio = _id(studio_id, "studio_id")
        target_version = _integer(target_version, "target_version", 1, 2_147_483_647)
        target_digest = _digest(
            expected_target_blueprint_sha256, "expected_target_blueprint_sha256"
        )
        active_version = _integer(
            expected_active_version, "expected_active_version", 1, 2_147_483_647
        )
        active_digest = _digest(
            expected_active_blueprint_sha256, "expected_active_blueprint_sha256"
        )
        pointer_revision = _integer(
            expected_pointer_revision, "expected_pointer_revision", 1, 2_147_483_647
        )
        rationale = _id(rationale_ref, "rationale_ref")
        actor = self._actor()
        now = self._now()
        request = {
            "action": "version_rolled_back",
            "studio_id": studio,
            "target_version": target_version,
            "expected_target_blueprint_sha256": target_digest,
            "expected_active_version": active_version,
            "expected_active_blueprint_sha256": active_digest,
            "expected_pointer_revision": pointer_revision,
            "rationale_ref": rationale,
            "actor_ref": actor,
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return self._result_version(replay)
            pointer = self._get_active(connection, studio)
            assert pointer is not None
            if (
                pointer.active_version != active_version
                or pointer.revision != pointer_revision
                or not hmac.compare_digest(pointer.active_blueprint_sha256, active_digest)
            ):
                raise GRCStudioConflict("active studio pointer changed")
            if target_version == active_version:
                raise GRCStudioConflict("rollback target is already active")
            target = self._get_version(connection, studio, target_version)
            if target.state != "superseded" or not hmac.compare_digest(
                target.blueprint_sha256, target_digest
            ):
                raise GRCStudioConflict("rollback target is not an exact prior release")
            current = self._get_version(connection, studio, active_version)
            current_stored = self._update_version(
                connection,
                current,
                replace(current, revision=current.revision + 1, state="superseded", updated_at=now),
            )
            target_stored = self._update_version(
                connection,
                target,
                replace(target, revision=target.revision + 1, state="published", updated_at=now),
            )
            self._history(connection, current_stored, "version_superseded_by_rollback")
            self._history(connection, target_stored, "version_reactivated")
            pointer_candidate = ActivePointer(
                schema=ACTIVE_SCHEMA,
                tenant_id=self.tenant_id,
                studio_id=studio,
                active_version=target_stored.version,
                active_blueprint_sha256=target_stored.blueprint_sha256,
                revision=pointer.revision + 1,
                updated_at=now,
                integrity_sha256="",
            )
            pointer_candidate = replace(
                pointer_candidate, integrity_sha256=self._mac(self._active_body(pointer_candidate))
            )
            cursor = connection.execute(
                "UPDATE grc_active SET active_version=?,active_blueprint_sha256=?,revision=?,updated_at=?,integrity_sha256=? "
                "WHERE tenant_id=? AND studio_id=? AND revision=? AND integrity_sha256=?",
                (
                    target_stored.version,
                    target_stored.blueprint_sha256,
                    pointer_candidate.revision,
                    now,
                    pointer_candidate.integrity_sha256,
                    self.tenant_id,
                    studio,
                    pointer.revision,
                    pointer.integrity_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise GRCStudioConflict("active studio pointer changed")
            self._audit(
                connection,
                "version_rolled_back",
                f"{studio}:{target_version}",
                actor,
                {
                    "from_version": active_version,
                    "rationale_ref": rationale,
                    "pointer_revision": pointer_candidate.revision,
                },
                now,
            )
            result = self._version_result(target_stored)
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return target_stored

    def get_version(self, tenant_id: str, studio_id: str, version: int) -> StudioVersion:
        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        with self._connect() as connection:
            return self._get_version(connection, studio_id, version)

    def get_active(self, tenant_id: str, studio_id: str) -> tuple[ActivePointer, StudioVersion]:
        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("active studio version not found")
        with self._connect() as connection:
            pointer = self._get_active(connection, studio_id)
            assert pointer is not None
            return pointer, self._get_version(connection, pointer.studio_id, pointer.active_version)

    @contextmanager
    def active_source_fence(self, tenant_id: str, studio_id: str, *,
                            expected_pointer_integrity: str, expected_blueprint_sha256: str):
        """Hold the actual lifecycle writer lock through a local consumer's save.

        This is source custody, not target enrollment or approval. Consumers
        still need their own exact target CAS, idempotence and independent review.
        No provider operations belong inside this bounded local writer fence.
        """
        pointer_pin = _digest(expected_pointer_integrity, "active pointer integrity")
        blueprint_pin = _digest(expected_blueprint_sha256, "active blueprint integrity")
        with self._thread_lock, cross_process_lock(self._lock_path):
            pointer, version = self.get_active(tenant_id, studio_id)
            if (pointer.integrity_sha256 != pointer_pin
                    or version.blueprint_sha256 != blueprint_pin):
                raise GRCStudioConflict("the selected live form changed before saving")
            yield version

    def list_versions(
        self,
        tenant_id: str,
        *,
        studio_id: str | None = None,
        state: str | None = None,
        limit: int = 100,
    ) -> tuple[StudioVersion, ...]:
        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            return ()
        clauses = ["tenant_id=?"]
        params: list[object] = [self.tenant_id]
        if studio_id is not None:
            clauses.append("studio_id=?")
            params.append(_id(studio_id, "studio_id"))
        if state is not None:
            selected_state = _id(state, "state")
            if selected_state not in STATES:
                raise GRCStudioValidationError("state filter is unsupported")
            clauses.append("state=?")
            params.append(selected_state)
        params.append(_integer(limit, "limit", 1, 1_000))
        with self._connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM grc_versions WHERE {' AND '.join(clauses)} ORDER BY studio_id,version DESC LIMIT ?",  # noqa: S608 -- clauses are fixed literals
                params,
            ).fetchall()
            return tuple(self._version(row) for row in rows)

    def history(
        self, tenant_id: str, studio_id: str, version: int
    ) -> tuple[dict[str, object], ...]:
        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            return ()
        studio = _id(studio_id, "studio_id")
        selected_version = _integer(version, "version", 1, 2_147_483_647)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM grc_history WHERE tenant_id=? AND studio_id=? AND version=? ORDER BY event_seq",
                (self.tenant_id, studio, selected_version),
            ).fetchall()
            output: list[dict[str, object]] = []
            for row in rows:
                try:
                    snapshot = json.loads(row["snapshot_json"])
                except json.JSONDecodeError as exc:
                    raise GRCStudioIntegrityError("studio history is unreadable") from exc
                body = {
                    "tenant_id": self.tenant_id,
                    "studio_id": studio,
                    "version": selected_version,
                    "event_seq": row["event_seq"],
                    "event_type": row["event_type"],
                    "snapshot": snapshot,
                }
                if not hmac.compare_digest(row["integrity_sha256"], self._mac(body)):
                    raise GRCStudioIntegrityError("studio history integrity changed")
                output.append(
                    {
                        "event_seq": row["event_seq"],
                        "event_type": row["event_type"],
                        "snapshot": snapshot,
                        "integrity_sha256": row["integrity_sha256"],
                    }
                )
            return tuple(output)

    def export_version(
        self,
        tenant_id: str,
        studio_id: str,
        version: int,
        *,
        operation_id: str,
    ) -> dict[str, object]:
        """Create a bounded deployment-authenticated export with an audit event."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio version not found")
        studio = _id(studio_id, "studio_id")
        selected_version = _integer(version, "version", 1, 2_147_483_647)
        actor = self._actor()
        now = self._now()
        request = {
            "action": "version_exported",
            "studio_id": studio,
            "version": selected_version,
            "actor_ref": actor,
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return dict(replay)
            selected = self._get_version(connection, studio, selected_version)
            body = {
                "schema": EXPORT_SCHEMA,
                "tenant_scope_sha256": hashlib.sha256(self.tenant_id.encode()).hexdigest(),
                "studio_id": selected.studio_id,
                "source_version": selected.version,
                "source_state": selected.state,
                "blueprint": dict(selected.blueprint),
                "blueprint_sha256": selected.blueprint_sha256,
                "source_integrity_sha256": selected.integrity_sha256,
                "exported_at": now,
            }
            result = {**body, "export_hmac_sha256": self._mac(body)}
            _canonical(result, maximum=self._max_import_bytes)
            self._audit(
                connection,
                "version_exported",
                f"{studio}:{selected_version}",
                actor,
                {"blueprint_sha256": selected.blueprint_sha256, "export_sha256": _sha256(result)},
                now,
            )
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return result

    def _validate_export(self, value: object) -> dict[str, object]:
        envelope = _closed(
            value,
            "studio export",
            frozenset(
                {
                    "schema",
                    "tenant_scope_sha256",
                    "studio_id",
                    "source_version",
                    "source_state",
                    "blueprint",
                    "blueprint_sha256",
                    "source_integrity_sha256",
                    "exported_at",
                    "export_hmac_sha256",
                }
            ),
        )
        _canonical(dict(envelope), maximum=self._max_import_bytes)
        if envelope["schema"] != EXPORT_SCHEMA:
            raise GRCStudioValidationError("studio export schema is unsupported")
        body = {key: envelope[key] for key in envelope if key != "export_hmac_sha256"}
        supplied_hmac = _digest(envelope["export_hmac_sha256"], "export_hmac_sha256")
        if not hmac.compare_digest(supplied_hmac, self._mac(body)):
            raise GRCStudioIntegrityError("studio export authentication failed")
        if not hmac.compare_digest(
            _digest(envelope["tenant_scope_sha256"], "tenant_scope_sha256"),
            hashlib.sha256(self.tenant_id.encode()).hexdigest(),
        ):
            raise GRCStudioPermissionDenied("studio export belongs to another tenant scope")
        studio = _id(envelope["studio_id"], "studio_id")
        state = _id(envelope["source_state"], "source_state")
        if state not in STATES:
            raise GRCStudioValidationError("studio export lifecycle state is unsupported")
        blueprint = validate_blueprint(envelope["blueprint"], expected_studio_id=studio)
        blueprint_digest = _digest(envelope["blueprint_sha256"], "blueprint_sha256")
        if not hmac.compare_digest(blueprint_digest, _sha256(blueprint)):
            raise GRCStudioIntegrityError("studio export blueprint digest changed")
        _integer(envelope["source_version"], "source_version", 1, 2_147_483_647)
        _digest(envelope["source_integrity_sha256"], "source_integrity_sha256")
        _timestamp(envelope["exported_at"], "exported_at")
        return {**dict(envelope), "blueprint": blueprint}

    def import_version(
        self,
        tenant_id: str,
        envelope: Mapping[str, object] | bytes,
        *,
        expected_latest_version: int,
        operation_id: str,
    ) -> StudioVersion:
        """Import a same-custody authenticated envelope as a new local draft."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio export not found")
        if isinstance(envelope, bytes):
            if not 1 <= len(envelope) <= self._max_import_bytes:
                raise GRCStudioValidationError("studio import exceeds its byte bound")
            try:
                decoded = json.loads(envelope)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise GRCStudioValidationError("studio import is not canonical JSON") from exc
        else:
            decoded = envelope
        exported = self._validate_export(decoded)
        studio = str(exported["studio_id"])
        normalized = dict(exported["blueprint"])  # type: ignore[arg-type]
        expected = _integer(expected_latest_version, "expected_latest_version", 0, 2_147_483_646)
        actor = self._actor()
        now = self._now()
        request = {
            "action": "version_imported",
            "studio_id": studio,
            "export_sha256": _sha256(exported),
            "expected_latest_version": expected,
            "actor_ref": actor,
        }
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            replay = self._operation(connection, operation_id, request)
            if replay is not None:
                connection.rollback()
                return self._result_version(replay)
            row = connection.execute(
                "SELECT MAX(version) AS latest FROM (SELECT version FROM grc_versions WHERE tenant_id=? AND studio_id=? UNION ALL SELECT version FROM grc_tombstones WHERE tenant_id=? AND studio_id=?)",
                (self.tenant_id, studio, self.tenant_id, studio),
            ).fetchone()
            latest = 0 if row["latest"] is None else int(row["latest"])
            if latest != expected:
                raise GRCStudioConflict("latest studio version changed")
            if latest == 0:
                count = connection.execute(
                    "SELECT COUNT(DISTINCT studio_id) AS count FROM grc_versions WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()["count"]
                if int(count) >= self._max_studios:
                    raise GRCStudioConflict("tenant studio capacity is exhausted")
            candidate = StudioVersion(
                schema=VERSION_SCHEMA,
                tenant_id=self.tenant_id,
                studio_id=studio,
                version=expected + 1,
                revision=1,
                state="draft",
                blueprint=normalized,
                blueprint_sha256=_sha256(normalized),
                created_by_ref=actor,
                reviewed_by_ref=None,
                approved_by_ref=None,
                published_by_ref=None,
                created_at=now,
                updated_at=now,
                reviewed_at=None,
                approved_at=None,
                published_at=None,
                retention_due_at=None,
                integrity_sha256="",
            )
            stored = self._insert_version(connection, candidate)
            self._history(connection, stored, "version_imported")
            self._audit(
                connection,
                "version_imported",
                f"{studio}:{stored.version}",
                actor,
                {
                    "source_version": exported["source_version"],
                    "source_integrity_sha256": exported["source_integrity_sha256"],
                    "export_sha256": request["export_sha256"],
                },
                now,
            )
            result = self._version_result(stored)
            self._record_operation(connection, operation_id, request, result, now)
            connection.commit()
            return stored

    @staticmethod
    def _projection_payload(
        blueprint: Mapping[str, object], projection_kind: str, definition_id: str
    ) -> dict[str, object]:
        kind = _id(projection_kind, "projection_kind")
        selected_id = _id(definition_id, "definition_id")
        if kind not in PROJECTION_KINDS:
            raise GRCStudioValidationError("projection kind is unsupported")
        key = {
            "questionnaire": "forms",
            "collector": "collector_bindings",
            "report": "report_views",
        }[kind]
        identity_key = {"questionnaire": "form_id", "collector": "binding_id", "report": "view_id"}[
            kind
        ]
        rows = blueprint[key]
        selected = next((dict(item) for item in rows if item[identity_key] == selected_id), None)  # type: ignore[index,union-attr]
        if selected is None:
            raise GRCStudioNotFound("projection definition not found")
        object_id = str(selected["object_id"])
        object_definition = next(
            dict(item) for item in blueprint["objects"] if item["object_id"] == object_id
        )  # type: ignore[index,union-attr]
        rules = [dict(item) for item in blueprint["rules"] if item["object_id"] == object_id]  # type: ignore[index,union-attr]
        return {
            "definition": selected,
            "object": object_definition,
            "rules": rules,
        }

    def preview_projection(
        self,
        tenant_id: str,
        studio_id: str,
        *,
        projection_kind: str,
        definition_id: str,
        target_authority: RuntimeTargetAuthority,
        expected_active_version: int,
        expected_blueprint_sha256: str,
    ) -> dict[str, object]:
        """Build a side-effect-free projection bound to exact source and target authority."""

        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("active studio version not found")
        studio = _id(studio_id, "studio_id")
        kind = _id(projection_kind, "projection_kind")
        expected_version = _integer(
            expected_active_version, "expected_active_version", 1, 2_147_483_647
        )
        expected_blueprint = _digest(expected_blueprint_sha256, "expected_blueprint_sha256")
        if not isinstance(target_authority, RuntimeTargetAuthority):
            raise GRCStudioValidationError("runtime target authority type is invalid")
        authority = target_authority.normalized()
        now = self._now()
        if authority.tenant_id != self.tenant_id or authority.target_kind != kind:
            raise GRCStudioPermissionDenied("runtime target authority scope is invalid")
        if authority.valid_until <= now:
            raise GRCStudioPermissionDenied("runtime target authority expired")
        with self._connect() as connection:
            pointer = self._get_active(connection, studio)
            assert pointer is not None
            if pointer.active_version != expected_version or not hmac.compare_digest(
                pointer.active_blueprint_sha256, expected_blueprint
            ):
                raise GRCStudioConflict("active studio authority changed")
            selected = self._get_version(connection, studio, pointer.active_version)
        if not hmac.compare_digest(authority.allowed_blueprint_sha256, selected.blueprint_sha256):
            raise GRCStudioPermissionDenied("runtime target is not enrolled for this blueprint")
        payload = self._projection_payload(selected.blueprint, kind, definition_id)
        body = {
            "schema": PROJECTION_SCHEMA,
            "tenant_scope_sha256": hashlib.sha256(self.tenant_id.encode()).hexdigest(),
            "studio_id": studio,
            "studio_version": selected.version,
            "blueprint_sha256": selected.blueprint_sha256,
            "projection_kind": kind,
            "definition_id": _id(definition_id, "definition_id"),
            "target_id": authority.target_id,
            "target_revision": authority.target_revision,
            "target_integrity_sha256": authority.target_integrity_sha256,
            "target_authority_sha256": authority.authority_sha256,
            "payload": payload,
        }
        return {**body, "projection_sha256": _sha256(body)}

    def apply_projection(
        self,
        tenant_id: str,
        studio_id: str,
        *,
        projection_kind: str,
        definition_id: str,
        target_id: str,
        target_revision: int,
        expected_active_version: int,
        expected_blueprint_sha256: str,
        operation_id: str,
        authority_resolver: Callable[[str, str, str, int], RuntimeTargetAuthority],
        applier: Callable[..., Mapping[str, object]],
    ) -> dict[str, object]:
        """Apply only through a server-owned adapter under double-resolved authority.

        The adapter must itself use ``operation_id`` as its idempotency key and
        return the exact receipt contract.  There is intentionally no generic
        callable, expression or browser-selected destination seam.
        """

        self._gate()
        actor = self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("runtime target not found")
        if not callable(authority_resolver) or not callable(applier):
            raise GRCStudioConfigError("runtime projection adapter is unavailable")
        kind = _id(projection_kind, "projection_kind")
        target = _id(target_id, "target_id")
        target_revision = _integer(target_revision, "target_revision", 1, 2_147_483_647)
        operation = _id(operation_id, "operation_id", operation=True)
        request = {
            "action": "runtime_projection_applied",
            "studio_id": _id(studio_id, "studio_id"),
            "projection_kind": kind,
            "definition_id": _id(definition_id, "definition_id"),
            "target_id": target,
            "target_revision": target_revision,
            "expected_active_version": _integer(
                expected_active_version, "expected_active_version", 1, 2_147_483_647
            ),
            "expected_blueprint_sha256": _digest(
                expected_blueprint_sha256, "expected_blueprint_sha256"
            ),
            "actor_ref": actor,
        }
        # A deployment adapter must also use operation_id idempotently.  The
        # cross-process store lock prevents duplicate local dispatches; if the
        # process dies after the adapter changes its target but before the
        # receipt commits, retrying the same operation_id asks the adapter to
        # reconcile/replay rather than issue a second mutation.
        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                replay = self._operation(connection, operation, request)
            if replay is not None:
                return dict(replay)
            first = authority_resolver(self.tenant_id, kind, target, target_revision)
            projection = self.preview_projection(
                self.tenant_id,
                studio_id,
                projection_kind=kind,
                definition_id=definition_id,
                target_authority=first,
                expected_active_version=expected_active_version,
                expected_blueprint_sha256=expected_blueprint_sha256,
            )
            second = authority_resolver(self.tenant_id, kind, target, target_revision)
            if not isinstance(second, RuntimeTargetAuthority):
                raise GRCStudioConfigError("runtime target resolver returned an invalid authority")
            second = second.normalized()
            if not hmac.compare_digest(
                first.normalized().authority_sha256, second.authority_sha256
            ):
                raise GRCStudioConflict("runtime target authority changed before application")
            receipt = applier(
                projection=projection,
                operation_id=operation,
                actor_ref=actor,
                expected_target_revision=second.target_revision,
                expected_target_integrity_sha256=second.target_integrity_sha256,
                target_authority_sha256=second.authority_sha256,
            )
            expected_keys = frozenset(
                {
                    "schema",
                    "operation_id",
                    "applied",
                    "projection_sha256",
                    "authority_sha256",
                    "target_revision_before",
                    "target_revision_after",
                    "target_integrity_sha256_after",
                }
            )
            if not isinstance(receipt, Mapping) or set(receipt) != expected_keys:
                raise GRCStudioIntegrityError("runtime adapter receipt schema is invalid")
            if (
                receipt["schema"] != APPLY_RECEIPT_SCHEMA
                or receipt["operation_id"] != operation
                or type(receipt["applied"]) is not bool
            ):
                raise GRCStudioIntegrityError("runtime adapter receipt identity is invalid")
            if not hmac.compare_digest(
                _digest(receipt["projection_sha256"], "receipt projection_sha256"),
                str(projection["projection_sha256"]),
            ) or not hmac.compare_digest(
                _digest(receipt["authority_sha256"], "receipt authority_sha256"),
                second.authority_sha256,
            ):
                raise GRCStudioIntegrityError("runtime adapter receipt authority changed")
            before = _integer(
                receipt["target_revision_before"],
                "target_revision_before",
                1,
                2_147_483_647,
            )
            after = _integer(
                receipt["target_revision_after"],
                "target_revision_after",
                1,
                2_147_483_647,
            )
            _digest(
                receipt["target_integrity_sha256_after"],
                "target_integrity_sha256_after",
            )
            if (
                before != target_revision
                or (receipt["applied"] is True and after <= before)
                or (receipt["applied"] is False and after != before)
            ):
                raise GRCStudioIntegrityError(
                    "runtime adapter receipt revision transition is invalid"
                )
            now = self._now()
            with self._connect() as connection:
                self._begin(connection)
                replay = self._operation(connection, operation, request)
                if replay is not None:
                    connection.rollback()
                    return dict(replay)
                normalized_receipt = dict(receipt)
                self._record_operation(connection, operation, request, normalized_receipt, now)
                self._audit(
                    connection,
                    "runtime_projection_applied",
                    f"{request['studio_id']}:{request['expected_active_version']}",
                    actor,
                    {
                        "projection_kind": kind,
                        "definition_id": request["definition_id"],
                        "target_id": target,
                        "target_revision_before": before,
                        "target_revision_after": after,
                        "projection_sha256": normalized_receipt["projection_sha256"],
                        "applied": normalized_receipt["applied"],
                    },
                    now,
                )
                connection.commit()
            return normalized_receipt

    def retention_due(self, tenant_id: str, *, limit: int = 100) -> tuple[StudioVersion, ...]:
        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            return ()
        now = self._now()
        selected_limit = _integer(limit, "limit", 1, 1_000)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM grc_versions WHERE tenant_id=? AND state='rejected' "
                "AND retention_due_at IS NOT NULL AND retention_due_at<=? "
                "ORDER BY retention_due_at,studio_id,version LIMIT ?",
                (self.tenant_id, now, selected_limit),
            ).fetchall()
            return tuple(self._version(row) for row in rows)

    def purge_expired(self, tenant_id: str, *, limit: int = 100) -> dict[str, object]:
        """Purge rejected definition content while retaining audit and tombstones."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("retention scope not found")
        if self._maintenance_authorizer() is not True:
            raise GRCStudioPermissionDenied("studio retention requires maintenance authority")
        actor = self._actor()
        now = self._now()
        selected_limit = _integer(limit, "limit", 1, 1_000)
        purged: list[dict[str, object]] = []
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            rows = connection.execute(
                "SELECT * FROM grc_versions WHERE tenant_id=? AND state='rejected' "
                "AND retention_due_at IS NOT NULL AND retention_due_at<=? "
                "ORDER BY retention_due_at,studio_id,version LIMIT ?",
                (self.tenant_id, now, selected_limit),
            ).fetchall()
            for row in rows:
                selected = self._version(row)
                tombstone_body = {
                    "schema": "lightwork.no-code-grc-tombstone.v1",
                    "tenant_id": self.tenant_id,
                    "studio_id": selected.studio_id,
                    "version": selected.version,
                    "blueprint_sha256": selected.blueprint_sha256,
                    "purged_at": now,
                    "last_integrity_sha256": selected.integrity_sha256,
                }
                tombstone_digest = self._mac(tombstone_body)
                connection.execute(
                    "INSERT INTO grc_tombstones VALUES(?,?,?,?,?,?,?)",
                    (
                        self.tenant_id,
                        selected.studio_id,
                        selected.version,
                        selected.blueprint_sha256,
                        now,
                        selected.integrity_sha256,
                        tombstone_digest,
                    ),
                )
                connection.execute(
                    "DELETE FROM grc_history WHERE tenant_id=? AND studio_id=? AND version=?",
                    (self.tenant_id, selected.studio_id, selected.version),
                )
                operation_rows = connection.execute(
                    "SELECT operation_id,result_json FROM grc_operations WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchall()
                for operation_row in operation_rows:
                    try:
                        result = json.loads(operation_row["result_json"])
                    except json.JSONDecodeError as exc:
                        raise GRCStudioIntegrityError("operation replay is unreadable") from exc
                    if (
                        isinstance(result, Mapping)
                        and result.get("studio_id") == selected.studio_id
                        and (
                            result.get("version") == selected.version
                            or result.get("source_version") == selected.version
                        )
                    ):
                        connection.execute(
                            "DELETE FROM grc_operations WHERE tenant_id=? AND operation_id=?",
                            (self.tenant_id, operation_row["operation_id"]),
                        )
                cursor = connection.execute(
                    "DELETE FROM grc_versions WHERE tenant_id=? AND studio_id=? AND version=? AND integrity_sha256=?",
                    (
                        self.tenant_id,
                        selected.studio_id,
                        selected.version,
                        selected.integrity_sha256,
                    ),
                )
                if cursor.rowcount != 1:
                    raise GRCStudioConflict("retention candidate changed")
                self._audit(
                    connection,
                    "version_purged",
                    f"{selected.studio_id}:{selected.version}",
                    actor,
                    {
                        "blueprint_sha256": selected.blueprint_sha256,
                        "tombstone_sha256": tombstone_digest,
                    },
                    now,
                )
                purged.append(
                    {
                        "studio_id": selected.studio_id,
                        "version": selected.version,
                        "blueprint_sha256": selected.blueprint_sha256,
                        "tombstone_sha256": tombstone_digest,
                    }
                )
            connection.commit()
        body: dict[str, object] = {
            "schema": "lightwork.no-code-grc-retention-result.v1",
            "purged_count": len(purged),
            "items": purged,
            "completed_at": now,
        }
        return {**body, "result_sha256": _sha256(body)}

    def verify_integrity(self, tenant_id: str) -> dict[str, object]:  # noqa: C901
        """Verify versions, active pointers, history, operations, tombstones and audit chain."""

        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("studio integrity scope not found")
        with self._thread_lock, cross_process_lock(self._lock_path):
            return self._verify_integrity_unlocked()

    def _verify_integrity_unlocked(self) -> dict[str, object]:  # noqa: C901
        """Verify one stable snapshot while the caller owns the store lock."""

        counts = {
            "versions": 0,
            "active_pointers": 0,
            "history_events": 0,
            "operations": 0,
            "audit_events": 0,
            "tombstones": 0,
        }
        with self._connect() as connection:
            version_keys: set[tuple[str, int]] = set()
            for row in connection.execute(
                "SELECT * FROM grc_versions WHERE tenant_id=? ORDER BY studio_id,version",
                (self.tenant_id,),
            ):
                version = self._version(row)
                version_keys.add((version.studio_id, version.version))
                counts["versions"] += 1
            for row in connection.execute(
                "SELECT * FROM grc_active WHERE tenant_id=? ORDER BY studio_id",
                (self.tenant_id,),
            ):
                pointer = self._active(row)
                if (pointer.studio_id, pointer.active_version) not in version_keys:
                    raise GRCStudioIntegrityError("active pointer is orphaned")
                selected = self._get_version(connection, pointer.studio_id, pointer.active_version)
                if selected.state != "published" or not hmac.compare_digest(
                    selected.blueprint_sha256, pointer.active_blueprint_sha256
                ):
                    raise GRCStudioIntegrityError("active pointer binding changed")
                counts["active_pointers"] += 1
            history_counts: dict[tuple[str, int], int] = {}
            for row in connection.execute(
                "SELECT * FROM grc_history WHERE tenant_id=? ORDER BY studio_id,version,event_seq",
                (self.tenant_id,),
            ):
                key = (row["studio_id"], int(row["version"]))
                if key not in version_keys:
                    raise GRCStudioIntegrityError("studio history is orphaned")
                expected_seq = history_counts.get(key, 0) + 1
                if row["event_seq"] != expected_seq:
                    raise GRCStudioIntegrityError("studio history is discontinuous")
                try:
                    snapshot = json.loads(row["snapshot_json"])
                except json.JSONDecodeError as exc:
                    raise GRCStudioIntegrityError("studio history is unreadable") from exc
                body = {
                    "tenant_id": self.tenant_id,
                    "studio_id": row["studio_id"],
                    "version": row["version"],
                    "event_seq": row["event_seq"],
                    "event_type": row["event_type"],
                    "snapshot": snapshot,
                }
                if not hmac.compare_digest(row["integrity_sha256"], self._mac(body)):
                    raise GRCStudioIntegrityError("studio history integrity changed")
                history_counts[key] = expected_seq
                counts["history_events"] += 1
            if any(history_counts.get(key, 0) < 1 for key in version_keys):
                raise GRCStudioIntegrityError("studio version history is incomplete")
            for row in connection.execute(
                "SELECT * FROM grc_operations WHERE tenant_id=? ORDER BY operation_id",
                (self.tenant_id,),
            ):
                _id(row["operation_id"], "operation_id", operation=True)
                _digest(row["request_sha256"], "request_sha256")
                operation_body = {
                    "tenant_id": self.tenant_id,
                    "operation_id": row["operation_id"],
                    "request_sha256": row["request_sha256"],
                    "result_json": row["result_json"],
                    "created_at": row["created_at"],
                }
                if not hmac.compare_digest(row["integrity_sha256"], self._mac(operation_body)):
                    raise GRCStudioIntegrityError("operation result integrity changed")
                try:
                    result = json.loads(row["result_json"])
                except json.JSONDecodeError as exc:
                    raise GRCStudioIntegrityError("operation result is unreadable") from exc
                if not isinstance(result, Mapping):
                    raise GRCStudioIntegrityError("operation result is invalid")
                counts["operations"] += 1
            previous = "0" * 64
            expected_seq = 1
            for row in connection.execute(
                "SELECT * FROM grc_audit WHERE tenant_id=? ORDER BY seq",
                (self.tenant_id,),
            ):
                if row["seq"] != expected_seq or not hmac.compare_digest(
                    row["previous_sha256"], previous
                ):
                    raise GRCStudioIntegrityError("studio audit chain is discontinuous")
                try:
                    event = json.loads(row["event_json"])
                except json.JSONDecodeError as exc:
                    raise GRCStudioIntegrityError("studio audit event is unreadable") from exc
                if not isinstance(event, Mapping) or not hmac.compare_digest(
                    row["integrity_sha256"], self._mac(event)
                ):
                    raise GRCStudioIntegrityError("studio audit event integrity changed")
                previous = row["integrity_sha256"]
                expected_seq += 1
                counts["audit_events"] += 1
            for row in connection.execute(
                "SELECT * FROM grc_tombstones WHERE tenant_id=? ORDER BY studio_id,version",
                (self.tenant_id,),
            ):
                body = {
                    "schema": "lightwork.no-code-grc-tombstone.v1",
                    "tenant_id": self.tenant_id,
                    "studio_id": row["studio_id"],
                    "version": row["version"],
                    "blueprint_sha256": row["blueprint_sha256"],
                    "purged_at": row["purged_at"],
                    "last_integrity_sha256": row["last_integrity_sha256"],
                }
                if not hmac.compare_digest(row["integrity_sha256"], self._mac(body)):
                    raise GRCStudioIntegrityError("studio tombstone integrity changed")
                if (row["studio_id"], int(row["version"])) in version_keys:
                    raise GRCStudioIntegrityError("studio tombstone overlaps live content")
                counts["tombstones"] += 1
        summary: dict[str, object] = {
            "schema": "lightwork.no-code-grc-integrity-report.v1",
            "tenant_scope_sha256": hashlib.sha256(self.tenant_id.encode()).hexdigest(),
            "verified": True,
            "counts": counts,
            "verified_at": self._now(),
        }
        return {**summary, "report_sha256": _sha256(summary)}

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def create_recovery_backup(self, tenant_id: str) -> dict[str, object]:
        """Create and authenticate one backup in the server-configured directory."""

        self._gate()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("recovery scope not found")
        if self._maintenance_authorizer() is not True:
            raise GRCStudioPermissionDenied("studio recovery requires maintenance authority")
        if self._recovery_directory is None:
            raise GRCStudioConfigError("studio recovery directory is not configured")
        actor = self._actor()
        now = self._now()
        backup_id = f"grc-{int(now)}-{secrets.token_hex(12)}"
        recovery = ensure_private_directory(self._recovery_directory)
        backup_path = recovery / f"{backup_id}.sqlite3"
        manifest_path = recovery / f"{backup_id}.json"
        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                self._begin(connection)
                self._audit(
                    connection,
                    "recovery_backup_started",
                    backup_id,
                    actor,
                    {},
                    now,
                )
                connection.commit()
            # Keep the cross-process lock through verification and backup so
            # the manifest's source report describes the exact SQLite snapshot.
            integrity = self._verify_integrity_unlocked()
            atomic_create_bytes(backup_path, b"", mode=0o600)
            with (
                self._connect() as source,
                sqlite3.connect(backup_path, factory=ClosingConnection) as destination,
            ):
                source.backup(destination)
                result = destination.execute("PRAGMA integrity_check").fetchone()
                if result is None or result[0] != "ok":
                    raise GRCStudioIntegrityError("recovery database integrity check failed")
            ensure_private_file(backup_path)
        body = {
            "schema": RECOVERY_SCHEMA,
            "backup_id": backup_id,
            "tenant_scope_sha256": hashlib.sha256(self.tenant_id.encode()).hexdigest(),
            "database_sha256": self._file_sha256(backup_path),
            "source_integrity_report_sha256": integrity["report_sha256"],
            "created_by_ref": actor,
            "created_at": now,
        }
        manifest = {**body, "manifest_hmac_sha256": self._mac(body)}
        atomic_write_text(manifest_path, _canonical(manifest).decode("ascii"), mode=0o600)
        ensure_private_file(manifest_path)
        with self._thread_lock, cross_process_lock(self._lock_path), self._connect() as connection:
            self._begin(connection)
            self._audit(
                connection,
                "recovery_backup_created",
                backup_id,
                actor,
                {
                    "database_sha256": body["database_sha256"],
                    "source_integrity_report_sha256": body["source_integrity_report_sha256"],
                },
                self._now(),
            )
            connection.commit()
        return manifest

    def list_recovery_backups(self, tenant_id: str, *, limit: int = 50) -> tuple[dict, ...]:
        """List this tenant's backup manifests, newest first.

        This is an index only: each entry still has to pass
        :meth:`verify_recovery_backup` before it can be trusted.
        """

        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("recovery scope not found")
        bound = _integer(limit, "limit", 1, 500)
        if self._recovery_directory is None or not self._recovery_directory.is_dir():
            return ()
        scope = hashlib.sha256(self.tenant_id.encode()).hexdigest()
        rows: list[dict[str, object]] = []
        for manifest_path in self._recovery_directory.glob("grc-*.json"):
            backup_id = manifest_path.stem
            if not _ID_RE.fullmatch(backup_id):
                continue
            try:
                raw = manifest_path.read_bytes()
                manifest = json.loads(raw) if len(raw) <= 64 * 1024 else None
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                not isinstance(manifest, Mapping)
                or manifest.get("schema") != RECOVERY_SCHEMA
                or manifest.get("backup_id") != backup_id
                or manifest.get("tenant_scope_sha256") != scope
            ):
                continue
            created_at = manifest.get("created_at")
            if isinstance(created_at, bool) or not isinstance(created_at, (int, float)):
                continue
            rows.append({"backup_id": backup_id, "created_at": float(created_at)})
        rows.sort(key=lambda row: (-float(row["created_at"]), str(row["backup_id"])))
        return tuple(rows[:bound])

    def verify_recovery_backup(self, tenant_id: str, backup_id: str) -> dict[str, object]:
        self._gate()
        self._actor()
        if _tenant(tenant_id) != self.tenant_id:
            raise GRCStudioNotFound("recovery backup not found")
        if self._recovery_directory is None:
            raise GRCStudioConfigError("studio recovery directory is not configured")
        selected = _id(backup_id, "backup_id")
        manifest_path = self._recovery_directory / f"{selected}.json"
        backup_path = self._recovery_directory / f"{selected}.sqlite3"
        try:
            ensure_private_file(manifest_path)
            ensure_private_file(backup_path)
            raw = manifest_path.read_bytes()
        except OSError as exc:
            raise GRCStudioNotFound("recovery backup not found") from exc
        if len(raw) > 64 * 1024:
            raise GRCStudioIntegrityError("recovery manifest exceeds its bound")
        try:
            manifest = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise GRCStudioIntegrityError("recovery manifest is unreadable") from exc
        expected_keys = frozenset(
            {
                "schema",
                "backup_id",
                "tenant_scope_sha256",
                "database_sha256",
                "source_integrity_report_sha256",
                "created_by_ref",
                "created_at",
                "manifest_hmac_sha256",
            }
        )
        if (
            not isinstance(manifest, Mapping)
            or set(manifest) != expected_keys
            or manifest["schema"] != RECOVERY_SCHEMA
            or manifest["backup_id"] != selected
        ):
            raise GRCStudioIntegrityError("recovery manifest schema is invalid")
        body = {key: manifest[key] for key in manifest if key != "manifest_hmac_sha256"}
        if not hmac.compare_digest(
            _digest(manifest["manifest_hmac_sha256"], "manifest_hmac_sha256"), self._mac(body)
        ):
            raise GRCStudioIntegrityError("recovery manifest authentication failed")
        if not hmac.compare_digest(
            _digest(manifest["tenant_scope_sha256"], "tenant_scope_sha256"),
            hashlib.sha256(self.tenant_id.encode()).hexdigest(),
        ):
            raise GRCStudioPermissionDenied("recovery backup belongs to another tenant scope")
        _digest(
            manifest["source_integrity_report_sha256"],
            "source_integrity_report_sha256",
        )
        _id(manifest["created_by_ref"], "created_by_ref")
        _timestamp(manifest["created_at"], "created_at")
        if not hmac.compare_digest(
            _digest(manifest["database_sha256"], "database_sha256"), self._file_sha256(backup_path)
        ):
            raise GRCStudioIntegrityError("recovery database digest changed")
        with sqlite3.connect(
            f"file:{backup_path}?mode=ro", uri=True, factory=ClosingConnection
        ) as connection:
            result = connection.execute("PRAGMA integrity_check").fetchone()
            if result is None or result[0] != "ok":
                raise GRCStudioIntegrityError("recovery database integrity check failed")
            tables = (
                "grc_versions",
                "grc_active",
                "grc_history",
                "grc_operations",
                "grc_audit",
                "grc_tombstones",
            )
            for table in tables:
                rows = connection.execute(
                    f"SELECT DISTINCT tenant_id FROM {table}"  # noqa: S608 -- fixed table allowlist
                ).fetchall()
                if any(row[0] != self.tenant_id for row in rows):
                    raise GRCStudioPermissionDenied(
                        "recovery database belongs to another tenant scope"
                    )
        return {
            "schema": "lightwork.no-code-grc-recovery-verification.v1",
            "backup_id": selected,
            "verified": True,
            "database_sha256": manifest["database_sha256"],
            "source_integrity_report_sha256": manifest["source_integrity_report_sha256"],
        }


__all__ = [
    "ACTION_TYPES",
    "APPLY_RECEIPT_SCHEMA",
    "ARBITRARY_CODE_SUPPORTED",
    "ARBITRARY_HTML_CSS_SUPPORTED",
    "BLUEPRINT_SCHEMA",
    "CALLER_URLS_SUPPORTED",
    "CONDITION_OPERATORS",
    "EXPORT_SCHEMA",
    "FIELD_TYPES",
    "GRCStudioConfigError",
    "GRCStudioConflict",
    "GRCStudioError",
    "GRCStudioIntegrityError",
    "GRCStudioNotFound",
    "GRCStudioPermissionDenied",
    "GRCStudioStore",
    "GRCStudioValidationError",
    "LIVE_PROVIDER_ACCEPTANCE_VERIFIED",
    "OBJECT_KINDS",
    "PROJECTION_KINDS",
    "RuntimeTargetAuthority",
    "STATES",
    "StudioVersion",
    "ActivePointer",
    "enabled",
    "issue_runtime_target_authority",
    "validate_blueprint",
]
