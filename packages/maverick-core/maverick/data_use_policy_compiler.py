"""Deterministic compiler for provider-neutral data-use control IR.

The compiler accepts only authorization decisions produced by the explicit
tenant authority in :mod:`maverick.data_use_governance`.  It re-resolves and
compares every bound record, validates a closed control vocabulary, and emits
immutable desired and safe rollback states.  It never accepts SQL or arbitrary
provider operations and never executes a provider mutation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import Any, Protocol

from .data_use_governance import (
    AUTHORITY_BUNDLE_SCHEMA,
    CONTEXT_KINDS,
    CONTROL_EFFECTS,
    FIELD_TYPES,
    MASKING_METHODS,
    DataUseCorruptionError,
    DataUseGovernanceStore,
    DataUseMissingAuthority,
    DataUseNotFound,
    DataUseStaleAuthority,
    DataUseValidationError,
    data_use_limits,
)
from .paths import canonical_tenant_id

CONTROL_IR_SCHEMA = "lightwork.data-use.control-ir.v1"
COMPILER_VERSION = "data-use-compiler/1"
_CONTROLLED_PROVIDER_OPERATIONS = frozenset({"apply_control_ir", "rollback_control_ir"})
_EFFECT_RANK = {"allow": 0, "mask": 1, "row_filter": 2, "review": 3, "deny": 4}
_SUPPORTED_FIELD_TYPES = frozenset(
    {"string", "integer", "number", "boolean", "date", "datetime", "uuid"}
)
_FUNCTIONS = {
    "lower": ({"string"}, "string"),
    "upper": ({"string"}, "string"),
    "date": ({"date", "datetime"}, "date"),
    "year": ({"date", "datetime"}, "integer"),
}
_COMPARISONS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte"})
_LOGICAL = frozenset({"and", "or"})
_SQLISH_RE = re.compile(r"(?:--|/\*|\*/|;)")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_DATETIME_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})\Z"
)
_MAX_JSON_BYTES = 512 * 1024
_MAX_AST_DEPTH = 16
_MAX_AST_NODES = 256
_MAX_SET_VALUES = 128


class DataUsePolicyCompilerError(RuntimeError):
    """Base error for control compilation."""


class DataUseCompilationValidationError(DataUsePolicyCompilerError, ValueError):
    """Decision or control material is outside the closed compiler contract."""


class DataUseCompilationStale(DataUsePolicyCompilerError):
    """A decision no longer matches current authoritative records."""


class DataUseUnsafeFilter(DataUseCompilationValidationError):
    """A row-filter expression is unsafe or not type-correct."""


class DataUseUnsupportedType(DataUseCompilationValidationError):
    """A requested control references an unsupported field type."""


class DataUseProviderOperationError(DataUseCompilationValidationError):
    """A native adapter exposes an uncontrolled provider operation."""


class NativeDataUseControlAdapter(Protocol):
    """Credential-owning seam for a separately implemented native adapter."""

    adapter_id: str
    adapter_authority_sha256: str
    control_schema: str
    supported_effects: frozenset[str]
    controlled_operations: frozenset[str]

    def apply_control_ir(
        self, control_ir: Mapping[str, Any], *, idempotency_sha256: str
    ) -> Mapping[str, Any]: ...

    def rollback_control_ir(
        self, control_ir: Mapping[str, Any], *, idempotency_sha256: str
    ) -> Mapping[str, Any]: ...


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise DataUseCompilationValidationError("compiler material must be finite JSON") from exc
    if not 1 <= len(encoded) <= _MAX_JSON_BYTES:
        raise DataUseCompilationValidationError("compiler material exceeds its byte bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise DataUseCompilationValidationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER_RE.fullmatch(value):
        raise DataUseCompilationValidationError(f"{label} is not a bounded opaque identifier")
    if _SQLISH_RE.search(value):
        raise DataUseCompilationValidationError(f"{label} contains prohibited syntax")
    return value


def _tenant_id(value: str) -> str:
    """Canonicalise a tenant with the rule the governance store applies."""

    try:
        return canonical_tenant_id(value)
    except ValueError as exc:
        raise DataUseCompilationValidationError("tenant_id is invalid") from exc


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise DataUseCompilationValidationError(f"{label} must be a positive finite timestamp")
    return float(value)


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    return value


def thaw_control_ir(value: object) -> Any:
    """Return a JSON-compatible copy of an immutable compiled IR."""

    if isinstance(value, Mapping):
        return {str(key): thaw_control_ir(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_control_ir(item) for item in value]
    return value


def _without_record_metadata(record: Mapping[str, Any], *extra: str) -> dict[str, Any]:
    omitted = {
        "revision",
        "record_sha256",
        "created_at",
        "updated_at",
        *extra,
    }
    return {key: value for key, value in record.items() if key not in omitted}


def _assert_tenant(value: object, tenant: str, label: str) -> None:
    if isinstance(value, Mapping):
        if "tenant_id" in value and value.get("tenant_id") != tenant:
            raise DataUseCompilationValidationError(f"{label} contains a cross-tenant reference")
        for key, item in value.items():
            _assert_tenant(item, tenant, f"{label}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for index, item in enumerate(value):
            _assert_tenant(item, tenant, f"{label}[{index}]")


def _literal(value: object, field_type: str, label: str) -> object:
    if field_type not in _SUPPORTED_FIELD_TYPES:
        raise DataUseUnsupportedType(f"{label} uses unsupported type {field_type}")
    if field_type in {"string", "uuid", "date", "datetime"}:
        if not isinstance(value, str) or len(value) > 512 or _SQLISH_RE.search(value):
            raise DataUseUnsafeFilter(f"{label} is not a safe bounded string literal")
        if field_type == "uuid" and not re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            value,
        ):
            raise DataUseUnsafeFilter(f"{label} is not a valid UUID literal")
        if field_type == "date" and not _DATE_RE.fullmatch(value):
            raise DataUseUnsafeFilter(f"{label} is not an ISO date literal")
        if field_type == "datetime" and not _DATETIME_RE.fullmatch(value):
            raise DataUseUnsafeFilter(f"{label} is not an ISO datetime literal")
        return value
    if field_type == "boolean":
        if not isinstance(value, bool):
            raise DataUseUnsafeFilter(f"{label} must be boolean")
        return value
    if field_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            raise DataUseUnsafeFilter(f"{label} must be an integer")
        return value
    if field_type == "number":
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise DataUseUnsafeFilter(f"{label} must be a finite number")
        return value
    raise DataUseUnsupportedType(f"{label} uses unsupported type {field_type}")


def compiler_limits(config: Mapping[str, Any] | None = None) -> tuple[int, int | None]:
    """``(row-filter parts, operations)`` from ``[data_use_governance.compiler]``.

    ``max_row_filter_nodes`` lowers the built-in 256-part row-filter bound
    (the native adapters accept no more than 256, so it can only be lowered).
    ``max_operations`` caps how many controls one decision may compile to;
    unset means no cap beyond the policy bounds (the historical behaviour).
    """
    if config is None:
        from .config import load_config

        config = load_config() or {}
    root = config.get("data_use_governance") if isinstance(config, Mapping) else None
    section = root.get("compiler") if isinstance(root, Mapping) else None
    section = section if isinstance(section, Mapping) else {}
    nodes, operations = _MAX_AST_NODES, None
    for key, upper in (("max_row_filter_nodes", _MAX_AST_NODES), ("max_operations", 10_000)):
        if key not in section:
            continue
        value = section[key]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= upper:
            raise DataUseCompilationValidationError(
                f"data-use compiler {key} must be between 1 and {upper}"
            )
        if key == "max_row_filter_nodes":
            nodes = value
        else:
            operations = value
    return nodes, operations


class _AstBudget:
    def __init__(self, max_nodes: int = _MAX_AST_NODES) -> None:
        self.nodes = 0
        self.max_nodes = max_nodes

    def consume(self, depth: int) -> None:
        self.nodes += 1
        if depth > _MAX_AST_DEPTH or self.nodes > self.max_nodes:
            raise DataUseUnsafeFilter("row-filter AST exceeds its complexity bound")


def _field_expression(
    value: object,
    field_types: Mapping[str, str],
    budget: _AstBudget,
    depth: int,
) -> tuple[dict[str, Any], str]:
    budget.consume(depth)
    if not isinstance(value, Mapping):
        raise DataUseUnsafeFilter("row-filter expression must be an object")
    if set(value) == {"field"}:
        field = _identifier(value.get("field"), "row-filter field")
        if field not in field_types:
            raise DataUseUnsafeFilter(f"row-filter references unknown field {field}")
        field_type = field_types[field]
        if field_type not in _SUPPORTED_FIELD_TYPES:
            raise DataUseUnsupportedType(
                f"row-filter field {field} uses unsupported type {field_type}"
            )
        return {"field": field}, field_type
    if set(value) == {"function", "args"}:
        function = _identifier(value.get("function"), "row-filter function")
        if function not in _FUNCTIONS:
            raise DataUseUnsafeFilter(f"row-filter function {function} is unsupported")
        args = value.get("args")
        if isinstance(args, (str, bytes)) or not isinstance(args, Sequence) or len(args) != 1:
            raise DataUseUnsafeFilter("row-filter function requires exactly one argument")
        normalized, argument_type = _field_expression(args[0], field_types, budget, depth + 1)
        accepted, result_type = _FUNCTIONS[function]
        if argument_type not in accepted:
            raise DataUseUnsafeFilter(
                f"row-filter function {function} does not accept {argument_type}"
            )
        return {"function": function, "args": [normalized]}, result_type
    raise DataUseUnsafeFilter("row-filter expression contains unknown fields")


def normalize_row_filter_ast(
    value: object,
    field_types: Mapping[str, str],
    *,
    max_nodes: int | None = None,
) -> dict[str, Any]:
    """Validate and normalize the closed, non-SQL row-filter AST.

    ``max_nodes`` defaults to the installation's row-filter bound
    (:func:`compiler_limits`).
    """

    normalized_types = {
        _identifier(key, "field identifier"): _identifier(field_type, "field type")
        for key, field_type in field_types.items()
    }
    budget = _AstBudget(compiler_limits()[0] if max_nodes is None else max_nodes)

    def visit(node: object, depth: int) -> dict[str, Any]:
        budget.consume(depth)
        if not isinstance(node, Mapping):
            raise DataUseUnsafeFilter("row-filter node must be an object")
        operation = _identifier(node.get("op"), "row-filter operation")
        if operation in _LOGICAL:
            if set(node) != {"op", "args"}:
                raise DataUseUnsafeFilter("logical row-filter node has unknown fields")
            args = node.get("args")
            if (
                isinstance(args, (str, bytes))
                or not isinstance(args, Sequence)
                or not 2 <= len(args) <= 32
            ):
                raise DataUseUnsafeFilter("logical row-filter requires 2 to 32 arguments")
            normalized = [visit(item, depth + 1) for item in args]
            normalized.sort(key=_sha256)
            return {"op": operation, "args": normalized}
        if operation == "not":
            if set(node) != {"op", "arg"}:
                raise DataUseUnsafeFilter("not row-filter node has unknown fields")
            return {"op": "not", "arg": visit(node.get("arg"), depth + 1)}

        shorthand = "field" in node and "left" not in node
        left_raw: object = {"field": node.get("field")} if shorthand else node.get("left")
        left, result_type = _field_expression(left_raw, normalized_types, budget, depth + 1)
        expected_base = {"op", "field"} if shorthand else {"op", "left"}
        if operation in _COMPARISONS:
            if set(node) != expected_base | {"value"}:
                raise DataUseUnsafeFilter("comparison row-filter has unknown fields")
            if operation in {"lt", "lte", "gt", "gte"} and result_type not in {
                "string",
                "integer",
                "number",
                "date",
                "datetime",
            }:
                raise DataUseUnsafeFilter(f"ordering comparison does not support {result_type}")
            return {
                "op": operation,
                "left": left,
                "value": _literal(node.get("value"), result_type, "comparison value"),
            }
        if operation == "in":
            if set(node) != expected_base | {"values"}:
                raise DataUseUnsafeFilter("in row-filter has unknown fields")
            values = node.get("values")
            if (
                isinstance(values, (str, bytes))
                or not isinstance(values, Sequence)
                or not 1 <= len(values) <= _MAX_SET_VALUES
            ):
                raise DataUseUnsafeFilter("in row-filter values are outside their bound")
            normalized_values = [_literal(item, result_type, "in value") for item in values]
            normalized_values.sort(key=_sha256)
            return {"op": "in", "left": left, "values": normalized_values}
        if operation in {"is_null", "not_null"}:
            if set(node) != expected_base:
                raise DataUseUnsafeFilter("null row-filter has unknown fields")
            return {"op": operation, "left": left}
        raise DataUseUnsafeFilter(f"row-filter operation {operation} is unsupported")

    return visit(value, 0)


def _validate_mask(method: str, field_type: str, nullable: bool) -> None:
    if method not in MASKING_METHODS:
        raise DataUseCompilationValidationError("masking method is unsupported")
    if field_type not in _SUPPORTED_FIELD_TYPES:
        raise DataUseUnsupportedType(f"masking method {method} uses unsupported type {field_type}")
    if method == "null" and not nullable:
        raise DataUseCompilationValidationError("null masking cannot target a non-nullable field")
    allowed = {
        "redact": _SUPPORTED_FIELD_TYPES,
        "null": _SUPPORTED_FIELD_TYPES,
        "hash_sha256": frozenset({"string", "uuid"}),
        "tokenize": frozenset({"string", "uuid"}),
        "preserve_last4": frozenset({"string"}),
        "bucket": frozenset({"integer", "number"}),
        "generalize_date": frozenset({"date", "datetime"}),
    }[method]
    if field_type not in allowed:
        raise DataUseCompilationValidationError(
            f"masking method {method} does not support {field_type}"
        )


def _adapter_is_controlled(adapter: object | None) -> bool:
    if adapter is None:
        return False
    if getattr(adapter, "control_schema", None) != CONTROL_IR_SCHEMA:
        raise DataUseProviderOperationError("native adapter control schema is unsupported")
    adapter_id = getattr(adapter, "adapter_id", None)
    _identifier(adapter_id, "native adapter_id")
    _digest(
        getattr(adapter, "adapter_authority_sha256", None),
        "native adapter_authority_sha256",
    )
    effects = getattr(adapter, "supported_effects", None)
    if not isinstance(effects, frozenset) or not effects or not effects.issubset(CONTROL_EFFECTS):
        raise DataUseProviderOperationError("native adapter effects are uncontrolled")
    operations = getattr(adapter, "controlled_operations", None)
    if operations != _CONTROLLED_PROVIDER_OPERATIONS:
        raise DataUseProviderOperationError("native adapter operations are uncontrolled")
    if not callable(getattr(adapter, "apply_control_ir", None)) or not callable(
        getattr(adapter, "rollback_control_ir", None)
    ):
        raise DataUseProviderOperationError("native adapter mutation contract is incomplete")
    return True


_COMPILER_SHA256 = _sha256(
    {
        "schema": CONTROL_IR_SCHEMA,
        "version": COMPILER_VERSION,
        "effects": sorted(CONTROL_EFFECTS),
        "masking_methods": sorted(MASKING_METHODS),
        "field_types": sorted(_SUPPORTED_FIELD_TYPES),
        "row_filter_operations": sorted(
            {*_COMPARISONS, *_LOGICAL, "not", "in", "is_null", "not_null"}
        ),
        "row_filter_functions": sorted(_FUNCTIONS),
    }
)


class DataUsePolicyCompiler:
    """Compile exact current authority into immutable provider-neutral IR."""

    def __init__(
        self,
        store: DataUseGovernanceStore,
        *,
        clock: Callable[[], float] = time.time,
        native_adapter: NativeDataUseControlAdapter | None = None,
    ) -> None:
        if not callable(getattr(store, "resolve_compilation_authority", None)):
            raise DataUseCompilationValidationError(
                "compiler requires a data-use authority resolver"
            )
        self._store = store
        self._clock = clock
        self._native_adapter = native_adapter
        self._provider_writes_possible = _adapter_is_controlled(native_adapter)

    @property
    def provider_writes_possible(self) -> bool:
        return self._provider_writes_possible

    def _now(self) -> float:
        try:
            return _timestamp(self._clock(), "compiler clock")
        except (KeyboardInterrupt, SystemExit):
            raise
        except DataUseCompilationValidationError:
            raise
        except Exception as exc:
            raise DataUsePolicyCompilerError("compiler clock is unavailable") from exc

    @staticmethod
    def _validate_bundle_digest(bundle: Mapping[str, Any]) -> None:
        if bundle.get("schema") != AUTHORITY_BUNDLE_SCHEMA:
            raise DataUseCompilationValidationError("authority bundle schema is unsupported")
        actual = _digest(bundle.get("bundle_sha256"), "bundle_sha256")
        expected = _sha256({key: value for key, value in bundle.items() if key != "bundle_sha256"})
        if not hmac.compare_digest(actual, expected):
            raise DataUseCorruptionError("authority bundle digest does not match")

    @staticmethod
    def _validate_decision_digest(decision: Mapping[str, Any]) -> None:
        actual = _digest(decision.get("decision_sha256"), "decision_sha256")
        expected = _sha256(_without_record_metadata(decision, "decision_sha256"))
        if not hmac.compare_digest(actual, expected):
            raise DataUseCorruptionError("authorization decision digest does not match")
        authority = decision.get("authority")
        if not isinstance(authority, Mapping):
            raise DataUseCompilationValidationError("decision authority is missing")
        bound = _digest(decision.get("authority_sha256"), "authority_sha256")
        if not hmac.compare_digest(bound, _sha256(authority)):
            raise DataUseCorruptionError("decision authority digest does not match")

    @staticmethod
    def _validate_contexts(
        contexts: object, *, now: float, tenant: str, asset_id: str
    ) -> list[Mapping[str, Any]]:
        if isinstance(contexts, (str, bytes)) or not isinstance(contexts, Sequence):
            raise DataUseMissingAuthority("decision contexts are missing")
        values = list(contexts)
        kinds = [item.get("context_kind") for item in values if isinstance(item, Mapping)]
        if sorted(kinds) != sorted(CONTEXT_KINDS) or len(values) != len(CONTEXT_KINDS):
            raise DataUseMissingAuthority("all four independent decision contexts are required")
        try:
            max_age = data_use_limits().get("max_context_age_seconds")
        except DataUseValidationError as exc:
            raise DataUseCompilationValidationError(str(exc)) from exc
        source_roots: set[str] = set()
        for context in values:
            if not isinstance(context, Mapping):
                raise DataUseMissingAuthority("decision context is malformed")
            _assert_tenant(context, tenant, "context")
            if context.get("asset_id") != asset_id:
                raise DataUseCompilationValidationError("decision context references another asset")
            source_roots.add(
                _digest(
                    context.get("source_authority_sha256"),
                    "source_authority_sha256",
                )
            )
            _digest(context.get("reviewer_authority_sha256"), "reviewer authority")
            _identifier(context.get("reviewer_id"), "reviewer_id")
            if _timestamp(context.get("fresh_until"), "fresh_until") <= now or (
                max_age is not None
                and now - _timestamp(context.get("observed_at"), "observed_at") > max_age
            ):
                raise DataUseCompilationStale("decision context is stale")
            semantic = _without_record_metadata(context, "context_sha256")
            actual = _digest(context.get("context_sha256"), "context_sha256")
            if not hmac.compare_digest(actual, _sha256(semantic)):
                raise DataUseCorruptionError("decision context digest does not match")
        if len(source_roots) != len(CONTEXT_KINDS):
            raise DataUseMissingAuthority(
                "decision contexts do not have independent authority roots"
            )
        return values

    @staticmethod
    def _field_map(
        authority: Mapping[str, Any], decision: Mapping[str, Any], tenant: str
    ) -> dict[str, Mapping[str, Any]]:
        raw_fields = authority.get("fields")
        if isinstance(raw_fields, (str, bytes)) or not isinstance(raw_fields, Sequence):
            raise DataUseMissingAuthority("field authority is missing")
        result: dict[str, Mapping[str, Any]] = {}
        for field in raw_fields:
            if not isinstance(field, Mapping):
                raise DataUseCompilationValidationError("field authority is malformed")
            _assert_tenant(field, tenant, "field")
            field_id = _identifier(field.get("field_id"), "field_id")
            if field.get("asset_id") != decision.get("asset_id"):
                raise DataUseCompilationValidationError("field authority references another asset")
            field_type = _identifier(field.get("data_type"), "field data_type")
            if field_type not in FIELD_TYPES:
                raise DataUseUnsupportedType(f"unknown field type {field_type}")
            if field_type not in _SUPPORTED_FIELD_TYPES:
                raise DataUseUnsupportedType(f"unsupported field type {field_type}")
            if field_id in result:
                raise DataUseCompilationValidationError(
                    "field authority contains duplicate identifiers"
                )
            result[field_id] = field
        expected = decision.get("field_ids")
        if isinstance(expected, (str, bytes)) or not isinstance(expected, Sequence):
            raise DataUseCompilationValidationError("decision field_ids are malformed")
        if sorted(result) != sorted(expected):
            raise DataUseMissingAuthority("decision field authority is incomplete")
        return result

    @staticmethod
    def _validate_labels(
        authority: Mapping[str, Any],
        fields: Mapping[str, Mapping[str, Any]],
        tenant: str,
    ) -> None:
        for entry in authority.get("labels", []):
            if not isinstance(entry, Mapping):
                raise DataUseCompilationValidationError("label binding is malformed")
            assignment = entry.get("assignment")
            pointer = entry.get("pointer")
            version = entry.get("version")
            if not all(isinstance(item, Mapping) for item in (assignment, pointer, version)):
                raise DataUseCompilationValidationError("label authority is incomplete")
            assert isinstance(assignment, Mapping)
            assert isinstance(pointer, Mapping)
            assert isinstance(version, Mapping)
            _assert_tenant(entry, tenant, "label authority")
            field_id = _identifier(assignment.get("field_id"), "label field_id")
            field = fields.get(field_id)
            if field is None:
                raise DataUseCompilationValidationError(
                    "label references an unknown decision field"
                )
            if (
                assignment.get("status") != "active"
                or assignment.get("field_revision") != field.get("revision")
                or assignment.get("field_sha256") != field.get("record_sha256")
                or assignment.get("label_id") != pointer.get("label_id")
                or assignment.get("label_version") != pointer.get("current_version")
                or pointer.get("state") != "active"
                or assignment.get("label_pointer_revision") != pointer.get("revision")
                or assignment.get("label_pointer_sha256") != pointer.get("record_sha256")
                or assignment.get("label_id") != version.get("label_id")
                or assignment.get("label_version") != version.get("version")
            ):
                raise DataUseCompilationStale("reviewed label binding is stale")
            reviewer = _identifier(version.get("reviewer_id"), "label reviewer_id")
            if not reviewer:
                raise DataUseCompilationValidationError("label reviewer is missing")
            _digest(
                version.get("reviewer_authority_sha256"),
                "label reviewer_authority_sha256",
            )
            expected_label = _sha256(_without_record_metadata(version, "label_sha256"))
            actual_label = _digest(version.get("label_sha256"), "label_sha256")
            if not hmac.compare_digest(expected_label, actual_label):
                raise DataUseCorruptionError("reviewed label digest does not match")
            if assignment.get("label_sha256") != actual_label:
                raise DataUseCompilationStale("label assignment does not bind the reviewed version")
            expected_assignment = _sha256(_without_record_metadata(assignment, "assignment_sha256"))
            actual_assignment = _digest(assignment.get("assignment_sha256"), "assignment_sha256")
            if not hmac.compare_digest(expected_assignment, actual_assignment):
                raise DataUseCorruptionError("label assignment digest does not match")

    @staticmethod
    def _binding_indexes(
        authority: Mapping[str, Any],
    ) -> tuple[dict[str, tuple[int, str]], dict[str, tuple[str, int, str]]]:
        policies: dict[str, tuple[int, str]] = {}
        for entry in authority.get("policies", []):
            if not isinstance(entry, Mapping) or not isinstance(entry.get("pointer"), Mapping):
                raise DataUseCompilationValidationError("policy binding is malformed")
            pointer = entry["pointer"]
            version = entry.get("version")
            if not isinstance(version, Mapping):
                raise DataUseCompilationValidationError("policy version binding is missing")
            policy_id = _identifier(pointer.get("policy_id"), "policy_id")
            if (
                pointer.get("state") != "active"
                or pointer.get("active_version") != version.get("version")
                or pointer.get("current_semantic_sha256") != version.get("semantic_sha256")
            ):
                raise DataUseCompilationStale("policy binding is no longer active")
            if not isinstance(pointer.get("reviewer_id"), str) or not isinstance(
                pointer.get("reviewer_authority_sha256"), str
            ):
                raise DataUseCompilationValidationError("active policy reviewer binding is missing")
            _identifier(pointer.get("reviewer_id"), "policy reviewer_id")
            _digest(
                pointer.get("reviewer_authority_sha256"),
                "policy reviewer_authority_sha256",
            )
            if not hmac.compare_digest(
                _digest(version.get("semantic_sha256"), "policy semantic_sha256"),
                _sha256(version.get("document")),
            ):
                raise DataUseCorruptionError("policy semantic digest does not match")
            policies[policy_id] = (
                int(version["version"]),
                _digest(version.get("semantic_sha256"), "policy semantic_sha256"),
            )
        exceptions: dict[str, tuple[str, int, str]] = {}
        for exception in authority.get("exceptions", []):
            if not isinstance(exception, Mapping):
                raise DataUseCompilationValidationError("exception binding is malformed")
            if exception.get("state") != "approved":
                raise DataUseCompilationStale("exception binding is not approved")
            exception_id = _identifier(exception.get("exception_id"), "exception_id")
            exception_version = exception.get("policy_version")
            if (
                isinstance(exception_version, bool)
                or not isinstance(exception_version, int)
                or exception_version < 1
            ):
                raise DataUseCompilationValidationError("exception policy version is invalid")
            exceptions[exception_id] = (
                _identifier(exception.get("policy_id"), "exception policy_id"),
                exception_version,
                _digest(
                    exception.get("policy_semantic_sha256"),
                    "exception policy_semantic_sha256",
                ),
            )
        return policies, exceptions

    @staticmethod
    def _normalize_decision_control(
        control: object,
        *,
        asset_id: str,
        fields: Mapping[str, Mapping[str, Any]],
        policy_bindings: Mapping[str, tuple[int, str]],
        exception_bindings: Mapping[str, tuple[str, int, str]],
    ) -> dict[str, Any]:
        if not isinstance(control, Mapping):
            raise DataUseCompilationValidationError("decision control is not an object")
        allowed = {
            "control_id",
            "effect",
            "field_id",
            "field_ids",
            "mask_method",
            "row_filter",
            "source_policy_id",
            "source_policy_version",
            "source_policy_sha256",
            "source_exception_id",
        }
        unknown = sorted(set(control) - allowed)
        if unknown:
            raise DataUseProviderOperationError(
                "decision control contains uncontrolled fields: " + ", ".join(unknown)
            )
        control_id = _identifier(control.get("control_id"), "control_id")
        effect = _identifier(control.get("effect"), "control effect")
        if effect not in CONTROL_EFFECTS:
            raise DataUseProviderOperationError("control effect is uncontrolled")
        field_id = _identifier(control.get("field_id"), "control field_id")
        if field_id not in fields:
            raise DataUseCompilationValidationError(
                "control references an unknown field identifier"
            )
        source_policy = control.get("source_policy_id")
        source_exception = control.get("source_exception_id")
        source: dict[str, Any]
        if source_policy is None:
            if effect != "deny" or source_exception is not None:
                raise DataUseCompilationValidationError(
                    "only system default-deny controls may omit a policy binding"
                )
            source = {
                "policy_id": None,
                "policy_version": None,
                "policy_sha256": None,
                "exception_id": None,
            }
        else:
            policy_id = _identifier(source_policy, "source_policy_id")
            if policy_id not in policy_bindings:
                raise DataUseCompilationStale("control policy binding is unavailable")
            policy_version = control.get("source_policy_version")
            if (
                isinstance(policy_version, bool)
                or not isinstance(policy_version, int)
                or policy_version < 1
            ):
                raise DataUseCompilationValidationError("control policy version is invalid")
            policy_digest = _digest(control.get("source_policy_sha256"), "source_policy_sha256")
            if policy_bindings[policy_id] != (policy_version, policy_digest):
                raise DataUseCompilationStale(
                    "control does not match the exact active policy binding"
                )
            if source_exception is not None:
                exception_id = _identifier(source_exception, "source_exception_id")
                if exception_id not in exception_bindings:
                    raise DataUseCompilationStale("control exception binding is unavailable")
                if exception_bindings[exception_id] != (
                    policy_id,
                    policy_version,
                    policy_digest,
                ):
                    raise DataUseCompilationStale(
                        "control does not match the exact exception binding"
                    )
            else:
                exception_id = None
            source = {
                "policy_id": policy_id,
                "policy_version": policy_version,
                "policy_sha256": policy_digest,
                "exception_id": exception_id,
            }

        field = fields[field_id]
        field_type = str(field["data_type"])
        nullable = field.get("nullable")
        if not isinstance(nullable, bool):
            raise DataUseCompilationValidationError("field nullable binding is invalid")
        parameters: dict[str, Any] = {}
        mask_method = control.get("mask_method")
        row_filter = control.get("row_filter")
        if effect == "mask":
            method = _identifier(mask_method, "mask_method")
            _validate_mask(method, field_type, nullable)
            if row_filter is not None:
                raise DataUseCompilationValidationError("mask control contains a row filter")
            parameters = {"method": method}
        elif mask_method is not None:
            raise DataUseCompilationValidationError("non-mask control contains a masking method")
        if effect == "row_filter":
            if row_filter is None:
                raise DataUseCompilationValidationError("row_filter control is missing its AST")
            parameters = {
                "ast": normalize_row_filter_ast(
                    row_filter,
                    {key: str(value["data_type"]) for key, value in fields.items()},
                )
            }
        elif row_filter is not None:
            raise DataUseCompilationValidationError("non-row-filter control contains a row filter")
        return {
            "operation": effect,
            "control_id": control_id,
            "asset_id": asset_id,
            "field_id": field_id,
            "parameters": parameters,
            "source": source,
        }

    def compile(  # noqa: C901 - one linear fail-closed authority validation walk
        self,
        tenant_id: str,
        decision_id: str,
        *,
        expected_decision_sha256: str | None = None,
    ) -> Mapping[str, Any]:
        """Compile one decision, rejecting any stale or unsafe authority."""

        tenant = _tenant_id(tenant_id)
        identity = _identifier(decision_id, "decision_id")
        try:
            bundle = self._store.resolve_compilation_authority(tenant, identity)
        except (DataUseMissingAuthority, DataUseNotFound) as exc:
            raise DataUseCompilationStale("decision authority is missing") from exc
        except DataUseStaleAuthority as exc:
            raise DataUseCompilationStale("decision authority is stale") from exc
        if not isinstance(bundle, Mapping):
            raise DataUseCompilationValidationError("authority resolver returned an invalid bundle")
        self._validate_bundle_digest(bundle)
        if bundle.get("tenant_id") != tenant:
            raise DataUseCompilationValidationError("authority resolver crossed a tenant boundary")
        _assert_tenant(bundle, tenant, "authority bundle")
        decision = bundle.get("decision")
        current = bundle.get("current_authority")
        if not isinstance(decision, Mapping) or not isinstance(current, Mapping):
            raise DataUseMissingAuthority("decision or current authority is missing")
        self._validate_decision_digest(decision)
        if decision.get("decision_id") != identity:
            raise DataUseCompilationValidationError("decision identity does not match")
        if expected_decision_sha256 is not None and not hmac.compare_digest(
            _digest(expected_decision_sha256, "expected_decision_sha256"),
            str(decision["decision_sha256"]),
        ):
            raise DataUseCompilationStale("decision digest precondition changed")
        reasons = bundle.get("current_authority_reasons")
        if reasons:
            raise DataUseCompilationStale("current authority has incomplete or stale bindings")
        current_sha256 = _sha256(current)
        if not hmac.compare_digest(str(decision["authority_sha256"]), current_sha256):
            raise DataUseCompilationStale("decision no longer matches current authority")
        now = self._now()
        if _timestamp(decision.get("expires_at"), "decision expires_at") <= now:
            raise DataUseCompilationStale("authorization decision is stale")
        asset = current.get("asset")
        if not isinstance(asset, Mapping):
            raise DataUseMissingAuthority("asset authority is missing")
        asset_id = _identifier(asset.get("asset_id"), "asset_id")
        if asset_id != decision.get("asset_id"):
            raise DataUseCompilationValidationError("decision asset binding does not match")
        fields = self._field_map(current, decision, tenant)
        self._validate_contexts(current.get("contexts"), now=now, tenant=tenant, asset_id=asset_id)
        self._validate_labels(current, fields, tenant)
        policy_bindings, exception_bindings = self._binding_indexes(current)
        raw_controls = decision.get("controls")
        if isinstance(raw_controls, (str, bytes)) or not isinstance(raw_controls, Sequence):
            raise DataUseCompilationValidationError("decision controls are missing")
        desired = [
            self._normalize_decision_control(
                control,
                asset_id=asset_id,
                fields=fields,
                policy_bindings=policy_bindings,
                exception_bindings=exception_bindings,
            )
            for control in raw_controls
        ]
        if not desired:
            raise DataUseCompilationValidationError("decision controls are empty")
        most_operations = compiler_limits()[1]
        if most_operations is not None and len(desired) > most_operations:
            raise DataUseCompilationValidationError(
                "decision compiles to more operations than this installation allows"
            )
        desired.sort(
            key=lambda item: (
                item["asset_id"],
                item["field_id"],
                item["operation"],
                item["control_id"],
                _sha256(item),
            )
        )
        target_counts = dict.fromkeys(fields, 0)
        for item in desired:
            target_counts[item["field_id"]] += 1
        if any(count < 1 for count in target_counts.values()):
            raise DataUseCompilationValidationError(
                "decision does not control every requested field"
            )
        outcome = decision.get("outcome")
        if outcome not in CONTROL_EFFECTS:
            raise DataUseCompilationValidationError("decision outcome is unsupported")
        effective_outcome = max(
            (item["operation"] for item in desired),
            key=lambda effect: _EFFECT_RANK[effect],
        )
        if effective_outcome != outcome:
            raise DataUseCorruptionError("decision outcome does not match its effective controls")
        if self._native_adapter is not None:
            supported = self._native_adapter.supported_effects
            uncontrolled = sorted({item["operation"] for item in desired} - set(supported))
            if uncontrolled:
                raise DataUseProviderOperationError(
                    "native adapter does not control effects: " + ", ".join(uncontrolled)
                )
        rollback = [
            {
                "operation": "deny",
                "control_id": f"rollback-deny-{field_id}",
                "asset_id": asset_id,
                "field_id": field_id,
                "parameters": {},
                "source": {
                    "policy_id": None,
                    "policy_version": None,
                    "policy_sha256": None,
                    "exception_id": None,
                },
            }
            for field_id in sorted(fields)
        ]
        bindings = {
            "decision": {
                "decision_id": identity,
                "decision_sha256": decision["decision_sha256"],
                "record_revision": decision["revision"],
                "record_sha256": decision["record_sha256"],
            },
            "request": {
                "request_id": current["request"]["request_id"],
                "revision": current["request"]["revision"],
                "record_sha256": current["request"]["record_sha256"],
            },
            "asset": {
                "asset_id": asset_id,
                "revision": asset["revision"],
                "record_sha256": asset["record_sha256"],
            },
            "fields": [
                {
                    "field_id": field_id,
                    "revision": fields[field_id]["revision"],
                    "record_sha256": fields[field_id]["record_sha256"],
                }
                for field_id in sorted(fields)
            ],
            "contexts": [
                {
                    "context_kind": item["context_kind"],
                    "revision": item["revision"],
                    "record_sha256": item["record_sha256"],
                    "context_sha256": item["context_sha256"],
                    "source_revision": item["source_revision"],
                    "source_authority_sha256": item["source_authority_sha256"],
                    "reviewer_id": item["reviewer_id"],
                    "reviewer_authority_sha256": item["reviewer_authority_sha256"],
                    "fresh_until": item["fresh_until"],
                }
                for item in sorted(current["contexts"], key=lambda value: value["context_kind"])
            ],
            "policies": [
                {
                    "policy_id": item["pointer"]["policy_id"],
                    "version": item["version"]["version"],
                    "pointer_revision": item["pointer"]["revision"],
                    "pointer_sha256": item["pointer"]["record_sha256"],
                    "semantic_sha256": item["version"]["semantic_sha256"],
                }
                for item in sorted(
                    current.get("policies", []),
                    key=lambda value: value["pointer"]["policy_id"],
                )
            ],
            "labels": [
                {
                    "assignment_id": item["assignment"]["record_id"],
                    "assignment_revision": item["assignment"]["revision"],
                    "assignment_sha256": item["assignment"]["assignment_sha256"],
                    "label_id": item["assignment"]["label_id"],
                    "label_version": item["assignment"]["label_version"],
                    "label_sha256": item["version"]["label_sha256"],
                    "reviewer_id": item["version"]["reviewer_id"],
                    "reviewer_authority_sha256": item["version"]["reviewer_authority_sha256"],
                }
                for item in sorted(
                    current.get("labels", []),
                    key=lambda value: value["assignment"]["record_id"],
                )
            ],
            "exceptions": [
                {
                    "exception_id": item["exception_id"],
                    "revision": item["revision"],
                    "record_sha256": item["record_sha256"],
                    "policy_id": item["policy_id"],
                    "policy_version": item["policy_version"],
                    "expires_at": item["expires_at"],
                }
                for item in sorted(
                    current.get("exceptions", []),
                    key=lambda value: value["exception_id"],
                )
            ],
        }
        bindings_sha256 = _sha256(bindings)
        desired_sha256 = _sha256(
            {
                "kind": "desired",
                "bindings_sha256": bindings_sha256,
                "controls": desired,
            }
        )
        rollback_sha256 = _sha256(
            {
                "kind": "rollback",
                "bindings_sha256": bindings_sha256,
                "controls": rollback,
            }
        )
        adapter_binding = (
            {
                "adapter_id": self._native_adapter.adapter_id,
                "adapter_authority_sha256": self._native_adapter.adapter_authority_sha256,
                "control_schema": self._native_adapter.control_schema,
                "supported_effects": sorted(self._native_adapter.supported_effects),
                "controlled_operations": sorted(self._native_adapter.controlled_operations),
            }
            if self._native_adapter is not None
            else None
        )
        material = {
            "schema": CONTROL_IR_SCHEMA,
            "tenant_id": tenant,
            "compiler": {
                "version": COMPILER_VERSION,
                "compiler_sha256": _COMPILER_SHA256,
            },
            "bindings": bindings,
            "bindings_sha256": bindings_sha256,
            "desired_state": desired,
            "desired_state_sha256": desired_sha256,
            "rollback_state": rollback,
            "rollback_state_sha256": rollback_sha256,
            "native_adapter": adapter_binding,
            "provider_writes_possible": self._provider_writes_possible,
            "live_provider_acceptance_verified": False,
        }
        ir_sha256 = _sha256(material)
        output = {
            **material,
            "compilation_id": f"duc-{ir_sha256[:40]}",
            "ir_sha256": ir_sha256,
        }
        return _freeze(output)

    def status(self) -> Mapping[str, Any]:
        return _freeze(
            {
                "schema": "lightwork.data-use.compiler-status.v1",
                "compiler_version": COMPILER_VERSION,
                "compiler_sha256": _COMPILER_SHA256,
                "provider_writes_possible": self._provider_writes_possible,
                "native_adapter_attached": self._native_adapter is not None,
                "provider_operations_executed": False,
                "live_provider_acceptance_verified": False,
            }
        )


__all__ = [
    "COMPILER_VERSION",
    "CONTROL_IR_SCHEMA",
    "DataUseCompilationStale",
    "DataUseCompilationValidationError",
    "DataUsePolicyCompiler",
    "DataUsePolicyCompilerError",
    "DataUseProviderOperationError",
    "DataUseUnsafeFilter",
    "DataUseUnsupportedType",
    "NativeDataUseControlAdapter",
    "compiler_limits",
    "normalize_row_filter_ast",
    "thaw_control_ir",
]
