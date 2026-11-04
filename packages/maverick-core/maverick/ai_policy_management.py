"""Operational, tenant-scoped AI policy management.

This module turns policy prose into deterministic runtime decision records.  A
policy is an immutable sequence of versions.  Each version contains bounded
statements, applicability conditions, an effect, and required controls.  A
human principal must activate a version with compare-and-swap (CAS), and the
strictest applicable statement wins.

Exceptions are separate governed records.  They are pinned to an exact policy
version and digest, require a different human requester and approver, expire
automatically, and can be closed explicitly.  An applicable approved exception
waives only its selected statements and adds its compensating controls; it
never changes another policy's result.

Recorded evaluations retain the exact active-policy authority and decision
digests used at assessment time.  Reads recompute the current decision, so a
policy activation, exception lifecycle change, or exception expiry makes a
prior evaluation and its attestation visibly stale.  The feature is default
off behind ``[ai_policy_management].enable = true``.

The module provides decision support, not legal advice, certification, or an
autonomous compliance determination.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

POLICY_SCHEMA = "lightwork.ai-operational-policy.v1"
EXCEPTION_SCHEMA = "lightwork.ai-policy-exception.v1"
EVALUATION_SCHEMA = "lightwork.ai-policy-evaluation.v1"
DECISION_SCHEMA = "lightwork.ai-policy-decision.v1"
NON_CERTIFICATION_NOTICE = (
    "Operational policy decision support only; not legal advice, a conformity "
    "assessment, certification, or autonomous compliance determination."
)

_POLICIES = GovernedRecordStore(
    "ai_operational_policies", "AOP", "ai_operational_policy"
)
_EXCEPTIONS = GovernedRecordStore(
    "ai_policy_exceptions", "APX", "ai_policy_exception"
)
_EVALUATIONS = GovernedRecordStore(
    "ai_policy_evaluations", "APE", "ai_policy_evaluation"
)

_MAX_POLICIES = 2_000
_MAX_EXCEPTIONS = 10_000
_MAX_EVALUATIONS = 25_000
_MAX_VERSIONS = 100
_MAX_STATEMENTS = 128
_MAX_LIST_ITEMS = 64
_MAX_JSON_BYTES = 256 * 1024
_MAX_EXCEPTION_SECONDS = 366 * 24 * 60 * 60

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_SECRET_RE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{16,}|"
    r"\bsk-[A-Za-z0-9_-]{16,}|"
    r"\bAKIA[0-9A-Z]{16}\b)",
    re.IGNORECASE,
)

_EFFECT_RANK = {"allow": 0, "review": 1, "restrict": 2, "prohibit": 3}
_RISK_TIERS = frozenset({"unclassified", "low", "medium", "high", "critical"})
_CONDITION_FIELDS = (
    "risk_tiers",
    "jurisdictions",
    "data_classes",
    "deployment_types",
    "asset_types",
    "tags",
    "use_case_tags",
)
_STATEMENT_FIELDS = frozenset({
    "statement_id",
    "text",
    "effect",
    "applicability",
    "required_control_ids",
})
_CONTEXT_FIELDS = frozenset({
    "asset_id",
    "risk_tier",
    "jurisdictions",
    "data_classes",
    "deployment_types",
    "asset_types",
    "tags",
    "use_case_tags",
})
_SCOPE_FIELDS = frozenset((*_CONDITION_FIELDS, "asset_ids", "statement_ids"))


class AIPolicyManagementError(RuntimeError):
    """Base error for operational AI policy management."""


class AIPolicyManagementConfigError(AIPolicyManagementError):
    """The default-off policy-management authority is unavailable."""


class AIPolicyManagementStateError(AIPolicyManagementError):
    """Persisted policy-management authority is malformed or inconsistent."""


def enabled() -> bool:
    """Return whether the explicit default-off feature gate is admitted."""

    try:
        from .config import config_source_errors, load_config

        config = load_config()
        if config_source_errors() or not isinstance(config, dict):
            return False
        section = config.get("ai_policy_management")
        return isinstance(section, dict) and section.get("enable") is True
    except Exception:
        return False


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("AI policy data must be finite, bounded JSON") from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise ValueError("AI policy data exceeds the 256 KiB limit")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _known_keys(value: Mapping[str, Any], allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {', '.join(unknown)}")


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{label} must be an object")
    return value


def _text(
    value: object,
    label: str,
    limit: int,
    *,
    required: bool = True,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    result = unicodedata.normalize("NFKC", value).strip()
    if required and not result:
        raise ValueError(f"{label} is required")
    if len(result) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(result):
        raise ValueError(f"{label} contains control characters")
    if _SECRET_RE.search(result):
        raise ValueError(f"{label} appears to contain secret material")
    return result


def _token(value: object, label: str) -> str:
    result = _text(value, label, 128)
    if not _TOKEN_RE.fullmatch(result):
        raise ValueError(f"{label} must be a bounded identifier")
    return result


def _actor(value: object, label: str = "actor") -> str:
    return _text(value, label, 256)


def _human_actor(value: object, label: str) -> str:
    actor = _actor(value, label)
    if not actor.startswith("user:") or len(actor) <= len("user:"):
        raise ValueError(f"{label} must be an authenticated user: principal")
    return actor


def _revision(value: object, label: str = "expected_revision") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a timestamp")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return result


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return value


def _record_times(row: Mapping[str, Any]) -> tuple[float, float]:
    created_at = _timestamp(row.get("created_at"), "created_at")
    updated_at = _timestamp(row.get("updated_at"), "updated_at")
    if updated_at < created_at:
        raise ValueError("updated_at precedes created_at")
    return created_at, updated_at


def _tokens(
    value: object,
    label: str,
    *,
    allow_empty: bool = True,
    maximum: int = _MAX_LIST_ITEMS,
) -> list[str]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError(f"{label} must be an array")
    if len(value) > maximum:
        raise ValueError(f"{label} exceeds {maximum} entries")
    result = sorted({_token(item, label).lower() for item in value})
    if not allow_empty and not result:
        raise ValueError(f"{label} must not be empty")
    return result


def _active_tenant() -> tuple[str, str]:
    from .paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIPolicyManagementStateError(
            "AI policy management requires an explicit tenant authority"
        )
    tenant_name = _text(tenant, "tenant", 256)
    return tenant_name, hashlib.sha256(tenant_name.encode("utf-8")).hexdigest()


def _stable_id(prefix: str, tenant_ref: str, *parts: str) -> str:
    binding = _sha256([tenant_ref, *parts])[:24]
    return f"{prefix}-{binding}"


def _policy_record_id(tenant_ref: str, policy_id: str) -> str:
    return _stable_id("AOP", tenant_ref, policy_id)


def _exception_record_id(tenant_ref: str, exception_key: str) -> str:
    return _stable_id("APX", tenant_ref, exception_key)


def _evaluation_record_id(tenant_ref: str, evaluation_key: str) -> str:
    return _stable_id("APE", tenant_ref, evaluation_key)


def _normalize_conditions(value: object) -> dict[str, list[str]]:
    raw = _mapping(value, "applicability")
    _known_keys(raw, frozenset(_CONDITION_FIELDS), "applicability")
    output = {
        field: _tokens(raw.get(field, []), f"applicability.{field}")
        for field in _CONDITION_FIELDS
    }
    if any(item not in _RISK_TIERS for item in output["risk_tiers"]):
        raise ValueError("applicability.risk_tiers contains an unsupported tier")
    return output


def _normalize_statement(value: object) -> dict[str, Any]:
    raw = _mapping(value, "policy statement")
    _known_keys(raw, _STATEMENT_FIELDS, "policy statement")
    effect = _text(raw.get("effect"), "statement effect", 32).lower()
    if effect not in _EFFECT_RANK:
        raise ValueError(
            "statement effect must be allow, review, restrict, or prohibit"
        )
    return {
        "statement_id": _token(raw.get("statement_id"), "statement_id"),
        "text": _text(raw.get("text"), "statement text", 4_000),
        "effect": effect,
        "applicability": _normalize_conditions(raw.get("applicability", {})),
        "required_control_ids": _tokens(
            raw.get("required_control_ids", []),
            "required_control_ids",
            maximum=128,
        ),
    }


def _normalize_statements(value: object) -> list[dict[str, Any]]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("statements must be an array")
    if not 1 <= len(value) <= _MAX_STATEMENTS:
        raise ValueError(f"statements must contain 1 to {_MAX_STATEMENTS} entries")
    result = sorted(
        (_normalize_statement(item) for item in value),
        key=lambda item: item["statement_id"],
    )
    identifiers = [item["statement_id"] for item in result]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("statement_id values must be unique within a policy version")
    return result


def _version_payload(
    *,
    policy_id: str,
    version: int,
    title: object,
    description: object,
    statements: object,
) -> dict[str, Any]:
    if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
        raise ValueError("policy version must be a positive integer")
    return {
        "policy_id": _token(policy_id, "policy_id"),
        "version": version,
        "title": _text(title, "policy title", 256),
        "description": _text(
            description,
            "policy description",
            4_000,
            required=False,
        ),
        "statements": _normalize_statements(statements),
    }


def _new_version(
    *,
    policy_id: str,
    version: int,
    title: object,
    description: object,
    statements: object,
    actor: str,
    now: float,
) -> dict[str, Any]:
    payload = _version_payload(
        policy_id=policy_id,
        version=version,
        title=title,
        description=description,
        statements=statements,
    )
    return {
        **{key: value for key, value in payload.items() if key != "policy_id"},
        "digest": _sha256(payload),
        "authored_by": _actor(actor),
        "authored_at": now,
    }


def _validate_version(value: object, policy_id: str, expected_version: int) -> dict[str, Any]:
    try:
        raw = _mapping(value, "persisted policy version")
        if set(raw) != {
            "version",
            "title",
            "description",
            "statements",
            "digest",
            "authored_by",
            "authored_at",
        }:
            raise ValueError("persisted policy version has an invalid shape")
        payload = _version_payload(
            policy_id=policy_id,
            version=raw.get("version"),
            title=raw.get("title"),
            description=raw.get("description"),
            statements=raw.get("statements"),
        )
        if payload["version"] != expected_version:
            raise ValueError("persisted policy versions are not contiguous")
        claimed = _digest(raw.get("digest"), "policy version digest")
        if claimed != _sha256(payload):
            raise ValueError("policy version digest does not match its authority")
        return {
            **{key: item for key, item in payload.items() if key != "policy_id"},
            "digest": claimed,
            "authored_by": _actor(raw.get("authored_by"), "authored_by"),
            "authored_at": _timestamp(raw.get("authored_at"), "authored_at"),
        }
    except (TypeError, ValueError) as exc:
        raise AIPolicyManagementStateError(
            "persisted AI policy version is malformed"
        ) from exc


def _validate_policy_record(
    value: Mapping[str, Any],
    tenant_ref: str,
) -> dict[str, Any]:
    try:
        row = dict(value)
        policy_id = _token(row.get("policy_id"), "policy_id")
        if (
            row.get("schema") != POLICY_SCHEMA
            or row.get("tenant_ref") != tenant_ref
            or row.get("id") != _policy_record_id(tenant_ref, policy_id)
        ):
            raise ValueError("policy identity binding is invalid")
        revision = _revision(row.get("revision"), "persisted revision")
        if revision <= 0:
            raise ValueError("persisted revision must be positive")
        _record_times(row)
        raw_versions = row.get("versions")
        if (
            not isinstance(raw_versions, list)
            or not 1 <= len(raw_versions) <= _MAX_VERSIONS
        ):
            raise ValueError("policy version history is invalid")
        versions = [
            _validate_version(item, policy_id, index)
            for index, item in enumerate(raw_versions, start=1)
        ]
        active_version = row.get("active_version")
        active_digest = row.get("active_digest")
        activation = row.get("activation")
        if active_version is None:
            if active_digest not in {None, ""} or activation is not None:
                raise ValueError("draft policy has active authority")
            status = "draft"
            active_digest = ""
        else:
            if (
                isinstance(active_version, bool)
                or not isinstance(active_version, int)
                or not 1 <= active_version <= len(versions)
            ):
                raise ValueError("active policy version is invalid")
            expected_digest = versions[active_version - 1]["digest"]
            if active_digest != expected_digest:
                raise ValueError("active policy digest is invalid")
            activation_map = _mapping(activation, "activation")
            if set(activation_map) != {"version", "digest", "activated_by", "activated_at"}:
                raise ValueError("activation has an invalid shape")
            if (
                activation_map.get("version") != active_version
                or activation_map.get("digest") != active_digest
            ):
                raise ValueError("activation authority is inconsistent")
            _human_actor(activation_map.get("activated_by"), "activated_by")
            _timestamp(activation_map.get("activated_at"), "activated_at")
            status = "active"
        if row.get("status") != status:
            raise ValueError("policy status is inconsistent")
        row.update({
            "policy_id": policy_id,
            "versions": versions,
            "active_version": active_version,
            "active_digest": active_digest,
            "revision": revision,
        })
        return row
    except AIPolicyManagementStateError:
        raise
    except (TypeError, ValueError) as exc:
        raise AIPolicyManagementStateError(
            "persisted AI policy authority is malformed"
        ) from exc


def _policy_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    versions = [
        {
            "version": version["version"],
            "digest": version["digest"],
            "title": version["title"],
            "description": version["description"],
            "statements": version["statements"],
            "authored_by": version["authored_by"],
            "authored_at": version["authored_at"],
        }
        for version in row["versions"]
    ]
    return {
        "schema": POLICY_SCHEMA,
        "policy_id": row["policy_id"],
        "status": row["status"],
        "versions": versions,
        "active_version": row["active_version"],
        "active_digest": row["active_digest"],
        "activation": row["activation"],
        "revision": row["revision"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "notice": NON_CERTIFICATION_NOTICE,
    }


def _normalize_scope(value: object) -> dict[str, list[str]]:
    raw = _mapping(value, "exception scope")
    _known_keys(raw, _SCOPE_FIELDS, "exception scope")
    output = {
        field: _tokens(raw.get(field, []), f"exception scope.{field}")
        for field in sorted(_SCOPE_FIELDS)
    }
    if any(item not in _RISK_TIERS for item in output["risk_tiers"]):
        raise ValueError("exception scope.risk_tiers contains an unsupported tier")
    if not any(output.values()):
        raise ValueError("exception scope must contain at least one selector")
    return output


def _effective_exception_status(row: Mapping[str, Any], now: float) -> str:
    status = str(row["status"])
    if status != "closed" and now >= float(row["expires_at"]):
        return "expired"
    return status


def _validate_exception_record(
    value: Mapping[str, Any],
    tenant_ref: str,
) -> dict[str, Any]:
    try:
        row = dict(value)
        exception_key = _token(row.get("exception_key"), "exception_key")
        if (
            row.get("schema") != EXCEPTION_SCHEMA
            or row.get("tenant_ref") != tenant_ref
            or row.get("id") != _exception_record_id(tenant_ref, exception_key)
        ):
            raise ValueError("exception identity binding is invalid")
        policy_id = _token(row.get("policy_id"), "policy_id")
        policy_version = row.get("policy_version")
        if (
            isinstance(policy_version, bool)
            or not isinstance(policy_version, int)
            or policy_version <= 0
        ):
            raise ValueError("exception policy version is invalid")
        policy_digest = _digest(row.get("policy_digest"), "policy_digest")
        scope = _normalize_scope(row.get("scope"))
        reason = _text(row.get("reason"), "exception reason", 2_000)
        controls = _tokens(
            row.get("compensating_control_ids"),
            "compensating_control_ids",
            allow_empty=False,
            maximum=128,
        )
        requester = _human_actor(row.get("requester"), "requester")
        status = row.get("status")
        if status not in {"pending", "approved", "closed"}:
            raise ValueError("exception status is invalid")
        requested_at = _timestamp(row.get("requested_at"), "requested_at")
        expires_at = _timestamp(row.get("expires_at"), "expires_at")
        if expires_at <= requested_at or expires_at - requested_at > _MAX_EXCEPTION_SECONDS:
            raise ValueError("exception expiry is outside the bounded window")
        approver = row.get("approver")
        approved_at = row.get("approved_at")
        closeout = row.get("closeout")
        if status == "pending":
            if approver is not None or approved_at is not None or closeout is not None:
                raise ValueError("pending exception has decision state")
        elif status == "approved":
            approved_by = _human_actor(approver, "approver")
            if approved_by == requester:
                raise ValueError("exception violates four-eyes approval")
            _timestamp(approved_at, "approved_at")
            if closeout is not None:
                raise ValueError("approved exception has closeout state")
        else:
            if approver is not None:
                approved_by = _human_actor(approver, "approver")
                if approved_by == requester:
                    raise ValueError("exception violates four-eyes approval")
                _timestamp(approved_at, "approved_at")
            elif approved_at is not None:
                raise ValueError("closed exception approval state is invalid")
            closeout_map = _mapping(closeout, "closeout")
            if set(closeout_map) != {"closed_by", "closed_at", "reason"}:
                raise ValueError("exception closeout has an invalid shape")
            _human_actor(closeout_map.get("closed_by"), "closed_by")
            _timestamp(closeout_map.get("closed_at"), "closed_at")
            _text(closeout_map.get("reason"), "closeout reason", 1_000)
        revision = _revision(row.get("revision"), "persisted revision")
        if revision <= 0:
            raise ValueError("persisted revision must be positive")
        _record_times(row)
        row.update({
            "exception_key": exception_key,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "policy_digest": policy_digest,
            "scope": scope,
            "reason": reason,
            "compensating_control_ids": controls,
            "requester": requester,
            "requested_at": requested_at,
            "expires_at": expires_at,
            "revision": revision,
        })
        return row
    except (TypeError, ValueError) as exc:
        raise AIPolicyManagementStateError(
            "persisted AI policy exception is malformed"
        ) from exc


def _exception_projection(row: Mapping[str, Any], *, now: float) -> dict[str, Any]:
    status = _effective_exception_status(row, now)
    return {
        "schema": EXCEPTION_SCHEMA,
        "exception_key": row["exception_key"],
        "policy_id": row["policy_id"],
        "policy_version": row["policy_version"],
        "policy_digest": row["policy_digest"],
        "scope": row["scope"],
        "reason": row["reason"],
        "compensating_control_ids": row["compensating_control_ids"],
        "requester": row["requester"],
        "approver": row["approver"],
        "requested_at": row["requested_at"],
        "approved_at": row["approved_at"],
        "expires_at": row["expires_at"],
        "closeout": row["closeout"],
        "status": status,
        "authorizes": status == "approved",
        "revision": row["revision"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "notice": NON_CERTIFICATION_NOTICE,
    }


def _normalize_context(value: object) -> dict[str, Any]:
    raw = _mapping(value, "evaluation context")
    _known_keys(raw, _CONTEXT_FIELDS, "evaluation context")
    risk_tier = _text(raw.get("risk_tier", "unclassified"), "risk_tier", 32).lower()
    if risk_tier not in _RISK_TIERS:
        raise ValueError("risk_tier is unsupported")
    return {
        "asset_id": _token(raw.get("asset_id"), "asset_id"),
        "risk_tier": risk_tier,
        **{
            field: _tokens(raw.get(field, []), field)
            for field in _CONDITION_FIELDS
            if field != "risk_tiers"
        },
    }


def _condition_matches(
    applicability: Mapping[str, list[str]],
    context: Mapping[str, Any],
) -> bool:
    for field in _CONDITION_FIELDS:
        required = set(applicability[field])
        if not required:
            continue
        actual = (
            {str(context["risk_tier"])}
            if field == "risk_tiers"
            else set(context[field])
        )
        if required.isdisjoint(actual):
            return False
    return True


def _scope_matches(
    scope: Mapping[str, list[str]],
    context: Mapping[str, Any],
    statement_id: str,
) -> bool:
    if scope["asset_ids"] and context["asset_id"].lower() not in scope["asset_ids"]:
        return False
    if scope["statement_ids"] and statement_id.lower() not in scope["statement_ids"]:
        return False
    applicability = {field: scope[field] for field in _CONDITION_FIELDS}
    return _condition_matches(applicability, context)


def _validate_policy_authority(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_POLICIES:
        raise ValueError("decision policy authority is invalid")
    normalized: list[dict[str, Any]] = []
    for item in value:
        current = _mapping(item, "policy authority")
        if set(current) != {"policy_id", "version", "digest"}:
            raise ValueError("policy authority has an invalid shape")
        version = current.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("policy authority version is invalid")
        normalized.append({
            "policy_id": _token(current.get("policy_id"), "policy_id"),
            "version": version,
            "digest": _digest(current.get("digest"), "policy digest"),
        })
    normalized.sort(key=lambda item: item["policy_id"])
    if value != normalized:
        raise ValueError("policy authority is not canonical")
    return normalized


def _validate_applied_exception(value: object, effective: str) -> dict[str, Any] | None:
    if value is None:
        return None
    exception = _mapping(value, "applied exception")
    if set(exception) != {"exception_key", "status", "expires_at"}:
        raise ValueError("applied exception has an invalid shape")
    if exception.get("status") != "approved" or effective != "allow":
        raise ValueError("applied exception is not authorizing")
    return {
        "exception_key": _token(exception.get("exception_key"), "exception_key"),
        "status": "approved",
        "expires_at": _timestamp(exception.get("expires_at"), "exception expires_at"),
    }


def _validate_matched_statements(
    value: object,
    authority: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], set[str], list[str]]:
    if (
        not isinstance(value, list)
        or len(value) > _MAX_POLICIES * _MAX_STATEMENTS
    ):
        raise ValueError("matched statements are invalid")
    authority_keys = {
        (item["policy_id"], item["version"], item["digest"])
        for item in authority
    }
    required_fields = {
        "policy_id",
        "policy_version",
        "policy_digest",
        "statement_id",
        "statement_text",
        "effect",
        "effective_effect",
        "required_control_ids",
        "exception",
    }
    normalized: list[dict[str, Any]] = []
    controls: set[str] = set()
    effects: list[str] = []
    for item in value:
        current = _mapping(item, "matched statement")
        if set(current) != required_fields:
            raise ValueError("matched statement has an invalid shape")
        policy_id = _token(current.get("policy_id"), "policy_id")
        version = current.get("policy_version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("matched policy version is invalid")
        digest = _digest(current.get("policy_digest"), "policy_digest")
        if (policy_id, version, digest) not in authority_keys:
            raise ValueError("matched statement is outside policy authority")
        effect = _text(current.get("effect"), "effect", 32).lower()
        effective = _text(
            current.get("effective_effect"), "effective_effect", 32
        ).lower()
        if effect not in _EFFECT_RANK or effective not in _EFFECT_RANK:
            raise ValueError("matched statement effect is invalid")
        exception = _validate_applied_exception(current.get("exception"), effective)
        if exception is None and effective != effect:
            raise ValueError("statement effect changed without an exception")
        required_controls = _tokens(
            current.get("required_control_ids"),
            "required_control_ids",
            maximum=256,
        )
        controls.update(required_controls)
        effects.append(effective)
        normalized.append({
            "policy_id": policy_id,
            "policy_version": version,
            "policy_digest": digest,
            "statement_id": _token(current.get("statement_id"), "statement_id"),
            "statement_text": _text(
                current.get("statement_text"), "statement_text", 4_000
            ),
            "effect": effect,
            "effective_effect": effective,
            "required_control_ids": required_controls,
            "exception": exception,
        })
    normalized.sort(
        key=lambda item: (
            item["policy_id"],
            item["policy_version"],
            item["statement_id"],
        )
    )
    if value != normalized:
        raise ValueError("matched statements are not canonical")
    return normalized, controls, effects


def _validate_decision(value: object) -> dict[str, Any]:
    try:
        row = dict(_mapping(value, "persisted policy decision"))
        if row.get("schema") != DECISION_SCHEMA:
            raise ValueError("decision schema is invalid")
        context = _normalize_context(row.get("context"))
        normalized_authority = _validate_policy_authority(
            row.get("policy_authority")
        )
        normalized_matches, controls, effects = _validate_matched_statements(
            row.get("matched_statements"), normalized_authority
        )
        expected_effect = (
            max(effects, key=_EFFECT_RANK.__getitem__) if effects else "review"
        )
        if row.get("final_effect") != expected_effect:
            raise ValueError("final effect is inconsistent")
        required = sorted(controls)
        if row.get("required_control_ids") != required:
            raise ValueError("required controls are inconsistent")
        expected_default = not normalized_matches
        if row.get("defaulted_to_review") is not expected_default:
            raise ValueError("default review state is inconsistent")
        if row.get("notice") != NON_CERTIFICATION_NOTICE:
            raise ValueError("decision notice is invalid")
        return {
            "schema": DECISION_SCHEMA,
            "context": context,
            "policy_authority": normalized_authority,
            "matched_statements": normalized_matches,
            "required_control_ids": required,
            "final_effect": expected_effect,
            "defaulted_to_review": expected_default,
            "notice": NON_CERTIFICATION_NOTICE,
        }
    except (TypeError, ValueError) as exc:
        raise AIPolicyManagementStateError(
            "persisted AI policy evaluation decision is malformed"
        ) from exc


def _validate_evaluation_record(
    value: Mapping[str, Any],
    tenant_ref: str,
) -> dict[str, Any]:
    try:
        row = dict(value)
        evaluation_key = _token(row.get("evaluation_key"), "evaluation_key")
        if (
            row.get("schema") != EVALUATION_SCHEMA
            or row.get("tenant_ref") != tenant_ref
            or row.get("id") != _evaluation_record_id(tenant_ref, evaluation_key)
        ):
            raise ValueError("evaluation identity binding is invalid")
        context = _normalize_context(row.get("context"))
        context_digest = _digest(row.get("context_digest"), "context_digest")
        if context_digest != _sha256(context):
            raise ValueError("evaluation context digest is invalid")
        decision = _validate_decision(row.get("decision"))
        if decision["context"] != context:
            raise ValueError("evaluation context and decision disagree")
        authority_digest = _digest(row.get("authority_digest"), "authority_digest")
        if authority_digest != _sha256(decision["policy_authority"]):
            raise ValueError("evaluation authority digest is invalid")
        decision_digest = _digest(row.get("decision_digest"), "decision_digest")
        if decision_digest != _sha256(decision):
            raise ValueError("evaluation decision digest is invalid")
        _actor(row.get("evaluated_by"), "evaluated_by")
        _timestamp(row.get("evaluated_at"), "evaluated_at")
        attestation = row.get("attestation")
        if attestation is not None:
            attestation_map = _mapping(attestation, "attestation")
            if set(attestation_map) != {
                "attested_by",
                "attested_at",
                "authority_digest",
                "decision_digest",
            }:
                raise ValueError("evaluation attestation has an invalid shape")
            _human_actor(attestation_map.get("attested_by"), "attested_by")
            _timestamp(attestation_map.get("attested_at"), "attested_at")
            if (
                attestation_map.get("authority_digest") != authority_digest
                or attestation_map.get("decision_digest") != decision_digest
            ):
                raise ValueError("evaluation attestation authority is invalid")
        revision = _revision(row.get("revision"), "persisted revision")
        if revision <= 0:
            raise ValueError("persisted revision must be positive")
        _record_times(row)
        row.update({
            "evaluation_key": evaluation_key,
            "context": context,
            "context_digest": context_digest,
            "decision": decision,
            "authority_digest": authority_digest,
            "decision_digest": decision_digest,
            "revision": revision,
        })
        return row
    except AIPolicyManagementStateError:
        raise
    except (TypeError, ValueError) as exc:
        raise AIPolicyManagementStateError(
            "persisted AI policy evaluation is malformed"
        ) from exc


def _bounded_rows(
    store: GovernedRecordStore,
    maximum: int,
    label: str,
) -> list[dict[str, Any]]:
    if maximum <= 10_000:
        rows = store.list(limit=maximum + 1)
    else:
        # The governed backend admits at most 10,001 rows per list read. The
        # evaluation domain supports 25,000: use its existing bounded identity
        # iterator and integrity-checked get rather than an invalid list limit.
        # Iterators rotate at their end; stop on a previously read identity.
        rows, seen, cursor = [], set(), ""
        while len(seen) <= maximum:
            budget = min(10_000, maximum + 1 - len(seen))
            window = list(store.iter_record_ids(start_after=cursor, limit=budget))
            if not window:
                break
            for next_cursor, identifier in window:
                cursor = next_cursor
                if identifier in seen:
                    if identifier != rows[0]["id"]:
                        raise AIPolicyManagementStateError(f"{label} changed during its bounded cursor scan")
                    return rows
                seen.add(identifier)
                row = store.get(identifier)
                if row is None:
                    raise AIPolicyManagementStateError(f"{label} changed during its bounded read")
                rows.append(row)
                if len(rows) > maximum:
                    raise AIPolicyManagementStateError(f"{label} exceeds its governed limit")
            if len(window) < budget:
                break
    if len(rows) > maximum:
        raise AIPolicyManagementStateError(f"{label} exceeds its governed limit")
    return rows


class AIPolicyManagement:
    """Governed operational-policy authority with injectable stores and clock."""

    def __init__(
        self,
        *,
        policies: GovernedRecordStore | None = None,
        exceptions: GovernedRecordStore | None = None,
        evaluations: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self._policies = policies or _POLICIES
        self._exceptions = exceptions or _EXCEPTIONS
        self._evaluations = evaluations or _EVALUATIONS
        self._clock = clock

    @property
    def backend_kind(self) -> str:
        kinds = {
            store.backend_kind
            for store in (self._policies, self._exceptions, self._evaluations)
        }
        if len(kinds) != 1:
            raise AIPolicyManagementStateError(
                "AI policy-management authorities use different backends"
            )
        return next(iter(kinds))

    def _now(self) -> float:
        source = self._clock or self._policies.authoritative_time
        try:
            return _timestamp(source(), "authority clock")
        except (TypeError, ValueError) as exc:
            raise AIPolicyManagementStateError(
                "AI policy-management authority clock is invalid"
            ) from exc

    def create_policy(
        self,
        policy_id: str,
        *,
        title: str,
        description: str = "",
        statements: Sequence[Mapping[str, Any]],
        actor: str,
    ) -> dict[str, Any]:
        """Create version 1 of an inactive operational policy."""

        _, tenant_ref = _active_tenant()
        identifier = _token(policy_id, "policy_id")
        operator = _actor(actor)
        now = self._now()
        version = _new_version(
            policy_id=identifier,
            version=1,
            title=title,
            description=description,
            statements=statements,
            actor=operator,
            now=now,
        )
        record = {
            "id": _policy_record_id(tenant_ref, identifier),
            "schema": POLICY_SCHEMA,
            "tenant_ref": tenant_ref,
            "policy_id": identifier,
            "status": "draft",
            "versions": [version],
            "active_version": None,
            "active_digest": "",
            "activation": None,
        }
        saved = self._policies.create(
            record,
            action="create_ai_policy",
            actor=operator,
            max_records=_MAX_POLICIES,
        )
        return _policy_projection(_validate_policy_record(saved, tenant_ref))

    def add_policy_version(
        self,
        policy_id: str,
        *,
        title: str,
        description: str = "",
        statements: Sequence[Mapping[str, Any]],
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        """Append, but never mutate, the next immutable policy version."""

        _, tenant_ref = _active_tenant()
        identifier = _token(policy_id, "policy_id")
        expected = _revision(expected_revision)
        operator = _actor(actor)
        record_id = _policy_record_id(tenant_ref, identifier)
        current_raw = self._policies.get(record_id)
        if current_raw is None:
            raise AIPolicyManagementStateError("AI policy does not exist")
        current = _validate_policy_record(current_raw, tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                "AI policy changed "
                f"(expected revision {expected}, found {current['revision']})"
            )
        if len(current["versions"]) >= _MAX_VERSIONS:
            raise AIPolicyManagementStateError("AI policy version limit reached")
        version = _new_version(
            policy_id=identifier,
            version=len(current["versions"]) + 1,
            title=title,
            description=description,
            statements=statements,
            actor=operator,
            now=self._now(),
        )

        def mutate(row: dict[str, Any]) -> None:
            validated = _validate_policy_record(row, tenant_ref)
            row["versions"] = [*validated["versions"], version]

        saved = self._policies.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="append_ai_policy_version",
            actor=operator,
        )
        if saved is None:
            raise AIPolicyManagementStateError("AI policy disappeared during update")
        return _policy_projection(_validate_policy_record(saved, tenant_ref))

    def activate_policy(
        self,
        policy_id: str,
        version: int,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        """Human-activate an exact immutable version under CAS."""

        _, tenant_ref = _active_tenant()
        identifier = _token(policy_id, "policy_id")
        expected = _revision(expected_revision)
        operator = _human_actor(actor, "actor")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise ValueError("version must be a positive integer")
        record_id = _policy_record_id(tenant_ref, identifier)
        raw = self._policies.get(record_id)
        if raw is None:
            raise AIPolicyManagementStateError("AI policy does not exist")
        current = _validate_policy_record(raw, tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                "AI policy activation changed "
                f"(expected revision {expected}, found {current['revision']})"
            )
        if version > len(current["versions"]):
            raise ValueError("policy version does not exist")
        chosen = current["versions"][version - 1]
        if current["active_version"] == version:
            return _policy_projection(current)
        activation = {
            "version": version,
            "digest": chosen["digest"],
            "activated_by": operator,
            "activated_at": self._now(),
        }

        def mutate(row: dict[str, Any]) -> None:
            validated = _validate_policy_record(row, tenant_ref)
            if version > len(validated["versions"]):
                raise AIPolicyManagementStateError(
                    "AI policy version disappeared during activation"
                )
            if validated["versions"][version - 1]["digest"] != chosen["digest"]:
                raise AIPolicyManagementStateError(
                    "AI policy version authority changed during activation"
                )
            row["status"] = "active"
            row["active_version"] = version
            row["active_digest"] = chosen["digest"]
            row["activation"] = activation

        saved = self._policies.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="activate_ai_policy_version",
            actor=operator,
        )
        if saved is None:
            raise AIPolicyManagementStateError("AI policy disappeared during activation")
        return _policy_projection(_validate_policy_record(saved, tenant_ref))

    def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        """Return one safe, integrity-checked policy projection."""

        _, tenant_ref = _active_tenant()
        identifier = _token(policy_id, "policy_id")
        raw = self._policies.get(_policy_record_id(tenant_ref, identifier))
        if raw is None:
            return None
        return _policy_projection(_validate_policy_record(raw, tenant_ref))

    def list_policies(self) -> list[dict[str, Any]]:
        """Return all active-tenant policies in deterministic semantic order."""

        _, tenant_ref = _active_tenant()
        rows = [
            _validate_policy_record(row, tenant_ref)
            for row in _bounded_rows(self._policies, _MAX_POLICIES, "AI policies")
        ]
        return [
            _policy_projection(row)
            for row in sorted(rows, key=lambda item: item["policy_id"])
        ]

    def request_exception(
        self,
        exception_key: str,
        *,
        policy_id: str,
        policy_version: int,
        scope: Mapping[str, Sequence[str]],
        reason: str,
        compensating_control_ids: Sequence[str],
        expires_at: float,
        requester: str,
    ) -> dict[str, Any]:
        """Request a bounded exception pinned to the current exact authority."""

        _, tenant_ref = _active_tenant()
        key = _token(exception_key, "exception_key")
        identifier = _token(policy_id, "policy_id")
        requestor = _human_actor(requester, "requester")
        normalized_scope = _normalize_scope(scope)
        bounded_reason = _text(reason, "exception reason", 2_000)
        controls = _tokens(
            compensating_control_ids,
            "compensating_control_ids",
            allow_empty=False,
            maximum=128,
        )
        now = self._now()
        expiry = _timestamp(expires_at, "expires_at")
        if expiry <= now or expiry - now > _MAX_EXCEPTION_SECONDS:
            raise ValueError("expires_at must be within the next 366 days")
        raw_policy = self._policies.get(_policy_record_id(tenant_ref, identifier))
        if raw_policy is None:
            raise AIPolicyManagementStateError("AI policy does not exist")
        policy = _validate_policy_record(raw_policy, tenant_ref)
        if policy["active_version"] != policy_version:
            raise ValueError("exception must target the active policy version")
        version = policy["versions"][policy_version - 1]
        statement_ids = {item["statement_id"].lower() for item in version["statements"]}
        if not set(normalized_scope["statement_ids"]).issubset(statement_ids):
            raise ValueError("exception scope contains an unknown statement_id")
        record = {
            "id": _exception_record_id(tenant_ref, key),
            "schema": EXCEPTION_SCHEMA,
            "tenant_ref": tenant_ref,
            "exception_key": key,
            "policy_id": identifier,
            "policy_version": policy_version,
            "policy_digest": version["digest"],
            "scope": normalized_scope,
            "reason": bounded_reason,
            "compensating_control_ids": controls,
            "requester": requestor,
            "approver": None,
            "requested_at": now,
            "approved_at": None,
            "expires_at": expiry,
            "status": "pending",
            "closeout": None,
        }
        saved = self._exceptions.create(
            record,
            action="request_ai_policy_exception",
            actor=requestor,
            max_records=_MAX_EXCEPTIONS,
        )
        return _exception_projection(
            _validate_exception_record(saved, tenant_ref), now=now
        )

    def approve_exception(
        self,
        exception_key: str,
        *,
        expected_revision: int,
        approver: str,
    ) -> dict[str, Any]:
        """Approve an unexpired exception with a separate human principal."""

        _, tenant_ref = _active_tenant()
        key = _token(exception_key, "exception_key")
        expected = _revision(expected_revision)
        reviewer = _human_actor(approver, "approver")
        record_id = _exception_record_id(tenant_ref, key)
        raw = self._exceptions.get(record_id)
        if raw is None:
            raise AIPolicyManagementStateError("AI policy exception does not exist")
        current = _validate_exception_record(raw, tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                "AI policy exception changed "
                f"(expected revision {expected}, found {current['revision']})"
            )
        if reviewer == current["requester"]:
            raise ValueError("exception requester cannot approve their own request")
        if current["status"] != "pending":
            raise ValueError("only a pending exception may be approved")
        now = self._now()
        if now >= current["expires_at"]:
            raise ValueError("expired exception cannot be approved")
        raw_policy = self._policies.get(
            _policy_record_id(tenant_ref, current["policy_id"])
        )
        if raw_policy is None:
            raise AIPolicyManagementStateError("exception policy authority is missing")
        policy = _validate_policy_record(raw_policy, tenant_ref)
        if (
            policy["active_version"] != current["policy_version"]
            or policy["active_digest"] != current["policy_digest"]
        ):
            raise ValueError("exception policy authority requires revalidation")

        def mutate(row: dict[str, Any]) -> None:
            validated = _validate_exception_record(row, tenant_ref)
            if validated["status"] != "pending":
                raise AIPolicyManagementStateError(
                    "exception state changed during approval"
                )
            row["status"] = "approved"
            row["approver"] = reviewer
            row["approved_at"] = now

        saved = self._exceptions.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="approve_ai_policy_exception",
            actor=reviewer,
        )
        if saved is None:
            raise AIPolicyManagementStateError(
                "AI policy exception disappeared during approval"
            )
        return _exception_projection(
            _validate_exception_record(saved, tenant_ref), now=now
        )

    def close_exception(
        self,
        exception_key: str,
        *,
        expected_revision: int,
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        """Explicitly close a pending, approved, or expired exception."""

        _, tenant_ref = _active_tenant()
        key = _token(exception_key, "exception_key")
        expected = _revision(expected_revision)
        operator = _human_actor(actor, "actor")
        rationale = _text(reason, "closeout reason", 1_000)
        record_id = _exception_record_id(tenant_ref, key)
        raw = self._exceptions.get(record_id)
        if raw is None:
            raise AIPolicyManagementStateError("AI policy exception does not exist")
        current = _validate_exception_record(raw, tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                "AI policy exception changed "
                f"(expected revision {expected}, found {current['revision']})"
            )
        if current["status"] == "closed":
            raise ValueError("AI policy exception is already closed")
        now = self._now()

        def mutate(row: dict[str, Any]) -> None:
            validated = _validate_exception_record(row, tenant_ref)
            if validated["status"] == "closed":
                raise AIPolicyManagementStateError(
                    "exception state changed during closeout"
                )
            row["status"] = "closed"
            row["closeout"] = {
                "closed_by": operator,
                "closed_at": now,
                "reason": rationale,
            }

        saved = self._exceptions.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="close_ai_policy_exception",
            actor=operator,
        )
        if saved is None:
            raise AIPolicyManagementStateError(
                "AI policy exception disappeared during closeout"
            )
        return _exception_projection(
            _validate_exception_record(saved, tenant_ref), now=now
        )

    def get_exception(self, exception_key: str) -> dict[str, Any] | None:
        """Return one safe exception projection with dynamic expiry."""

        _, tenant_ref = _active_tenant()
        key = _token(exception_key, "exception_key")
        raw = self._exceptions.get(_exception_record_id(tenant_ref, key))
        if raw is None:
            return None
        return _exception_projection(
            _validate_exception_record(raw, tenant_ref), now=self._now()
        )

    def list_exceptions(self) -> list[dict[str, Any]]:
        """Return all active-tenant exception records in semantic order."""

        _, tenant_ref = _active_tenant()
        now = self._now()
        rows = [
            _validate_exception_record(row, tenant_ref)
            for row in _bounded_rows(
                self._exceptions, _MAX_EXCEPTIONS, "AI policy exceptions"
            )
        ]
        return [
            _exception_projection(row, now=now)
            for row in sorted(rows, key=lambda item: item["exception_key"])
        ]

    def _authorities(
        self,
        tenant_ref: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        policies = [
            _validate_policy_record(row, tenant_ref)
            for row in _bounded_rows(self._policies, _MAX_POLICIES, "AI policies")
        ]
        active = sorted(
            (row for row in policies if row["active_version"] is not None),
            key=lambda row: row["policy_id"],
        )
        authority = [
            {
                "policy_id": row["policy_id"],
                "version": row["active_version"],
                "digest": row["active_digest"],
            }
            for row in active
        ]
        return active, authority

    def _exception_authorities(
        self,
        tenant_ref: str,
    ) -> list[dict[str, Any]]:
        return sorted(
            (
                _validate_exception_record(row, tenant_ref)
                for row in _bounded_rows(
                    self._exceptions, _MAX_EXCEPTIONS, "AI policy exceptions"
                )
            ),
            key=lambda row: row["exception_key"],
        )

    def _decision(
        self,
        context: Mapping[str, Any],
        *,
        tenant_ref: str,
        now: float,
    ) -> dict[str, Any]:
        policies, authority = self._authorities(tenant_ref)
        exceptions = self._exception_authorities(tenant_ref)
        matches: list[dict[str, Any]] = []
        required_controls: set[str] = set()
        for policy in policies:
            version = policy["versions"][policy["active_version"] - 1]
            for statement in version["statements"]:
                if not _condition_matches(statement["applicability"], context):
                    continue
                candidates = [
                    exception
                    for exception in exceptions
                    if (
                        exception["policy_id"] == policy["policy_id"]
                        and exception["policy_version"] == version["version"]
                        and exception["policy_digest"] == version["digest"]
                        and _effective_exception_status(exception, now) == "approved"
                        and _scope_matches(
                            exception["scope"], context, statement["statement_id"]
                        )
                    )
                ]
                selected = candidates[0] if candidates else None
                controls = set(statement["required_control_ids"])
                if selected is not None:
                    controls.update(selected["compensating_control_ids"])
                required_controls.update(controls)
                matches.append({
                    "policy_id": policy["policy_id"],
                    "policy_version": version["version"],
                    "policy_digest": version["digest"],
                    "statement_id": statement["statement_id"],
                    "statement_text": statement["text"],
                    "effect": statement["effect"],
                    "effective_effect": (
                        "allow" if selected is not None else statement["effect"]
                    ),
                    "required_control_ids": sorted(controls),
                    "exception": (
                        None
                        if selected is None
                        else {
                            "exception_key": selected["exception_key"],
                            "status": "approved",
                            "expires_at": selected["expires_at"],
                        }
                    ),
                })
        matches.sort(
            key=lambda item: (
                item["policy_id"],
                item["policy_version"],
                item["statement_id"],
            )
        )
        final_effect = (
            max(
                (item["effective_effect"] for item in matches),
                key=_EFFECT_RANK.__getitem__,
            )
            if matches
            else "review"
        )
        return {
            "schema": DECISION_SCHEMA,
            "context": dict(context),
            "policy_authority": authority,
            "matched_statements": matches,
            "required_control_ids": sorted(required_controls),
            "final_effect": final_effect,
            "defaulted_to_review": not matches,
            "notice": NON_CERTIFICATION_NOTICE,
        }

    def preview(self, context: Mapping[str, Any]) -> dict[str, Any]:
        """Return a deterministic, non-persisted decision for current authority."""

        _, tenant_ref = _active_tenant()
        normalized = _normalize_context(context)
        decision = self._decision(normalized, tenant_ref=tenant_ref, now=self._now())
        # Structural validation is part of the fail-closed evaluation boundary.
        return _validate_decision(decision)

    def _evaluation_projection(
        self,
        row: Mapping[str, Any],
        *,
        tenant_ref: str,
        now: float,
    ) -> dict[str, Any]:
        current_decision = self._decision(row["context"], tenant_ref=tenant_ref, now=now)
        current_authority_digest = _sha256(current_decision["policy_authority"])
        current_decision_digest = _sha256(current_decision)
        is_current = (
            row["authority_digest"] == current_authority_digest
            and row["decision_digest"] == current_decision_digest
        )
        attestation = row.get("attestation")
        if attestation is None:
            attestation_projection: dict[str, Any] = {"status": "missing"}
        else:
            attestation_projection = {
                "status": "current" if is_current else "stale",
                "attested_by": attestation["attested_by"],
                "attested_at": attestation["attested_at"],
                "authority_digest": attestation["authority_digest"],
                "decision_digest": attestation["decision_digest"],
            }
        return {
            "schema": EVALUATION_SCHEMA,
            "evaluation_key": row["evaluation_key"],
            "context": row["context"],
            "context_digest": row["context_digest"],
            "decision": row["decision"],
            "authority_digest": row["authority_digest"],
            "decision_digest": row["decision_digest"],
            "evaluated_by": row["evaluated_by"],
            "evaluated_at": row["evaluated_at"],
            "attestation": attestation_projection,
            "current_authority_digest": current_authority_digest,
            "current_decision_digest": current_decision_digest,
            "revalidation_required": not is_current,
            "revision": row["revision"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "notice": NON_CERTIFICATION_NOTICE,
        }

    def evaluate(
        self,
        evaluation_key: str,
        context: Mapping[str, Any],
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        """CAS-record the exact current policy decision and authority digests."""

        _, tenant_ref = _active_tenant()
        key = _token(evaluation_key, "evaluation_key")
        expected = _revision(expected_revision)
        operator = _actor(actor)
        normalized = _normalize_context(context)
        now = self._now()
        decision = _validate_decision(
            self._decision(normalized, tenant_ref=tenant_ref, now=now)
        )
        authority_digest = _sha256(decision["policy_authority"])
        decision_digest = _sha256(decision)
        context_digest = _sha256(normalized)
        record_id = _evaluation_record_id(tenant_ref, key)
        raw = self._evaluations.get(record_id)
        current = (
            None if raw is None else _validate_evaluation_record(raw, tenant_ref)
        )
        found_revision = int((current or {}).get("revision") or 0)
        if found_revision != expected:
            raise RecordConflict(
                "AI policy evaluation changed "
                f"(expected revision {expected}, found {found_revision})"
            )
        if (
            current is not None
            and current["context_digest"] == context_digest
            and current["authority_digest"] == authority_digest
            and current["decision_digest"] == decision_digest
        ):
            return self._evaluation_projection(
                current, tenant_ref=tenant_ref, now=now
            )
        if current is None:
            record = {
                "id": record_id,
                "schema": EVALUATION_SCHEMA,
                "tenant_ref": tenant_ref,
                "evaluation_key": key,
                "context": normalized,
                "context_digest": context_digest,
                "decision": decision,
                "authority_digest": authority_digest,
                "decision_digest": decision_digest,
                "evaluated_by": operator,
                "evaluated_at": now,
                "attestation": None,
            }
            saved = self._evaluations.create(
                record,
                action="record_ai_policy_evaluation",
                actor=operator,
                max_records=_MAX_EVALUATIONS,
            )
        else:
            def mutate(row: dict[str, Any]) -> None:
                _validate_evaluation_record(row, tenant_ref)
                row["context"] = normalized
                row["context_digest"] = context_digest
                row["decision"] = decision
                row["authority_digest"] = authority_digest
                row["decision_digest"] = decision_digest
                row["evaluated_by"] = operator
                row["evaluated_at"] = now
                row["attestation"] = None

            saved = self._evaluations.update(
                record_id,
                mutate,
                expected_revision=expected,
                action="revalidate_ai_policy_evaluation",
                actor=operator,
            )
            if saved is None:
                raise AIPolicyManagementStateError(
                    "AI policy evaluation disappeared during revalidation"
                )
        validated = _validate_evaluation_record(saved, tenant_ref)
        return self._evaluation_projection(validated, tenant_ref=tenant_ref, now=now)

    def attest_evaluation(
        self,
        evaluation_key: str,
        *,
        expected_revision: int,
        actor: str,
    ) -> dict[str, Any]:
        """Human-attest a current evaluation; stale decisions fail closed."""

        _, tenant_ref = _active_tenant()
        key = _token(evaluation_key, "evaluation_key")
        expected = _revision(expected_revision)
        operator = _human_actor(actor, "actor")
        record_id = _evaluation_record_id(tenant_ref, key)
        raw = self._evaluations.get(record_id)
        if raw is None:
            raise AIPolicyManagementStateError("AI policy evaluation does not exist")
        current = _validate_evaluation_record(raw, tenant_ref)
        if current["revision"] != expected:
            raise RecordConflict(
                "AI policy evaluation changed "
                f"(expected revision {expected}, found {current['revision']})"
            )
        now = self._now()
        projection = self._evaluation_projection(
            current, tenant_ref=tenant_ref, now=now
        )
        if projection["revalidation_required"]:
            raise AIPolicyManagementStateError(
                "AI policy evaluation requires revalidation before attestation"
            )
        attestation = {
            "attested_by": operator,
            "attested_at": now,
            "authority_digest": current["authority_digest"],
            "decision_digest": current["decision_digest"],
        }

        def mutate(row: dict[str, Any]) -> None:
            validated = _validate_evaluation_record(row, tenant_ref)
            if (
                validated["authority_digest"] != current["authority_digest"]
                or validated["decision_digest"] != current["decision_digest"]
            ):
                raise AIPolicyManagementStateError(
                    "evaluation authority changed during attestation"
                )
            row["attestation"] = attestation

        saved = self._evaluations.update(
            record_id,
            mutate,
            expected_revision=expected,
            action="attest_ai_policy_evaluation",
            actor=operator,
        )
        if saved is None:
            raise AIPolicyManagementStateError(
                "AI policy evaluation disappeared during attestation"
            )
        validated = _validate_evaluation_record(saved, tenant_ref)
        return self._evaluation_projection(validated, tenant_ref=tenant_ref, now=now)

    def get_evaluation(self, evaluation_key: str) -> dict[str, Any] | None:
        """Return an integrity-checked evaluation with current/stale state."""

        _, tenant_ref = _active_tenant()
        key = _token(evaluation_key, "evaluation_key")
        raw = self._evaluations.get(_evaluation_record_id(tenant_ref, key))
        if raw is None:
            return None
        row = _validate_evaluation_record(raw, tenant_ref)
        return self._evaluation_projection(row, tenant_ref=tenant_ref, now=self._now())

    def list_evaluations(self) -> list[dict[str, Any]]:
        """Return all evaluations with dynamic revalidation status."""

        _, tenant_ref = _active_tenant()
        now = self._now()
        rows = [
            _validate_evaluation_record(row, tenant_ref)
            for row in _bounded_rows(
                self._evaluations, _MAX_EVALUATIONS, "AI policy evaluations"
            )
        ]
        return [
            self._evaluation_projection(row, tenant_ref=tenant_ref, now=now)
            for row in sorted(rows, key=lambda item: item["evaluation_key"])
        ]


def configured_policy_management() -> AIPolicyManagement:
    """Return the default authority only when explicitly enabled."""

    if not enabled():
        raise AIPolicyManagementConfigError(
            "AI policy management is disabled; set "
            "[ai_policy_management].enable = true"
        )
    return AIPolicyManagement()


__all__ = [
    "AIPolicyManagement",
    "AIPolicyManagementConfigError",
    "AIPolicyManagementError",
    "AIPolicyManagementStateError",
    "DECISION_SCHEMA",
    "EVALUATION_SCHEMA",
    "EXCEPTION_SCHEMA",
    "NON_CERTIFICATION_NOTICE",
    "POLICY_SCHEMA",
    "configured_policy_management",
    "enabled",
]
