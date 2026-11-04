"""Tenant-scoped, privacy-minimising AI literacy evidence register.

The register keeps four authorities separate:

* role/system requirements define the training content that is required;
* pseudonymous assignments say which roles and AI systems apply to a person;
* immutable completion receipts bind provider, content version, and validity;
* independently reviewed exemptions or waivers temporarily satisfy a gap.

Callers provide their own opaque person and reviewer identifiers.  Those values
are tenant-separated and hashed before persistence; names, email addresses,
training transcripts, test answers, and scores are never accepted or stored.
The returned projections and evidence exports contain only those pseudonymous
references and bounded governance metadata.

This is a technical evidence register, not a legal determination that a person
or organisation has met any particular regulatory obligation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from itertools import islice
from typing import Any

from .governed_records import GovernedRecordStore
from .privacy_ops import RecordConflict

REQUIREMENT_SCHEMA = "lightwork.ai-literacy-requirement.v1"
ASSIGNMENT_SCHEMA = "lightwork.ai-literacy-assignment.v1"
COMPLETION_SCHEMA = "lightwork.ai-literacy-completion.v1"
WAIVER_SCHEMA = "lightwork.ai-literacy-waiver.v1"
STATUS_SCHEMA = "lightwork.ai-literacy-status.v1"
EVIDENCE_EXPORT_SCHEMA = "lightwork.ai-literacy-evidence-export.v1"

NON_DETERMINATION_NOTICE = (
    "Technical literacy evidence only; not legal advice, a certification, or a "
    "regulatory compliance determination."
)

_REQUIREMENTS = GovernedRecordStore(
    "ai_literacy_requirements",
    "ALR",
    "ai_literacy_requirement",
)
_ASSIGNMENTS = GovernedRecordStore(
    "ai_literacy_assignments",
    "ALA",
    "ai_literacy_assignment",
)
_COMPLETIONS = GovernedRecordStore(
    "ai_literacy_completions",
    "ALC",
    "ai_literacy_completion",
)
_WAIVERS = GovernedRecordStore(
    "ai_literacy_waivers",
    "ALW",
    "ai_literacy_waiver",
)

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z")
_RECORD_RE = re.compile(r"AL[ARCW]-[0-9a-f]{32}\Z")
_PRINCIPAL_RE = re.compile(r"PRN-[0-9a-f]{32}\Z")
_TENANT_RE = re.compile(r"TEN-[0-9a-f]{32}\Z")
_DIGEST_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

_REQUIREMENT_STATUSES = frozenset({"active", "retired"})
_WAIVER_KINDS = frozenset({"exemption", "waiver"})
_WAIVER_REASONS = frozenset({
    "accessibility_accommodation",
    "equivalent_training",
    "leave_or_absence",
    "contractual_exception",
    "role_transition",
    "other_reviewed_basis",
})
_WAIVER_STATUSES = frozenset({"active", "revoked"})

_SECONDS_PER_DAY = 24 * 60 * 60
_MAX_VALIDITY_DAYS = 5 * 366
_MAX_DUE_DAYS = 366
_MAX_FUTURE_SKEW = 300.0
_MAX_FUTURE_WAIVER_DAYS = 366
_MAX_REQUIREMENTS = 5_000
_MAX_ASSIGNMENTS = 5_000
_MAX_COMPLETIONS = 10_000
_MAX_WAIVERS = 5_000
_MAX_EXPORT_SUBJECTS = 1_000
_MAX_SCOPES = 256
_MAX_IDEMPOTENCY_RECEIPTS = 256


class AILiteracyError(RuntimeError):
    """Base failure for the governed AI literacy register."""


class AILiteracyStateError(AILiteracyError):
    """Persisted or deployment state cannot satisfy the register contract."""


class AILiteracyIdempotencyConflict(AILiteracyError):
    """An idempotency key is already bound to different mutation input."""


def enabled() -> bool:
    """Return whether the tenant's explicit AI-literacy gate is enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_literacy")
    return isinstance(section, Mapping) and section.get("enable") is True


def _canonical(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value must be bounded canonical JSON") from exc
    raw = rendered.encode("utf-8")
    if len(raw) > 256 * 1024:
        raise ValueError("value exceeds the AI literacy JSON limit")
    return raw


def _sha256(value: object) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _required_text(value: object, label: str, limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if _CONTROL_RE.search(text):
        raise ValueError(f"{label} contains control characters")
    return text


def _token(value: object, label: str) -> str:
    text = _required_text(value, label, 128)
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} must be a stable opaque token")
    return text


def _safe_title(value: object) -> str:
    title = _required_text(value, "title", 256)
    try:
        from .safety.secret_detector import scan

        matches = scan(title)
    except Exception as exc:
        raise ValueError("secret detection is unavailable") from exc
    if matches:
        raise ValueError("title contains secret material")
    return title


def _tokens(values: object, label: str) -> list[str]:
    if isinstance(values, (str, bytes, Mapping)) or not isinstance(values, Iterable):
        raise ValueError(f"{label} must be a list")
    raw = list(islice(iter(values), _MAX_SCOPES + 1))
    if len(raw) > _MAX_SCOPES:
        raise ValueError(f"{label} exceeds {_MAX_SCOPES} items")
    return sorted({_token(item, label) for item in raw})


def _digest(value: object, label: str) -> str:
    text = _required_text(value, label, 71).lower()
    match = _DIGEST_RE.fullmatch(text)
    if match is None:
        raise ValueError(f"{label} must be a SHA-256 digest")
    return match.group(1)


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _revision(value: object) -> int:
    return _integer(value, "expected_revision", 0, 1_000_000_000)


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a positive finite timestamp")
    try:
        stamp = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a positive finite timestamp") from exc
    if not math.isfinite(stamp) or stamp <= 0:
        raise ValueError(f"{label} must be a positive finite timestamp")
    return stamp


def _record_id(value: object, prefix: str) -> str:
    text = _required_text(value, "record id", 36)
    if not _RECORD_RE.fullmatch(text) or not text.startswith(f"{prefix}-"):
        raise ValueError("record id is invalid")
    return text


def _principal(value: object) -> str:
    text = _required_text(value, "principal reference", 36)
    if not _PRINCIPAL_RE.fullmatch(text):
        raise ValueError("principal reference is invalid")
    return text


def _tenant_reference(value: object) -> str:
    text = _required_text(value, "tenant reference", 36)
    if not _TENANT_RE.fullmatch(text):
        raise ValueError("tenant reference is invalid")
    return text


def _active_tenant() -> tuple[str, str]:
    from .paths import current_tenant_id_strict, data_dir

    tenant_id = current_tenant_id_strict()
    if not tenant_id:
        raise AILiteracyStateError(
            "AI literacy records require an explicit tenant scope"
        )
    # Resolve the tenant namespace before hashing or touching a record store.
    data_dir(tenant=tenant_id)
    return tenant_id, f"TEN-{_sha256({'tenant_id': tenant_id})[:32]}"


def _principal_ref(tenant_id: str, principal_id: object) -> str:
    opaque = _required_text(principal_id, "principal_id", 512)
    return f"PRN-{_sha256({'tenant_id': tenant_id, 'principal_id': opaque})[:32]}"


def _stable_id(prefix: str, tenant_ref: str, *parts: object) -> str:
    return f"{prefix}-{_sha256([tenant_ref, *[str(part) for part in parts]])[:32]}"


def _idempotency_digest(value: object) -> str:
    key = _required_text(value, "idempotency_key", 512)
    return _sha256({"idempotency_key": key})


def _content(provider_id: object, content_id: object, content_version: object) -> dict[str, str]:
    content = {
        "provider_id": _token(provider_id, "provider_id"),
        "content_id": _token(content_id, "content_id"),
        "content_version": _token(content_version, "content_version"),
    }
    return {**content, "content_sha256": _sha256(content)}


def _receipt_list(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_IDEMPOTENCY_RECEIPTS:
        raise AILiteracyStateError("idempotency receipts are invalid")
    receipts: list[dict[str, Any]] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            raise AILiteracyStateError("idempotency receipt is invalid")
        try:
            receipt = {
                "operation": _token(raw.get("operation"), "idempotency operation"),
                "key_sha256": _digest(raw.get("key_sha256"), "idempotency key digest"),
                "payload_sha256": _digest(
                    raw.get("payload_sha256"),
                    "idempotency payload digest",
                ),
                "result_revision": _integer(
                    raw.get("result_revision"),
                    "idempotency result revision",
                    1,
                    1_000_000_000,
                ),
            }
        except ValueError as exc:
            raise AILiteracyStateError("idempotency receipt is invalid") from exc
        if set(raw) != set(receipt):
            raise AILiteracyStateError("idempotency receipt has unexpected fields")
        receipts.append(receipt)
    return receipts


def _replayed(
    record: Mapping[str, Any],
    *,
    operation: str,
    key_sha256: str,
    payload_sha256: str,
) -> bool:
    for receipt in _receipt_list(record.get("idempotency_receipts")):
        if not hmac.compare_digest(receipt["key_sha256"], key_sha256):
            continue
        if (
            receipt["operation"] != operation
            or not hmac.compare_digest(receipt["payload_sha256"], payload_sha256)
        ):
            raise AILiteracyIdempotencyConflict(
                "idempotency key is already bound to different literacy input"
            )
        return True
    return False


def _append_receipt(
    record: dict[str, Any],
    *,
    operation: str,
    key_sha256: str,
    payload_sha256: str,
    result_revision: int,
) -> None:
    receipts = _receipt_list(record.get("idempotency_receipts", []))
    receipts.append({
        "operation": operation,
        "key_sha256": key_sha256,
        "payload_sha256": payload_sha256,
        "result_revision": result_revision,
    })
    record["idempotency_receipts"] = receipts[-_MAX_IDEMPOTENCY_RECEIPTS:]


def _logical_record(record: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in record.items() if key != "_audit_pending"}


def _citation(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "record_id": _required_text(record.get("id"), "record id", 64),
        "revision": _integer(record.get("revision"), "record revision", 1, 1_000_000_000),
        "record_sha256": _sha256(_logical_record(record)),
    }


def _base_record(
    record: Mapping[str, Any],
    *,
    schema: str,
    prefix: str,
    tenant_ref: str,
) -> dict[str, Any]:
    try:
        if record.get("schema") != schema:
            raise ValueError("schema")
        normal = {
            "id": _record_id(record.get("id"), prefix),
            "schema": schema,
            "tenant_ref": _tenant_reference(record.get("tenant_ref")),
            "revision": _integer(
                record.get("revision"),
                "record revision",
                1,
                1_000_000_000,
            ),
            "created_at": _timestamp(record.get("created_at"), "created_at"),
            "updated_at": _timestamp(record.get("updated_at"), "updated_at"),
        }
    except ValueError as exc:
        raise AILiteracyStateError(f"{schema} record failed validation") from exc
    if normal["tenant_ref"] != tenant_ref:
        raise AILiteracyStateError("AI literacy record belongs to another tenant")
    return normal


def _requirement_payload(
    *,
    requirement_key: str,
    title: str,
    role_ids: Sequence[str],
    system_ids: Sequence[str],
    content: Mapping[str, str],
    validity_days: int,
    due_within_days: int,
    status: str,
) -> dict[str, Any]:
    return {
        "requirement_key": requirement_key,
        "title": title,
        "scope": {"role_ids": list(role_ids), "system_ids": list(system_ids)},
        "content": dict(content),
        "validity_days": validity_days,
        "due_within_days": due_within_days,
        "status": status,
    }


def _validate_requirement(record: Mapping[str, Any], tenant_ref: str) -> dict[str, Any]:
    base = _base_record(
        record,
        schema=REQUIREMENT_SCHEMA,
        prefix="ALR",
        tenant_ref=tenant_ref,
    )
    try:
        scope = record.get("scope")
        content = record.get("content")
        if not isinstance(scope, Mapping) or set(scope) != {"role_ids", "system_ids"}:
            raise ValueError("scope")
        if not isinstance(content, Mapping):
            raise ValueError("content")
        role_ids = _tokens(scope.get("role_ids"), "role_id")
        system_ids = _tokens(scope.get("system_ids"), "system_id")
        if scope.get("role_ids") != role_ids or scope.get("system_ids") != system_ids:
            raise ValueError("scope ordering")
        normalized_content = _content(
            content.get("provider_id"),
            content.get("content_id"),
            content.get("content_version"),
        )
        if dict(content) != normalized_content:
            raise ValueError("content")
        status = _token(record.get("status"), "status")
        if status not in _REQUIREMENT_STATUSES:
            raise ValueError("status")
        payload = _requirement_payload(
            requirement_key=_token(record.get("requirement_key"), "requirement_key"),
            title=_safe_title(record.get("title")),
            role_ids=role_ids,
            system_ids=system_ids,
            content=normalized_content,
            validity_days=_integer(
                record.get("validity_days"),
                "validity_days",
                1,
                _MAX_VALIDITY_DAYS,
            ),
            due_within_days=_integer(
                record.get("due_within_days"),
                "due_within_days",
                0,
                _MAX_DUE_DAYS,
            ),
            status=status,
        )
        if not role_ids and not system_ids:
            raise ValueError("empty scope")
        effective_at = _timestamp(record.get("effective_at"), "effective_at")
        payload_sha = _digest(record.get("payload_sha256"), "payload_sha256")
        control_sha = _digest(record.get("control_sha256"), "control_sha256")
        expected_control = _sha256({key: payload[key] for key in payload if key != "title"})
        if payload_sha != _sha256(payload) or control_sha != expected_control:
            raise ValueError("record digest")
        _receipt_list(record.get("idempotency_receipts"))
    except (TypeError, ValueError) as exc:
        raise AILiteracyStateError("AI literacy requirement failed validation") from exc
    expected_id = _stable_id("ALR", tenant_ref, payload["requirement_key"])
    if base["id"] != expected_id:
        raise AILiteracyStateError("AI literacy requirement identity changed")
    return {
        **base,
        **payload,
        "effective_at": effective_at,
        "payload_sha256": payload_sha,
        "control_sha256": control_sha,
        "idempotency_receipts": _receipt_list(record.get("idempotency_receipts")),
        "_source": record,
    }


def _scope_entries(value: object, *, kind: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) > _MAX_SCOPES:
        raise ValueError(f"{kind} assignments are invalid")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    id_key = f"{kind}_id"
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != {id_key, "assigned_at"}:
            raise ValueError(f"{kind} assignment is invalid")
        token = _token(raw.get(id_key), id_key)
        if token in seen:
            raise ValueError(f"duplicate {id_key}")
        seen.add(token)
        entries.append({id_key: token, "assigned_at": _timestamp(raw.get("assigned_at"), "assigned_at")})
    ordered = sorted(entries, key=lambda item: item[id_key])
    if entries != ordered:
        raise ValueError(f"{kind} assignments are not ordered")
    return entries


def _assignment_payload(role_ids: Sequence[str], system_ids: Sequence[str]) -> dict[str, Any]:
    return {"role_ids": list(role_ids), "system_ids": list(system_ids)}


def _validate_assignment(record: Mapping[str, Any], tenant_ref: str) -> dict[str, Any]:
    base = _base_record(
        record,
        schema=ASSIGNMENT_SCHEMA,
        prefix="ALA",
        tenant_ref=tenant_ref,
    )
    try:
        subject_ref = _principal(record.get("subject_ref"))
        roles = _scope_entries(record.get("role_assignments"), kind="role")
        systems = _scope_entries(record.get("system_assignments"), kind="system")
        status = _token(record.get("status"), "status")
        expected_status = "active" if roles or systems else "inactive"
        if status != expected_status:
            raise ValueError("status")
        payload = _assignment_payload(
            [item["role_id"] for item in roles],
            [item["system_id"] for item in systems],
        )
        payload_sha = _digest(record.get("payload_sha256"), "payload_sha256")
        if payload_sha != _sha256(payload):
            raise ValueError("payload digest")
        receipts = _receipt_list(record.get("idempotency_receipts"))
    except (TypeError, ValueError) as exc:
        raise AILiteracyStateError("AI literacy assignment failed validation") from exc
    if base["id"] != _stable_id("ALA", tenant_ref, subject_ref):
        raise AILiteracyStateError("AI literacy assignment identity changed")
    return {
        **base,
        "subject_ref": subject_ref,
        "role_assignments": roles,
        "system_assignments": systems,
        "status": status,
        "payload_sha256": payload_sha,
        "idempotency_receipts": receipts,
        "_source": record,
    }


def _completion_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "subject_ref": _principal(record.get("subject_ref")),
        "requirement_id": _record_id(record.get("requirement_id"), "ALR"),
        "content": dict(record.get("content") or {}),
        "completed_at": _timestamp(record.get("completed_at"), "completed_at"),
        "expires_at": _timestamp(record.get("expires_at"), "expires_at"),
        "provider_evidence_sha256": _digest(
            record.get("provider_evidence_sha256"),
            "provider_evidence_sha256",
        ),
        "provider_record_sha256": _digest(
            record.get("provider_record_sha256"),
            "provider_record_sha256",
        ),
    }


def _validate_completion(record: Mapping[str, Any], tenant_ref: str) -> dict[str, Any]:
    base = _base_record(
        record,
        schema=COMPLETION_SCHEMA,
        prefix="ALC",
        tenant_ref=tenant_ref,
    )
    try:
        payload = _completion_payload(record)
        content = payload["content"]
        normalized_content = _content(
            content.get("provider_id"),
            content.get("content_id"),
            content.get("content_version"),
        )
        if content != normalized_content or payload["expires_at"] <= payload["completed_at"]:
            raise ValueError("content or dates")
        binding = record.get("requirement_binding")
        if not isinstance(binding, Mapping) or set(binding) != {
            "requirement_id",
            "revision",
            "content_sha256",
        }:
            raise ValueError("requirement binding")
        normalized_binding = {
            "requirement_id": _record_id(binding.get("requirement_id"), "ALR"),
            "revision": _integer(
                binding.get("revision"),
                "requirement revision",
                1,
                1_000_000_000,
            ),
            "content_sha256": _digest(
                binding.get("content_sha256"),
                "content_sha256",
            ),
        }
        if dict(binding) != normalized_binding:
            raise ValueError("requirement binding")
        if (
            normalized_binding["requirement_id"] != payload["requirement_id"]
            or normalized_binding["content_sha256"] != normalized_content["content_sha256"]
        ):
            raise ValueError("requirement binding")
        recorded_at = _timestamp(record.get("recorded_at"), "recorded_at")
        key_sha = _digest(record.get("idempotency_sha256"), "idempotency_sha256")
        payload_sha = _digest(record.get("payload_sha256"), "payload_sha256")
        payload["content"] = normalized_content
        if payload_sha != _sha256(payload):
            raise ValueError("payload digest")
    except (TypeError, ValueError) as exc:
        raise AILiteracyStateError("AI literacy completion failed validation") from exc
    expected_id = _stable_id(
        "ALC",
        tenant_ref,
        payload["subject_ref"],
        payload["requirement_id"],
        key_sha,
    )
    if base["id"] != expected_id:
        raise AILiteracyStateError("AI literacy completion identity changed")
    return {
        **base,
        **payload,
        "requirement_binding": normalized_binding,
        "recorded_at": recorded_at,
        "idempotency_sha256": key_sha,
        "payload_sha256": payload_sha,
        "_source": record,
    }


def _waiver_grant_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "subject_ref": _principal(record.get("subject_ref")),
        "requirement_id": _record_id(record.get("requirement_id"), "ALR"),
        "kind": _token(record.get("kind"), "waiver kind"),
        "reviewer_ref": _principal(record.get("reviewer_ref")),
        "reason_code": _token(record.get("reason_code"), "reason_code"),
        "decision_basis_sha256": _digest(
            record.get("decision_basis_sha256"),
            "decision_basis_sha256",
        ),
        "starts_at": _timestamp(record.get("starts_at"), "starts_at"),
        "expires_at": _timestamp(record.get("expires_at"), "expires_at"),
    }


def _validate_waiver(record: Mapping[str, Any], tenant_ref: str) -> dict[str, Any]:
    base = _base_record(
        record,
        schema=WAIVER_SCHEMA,
        prefix="ALW",
        tenant_ref=tenant_ref,
    )
    try:
        payload = _waiver_grant_payload(record)
        if payload["kind"] not in _WAIVER_KINDS:
            raise ValueError("kind")
        if payload["reason_code"] not in _WAIVER_REASONS:
            raise ValueError("reason")
        if payload["subject_ref"] == payload["reviewer_ref"]:
            raise ValueError("self review")
        if payload["expires_at"] <= payload["starts_at"]:
            raise ValueError("dates")
        binding = record.get("requirement_binding")
        if not isinstance(binding, Mapping) or set(binding) != {
            "requirement_id",
            "revision",
            "control_sha256",
        }:
            raise ValueError("requirement binding")
        normalized_binding = {
            "requirement_id": _record_id(binding.get("requirement_id"), "ALR"),
            "revision": _integer(
                binding.get("revision"),
                "requirement revision",
                1,
                1_000_000_000,
            ),
            "control_sha256": _digest(
                binding.get("control_sha256"),
                "control_sha256",
            ),
        }
        if normalized_binding["requirement_id"] != payload["requirement_id"]:
            raise ValueError("requirement binding")
        status = _token(record.get("status"), "waiver status")
        if status not in _WAIVER_STATUSES:
            raise ValueError("status")
        revoked = record.get("revocation")
        if status == "active" and revoked is not None:
            raise ValueError("active revocation")
        if status == "revoked":
            if not isinstance(revoked, Mapping) or set(revoked) != {
                "reviewer_ref",
                "revoked_at",
            }:
                raise ValueError("revocation")
            revoked = {
                "reviewer_ref": _principal(revoked.get("reviewer_ref")),
                "revoked_at": _timestamp(revoked.get("revoked_at"), "revoked_at"),
            }
        granted_at = _timestamp(record.get("granted_at"), "granted_at")
        key_sha = _digest(record.get("idempotency_sha256"), "idempotency_sha256")
        payload_sha = _digest(record.get("payload_sha256"), "payload_sha256")
        if payload_sha != _sha256(payload):
            raise ValueError("payload digest")
        receipts = _receipt_list(record.get("idempotency_receipts"))
    except (TypeError, ValueError) as exc:
        raise AILiteracyStateError("AI literacy waiver failed validation") from exc
    expected_id = _stable_id(
        "ALW",
        tenant_ref,
        payload["subject_ref"],
        payload["requirement_id"],
        key_sha,
    )
    if base["id"] != expected_id:
        raise AILiteracyStateError("AI literacy waiver identity changed")
    return {
        **base,
        **payload,
        "requirement_binding": normalized_binding,
        "status": status,
        "revocation": revoked,
        "granted_at": granted_at,
        "idempotency_sha256": key_sha,
        "payload_sha256": payload_sha,
        "idempotency_receipts": receipts,
        "_source": record,
    }


def _requirement_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "schema": REQUIREMENT_SCHEMA,
        "tenant_ref": row["tenant_ref"],
        "requirement_key": row["requirement_key"],
        "title": row["title"],
        "scope": row["scope"],
        "content": row["content"],
        "validity_days": row["validity_days"],
        "due_within_days": row["due_within_days"],
        "status": row["status"],
        "effective_at": row["effective_at"],
        "control_sha256": row["control_sha256"],
        "revision": row["revision"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _assignment_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "schema": ASSIGNMENT_SCHEMA,
        "tenant_ref": row["tenant_ref"],
        "subject_ref": row["subject_ref"],
        "role_assignments": row["role_assignments"],
        "system_assignments": row["system_assignments"],
        "status": row["status"],
        "revision": row["revision"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _completion_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "schema": COMPLETION_SCHEMA,
        "tenant_ref": row["tenant_ref"],
        "subject_ref": row["subject_ref"],
        "requirement_id": row["requirement_id"],
        "requirement_binding": row["requirement_binding"],
        "content": row["content"],
        "completed_at": row["completed_at"],
        "expires_at": row["expires_at"],
        "provider_evidence_sha256": row["provider_evidence_sha256"],
        "provider_record_sha256": row["provider_record_sha256"],
        "recorded_at": row["recorded_at"],
        "revision": row["revision"],
        "created_at": row["created_at"],
    }


def _waiver_projection(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "schema": WAIVER_SCHEMA,
        "tenant_ref": row["tenant_ref"],
        "subject_ref": row["subject_ref"],
        "requirement_id": row["requirement_id"],
        "requirement_binding": row["requirement_binding"],
        "kind": row["kind"],
        "reviewer_ref": row["reviewer_ref"],
        "reason_code": row["reason_code"],
        "decision_basis_sha256": row["decision_basis_sha256"],
        "starts_at": row["starts_at"],
        "expires_at": row["expires_at"],
        "status": row["status"],
        "revocation": row["revocation"],
        "granted_at": row["granted_at"],
        "revision": row["revision"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _bounded_rows(store: GovernedRecordStore, maximum: int, label: str) -> list[dict[str, Any]]:
    rows = store.list(limit=maximum + 1)
    if len(rows) > maximum:
        raise AILiteracyStateError(f"{label} exceeds the {maximum}-record limit")
    return rows


def _create_idempotent(
    store: GovernedRecordStore,
    record: dict[str, Any],
    *,
    action: str,
    actor: str,
    maximum: int,
    operation: str,
    key_sha256: str,
    payload_sha256: str,
) -> dict[str, Any]:
    try:
        return store.create(record, action=action, actor=actor, max_records=maximum)
    except RecordConflict:
        current = store.get(record["id"])
        if current is not None and _replayed(
            current,
            operation=operation,
            key_sha256=key_sha256,
            payload_sha256=payload_sha256,
        ):
            return current
        raise


def verify_evidence_export(value: object) -> bool:
    """Return whether a literacy export is internally canonical and untampered."""

    if not isinstance(value, Mapping):
        return False
    try:
        document = dict(value)
        claimed = _digest(document.pop("evidence_sha256", None), "evidence_sha256")
        if (
            document.get("schema") != EVIDENCE_EXPORT_SCHEMA
            or document.get("stores_direct_person_identifiers") is not False
            or document.get("notice") != NON_DETERMINATION_NOTICE
        ):
            return False
        return hmac.compare_digest(claimed, _sha256(document))
    except (TypeError, ValueError):
        return False


class AILiteracyRegister:
    """Governed AI-literacy authority with injectable persistence backends."""

    def __init__(
        self,
        *,
        requirements: GovernedRecordStore | None = None,
        assignments: GovernedRecordStore | None = None,
        completions: GovernedRecordStore | None = None,
        waivers: GovernedRecordStore | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if clock is not None and not callable(clock):
            raise ValueError("clock must be callable")
        self._requirements = requirements or _REQUIREMENTS
        self._assignments = assignments or _ASSIGNMENTS
        self._completions = completions or _COMPLETIONS
        self._waivers = waivers or _WAIVERS
        self._clock = clock

    @property
    def backend_kind(self) -> str:
        kinds = {
            store.backend_kind
            for store in (
                self._requirements,
                self._assignments,
                self._completions,
                self._waivers,
            )
        }
        if len(kinds) != 1:
            raise AILiteracyStateError("AI literacy authorities use different backends")
        return next(iter(kinds))

    def _now(self) -> float:
        source = self._clock or self._requirements.authoritative_time
        try:
            return _timestamp(source(), "authority clock")
        except (TypeError, ValueError) as exc:
            raise AILiteracyStateError("AI literacy authority clock is invalid") from exc

    def upsert_requirement(
        self,
        requirement_key: str,
        *,
        title: str,
        role_ids: Sequence[str],
        system_ids: Sequence[str],
        provider_id: str,
        content_id: str,
        content_version: str,
        validity_days: int,
        due_within_days: int,
        status: str = "active",
        expected_revision: int,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        """CAS-create or replace one role/system literacy requirement."""

        _, tenant_ref = _active_tenant()
        key = _token(requirement_key, "requirement_key")
        name = _safe_title(title)
        roles = _tokens(role_ids, "role_id")
        systems = _tokens(system_ids, "system_id")
        if not roles and not systems:
            raise ValueError("a literacy requirement needs a role or system scope")
        content = _content(provider_id, content_id, content_version)
        validity = _integer(validity_days, "validity_days", 1, _MAX_VALIDITY_DAYS)
        due = _integer(due_within_days, "due_within_days", 0, _MAX_DUE_DAYS)
        state = _token(status, "status")
        if state not in _REQUIREMENT_STATUSES:
            raise ValueError(f"status must be one of {sorted(_REQUIREMENT_STATUSES)}")
        expected = _revision(expected_revision)
        operator = _required_text(actor, "actor", 256)
        idem_sha = _idempotency_digest(idempotency_key)
        payload = _requirement_payload(
            requirement_key=key,
            title=name,
            role_ids=roles,
            system_ids=systems,
            content=content,
            validity_days=validity,
            due_within_days=due,
            status=state,
        )
        payload_sha = _sha256(payload)
        control_sha = _sha256({item: payload[item] for item in payload if item != "title"})
        record_id = _stable_id("ALR", tenant_ref, key)
        current_raw = self._requirements.get(record_id)
        current = (
            None
            if current_raw is None
            else _validate_requirement(current_raw, tenant_ref)
        )
        if current is not None and _replayed(
            current_raw,
            operation="upsert_requirement",
            key_sha256=idem_sha,
            payload_sha256=payload_sha,
        ):
            return _requirement_projection(current)
        current_revision = int((current or {}).get("revision") or 0)
        if current_revision != expected:
            raise RecordConflict(
                f"literacy requirement changed (expected revision {expected}, "
                f"found {current_revision})"
            )
        effective_at = (
            current["effective_at"]
            if current is not None and current["control_sha256"] == control_sha
            else self._now()
        )
        if current is None:
            record = {
                "id": record_id,
                "schema": REQUIREMENT_SCHEMA,
                "tenant_ref": tenant_ref,
                **payload,
                "effective_at": effective_at,
                "payload_sha256": payload_sha,
                "control_sha256": control_sha,
                "idempotency_receipts": [],
            }
            _append_receipt(
                record,
                operation="upsert_requirement",
                key_sha256=idem_sha,
                payload_sha256=payload_sha,
                result_revision=1,
            )
            saved = _create_idempotent(
                self._requirements,
                record,
                action="upsert_literacy_requirement",
                actor=operator,
                maximum=_MAX_REQUIREMENTS,
                operation="upsert_requirement",
                key_sha256=idem_sha,
                payload_sha256=payload_sha,
            )
        else:
            def mutate(row: dict[str, Any]) -> None:
                for field, value in payload.items():
                    row[field] = value
                row["effective_at"] = effective_at
                row["payload_sha256"] = payload_sha
                row["control_sha256"] = control_sha
                _append_receipt(
                    row,
                    operation="upsert_requirement",
                    key_sha256=idem_sha,
                    payload_sha256=payload_sha,
                    result_revision=expected + 1,
                )

            try:
                saved = self._requirements.update(
                    record_id,
                    mutate,
                    expected_revision=expected,
                    action="upsert_literacy_requirement",
                    actor=operator,
                )
            except RecordConflict:
                latest = self._requirements.get(record_id)
                if latest is None or not _replayed(
                    latest,
                    operation="upsert_requirement",
                    key_sha256=idem_sha,
                    payload_sha256=payload_sha,
                ):
                    raise
                saved = latest
            if saved is None:
                raise AILiteracyStateError("literacy requirement disappeared during update")
        return _requirement_projection(_validate_requirement(saved, tenant_ref))

    def get_requirement(self, requirement_key: str) -> dict[str, Any] | None:
        _, tenant_ref = _active_tenant()
        key = _token(requirement_key, "requirement_key")
        raw = self._requirements.get(_stable_id("ALR", tenant_ref, key))
        if raw is None:
            return None
        return _requirement_projection(_validate_requirement(raw, tenant_ref))

    def list_requirements(self, *, include_retired: bool = False) -> list[dict[str, Any]]:
        _, tenant_ref = _active_tenant()
        rows = [
            _validate_requirement(row, tenant_ref)
            for row in _bounded_rows(
                self._requirements,
                _MAX_REQUIREMENTS,
                "AI literacy requirements",
            )
        ]
        if not include_retired:
            rows = [row for row in rows if row["status"] == "active"]
        return [
            _requirement_projection(row)
            for row in sorted(rows, key=lambda item: item["requirement_key"])
        ]

    def set_person_assignments(
        self,
        person_id: str,
        *,
        role_ids: Sequence[str],
        system_ids: Sequence[str],
        expected_revision: int,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        """CAS-replace a person's role/system assignment without storing its ID."""

        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        roles = _tokens(role_ids, "role_id")
        systems = _tokens(system_ids, "system_id")
        expected = _revision(expected_revision)
        operator = _required_text(actor, "actor", 256)
        idem_sha = _idempotency_digest(idempotency_key)
        payload = _assignment_payload(roles, systems)
        payload_sha = _sha256(payload)
        record_id = _stable_id("ALA", tenant_ref, subject_ref)
        current_raw = self._assignments.get(record_id)
        current = (
            None
            if current_raw is None
            else _validate_assignment(current_raw, tenant_ref)
        )
        if current is not None and _replayed(
            current_raw,
            operation="set_person_assignments",
            key_sha256=idem_sha,
            payload_sha256=payload_sha,
        ):
            return _assignment_projection(current)
        current_revision = int((current or {}).get("revision") or 0)
        if current_revision != expected:
            raise RecordConflict(
                f"literacy assignment changed (expected revision {expected}, "
                f"found {current_revision})"
            )
        changed_at = self._now()
        prior_roles = {
            item["role_id"]: item["assigned_at"]
            for item in (current or {}).get("role_assignments", [])
        }
        prior_systems = {
            item["system_id"]: item["assigned_at"]
            for item in (current or {}).get("system_assignments", [])
        }
        role_entries = [
            {"role_id": role, "assigned_at": prior_roles.get(role, changed_at)}
            for role in roles
        ]
        system_entries = [
            {"system_id": system, "assigned_at": prior_systems.get(system, changed_at)}
            for system in systems
        ]
        state = "active" if role_entries or system_entries else "inactive"
        if current is None:
            record = {
                "id": record_id,
                "schema": ASSIGNMENT_SCHEMA,
                "tenant_ref": tenant_ref,
                "subject_ref": subject_ref,
                "role_assignments": role_entries,
                "system_assignments": system_entries,
                "status": state,
                "payload_sha256": payload_sha,
                "idempotency_receipts": [],
            }
            _append_receipt(
                record,
                operation="set_person_assignments",
                key_sha256=idem_sha,
                payload_sha256=payload_sha,
                result_revision=1,
            )
            saved = _create_idempotent(
                self._assignments,
                record,
                action="set_literacy_assignments",
                actor=operator,
                maximum=_MAX_ASSIGNMENTS,
                operation="set_person_assignments",
                key_sha256=idem_sha,
                payload_sha256=payload_sha,
            )
        else:
            def mutate(row: dict[str, Any]) -> None:
                row["role_assignments"] = role_entries
                row["system_assignments"] = system_entries
                row["status"] = state
                row["payload_sha256"] = payload_sha
                _append_receipt(
                    row,
                    operation="set_person_assignments",
                    key_sha256=idem_sha,
                    payload_sha256=payload_sha,
                    result_revision=expected + 1,
                )

            try:
                saved = self._assignments.update(
                    record_id,
                    mutate,
                    expected_revision=expected,
                    action="set_literacy_assignments",
                    actor=operator,
                )
            except RecordConflict:
                latest = self._assignments.get(record_id)
                if latest is None or not _replayed(
                    latest,
                    operation="set_person_assignments",
                    key_sha256=idem_sha,
                    payload_sha256=payload_sha,
                ):
                    raise
                saved = latest
            if saved is None:
                raise AILiteracyStateError("literacy assignment disappeared during update")
        return _assignment_projection(_validate_assignment(saved, tenant_ref))

    def get_person_assignment(self, person_id: str) -> dict[str, Any] | None:
        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        raw = self._assignments.get(_stable_id("ALA", tenant_ref, subject_ref))
        if raw is None:
            return None
        return _assignment_projection(_validate_assignment(raw, tenant_ref))

    def record_completion(
        self,
        person_id: str,
        requirement_key: str,
        *,
        provider_id: str,
        content_id: str,
        content_version: str,
        completed_at: float,
        expires_at: float,
        provider_evidence_sha256: str,
        provider_record_id: str,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        """Persist an immutable, content-version-bound LMS completion receipt."""

        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        key = _token(requirement_key, "requirement_key")
        requirement_raw = self._requirements.get(_stable_id("ALR", tenant_ref, key))
        if requirement_raw is None:
            raise AILiteracyStateError("AI literacy requirement does not exist")
        requirement = _validate_requirement(requirement_raw, tenant_ref)
        if requirement["status"] != "active":
            raise AILiteracyStateError("cannot record completion for a retired requirement")
        completion_content = _content(provider_id, content_id, content_version)
        if (
            completion_content["provider_id"] != requirement["content"]["provider_id"]
            or completion_content["content_id"] != requirement["content"]["content_id"]
        ):
            raise ValueError(
                "completion provider and content identity do not match the requirement"
            )
        now = self._now()
        completed = _timestamp(completed_at, "completed_at")
        if completed > now + _MAX_FUTURE_SKEW:
            raise ValueError("completed_at exceeds the clock-skew allowance")
        expires = _timestamp(expires_at, "expires_at")
        if expires <= completed:
            raise ValueError("expires_at must be after completed_at")
        max_expiry = completed + requirement["validity_days"] * _SECONDS_PER_DAY
        if expires > max_expiry + _MAX_FUTURE_SKEW:
            raise ValueError("expires_at exceeds the requirement validity period")
        evidence_sha = _digest(provider_evidence_sha256, "provider_evidence_sha256")
        provider_record = _required_text(provider_record_id, "provider_record_id", 512)
        provider_record_sha = _sha256({
            "provider_id": completion_content["provider_id"],
            "provider_record_id": provider_record,
        })
        operator = _required_text(actor, "actor", 256)
        idem_sha = _idempotency_digest(idempotency_key)
        payload = {
            "subject_ref": subject_ref,
            "requirement_id": requirement["id"],
            "content": completion_content,
            "completed_at": completed,
            "expires_at": expires,
            "provider_evidence_sha256": evidence_sha,
            "provider_record_sha256": provider_record_sha,
        }
        payload_sha = _sha256(payload)
        record_id = _stable_id(
            "ALC",
            tenant_ref,
            subject_ref,
            requirement["id"],
            idem_sha,
        )
        existing = self._completions.get(record_id)
        if existing is not None:
            completion = _validate_completion(existing, tenant_ref)
            if not hmac.compare_digest(completion["payload_sha256"], payload_sha):
                raise AILiteracyIdempotencyConflict(
                    "idempotency key is already bound to different completion evidence"
                )
            return _completion_projection(completion)
        record = {
            "id": record_id,
            "schema": COMPLETION_SCHEMA,
            "tenant_ref": tenant_ref,
            **payload,
            "requirement_binding": {
                "requirement_id": requirement["id"],
                "revision": requirement["revision"],
                "content_sha256": completion_content["content_sha256"],
            },
            "recorded_at": now,
            "idempotency_sha256": idem_sha,
            "payload_sha256": payload_sha,
        }
        try:
            saved = self._completions.create(
                record,
                action="record_literacy_completion",
                actor=operator,
                max_records=_MAX_COMPLETIONS,
            )
        except RecordConflict:
            saved = self._completions.get(record_id)
            if saved is None:
                raise
            raced = _validate_completion(saved, tenant_ref)
            if not hmac.compare_digest(raced["payload_sha256"], payload_sha):
                raise AILiteracyIdempotencyConflict(
                    "idempotency key is already bound to different completion evidence"
                ) from None
        return _completion_projection(_validate_completion(saved, tenant_ref))

    def grant_waiver(
        self,
        person_id: str,
        requirement_key: str,
        *,
        kind: str,
        reviewer_id: str,
        reason_code: str,
        decision_basis_sha256: str,
        starts_at: float,
        expires_at: float,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        """Grant a bounded exemption/waiver reviewed by another principal."""

        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        reviewer_ref = _principal_ref(tenant_id, reviewer_id)
        if subject_ref == reviewer_ref:
            raise ValueError("a literacy exemption or waiver cannot be self-reviewed")
        key = _token(requirement_key, "requirement_key")
        requirement_raw = self._requirements.get(_stable_id("ALR", tenant_ref, key))
        if requirement_raw is None:
            raise AILiteracyStateError("AI literacy requirement does not exist")
        requirement = _validate_requirement(requirement_raw, tenant_ref)
        if requirement["status"] != "active":
            raise AILiteracyStateError("cannot waive a retired requirement")
        waiver_kind = _token(kind, "kind")
        if waiver_kind not in _WAIVER_KINDS:
            raise ValueError(f"kind must be one of {sorted(_WAIVER_KINDS)}")
        reason = _token(reason_code, "reason_code")
        if reason not in _WAIVER_REASONS:
            raise ValueError(f"reason_code must be one of {sorted(_WAIVER_REASONS)}")
        basis = _digest(decision_basis_sha256, "decision_basis_sha256")
        starts = _timestamp(starts_at, "starts_at")
        expires = _timestamp(expires_at, "expires_at")
        now = self._now()
        if starts > now + _MAX_FUTURE_WAIVER_DAYS * _SECONDS_PER_DAY:
            raise ValueError("starts_at is too far in the future")
        if expires <= starts:
            raise ValueError("expires_at must be after starts_at")
        if expires > starts + _MAX_VALIDITY_DAYS * _SECONDS_PER_DAY:
            raise ValueError("waiver exceeds the maximum validity period")
        operator = _required_text(actor, "actor", 256)
        idem_sha = _idempotency_digest(idempotency_key)
        payload = {
            "subject_ref": subject_ref,
            "requirement_id": requirement["id"],
            "kind": waiver_kind,
            "reviewer_ref": reviewer_ref,
            "reason_code": reason,
            "decision_basis_sha256": basis,
            "starts_at": starts,
            "expires_at": expires,
        }
        payload_sha = _sha256(payload)
        record_id = _stable_id(
            "ALW",
            tenant_ref,
            subject_ref,
            requirement["id"],
            idem_sha,
        )
        existing = self._waivers.get(record_id)
        if existing is not None:
            waiver = _validate_waiver(existing, tenant_ref)
            if not hmac.compare_digest(waiver["payload_sha256"], payload_sha):
                raise AILiteracyIdempotencyConflict(
                    "idempotency key is already bound to a different waiver"
                )
            return _waiver_projection(waiver)
        record = {
            "id": record_id,
            "schema": WAIVER_SCHEMA,
            "tenant_ref": tenant_ref,
            **payload,
            "requirement_binding": {
                "requirement_id": requirement["id"],
                "revision": requirement["revision"],
                "control_sha256": requirement["control_sha256"],
            },
            "status": "active",
            "revocation": None,
            "granted_at": now,
            "idempotency_sha256": idem_sha,
            "payload_sha256": payload_sha,
            "idempotency_receipts": [],
        }
        _append_receipt(
            record,
            operation="grant_waiver",
            key_sha256=idem_sha,
            payload_sha256=payload_sha,
            result_revision=1,
        )
        saved = _create_idempotent(
            self._waivers,
            record,
            action="grant_literacy_waiver",
            actor=operator,
            maximum=_MAX_WAIVERS,
            operation="grant_waiver",
            key_sha256=idem_sha,
            payload_sha256=payload_sha,
        )
        return _waiver_projection(_validate_waiver(saved, tenant_ref))

    def revoke_waiver(
        self,
        waiver_id: str,
        *,
        reviewer_id: str,
        expected_revision: int,
        idempotency_key: str,
        actor: str,
    ) -> dict[str, Any]:
        """CAS-revoke a waiver while retaining the original decision evidence."""

        tenant_id, tenant_ref = _active_tenant()
        record_id = _record_id(waiver_id, "ALW")
        reviewer_ref = _principal_ref(tenant_id, reviewer_id)
        expected = _revision(expected_revision)
        operator = _required_text(actor, "actor", 256)
        idem_sha = _idempotency_digest(idempotency_key)
        payload = {"waiver_id": record_id, "reviewer_ref": reviewer_ref}
        payload_sha = _sha256(payload)
        current_raw = self._waivers.get(record_id)
        if current_raw is None:
            raise AILiteracyStateError("AI literacy waiver does not exist")
        current = _validate_waiver(current_raw, tenant_ref)
        if _replayed(
            current_raw,
            operation="revoke_waiver",
            key_sha256=idem_sha,
            payload_sha256=payload_sha,
        ):
            return _waiver_projection(current)
        if current["revision"] != expected:
            raise RecordConflict(
                f"literacy waiver changed (expected revision {expected}, "
                f"found {current['revision']})"
            )
        if current["status"] != "active":
            raise AILiteracyStateError("AI literacy waiver is already revoked")
        revoked_at = self._now()

        def mutate(row: dict[str, Any]) -> None:
            row["status"] = "revoked"
            row["revocation"] = {
                "reviewer_ref": reviewer_ref,
                "revoked_at": revoked_at,
            }
            _append_receipt(
                row,
                operation="revoke_waiver",
                key_sha256=idem_sha,
                payload_sha256=payload_sha,
                result_revision=expected + 1,
            )

        try:
            saved = self._waivers.update(
                record_id,
                mutate,
                expected_revision=expected,
                action="revoke_literacy_waiver",
                actor=operator,
            )
        except RecordConflict:
            saved = self._waivers.get(record_id)
            if saved is None or not _replayed(
                saved,
                operation="revoke_waiver",
                key_sha256=idem_sha,
                payload_sha256=payload_sha,
            ):
                raise
        if saved is None:
            raise AILiteracyStateError("AI literacy waiver disappeared during revocation")
        return _waiver_projection(_validate_waiver(saved, tenant_ref))

    def list_completions(self, person_id: str) -> list[dict[str, Any]]:
        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        rows = [
            _validate_completion(row, tenant_ref)
            for row in _bounded_rows(
                self._completions,
                _MAX_COMPLETIONS,
                "AI literacy completions",
            )
        ]
        return [
            _completion_projection(row)
            for row in sorted(
                (item for item in rows if item["subject_ref"] == subject_ref),
                key=lambda item: (item["completed_at"], item["id"]),
            )
        ]

    def list_waivers(self, person_id: str) -> list[dict[str, Any]]:
        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        rows = [
            _validate_waiver(row, tenant_ref)
            for row in _bounded_rows(
                self._waivers,
                _MAX_WAIVERS,
                "AI literacy waivers",
            )
        ]
        return [
            _waiver_projection(row)
            for row in sorted(
                (item for item in rows if item["subject_ref"] == subject_ref),
                key=lambda item: (item["starts_at"], item["id"]),
            )
        ]

    @staticmethod
    def _matching_scopes(
        requirement: Mapping[str, Any],
        assignment: Mapping[str, Any],
        as_of: float,
    ) -> tuple[list[str], list[str], list[float]]:
        role_scope = set(requirement["scope"]["role_ids"])
        system_scope = set(requirement["scope"]["system_ids"])
        matched_roles = [
            item for item in assignment["role_assignments"]
            if item["role_id"] in role_scope and item["assigned_at"] <= as_of
        ]
        matched_systems = [
            item for item in assignment["system_assignments"]
            if item["system_id"] in system_scope and item["assigned_at"] <= as_of
        ]
        return (
            [item["role_id"] for item in matched_roles],
            [item["system_id"] for item in matched_systems],
            [item["assigned_at"] for item in [*matched_roles, *matched_systems]],
        )

    @staticmethod
    def _completion_state(
        requirement: Mapping[str, Any],
        completions: Sequence[Mapping[str, Any]],
        as_of: float,
    ) -> tuple[Mapping[str, Any] | None, str]:
        relevant = [
            row for row in completions
            if row["requirement_id"] == requirement["id"]
            and row["completed_at"] <= as_of
        ]
        exact = [
            row for row in relevant
            if row["content"]["content_sha256"]
            == requirement["content"]["content_sha256"]
        ]
        valid = [row for row in exact if row["expires_at"] > as_of]
        if valid:
            return max(valid, key=lambda row: (row["completed_at"], row["id"])), ""
        if exact:
            return None, "completion_expired"
        if relevant:
            return None, "current_content_not_completed"
        return None, "completion_missing"

    @staticmethod
    def _waiver_state(
        requirement: Mapping[str, Any],
        waivers: Sequence[Mapping[str, Any]],
        as_of: float,
    ) -> tuple[Mapping[str, Any] | None, str]:
        for_requirement = [
            row for row in waivers if row["requirement_id"] == requirement["id"]
        ]
        relevant = [
            row for row in waivers
            if row["requirement_id"] == requirement["id"]
            and row["requirement_binding"]["control_sha256"]
            == requirement["control_sha256"]
        ]
        active = [
            row for row in relevant
            if row["status"] == "active"
            and row["starts_at"] <= as_of < row["expires_at"]
        ]
        if active:
            return max(active, key=lambda row: (row["starts_at"], row["id"])), ""
        if any(row["status"] == "revoked" for row in relevant):
            return None, "waiver_revoked"
        if any(row["expires_at"] <= as_of for row in relevant):
            return None, "waiver_expired"
        if for_requirement:
            return None, "waiver_requirement_changed"
        return None, ""

    @staticmethod
    def _gap_reason(completion_gap: str, waiver_gap: str) -> str:
        if completion_gap and completion_gap != "completion_missing":
            return completion_gap
        return waiver_gap or completion_gap or "completion_missing"

    def _status_for_assignment(
        self,
        assignment: Mapping[str, Any],
        *,
        requirements: Sequence[Mapping[str, Any]],
        completions: Sequence[Mapping[str, Any]],
        waivers: Sequence[Mapping[str, Any]],
        as_of: float,
    ) -> dict[str, Any]:
        subject_ref = assignment["subject_ref"]
        subject_completions = [row for row in completions if row["subject_ref"] == subject_ref]
        subject_waivers = [row for row in waivers if row["subject_ref"] == subject_ref]
        results: list[dict[str, Any]] = []
        for requirement in requirements:
            if requirement["status"] != "active" or requirement["effective_at"] > as_of:
                continue
            roles, systems, assigned_dates = self._matching_scopes(
                requirement,
                assignment,
                as_of,
            )
            if not assigned_dates:
                continue
            due_at = (
                max(requirement["effective_at"], min(assigned_dates))
                + requirement["due_within_days"] * _SECONDS_PER_DAY
            )
            completion, completion_gap = self._completion_state(
                requirement,
                subject_completions,
                as_of,
            )
            waiver, waiver_gap = self._waiver_state(requirement, subject_waivers, as_of)
            if completion is not None:
                state = "satisfied"
                gap_reason = ""
            elif waiver is not None:
                state = "waived"
                gap_reason = ""
            elif as_of <= due_at:
                state = "due"
                gap_reason = self._gap_reason(completion_gap, waiver_gap)
            else:
                state = "overdue"
                gap_reason = self._gap_reason(completion_gap, waiver_gap)
            item = {
                "requirement": _requirement_projection(requirement),
                "requirement_authority": _citation(requirement["_source"]),
                "matched_role_ids": roles,
                "matched_system_ids": systems,
                "due_at": due_at,
                "state": state,
                "coverage_gap": state in {"due", "overdue"},
                "overdue": state == "overdue",
                "gap_reason": gap_reason,
                "completion": (
                    None if completion is None else _completion_projection(completion)
                ),
                "completion_authority": (
                    None if completion is None else _citation(completion["_source"])
                ),
                "waiver": None if waiver is None else _waiver_projection(waiver),
                "waiver_authority": (
                    None if waiver is None else _citation(waiver["_source"])
                ),
            }
            results.append(item)
        results.sort(key=lambda item: item["requirement"]["requirement_key"])
        summary = {
            "applicable_requirements": len(results),
            "satisfied": sum(item["state"] == "satisfied" for item in results),
            "waived": sum(item["state"] == "waived" for item in results),
            "due": sum(item["state"] == "due" for item in results),
            "overdue": sum(item["state"] == "overdue" for item in results),
            "coverage_gaps": sum(item["coverage_gap"] for item in results),
        }
        return {
            "schema": STATUS_SCHEMA,
            "as_of": as_of,
            "tenant_ref": assignment["tenant_ref"],
            "subject_ref": subject_ref,
            "assignment": _assignment_projection(assignment),
            "assignment_authority": _citation(assignment["_source"]),
            "summary": summary,
            "requirements": results,
            "compliant_for_registered_requirements": summary["coverage_gaps"] == 0,
            "stores_direct_person_identifiers": False,
            "notice": NON_DETERMINATION_NOTICE,
        }

    @staticmethod
    def _empty_status(tenant_ref: str, subject_ref: str, as_of: float) -> dict[str, Any]:
        return {
            "schema": STATUS_SCHEMA,
            "as_of": as_of,
            "tenant_ref": tenant_ref,
            "subject_ref": subject_ref,
            "assignment": None,
            "assignment_authority": None,
            "summary": {
                "applicable_requirements": 0,
                "satisfied": 0,
                "waived": 0,
                "due": 0,
                "overdue": 0,
                "coverage_gaps": 0,
            },
            "requirements": [],
            "compliant_for_registered_requirements": True,
            "stores_direct_person_identifiers": False,
            "notice": NON_DETERMINATION_NOTICE,
        }

    def _snapshot(
        self,
        tenant_ref: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
        requirements = [
            _validate_requirement(row, tenant_ref)
            for row in _bounded_rows(
                self._requirements,
                _MAX_REQUIREMENTS,
                "AI literacy requirements",
            )
        ]
        completions = [
            _validate_completion(row, tenant_ref)
            for row in _bounded_rows(
                self._completions,
                _MAX_COMPLETIONS,
                "AI literacy completions",
            )
        ]
        waivers = [
            _validate_waiver(row, tenant_ref)
            for row in _bounded_rows(
                self._waivers,
                _MAX_WAIVERS,
                "AI literacy waivers",
            )
        ]
        return requirements, completions, waivers

    def compute_gaps(self, person_id: str, *, as_of: float | None = None) -> dict[str, Any]:
        """Compute current coverage without exposing the supplied person ID."""

        tenant_id, tenant_ref = _active_tenant()
        subject_ref = _principal_ref(tenant_id, person_id)
        observed_at = self._now() if as_of is None else _timestamp(as_of, "as_of")
        raw = self._assignments.get(_stable_id("ALA", tenant_ref, subject_ref))
        if raw is None:
            return self._empty_status(tenant_ref, subject_ref, observed_at)
        assignment = _validate_assignment(raw, tenant_ref)
        requirements, completions, waivers = self._snapshot(tenant_ref)
        return self._status_for_assignment(
            assignment,
            requirements=requirements,
            completions=completions,
            waivers=waivers,
            as_of=observed_at,
        )

    def export_evidence(
        self,
        *,
        person_ids: Sequence[str] | None = None,
        as_of: float | None = None,
    ) -> dict[str, Any]:
        """Build a self-digested, pseudonymous tenant literacy evidence export."""

        tenant_id, tenant_ref = _active_tenant()
        observed_at = self._now() if as_of is None else _timestamp(as_of, "as_of")
        generated_at = self._now()
        requirements, completions, waivers = self._snapshot(tenant_ref)
        selected = person_ids is not None
        if selected:
            if isinstance(person_ids, (str, bytes, Mapping)):
                raise ValueError("person_ids must be a list")
            raw_ids = list(islice(iter(person_ids or []), _MAX_EXPORT_SUBJECTS + 1))
            if len(raw_ids) > _MAX_EXPORT_SUBJECTS:
                raise ValueError(
                    f"person_ids exceeds the {_MAX_EXPORT_SUBJECTS}-subject export limit"
                )
            subject_refs = sorted({_principal_ref(tenant_id, item) for item in raw_ids})
            assignments: list[dict[str, Any] | None] = []
            for subject_ref in subject_refs:
                raw = self._assignments.get(_stable_id("ALA", tenant_ref, subject_ref))
                assignments.append(
                    None if raw is None else _validate_assignment(raw, tenant_ref)
                )
        else:
            raw_assignments = _bounded_rows(
                self._assignments,
                _MAX_ASSIGNMENTS,
                "AI literacy assignments",
            )
            if len(raw_assignments) > _MAX_EXPORT_SUBJECTS:
                raise AILiteracyStateError(
                    "tenant literacy export exceeds the subject limit; select person_ids"
                )
            assignments = [
                _validate_assignment(row, tenant_ref) for row in raw_assignments
            ]
            assignments.sort(key=lambda row: row["subject_ref"])
            subject_refs = [row["subject_ref"] for row in assignments]
        subjects: list[dict[str, Any]] = []
        for subject_ref, assignment in zip(subject_refs, assignments, strict=True):
            if assignment is None:
                subjects.append(self._empty_status(tenant_ref, subject_ref, observed_at))
            else:
                subjects.append(self._status_for_assignment(
                    assignment,
                    requirements=requirements,
                    completions=completions,
                    waivers=waivers,
                    as_of=observed_at,
                ))
        summary = {
            "subjects": len(subjects),
            "applicable_requirements": sum(
                row["summary"]["applicable_requirements"] for row in subjects
            ),
            "satisfied": sum(row["summary"]["satisfied"] for row in subjects),
            "waived": sum(row["summary"]["waived"] for row in subjects),
            "due": sum(row["summary"]["due"] for row in subjects),
            "overdue": sum(row["summary"]["overdue"] for row in subjects),
            "coverage_gaps": sum(row["summary"]["coverage_gaps"] for row in subjects),
        }
        document: dict[str, Any] = {
            "schema": EVIDENCE_EXPORT_SCHEMA,
            "generated_at": generated_at,
            "as_of": observed_at,
            "tenant_ref": tenant_ref,
            "scope": "selected_subjects" if selected else "all_assignments",
            "summary": summary,
            "subjects": subjects,
            "stores_direct_person_identifiers": False,
            "notice": NON_DETERMINATION_NOTICE,
        }
        document["evidence_sha256"] = _sha256(document)
        return document


default_register = AILiteracyRegister()


# Role-oriented compatibility API used by the governance workspace and CLI.
# Its records use separate stores so the privacy-minimising evidence register
# above retains its closed schemas and pseudonymous subject projections.
ROLE_REQUIREMENT_SCHEMA = "lightwork.ai-literacy-role-requirement.v1"
ROLE_ASSIGNMENT_SCHEMA = "lightwork.ai-literacy-role-assignment.v1"
ROLE_COMPLETION_SCHEMA = "lightwork.ai-literacy-role-completion.v1"
REGULATION_METADATA = {
    "regulation": "Regulation (EU) 2024/1689",
    "article": "Art. 4",
    "obligation": "AI literacy of staff and other persons operating AI systems",
    "applicable_since": "2025-02-02",
}
NON_CERTIFICATION_NOTICE = (
    "AI-literacy tracking is decision support for the Art. 4 obligation; it "
    "is not a certification of competence or of training sufficiency."
)
PLANE_RECONCILIATION_NOTICE = (
    "The privacy-minimising canonical register is the compliance evidence "
    "authority. Role-compatibility records are operational intake only and "
    "require explicit evidence-enriched reconciliation; they are never "
    "promoted automatically."
)
_ROLE_REQUIREMENTS = GovernedRecordStore(
    "ai_literacy_role_requirements", "ALR", "ai_literacy_role_requirement",
)
_ROLE_ASSIGNMENTS = GovernedRecordStore(
    "ai_literacy_role_assignments", "ALA", "ai_literacy_role_assignment",
)
_ROLE_COMPLETIONS = GovernedRecordStore(
    "ai_literacy_role_completions", "ALC", "ai_literacy_role_completion",
)

_ROLE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,127}\Z")
_ROLE_MAX_TRAININGS = 64
_ROLE_MAX_ROLES = 64
_ROLE_MAX_HISTORY = 20
_ROLE_MAX_LIST = 500
_ROLE_DAY = 86_400.0


class AILiteracyConfigError(AILiteracyError):
    """The [ai_literacy] configuration is missing, malformed, or disabled."""


def _role_sha256(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _role_token(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ROLE_TOKEN_RE.fullmatch(value.strip()):
        raise ValueError(f"{label} must be a bounded identifier token")
    return value.strip()


def _role_text(value: Any, label: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    out = value.strip()
    if len(out) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    return out


def _role_timestamp(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{label} must be a Unix timestamp")
    number = float(value)
    if not 0 < number < 10_000_000_000:
        raise ValueError(f"{label} is out of range")
    return number


def get_ai_literacy_config() -> dict[str, bool]:
    try:
        from .config import config_source_errors, load_global_config

        errors = config_source_errors(include_tenant=False)
        root = load_global_config()
    except Exception as exc:
        raise AILiteracyConfigError("AI literacy configuration is unavailable") from exc
    if errors or not isinstance(root, Mapping):
        raise AILiteracyConfigError("AI literacy configuration is unreadable")
    raw = root.get("ai_literacy") or {}
    if not isinstance(raw, Mapping):
        raise AILiteracyConfigError("ai_literacy must be a table")
    unknown = sorted(set(raw) - {"enable"})
    if unknown:
        raise AILiteracyConfigError(f"unknown ai_literacy keys: {', '.join(unknown)}")
    flag = raw.get("enable", False)
    if not isinstance(flag, bool):
        raise AILiteracyConfigError("ai_literacy.enable must be a boolean")
    return {"enable": flag}


def _require_role_api_enabled() -> None:
    if not enabled():
        raise AILiteracyConfigError(
            "AI literacy register requires [ai_literacy] enable = true"
        )


def _role_trainings(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError("trainings must be a list")
    if not value or len(value) > _ROLE_MAX_TRAININGS:
        raise ValueError(f"trainings must contain 1-{_ROLE_MAX_TRAININGS} entries")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise ValueError("each training must be an object")
        unknown = sorted(set(raw) - {"key", "title", "validity_days"})
        if unknown:
            raise ValueError(f"unknown training keys: {', '.join(unknown)}")
        key = _role_token(raw.get("key"), "training key")
        if key in seen:
            raise ValueError("training keys must be unique")
        seen.add(key)
        validity = raw.get("validity_days")
        if validity is not None:
            if isinstance(validity, bool) or not isinstance(validity, int):
                raise ValueError("validity_days must be an integer or omitted")
            if not 1 <= validity <= 3_650:
                raise ValueError("validity_days must be between 1 and 3650")
        out.append(
            {
                "key": key,
                "title": _role_text(raw.get("title"), "training title", 256),
                "validity_days": validity,
            }
        )
    out.sort(key=lambda row: row["key"])
    return out


def set_role_requirement(
    role: str,
    trainings: Sequence[Mapping[str, Any]],
    *,
    actor: str,
    expected_revision: int = 0,
) -> dict[str, Any]:
    """Create or CAS-update the training requirement for one role."""

    _require_role_api_enabled()
    role_role_token = _role_token(role, "role")
    operator = _role_text(actor, "actor", 256)
    normalized = _role_trainings(trainings)
    record_id = f"ALR-{_role_sha256(role_role_token)[:24]}"
    if expected_revision == 0:
        record = {
            "id": record_id,
            "schema": ROLE_REQUIREMENT_SCHEMA,
            "role": role_role_token,
            "trainings": normalized,
            "set_by": operator,
            "notice": NON_CERTIFICATION_NOTICE,
        }
        return dict(_ROLE_REQUIREMENTS.create(
            record, action="set_literacy_requirement", actor=operator,
        ))

    def mutate(value: dict[str, Any]) -> None:
        value["trainings"] = normalized
        value["set_by"] = operator

    saved = _ROLE_REQUIREMENTS.update(
        record_id,
        mutate,
        expected_revision=int(expected_revision),
        action="set_literacy_requirement",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"role requirement is not recorded: {role_role_token}")
    return dict(saved)


def assign_roles(
    person: str,
    roles: Sequence[str],
    *,
    actor: str,
    expected_revision: int = 0,
) -> dict[str, Any]:
    """Create or CAS-update one person's role assignment."""

    _require_role_api_enabled()
    person_role_token = _role_token(person, "person")
    operator = _role_text(actor, "actor", 256)
    if not isinstance(roles, Sequence) or isinstance(roles, (str, bytes)):
        raise ValueError("roles must be a list")
    if not roles or len(roles) > _ROLE_MAX_ROLES:
        raise ValueError(f"roles must contain 1-{_ROLE_MAX_ROLES} entries")
    normalized = sorted({_role_token(role, "role") for role in roles})
    known = {row["role"] for row in _role_requirement_rows()}
    missing = sorted(set(normalized) - known)
    if missing:
        raise ValueError(
            f"roles have no recorded requirement: {', '.join(missing)}"
        )
    record_id = f"ALA-{_role_sha256(person_role_token)[:24]}"
    if expected_revision == 0:
        record = {
            "id": record_id,
            "schema": ROLE_ASSIGNMENT_SCHEMA,
            "person": person_role_token,
            "roles": normalized,
            "assigned_by": operator,
        }
        return dict(_ROLE_ASSIGNMENTS.create(
            record, action="assign_literacy_roles", actor=operator,
        ))

    def mutate(value: dict[str, Any]) -> None:
        value["roles"] = normalized
        value["assigned_by"] = operator

    saved = _ROLE_ASSIGNMENTS.update(
        record_id,
        mutate,
        expected_revision=int(expected_revision),
        action="assign_literacy_roles",
        actor=operator,
    )
    if saved is None:
        raise KeyError(f"assignment is not recorded: {person_role_token}")
    return dict(saved)


def record_completion(
    person: str,
    training: str,
    *,
    completed_at: float,
    evidence_ref: str,
    actor: str,
) -> dict[str, Any]:
    """Record (or refresh) one person's completion of one training."""

    _require_role_api_enabled()
    person_role_token = _role_token(person, "person")
    training_role_token = _role_token(training, "training")
    operator = _role_text(actor, "actor", 256)
    completed = _role_timestamp(completed_at, "completed_at")
    if completed > time.time() + 300:
        raise ValueError("completed_at must not be future-dated")
    reference = _role_text(evidence_ref, "evidence_ref", 512)
    record_id = f"ALC-{_role_sha256([person_role_token, training_role_token])[:24]}"
    current = _ROLE_COMPLETIONS.get(record_id)
    if current is None:
        record = {
            "id": record_id,
            "schema": ROLE_COMPLETION_SCHEMA,
            "person": person_role_token,
            "training": training_role_token,
            "completed_at": completed,
            "evidence_ref": reference,
            "recorded_by": operator,
            "history": [],
        }
        try:
            return dict(_ROLE_COMPLETIONS.create(
                record, action="record_literacy_completion", actor=operator,
            ))
        except RecordConflict:
            current = _ROLE_COMPLETIONS.get(record_id)
            if current is None:
                raise

    def mutate(value: dict[str, Any]) -> None:
        history = list(value.get("history") or [])
        history.append(
            {
                "completed_at": value.get("completed_at"),
                "evidence_ref": value.get("evidence_ref"),
                "recorded_by": value.get("recorded_by"),
            }
        )
        value["history"] = history[-_ROLE_MAX_HISTORY:]
        value["completed_at"] = completed
        value["evidence_ref"] = reference
        value["recorded_by"] = operator

    saved = _ROLE_COMPLETIONS.update(
        record_id,
        mutate,
        expected_revision=int(current.get("revision") or 0),
        action="record_literacy_completion",
        actor=operator,
    )
    if saved is None:
        raise AILiteracyError("completion record disappeared during refresh")
    return dict(saved)


def _role_requirement_rows() -> list[dict[str, Any]]:
    rows = _bounded_rows(_ROLE_REQUIREMENTS, _ROLE_MAX_LIST, "Role requirements")
    rows.sort(key=lambda row: str(row.get("role") or ""))
    return rows


def literacy_gaps(*, now: float | None = None) -> dict[str, Any]:
    """Per person: every required training that is missing or expired."""

    _require_role_api_enabled()
    current = time.time() if now is None else _role_timestamp(now, "now")
    requirements = {row["role"]: row for row in _role_requirement_rows()}
    completions: dict[tuple[str, str], dict[str, Any]] = {}
    for row in _bounded_rows(_ROLE_COMPLETIONS, _ROLE_MAX_LIST * 4, "Training completions"):
        completions[(str(row.get("person")), str(row.get("training")))] = row
    persons: list[dict[str, Any]] = []
    counts = {"current": 0, "expired": 0, "missing": 0}
    assignments = _bounded_rows(_ROLE_ASSIGNMENTS, _ROLE_MAX_LIST * 4, "Role assignments")
    assignments.sort(key=lambda row: str(row.get("person") or ""))
    for assignment in assignments:
        person = str(assignment.get("person") or "")
        required: dict[str, dict[str, Any]] = {}
        for role in assignment.get("roles") or []:
            requirement = requirements.get(str(role))
            if requirement is None:
                continue
            for training in requirement.get("trainings") or []:
                required.setdefault(str(training["key"]), dict(training))
        states: list[dict[str, Any]] = []
        for key in sorted(required):
            training = required[key]
            completion = completions.get((person, key))
            if completion is None:
                status = "missing"
                completed_at = None
                valid_until = None
            else:
                completed_at = float(completion.get("completed_at") or 0.0)
                validity = training.get("validity_days")
                valid_until = (
                    completed_at + float(validity) * _ROLE_DAY
                    if validity is not None
                    else None
                )
                status = (
                    "expired"
                    if valid_until is not None and valid_until <= current
                    else "current"
                )
            counts[status] += 1
            states.append(
                {
                    "training": key,
                    "title": training.get("title"),
                    "status": status,
                    "completed_at": completed_at,
                    "valid_until": valid_until,
                }
            )
        persons.append(
            {
                "person": person,
                "roles": list(assignment.get("roles") or []),
                "trainings": states,
                "gap_count": sum(
                    1 for state in states if state["status"] != "current"
                ),
            }
        )
    return {
        "persons": persons,
        "person_count": len(persons),
        "counts": counts,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
        "generated_at": current,
    }


def export_evidence(*, now: float | None = None) -> str:
    """A bounded JSON snapshot of the whole register for an auditor."""

    _require_role_api_enabled()
    gaps = literacy_gaps(now=now)
    snapshot = {
        "schema": "lightwork.ai-literacy-evidence.v1",
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
        "generated_at": gaps["generated_at"],
        "roles": [
            {
                "role": row.get("role"),
                "trainings": row.get("trainings"),
                "set_by": row.get("set_by"),
                "revision": row.get("revision"),
            }
            for row in _role_requirement_rows()
        ],
        "persons": gaps["persons"],
        "counts": gaps["counts"],
    }
    return json.dumps(snapshot, indent=2, sort_keys=True, default=str)


def list_requirements() -> list[dict[str, Any]]:
    _require_role_api_enabled()
    return [
        {
            "role": row.get("role"),
            "trainings": row.get("trainings"),
            "set_by": row.get("set_by"),
            "revision": row.get("revision"),
        }
        for row in _role_requirement_rows()
    ]


def literacy_plane_status(*, now: float | None = None) -> dict[str, Any]:
    """Report both literacy planes without conflating their evidence strength.

    The role-oriented workspace intentionally accepts less evidence than the
    canonical register.  This facade makes that boundary machine-readable and
    fails closed whenever operational records still require an explicit,
    evidence-enriched migration into the canonical authority.
    """

    _require_role_api_enabled()
    observed_at = time.time() if now is None else _role_timestamp(now, "now")
    canonical_available = True
    try:
        canonical_export = default_register.export_evidence(as_of=observed_at)
        canonical_requirements = default_register.list_requirements(
            include_retired=True,
        )
    except AILiteracyStateError:
        # The canonical plane requires explicit tenant authority.  Compatibility
        # callers may still run without it, but must see a fail-closed status
        # instead of silently treating the role plane as authoritative.
        canonical_available = False
        canonical_export = {"summary": {}}
        canonical_requirements = []
    role_gaps = literacy_gaps(now=observed_at)
    role_requirements = _role_requirement_rows()
    role_assignments = _bounded_rows(_ROLE_ASSIGNMENTS, _ROLE_MAX_LIST * 4, "Role assignments")
    role_completions = _bounded_rows(_ROLE_COMPLETIONS, _ROLE_MAX_LIST * 4, "Training completions")
    canonical_summary = dict(canonical_export.get("summary") or {})
    canonical_present = bool(
        canonical_requirements or int(canonical_summary.get("subjects") or 0)
    )
    role_present = bool(
        role_requirements or role_assignments or role_completions
    )
    return {
        "enabled": True,
        "authoritative_plane": "canonical",
        "canonical": {
            "available": canonical_available,
            "requirement_count": len(canonical_requirements),
            "summary": canonical_summary,
            "records_present": canonical_present,
            "stores_direct_person_identifiers": False,
        },
        "role_compatibility": {
            "requirement_count": len(role_requirements),
            "assignment_count": len(role_assignments),
            "completion_count": len(role_completions),
            "person_count": role_gaps["person_count"],
            "counts": dict(role_gaps["counts"]),
            "records_present": role_present,
            "stores_direct_person_identifiers": True,
            "authoritative_for_compliance": False,
        },
        "mixed_planes": canonical_present and role_present,
        "reconciliation_required": role_present,
        "notice": PLANE_RECONCILIATION_NOTICE,
        "generated_at": observed_at,
    }


__all__ = [
    "AILiteracyConfigError",
    "AILiteracyError",
    "AILiteracyIdempotencyConflict",
    "AILiteracyRegister",
    "AILiteracyStateError",
    "ASSIGNMENT_SCHEMA",
    "COMPLETION_SCHEMA",
    "EVIDENCE_EXPORT_SCHEMA",
    "NON_CERTIFICATION_NOTICE",
    "NON_DETERMINATION_NOTICE",
    "PLANE_RECONCILIATION_NOTICE",
    "REGULATION_METADATA",
    "REQUIREMENT_SCHEMA",
    "ROLE_ASSIGNMENT_SCHEMA",
    "ROLE_COMPLETION_SCHEMA",
    "ROLE_REQUIREMENT_SCHEMA",
    "STATUS_SCHEMA",
    "WAIVER_SCHEMA",
    "assign_roles",
    "default_register",
    "enabled",
    "export_evidence",
    "get_ai_literacy_config",
    "list_requirements",
    "literacy_plane_status",
    "literacy_gaps",
    "record_completion",
    "set_role_requirement",
    "verify_evidence_export",
]
