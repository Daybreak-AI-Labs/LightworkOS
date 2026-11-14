"""Exact, bounded approval cards for externally effecting operations.

The world-model approval table intentionally remains a small generic queue.
Structured cards are therefore stored in its encrypted ``detail`` field as a
versioned envelope.  The card contains only safe labels and commitments: raw
typed values and credentials are hashed in memory and are never persisted.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from collections.abc import Mapping, Sequence
from typing import Any

APPROVAL_CARD_SCHEMA = "lightwork.approval-card.v1"
APPROVAL_DETAIL_PREFIX = "lightwork-approval-card:v1:"
_MAX_ENVELOPE_CHARS = 24_000
_MAX_LABEL_CHARS = 500
_MAX_LIST_ITEMS = 24
# The exact text a reviewer checks (today: a command). It keeps its lines and
# is bounded so the whole envelope stays within the storage limit.
_MAX_DISPLAY_CHARS = 4000
_DISPLAY_FIELDS = frozenset({"command"})
_HEX_DIGITS = frozenset("0123456789abcdef")


class ApprovalCardError(ValueError):
    """A structured approval card is malformed, stale, or expired."""


def _sha256(value: Any, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in _HEX_DIGITS for char in value)
    ):
        raise ApprovalCardError(f"{name} is not a lowercase SHA-256 digest")
    return value


def digest(value: Any) -> str:
    """Return a deterministic commitment to JSON-compatible ``value``."""
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ApprovalCardError("approval input is not canonical JSON") from exc
    return hashlib.sha256(raw).hexdigest()


def _label(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ApprovalCardError(f"{name} must be a string")
    # Drop format and control characters (bidirectional overrides, zero-width
    # spaces): the label a person approves must render as its bytes read.
    text = " ".join("".join(c for c in value if c.isprintable() or c.isspace()).split())
    try:
        from .safety.secret_detector import redact

        text, _matches = redact(text)
    except Exception as exc:
        raise ApprovalCardError("approval label redaction is unavailable") from exc
    if not text and not allow_empty:
        raise ApprovalCardError(f"{name} is required")
    if len(text) > _MAX_LABEL_CHARS:
        raise ApprovalCardError(f"{name} exceeds {_MAX_LABEL_CHARS} characters")
    return text


def _display_text(value: Any, name: str) -> str:
    """Exact text a person reads before deciding, with secrets masked.

    Unlike a label it keeps its lines and spacing (a command must read as it
    will run); other control characters are dropped.
    """
    if not isinstance(value, str):
        raise ApprovalCardError(f"{name} must be a string")
    text = "".join(char for char in value if char in "\n\t" or char.isprintable())
    try:
        from .safety.secret_detector import redact

        text, _matches = redact(text)
    except Exception as exc:
        raise ApprovalCardError("approval display redaction is unavailable") from exc
    if not text.strip():
        raise ApprovalCardError(f"{name} is required")
    if len(text) > _MAX_DISPLAY_CHARS:
        raise ApprovalCardError(f"{name} exceeds {_MAX_DISPLAY_CHARS} characters")
    return text


def _display(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping) or not value or set(value) - _DISPLAY_FIELDS:
        raise ApprovalCardError("approval display fields are invalid")
    return {key: _display_text(value[key], f"display {key}") for key in sorted(value)}


def _safe_mapping(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Copy a card mapping only when its persisted JSON is secret-free."""

    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        from .safety.secret_detector import scan

        if scan(serialized):
            raise ApprovalCardError(f"{name} contains secret-bearing material")
    except ApprovalCardError:
        raise
    except Exception as exc:
        raise ApprovalCardError(f"{name} could not be checked for secrets") from exc
    return dict(value)


def _labels(values: Sequence[str], name: str, *, require_one: bool = False) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ApprovalCardError(f"{name} must be a list")
    if len(values) > _MAX_LIST_ITEMS:
        raise ApprovalCardError(f"{name} exceeds {_MAX_LIST_ITEMS} items")
    result = [_label(value, name) for value in values]
    if require_one and not result:
        raise ApprovalCardError(f"{name} requires at least one item")
    return result


def build_approval_card(
    *,
    action: str,
    summary: str,
    target_label: str,
    target: Any,
    parameters: Any,
    parameter_summary: Sequence[str],
    actor: str,
    workspace: str,
    role: str,
    authority_versions: Mapping[str, Any],
    input_versions: Mapping[str, Any],
    credential_versions: Mapping[str, Any],
    budget: Mapping[str, Any],
    expires_at: float,
    known_effects: Sequence[str],
    unresolved_assumptions: Sequence[str],
    before: str,
    after: str,
    irreversible: bool,
    display_command: str | None = None,
) -> dict[str, Any]:
    """Build an integrity-bound card without retaining raw parameters.

    ``target`` and ``parameters`` may contain sensitive values.  Only their
    SHA-256 commitments are stored; callers supply separate safe labels for the
    person reviewing the action. ``display_command`` is the exact command the
    person is asked to approve (secrets masked); it is bound into the card like
    every other field, and is shown only where the card itself may be read.
    """
    if type(irreversible) is not bool:
        raise ApprovalCardError("irreversible must be a boolean")
    if type(expires_at) not in (int, float) or not math.isfinite(expires_at):
        raise ApprovalCardError("expires_at must be finite")
    for name, value in (
        ("authority_versions", authority_versions),
        ("input_versions", input_versions),
        ("credential_versions", credential_versions),
        ("budget", budget),
    ):
        if not isinstance(value, Mapping):
            raise ApprovalCardError(f"{name} must be an object")
        # Validate serializability and prevent cleartext credentials/capability
        # tokens from entering the durable approval envelope.
        digest(value)
    material: dict[str, Any] = {
        "schema": APPROVAL_CARD_SCHEMA,
        "authorization": {
            "state": "recommendation_only",
            "authority_required": True,
            "prediction_grants_authority": False,
        },
        "action": _label(action, "action"),
        "summary": _label(summary, "summary"),
        "target": {
            "label": _label(target_label, "target_label"),
            "sha256": digest(target),
        },
        "parameters": {
            "sha256": digest(parameters),
            "summary": _labels(parameter_summary, "parameter_summary", require_one=True),
        },
        "authority": {
            "actor": _label(actor, "actor"),
            "workspace": _label(workspace, "workspace"),
            "role": _label(role, "role"),
            "versions": _safe_mapping(authority_versions, "authority_versions"),
        },
        "inputs": _safe_mapping(input_versions, "input_versions"),
        "credentials": _safe_mapping(credential_versions, "credential_versions"),
        "budget": _safe_mapping(budget, "budget"),
        "expires_at": float(expires_at),
        "consequences": {
            "irreversible": irreversible,
            "known_effects": _labels(known_effects, "known_effects", require_one=True),
            "unresolved_assumptions": _labels(
                unresolved_assumptions, "unresolved_assumptions"
            ),
        },
        "preview": {
            "before": _label(before, "before"),
            "after": _label(after, "after"),
        },
    }
    if display_command is not None:
        material["display"] = _display({"command": display_command})
    material["binding_sha256"] = digest(material)
    return material


def validate_approval_card(card: Mapping[str, Any]) -> dict[str, Any]:
    """Return a plain validated card or raise ``ApprovalCardError``."""
    if not isinstance(card, Mapping):
        raise ApprovalCardError("approval card must be an object")
    value = dict(card)
    binding = value.pop("binding_sha256", None)
    if value.get("schema") != APPROVAL_CARD_SCHEMA:
        raise ApprovalCardError("unsupported approval card schema")
    binding = _sha256(binding, "approval card binding")
    if not hmac.compare_digest(binding, digest(value)):
        raise ApprovalCardError("approval card integrity check failed")
    # Rebuild from the public fields to enforce closed types and bounds.  The
    # exact key set is deliberate: silently ignored fields must not appear to be
    # part of what the person approved.
    expected = {
        "schema", "authorization", "action", "summary", "target", "parameters",
        "authority", "inputs", "credentials", "budget", "expires_at",
        "consequences", "preview",
    }
    # ``display`` (the exact command shown to the reviewer) is optional.
    if set(value) - {"display"} != expected:
        raise ApprovalCardError("approval card fields are invalid")
    if "display" in value and _display(value["display"]) != value["display"]:
        raise ApprovalCardError("approval display contains unsafe material")
    authorization = value.get("authorization")
    if authorization != {
        "state": "recommendation_only",
        "authority_required": True,
        "prediction_grants_authority": False,
    }:
        raise ApprovalCardError("approval authorization statement is invalid")
    target = value.get("target")
    parameters = value.get("parameters")
    authority = value.get("authority")
    consequences = value.get("consequences")
    preview = value.get("preview")
    if not all(isinstance(item, Mapping) for item in (
        target, parameters, authority, consequences, preview,
    )):
        raise ApprovalCardError("approval card sections are invalid")
    if set(target) != {"label", "sha256"} or set(parameters) != {"sha256", "summary"}:
        raise ApprovalCardError("approval target or parameters are invalid")
    if set(authority) != {"actor", "workspace", "role", "versions"}:
        raise ApprovalCardError("approval authority fields are invalid")
    if set(consequences) != {"irreversible", "known_effects", "unresolved_assumptions"}:
        raise ApprovalCardError("approval consequence fields are invalid")
    if set(preview) != {"before", "after"}:
        raise ApprovalCardError("approval preview fields are invalid")
    labels = (
        (value.get("action"), "action"),
        (value.get("summary"), "summary"),
        (target.get("label"), "target_label"),
        (authority.get("actor"), "actor"),
        (authority.get("workspace"), "workspace"),
        (authority.get("role"), "role"),
        (preview.get("before"), "before"),
        (preview.get("after"), "after"),
    )
    for label_value, label_name in labels:
        if _label(label_value, label_name) != label_value:
            raise ApprovalCardError(f"approval {label_name} contains unsafe material")
    for label_values, label_name, require_one in (
        (parameters.get("summary"), "parameter_summary", True),
        (consequences.get("known_effects"), "known_effects", True),
        (consequences.get("unresolved_assumptions"), "unresolved_assumptions", False),
    ):
        if _labels(label_values, label_name, require_one=require_one) != label_values:
            raise ApprovalCardError(f"approval {label_name} contains unsafe material")
    _sha256(target.get("sha256"), "approval target commitment")
    _sha256(parameters.get("sha256"), "approval parameter commitment")
    if type(consequences.get("irreversible")) is not bool:
        raise ApprovalCardError("approval irreversible flag is invalid")
    expires_at = value.get("expires_at")
    if type(expires_at) not in (int, float) or not math.isfinite(expires_at):
        raise ApprovalCardError("approval expiry is invalid")
    for section_name, section in (
        ("authority_versions", authority.get("versions")),
        ("input_versions", value.get("inputs")),
        ("credential_versions", value.get("credentials")),
        ("budget", value.get("budget")),
    ):
        if not isinstance(section, Mapping):
            raise ApprovalCardError("approval version section is invalid")
        digest(section)
        _safe_mapping(section, section_name)
    value["binding_sha256"] = binding
    return value


def encode_approval_detail(card: Mapping[str, Any]) -> str:
    """Serialize a validated card for the encrypted approval detail column."""
    value = validate_approval_card(card)
    text = APPROVAL_DETAIL_PREFIX + json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    if len(text) > _MAX_ENVELOPE_CHARS:
        raise ApprovalCardError("approval card exceeds the storage limit")
    return text


def encode_operation_approval_detail(
    *,
    action: str,
    summary: str,
    target_label: str,
    target: Any,
    parameters: Any,
    parameter_summary: Sequence[str],
    actor: str,
    role: str,
    known_effects: Sequence[str],
    unresolved_assumptions: Sequence[str],
    before: str,
    after: str,
    irreversible: bool,
    authority_versions: Mapping[str, Any] | None = None,
    input_versions: Mapping[str, Any] | None = None,
    credential_versions: Mapping[str, Any] | None = None,
    budget: Mapping[str, Any] | None = None,
    ttl_seconds: float = 3600.0,
) -> str:
    """Encode a conservative exact-operation card for a queue producer.

    This is the shared migration boundary for subsystems that historically
    wrote free-form approval details. It resolves the strict workspace and
    stores only commitments to raw targets and parameters.
    """

    try:
        from .paths import current_tenant_id_strict

        workspace = current_tenant_id_strict() or "local"
    except Exception as exc:
        raise ApprovalCardError("approval workspace authority is unavailable") from exc
    if type(ttl_seconds) not in (int, float) or not math.isfinite(ttl_seconds):
        raise ApprovalCardError("approval ttl must be finite")
    ttl = max(60.0, min(float(ttl_seconds), 7 * 24 * 3600.0))
    request = {"target": target, "parameters": parameters}
    card = build_approval_card(
        action=action,
        summary=summary,
        target_label=target_label,
        target=target,
        parameters=parameters,
        parameter_summary=parameter_summary,
        actor=actor or "local:operator",
        workspace=workspace,
        role=role,
        authority_versions=(
            dict(authority_versions)
            if authority_versions is not None
            else {"request_schema": "lightwork.operation-approval.v1"}
        ),
        input_versions=(
            dict(input_versions)
            if input_versions is not None
            else {"request_sha256": digest(request)}
        ),
        credential_versions=(
            dict(credential_versions)
            if credential_versions is not None
            else {"state": "resolved_again_at_execution"}
        ),
        budget=(
            dict(budget)
            if budget is not None
            else {"state": "governed_again_at_execution"}
        ),
        expires_at=time.time() + ttl,
        known_effects=known_effects,
        unresolved_assumptions=unresolved_assumptions,
        before=before,
        after=after,
        irreversible=irreversible,
    )
    return encode_approval_detail(card)


def decode_approval_detail(detail: str | None) -> dict[str, Any] | None:
    """Decode a structured detail; return ``None`` for a legacy plain detail."""
    if not isinstance(detail, str) or not detail.startswith(APPROVAL_DETAIL_PREFIX):
        return None
    if len(detail) > _MAX_ENVELOPE_CHARS:
        raise ApprovalCardError("approval card exceeds the storage limit")
    try:
        value = json.loads(detail[len(APPROVAL_DETAIL_PREFIX):])
    except (TypeError, ValueError) as exc:
        raise ApprovalCardError("approval card encoding is invalid") from exc
    return validate_approval_card(value)


def require_current_approval_card(
    card: Mapping[str, Any],
    *,
    expected_binding: str | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate integrity, caller version and authoritative wall-clock expiry."""
    value = validate_approval_card(card)
    if expected_binding is not None:
        expected = _sha256(expected_binding, "reviewed approval binding")
        if not hmac.compare_digest(value["binding_sha256"], expected):
            raise ApprovalCardError(
                "the approval card changed; review the current operation"
            )
    current = time.time() if now is None else float(now)
    if not math.isfinite(current) or current >= float(value["expires_at"]):
        raise ApprovalCardError("the approval expired; request a fresh review")
    return value


__all__ = [
    "APPROVAL_CARD_SCHEMA",
    "APPROVAL_DETAIL_PREFIX",
    "ApprovalCardError",
    "build_approval_card",
    "decode_approval_detail",
    "digest",
    "encode_approval_detail",
    "encode_operation_approval_detail",
    "require_current_approval_card",
    "validate_approval_card",
]
