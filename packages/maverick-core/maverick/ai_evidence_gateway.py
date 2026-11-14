"""Evidence-ready delivery gateway for governed AI interactions.

The gateway is deliberately opt-in.  When enabled it renders the exact text
that may leave Lightwork, binds those UTF-8 bytes to a tenant-private signed
receipt, and keeps the policy and regulatory authority behind that receipt
reviewable through CAS-governed records.

Receipts contain hashes and governance metadata only.  They never persist the
user input, generated output, or delivered output.  Framework mappings are
evidence aids, not legal advice, certification, conformity assessment, or a
compliance verdict.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .ai_evidence.definitions import (
    ASSURANCE_PACKET_EVENT,
    ASSURANCE_PACKET_SCHEMA,
    CONVERSATION_SCHEMA,
    DEFAULT_DISCLOSURE_TEXT,
    DEFAULT_MACHINE_MARKER,
    DEFAULT_VISIBLE_MARKER,
    FRAMEWORK_SOURCES,
    INTERACTION_EVENT,
    NON_CERTIFICATION_NOTICE,
    POLICY_MODE_SCHEMA,
    POLICY_SCHEMA,
    RECEIPT_SCHEMA,
    REGULATORY_IMPACT_SCHEMA,
    SUMMARY_SCHEMA,
)
from .constant_time import text_equals
from .governed_records import (
    GovernedRecordCapacityError,
    GovernedRecordStore,
)
from .privacy_ops import RecordConflict

_POLICIES = GovernedRecordStore(
    "ai_evidence_policies",
    "AIP",
    "ai_evidence_policy",
)
_RECEIPTS = GovernedRecordStore(
    "ai_evidence_receipts",
    "AIR",
    "ai_interaction_evidence_receipt",
)
_CONVERSATIONS = GovernedRecordStore(
    "ai_evidence_conversations",
    "AIC",
    "ai_evidence_conversation",
)
_IMPACTS = GovernedRecordStore(
    "ai_regulatory_impacts",
    "AII",
    "ai_regulatory_impact",
)
_POLICY_SNAPSHOTS = GovernedRecordStore(
    "ai_evidence_policy_snapshots",
    "AIS",
    "ai_evidence_policy_snapshot",
)
_POLICY_MODES = GovernedRecordStore(
    "ai_evidence_policy_modes",
    "AIM",
    "ai_evidence_policy_mode",
)
_PACKET_REPLAYS = GovernedRecordStore(
    "ai_evidence_packet_replays",
    "AIX",
    "ai_evidence_packet_replay",
)

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})
_DIGEST_RE = re.compile(r"(?:sha256:)?([0-9a-f]{64})\Z")
_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_RECORD_ID_RE = re.compile(r"[A-Z]{3}-[0-9a-f]{32}\Z")
_METADATA_TOKEN_KEYS = frozenset(
    {"owner_id", "asset_id", "environment", "jurisdiction", "version"}
)
_METADATA_BOOLEAN_KEYS = frozenset({"demo", "synthetic", "network_access"})
_METADATA_KEYS = _METADATA_TOKEN_KEYS | _METADATA_BOOLEAN_KEYS | {"tags"}
_PROFILE_SOURCES = {
    "article50_gpai": ("ec_article_50", "ec_gpai_guidelines"),
    "nist_ai_rmf": ("nist_ai_rmf_1_0",),
    "federal_vendor": ("nist_ai_rmf_1_0", "omb_m_25_22"),
    "combined": tuple(FRAMEWORK_SOURCES),
}
_RECEIPT_EVENT_FIELDS = frozenset(
    {
        "schema",
        "event",
        "receipt_id",
        "issued_at",
        "tenant_id",
        "conversation_sha256",
        "sequence",
        "idempotency_sha256",
        "input_sha256",
        "generated_output_sha256",
        "delivered_output_sha256",
        "policy_binding",
        "model_sha256",
        "context_sha256",
        "transparency",
        "parent_receipt_hash",
        "actor_sha256",
        "modality",
        "stores_raw_interaction_content",
        "legal_certification",
        "compliance_verdict",
        "notice",
        "receipt_payload_sha256",
        "prev_hash",
        "key_id",
        "hash",
        "sig",
    }
)
_TRANSPARENCY_FIELDS = frozenset(
    {
        "human_interaction",
        "synthetic_content",
        "deepfake",
        "public_interest_text",
        "interaction_disclosure_required",
        "interaction_disclosure_applied",
        "machine_readable_marking_required",
        "machine_readable_marking_applied",
        "visible_marking_required",
        "visible_marking_applied",
        "editorial_exception",
        "rendering_policy",
    }
)
_IMPACT_DECISIONS = frozenset({"accepted", "dismissed"})
_IMPACT_STATUSES = frozenset(
    {"pending_review", "accepted_refreshing", "accepted", "dismissed"}
)
_MAX_POLICIES = 1_000
# Total signed receipt retention is a controlled fail-closed bound.  Individual
# files and API reads use much smaller bounds; the segmented journal and cursor
# index make the larger tenant lifetime safe to operate.
_MAX_RECEIPTS = 1_000_000
_MAX_PACKETS = 100_000
_MAX_RECEIPT_LIST = 10_000
_DEFAULT_RECEIPT_SEGMENT_ROWS = 4_096
_DEFAULT_RECEIPT_SEGMENT_BYTES = 64 * 1024 * 1024
_DEFAULT_PACKET_SEGMENT_ROWS = 4_096
_DEFAULT_PACKET_SEGMENT_BYTES = 64 * 1024 * 1024
_MAX_IMPACTS = 5_000
_MAX_POLICY_HISTORY = 256
_MAX_CITATIONS = 64
_MAX_AFFECTED = 256
_MAX_JSON_BYTES = 512 * 1024
_MAX_PACKET_POLICIES = 100
_MAX_PACKET_RECEIPTS = 100
_MAX_PACKET_IMPACTS = 100
_MAX_RECEIPT_SNAPSHOT_ATTEMPTS = 3
_DELIVERY_LOCK = threading.RLock()
_POLICY_MUTATION_LOCK = threading.RLock()
_IMPACT_MUTATION_LOCK = threading.RLock()
_PACKET_ISSUE_LOCK = threading.RLock()


class EvidenceGatewayError(RuntimeError):
    """Base error for evidence-gateway state and enforcement failures."""


class EvidenceGatewayDisabled(EvidenceGatewayError):
    """The default-off evidence gateway has not been explicitly enabled."""


class EvidenceGatewayStateError(EvidenceGatewayError):
    """Persisted evidence state cannot satisfy the gateway contract."""


class EvidenceGatewaySnapshotIndeterminate(EvidenceGatewayStateError):
    """A stable assurance snapshot could not be observed after bounded retries."""


class UnsupportedMediaMarking(EvidenceGatewayError):
    """A required output mark cannot be applied to this modality."""


class ConversationOrderError(EvidenceGatewayError):
    """A conversation has an earlier delivery that is not yet committed."""


def _canonical_json(value: object) -> str:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("value must be canonical bounded JSON") from exc
    if len(rendered.encode("utf-8")) > _MAX_JSON_BYTES:
        raise ValueError("value exceeds the evidence gateway JSON limit")
    return rendered


def _sha256(value: object) -> str:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        raw = value.encode("utf-8")
    else:
        raw = _canonical_json(value).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _required_text(value: object, label: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit:
        raise ValueError(f"{label} exceeds {limit} characters")
    if any(ord(char) < 32 and char not in "\n\t" for char in text):
        raise ValueError(f"{label} contains control characters")
    return text


def _token(value: object, label: str) -> str:
    text = _required_text(value, label, 128)
    if not _TOKEN_RE.fullmatch(text):
        raise ValueError(f"{label} is invalid")
    return text


def _digest(value: object, label: str, *, optional: bool = False) -> str:
    text = str(value or "").strip().lower()
    if optional and not text:
        return ""
    match = _DIGEST_RE.fullmatch(text)
    if match is None:
        raise ValueError(f"{label} must be a SHA-256 digest")
    return match.group(1)


def _https_url(value: object, label: str) -> str:
    text = _required_text(value, label, 4096)
    parsed = urlparse(text)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be an official HTTPS URL")
    return text


def _retrieval_timestamp(value: object) -> str:
    text = _required_text(value, "citation retrieved_at", 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        timestamp = parsed.timestamp()
    except (OverflowError, ValueError) as exc:
        raise ValueError(
            "citation retrieved_at must be an ISO-8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or timestamp > time.time() + 300:
        raise ValueError(
            "citation retrieved_at must be timezone-aware and not in the future"
        )
    return text


def _safe_metadata(value: Mapping[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise TypeError("metadata must be a mapping")
    unsupported = set(value) - _METADATA_KEYS
    if unsupported:
        raise ValueError(
            "metadata uses unsupported non-governance fields"
        )
    normalized: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        if key in _METADATA_TOKEN_KEYS:
            normalized[key] = _token(item, f"metadata {key}")
        elif key in _METADATA_BOOLEAN_KEYS:
            if not isinstance(item, bool):
                raise TypeError(f"metadata {key} must be a boolean")
            normalized[key] = item
        elif key == "tags":
            normalized[key] = _tokens(item, "metadata tag")
            if len(normalized[key]) > 64:
                raise ValueError("metadata tags exceeds 64 values")
    _canonical_json(normalized)
    return normalized


def _active_tenant() -> str:
    from .paths import current_tenant_id_strict, data_dir

    tenant_id = current_tenant_id_strict()
    if not tenant_id:
        raise EvidenceGatewayStateError(
            "AI evidence gateway records require an explicit tenant scope"
        )
    tenant = _required_text(tenant_id, "tenant_id", 200)
    data_dir(tenant=tenant)
    return tenant


def _stable_id(prefix: str, *parts: object) -> str:
    return f"{prefix}-{_sha256([str(part) for part in parts])[:32]}"


def _public(record: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in record.items()
        if key != "_audit_pending"
    }


def _list_limit(value: object, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("limit must be an integer")
    if value < 1 or value > maximum:
        raise ValueError(f"limit must be between 1 and {maximum}")
    return value


def _storage_integer(
    *,
    environment: str,
    config_key: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Resolve one advanced receipt-storage limit without a silent fallback."""

    raw: object | None = os.environ.get(environment)
    if raw is None:
        try:
            from .config import load_global_config

            config = load_global_config()
            section = (
                config.get("evidence_gateway")
                if isinstance(config, Mapping)
                else None
            )
            if isinstance(section, Mapping):
                raw = section.get(config_key)
        except Exception as exc:
            raise EvidenceGatewayStateError(
                "AI evidence receipt storage configuration is unavailable"
            ) from exc
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise EvidenceGatewayStateError(
            f"{config_key} must be an integer between {minimum} and {maximum}"
        )
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError) as exc:
        raise EvidenceGatewayStateError(
            f"{config_key} must be an integer between {minimum} and {maximum}"
        ) from exc
    if value < minimum or value > maximum:
        raise EvidenceGatewayStateError(
            f"{config_key} must be an integer between {minimum} and {maximum}"
        )
    return value


def _receipt_segment_rows() -> int:
    return _storage_integer(
        environment="MAVERICK_EVIDENCE_RECEIPT_SEGMENT_ROWS",
        config_key="receipt_segment_rows",
        default=_DEFAULT_RECEIPT_SEGMENT_ROWS,
        minimum=1,
        maximum=1_000_000,
    )


def _receipt_capacity() -> int:
    return _storage_integer(
        environment="MAVERICK_EVIDENCE_RECEIPT_MAX_TOTAL",
        config_key="receipt_max_total",
        default=_MAX_RECEIPTS,
        minimum=1,
        maximum=100_000_000,
    )


def _receipt_segment_bytes() -> int:
    return _storage_integer(
        environment="MAVERICK_EVIDENCE_RECEIPT_SEGMENT_BYTES",
        config_key="receipt_segment_bytes",
        default=_DEFAULT_RECEIPT_SEGMENT_BYTES,
        minimum=1024 * 1024,
        maximum=1024 * 1024 * 1024,
    )


def _packet_segment_rows() -> int:
    return _storage_integer(
        environment="MAVERICK_EVIDENCE_PACKET_SEGMENT_ROWS",
        config_key="packet_segment_rows",
        default=_DEFAULT_PACKET_SEGMENT_ROWS,
        minimum=1,
        maximum=1_000_000,
    )


def _packet_capacity() -> int:
    return _storage_integer(
        environment="MAVERICK_EVIDENCE_PACKET_MAX_TOTAL",
        config_key="packet_max_total",
        default=_MAX_PACKETS,
        minimum=1,
        maximum=100_000_000,
    )


def _packet_segment_bytes() -> int:
    return _storage_integer(
        environment="MAVERICK_EVIDENCE_PACKET_SEGMENT_BYTES",
        config_key="packet_segment_bytes",
        default=_DEFAULT_PACKET_SEGMENT_BYTES,
        minimum=1024 * 1024,
        maximum=1024 * 1024 * 1024,
    )


def enabled() -> bool:
    """Return the explicit, default-off ``[evidence_gateway]`` feature gate."""

    raw = os.environ.get("MAVERICK_EVIDENCE_GATEWAY")
    if raw is not None:
        value = raw.strip().lower()
        if value in _TRUE:
            return True
        if value in _FALSE:
            return False
        return False
    try:
        from .config import config_source_errors, load_global_config

        if config_source_errors(include_tenant=False):
            return False
        config = load_global_config()
        if not isinstance(config, Mapping):
            return False
        section = config.get("evidence_gateway")
        return isinstance(section, Mapping) and section.get("enable") is True
    except Exception:
        return False


def _require_enabled() -> None:
    if not enabled():
        raise EvidenceGatewayDisabled(
            "AI evidence gateway is disabled; set [evidence_gateway] enable = true"
        )


def _settings(
    *,
    disclosure_text: object,
    require_interaction_disclosure: object,
    require_machine_readable_marking: object,
    require_visible_marking: object,
    supported_modalities: Sequence[str],
    machine_marker: object,
    visible_marker: object,
) -> dict[str, Any]:
    for value, label in (
        (require_interaction_disclosure, "require_interaction_disclosure"),
        (require_machine_readable_marking, "require_machine_readable_marking"),
        (require_visible_marking, "require_visible_marking"),
    ):
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be a boolean")
    disclosure = _required_text(disclosure_text, "disclosure_text", 2_000)
    machine = _required_text(machine_marker, "machine_marker", 1_000)
    visible = _required_text(visible_marker, "visible_marker", 1_000)
    if machine.count("{receipt_id}") != 1:
        raise ValueError("machine_marker must contain one {receipt_id} placeholder")
    remainder = machine.replace("{receipt_id}", "")
    if "{" in remainder or "}" in remainder:
        raise ValueError("machine_marker contains an unsupported placeholder")
    if (
        isinstance(supported_modalities, (str, bytes, bytearray))
        or not isinstance(supported_modalities, Sequence)
    ):
        raise TypeError("supported_modalities must be a sequence")
    modalities = sorted({_token(item, "supported modality").lower() for item in supported_modalities})
    if not modalities or len(modalities) > 16:
        raise ValueError("supported_modalities must contain between 1 and 16 values")
    if (
        require_interaction_disclosure
        or require_machine_readable_marking
        or require_visible_marking
    ) and "text" not in modalities:
        raise ValueError("text must be supported when text transparency is required")
    return {
        "disclosure_text": disclosure,
        "require_interaction_disclosure": require_interaction_disclosure,
        "require_machine_readable_marking": require_machine_readable_marking,
        "require_visible_marking": require_visible_marking,
        "supported_modalities": modalities,
        "machine_marker": machine,
        "visible_marker": visible,
    }


def _regulatory_binding(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("regulatory binding must be a mapping")
    return {
        "impact_id": _required_text(value.get("impact_id"), "impact_id", 128),
        "impact_sha256": _digest(
            value.get("impact_sha256"),
            "impact_sha256",
        ),
        "citations_sha256": _digest(
            value.get("citations_sha256"),
            "citations_sha256",
        ),
    }


def _normalize_regulatory_bindings(
    values: Sequence[Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(
        values,
        Sequence,
    ):
        raise TypeError("regulatory_bindings must be a sequence")
    normalized = [_regulatory_binding(value) for value in values]
    if len(normalized) > _MAX_AFFECTED:
        raise ValueError("regulatory_bindings exceeds the collection limit")
    by_id: dict[str, dict[str, Any]] = {}
    for binding in normalized:
        existing = by_id.get(binding["impact_id"])
        if existing is not None and existing != binding:
            raise ValueError("regulatory binding identity is ambiguous")
        by_id[binding["impact_id"]] = binding
    return [by_id[key] for key in sorted(by_id)]


def _snapshot_content(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "policy_id": snapshot["policy_id"],
        "settings": snapshot["settings"],
        "model_sha256": snapshot["model_sha256"],
        "context_sha256": snapshot["context_sha256"],
        "regulatory_bindings": snapshot["regulatory_bindings"],
        "framework_sources": snapshot["framework_sources"],
        "metadata": snapshot["metadata"],
        "legal_certification": False,
        "compliance_verdict": "not_provided",
        "notice": NON_CERTIFICATION_NOTICE,
    }


def _build_snapshot(
    *,
    policy_id: str,
    actor: str,
    record_revision: int,
    settings: Mapping[str, Any],
    model_sha256: str,
    context_sha256: str,
    regulatory_bindings: Sequence[Mapping[str, Any]],
    metadata: Mapping[str, Any],
    effective_at: float,
) -> dict[str, Any]:
    snapshot: dict[str, Any] = {
        "schema": POLICY_SCHEMA,
        "policy_id": policy_id,
        "record_revision": record_revision,
        "effective_at": effective_at,
        "authored_by": actor,
        "settings": dict(settings),
        "model_sha256": model_sha256,
        "context_sha256": context_sha256,
        "regulatory_bindings": [dict(item) for item in regulatory_bindings],
        "framework_sources": {
            key: dict(value) for key, value in FRAMEWORK_SOURCES.items()
        },
        "metadata": dict(metadata),
        "legal_certification": False,
        "compliance_verdict": "not_provided",
        "notice": NON_CERTIFICATION_NOTICE,
    }
    snapshot["policy_sha256"] = _sha256(_snapshot_content(snapshot))
    return snapshot


def _validated_snapshot(
    value: object,
    *,
    expected_record_revision: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise EvidenceGatewayStateError("AI evidence policy snapshot is invalid")
    try:
        snapshot = dict(value)
        if snapshot.get("schema") != POLICY_SCHEMA:
            raise ValueError("schema")
        policy_id = _token(snapshot.get("policy_id"), "policy_id")
        revision = snapshot.get("record_revision")
        if (
            isinstance(revision, bool)
            or not isinstance(revision, int)
            or revision < 1
            or (
                expected_record_revision is not None
                and revision != expected_record_revision
            )
        ):
            raise ValueError("record_revision")
        effective_at = snapshot.get("effective_at")
        if isinstance(effective_at, bool):
            raise ValueError("effective_at")
        timestamp = float(effective_at)
        if not math.isfinite(timestamp) or timestamp <= 0:
            raise ValueError("effective_at")
        _required_text(snapshot.get("authored_by"), "authored_by", 256)
        settings_value = snapshot.get("settings")
        if not isinstance(settings_value, Mapping):
            raise ValueError("settings")
        normalized_settings = _settings(
            disclosure_text=settings_value.get("disclosure_text"),
            require_interaction_disclosure=settings_value.get(
                "require_interaction_disclosure"
            ),
            require_machine_readable_marking=settings_value.get(
                "require_machine_readable_marking"
            ),
            require_visible_marking=settings_value.get(
                "require_visible_marking"
            ),
            supported_modalities=settings_value.get("supported_modalities"),
            machine_marker=settings_value.get("machine_marker"),
            visible_marker=settings_value.get("visible_marker"),
        )
        if dict(settings_value) != normalized_settings:
            raise ValueError("settings")
        model_digest = _digest(
            snapshot.get("model_sha256"),
            "model_sha256",
            optional=True,
        )
        context_digest = _digest(
            snapshot.get("context_sha256"),
            "context_sha256",
            optional=True,
        )
        bindings_value = snapshot.get("regulatory_bindings")
        normalized_bindings = _normalize_regulatory_bindings(bindings_value)
        if bindings_value != normalized_bindings:
            raise ValueError("regulatory_bindings")
        framework_sources = snapshot.get("framework_sources")
        if framework_sources != FRAMEWORK_SOURCES:
            raise ValueError("framework_sources")
        metadata = _safe_metadata(snapshot.get("metadata"))
        if snapshot.get("metadata") != metadata:
            raise ValueError("metadata")
        if (
            snapshot.get("legal_certification") is not False
            or snapshot.get("compliance_verdict") != "not_provided"
            or snapshot.get("notice") != NON_CERTIFICATION_NOTICE
        ):
            raise ValueError("non_certification")
        normalized = {
            **snapshot,
            "policy_id": policy_id,
            "settings": normalized_settings,
            "model_sha256": model_digest,
            "context_sha256": context_digest,
            "regulatory_bindings": normalized_bindings,
            "metadata": metadata,
        }
        claimed = _digest(
            snapshot.get("policy_sha256"),
            "policy_sha256",
        )
        if not hmac.compare_digest(
            claimed,
            _sha256(_snapshot_content(normalized)),
        ):
            raise ValueError("policy_sha256")
        normalized["policy_sha256"] = claimed
        return normalized
    except (
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise EvidenceGatewayStateError(
            "AI evidence policy snapshot failed integrity validation"
        ) from exc


def _policy_view(record: Mapping[str, Any]) -> dict[str, Any]:
    current = record.get("current")
    revision = record.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
        raise EvidenceGatewayStateError("AI evidence policy revision is invalid")
    current_snapshot = _validated_snapshot(
        current,
        expected_record_revision=revision,
    )
    if (
        record.get("schema") != POLICY_SCHEMA
        or record.get("policy_id") != current_snapshot["policy_id"]
        or record.get("id")
        != _stable_id("AIP", current_snapshot["policy_id"])
        or record.get("status") != "active"
    ):
        raise EvidenceGatewayStateError("AI evidence policy identity is invalid")
    history = record.get("history")
    if not isinstance(history, list) or len(history) > _MAX_POLICY_HISTORY:
        raise EvidenceGatewayStateError("AI evidence policy history is invalid")
    seen: set[str] = {current_snapshot["policy_sha256"]}
    prior_revision = 0
    for item in history:
        historical = _validated_snapshot(item)
        if (
            historical["policy_id"] != current_snapshot["policy_id"]
            or historical["record_revision"] <= prior_revision
            or historical["record_revision"] >= revision
            or historical["policy_sha256"] in seen
        ):
            raise EvidenceGatewayStateError(
                "AI evidence policy history is not monotonic"
            )
        prior_revision = historical["record_revision"]
        seen.add(historical["policy_sha256"])
    return {
        "id": record["id"],
        "schema": POLICY_SCHEMA,
        "status": record.get("status", "active"),
        "revision": revision,
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
        **current_snapshot,
        "snapshot_count": len(history) + 1,
    }


def _policy_record(policy_id: str) -> dict[str, Any] | None:
    token = _token(policy_id, "policy_id")
    return _POLICIES.get(_stable_id("AIP", token))


def _policy_transaction_target() -> Path:
    from .paths import data_dir

    _active_tenant()
    return data_dir("ai_evidence_gateway", "policy-mutations.transaction")


def _impact_transaction_target() -> Path:
    from .paths import data_dir

    _active_tenant()
    return data_dir(
        "ai_evidence_gateway",
        "regulatory-impact-mutations.transaction",
    )


def _claim_policy_tenant_mode(
    *,
    synthetic: bool,
    actor: str,
) -> None:
    """Permanently separate synthetic-demo and production policy authorities."""

    tenant = _active_tenant()
    requested = "synthetic" if synthetic else "production"
    record_id = _stable_id("AIM", "tenant-policy-mode")

    def validated_mode(record: Mapping[str, Any]) -> str:
        mode = record.get("mode")
        if (
            record.get("id") != record_id
            or record.get("schema") != POLICY_MODE_SCHEMA
            or record.get("status") != "active"
            or record.get("tenant_id") != tenant
            or mode not in {"production", "synthetic"}
        ):
            raise EvidenceGatewayStateError(
                "AI evidence policy tenant mode failed validation"
            )
        return str(mode)

    existing = _POLICY_MODES.get(record_id)
    if existing is None:
        # Upgrade an existing tenant conservatively. A historically mixed
        # namespace is refused; otherwise the current policy set determines
        # the permanent mode before a new mutation can proceed.
        legacy_rows = _POLICIES.list(limit=_MAX_POLICIES + 1)
        if len(legacy_rows) > _MAX_POLICIES:
            raise EvidenceGatewayStateError(
                "AI evidence policy namespace is oversized"
            )
        legacy_modes = {
            (
                "synthetic"
                if (
                    isinstance(policy.get("metadata"), Mapping)
                    and (
                        policy["metadata"].get("demo") is True
                        or policy["metadata"].get("synthetic") is True
                    )
                )
                else "production"
            )
            for policy in (_policy_view(row) for row in legacy_rows)
        }
        if len(legacy_modes) > 1:
            raise EvidenceGatewayStateError(
                "AI evidence policy tenant already mixes synthetic and "
                "production authority; provision separate tenants"
            )
        inherited = next(iter(legacy_modes), requested)
        try:
            existing = _POLICY_MODES.create(
                {
                    "id": record_id,
                    "schema": POLICY_MODE_SCHEMA,
                    "status": "active",
                    "tenant_id": tenant,
                    "mode": inherited,
                },
                action="policy_tenant_mode_claimed",
                actor=actor,
            )
        except RecordConflict:
            existing = _POLICY_MODES.get(record_id)
            if existing is None:
                raise EvidenceGatewayStateError(
                    "AI evidence policy tenant mode could not be recovered"
                ) from None
    actual = validated_mode(existing)
    if actual != requested:
        raise EvidenceGatewayStateError(
            "synthetic demo and production AI evidence policies require "
            "separate tenant namespaces"
        )


def _archive_policy_snapshot(
    snapshot: Mapping[str, Any],
    *,
    actor: str,
) -> None:
    """Move one immutable policy snapshot out of the bounded hot document."""

    validated = _validated_snapshot(snapshot)
    policy_id = str(validated["policy_id"])
    policy_sha = str(validated["policy_sha256"])
    record_id = _stable_id("AIS", policy_id, policy_sha)
    body = {
        "id": record_id,
        "schema": "lightwork.ai-evidence-policy-snapshot-archive.v1",
        "status": "archived",
        "policy_id": policy_id,
        "policy_sha256": policy_sha,
        "snapshot": validated,
    }
    existing = _POLICY_SNAPSHOTS.get(record_id)
    if existing is not None:
        if (
            existing.get("schema") != body["schema"]
            or existing.get("status") != "archived"
            or existing.get("policy_id") != policy_id
            or existing.get("policy_sha256") != policy_sha
            or not text_equals(
                _canonical_json(existing.get("snapshot")),
                _canonical_json(validated),
            )
        ):
            raise EvidenceGatewayStateError(
                "archived AI evidence policy snapshot diverges from authority"
            )
        return
    try:
        _POLICY_SNAPSHOTS.create(
            body,
            action="policy_snapshot_archived",
            actor=actor,
        )
    except RecordConflict:
        # Another process may have archived the same immutable snapshot first.
        recovered = _POLICY_SNAPSHOTS.get(record_id)
        if (
            recovered is None
            or recovered.get("policy_sha256") != policy_sha
            or not text_equals(
                _canonical_json(recovered.get("snapshot")),
                _canonical_json(validated),
            )
        ):
            raise EvidenceGatewayStateError(
                "archived AI evidence policy snapshot could not be recovered"
            ) from None


def upsert_policy(
    policy_id: str = "default",
    *,
    actor: str,
    expected_revision: int | None = None,
    disclosure_text: str = DEFAULT_DISCLOSURE_TEXT,
    require_interaction_disclosure: bool = True,
    require_machine_readable_marking: bool = True,
    require_visible_marking: bool = False,
    supported_modalities: Sequence[str] = ("text",),
    machine_marker: str = DEFAULT_MACHINE_MARKER,
    visible_marker: str = DEFAULT_VISIBLE_MARKER,
    model_sha256: str = "",
    context_sha256: str = "",
    regulatory_bindings: Sequence[Mapping[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create or CAS-update an immutable-in-history policy snapshot."""

    from .file_lock import cross_process_lock

    with _POLICY_MUTATION_LOCK:
        with cross_process_lock(_policy_transaction_target(), strict=True):
            return _upsert_policy_locked(
                policy_id,
                actor=actor,
                expected_revision=expected_revision,
                disclosure_text=disclosure_text,
                require_interaction_disclosure=(
                    require_interaction_disclosure
                ),
                require_machine_readable_marking=(
                    require_machine_readable_marking
                ),
                require_visible_marking=require_visible_marking,
                supported_modalities=supported_modalities,
                machine_marker=machine_marker,
                visible_marker=visible_marker,
                model_sha256=model_sha256,
                context_sha256=context_sha256,
                regulatory_bindings=regulatory_bindings,
                metadata=metadata,
            )


def _upsert_policy_locked(
    policy_id: str = "default",
    *,
    actor: str,
    expected_revision: int | None = None,
    disclosure_text: str = DEFAULT_DISCLOSURE_TEXT,
    require_interaction_disclosure: bool = True,
    require_machine_readable_marking: bool = True,
    require_visible_marking: bool = False,
    supported_modalities: Sequence[str] = ("text",),
    machine_marker: str = DEFAULT_MACHINE_MARKER,
    visible_marker: str = DEFAULT_VISIBLE_MARKER,
    model_sha256: str = "",
    context_sha256: str = "",
    regulatory_bindings: Sequence[Mapping[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Policy mutation after tenant-wide serialization has been acquired."""

    _require_enabled()
    _active_tenant()
    token = _token(policy_id, "policy_id")
    operator = _required_text(actor, "actor", 256)
    settings = _settings(
        disclosure_text=disclosure_text,
        require_interaction_disclosure=require_interaction_disclosure,
        require_machine_readable_marking=require_machine_readable_marking,
        require_visible_marking=require_visible_marking,
        supported_modalities=supported_modalities,
        machine_marker=machine_marker,
        visible_marker=visible_marker,
    )
    model_digest = _digest(model_sha256, "model_sha256", optional=True)
    context_digest = _digest(context_sha256, "context_sha256", optional=True)
    safe_metadata = _safe_metadata(metadata)
    synthetic_mode = (
        safe_metadata.get("demo") is True
        or safe_metadata.get("synthetic") is True
    )
    record_id = _stable_id("AIP", token)
    existing = _POLICIES.get(record_id)
    # Regulatory bindings are written only by the cited, human-reviewed
    # impact state machine.  A caller may echo the current value for backward
    # compatibility, but neither a direct Python caller nor an HTTP caller may
    # add, replace, or erase those bindings through an ordinary policy update.
    governed_bindings = (
        []
        if existing is None
        else list(_policy_view(existing)["regulatory_bindings"])
    )
    if regulatory_bindings is not None:
        requested_bindings = _normalize_regulatory_bindings(
            regulatory_bindings
        )
        if requested_bindings != governed_bindings:
            raise EvidenceGatewayStateError(
                "regulatory bindings may only be changed by an accepted "
                "regulatory impact"
            )
    bindings = governed_bindings
    # GovernedRecordStore creates a new logical document at revision 1.
    next_revision = 1 if existing is None else int(existing["revision"]) + 1
    snapshot = _build_snapshot(
        policy_id=token,
        actor=operator,
        record_revision=next_revision,
        settings=settings,
        model_sha256=model_digest,
        context_sha256=context_digest,
        regulatory_bindings=bindings,
        metadata=safe_metadata,
        effective_at=time.time(),
    )
    if existing is None:
        if expected_revision not in (None, 0):
            raise RecordConflict("AI evidence policy does not exist at that revision")
        if len(_POLICIES.list(limit=_MAX_POLICIES)) >= _MAX_POLICIES:
            raise EvidenceGatewayStateError(
                "AI evidence policy capacity has been reached; archive or "
                "provision a new governed tenant namespace before creating "
                "another policy"
            )
        # Claim only after every deterministic rejection above. A malformed or
        # stale request must not permanently choose this tenant's posture.
        _claim_policy_tenant_mode(
            synthetic=synthetic_mode,
            actor=operator,
        )
        try:
            created = _POLICIES.create(
                {
                    "id": record_id,
                    "schema": POLICY_SCHEMA,
                    "policy_id": token,
                    "status": "active",
                    "current": snapshot,
                    "history": [],
                },
                action="policy_created",
                actor=operator,
                max_records=_MAX_POLICIES,
            )
        except GovernedRecordCapacityError as exc:
            raise EvidenceGatewayStateError(
                "AI evidence policy capacity has been reached; archive or "
                "provision a new governed tenant namespace before creating "
                "another policy"
            ) from exc
        return _policy_view(created)
    current = existing.get("current")
    if not isinstance(current, Mapping):
        raise EvidenceGatewayStateError("AI evidence policy is malformed")
    # An existing valid policy is itself durable evidence of tenant posture, so
    # a recovered legacy mode claim cannot strand an otherwise empty tenant.
    _claim_policy_tenant_mode(
        synthetic=synthetic_mode,
        actor=operator,
    )
    if hmac.compare_digest(
        str(current.get("policy_sha256") or ""),
        snapshot["policy_sha256"],
    ):
        return _policy_view(existing)
    if expected_revision is None:
        raise RecordConflict(
            "expected_revision is required to replace an AI evidence policy"
        )
    if expected_revision != existing["revision"]:
        raise RecordConflict("AI evidence policy changed since it was reviewed")
    history = existing.get("history")
    if not isinstance(history, list):
        raise EvidenceGatewayStateError(
            "AI evidence policy snapshot history is malformed"
        )
    if len(history) >= _MAX_POLICY_HISTORY:
        _archive_policy_snapshot(history[0], actor=operator)

    def mutate(row: dict[str, Any]) -> None:
        row_history = row.get("history")
        row_current = row.get("current")
        if not isinstance(row_history, list) or not isinstance(row_current, dict):
            raise EvidenceGatewayStateError("AI evidence policy is malformed")
        if len(row_history) >= _MAX_POLICY_HISTORY:
            row_history.pop(0)
        row_history.append(dict(row_current))
        row["current"] = snapshot
        row["status"] = "active"

    updated = _POLICIES.update(
        record_id,
        mutate,
        expected_revision=expected_revision,
        action="policy_snapshot_published",
        actor=operator,
    )
    if updated is None:
        raise EvidenceGatewayStateError("AI evidence policy disappeared")
    return _policy_view(updated)


def get_policy(policy_id: str = "default") -> dict[str, Any] | None:
    """Return the current policy snapshot for the active tenant."""

    _require_enabled()
    _active_tenant()
    record = _policy_record(policy_id)
    return None if record is None else _policy_view(record)


def list_policies() -> list[dict[str, Any]]:
    """List current policy snapshots for the active tenant."""

    _require_enabled()
    _active_tenant()
    rows = _POLICIES.list(limit=_MAX_POLICIES + 1)
    if len(rows) > _MAX_POLICIES:
        raise EvidenceGatewayStateError("AI evidence policy namespace is oversized")
    return sorted(
        (_policy_view(row) for row in rows),
        key=lambda row: str(row["policy_id"]),
    )


def _snapshot_for_binding(
    record: Mapping[str, Any],
    policy_sha256: str,
) -> dict[str, Any] | None:
    current = record.get("current")
    candidates: list[Mapping[str, Any]] = []
    if isinstance(current, Mapping):
        candidates.append(current)
    history = record.get("history")
    if isinstance(history, list):
        candidates.extend(item for item in history if isinstance(item, Mapping))
    for snapshot in candidates:
        validated = _validated_snapshot(snapshot)
        claimed = str(validated.get("policy_sha256") or "")
        if hmac.compare_digest(claimed, policy_sha256):
            return validated
    policy_id = record.get("policy_id")
    if isinstance(policy_id, str):
        archived = _POLICY_SNAPSHOTS.get(
            _stable_id("AIS", policy_id, policy_sha256)
        )
        if archived is not None:
            snapshot = archived.get("snapshot")
            validated = _validated_snapshot(snapshot)
            if (
                archived.get("schema")
                != "lightwork.ai-evidence-policy-snapshot-archive.v1"
                or archived.get("status") != "archived"
                or archived.get("policy_id") != policy_id
                or archived.get("policy_sha256") != policy_sha256
                or validated.get("policy_id") != policy_id
                or not hmac.compare_digest(
                    str(validated.get("policy_sha256") or ""),
                    policy_sha256,
                )
            ):
                raise EvidenceGatewayStateError(
                    "archived AI evidence policy snapshot failed integrity "
                    "validation"
                )
            return validated
    return None


def _reserved_issued_at(pending: Mapping[str, Any]) -> float:
    value = pending.get("issued_at")
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) <= 0
    ):
        raise EvidenceGatewayStateError(
            "conversation reservation timestamp is invalid"
        )
    return float(value)


def _conversation_reservation(
    conversation_sha256: str,
    receipt_id: str,
    idempotency_sha256: str,
    *,
    interaction_disclosure_required: bool,
    human_interaction: bool,
    actor: str,
) -> tuple[int, str, bool, float]:
    record_id = _stable_id("AIC", conversation_sha256)
    for _attempt in range(16):
        current = _CONVERSATIONS.get(record_id)
        if current is None:
            disclosure_due = interaction_disclosure_required
            issued_at = time.time()
            try:
                created = _CONVERSATIONS.create(
                    {
                        "id": record_id,
                        "schema": CONVERSATION_SCHEMA,
                        "conversation_sha256": conversation_sha256,
                        "next_sequence": 2,
                        "last_receipt_id": "",
                        "last_receipt_hash": "",
                        "human_disclosure_completed": False,
                        "pending": {
                            "receipt_id": receipt_id,
                            "idempotency_sha256": idempotency_sha256,
                            "sequence": 1,
                            "parent_receipt_hash": "",
                            "interaction_disclosure_required": (
                                interaction_disclosure_required
                            ),
                            "interaction_disclosure_due": disclosure_due,
                            "human_interaction": human_interaction,
                            "issued_at": issued_at,
                        },
                    },
                    action="delivery_reserved",
                    actor=actor,
                )
            except RecordConflict:
                continue
            pending = created["pending"]
            return (
                int(pending["sequence"]),
                str(pending["parent_receipt_hash"]),
                bool(pending["interaction_disclosure_due"]),
                _reserved_issued_at(pending),
            )
        completed = current.get("human_disclosure_completed", False)
        if not isinstance(completed, bool):
            raise EvidenceGatewayStateError(
                "conversation disclosure state is invalid"
            )
        pending = current.get("pending")
        if isinstance(pending, Mapping):
            if (
                pending.get("receipt_id") == receipt_id
                and pending.get("idempotency_sha256") == idempotency_sha256
            ):
                if (
                    pending.get("interaction_disclosure_required")
                    is not interaction_disclosure_required
                    or pending.get("human_interaction")
                    is not human_interaction
                    or not isinstance(
                        pending.get("interaction_disclosure_due"),
                        bool,
                    )
                ):
                    raise EvidenceGatewayStateError(
                        "idempotency key was reused with different "
                        "interaction disclosure requirements"
                    )
                return (
                    int(pending["sequence"]),
                    str(pending.get("parent_receipt_hash") or ""),
                    bool(pending["interaction_disclosure_due"]),
                    _reserved_issued_at(pending),
                )
            raise ConversationOrderError(
                "an earlier delivery in this conversation is not committed"
            )
        sequence = current.get("next_sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise EvidenceGatewayStateError("conversation sequence is invalid")
        parent_hash = str(current.get("last_receipt_hash") or "")
        # V1 has no independently attested presentation event. A caller could
        # otherwise discard an earlier response while claiming it was the
        # human-facing turn, consuming the disclosure before a user sees it.
        # Apply the disclosure at every delivery boundary.
        disclosure_due = interaction_disclosure_required
        issued_at = time.time()

        def mutate(
            row: dict[str, Any],
            reserved_sequence: int = sequence,
            reserved_parent_hash: str = parent_hash,
            reserved_disclosure_due: bool = disclosure_due,
            reserved_issued_at: float = issued_at,
        ) -> None:
            if row.get("pending") is not None:
                raise RecordConflict("conversation delivery was reserved concurrently")
            row_completed = row.get("human_disclosure_completed", False)
            if not isinstance(row_completed, bool):
                raise EvidenceGatewayStateError(
                    "conversation disclosure state is invalid"
                )
            expected_due = interaction_disclosure_required
            if expected_due is not reserved_disclosure_due:
                raise RecordConflict(
                    "conversation disclosure state changed concurrently"
                )
            row["pending"] = {
                "receipt_id": receipt_id,
                "idempotency_sha256": idempotency_sha256,
                "sequence": reserved_sequence,
                "parent_receipt_hash": reserved_parent_hash,
                "interaction_disclosure_required": (
                    interaction_disclosure_required
                ),
                "interaction_disclosure_due": reserved_disclosure_due,
                "human_interaction": human_interaction,
                "issued_at": reserved_issued_at,
            }
            row["next_sequence"] = reserved_sequence + 1

        try:
            _CONVERSATIONS.update(
                record_id,
                mutate,
                expected_revision=int(current["revision"]),
                action="delivery_reserved",
                actor=actor,
            )
        except RecordConflict:
            continue
        return sequence, parent_hash, disclosure_due, issued_at
    raise EvidenceGatewayStateError("conversation reservation contention exceeded")


def _complete_conversation(
    conversation_sha256: str,
    receipt_id: str,
    receipt_hash: str,
    *,
    interaction_disclosure_applied: bool,
    actor: str,
) -> None:
    record_id = _stable_id("AIC", conversation_sha256)
    for _attempt in range(16):
        current = _CONVERSATIONS.get(record_id)
        if current is None:
            raise EvidenceGatewayStateError("conversation reservation disappeared")
        pending = current.get("pending")
        if pending is None:
            # A committed receipt remains replayable after later turns advance
            # the conversation.  The receipt's own signed sequence and parent
            # hash are the authority; never rewind the live conversation head.
            return
        if not isinstance(pending, Mapping) or pending.get("receipt_id") != receipt_id:
            # Likewise, a later in-flight delivery must not make an older,
            # already-issued receipt non-idempotent.
            return

        def mutate(row: dict[str, Any]) -> None:
            row_pending = row.get("pending")
            if (
                not isinstance(row_pending, Mapping)
                or row_pending.get("receipt_id") != receipt_id
            ):
                raise RecordConflict("conversation reservation changed")
            disclosure_due = row_pending.get(
                "interaction_disclosure_due"
            )
            if (
                not isinstance(disclosure_due, bool)
                or disclosure_due is not interaction_disclosure_applied
            ):
                raise EvidenceGatewayStateError(
                    "conversation disclosure completion does not match "
                    "the reserved delivery"
                )
            completed = row.get("human_disclosure_completed", False)
            if not isinstance(completed, bool):
                raise EvidenceGatewayStateError(
                    "conversation disclosure state is invalid"
                )
            row["pending"] = None
            row["last_receipt_id"] = receipt_id
            row["last_receipt_hash"] = receipt_hash
            row["human_disclosure_completed"] = bool(
                completed
                or (
                    interaction_disclosure_applied
                    and row_pending.get("human_interaction") is True
                )
            )

        try:
            updated = _CONVERSATIONS.update(
                record_id,
                mutate,
                expected_revision=int(current["revision"]),
                action="delivery_committed",
                actor=actor,
            )
        except RecordConflict:
            continue
        if updated is None:
            raise EvidenceGatewayStateError("conversation reservation disappeared")
        return
    raise EvidenceGatewayStateError("conversation completion contention exceeded")


def _abandon_conversation_reservation(
    conversation_sha256: str,
    receipt_id: str,
    *,
    actor: str,
) -> None:
    """Release a reservation whose delivery failed before it could be
    committed.

    ``_conversation_reservation`` reserves the conversation, and only
    ``_complete_conversation`` ever clears ``pending`` -- if rendering or
    signing raises after the reservation (signer refusal, segment/capacity
    error, disk full), nothing released it, so every later ``deliver_text``
    for this conversation with a *different* idempotency key raised
    ``ConversationOrderError`` forever (the only recovery was resending the
    exact same key, which real clients rarely do).

    Only clears a reservation that still belongs to ``receipt_id`` -- a
    compare-and-swap, matching ``_complete_conversation``'s own pattern --
    and only after confirming no signed row for ``receipt_id`` actually
    landed in the ledger. If the write partially succeeded (e.g. the ledger
    append landed but a later bookkeeping step failed), that sequence number
    is legitimately spent and must not be handed to a different receipt on a
    later attempt, so this is a no-op in that case: fail toward leaving the
    conversation reservation in place (the pre-existing, if inconvenient,
    behavior) rather than risk a sequence collision. Likewise a no-op (never
    raises) if the ledger can't be consulted, or the reservation no longer
    matches (already completed, or already abandoned by a concurrent
    caller).
    """
    try:
        rows = _signed_rows(_receipt_path(), "receipt_id", receipt_id)
    except Exception:
        return
    if rows:
        return
    record_id = _stable_id("AIC", conversation_sha256)
    for _attempt in range(16):
        current = _CONVERSATIONS.get(record_id)
        if current is None:
            return
        pending = current.get("pending")
        if not isinstance(pending, Mapping) or pending.get("receipt_id") != receipt_id:
            return
        reserved_sequence = pending.get("sequence")

        def mutate(row: dict[str, Any], reserved_sequence: Any = reserved_sequence) -> None:
            row_pending = row.get("pending")
            if (
                not isinstance(row_pending, Mapping)
                or row_pending.get("receipt_id") != receipt_id
            ):
                raise RecordConflict("conversation reservation changed")
            row["pending"] = None
            # Give the sequence number back so the next successful attempt
            # reuses it and the chain stays gapless (_conversation_chains_valid
            # requires exactly 1, 2, 3, ... with no skips). Only when this
            # reservation is still the one that consumed it -- a concurrent
            # successful delivery already advancing next_sequence further
            # must not be rewound.
            if (
                isinstance(reserved_sequence, int)
                and not isinstance(reserved_sequence, bool)
                and row.get("next_sequence") == reserved_sequence + 1
            ):
                row["next_sequence"] = reserved_sequence

        try:
            _CONVERSATIONS.update(
                record_id,
                mutate,
                expected_revision=int(current["revision"]),
                action="delivery_abandoned",
                actor=actor,
            )
        except RecordConflict:
            continue
        return


def _editorial_exception(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if value is None:
        return None
    # V1 has no independent, admin-approved governed exception authority.
    # Accepting a structurally plausible dict from the delivery caller would
    # let that caller suppress Article-50-style visible marking.  Keep the
    # parameter for a future governed-decision citation, but fail closed until
    # such a decision store is wired.
    raise EvidenceGatewayStateError(
        "editorial exceptions require a governed approved authority record; "
        "inline exceptions are not accepted"
    )


def _render_text(
    generated_text: str,
    *,
    receipt_id: str,
    settings: Mapping[str, Any],
    human_interaction: bool,
    apply_interaction_disclosure: bool,
    synthetic_content: bool,
    deepfake: bool,
    public_interest_text: bool,
    editorial_exception: Mapping[str, Any] | None,
) -> tuple[str, dict[str, Any]]:
    """Compatibility seam for deterministic, policy-checked rendering."""
    from .ai_evidence.rendering import render_text

    return render_text(
        generated_text, receipt_id=receipt_id, settings=settings,
        human_interaction=human_interaction,
        apply_interaction_disclosure=apply_interaction_disclosure,
        synthetic_content=synthetic_content, deepfake=deepfake,
        public_interest_text=public_interest_text, editorial_exception=editorial_exception,
        state_error=EvidenceGatewayStateError,
    )


def _receipt_path() -> Path:
    from .paths import data_dir

    _active_tenant()
    return data_dir("ai_evidence_gateway", "interaction_receipts.ndjson")


def _receipt_ledger(*, max_receipts: int | None = None):
    """Return the tenant-bound segmented receipt authority.

    The object is intentionally cheap and stateless.  Its authenticated state
    and SQLite index live beside the legacy ledger, so independent workers
    converge under the same cross-process transaction lock.
    """

    from .ai_evidence_ledger import SegmentedReceiptLedger

    tenant = _active_tenant()
    return SegmentedReceiptLedger(
        _receipt_path(),
        tenant_id=tenant,
        segment_rows=_receipt_segment_rows(),
        segment_bytes=_receipt_segment_bytes(),
        max_receipts=(
            _receipt_capacity()
            if max_receipts is None
            else max_receipts
        ),
    )


def _packet_path() -> Path:
    from .paths import data_dir

    _active_tenant()
    return data_dir("ai_evidence_gateway", "assurance_packets.ndjson")


def _packet_ledger(*, max_packets: int | None = None):
    """Return the tenant-bound segmented assurance-packet authority."""

    from .ai_evidence_ledger import SegmentedReceiptLedger

    tenant = _active_tenant()
    return SegmentedReceiptLedger(
        _packet_path(),
        tenant_id=tenant,
        identity_key="packet_id",
        payload_key="packet_sha256",
        segment_rows=_packet_segment_rows(),
        segment_bytes=_packet_segment_bytes(),
        max_receipts=(
            _packet_capacity()
            if max_packets is None
            else max_packets
        ),
    )


def _signed_ledger_rows(path: Path) -> list[dict[str, Any]]:
    if path == _receipt_path():
        try:
            return _receipt_ledger().rows()
        except Exception as exc:
            from .ai_evidence_ledger import SegmentedLedgerError

            if isinstance(exc, SegmentedLedgerError):
                raise EvidenceGatewayStateError(str(exc)) from exc
            raise
    if path == _packet_path():
        try:
            return _packet_ledger().rows()
        except Exception as exc:
            from .ai_evidence_ledger import SegmentedLedgerError

            if isinstance(exc, SegmentedLedgerError):
                raise EvidenceGatewayStateError(str(exc)) from exc
            raise
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []
    except (OSError, UnicodeError) as exc:
        raise EvidenceGatewayStateError("signed evidence ledger is unreadable") from exc
    rows: list[dict[str, Any]] = []
    for raw in raw_lines:
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise EvidenceGatewayStateError(
                "signed evidence ledger contains malformed JSON"
            ) from exc
        if not isinstance(row, dict):
            raise EvidenceGatewayStateError(
                "signed evidence ledger contains a non-object row"
            )
        rows.append(row)
    return rows


def _signed_rows(path: Path, identity_key: str, identity: str) -> list[dict[str, Any]]:
    if path == _receipt_path() and identity_key == "receipt_id":
        try:
            row = _receipt_ledger().find(identity)
        except Exception as exc:
            from .ai_evidence_ledger import SegmentedLedgerError

            if isinstance(exc, SegmentedLedgerError):
                raise EvidenceGatewayStateError(str(exc)) from exc
            raise
        return [] if row is None else [row]
    if path == _packet_path() and identity_key == "packet_id":
        try:
            row = _packet_ledger().find(identity)
        except Exception as exc:
            from .ai_evidence_ledger import SegmentedLedgerError

            if isinstance(exc, SegmentedLedgerError):
                raise EvidenceGatewayStateError(str(exc)) from exc
            raise
        return [] if row is None else [row]
    return [
        row
        for row in _signed_ledger_rows(path)
        if row.get(identity_key) == identity
    ]


def _identity_transaction_target(path: Path) -> Path:
    return path.with_name(f"{path.name}.identity-transaction")


def _assert_receipt_admission_capacity(receipt_id: str) -> None:
    """Reject a new identity before reserving conversation state at the cap."""

    try:
        ledger = _receipt_ledger()
        existing = ledger.find(receipt_id)
        state = ledger.state()
    except Exception as exc:
        from .ai_evidence_ledger import SegmentedLedgerError

        if isinstance(exc, SegmentedLedgerError):
            raise EvidenceGatewayStateError(str(exc)) from exc
        raise
    if existing is None and state.total_receipts >= ledger.max_receipts:
        raise EvidenceGatewayStateError(
            "AI evidence receipt capacity has been reached; delivery is "
            "withheld until the configured tenant evidence capacity is "
            "increased or a new governed namespace is provisioned"
        )


def _sign_event(
    event: Mapping[str, Any],
    *,
    path: Path,
    identity_key: str,
    identity: str,
    max_rows: int | None = None,
) -> tuple[dict[str, Any], str]:
    segmented_ledger = None
    if path == _receipt_path() and identity_key == "receipt_id":
        segmented_ledger = _receipt_ledger(max_receipts=max_rows)
    elif path == _packet_path() and identity_key == "packet_id":
        segmented_ledger = _packet_ledger(max_packets=max_rows)
    if segmented_ledger is not None:
        try:
            return segmented_ledger.append(
                event,
                identity=identity,
            )
        except Exception as exc:
            from .ai_evidence_ledger import SegmentedLedgerError

            if isinstance(exc, SegmentedLedgerError):
                raise EvidenceGatewayStateError(str(exc)) from exc
            raise
    from .audit.signing import AuditSigner
    from .file_lock import cross_process_lock

    # AuditSigner serializes chain appends, but the identity existence check is
    # a separate operation.  Hold a sibling transaction lock across the whole
    # check/write/recover sequence so two workers cannot append the same
    # receipt_id or packet_id as distinct, individually valid chain rows.
    with cross_process_lock(_identity_transaction_target(path), strict=True):
        rows = _signed_ledger_rows(path)
        existing = [
            row for row in rows if row.get(identity_key) == identity
        ]
        if len(existing) > 1:
            raise EvidenceGatewayStateError("signed evidence identity is duplicated")
        if existing:
            row = existing[0]
            for key, value in event.items():
                if row.get(key) != value:
                    raise EvidenceGatewayStateError(
                        "signed evidence identity was reused with different content"
                    )
            key_id = row.get("key_id")
            trust = trusted_public_keys()
            public_key = trust.get(str(key_id or ""))
            if not isinstance(public_key, str):
                raise EvidenceGatewayStateError(
                    "signed evidence key is absent from the protected trust registry"
                )
            return row, public_key
        if max_rows is not None:
            if (
                isinstance(max_rows, bool)
                or not isinstance(max_rows, int)
                or max_rows < 1
            ):
                raise ValueError("signed evidence row limit must be positive")
            if len(rows) >= max_rows:
                raise EvidenceGatewayStateError(
                    "AI evidence receipt capacity has been reached; "
                    "delivery was withheld before signing"
                )
        signer = AuditSigner(path)
        if not signer.write(dict(event)):
            raise EvidenceGatewayStateError("audit signer refused evidence")
        recovered = _signed_rows(path, identity_key, identity)
        if len(recovered) != 1:
            raise EvidenceGatewayStateError("signed evidence could not be recovered")
        return recovered[0], signer.public_key_hex


def _receipt_event(
    *,
    tenant_id: str,
    receipt_id: str,
    issued_at: float,
    conversation_sha256: str,
    sequence: int,
    idempotency_sha256: str,
    input_sha256: str,
    generated_output_sha256: str,
    delivered_output_sha256: str,
    policy: Mapping[str, Any],
    model_sha256: str,
    context_sha256: str,
    transparency: Mapping[str, Any],
    parent_receipt_hash: str,
    actor_sha256: str,
    modality: str,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "schema": RECEIPT_SCHEMA,
        "event": INTERACTION_EVENT,
        "receipt_id": receipt_id,
        "issued_at": issued_at,
        "tenant_id": tenant_id,
        "conversation_sha256": conversation_sha256,
        "sequence": sequence,
        "idempotency_sha256": idempotency_sha256,
        "input_sha256": input_sha256,
        "generated_output_sha256": generated_output_sha256,
        "delivered_output_sha256": delivered_output_sha256,
        "policy_binding": {
            "record_id": policy["id"],
            "record_revision": policy["record_revision"],
            "policy_id": policy["policy_id"],
            "policy_sha256": policy["policy_sha256"],
        },
        "model_sha256": model_sha256,
        "context_sha256": context_sha256,
        "transparency": dict(transparency),
        "parent_receipt_hash": parent_receipt_hash,
        "actor_sha256": actor_sha256,
        "modality": modality,
        "stores_raw_interaction_content": False,
        "legal_certification": False,
        "compliance_verdict": "not_provided",
        "notice": NON_CERTIFICATION_NOTICE,
    }
    event["receipt_payload_sha256"] = _sha256(event)
    return event


def _receipt_view(record: Mapping[str, Any]) -> dict[str, Any]:
    signed = record.get("signed_receipt")
    if not isinstance(signed, Mapping):
        raise EvidenceGatewayStateError("interaction receipt has no signed evidence")
    binding = signed.get("policy_binding")
    reasons: list[str] = []
    if not isinstance(binding, Mapping):
        reasons.append("invalid_policy_binding")
        current_policy = None
    else:
        current_policy = _POLICIES.get(str(binding.get("record_id") or ""))
        if current_policy is None:
            reasons.append("missing_policy")
        else:
            current = current_policy.get("current")
            if not isinstance(current, Mapping):
                reasons.append("invalid_current_policy")
            else:
                if int(current_policy["revision"]) != int(
                    binding.get("record_revision", -1)
                ):
                    reasons.append("stale_policy_revision")
                if not hmac.compare_digest(
                    str(current.get("policy_sha256") or ""),
                    str(binding.get("policy_sha256") or ""),
                ):
                    reasons.append("stale_policy_digest")
                current_model = str(current.get("model_sha256") or "")
                if current_model and not hmac.compare_digest(
                    current_model,
                    str(signed.get("model_sha256") or ""),
                ):
                    reasons.append("stale_model")
                current_context = str(current.get("context_sha256") or "")
                if current_context and not hmac.compare_digest(
                    current_context,
                    str(signed.get("context_sha256") or ""),
                ):
                    reasons.append("stale_context")
    result = _public(record)
    binding = signed.get("policy_binding")
    result.update(
        {
            "policy_id": (
                str(binding.get("policy_id") or "")
                if isinstance(binding, Mapping)
                else ""
            ),
            "model_sha256": str(signed.get("model_sha256") or ""),
            "context_sha256": str(signed.get("context_sha256") or ""),
            "conversation_sha256": str(
                signed.get("conversation_sha256") or ""
            ),
            "modality": str(signed.get("modality") or ""),
            "issued_at": signed.get("issued_at"),
            "sequence": signed.get("sequence"),
        }
    )
    result["assurance"] = {
        "status": "stale" if reasons else "current",
        "reasons": sorted(set(reasons)),
    }
    return result


def _validate_retry(
    record: Mapping[str, Any],
    *,
    input_sha256: str,
    generated_sha256: str,
    idempotency_sha256: str,
    conversation_sha256: str,
    policy_id: str,
    model_sha256: str,
    context_sha256: str,
    modality: str,
    actor_sha256: str,
    human_interaction: bool,
    synthetic_content: bool,
    deepfake: bool,
    public_interest_text: bool,
    editorial_exception: Mapping[str, Any] | None,
) -> Mapping[str, Any]:
    signed = record.get("signed_receipt")
    if not isinstance(signed, Mapping):
        raise EvidenceGatewayStateError("interaction receipt is not issued")
    expected = {
        "input_sha256": input_sha256,
        "generated_output_sha256": generated_sha256,
        "idempotency_sha256": idempotency_sha256,
        "conversation_sha256": conversation_sha256,
    }
    for key, value in expected.items():
        if not hmac.compare_digest(str(signed.get(key) or ""), value):
            raise EvidenceGatewayStateError(
                "idempotency key was reused with different interaction content"
            )
    binding = signed.get("policy_binding")
    transparency = signed.get("transparency")
    if not isinstance(binding, Mapping) or not isinstance(transparency, Mapping):
        raise EvidenceGatewayStateError("interaction receipt binding is invalid")
    exact_values = {
        "policy_id": (binding.get("policy_id"), policy_id),
        "model_sha256": (signed.get("model_sha256"), model_sha256),
        "context_sha256": (signed.get("context_sha256"), context_sha256),
        "modality": (signed.get("modality"), modality),
        "actor_sha256": (signed.get("actor_sha256"), actor_sha256),
        "human_interaction": (
            transparency.get("human_interaction"),
            human_interaction,
        ),
        "synthetic_content": (
            transparency.get("synthetic_content"),
            synthetic_content,
        ),
        "deepfake": (transparency.get("deepfake"), deepfake),
        "public_interest_text": (
            transparency.get("public_interest_text"),
            public_interest_text,
        ),
        "editorial_exception": (
            transparency.get("editorial_exception"),
            editorial_exception,
        ),
    }
    for label, (prior, retried) in exact_values.items():
        if prior != retried:
            raise EvidenceGatewayStateError(
                f"idempotency key was reused with different {label}"
            )
    return signed


def _reproduce_delivery(
    record: Mapping[str, Any],
    generated_text: str,
    *,
    tenant_id: str,
    input_sha256: str,
    generated_sha256: str,
    idempotency_sha256: str,
    conversation_sha256: str,
    policy_id: str,
    model_sha256: str,
    context_sha256: str,
    modality: str,
    actor_sha256: str,
    human_interaction: bool,
    synthetic_content: bool,
    deepfake: bool,
    public_interest_text: bool,
    editorial_exception: Mapping[str, Any] | None,
) -> tuple[Mapping[str, Any], str]:
    signed = _validate_retry(
        record,
        input_sha256=input_sha256,
        generated_sha256=generated_sha256,
        idempotency_sha256=idempotency_sha256,
        conversation_sha256=conversation_sha256,
        policy_id=policy_id,
        model_sha256=model_sha256,
        context_sha256=context_sha256,
        modality=modality,
        actor_sha256=actor_sha256,
        human_interaction=human_interaction,
        synthetic_content=synthetic_content,
        deepfake=deepfake,
        public_interest_text=public_interest_text,
        editorial_exception=editorial_exception,
    )
    if not verify_interaction_receipt(
        signed,
        trusted_public_keys=trusted_public_keys(),
        expected_tenant_id=tenant_id,
    ):
        raise EvidenceGatewayStateError(
            "stored interaction receipt failed signature verification"
        )
    binding = signed.get("policy_binding")
    if not isinstance(binding, Mapping):
        raise EvidenceGatewayStateError("receipt policy binding is invalid")
    policy_record = _POLICIES.get(str(binding.get("record_id") or ""))
    if policy_record is None:
        raise EvidenceGatewayStateError(
            "receipt policy snapshot is unavailable for retry"
        )
    snapshot = _snapshot_for_binding(
        policy_record,
        str(binding.get("policy_sha256") or ""),
    )
    if snapshot is None:
        raise EvidenceGatewayStateError(
            "receipt policy snapshot is unavailable for retry"
        )
    delivered, decision = _render_text(
        generated_text,
        receipt_id=str(signed.get("receipt_id") or ""),
        settings=snapshot["settings"],
        human_interaction=bool(signed["transparency"]["human_interaction"]),
        apply_interaction_disclosure=bool(
            signed["transparency"]["interaction_disclosure_applied"]
        ),
        synthetic_content=bool(signed["transparency"]["synthetic_content"]),
        deepfake=bool(signed["transparency"]["deepfake"]),
        public_interest_text=bool(
            signed["transparency"]["public_interest_text"]
        ),
        editorial_exception=signed["transparency"].get("editorial_exception"),
    )
    if decision != signed["transparency"] or not hmac.compare_digest(
        _sha256(delivered.encode("utf-8")),
        str(signed.get("delivered_output_sha256") or ""),
    ):
        raise EvidenceGatewayStateError(
            "idempotent retry cannot reproduce the delivered bytes"
        )
    return signed, delivered


def _ensure_default_policy(policy_id: str, *, actor: str) -> None:
    """Provision the tenant's ``default`` policy from the module defaults.

    The orchestrator delivers every human-facing goal output under the
    ``default`` policy.  Without one, every goal of a tenant would be withheld
    with "policy 'default' does not exist" until an operator created it by hand
    through the assurance API, which a per-user isolation tenant or a
    session-selected workspace cannot reach with the static dashboard token.
    So the gateway creates revision 1 itself, from
    the same defaults the API applies (disclosure text, machine marker,
    text-only), so the first delivery is receipted and disclosed rather than
    blocked.  The creation is an ordinary audited ``policy_created`` mutation;
    operators review and revise it exactly as a hand-made policy.  Only the
    ``default`` id is provisioned: an explicit policy id must still exist.

    Runs before the delivery transaction so the policy lock is never taken
    inside the delivery lock.  A concurrent creator is harmless: the upsert
    re-reads the record under the policy lock and returns the existing
    revision when its snapshot is identical.
    """

    if _token(policy_id, "policy_id") != "default":
        return
    if _policy_record("default") is not None:
        return
    upsert_policy("default", actor=actor)


def deliver_text(
    generated_text: str,
    *,
    input_text: str,
    conversation_id: str,
    idempotency_key: str,
    actor: str = "gateway",
    policy_id: str = "default",
    model_sha256: str = "",
    context_sha256: str = "",
    modality: str = "text",
    human_interaction: bool = True,
    synthetic_content: bool = True,
    deepfake: bool = False,
    public_interest_text: bool = False,
    editorial_exception: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Atomically render, receipt, and govern one human-facing AI output.

    The tenant identity transaction spans the signed ledger append, governed
    receipt persistence, and conversation advancement.  Assurance readers use
    the same lock only to capture short start/end state tokens, never while
    scanning historical evidence.
    """

    _require_enabled()
    from .file_lock import cross_process_lock

    receipt_path = _receipt_path()
    _ensure_default_policy(policy_id, actor=actor)
    # Windows mandatory file locks reject a second thread in the same process
    # with EDEADLK instead of waiting.  Serialize local contenders before
    # acquiring the cross-process transaction; the inner use is an RLock and
    # remains re-entrant for the existing linear delivery implementation.
    with _DELIVERY_LOCK:
        with cross_process_lock(
            _identity_transaction_target(receipt_path),
            strict=True,
        ):
            return _deliver_text_locked(
                generated_text,
                input_text=input_text,
                conversation_id=conversation_id,
                idempotency_key=idempotency_key,
                actor=actor,
                policy_id=policy_id,
                model_sha256=model_sha256,
                context_sha256=context_sha256,
                modality=modality,
                human_interaction=human_interaction,
                synthetic_content=synthetic_content,
                deepfake=deepfake,
                public_interest_text=public_interest_text,
                editorial_exception=editorial_exception,
            )


def _validate_delivery_flags(
    *,
    human_interaction: bool,
    synthetic_content: bool,
    deepfake: bool,
    public_interest_text: bool,
) -> None:
    for value, label in (
        (human_interaction, "human_interaction"),
        (synthetic_content, "synthetic_content"),
        (deepfake, "deepfake"),
        (public_interest_text, "public_interest_text"),
    ):
        if not isinstance(value, bool):
            raise ValueError(f"{label} must be a boolean")
    if synthetic_content is not True:
        raise EvidenceGatewayStateError(
            "deliver_text accepts AI-generated content only; "
            "synthetic_content cannot be disabled by the delivery caller"
        )
    if human_interaction is not True:
        raise EvidenceGatewayStateError(
            "deliver_text is the human-facing delivery boundary; "
            "human_interaction cannot be disabled by the delivery caller"
        )


def _validated_delivery_policy(
    policy_token: str,
    *,
    modality_token: str,
    deepfake: bool,
    public_interest_text: bool,
    model_digest: str,
    context_digest: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    policy_record = _policy_record(policy_token)
    if policy_record is None:
        raise EvidenceGatewayStateError(
            f"AI evidence policy {policy_token!r} does not exist"
        )
    policy = _policy_view(policy_record)
    settings = policy["settings"]
    if modality_token not in settings["supported_modalities"]:
        marking_required = bool(
            settings["require_machine_readable_marking"]
            or settings["require_visible_marking"]
            or deepfake
            or public_interest_text
        )
        if marking_required:
            raise UnsupportedMediaMarking(
                f"required {modality_token} marking is not implemented; "
                "delivery withheld"
            )
        raise ValueError(f"modality {modality_token!r} is not supported")
    if modality_token != "text":
        raise UnsupportedMediaMarking(
            f"{modality_token} delivery is not implemented by deliver_text"
        )
    policy_model = str(policy.get("model_sha256") or "")
    if policy_model and not hmac.compare_digest(policy_model, model_digest):
        raise EvidenceGatewayStateError(
            "model digest does not match the current evidence policy"
        )
    policy_context = str(policy.get("context_sha256") or "")
    if policy_context and not hmac.compare_digest(
        policy_context,
        context_digest,
    ):
        raise EvidenceGatewayStateError(
            "context digest does not match the current evidence policy"
        )
    return policy, settings


def _deliver_text_locked(
    generated_text: str,
    *,
    input_text: str,
    conversation_id: str,
    idempotency_key: str,
    actor: str = "gateway",
    policy_id: str = "default",
    model_sha256: str = "",
    context_sha256: str = "",
    modality: str = "text",
    human_interaction: bool = True,
    synthetic_content: bool = True,
    deepfake: bool = False,
    public_interest_text: bool = False,
    editorial_exception: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Render and receipt exact text without persisting interaction content."""

    _require_enabled()
    tenant_id = _active_tenant()
    if not isinstance(generated_text, str) or not isinstance(input_text, str):
        raise TypeError("input_text and generated_text must be strings")
    if len(input_text.encode("utf-8")) > 16 * 1024 * 1024:
        raise ValueError("input_text exceeds the gateway input limit")
    if len(generated_text.encode("utf-8")) > 16 * 1024 * 1024:
        raise ValueError("generated_text exceeds the gateway output limit")
    conversation = _required_text(conversation_id, "conversation_id", 1_024)
    idempotency = _required_text(idempotency_key, "idempotency_key", 1_024)
    operator = _required_text(actor, "actor", 256)
    policy_token = _token(policy_id, "policy_id")
    modality_token = _token(modality, "modality").lower()
    _validate_delivery_flags(
        human_interaction=human_interaction,
        synthetic_content=synthetic_content,
        deepfake=deepfake,
        public_interest_text=public_interest_text,
    )
    exception = _editorial_exception(editorial_exception)
    input_sha = _sha256(input_text.encode("utf-8"))
    generated_sha = _sha256(generated_text.encode("utf-8"))
    conversation_sha = _sha256(conversation.encode("utf-8"))
    idempotency_sha = _sha256(idempotency.encode("utf-8"))
    receipt_id = _stable_id("AIR", tenant_id, conversation_sha, idempotency_sha)
    actor_sha = _sha256(operator.encode("utf-8"))
    model_digest = _digest(model_sha256, "model_sha256", optional=True)
    context_digest = _digest(context_sha256, "context_sha256", optional=True)
    receipt_record_id = receipt_id
    reproduction_context = {
        "tenant_id": tenant_id,
        "input_sha256": input_sha,
        "generated_sha256": generated_sha,
        "idempotency_sha256": idempotency_sha,
        "conversation_sha256": conversation_sha,
        "policy_id": policy_token,
        "model_sha256": model_digest,
        "context_sha256": context_digest,
        "modality": modality_token,
        "actor_sha256": actor_sha,
        "human_interaction": human_interaction,
        "synthetic_content": synthetic_content,
        "deepfake": deepfake,
        "public_interest_text": public_interest_text,
        "editorial_exception": exception,
    }

    with _DELIVERY_LOCK:
        existing = _RECEIPTS.get(receipt_record_id)
        if existing is not None and existing.get("status") == "issued":
            signed, delivered = _reproduce_delivery(
                existing,
                generated_text,
                **reproduction_context,
            )
            _complete_conversation(
                conversation_sha,
                receipt_id,
                str(signed["hash"]),
                interaction_disclosure_applied=bool(
                    signed["transparency"][
                        "interaction_disclosure_applied"
                    ]
                ),
                actor=operator,
            )
            return {
                "enabled": True,
                "delivered_text": delivered,
                "receipt": _receipt_view(existing),
                "idempotent_replay": True,
            }

        if existing is None:
            receipt_path = _receipt_path()
            recovered_rows = _signed_rows(
                receipt_path,
                "receipt_id",
                receipt_id,
            )
            if len(recovered_rows) > 1:
                raise EvidenceGatewayStateError(
                    "signed evidence identity is duplicated"
                )
            if recovered_rows:
                recovered_record = {
                    "id": receipt_record_id,
                    "schema": RECEIPT_SCHEMA,
                    "status": "issued",
                    "receipt_id": receipt_id,
                    "signed_receipt": recovered_rows[0],
                }
                signed, delivered = _reproduce_delivery(
                    recovered_record,
                    generated_text,
                    **reproduction_context,
                )
                try:
                    saved = _RECEIPTS.create(
                        recovered_record,
                        action="interaction_receipt_recovered",
                        actor=operator,
                    )
                except RecordConflict:
                    saved = _RECEIPTS.get(receipt_record_id)
                    if saved is None or saved.get("status") != "issued":
                        raise EvidenceGatewayStateError(
                            "authoritative interaction receipt is unavailable "
                            "after ledger recovery"
                        ) from None
                    signed, delivered = _reproduce_delivery(
                        saved,
                        generated_text,
                        **reproduction_context,
                    )
                _complete_conversation(
                    conversation_sha,
                    receipt_id,
                    str(signed["hash"]),
                    interaction_disclosure_applied=bool(
                        signed["transparency"][
                            "interaction_disclosure_applied"
                        ]
                    ),
                    actor=operator,
                )
                return {
                    "enabled": True,
                    "delivered_text": delivered,
                    "receipt": _receipt_view(saved),
                    "idempotent_replay": True,
                }

        _assert_receipt_admission_capacity(receipt_id)
        policy, settings = _validated_delivery_policy(
            policy_token,
            modality_token=modality_token,
            deepfake=deepfake,
            public_interest_text=public_interest_text,
            model_digest=model_digest,
            context_digest=context_digest,
        )
        interaction_disclosure_required = bool(
            settings["require_interaction_disclosure"]
        )
        sequence, parent_hash, disclosure_due, issued_at = (
            _conversation_reservation(
                conversation_sha,
                receipt_id,
                idempotency_sha,
                interaction_disclosure_required=(
                    interaction_disclosure_required
                ),
                human_interaction=human_interaction,
                actor=operator,
            )
        )
        # Render/sign/receipt-commit can fail after the reservation
        # above (signer refusal, segment/capacity error, disk full) --
        # _complete_conversation below is the only thing that ever clears
        # it, so an unhandled exception here would poison every later delivery
        # in this conversation forever (a fresh idempotency key hits
        # ConversationOrderError permanently; only resending the exact same
        # key recovers). Abandon this receipt_id's reservation on any
        # failure so the conversation is not permanently stuck; the
        # abandon helper itself refuses to clear it if a signed row for
        # receipt_id actually made it into the ledger (a partial success
        # must not have its sequence number handed to a different receipt).
        try:
            delivered, decision = _render_text(
                generated_text,
                receipt_id=receipt_id,
                settings=settings,
                human_interaction=human_interaction,
                apply_interaction_disclosure=disclosure_due,
                synthetic_content=synthetic_content,
                deepfake=deepfake,
                public_interest_text=public_interest_text,
                editorial_exception=exception,
            )
            event = _receipt_event(
                tenant_id=tenant_id,
                receipt_id=receipt_id,
                issued_at=issued_at,
                conversation_sha256=conversation_sha,
                sequence=sequence,
                idempotency_sha256=idempotency_sha,
                input_sha256=input_sha,
                generated_output_sha256=generated_sha,
                delivered_output_sha256=_sha256(delivered.encode("utf-8")),
                policy=policy,
                model_sha256=model_digest,
                context_sha256=context_digest,
                transparency=decision,
                parent_receipt_hash=parent_hash,
                actor_sha256=actor_sha,
                modality=modality_token,
            )
            signed, _public_key = _sign_event(
                event,
                path=_receipt_path(),
                identity_key="receipt_id",
                identity=receipt_id,
            )
            if existing is None:
                try:
                    saved = _RECEIPTS.create(
                        {
                            "id": receipt_record_id,
                            "schema": RECEIPT_SCHEMA,
                            "status": "issued",
                            "receipt_id": receipt_id,
                            "signed_receipt": signed,
                        },
                        action="interaction_receipt_issued",
                        actor=operator,
                    )
                except RecordConflict:
                    saved = _RECEIPTS.get(receipt_record_id)
                    if saved is None or saved.get("status") != "issued":
                        raise EvidenceGatewayStateError(
                            "authoritative interaction receipt is unavailable "
                            "after a concurrent issue"
                        ) from None
                    return _deliver_text_locked(
                        generated_text,
                        input_text=input_text,
                        conversation_id=conversation,
                        idempotency_key=idempotency,
                        actor=operator,
                        policy_id=policy_token,
                        model_sha256=model_digest,
                        context_sha256=context_digest,
                        modality=modality_token,
                        human_interaction=human_interaction,
                        synthetic_content=synthetic_content,
                        deepfake=deepfake,
                        public_interest_text=public_interest_text,
                        editorial_exception=exception,
                    )
            else:
                if existing.get("status") != "pending":
                    raise EvidenceGatewayStateError(
                        "interaction receipt state is invalid"
                    )

                def issue(row: dict[str, Any]) -> None:
                    row["status"] = "issued"
                    row["signed_receipt"] = signed

                try:
                    saved = _RECEIPTS.update(
                        receipt_record_id,
                        issue,
                        expected_revision=int(existing["revision"]),
                        action="interaction_receipt_issued",
                        actor=operator,
                    )
                except RecordConflict:
                    saved = _RECEIPTS.get(receipt_record_id)
                    if saved is None or saved.get("status") != "issued":
                        raise EvidenceGatewayStateError(
                            "authoritative interaction receipt is unavailable "
                            "after a concurrent issue"
                        ) from None
                    return _deliver_text_locked(
                        generated_text,
                        input_text=input_text,
                        conversation_id=conversation,
                        idempotency_key=idempotency,
                        actor=operator,
                        policy_id=policy_token,
                        model_sha256=model_digest,
                        context_sha256=context_digest,
                        modality=modality_token,
                        human_interaction=human_interaction,
                        synthetic_content=synthetic_content,
                        deepfake=deepfake,
                        public_interest_text=public_interest_text,
                        editorial_exception=exception,
                    )
                if saved is None:
                    raise EvidenceGatewayStateError("interaction receipt disappeared")
            _complete_conversation(
                conversation_sha,
                receipt_id,
                str(signed["hash"]),
                interaction_disclosure_applied=bool(
                    signed["transparency"]["interaction_disclosure_applied"]
                ),
                actor=operator,
            )
        except Exception:
            _abandon_conversation_reservation(
                conversation_sha, receipt_id, actor=operator,
            )
            raise
        return {
            "enabled": True,
            "delivered_text": delivered,
            "receipt": _receipt_view(saved),
            "idempotent_replay": False,
        }


def list_interaction_receipts_page(
    *,
    limit: int = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Return one stable cursor page of hash-only receipts, newest first."""

    _require_enabled()
    tenant = _active_tenant()
    bounded = _list_limit(limit, _MAX_RECEIPT_LIST)
    trust = trusted_public_keys()
    rows: list[dict[str, Any]] = []
    missing_governed = 0
    try:
        ledger = _receipt_ledger()
        page = ledger.page(limit=bounded, cursor=cursor)
        for entry in page.entries:
            record = _RECEIPTS.get(entry.identity)
            if record is None or record.get("status") != "issued":
                # A signer append deliberately precedes governed-store commit.
                # Expose the incomplete window without hiding it; delivery
                # retry can recover the authoritative record from this row.
                missing_governed += 1
                continue
            signed = record.get("signed_receipt")
            if (
                not isinstance(signed, Mapping)
                or signed.get("hash") != entry.row_hash
                or signed.get("receipt_payload_sha256")
                != entry.payload_sha256
            ):
                raise EvidenceGatewayStateError(
                    "governed receipt record diverges from its signed ledger row"
                )
            view = _receipt_view(record)
            view["ledger_ordinal"] = entry.ordinal
            view["signature_valid"] = verify_interaction_receipt(
                view,
                trusted_public_keys=trust,
                expected_tenant_id=tenant,
            )
            rows.append(view)
    except EvidenceGatewayStateError:
        raise
    except Exception as exc:
        from .ai_evidence_ledger import SegmentedLedgerError

        if isinstance(exc, SegmentedLedgerError):
            raise EvidenceGatewayStateError(str(exc)) from exc
        raise
    return {
        "items": rows,
        "next_cursor": page.next_cursor,
        "snapshot_total": page.snapshot_total,
        "count": len(rows),
        "missing_governed_count": missing_governed,
    }


def list_interaction_receipts(*, limit: int = 100) -> list[dict[str, Any]]:
    """List one bounded first page of hash-only receipts, newest first."""

    return list_interaction_receipts_page(limit=limit)["items"]


def get_interaction_receipt(receipt_id: str) -> dict[str, Any] | None:
    """Get one hash-only interaction receipt."""

    _require_enabled()
    tenant = _active_tenant()
    value = _required_text(receipt_id, "receipt_id", 64)
    if not _RECORD_ID_RE.fullmatch(value) or not value.startswith("AIR-"):
        raise ValueError("receipt_id is invalid")
    record = _RECEIPTS.get(value)
    try:
        signed_row = _receipt_ledger().find(value)
    except Exception as exc:
        from .ai_evidence_ledger import SegmentedLedgerError

        if isinstance(exc, SegmentedLedgerError):
            raise EvidenceGatewayStateError(str(exc)) from exc
        raise
    if record is None or record.get("status") != "issued":
        if signed_row is not None:
            raise EvidenceGatewayStateError(
                "signed receipt is missing its governed authority record"
            )
        return None
    signed = record.get("signed_receipt")
    if not isinstance(signed, Mapping) or signed_row is None:
        raise EvidenceGatewayStateError(
            "governed receipt is missing its signed ledger authority"
        )
    if (
        signed.get("hash") != signed_row.get("hash")
        or signed.get("receipt_payload_sha256")
        != signed_row.get("receipt_payload_sha256")
        or not text_equals(
            _canonical_json(dict(signed)),
            _canonical_json(signed_row),
        )
    ):
        raise EvidenceGatewayStateError(
            "governed receipt diverges from its signed ledger authority"
        )
    view = _receipt_view(record)
    view["signature_valid"] = verify_interaction_receipt(
        view,
        trusted_public_keys=trusted_public_keys(),
        expected_tenant_id=tenant,
    )
    return view


def trusted_public_keys() -> dict[str, str]:
    """Return the server-protected audit trust registry.

    Verification never trusts a key disclosed by a receipt or packet.  HTTP
    callers should use this registry rather than accepting trust roots from a
    request.
    """

    from .audit.signing import trusted_audit_public_keys

    return trusted_audit_public_keys()


def _trusted_key(
    key_id: object,
    registry: Mapping[str, str],
) -> str | None:
    if not isinstance(key_id, str):
        return None
    public_key = registry.get(key_id)
    if not isinstance(public_key, str):
        return None
    normalized = public_key.strip().lower()
    try:
        key_bytes = bytes.fromhex(normalized)
    except ValueError:
        return None
    if len(key_bytes) != 32:
        return None
    if hashlib.sha256(key_bytes).hexdigest()[:16] != key_id:
        return None
    return normalized


def _verify_signed_row(
    row: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, str],
) -> bool:
    from .audit.signing import verify_ed25519

    trusted = _trusted_key(row.get("key_id"), trusted_keys)
    if trusted is None:
        return False
    unsigned = {
        key: value for key, value in row.items() if key not in {"hash", "sig"}
    }
    row_hash = hashlib.sha256(
        json.dumps(unsigned, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()
    if not hmac.compare_digest(row_hash, str(row.get("hash") or "")):
        return False
    signature = row.get("sig")
    return isinstance(signature, str) and verify_ed25519(
        trusted,
        signature,
        bytes.fromhex(row_hash),
    )


def _valid_receipt_shape(
    signed: Mapping[str, Any],
    *,
    expected_tenant_id: str,
) -> bool:
    try:
        if set(signed) != _RECEIPT_EVENT_FIELDS:
            return False
        if (
            signed["schema"] != RECEIPT_SCHEMA
            or signed["event"] != INTERACTION_EVENT
            or signed["stores_raw_interaction_content"] is not False
            or signed["legal_certification"] is not False
            or signed["compliance_verdict"] != "not_provided"
            or signed["notice"] != NON_CERTIFICATION_NOTICE
            or signed["tenant_id"] != expected_tenant_id
            or signed["modality"] != "text"
        ):
            return False
        receipt_id = str(signed["receipt_id"])
        if not _RECORD_ID_RE.fullmatch(receipt_id) or not receipt_id.startswith(
            "AIR-"
        ):
            return False
        issued_at = signed["issued_at"]
        if isinstance(issued_at, bool):
            return False
        issued_timestamp = float(issued_at)
        if not math.isfinite(issued_timestamp) or issued_timestamp <= 0:
            return False
        sequence = signed["sequence"]
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 1
        ):
            return False
        digest_fields = (
            "conversation_sha256",
            "idempotency_sha256",
            "input_sha256",
            "generated_output_sha256",
            "delivered_output_sha256",
            "actor_sha256",
            "receipt_payload_sha256",
            "hash",
        )
        normalized = {
            field: _digest(signed[field], field) for field in digest_fields
        }
        for field in ("model_sha256", "context_sha256"):
            normalized[field] = _digest(
                signed[field],
                field,
                optional=True,
            )
        parent_hash = _digest(
            signed["parent_receipt_hash"],
            "parent_receipt_hash",
            optional=True,
        )
        _digest(signed["prev_hash"], "prev_hash", optional=True)
        binding = signed["policy_binding"]
        if not isinstance(binding, Mapping) or set(binding) != {
            "record_id",
            "record_revision",
            "policy_id",
            "policy_sha256",
        }:
            return False
        policy_id = _token(binding["policy_id"], "policy_id")
        if binding["record_id"] != _stable_id("AIP", policy_id):
            return False
        policy_revision = binding["record_revision"]
        if (
            isinstance(policy_revision, bool)
            or not isinstance(policy_revision, int)
            or policy_revision < 1
        ):
            return False
        _digest(binding["policy_sha256"], "policy_sha256")
        transparency = signed["transparency"]
        if (
            not isinstance(transparency, Mapping)
            or set(transparency) != _TRANSPARENCY_FIELDS
            or transparency["rendering_policy"] != "deterministic_text_v1"
            or transparency["editorial_exception"] is not None
        ):
            return False
        boolean_fields = _TRANSPARENCY_FIELDS - {
            "editorial_exception",
            "rendering_policy",
        }
        if any(
            not isinstance(transparency[field], bool)
            for field in boolean_fields
        ):
            return False
        if (
            transparency["interaction_disclosure_applied"]
            and not transparency["interaction_disclosure_required"]
        ) or (
            transparency["machine_readable_marking_applied"]
            and not transparency["machine_readable_marking_required"]
        ) or (
            transparency["visible_marking_required"]
            and not transparency["visible_marking_applied"]
        ):
            return False
        expected_receipt_id = _stable_id(
            "AIR",
            expected_tenant_id,
            normalized["conversation_sha256"],
            normalized["idempotency_sha256"],
        )
        if not hmac.compare_digest(receipt_id, expected_receipt_id):
            return False
        if (parent_hash and sequence == 1) or (
            not parent_hash and sequence > 1
        ):
            return False
        return True
    except (KeyError, TypeError, ValueError):
        return False


def verify_interaction_receipt(
    receipt: Mapping[str, Any] | str,
    *,
    trusted_public_keys: Mapping[str, str] | None = None,
    expected_tenant_id: str | None = None,
) -> bool:
    """Verify a receipt with an external/protected key registry."""

    try:
        if isinstance(receipt, str):
            resolved = get_interaction_receipt(receipt)
            if resolved is None:
                return False
            receipt = resolved
        if not isinstance(receipt, Mapping):
            return False
        signed = receipt.get("signed_receipt", receipt)
        if not isinstance(signed, Mapping):
            return False
        expected = expected_tenant_id or _active_tenant()
        if not _valid_receipt_shape(
            signed,
            expected_tenant_id=expected,
        ):
            return False
        payload = dict(signed)
        claimed_payload = payload.pop("receipt_payload_sha256", None)
        payload.pop("prev_hash", None)
        payload.pop("key_id", None)
        payload.pop("hash", None)
        payload.pop("sig", None)
        if not isinstance(claimed_payload, str) or not hmac.compare_digest(
            claimed_payload,
            _sha256(payload),
        ):
            return False
        registry = (
            globals()["trusted_public_keys"]()
            if trusted_public_keys is None
            else trusted_public_keys
        )
        if not isinstance(registry, Mapping):
            return False
        return _verify_signed_row(signed, trusted_keys=registry)
    except (EvidenceGatewayError, KeyError, TypeError, ValueError):
        return False


def _citation(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("citation must be a mapping")
    record_url = value.get("record_url") or value.get("url")
    required = {
        "source_name": _required_text(
            value.get("source_name"),
            "citation source_name",
            256,
        ),
        "retrieval_url": _https_url(
            value.get("retrieval_url"),
            "citation retrieval_url",
        ),
        "record_url": _https_url(record_url, "citation record_url"),
        "retrieved_at": _retrieval_timestamp(value.get("retrieved_at")),
        "content_sha256": _digest(
            value.get("content_sha256"),
            "citation content_sha256",
        ),
    }
    optional_text = {
        "source_format": 64,
        "parser_version": 64,
        "acquisition": 64,
        "acquired_by": 256,
        "official_citation": 1_000,
    }
    for field, limit in optional_text.items():
        if value.get(field) not in (None, ""):
            required[field] = _required_text(
                value[field],
                f"citation {field}",
                limit,
            )
    if value.get("feed_url") not in (None, ""):
        required["feed_url"] = _https_url(value["feed_url"], "citation feed_url")
    for field in ("payload_sha256", "source_record_sha256"):
        if value.get(field) not in (None, ""):
            required[field] = _digest(value[field], f"citation {field}")
    return required


def _tokens(
    values: Sequence[str] | None,
    label: str,
) -> list[str]:
    if values is None:
        return []
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(
        values,
        Sequence,
    ):
        raise TypeError(f"{label} must be a sequence")
    normalized = sorted({_token(value, label) for value in values})
    if len(normalized) > _MAX_AFFECTED:
        raise ValueError(f"{label} exceeds {_MAX_AFFECTED} values")
    return normalized


def record_regulatory_impact(
    alert_id: str,
    *,
    alert_revision: int,
    content_sha256: str,
    citations: Sequence[Mapping[str, Any]],
    affected_policy_ids: Sequence[str] = ("default",),
    affected_asset_ids: Sequence[str] = (),
    control_ids: Sequence[str] = (),
    match_reasons: Sequence[str] = (),
    actor: str,
    impact_id: str | None = None,
) -> dict[str, Any]:
    """Record one deterministic, citation-complete impact for human review."""

    _require_enabled()
    _active_tenant()
    alert = _required_text(alert_id, "alert_id", 256)
    operator = _required_text(actor, "actor", 256)
    if (
        isinstance(alert_revision, bool)
        or not isinstance(alert_revision, int)
        or alert_revision < 0
    ):
        raise ValueError("alert_revision must be a non-negative integer")
    digest = _digest(content_sha256, "content_sha256")
    if isinstance(citations, (str, bytes, bytearray)) or not isinstance(
        citations,
        Sequence,
    ):
        raise TypeError("citations must be a sequence")
    normalized_citations = [_citation(value) for value in citations]
    if not normalized_citations or len(normalized_citations) > _MAX_CITATIONS:
        raise ValueError(
            f"citations must contain between 1 and {_MAX_CITATIONS} records"
        )
    normalized_citations.sort(
        key=lambda row: (row["source_name"], row["record_url"])
    )
    policy_ids = _tokens(affected_policy_ids, "affected_policy_id")
    if not policy_ids:
        raise ValueError("at least one affected_policy_id is required")
    for policy_id in policy_ids:
        if _policy_record(policy_id) is None:
            raise EvidenceGatewayStateError(
                f"affected policy {policy_id!r} does not exist"
            )
    assets = _tokens(affected_asset_ids, "affected_asset_id")
    controls = _tokens(control_ids, "control_id")
    if isinstance(match_reasons, (str, bytes, bytearray)) or not isinstance(
        match_reasons,
        Sequence,
    ):
        raise TypeError("match_reasons must be a sequence")
    reasons = sorted(
        {
            _required_text(value, "match_reason", 1_000)
            for value in match_reasons
        }
    )
    if len(reasons) > _MAX_AFFECTED:
        raise ValueError("match_reasons exceeds the collection limit")
    logical_id = (
        _required_text(impact_id, "impact_id", 128)
        if impact_id is not None
        else f"{alert}:{alert_revision}:{digest}"
    )
    record_id = _stable_id("AII", logical_id)
    body = {
        "schema": REGULATORY_IMPACT_SCHEMA,
        "impact_id": record_id,
        "alert_id": alert,
        "alert_revision": alert_revision,
        "content_sha256": digest,
        "citations": normalized_citations,
        "citations_sha256": _sha256(normalized_citations),
        "affected_policy_ids": policy_ids,
        "affected_asset_ids": assets,
        "control_ids": controls,
        "match_reasons": reasons,
    }
    body["impact_sha256"] = _sha256(body)
    from .file_lock import cross_process_lock

    with _IMPACT_MUTATION_LOCK:
        with cross_process_lock(_impact_transaction_target(), strict=True):
            existing = _IMPACTS.get(record_id)
            if existing is not None:
                _validated_impact_view(existing)
                if not hmac.compare_digest(
                    str(existing.get("impact_sha256") or ""),
                    body["impact_sha256"],
                ):
                    raise RecordConflict(
                        "regulatory impact identity was reused with different "
                        "evidence"
                    )
                return _validated_impact_view(existing)
            if len(_IMPACTS.list(limit=_MAX_IMPACTS)) >= _MAX_IMPACTS:
                raise EvidenceGatewayStateError(
                    "AI regulatory impact capacity has been reached; review "
                    "retention or provision a new governed tenant namespace "
                    "before ingesting another impact"
                )
            try:
                saved = _IMPACTS.create(
                    {
                        "id": record_id,
                        **body,
                        "status": "pending_review",
                        "review": None,
                        "policy_refreshes": [],
                        "legal_certification": False,
                        "compliance_verdict": "not_provided",
                        "notice": NON_CERTIFICATION_NOTICE,
                    },
                    action="regulatory_impact_recorded",
                    actor=operator,
                    max_records=_MAX_IMPACTS,
                )
            except GovernedRecordCapacityError as exc:
                raise EvidenceGatewayStateError(
                    "AI regulatory impact capacity has been reached; review "
                    "retention or provision a new governed tenant namespace "
                    "before ingesting another impact"
                ) from exc
            except RecordConflict:
                # A shared-backend replica may have committed the same
                # deterministic impact identity after our initial read. Exact
                # content is an idempotent recovery; divergent evidence keeps
                # the conflict authoritative.
                recovered = _IMPACTS.get(record_id)
                if recovered is None:
                    raise
                validated = _validated_impact_view(recovered)
                if not hmac.compare_digest(
                    str(recovered.get("impact_sha256") or ""),
                    body["impact_sha256"],
                ):
                    raise RecordConflict(
                        "regulatory impact identity was reused with different "
                        "evidence"
                    ) from None
                return validated
    return _validated_impact_view(saved)


def _validated_impact_view(record: Mapping[str, Any]) -> dict[str, Any]:
    try:
        record_id = _required_text(record.get("id"), "impact id", 64)
        if (
            not _RECORD_ID_RE.fullmatch(record_id)
            or not record_id.startswith("AII-")
            or record.get("impact_id") != record_id
            or record.get("schema") != REGULATORY_IMPACT_SCHEMA
            or record.get("legal_certification") is not False
            or record.get("compliance_verdict") != "not_provided"
            or record.get("notice") != NON_CERTIFICATION_NOTICE
        ):
            raise ValueError("impact identity")
        alert_id = _required_text(record.get("alert_id"), "alert_id", 256)
        alert_revision = record.get("alert_revision")
        if (
            isinstance(alert_revision, bool)
            or not isinstance(alert_revision, int)
            or alert_revision < 0
        ):
            raise ValueError("alert_revision")
        citations_value = record.get("citations")
        if not isinstance(citations_value, list):
            raise ValueError("citations")
        citations = [_citation(value) for value in citations_value]
        citations.sort(key=lambda row: (row["source_name"], row["record_url"]))
        if (
            not citations
            or len(citations) > _MAX_CITATIONS
            or citations != citations_value
        ):
            raise ValueError("citations")
        affected_policy_ids = _tokens(
            record.get("affected_policy_ids"),
            "affected_policy_id",
        )
        affected_asset_ids = _tokens(
            record.get("affected_asset_ids"),
            "affected_asset_id",
        )
        control_ids = _tokens(record.get("control_ids"), "control_id")
        match_reasons_value = record.get("match_reasons")
        if not isinstance(match_reasons_value, list):
            raise ValueError("match_reasons")
        match_reasons = sorted(
            {
                _required_text(value, "match_reason", 1_000)
                for value in match_reasons_value
            }
        )
        if (
            not affected_policy_ids
            or affected_policy_ids != record.get("affected_policy_ids")
            or affected_asset_ids != record.get("affected_asset_ids")
            or control_ids != record.get("control_ids")
            or match_reasons != match_reasons_value
        ):
            raise ValueError("impact mappings")
        body = {
            "schema": REGULATORY_IMPACT_SCHEMA,
            "impact_id": record_id,
            "alert_id": alert_id,
            "alert_revision": alert_revision,
            "content_sha256": _digest(
                record.get("content_sha256"),
                "content_sha256",
            ),
            "citations": citations,
            "citations_sha256": _digest(
                record.get("citations_sha256"),
                "citations_sha256",
            ),
            "affected_policy_ids": affected_policy_ids,
            "affected_asset_ids": affected_asset_ids,
            "control_ids": control_ids,
            "match_reasons": match_reasons,
        }
        if (
            not hmac.compare_digest(
                body["citations_sha256"],
                _sha256(citations),
            )
            or not hmac.compare_digest(
                _digest(record.get("impact_sha256"), "impact_sha256"),
                _sha256(body),
            )
        ):
            raise ValueError("impact digest")
        status = record.get("status")
        review = record.get("review")
        refreshes = record.get("policy_refreshes")
        if not isinstance(refreshes, list):
            raise ValueError("policy_refreshes")
        if status == "pending_review":
            if review is not None or refreshes:
                raise ValueError("pending review state")
        elif status in {"accepted_refreshing", "accepted", "dismissed"}:
            expected_decision = (
                "dismissed" if status == "dismissed" else "accepted"
            )
            if (
                not isinstance(review, Mapping)
                or review.get("decision") != expected_decision
                or review.get("human_review") is not True
                or not isinstance(review.get("reviewed_at"), (int, float))
                or isinstance(review.get("reviewed_at"), bool)
                or not isinstance(review.get("source_revision"), int)
                or isinstance(review.get("source_revision"), bool)
            ):
                raise ValueError("review state")
            _required_text(review.get("reviewer"), "reviewer", 256)
            _required_text(review.get("rationale"), "rationale", 4_000)
            if status in {"accepted_refreshing", "dismissed"} and refreshes:
                raise ValueError("policy refresh state")
        else:
            raise ValueError("impact status")
        return _public(record)
    except (KeyError, TypeError, ValueError) as exc:
        raise EvidenceGatewayStateError(
            "persisted regulatory impact failed integrity validation"
        ) from exc


def get_regulatory_impact(impact_id: str) -> dict[str, Any] | None:
    """Return one tenant-bound cited impact by its governed identity."""

    _require_enabled()
    _active_tenant()
    record_id = _required_text(impact_id, "impact_id", 64)
    if not _RECORD_ID_RE.fullmatch(record_id) or not record_id.startswith("AII-"):
        raise ValueError("impact_id is invalid")
    record = _IMPACTS.get(record_id)
    return None if record is None else _validated_impact_view(record)


def _impact_cursor(body: Mapping[str, Any]) -> str:
    envelope = {"body": dict(body), "sha256": _sha256(body)}
    return base64.urlsafe_b64encode(
        _canonical_json(envelope).encode("utf-8")
    ).decode("ascii").rstrip("=")


def _decode_impact_cursor(value: str) -> dict[str, Any]:
    try:
        raw = str(value)
        if len(raw) > 2_048:
            raise ValueError("cursor is too large")
        raw += "=" * (-len(raw) % 4)
        envelope = json.loads(
            base64.b64decode(
                raw.encode("ascii"),
                altchars=b"-_",
                validate=True,
            ).decode("utf-8")
        )
        body = envelope["body"]
        expected = {
            "v",
            "tenant",
            "status",
            "pending_first",
            "boundary_created_at",
            "boundary_id",
            "snapshot_sha256",
            "offset",
        }
        if (
            not isinstance(envelope, dict)
            or not isinstance(body, dict)
            or set(envelope) != {"body", "sha256"}
            or set(body) != expected
            or envelope["sha256"] != _sha256(body)
            or body["v"] != 1
            or not isinstance(body["tenant"], str)
            or not isinstance(body["status"], str)
            or not isinstance(body["pending_first"], bool)
            or isinstance(body["boundary_created_at"], bool)
            or not isinstance(body["boundary_created_at"], (int, float))
            or not math.isfinite(float(body["boundary_created_at"]))
            or not isinstance(body["boundary_id"], str)
            or not isinstance(body["snapshot_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", body["snapshot_sha256"])
            or isinstance(body["offset"], bool)
            or not isinstance(body["offset"], int)
            or body["offset"] < 1
        ):
            raise ValueError("invalid cursor")
        return body
    except (
        KeyError,
        TypeError,
        ValueError,
        UnicodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError("regulatory impact cursor is invalid") from exc


def list_regulatory_impacts_page(
    *,
    limit: int = 100,
    cursor: str | None = None,
    status: str | None = None,
    pending_first: bool = True,
) -> dict[str, Any]:
    """Page all cited impacts with a tenant-bound, append-stable cursor."""

    _require_enabled()
    tenant = _active_tenant()
    bounded = _list_limit(limit, 500)
    if not isinstance(pending_first, bool):
        raise ValueError("pending_first must be a boolean")
    status_filter = "" if status is None else _token(status, "status").lower()
    if status_filter and status_filter not in _IMPACT_STATUSES:
        raise ValueError("status is invalid")
    rows = _IMPACTS.list(limit=_MAX_IMPACTS + 1)
    if len(rows) > _MAX_IMPACTS:
        raise EvidenceGatewayStateError(
            "AI regulatory impact namespace exceeds the safety limit"
        )
    validated = [_validated_impact_view(row) for row in rows]
    if cursor is None:
        boundary_created_at, boundary_id = max(
            (
                (float(row.get("created_at") or 0.0), str(row["id"]))
                for row in validated
            ),
            default=(0.0, ""),
        )
        offset = 0
        expected_snapshot = ""
    else:
        decoded = _decode_impact_cursor(cursor)
        if (
            decoded["tenant"] != tenant
            or decoded["status"] != status_filter
            or decoded["pending_first"] is not pending_first
        ):
            raise ValueError(
                "regulatory impact cursor does not match this tenant or filter"
            )
        boundary_created_at = float(decoded["boundary_created_at"])
        boundary_id = str(decoded["boundary_id"])
        offset = int(decoded["offset"])
        expected_snapshot = str(decoded["snapshot_sha256"])
    snapshot_rows = [
        row
        for row in validated
        if (
            float(row.get("created_at") or 0.0),
            str(row["id"]),
        )
        <= (boundary_created_at, boundary_id)
        and (not status_filter or row.get("status") == status_filter)
    ]
    attention = {
        "pending_review": 0,
        "accepted_refreshing": 1,
        "accepted": 2,
        "dismissed": 2,
    }
    ordered = sorted(
        snapshot_rows,
        key=lambda row: (
            attention.get(str(row.get("status")), 3) if pending_first else 0,
            -float(row.get("created_at") or 0.0),
            str(row.get("id") or ""),
        ),
    )
    snapshot_sha = _sha256(
        [
            {
                "id": row["id"],
                "revision": row.get("revision"),
                "status": row.get("status"),
                "updated_at": row.get("updated_at"),
            }
            for row in ordered
        ]
    )
    if expected_snapshot and not hmac.compare_digest(
        expected_snapshot,
        snapshot_sha,
    ):
        raise EvidenceGatewayStateError(
            "regulatory impact page changed after the cursor was issued; "
            "restart pagination"
        )
    items = ordered[offset : offset + bounded]
    next_offset = offset + len(items)
    next_cursor = (
        _impact_cursor(
            {
                "v": 1,
                "tenant": tenant,
                "status": status_filter,
                "pending_first": pending_first,
                "boundary_created_at": boundary_created_at,
                "boundary_id": boundary_id,
                "snapshot_sha256": snapshot_sha,
                "offset": next_offset,
            }
        )
        if next_offset < len(ordered)
        else None
    )
    return {
        "items": items,
        "next_cursor": next_cursor,
        "snapshot_total": len(ordered),
        "count": len(items),
        "status": status_filter or None,
        "pending_first": pending_first,
    }


def list_regulatory_impacts(*, limit: int = 100) -> list[dict[str, Any]]:
    """Compatibility first page, with action-needed impacts first."""

    bounded = _list_limit(limit, _MAX_IMPACTS)
    if bounded > 500:
        # Internal complete-collection callers require all 5,000 records.
        _require_enabled()
        _active_tenant()
        rows = _IMPACTS.list(limit=_MAX_IMPACTS + 1)
        if len(rows) > _MAX_IMPACTS:
            raise EvidenceGatewayStateError(
                "AI regulatory impact namespace exceeds the safety limit"
            )
        return sorted(
            (_validated_impact_view(row) for row in rows),
            key=lambda row: (
                float(row.get("created_at") or 0.0),
                str(row.get("id") or ""),
            ),
            reverse=True,
        )[:bounded]
    return list_regulatory_impacts_page(limit=bounded)["items"]


def _bind_impact_to_policy(
    policy_id: str,
    impact: Mapping[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    token = _token(policy_id, "policy_id")
    operator = _required_text(actor, "actor", 256)
    impact_id = _required_text(impact.get("id"), "impact id", 64)
    authoritative = _IMPACTS.get(impact_id)
    if authoritative is None:
        raise EvidenceGatewayStateError(
            "regulatory impact authority record is missing"
        )
    _validated_impact_view(authoritative)
    review = authoritative.get("review")
    if (
        authoritative.get("status") not in {"accepted_refreshing", "accepted"}
        or not isinstance(review, Mapping)
        or review.get("decision") != "accepted"
        or review.get("human_review") is not True
        or token not in authoritative.get("affected_policy_ids", [])
    ):
        raise EvidenceGatewayStateError(
            "regulatory impact is not an accepted authority for this policy"
        )
    for field in ("impact_sha256", "citations_sha256"):
        claimed = _digest(impact.get(field), field)
        persisted = _digest(authoritative.get(field), field)
        if not hmac.compare_digest(claimed, persisted):
            raise EvidenceGatewayStateError(
                "regulatory impact authority does not match the reviewed record"
            )

    for _attempt in range(16):
        record = _policy_record(token)
        if record is None:
            raise EvidenceGatewayStateError(
                f"affected policy {token!r} is missing"
            )
        policy = _policy_view(record)
        binding = {
            "impact_id": impact_id,
            "impact_sha256": authoritative["impact_sha256"],
            "citations_sha256": authoritative["citations_sha256"],
        }
        current_bindings = list(policy["regulatory_bindings"])
        for existing in current_bindings:
            if existing["impact_id"] == binding["impact_id"]:
                if existing != binding:
                    raise EvidenceGatewayStateError(
                        "policy has a conflicting regulatory impact binding"
                    )
                return policy
        current_bindings.append(binding)
        if len(current_bindings) > _MAX_AFFECTED:
            raise EvidenceGatewayStateError(
                "AI evidence policy regulatory bindings reached their safety limit"
            )
        history = record.get("history")
        current_snapshot = record.get("current")
        if (
            not isinstance(history, list)
            or not isinstance(current_snapshot, Mapping)
        ):
            raise EvidenceGatewayStateError(
                "AI evidence policy snapshot history is malformed"
            )
        if len(history) >= _MAX_POLICY_HISTORY:
            _archive_policy_snapshot(history[0], actor=operator)
        next_revision = int(policy["revision"]) + 1
        snapshot = _build_snapshot(
            policy_id=token,
            actor=operator,
            record_revision=next_revision,
            settings=policy["settings"],
            model_sha256=policy["model_sha256"],
            context_sha256=policy["context_sha256"],
            regulatory_bindings=current_bindings,
            metadata=policy["metadata"],
            effective_at=time.time(),
        )

        def refresh(
            row: dict[str, Any],
            published_snapshot: dict[str, Any] = snapshot,
        ) -> None:
            row_history = row.get("history")
            row_current = row.get("current")
            if (
                not isinstance(row_history, list)
                or not isinstance(row_current, dict)
            ):
                raise EvidenceGatewayStateError(
                    "AI evidence policy snapshot history is malformed"
                )
            if len(row_history) >= _MAX_POLICY_HISTORY:
                row_history.pop(0)
            row_history.append(dict(row_current))
            row["current"] = published_snapshot
            row["status"] = "active"

        try:
            updated = _POLICIES.update(
                record["id"],
                refresh,
                expected_revision=int(policy["revision"]),
                action="policy_regulatory_impact_bound",
                actor=operator,
            )
        except RecordConflict:
            continue
        if updated is None:
            raise EvidenceGatewayStateError("AI evidence policy disappeared")
        return _policy_view(updated)
    raise EvidenceGatewayStateError("policy refresh contention exceeded")


def _preflight_impact_acceptance(
    impact: Mapping[str, Any],
    *,
    actor: str,
) -> None:
    """Prove every dependent policy can refresh before claiming acceptance."""

    impact_id = _required_text(impact.get("id"), "impact id", 64)
    binding = {
        "impact_id": impact_id,
        "impact_sha256": _digest(
            impact.get("impact_sha256"),
            "impact_sha256",
        ),
        "citations_sha256": _digest(
            impact.get("citations_sha256"),
            "citations_sha256",
        ),
    }
    affected = impact.get("affected_policy_ids")
    if (
        not isinstance(affected, list)
        or len(affected) > _MAX_AFFECTED
        or any(not isinstance(value, str) for value in affected)
    ):
        raise EvidenceGatewayStateError(
            "regulatory impact affected-policy authority is invalid"
        )
    reservations: dict[str, set[str]] = {
        policy_id: set() for policy_id in affected
    }
    rows = _IMPACTS.list(limit=_MAX_IMPACTS + 1)
    if len(rows) > _MAX_IMPACTS:
        raise EvidenceGatewayStateError(
            "AI regulatory impact namespace exceeds the safety limit"
        )
    for row in rows:
        candidate = _validated_impact_view(row)
        if candidate.get("status") != "accepted_refreshing":
            continue
        candidate_id = str(candidate["id"])
        for policy_id in candidate.get("affected_policy_ids", []):
            if policy_id in reservations:
                reservations[policy_id].add(candidate_id)
    for policy_id in affected:
        record = _policy_record(policy_id)
        if record is None:
            raise EvidenceGatewayStateError(
                f"affected policy {policy_id!r} is missing; acceptance was "
                "not claimed"
            )
        policy = _policy_view(record)
        current = list(policy["regulatory_bindings"])
        existing = next(
            (
                item
                for item in current
                if item.get("impact_id") == impact_id
            ),
            None,
        )
        if existing is not None:
            if existing != binding:
                raise EvidenceGatewayStateError(
                    "policy has a conflicting regulatory impact binding"
                )
            continue
        projected_ids = {
            str(item["impact_id"]) for item in current
        }
        projected_ids.update(reservations[policy_id])
        projected_ids.add(impact_id)
        if len(projected_ids) > _MAX_AFFECTED:
            raise EvidenceGatewayStateError(
                "AI evidence policy regulatory bindings reached their safety "
                "limit; acceptance was not claimed"
            )
        history = record.get("history")
        if not isinstance(history, list):
            raise EvidenceGatewayStateError(
                "AI evidence policy snapshot history is malformed; "
                "acceptance was not claimed"
            )
        if len(history) >= _MAX_POLICY_HISTORY:
            # Rollover is durable and idempotent. The oldest snapshot remains
            # discoverable for historical receipt verification.
            _archive_policy_snapshot(history[0], actor=actor)


def review_regulatory_impact(
    impact_id: str,
    *,
    decision: str,
    reviewer: str,
    rationale: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Serialize the multi-policy review transition for this tenant."""

    from .file_lock import cross_process_lock

    with _POLICY_MUTATION_LOCK:
        with cross_process_lock(_policy_transaction_target(), strict=True):
            return _review_regulatory_impact_locked(
                impact_id,
                decision=decision,
                reviewer=reviewer,
                rationale=rationale,
                expected_revision=expected_revision,
            )


def _complete_impact_acceptance(
    record_id: str,
    claimed: Mapping[str, Any],
    *,
    operator: str,
    reason: str,
) -> dict[str, Any]:
    refreshes: list[dict[str, Any]] = []
    for policy_id in claimed["affected_policy_ids"]:
        policy = _bind_impact_to_policy(policy_id, claimed, actor=operator)
        refreshes.append(
            {
                "policy_id": policy_id,
                "policy_record_id": policy["id"],
                "policy_record_revision": policy["revision"],
                "policy_sha256": policy["policy_sha256"],
            }
        )

    def finalize_acceptance(row: dict[str, Any]) -> None:
        row_review = row.get("review")
        if (
            row.get("status") != "accepted_refreshing"
            or not isinstance(row_review, Mapping)
            or row_review.get("decision") != "accepted"
            or row_review.get("reviewer") != operator
            or row_review.get("rationale") != reason
        ):
            raise RecordConflict("regulatory impact acceptance authority changed")
        row["status"] = "accepted"
        row["policy_refreshes"] = refreshes

    try:
        updated = _IMPACTS.update(
            record_id,
            finalize_acceptance,
            expected_revision=int(claimed["revision"]),
            action="regulatory_impact_accepted",
            actor=operator,
        )
    except RecordConflict:
        latest = _IMPACTS.get(record_id)
        latest_review = None if latest is None else latest.get("review")
        if (
            latest is not None
            and latest.get("status") == "accepted"
            and isinstance(latest_review, Mapping)
            and latest_review.get("decision") == "accepted"
            and latest_review.get("reviewer") == operator
            and latest_review.get("rationale") == reason
        ):
            return _public(latest)
        raise
    if updated is None:
        raise EvidenceGatewayStateError("regulatory impact disappeared")
    return _public(updated)


def _review_regulatory_impact_locked(
    impact_id: str,
    *,
    decision: str,
    reviewer: str,
    rationale: str,
    expected_revision: int,
) -> dict[str, Any]:
    """CAS-review an impact with a recoverable acceptance state machine.

    Acceptance first claims the impact as ``accepted_refreshing``.  Only that
    immutable human decision may then refresh policies and finalize
    ``accepted``.  A concurrent dismissal therefore cannot win between policy
    mutation and impact finalization.
    """

    _require_enabled()
    _active_tenant()
    record_id = _required_text(impact_id, "impact_id", 64)
    if not _RECORD_ID_RE.fullmatch(record_id) or not record_id.startswith("AII-"):
        raise ValueError("impact_id is invalid")
    choice = _token(decision, "decision").lower()
    if choice not in _IMPACT_DECISIONS:
        raise ValueError("decision must be accepted or dismissed")
    operator = _required_text(reviewer, "reviewer", 256)
    reason = _required_text(rationale, "rationale", 4_000)
    if (
        isinstance(expected_revision, bool)
        or not isinstance(expected_revision, int)
        or expected_revision < 0
    ):
        raise ValueError("expected_revision must be a non-negative integer")
    current = _IMPACTS.get(record_id)
    if current is None:
        raise EvidenceGatewayStateError("regulatory impact does not exist")
    _validated_impact_view(current)
    status = str(current.get("status") or "")
    prior_review = current.get("review")
    same_review = bool(
        isinstance(prior_review, Mapping)
        and prior_review.get("decision") == choice
        and prior_review.get("reviewer") == operator
        and prior_review.get("rationale") == reason
    )
    if status == choice and same_review:
        return _public(current)
    if status == "accepted_refreshing":
        if choice != "accepted" or not same_review:
            raise RecordConflict(
                "regulatory impact acceptance is already being applied"
            )
        source_revision = prior_review.get("source_revision")
        if expected_revision not in {int(current["revision"]), source_revision}:
            raise RecordConflict(
                "regulatory impact changed since acceptance was claimed"
            )
        _preflight_impact_acceptance(current, actor=operator)
        claimed = current
    else:
        if status != "pending_review":
            raise RecordConflict("regulatory impact has already been reviewed")
        if int(current["revision"]) != expected_revision:
            raise RecordConflict("regulatory impact changed since it was reviewed")
        reviewed_at = time.time()
        if choice == "dismissed":

            def dismiss(row: dict[str, Any]) -> None:
                if row.get("status") != "pending_review":
                    raise RecordConflict(
                        "regulatory impact has already been reviewed"
                    )
                row["status"] = "dismissed"
                row["review"] = {
                    "decision": "dismissed",
                    "reviewer": operator,
                    "rationale": reason,
                    "reviewed_at": reviewed_at,
                    "source_revision": expected_revision,
                    "human_review": True,
                }
                row["policy_refreshes"] = []

            dismissed = _IMPACTS.update(
                record_id,
                dismiss,
                expected_revision=expected_revision,
                action="regulatory_impact_dismissed",
                actor=operator,
            )
            if dismissed is None:
                raise EvidenceGatewayStateError("regulatory impact disappeared")
            return _public(dismissed)

        _preflight_impact_acceptance(current, actor=operator)

        def claim_acceptance(row: dict[str, Any]) -> None:
            if row.get("status") != "pending_review":
                raise RecordConflict("regulatory impact has already been reviewed")
            row["status"] = "accepted_refreshing"
            row["review"] = {
                "decision": "accepted",
                "reviewer": operator,
                "rationale": reason,
                "reviewed_at": reviewed_at,
                "source_revision": expected_revision,
                "human_review": True,
            }
            row["policy_refreshes"] = []

        claimed = _IMPACTS.update(
            record_id,
            claim_acceptance,
            expected_revision=expected_revision,
            action="regulatory_impact_acceptance_claimed",
            actor=operator,
        )
        if claimed is None:
            raise EvidenceGatewayStateError("regulatory impact disappeared")

    return _complete_impact_acceptance(
        record_id, claimed, operator=operator, reason=reason,
    )


def _receipt_verification_counts(
    receipts: Sequence[Mapping[str, Any]],
    trust: Mapping[str, str],
) -> tuple[int, int]:
    verified = 0
    unverified = 0
    tenant = _active_tenant()
    for receipt in receipts:
        if verify_interaction_receipt(
            receipt,
            trusted_public_keys=trust,
            expected_tenant_id=tenant,
        ):
            verified += 1
        else:
            unverified += 1
    return verified, unverified


def _governed_receipt_count() -> int:
    """Count the complete governed namespace through its rotating cursor seam."""

    first_identity = ""
    cursor = ""
    count = 0
    while True:
        batch = list(
            _RECEIPTS.iter_record_ids(
                start_after=cursor,
                limit=10_000,
            )
        )
        if not batch:
            return count
        for next_cursor, identity in batch:
            if not first_identity:
                first_identity = identity
            elif identity == first_identity:
                return count
            count += 1
            cursor = next_cursor
        if len(batch) < 10_000:
            return count


def _receipt_assurance_snapshot_once(
    *,
    ledger: Any,
    state: Any,
    include_limit: int,
    trust: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build one view for a caller-pinned signed ledger state."""

    tenant = _active_tenant()
    registry = trusted_public_keys() if trust is None else trust
    physical_valid, physical_error = ledger.verify_integrity(
        snapshot_state=state,
    )
    digest = hashlib.sha256()
    included: list[dict[str, Any]] = []
    total = 0
    current = 0
    verified = 0
    missing_governed = 0
    governed_binding_valid = True
    conversation_valid = True
    conversations: dict[str, list[object]] = {}
    for entry in ledger.iter_entries(
        descending=True,
        snapshot_total=state.total_receipts,
        validate_rows=False,
    ):
        record = _RECEIPTS.get(entry.identity)
        if record is None or record.get("status") != "issued":
            missing_governed += 1
            continue
        signed = record.get("signed_receipt")
        if not isinstance(signed, Mapping):
            raise EvidenceGatewayStateError(
                "governed receipt record has no signed evidence"
            )
        if (
            signed.get("hash") != entry.row_hash
            or signed.get("receipt_payload_sha256") != entry.payload_sha256
        ):
            governed_binding_valid = False
        view = _receipt_view(record)
        view["ledger_ordinal"] = entry.ordinal
        signature_valid = verify_interaction_receipt(
            view,
            trusted_public_keys=registry,
            expected_tenant_id=tenant,
        )
        view["signature_valid"] = signature_valid
        total += 1
        current += view["assurance"]["status"] == "current"
        verified += signature_valid
        encoded = _canonical_json(view).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
        if len(included) < include_limit:
            included.append(view)
        conversation = signed.get("conversation_sha256")
        sequence = signed.get("sequence")
        row_hash = signed.get("hash")
        parent = signed.get("parent_receipt_hash")
        if (
            not isinstance(conversation, str)
            or isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 1
            or not isinstance(row_hash, str)
            or not isinstance(parent, str)
        ):
            conversation_valid = False
            continue
        chain = conversations.get(conversation)
        if chain is None:
            authority = _CONVERSATIONS.get(_stable_id("AIC", conversation))
            if (
                authority is None
                or authority.get("schema") != CONVERSATION_SCHEMA
                or authority.get("pending") is not None
                or isinstance(authority.get("next_sequence"), bool)
                or not isinstance(authority.get("next_sequence"), int)
                or int(authority["next_sequence"]) < 2
                or not isinstance(authority.get("last_receipt_hash"), str)
            ):
                conversation_valid = False
                continue
            chain = [
                int(authority["next_sequence"]) - 1,
                str(authority["last_receipt_hash"]),
            ]
            conversations[conversation] = chain
        if sequence != chain[0] or row_hash != chain[1]:
            conversation_valid = False
        chain[0] = int(chain[0]) - 1
        chain[1] = parent
    if any(
        int(chain[0]) != 0 or str(chain[1]) != ""
        for chain in conversations.values()
    ):
        conversation_valid = False
    governed_count = _governed_receipt_count()
    extra_governed = max(0, governed_count - total)
    exact_reconciliation = (
        missing_governed == 0
        and extra_governed == 0
        and total == state.total_receipts
        and governed_binding_valid
    )
    return {
        "total": total,
        "current": current,
        "stale": total - current,
        "verified": verified,
        "unverified": total - verified,
        "included": included,
        "source_digest_sha256": digest.hexdigest(),
        "conversation_chains_valid": (
            conversation_valid and exact_reconciliation
        ),
        "ledger_chain_valid": physical_valid and exact_reconciliation,
        "ledger_error": physical_error,
        "ledger_total": state.total_receipts,
        "missing_governed": missing_governed,
        "extra_governed": extra_governed,
        "snapshot_state_hash": state.state_hash,
    }


def _capture_receipt_state(ledger: Any) -> Any:
    """Capture the signed receipt commit token between complete deliveries."""

    from .file_lock import cross_process_lock

    with _DELIVERY_LOCK:
        with cross_process_lock(
            _identity_transaction_target(_receipt_path()),
            strict=True,
        ):
            return ledger.state()


def _receipt_assurance_snapshot(
    *,
    include_limit: int,
    trust: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Return a stable complete view, retrying benign concurrent delivery.

    Expensive ledger, governed-record, signature, conversation, and count work
    runs without the append or delivery transaction locks.  Each accepted view
    is bracketed by the same signed ledger state hash while the tenant delivery
    transaction is quiescent.  A delivery that overlaps either stage therefore
    causes a bounded retry, never a false red result or stale false-ready result.
    """

    from .ai_evidence_ledger import SegmentedLedgerError

    try:
        ledger = _receipt_ledger()
        for _attempt in range(_MAX_RECEIPT_SNAPSHOT_ATTEMPTS):
            start = _capture_receipt_state(ledger)
            failure: Exception | None = None
            snapshot: dict[str, Any] | None = None
            try:
                snapshot = _receipt_assurance_snapshot_once(
                    ledger=ledger,
                    state=start,
                    include_limit=include_limit,
                    trust=trust,
                )
            except Exception as exc:
                failure = exc
            end = _capture_receipt_state(ledger)
            if not hmac.compare_digest(start.state_hash, end.state_hash):
                continue
            if failure is not None:
                raise failure
            assert snapshot is not None
            return snapshot
    except SegmentedLedgerError as exc:
        raise EvidenceGatewayStateError(str(exc)) from exc
    raise EvidenceGatewaySnapshotIndeterminate(
        "AI evidence receipts changed during every bounded assurance "
        "snapshot; retry when ingestion is quiescent"
    )


def _conversation_chains_valid(
    receipts: Sequence[Mapping[str, Any]],
) -> bool:
    conversations: dict[str, list[Mapping[str, Any]]] = {}
    for receipt in receipts:
        signed = receipt.get("signed_receipt", receipt)
        if not isinstance(signed, Mapping):
            return False
        conversation = signed.get("conversation_sha256")
        sequence = signed.get("sequence")
        if (
            not isinstance(conversation, str)
            or isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 1
        ):
            return False
        conversations.setdefault(conversation, []).append(signed)
    for rows in conversations.values():
        ordered = sorted(rows, key=lambda row: row["sequence"])
        prior_hash = ""
        for expected_sequence, row in enumerate(ordered, start=1):
            if (
                row.get("sequence") != expected_sequence
                or row.get("parent_receipt_hash") != prior_hash
                or not isinstance(row.get("hash"), str)
            ):
                return False
            prior_hash = str(row["hash"])
    return True


def _receipt_ledger_chain_valid(receipts: Sequence[Mapping[str, Any]]) -> bool:
    try:
        ledger = _receipt_ledger()
        valid, _detail = ledger.verify_integrity()
        if not valid:
            return False
        ledger_rows = ledger.rows()
    except Exception:
        return False
    if not receipts and not ledger_rows:
        return True

    def identity(row: Mapping[str, Any]) -> tuple[str, str] | None:
        if (
            row.get("schema") != RECEIPT_SCHEMA
            or row.get("event") != INTERACTION_EVENT
        ):
            return None
        receipt_id = row.get("receipt_id")
        receipt_hash = row.get("hash")
        if (
            not isinstance(receipt_id, str)
            or not receipt_id
            or not isinstance(receipt_hash, str)
            or not receipt_hash
        ):
            return None
        return receipt_id, receipt_hash

    stored_identities: list[tuple[str, str]] = []
    for receipt in receipts:
        signed = receipt.get("signed_receipt", receipt)
        if not isinstance(signed, Mapping):
            return False
        value = identity(signed)
        if value is None:
            return False
        stored_identities.append(value)
    ledger_identities: list[tuple[str, str]] = []
    for row in ledger_rows:
        value = identity(row)
        if value is None:
            return False
        ledger_identities.append(value)
    return (
        len(stored_identities) == len(set(stored_identities))
        and len(ledger_identities) == len(set(ledger_identities))
        and set(stored_identities) == set(ledger_identities)
    )


def _policy_readiness_gaps(
    policies: Sequence[Mapping[str, Any]],
) -> list[str]:
    gaps: list[str] = []
    if any(
        not policy["settings"]["require_interaction_disclosure"]
        for policy in policies
    ):
        gaps.append("interaction_disclosure_disabled")
    if any(
        not policy["settings"]["require_machine_readable_marking"]
        for policy in policies
    ):
        gaps.append("machine_readable_marking_disabled")
    if any(not policy.get("model_sha256") for policy in policies):
        gaps.append("unbound_policy_models")
    if any(not policy.get("context_sha256") for policy in policies):
        gaps.append("unbound_policy_contexts")
    if any(
        isinstance(policy.get("metadata"), Mapping)
        and (
            policy["metadata"].get("demo") is True
            or policy["metadata"].get("synthetic") is True
        )
        for policy in policies
    ):
        gaps.append("synthetic_demo_data_present")
    return gaps


def summary() -> dict[str, Any]:
    """Return cockpit-ready evidence coverage and stale-authority counts."""

    _require_enabled()
    tenant = _active_tenant()
    policies = list_policies()
    impacts = list_regulatory_impacts(limit=_MAX_IMPACTS)
    receipt_snapshot = _receipt_assurance_snapshot(
        include_limit=0,
        trust=trusted_public_keys(),
    )
    receipt_count = int(receipt_snapshot["total"])
    verified_receipts = int(receipt_snapshot["verified"])
    unverified_receipts = int(receipt_snapshot["unverified"])
    conversation_chains_valid = bool(
        receipt_snapshot["conversation_chains_valid"]
    )
    receipt_ledger_chain_valid = bool(
        receipt_snapshot["ledger_chain_valid"]
    )
    current_receipts = int(receipt_snapshot["current"])
    stale_receipts = int(receipt_snapshot["stale"])
    impact_counts = {
        status: sum(row.get("status") == status for row in impacts)
        for status in (
            "pending_review",
            "accepted_refreshing",
            "accepted",
            "dismissed",
        )
    }
    gaps: list[str] = []
    if not policies:
        gaps.append("no_current_policy")
    gaps.extend(_policy_readiness_gaps(policies))
    if not receipt_count:
        gaps.append("no_interaction_receipts")
    if stale_receipts:
        gaps.append("stale_interaction_receipts")
    if unverified_receipts:
        gaps.append("unverified_interaction_receipts")
    if not conversation_chains_valid:
        gaps.append("invalid_conversation_receipt_chains")
    if not receipt_ledger_chain_valid:
        gaps.append("invalid_receipt_ledger_chain")
    if impact_counts["pending_review"]:
        gaps.append("pending_regulatory_impacts")
    if impact_counts["accepted_refreshing"]:
        gaps.append("regulatory_impacts_refreshing")
    result = {
        "schema": SUMMARY_SCHEMA,
        "enabled": True,
        "tenant_id": tenant,
        "current_policy_count": len(policies),
        "interaction_receipt_count": receipt_count,
        "current_interaction_receipt_count": current_receipts,
        "stale_interaction_receipt_count": stale_receipts,
        "verified_interaction_receipt_count": verified_receipts,
        "unverified_interaction_receipt_count": unverified_receipts,
        "pending_regulatory_impact_count": impact_counts["pending_review"],
        "refreshing_regulatory_impact_count": impact_counts[
            "accepted_refreshing"
        ],
        "accepted_regulatory_impact_count": impact_counts["accepted"],
        "dismissed_regulatory_impact_count": impact_counts["dismissed"],
        "policies": {"current": len(policies)},
        "interaction_receipts": {
            "total": receipt_count,
            "current": current_receipts,
            "stale": stale_receipts,
            "verified": verified_receipts,
            "unverified": unverified_receipts,
            "conversation_chains_valid": conversation_chains_valid,
            "ledger_chain_valid": receipt_ledger_chain_valid,
            "ledger_total": receipt_snapshot["ledger_total"],
            "missing_governed": receipt_snapshot["missing_governed"],
            "extra_governed": receipt_snapshot["extra_governed"],
            "snapshot_state_hash": receipt_snapshot[
                "snapshot_state_hash"
            ],
        },
        "regulatory_impacts": {
            "total": len(impacts),
            **impact_counts,
        },
        "framework_sources": {
            key: dict(value) for key, value in FRAMEWORK_SOURCES.items()
        },
        "readiness": {
            "ready": not gaps,
            "gaps": gaps,
        },
        "legal_certification": False,
        "compliance_verdict": "not_provided",
        "notice": NON_CERTIFICATION_NOTICE,
    }
    result["summary_sha256"] = _sha256(result)
    return result


def _streaming_collection_digest(
    rows: Sequence[Mapping[str, Any]],
) -> str:
    """Digest an ordered collection without materializing one oversized JSON."""

    digest = hashlib.sha256()
    for row in rows:
        encoded = _canonical_json(row).encode("utf-8")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def _packet_json_size(value: Mapping[str, Any]) -> int:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("assurance packet must be canonical JSON") from exc
    return len(rendered.encode("utf-8"))


def _attestation(
    *,
    packet_id: str,
    packet_sha256: str,
    actor: str,
    generated_at: float,
) -> dict[str, Any]:
    event = {
        "schema": ASSURANCE_PACKET_SCHEMA,
        "event": ASSURANCE_PACKET_EVENT,
        "packet_id": packet_id,
        "packet_sha256": packet_sha256,
        "actor_sha256": _sha256(actor.encode("utf-8")),
        "generated_at": generated_at,
    }
    signed, public_key = _sign_event(
        event,
        path=_packet_path(),
        identity_key="packet_id",
        identity=packet_id,
    )
    return {
        "algorithm": "Ed25519",
        "key_id": signed["key_id"],
        "public_key": public_key,
        "signature": signed["sig"],
        "event_hash": signed["hash"],
        "signed_message": "hex-decoded event_hash",
        "receipt": signed,
    }


def render_assurance_packet(
    *,
    profile: str = "combined",
    actor: str = "gateway",
    packet_id: str | None = None,
    _before_attestation: (
        Callable[[dict[str, Any], str], None] | None
    ) = None,
) -> dict[str, Any]:
    """Render and sign a composite, non-certifying assurance packet."""

    _require_enabled()
    tenant = _active_tenant()
    profile_name = _token(profile, "profile").lower()
    if profile_name not in _PROFILE_SOURCES:
        raise ValueError(
            "profile must be article50_gpai, nist_ai_rmf, "
            "federal_vendor, or combined"
        )
    operator = _required_text(actor, "actor", 256)
    generated_at = time.time()
    logical_packet_id = (
        _required_text(packet_id, "packet_id", 128)
        if packet_id is not None
        else _sha256([tenant, profile_name, generated_at])[:32]
    )
    signed_packet_id = _stable_id("AIP", "packet", logical_packet_id)
    policies = list_policies()
    impacts = list_regulatory_impacts(limit=_MAX_IMPACTS)
    trust = trusted_public_keys()
    receipt_snapshot = _receipt_assurance_snapshot(
        include_limit=_MAX_PACKET_RECEIPTS,
        trust=trust,
    )
    receipts = list(receipt_snapshot["included"])
    source_verified = int(receipt_snapshot["verified"])
    source_unverified = int(receipt_snapshot["unverified"])
    source_conversation_chains_valid = bool(
        receipt_snapshot["conversation_chains_valid"]
    )
    receipt_ledger_chain_valid = bool(
        receipt_snapshot["ledger_chain_valid"]
    )
    stale = int(receipt_snapshot["stale"])
    pending = sum(row.get("status") == "pending_review" for row in impacts)
    refreshing = sum(
        row.get("status") == "accepted_refreshing" for row in impacts
    )
    gaps: list[str] = []
    if not policies:
        gaps.append("no_current_policy")
    gaps.extend(_policy_readiness_gaps(policies))
    if not receipt_snapshot["total"]:
        gaps.append("no_interaction_receipts")
    if stale:
        gaps.append("stale_interaction_receipts")
    if source_unverified:
        gaps.append("unverified_interaction_receipts")
    if not source_conversation_chains_valid:
        gaps.append("invalid_conversation_receipt_chains")
    if not receipt_ledger_chain_valid:
        gaps.append("invalid_receipt_ledger_chain")
    if pending:
        gaps.append("pending_regulatory_impacts")
    if refreshing:
        gaps.append("regulatory_impacts_refreshing")
    sources = {
        key: dict(FRAMEWORK_SOURCES[key])
        for key in _PROFILE_SOURCES[profile_name]
    }
    materialized_source_collections: dict[str, list[dict[str, Any]]] = {
        "policies": policies,
        "regulatory_impacts": impacts,
    }
    included: dict[str, list[dict[str, Any]]] = {
        "policies": policies[:_MAX_PACKET_POLICIES],
        "interaction_receipts": receipts[:_MAX_PACKET_RECEIPTS],
        "regulatory_impacts": impacts[:_MAX_PACKET_IMPACTS],
    }
    source_counts = {
        "policies": len(policies),
        "interaction_receipts": int(receipt_snapshot["total"]),
        "regulatory_impacts": len(impacts),
    }
    source_digests: dict[str, str] = {
        key: _streaming_collection_digest(rows)
        for key, rows in materialized_source_collections.items()
    }
    source_digests["interaction_receipts"] = str(
        receipt_snapshot["source_digest_sha256"]
    )

    def packet_body() -> dict[str, Any]:
        included_counts = {
            key: len(rows) for key, rows in included.items()
        }
        omitted_counts = {
            key: source_counts[key] - included_counts[key]
            for key in source_counts
        }
        packet_gaps = list(gaps)
        if any(omitted_counts.values()):
            packet_gaps.append("packet_window_truncated")
        included_verified, included_unverified = (
            _receipt_verification_counts(
                included["interaction_receipts"],
                trust,
            )
        )
        included_conversation_chains_valid = _conversation_chains_valid(
            included["interaction_receipts"]
        )
        return {
            "schema": ASSURANCE_PACKET_SCHEMA,
            "packet_id": signed_packet_id,
            "generated_at": generated_at,
            "generated_by_sha256": _sha256(operator.encode("utf-8")),
            "tenant_id": tenant,
            "profile": profile_name,
            "framework_sources": sources,
            "policies": included["policies"],
            "interaction_receipts": included["interaction_receipts"],
            "regulatory_impacts": included["regulatory_impacts"],
            "evidence_window": {
                "ordering": {
                    "policies": "policy_id_ascending",
                    "interaction_receipts": "ledger_ordinal_descending",
                    "regulatory_impacts": "created_at_descending",
                },
                "source_counts": source_counts,
                "included_counts": included_counts,
                "omitted_counts": omitted_counts,
                "source_digests_sha256": source_digests,
                "included_digests_sha256": {
                    key: _streaming_collection_digest(rows)
                    for key, rows in included.items()
                },
            },
            "verification": {
                "interaction_receipts_verified": included_verified,
                "interaction_receipts_unverified": included_unverified,
                "source_interaction_receipts_verified": source_verified,
                "source_interaction_receipts_unverified": source_unverified,
                "included_conversation_chains_valid": (
                    included_conversation_chains_valid
                ),
                "source_conversation_chains_valid": (
                    source_conversation_chains_valid
                ),
                "receipt_ledger_chain_valid": receipt_ledger_chain_valid,
                "receipt_ledger_state_hash": receipt_snapshot[
                    "snapshot_state_hash"
                ],
                "receipt_ledger_total": receipt_snapshot["ledger_total"],
                "receipt_ledger_missing_governed": receipt_snapshot[
                    "missing_governed"
                ],
                "receipt_ledger_extra_governed": receipt_snapshot[
                    "extra_governed"
                ],
                "trusted_key_ids": sorted(trust),
            },
            "readiness": {
                "ready": not packet_gaps,
                "gaps": packet_gaps,
            },
            "stores_raw_interaction_content": False,
            "legal_certification": False,
            "compliance_verdict": "not_provided",
            "notice": NON_CERTIFICATION_NOTICE,
        }

    # Leave ample room for packet_sha256 and the signed attestation envelope.
    # If unusually large bounded records still exceed the export budget,
    # deterministically remove the largest tail record while retaining totals
    # and full ordered collection digests.
    target_bytes = _MAX_JSON_BYTES - (16 * 1024)
    body = packet_body()
    while _packet_json_size(body) > target_bytes:
        candidates = [
            (
                len(_canonical_json(rows[-1]).encode("utf-8")),
                key,
            )
            for key, rows in included.items()
            if rows
        ]
        if not candidates:
            raise EvidenceGatewayStateError(
                "assurance packet metadata exceeds the bounded export limit"
            )
        _size, largest_key = max(candidates)
        included[largest_key].pop()
        body = packet_body()
    # Complete the expensive re-scan without the delivery transaction lock.
    # Its own start/end protocol refuses both half-commits and stale views.
    rechecked_receipts = _receipt_assurance_snapshot(
        include_limit=0,
        trust=trust,
    )
    rechecked_collections = {
        "policies": list_policies(),
        "regulatory_impacts": list_regulatory_impacts(
            limit=_MAX_IMPACTS
        ),
    }
    changed = (
        any(
            len(rechecked_collections[key]) != source_counts[key]
            or not hmac.compare_digest(
                _streaming_collection_digest(
                    rechecked_collections[key]
                ),
                source_digests[key],
            )
            for key in rechecked_collections
        )
        or int(rechecked_receipts["total"])
        != source_counts["interaction_receipts"]
        or not hmac.compare_digest(
            str(rechecked_receipts["source_digest_sha256"]),
            source_digests["interaction_receipts"],
        )
        or rechecked_receipts["snapshot_state_hash"]
        != receipt_snapshot["snapshot_state_hash"]
    )
    if (
        changed
        or rechecked_receipts["ledger_chain_valid"]
        is not receipt_ledger_chain_valid
    ):
        raise EvidenceGatewayStateError(
            "evidence records or receipt ledger changed during packet "
            "snapshot; retry export"
        )

    from .file_lock import cross_process_lock

    receipt_path = _receipt_path()
    with _DELIVERY_LOCK:
        with cross_process_lock(
            _identity_transaction_target(receipt_path),
            strict=True,
        ):
            # Keep the final signed-state comparison and attestation adjacent.
            # A new delivery cannot begin between them, while the historical
            # scan above never blocks ingestion.
            final_state = _receipt_ledger().state()
            if not hmac.compare_digest(
                final_state.state_hash,
                str(rechecked_receipts["snapshot_state_hash"]),
            ):
                raise EvidenceGatewayStateError(
                    "evidence records or receipt ledger changed during packet "
                    "snapshot; retry export"
                )
            digest = _sha256(body)
            if _before_attestation is not None:
                # Idempotent HTTP issuance checkpoints the exact unsigned
                # packet before its append-only attestation. A process crash
                # after signing can then recover the identical content rather
                # than re-rendering a different timestamp or evidence window.
                _before_attestation(_public(body), digest)
            attestation = _attestation(
                packet_id=signed_packet_id,
                packet_sha256=digest,
                actor=operator,
                generated_at=generated_at,
            )
    return {
        **body,
        "packet_sha256": digest,
        "attestation": attestation,
    }


def _validate_packet_replay_record(
    record: Mapping[str, Any],
    *,
    status: str,
    replay_id: str,
    tenant: str,
    actor_sha: str,
    profile_name: str,
    idempotency_sha: str,
) -> None:
    if (
        record.get("schema")
        != "lightwork.ai-evidence-packet-replay.v1"
        or record.get("id") != replay_id
        or record.get("status") != status
        or record.get("tenant_id") != tenant
        or record.get("actor_sha256") != actor_sha
        or record.get("profile") != profile_name
        or record.get("idempotency_sha256") != idempotency_sha
    ):
        raise EvidenceGatewayStateError(
            "assurance packet replay authority failed validation"
        )


def _recover_assurance_packet_checkpoint(
    record: Mapping[str, Any],
    *,
    signed_packet_id: str,
    tenant: str,
    profile_name: str,
    actor_sha: str,
    operator: str,
) -> dict[str, Any]:
    """Sign or idempotently recover one exact durable packet checkpoint."""

    raw_body = record.get("packet_body")
    digest = record.get("packet_sha256")
    if not isinstance(raw_body, Mapping) or not isinstance(digest, str):
        raise EvidenceGatewayStateError(
            "assurance packet checkpoint failed validation"
        )
    body = _public(raw_body)
    generated_at = body.get("generated_at")
    if (
        body.get("schema") != ASSURANCE_PACKET_SCHEMA
        or body.get("packet_id") != signed_packet_id
        or body.get("tenant_id") != tenant
        or body.get("profile") != profile_name
        or body.get("generated_by_sha256") != actor_sha
        or body.get("stores_raw_interaction_content") is not False
        or body.get("legal_certification") is not False
        or body.get("compliance_verdict") != "not_provided"
        or body.get("notice") != NON_CERTIFICATION_NOTICE
        or not isinstance(generated_at, (int, float))
        or isinstance(generated_at, bool)
        or not math.isfinite(float(generated_at))
        or float(generated_at) <= 0
        or not hmac.compare_digest(digest, _sha256(body))
    ):
        raise EvidenceGatewayStateError(
            "assurance packet checkpoint failed validation"
        )
    attestation = _attestation(
        packet_id=signed_packet_id,
        packet_sha256=digest,
        actor=operator,
        generated_at=float(generated_at),
    )
    packet = {
        **body,
        "packet_sha256": digest,
        "attestation": attestation,
    }
    if not verify_assurance_packet(packet, expected_tenant_id=tenant):
        raise EvidenceGatewayStateError(
            "recovered assurance packet failed signature validation"
        )
    return packet


def issue_assurance_packet(
    *,
    profile: str = "combined",
    actor: str = "gateway",
    idempotency_key: str,
) -> dict[str, Any]:
    """Issue once and replay the exact signed packet for an HTTP request key."""

    _require_enabled()
    tenant = _active_tenant()
    profile_name = _token(profile, "profile").lower()
    if profile_name not in _PROFILE_SOURCES:
        raise ValueError(
            "profile must be article50_gpai, nist_ai_rmf, "
            "federal_vendor, or combined"
        )
    operator = _required_text(actor, "actor", 256)
    request_key = _required_text(
        idempotency_key,
        "idempotency_key",
        1_024,
    )
    actor_sha = _sha256(operator.encode("utf-8"))
    idempotency_sha = _sha256(request_key.encode("utf-8"))
    replay_id = _stable_id(
        "AIX",
        tenant,
        actor_sha,
        profile_name,
        idempotency_sha,
    )
    signed_packet_id = _stable_id("AIP", "packet", replay_id)

    def validate_request_record(
        record: Mapping[str, Any],
        *,
        status: str,
    ) -> None:
        _validate_packet_replay_record(
            record,
            status=status,
            replay_id=replay_id,
            tenant=tenant,
            actor_sha=actor_sha,
            profile_name=profile_name,
            idempotency_sha=idempotency_sha,
        )

    def replay(record: Mapping[str, Any]) -> dict[str, Any]:
        validate_request_record(record, status="issued")
        packet = record.get("packet")
        if (
            not isinstance(packet, Mapping)
            or record.get("packet_sha256") != packet.get("packet_sha256")
            or not verify_assurance_packet(
                packet,
                expected_tenant_id=tenant,
            )
        ):
            raise EvidenceGatewayStateError(
                "assurance packet replay authority failed validation"
            )
        return {
            "packet": _public(packet),
            "idempotent_replay": True,
        }

    def prepared_packet(record: Mapping[str, Any]) -> dict[str, Any]:
        validate_request_record(record, status="prepared")
        return _recover_assurance_packet_checkpoint(
            record,
            signed_packet_id=signed_packet_id,
            tenant=tenant,
            profile_name=profile_name,
            actor_sha=actor_sha,
            operator=operator,
        )

    def complete_prepared(
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        """CAS a prepared packet to issued, recovering cross-worker races."""

        current = dict(record)
        for _attempt in range(4):
            if current.get("status") == "issued":
                return replay(current)
            packet = prepared_packet(current)
            revision = current.get("revision")
            if (
                not isinstance(revision, int)
                or isinstance(revision, bool)
                or revision < 1
            ):
                raise EvidenceGatewayStateError(
                    "assurance packet checkpoint revision is invalid"
                )

            def issue(
                prepared: dict[str, Any],
                issued_packet: dict[str, Any] = packet,
            ) -> None:
                validate_request_record(prepared, status="prepared")
                if (
                    prepared.get("packet_sha256")
                    != issued_packet["packet_sha256"]
                    or prepared.get("packet_body")
                    != {
                        key: value
                        for key, value in issued_packet.items()
                        if key not in {"packet_sha256", "attestation"}
                    }
                ):
                    raise EvidenceGatewayStateError(
                        "assurance packet checkpoint changed before commit"
                    )
                prepared.pop("packet_body", None)
                prepared["packet"] = issued_packet
                prepared["status"] = "issued"

            try:
                saved = _PACKET_REPLAYS.update(
                    replay_id,
                    issue,
                    expected_revision=revision,
                    action="assurance_packet_issued",
                    actor=operator,
                )
            except RecordConflict:
                recovered = _PACKET_REPLAYS.get(replay_id)
                if recovered is None:
                    raise EvidenceGatewayStateError(
                        "assurance packet replay authority could not be "
                        "recovered"
                    ) from None
                current = recovered
                continue
            if saved is None:
                raise EvidenceGatewayStateError(
                    "assurance packet replay authority disappeared during commit"
                )
            return {
                "packet": _public(packet),
                "idempotent_replay": False,
            }
        raise EvidenceGatewayStateError(
            "assurance packet replay authority remained contended"
        )

    from .file_lock import cross_process_lock

    with _PACKET_ISSUE_LOCK:
        with cross_process_lock(
            _identity_transaction_target(_packet_path()).with_name(
                "assurance-packet-requests.transaction"
            ),
            strict=True,
        ):
            existing = _PACKET_REPLAYS.get(replay_id)
            if existing is not None:
                return (
                    replay(existing)
                    if existing.get("status") == "issued"
                    else complete_prepared(existing)
                )

            checkpoint: dict[str, dict[str, Any]] = {}

            def prepare(
                packet_body: dict[str, Any],
                packet_sha256: str,
            ) -> None:
                checkpoint["record"] = _PACKET_REPLAYS.create(
                    {
                        "id": replay_id,
                        "schema": "lightwork.ai-evidence-packet-replay.v1",
                        "status": "prepared",
                        "tenant_id": tenant,
                        "actor_sha256": actor_sha,
                        "profile": profile_name,
                        "idempotency_sha256": idempotency_sha,
                        "packet_sha256": packet_sha256,
                        "packet_body": packet_body,
                    },
                    action="assurance_packet_prepared",
                    actor=operator,
                )

            try:
                render_assurance_packet(
                    profile=profile_name,
                    actor=operator,
                    packet_id=replay_id,
                    _before_attestation=prepare,
                )
            except RecordConflict:
                recovered = _PACKET_REPLAYS.get(replay_id)
                if recovered is None:
                    raise EvidenceGatewayStateError(
                        "assurance packet replay authority could not be "
                        "recovered"
                    ) from None
                return (
                    replay(recovered)
                    if recovered.get("status") == "issued"
                    else complete_prepared(recovered)
                )
            prepared = checkpoint.get("record")
            if prepared is None:
                raise EvidenceGatewayStateError(
                    "assurance packet was signed without a durable checkpoint"
                )
            return complete_prepared(prepared)


def _verify_packet_evidence(
    body: Mapping[str, Any],
    *,
    registry: Mapping[str, str],
    expected: str,
) -> bool:
    interaction_receipts = body.get("interaction_receipts")
    verification = body.get("verification")
    evidence_window = body.get("evidence_window")
    if not isinstance(interaction_receipts, list) or not isinstance(
        verification,
        Mapping,
    ) or not isinstance(evidence_window, Mapping):
        return False
    embedded_collections = {
        "policies": body.get("policies"),
        "interaction_receipts": interaction_receipts,
        "regulatory_impacts": body.get("regulatory_impacts"),
    }
    if any(
        not isinstance(rows, list)
        for rows in embedded_collections.values()
    ):
        return False
    source_counts = evidence_window.get("source_counts")
    included_counts = evidence_window.get("included_counts")
    omitted_counts = evidence_window.get("omitted_counts")
    source_digests = evidence_window.get("source_digests_sha256")
    included_digests = evidence_window.get(
        "included_digests_sha256"
    )
    window_maps = (
        source_counts,
        included_counts,
        omitted_counts,
        source_digests,
        included_digests,
    )
    if any(not isinstance(value, Mapping) for value in window_maps):
        return False
    names = set(embedded_collections)
    if any(set(value) != names for value in window_maps):
        return False
    for name, rows in embedded_collections.items():
        source_count = source_counts[name]
        included_count = included_counts[name]
        omitted_count = omitted_counts[name]
        if (
            isinstance(source_count, bool)
            or not isinstance(source_count, int)
            or isinstance(included_count, bool)
            or not isinstance(included_count, int)
            or isinstance(omitted_count, bool)
            or not isinstance(omitted_count, int)
            or source_count < 0
            or included_count != len(rows)
            or omitted_count != source_count - included_count
            or omitted_count < 0
        ):
            return False
        included_digest = _digest(
            included_digests[name],
            f"{name} included digest",
        )
        source_digest = _digest(
            source_digests[name],
            f"{name} source digest",
        )
        if not hmac.compare_digest(
            included_digest,
            _streaming_collection_digest(rows),
        ) or (
            omitted_count == 0
            and not hmac.compare_digest(
                source_digest,
                included_digest,
            )
        ):
            return False
    embedded_verified = sum(
        verify_interaction_receipt(
            item,
            trusted_public_keys=registry,
            expected_tenant_id=expected,
        )
        for item in interaction_receipts
    )
    embedded_unverified = len(interaction_receipts) - embedded_verified
    claimed_trusted_ids = verification.get("trusted_key_ids")
    if (
        not isinstance(claimed_trusted_ids, list)
        or claimed_trusted_ids != sorted(set(claimed_trusted_ids))
        or any(
            not isinstance(key_id, str)
            or _trusted_key(key_id, registry) is None
            for key_id in claimed_trusted_ids
        )
    ):
        return False
    source_receipt_count = source_counts["interaction_receipts"]
    source_verified = verification.get(
        "source_interaction_receipts_verified"
    )
    source_unverified = verification.get(
        "source_interaction_receipts_unverified"
    )
    if (
        isinstance(source_verified, bool)
        or not isinstance(source_verified, int)
        or isinstance(source_unverified, bool)
        or not isinstance(source_unverified, int)
        or source_verified < 0
        or source_unverified < 0
        or source_verified + source_unverified != source_receipt_count
        or not isinstance(
            verification.get("source_conversation_chains_valid"),
            bool,
        )
        or not isinstance(
            verification.get("receipt_ledger_chain_valid"),
            bool,
        )
    ):
        return False
    ledger_fields = {
        "receipt_ledger_state_hash",
        "receipt_ledger_total",
        "receipt_ledger_missing_governed",
        "receipt_ledger_extra_governed",
    }
    present_ledger_fields = ledger_fields.intersection(verification)
    if present_ledger_fields and present_ledger_fields != ledger_fields:
        return False
    if present_ledger_fields:
        ledger_total = verification["receipt_ledger_total"]
        ledger_missing = verification[
            "receipt_ledger_missing_governed"
        ]
        ledger_extra = verification["receipt_ledger_extra_governed"]
        if (
            isinstance(ledger_total, bool)
            or not isinstance(ledger_total, int)
            or ledger_total < 0
            or isinstance(ledger_missing, bool)
            or not isinstance(ledger_missing, int)
            or ledger_missing < 0
            or isinstance(ledger_extra, bool)
            or not isinstance(ledger_extra, int)
            or ledger_extra < 0
            or ledger_total != source_receipt_count + ledger_missing
        ):
            return False
        _digest(
            verification["receipt_ledger_state_hash"],
            "receipt ledger state hash",
        )
        if verification["receipt_ledger_chain_valid"] and (
            ledger_total != source_receipt_count
            or ledger_missing
            or ledger_extra
        ):
            return False
    embedded_chains_valid = _conversation_chains_valid(
        interaction_receipts
    )
    if (
        verification.get("interaction_receipts_verified")
        != embedded_verified
        or verification.get("interaction_receipts_unverified")
        != embedded_unverified
        or verification.get("included_conversation_chains_valid")
        is not embedded_chains_valid
    ):
        return False
    readiness = body.get("readiness")
    if not isinstance(readiness, Mapping):
        return False
    readiness_gaps = readiness.get("gaps")
    any_omitted = any(
        count > 0 for count in omitted_counts.values()
    )
    if (
        not isinstance(readiness_gaps, list)
        or any(
            not isinstance(value, str) for value in readiness_gaps
        )
        or (
            "packet_window_truncated" in readiness_gaps
        )
        is not any_omitted
        or readiness.get("ready") is not (not readiness_gaps)
    ):
        return False
    return True


def verify_assurance_packet(
    packet: Mapping[str, Any],
    *,
    trusted_public_keys: Mapping[str, str] | None = None,
    expected_tenant_id: str | None = None,
) -> bool:
    """Verify a composite packet against external/protected trust roots."""

    try:
        if not isinstance(packet, Mapping):
            return False
        body = dict(packet)
        digest = body.pop("packet_sha256")
        attestation = body.pop("attestation")
        if (
            body.get("schema") != ASSURANCE_PACKET_SCHEMA
            or body.get("stores_raw_interaction_content") is not False
            or not isinstance(digest, str)
            or not hmac.compare_digest(digest, _sha256(body))
            or not isinstance(attestation, Mapping)
        ):
            return False
        expected = expected_tenant_id or _active_tenant()
        if body.get("tenant_id") != expected:
            return False
        receipt = attestation.get("receipt")
        if not isinstance(receipt, Mapping):
            return False
        if (
            receipt.get("event") != ASSURANCE_PACKET_EVENT
            or receipt.get("packet_id") != body.get("packet_id")
            or receipt.get("packet_sha256") != digest
            or receipt.get("hash") != attestation.get("event_hash")
            or receipt.get("sig") != attestation.get("signature")
            or receipt.get("key_id") != attestation.get("key_id")
            or attestation.get("algorithm") != "Ed25519"
            or attestation.get("signed_message") != "hex-decoded event_hash"
        ):
            return False
        registry = (
            globals()["trusted_public_keys"]()
            if trusted_public_keys is None
            else trusted_public_keys
        )
        if not isinstance(registry, Mapping):
            return False
        trusted = _trusted_key(receipt.get("key_id"), registry)
        disclosed = attestation.get("public_key")
        if (
            trusted is None
            or not isinstance(disclosed, str)
            or not hmac.compare_digest(trusted, disclosed.strip().lower())
        ):
            return False
        if not _verify_signed_row(receipt, trusted_keys=registry):
            return False
        return _verify_packet_evidence(body, registry=registry, expected=expected)
    except (EvidenceGatewayError, KeyError, TypeError, ValueError):
        return False


def seed_demo(*, actor: str = "demo") -> dict[str, Any]:
    """Idempotently seed a no-network synthetic evidence-gateway scenario."""

    _require_enabled()
    _active_tenant()
    operator = _required_text(actor, "actor", 256)
    policy_id = "evidence-ready-demo"
    demo_impact_id = _stable_id("AII", "evidence-ready-demo-impact-v1")
    existing_policies = list_policies()
    # A demo tenant may contain only the single deterministic demo receipt.
    # A bounded first page is therefore sufficient and avoids a tenant-wide
    # materialization even if an operator calls this on the wrong namespace.
    existing_receipts = list_interaction_receipts(limit=2)
    existing_impacts = list_regulatory_impacts(limit=_MAX_IMPACTS)
    if (
        any(policy.get("policy_id") != policy_id for policy in existing_policies)
        or any(
            receipt.get("policy_id") != policy_id
            for receipt in existing_receipts
        )
        or any(impact.get("id") != demo_impact_id for impact in existing_impacts)
    ):
        raise EvidenceGatewayStateError(
            "synthetic demo requires an empty or dedicated demo tenant"
        )
    model_digest = _sha256("synthetic-demo-model-v1")
    context_digest = _sha256("synthetic-demo-context-v1")
    existing_policy = get_policy(policy_id)
    if existing_policy is None:
        policy = upsert_policy(
            policy_id,
            actor=operator,
            model_sha256=model_digest,
            context_sha256=context_digest,
            metadata={
                "demo": True,
                "synthetic": True,
                "network_access": False,
            },
        )
    else:
        policy = existing_policy
        if (
            policy["model_sha256"] != model_digest
            or policy["context_sha256"] != context_digest
            or policy["metadata"].get("demo") is not True
        ):
            raise EvidenceGatewayStateError(
                "synthetic demo policy identity is already in use"
            )
    delivery = deliver_text(
        "Synthetic evidence-ready response.",
        input_text="Synthetic evidence-ready request.",
        conversation_id="evidence-ready-demo-conversation-v1",
        idempotency_key="evidence-ready-demo-interaction-v1",
        actor=operator,
        policy_id=policy_id,
        model_sha256=model_digest,
        context_sha256=context_digest,
    )
    article_source = FRAMEWORK_SOURCES["ec_article_50"]["url"]
    impact = record_regulatory_impact(
        "synthetic-article-50-guidance-alert",
        alert_revision=1,
        content_sha256=_sha256(
            {
                "synthetic": True,
                "source": article_source,
                "scope": "demo",
            }
        ),
        citations=[
            {
                "source_name": "European Commission",
                "retrieval_url": article_source,
                "record_url": article_source,
                "retrieved_at": "2026-07-20T00:00:00Z",
                "content_sha256": _sha256(
                    "synthetic-demo-reference-not-source-content"
                ),
                "source_format": "html",
                "parser_version": "synthetic-demo-v1",
                "acquisition": "synthetic_demo",
                "acquired_by": "lightwork",
                "official_citation": (
                    "European Commission Article 50 transparency guidance "
                    "(synthetic demo reference)"
                ),
            }
        ],
        affected_policy_ids=(policy_id,),
        control_ids=("eu_ai_act_article_50",),
        match_reasons=("deterministic synthetic scope match",),
        actor=operator,
        impact_id="evidence-ready-demo-impact-v1",
    )
    receipt = delivery["receipt"]
    return {
        "schema": "lightwork.ai-evidence-demo-seed.v1",
        "synthetic": True,
        "network_access": False,
        "policy_id": policy["id"],
        "receipt_id": receipt["receipt_id"],
        "regulatory_impact_id": impact["id"],
        "idempotent_replay": delivery["idempotent_replay"],
        "summary": summary(),
    }


__all__ = [
    "ASSURANCE_PACKET_SCHEMA",
    "ConversationOrderError",
    "DEFAULT_DISCLOSURE_TEXT",
    "DEFAULT_MACHINE_MARKER",
    "DEFAULT_VISIBLE_MARKER",
    "EvidenceGatewayDisabled",
    "EvidenceGatewayError",
    "EvidenceGatewaySnapshotIndeterminate",
    "EvidenceGatewayStateError",
    "FRAMEWORK_SOURCES",
    "NON_CERTIFICATION_NOTICE",
    "POLICY_SCHEMA",
    "RECEIPT_SCHEMA",
    "REGULATORY_IMPACT_SCHEMA",
    "UnsupportedMediaMarking",
    "deliver_text",
    "enabled",
    "get_interaction_receipt",
    "get_policy",
    "get_regulatory_impact",
    "issue_assurance_packet",
    "list_interaction_receipts",
    "list_interaction_receipts_page",
    "list_policies",
    "list_regulatory_impacts",
    "list_regulatory_impacts_page",
    "record_regulatory_impact",
    "render_assurance_packet",
    "review_regulatory_impact",
    "seed_demo",
    "summary",
    "trusted_public_keys",
    "upsert_policy",
    "verify_assurance_packet",
    "verify_interaction_receipt",
]
