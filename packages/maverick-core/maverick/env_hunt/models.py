"""Vendor-neutral contracts for environment telemetry and governed response."""
from __future__ import annotations

import datetime as dt
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from ..platform_hunt.models import EvidenceRef, canonical_digest, deterministic_id

_RESPONSE_PARAMETER_BYTES = 32 * 1024
_RESPONSE_PARAMETER_DEPTH = 6
_RESPONSE_PARAMETER_NODES = 512
_RESPONSE_CONTAINER_ITEMS = 64
_RESPONSE_STRING_CHARS = 4096
_RESPONSE_FORBIDDEN_KEYS = {
    "authorization", "body", "content", "credential", "credentials", "data",
    "event", "events", "log", "logs", "password", "passwd", "payload",
    "private_key", "raw", "secret", "secrets", "telemetry", "token", "tokens",
}
_RESPONSE_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"authorization\s*:\s*\S+(?:\s+\S+)?|"
    r"bearer\s+[a-z0-9._~+/=-]{8,}|"
    r"(?:api[_-]?key|api[_-]?token|password|passwd|secret|credential)\s*[=:]\s*"
    r"(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s,;]+))"
)
_EXECUTOR_RE = re.compile(r"[a-z][a-z0-9_.-]{0,119}\Z")


def redact_credential_text(value: object, *, limit: int = 4096) -> str:
    """Return bounded derived text with detectable credentials removed.

    Connector fields are untrusted customer telemetry.  Although raw rows are
    intentionally ephemeral, selected structural fields become evidence quotes
    and investigation timeline entries.  Scrub them *before* either derived
    representation is built so a credential cannot cross that persistence seam.

    The shared detector covers provider keys, JWTs, connection strings, private
    keys, and environment assignments.  The local expression additionally
    catches bare bearer tokens and lower-case ``password=...``-style fragments
    commonly found in sensor fields.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("derived text limit must be a positive integer")
    text = str(value or "")
    from ..safety.secret_detector import redact

    scrubbed, _matches = redact(text)
    scrubbed = _RESPONSE_SECRET_VALUE_RE.sub("[REDACTED:credential]", scrubbed)
    return scrubbed[:limit]


def credential_text_detected(value: object) -> bool:
    """Whether ``value`` contains credential material the derived store rejects."""
    text = str(value or "")
    return redact_credential_text(text, limit=max(1, len(text) + 1)) != text


def validate_response_parameters(value: dict[str, Any] | None) -> dict[str, Any]:
    """Return a detached, bounded JSON mapping with no raw/credential material."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("response parameters must be an object")
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, allow_nan=False, separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("response parameters must be finite JSON values") from exc
    if len(encoded) > _RESPONSE_PARAMETER_BYTES:
        raise ValueError("response parameters exceed the 32 KiB limit")
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _RESPONSE_PARAMETER_NODES:
            raise ValueError("response parameters are too structurally complex")
        if depth > _RESPONSE_PARAMETER_DEPTH:
            raise ValueError("response parameters exceed the maximum nesting depth")
        if isinstance(current, dict):
            if len(current) > _RESPONSE_CONTAINER_ITEMS:
                raise ValueError("response parameters have too many object keys")
            for key, nested in current.items():
                if not isinstance(key, str) or not key or len(key) > 120:
                    raise ValueError("response parameter keys must be short strings")
                normalized = key.strip().lower().replace("-", "_")
                parts = {part for part in normalized.split("_") if part}
                if normalized in _RESPONSE_FORBIDDEN_KEYS or _RESPONSE_FORBIDDEN_KEYS.intersection(
                    parts
                ):
                    raise ValueError(
                        "raw telemetry and credentials are forbidden in response parameters"
                    )
                stack.append((nested, depth + 1))
        elif isinstance(current, list):
            if len(current) > _RESPONSE_CONTAINER_ITEMS:
                raise ValueError("response parameters contain an oversized array")
            stack.extend((nested, depth + 1) for nested in current)
        elif isinstance(current, str):
            if len(current) > _RESPONSE_STRING_CHARS:
                raise ValueError("response parameter strings are too long")
            if _RESPONSE_SECRET_VALUE_RE.search(current):
                raise ValueError("credential-like response parameter values are forbidden")
        elif current is not None and not isinstance(current, (bool, int, float)):
            raise ValueError("response parameters contain an unsupported value")
    return json.loads(encoded.decode("utf-8"))


def parse_timestamp(value: object) -> float:
    if isinstance(value, bool):
        raise ValueError("telemetry timestamp is invalid")
    if isinstance(value, (int, float)):
        timestamp = float(value)
    elif isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            timestamp = float(text)
        except ValueError:
            try:
                timestamp = dt.datetime.fromisoformat(text).timestamp()
            except ValueError as exc:
                raise ValueError("telemetry timestamp is invalid") from exc
    else:
        raise ValueError("telemetry timestamp is invalid")
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("telemetry timestamp must be finite and non-negative")
    return timestamp


@dataclass(frozen=True)
class TelemetryEvent:
    event_id: str
    source: str
    observed_at: float
    category: str
    action: str
    principal: str = ""
    target: str = ""
    outcome: str = ""
    tenant: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        raw_event_id = str(self.event_id or "")
        event_id = redact_credential_text(raw_event_id, limit=256)
        if event_id != raw_event_id:
            # Preserve deterministic de-duplication without retaining the
            # credential-bearing producer id itself.
            event_id = deterministic_id("env_redacted", raw_event_id)
        object.__setattr__(self, "event_id", event_id)
        object.__setattr__(self, "source", redact_credential_text(self.source, limit=120))
        object.__setattr__(self, "category", redact_credential_text(self.category, limit=240))
        object.__setattr__(self, "action", redact_credential_text(self.action, limit=1000))
        object.__setattr__(self, "principal", redact_credential_text(self.principal, limit=1000))
        object.__setattr__(self, "target", redact_credential_text(self.target, limit=1000))
        object.__setattr__(self, "outcome", redact_credential_text(self.outcome, limit=500))
        object.__setattr__(self, "tenant", redact_credential_text(self.tenant, limit=240))
        if not self.event_id or not self.source or not self.category or not self.action:
            raise ValueError("telemetry events require identity, source, category, and action")
        parse_timestamp(self.observed_at)

    @classmethod
    def from_mapping(cls, row: dict[str, Any]) -> TelemetryEvent:
        """Normalize an already vendor-neutral event mapping."""
        structural = {
            "event_id", "id", "source", "observed_at", "timestamp", "ts",
            "category", "kind", "action", "principal", "actor", "user",
            "target", "resource", "outcome", "status", "tenant", "attributes",
        }
        nested = row.get("attributes")
        attributes = dict(nested) if isinstance(nested, dict) else {}
        attributes.update({str(key): value for key, value in row.items() if key not in structural})
        source = str(row.get("source", "generic"))
        timestamp = parse_timestamp(
            row.get("observed_at", row.get("timestamp", row.get("ts", 0))),
        )
        action = str(row.get("action", row.get("kind", "event")))
        event_id = str(row.get("event_id", row.get("id", "")))
        if not event_id:
            event_id = deterministic_id("env", source, row)
        return cls(
            event_id=event_id,
            source=source,
            observed_at=timestamp,
            category=str(row.get("category", row.get("kind", "event"))),
            action=action,
            principal=str(row.get("principal", row.get("actor", row.get("user", "")))),
            target=str(row.get("target", row.get("resource", ""))),
            outcome=str(row.get("outcome", row.get("status", ""))),
            tenant=str(row.get("tenant", "")),
            attributes=attributes,
        )

    def evidence(self, quote: str = "") -> EvidenceRef:
        payload = {
            "event_id": self.event_id,
            "source": self.source,
            "observed_at": self.observed_at,
            "category": self.category,
            "action": self.action,
            "principal": self.principal,
            "target": self.target,
            "outcome": self.outcome,
            "tenant": self.tenant,
            "attributes": self.attributes,
        }
        return EvidenceRef(
            event_id=self.event_id,
            source=self.source,
            observed_at=self.observed_at,
            sha256=canonical_digest(payload),
            quote=quote[:320],
        )


@dataclass(frozen=True)
class QueryRequest:
    start: float
    end: float
    query: str = "*"
    filters: dict[str, Any] = field(default_factory=dict)
    limit: int = 1000
    read_only: bool = True

    def __post_init__(self) -> None:
        start = parse_timestamp(self.start)
        end = parse_timestamp(self.end)
        if end < start:
            raise ValueError("query end must not precede start")
        if not 1 <= self.limit <= 10_000:
            raise ValueError("query limit must be between 1 and 10000")
        if self.read_only is not True:
            raise ValueError("environment-hunt connectors are read-only")
        forbidden = ("secret", "password", "passwd", "token", "credential", "authorization")
        for key in self.filters:
            lowered = str(key).lower()
            if any(marker in lowered for marker in forbidden):
                raise ValueError("credentials must not be placed in query filters")
        if re.search(
            r"(?i)(?:authorization\s*:|bearer\s+[a-z0-9._-]{8,}|"
            r"(?:api[_-]?token|password|passwd|secret)\s*[=:]\s*\S+)",
            self.query,
        ):
            raise ValueError("credentials must not be embedded in connector queries")

    @property
    def digest(self) -> str:
        return canonical_digest({
            "start": self.start,
            "end": self.end,
            "query": self.query,
            "filters": self.filters,
            "limit": self.limit,
        })


@dataclass(frozen=True)
class IngestionBatch:
    connector: str
    query_sha256: str
    events: tuple[TelemetryEvent, ...]
    received: int
    discarded: int
    audited: bool
    raw_persisted: bool = False


@dataclass(frozen=True)
class ResponseProposal:
    proposal_id: str
    action: str
    target: str
    reason: str
    evidence: tuple[EvidenceRef, ...]
    parameters: dict[str, Any] = field(default_factory=dict)
    executor: str = ""
    audit_accepted: bool = False

    def __post_init__(self) -> None:
        if self.action not in {
            "isolate_host", "disable_identity", "disable_key", "rotate_credential",
            "block_destination", "revoke_session",
        }:
            raise ValueError("response action is not on the defensive allowlist")
        if not self.target or not self.evidence:
            raise ValueError("response proposals require a target and evidence")
        if len(self.target) > 1000 or not self.reason or len(self.reason) > 4000:
            raise ValueError("response proposal target or reason is invalid")
        if len(self.evidence) > 100:
            raise ValueError("response proposals cite at most 100 evidence items")
        normalized_executor = str(self.executor).strip().lower()
        if normalized_executor and not _EXECUTOR_RE.fullmatch(normalized_executor):
            raise ValueError("response executor must be a lowercase identifier")
        object.__setattr__(self, "executor", normalized_executor)
        object.__setattr__(self, "parameters", validate_response_parameters(self.parameters))

    @classmethod
    def build(
        cls,
        action: str,
        target: str,
        reason: str,
        evidence: tuple[EvidenceRef, ...],
        parameters: dict[str, Any] | None = None,
        *,
        executor: str = "",
    ) -> ResponseProposal:
        safe_parameters = validate_response_parameters(parameters)
        normalized_executor = str(executor).strip().lower()
        return cls(
            proposal_id=deterministic_id(
                "response", action, target, tuple(item.event_id for item in evidence),
                safe_parameters, normalized_executor,
            ),
            action=action,
            target=target,
            reason=reason,
            evidence=evidence,
            parameters=safe_parameters,
            executor=normalized_executor,
        )

    @property
    def digest(self) -> str:
        return canonical_digest({
            "proposal_id": self.proposal_id,
            "action": self.action,
            "target": self.target,
            "reason": self.reason,
            "evidence": self.evidence,
            "parameters": self.parameters,
            "executor": self.executor,
            "audit_accepted": self.audit_accepted,
        })


@dataclass(frozen=True)
class GovernedApproval:
    proposal_id: str
    proposal_sha256: str
    approval_id: str
    approved_by: str
    signature: str = ""
    executor: str = ""


@dataclass(frozen=True)
class ResponseReceipt:
    proposal_id: str
    approval_id: str
    executor: str
    outcome: str
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.proposal_id or not self.approval_id or not self.executor or not self.outcome:
            raise ValueError("response receipt is incomplete")
        object.__setattr__(self, "executor", self.executor.strip().lower())
        object.__setattr__(self, "details", validate_response_parameters(self.details))


__all__ = [
    "GovernedApproval",
    "IngestionBatch",
    "QueryRequest",
    "ResponseProposal",
    "ResponseReceipt",
    "TelemetryEvent",
    "parse_timestamp",
    "validate_response_parameters",
]
