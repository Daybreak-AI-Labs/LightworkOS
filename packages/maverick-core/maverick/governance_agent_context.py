"""Authoritative, bounded cross-suite context for packaged governance agents.

The packaged governance-agent engine intentionally accepts exact context items
instead of reaching into product databases itself.  This module supplies the
missing stock projection contract without turning an agent into a second data
authority:

* source readers remain the authorities for their own tenant-local records;
* every projected record pins its source revision and integrity digest;
* every source is read twice and a changed authority fails closed;
* absent, disabled, partial, and truncated sources are represented explicitly;
* raw source records are never persisted here; and
* preview references are resolved against the *current* source digest, so a
  stale preview cannot be submitted as current context.

Readers are injected because source stores live in several product packages.
The dashboard production composition binds those readers to the existing
stores.  This core module performs only validation, canonicalization, bounds,
stability verification, and context-item construction.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from . import governance_agents
from .paths import canonical_tenant_id

PROJECTION_SCHEMA = "lightwork.governance-agent.cross-suite-projection.v1"
SOURCE_CAPTURE_SCHEMA = "lightwork.governance-agent.source-capture.v1"
READINESS_SCHEMA = "lightwork.governance-agent.context-readiness.v1"
REFERENCE_PREFIX = "xsp."

AVAILABILITY = frozenset({"available", "partial", "unavailable"})
UNAVAILABILITY_REASONS = frozenset(
    {
        "authority_unavailable",
        "feature_disabled",
        "integrity_unverified",
        "not_configured",
        "record_limit",
        "source_error",
        "store_absent",
    }
)

_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_MAX_CANONICAL_BYTES = 16 * 1024 * 1024
_MAX_SOURCE_DEFINITIONS = 64
_MAX_RECORDS_PER_SOURCE = 500
_MAX_CONTEXT_ITEMS = 100
_MAX_TOTAL_BYTES = 10 * 1024 * 1024
_MAX_RECORD_PROJECTION_BYTES = 64 * 1024


class GovernanceContextProjectionError(governance_agents.GovernanceAgentError):
    """Base cross-suite projection failure."""


class GovernanceContextProjectionConfigError(
    GovernanceContextProjectionError,
    governance_agents.GovernanceAgentConfigError,
):
    """The projection is disabled or cannot establish source authority."""


class GovernanceContextProjectionValidationError(
    GovernanceContextProjectionError,
    governance_agents.GovernanceAgentValidationError,
):
    """A source reader returned material outside the closed contract."""


class GovernanceContextProjectionConflict(
    GovernanceContextProjectionError,
    governance_agents.GovernanceAgentConflict,
):
    """A source changed while it was being projected or after preview."""


class SourceUnavailable(GovernanceContextProjectionError):
    """A reader's explicit, non-sensitive source-availability result."""

    def __init__(self, reason_code: str) -> None:
        if reason_code not in UNAVAILABILITY_REASONS:
            raise GovernanceContextProjectionValidationError(
                "source availability reason is unsupported"
            )
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical(value: object, *, maximum: int = _MAX_CANONICAL_BYTES) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise GovernanceContextProjectionValidationError(
            "cross-suite context is not canonical JSON"
        ) from exc
    if not 1 <= len(encoded) <= maximum:
        raise GovernanceContextProjectionValidationError(
            "cross-suite context exceeds its byte bound"
        )
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise GovernanceContextProjectionValidationError(
            f"{label} must be a bounded opaque identifier"
        )
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise GovernanceContextProjectionValidationError(
            f"{label} must be a SHA-256 digest"
        )
    return value


def _revision(value: object, label: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= 2_147_483_647
    ):
        raise GovernanceContextProjectionValidationError(
            f"{label} must be a positive bounded revision"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or float(value) < 0
    ):
        raise GovernanceContextProjectionValidationError(
            f"{label} must be a finite timestamp"
        )
    return float(value)


@dataclass(frozen=True, slots=True)
class GovernanceContextProjectionSettings:
    """Restrictive tenant settings for the stock projection."""

    enable: bool = False
    max_records_per_source: int = 100
    max_context_items: int = 32
    max_total_bytes: int = 2 * 1024 * 1024
    max_record_projection_bytes: int = 16 * 1024
    enabled_agent_kinds: tuple[str, ...] = tuple(sorted(governance_agents.AGENT_KINDS))

    def __post_init__(self) -> None:
        if not isinstance(self.enable, bool):
            raise GovernanceContextProjectionConfigError(
                "context projection enable must be boolean"
            )
        values = (
            (
                self.max_records_per_source,
                1,
                _MAX_RECORDS_PER_SOURCE,
                "max_records_per_source",
            ),
            (self.max_context_items, 1, _MAX_CONTEXT_ITEMS, "max_context_items"),
            (self.max_total_bytes, 1_024, _MAX_TOTAL_BYTES, "max_total_bytes"),
            (
                self.max_record_projection_bytes,
                256,
                _MAX_RECORD_PROJECTION_BYTES,
                "max_record_projection_bytes",
            ),
        )
        for value, minimum, maximum, label in values:
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise GovernanceContextProjectionConfigError(
                    f"context projection {label} is outside its bound"
                )
        if (
            not isinstance(self.enabled_agent_kinds, tuple)
            or not self.enabled_agent_kinds
            or self.enabled_agent_kinds
            != tuple(sorted(set(self.enabled_agent_kinds)))
            or any(
                kind not in governance_agents.AGENT_KINDS
                for kind in self.enabled_agent_kinds
            )
        ):
            raise GovernanceContextProjectionConfigError(
                "context projection enabled-agent authority is invalid"
            )

    @classmethod
    def from_mapping(
        cls,
        config: Mapping[str, Any],
    ) -> GovernanceContextProjectionSettings:
        if not isinstance(config, Mapping):
            raise GovernanceContextProjectionConfigError(
                "context projection configuration is unavailable"
            )
        table = config.get("governance_agents")
        if not isinstance(table, Mapping):
            raise GovernanceContextProjectionConfigError(
                "governance-agent configuration is unavailable"
            )
        projection_enabled = table.get("context_projection_enable", False)
        if projection_enabled is True and table.get("enable") is not True:
            raise GovernanceContextProjectionConfigError(
                "context projection requires packaged governance agents"
            )
        raw_agent_kinds = table.get("enabled_agents")
        if raw_agent_kinds is None:
            enabled_agent_kinds = tuple(sorted(governance_agents.AGENT_KINDS))
        elif isinstance(raw_agent_kinds, (list, tuple)):
            normalized_agent_kinds = tuple(raw_agent_kinds)
            enabled_agent_kinds = (
                tuple(sorted(normalized_agent_kinds))
                if all(isinstance(kind, str) for kind in normalized_agent_kinds)
                and len(normalized_agent_kinds) == len(set(normalized_agent_kinds))
                else ()
            )
        else:
            enabled_agent_kinds = ()
        allowed = {
            "context_projection_enable": "enable",
            "context_projection_max_records_per_source": "max_records_per_source",
            "context_projection_max_context_items": "max_context_items",
            "context_projection_max_total_bytes": "max_total_bytes",
            "context_projection_max_record_bytes": "max_record_projection_bytes",
        }
        values = {
            target: table[source]
            for source, target in allowed.items()
            if source in table
        }
        values["enabled_agent_kinds"] = enabled_agent_kinds
        try:
            return cls(**values)
        except TypeError as exc:
            raise GovernanceContextProjectionConfigError(
                "context projection configuration is invalid"
            ) from exc


@dataclass(frozen=True, slots=True)
class AuthoritativeContextRecord:
    """One safe source-owned record projection with exact authority pins."""

    tenant_id: str
    record_id: str
    revision: int
    updated_at: float
    authority_sha256: str
    projection: Mapping[str, object]

    def __post_init__(self) -> None:
        object.__setattr__(self, "tenant_id", canonical_tenant_id(self.tenant_id))
        _id(self.record_id, "source record id")
        _revision(self.revision, "source record revision")
        _timestamp(self.updated_at, "source record updated_at")
        _digest(self.authority_sha256, "source record authority_sha256")
        if not isinstance(self.projection, Mapping):
            raise GovernanceContextProjectionValidationError(
                "source record projection must be an object"
            )
        encoded = _canonical(dict(self.projection), maximum=_MAX_RECORD_PROJECTION_BYTES)
        if not encoded:
            raise GovernanceContextProjectionValidationError(
                "source record projection is empty"
            )

    def material(self) -> dict[str, object]:
        return {
            "record_id": self.record_id,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "authority_sha256": self.authority_sha256,
            "projection": dict(self.projection),
            "projection_sha256": _sha256(dict(self.projection)),
        }


@dataclass(frozen=True, slots=True)
class AuthoritativeSourceCapture:
    """One source reader result before agent-specific envelope construction."""

    tenant_id: str
    source_id: str
    availability: str
    records: tuple[AuthoritativeContextRecord, ...]
    total_records: int
    observed_at: float
    reason_code: str | None = None

    def __post_init__(self) -> None:
        tenant = canonical_tenant_id(self.tenant_id)
        object.__setattr__(self, "tenant_id", tenant)
        _id(self.source_id, "source id")
        if self.availability not in AVAILABILITY:
            raise GovernanceContextProjectionValidationError(
                "source availability is unsupported"
            )
        if not isinstance(self.records, tuple):
            raise GovernanceContextProjectionValidationError(
                "source records must be an immutable tuple"
            )
        if len(self.records) > _MAX_RECORDS_PER_SOURCE:
            raise GovernanceContextProjectionValidationError(
                "source records exceed their hard bound"
            )
        if any(
            not isinstance(record, AuthoritativeContextRecord)
            or record.tenant_id != tenant
            for record in self.records
        ):
            raise GovernanceContextProjectionValidationError(
                "source record tenant authority is invalid"
            )
        identities = tuple(record.record_id for record in self.records)
        if identities != tuple(sorted(set(identities))):
            raise GovernanceContextProjectionValidationError(
                "source record identities must be unique and sorted"
            )
        if (
            isinstance(self.total_records, bool)
            or not isinstance(self.total_records, int)
            or self.total_records < len(self.records)
            or self.total_records > 10_000_000
        ):
            raise GovernanceContextProjectionValidationError(
                "source total record count is invalid"
            )
        _timestamp(self.observed_at, "source observed_at")
        if self.reason_code is not None and self.reason_code not in UNAVAILABILITY_REASONS:
            raise GovernanceContextProjectionValidationError(
                "source reason code is unsupported"
            )
        if self.availability == "available" and self.reason_code is not None:
            raise GovernanceContextProjectionValidationError(
                "available source cannot carry a limitation reason"
            )
        if self.availability != "available" and self.reason_code is None:
            raise GovernanceContextProjectionValidationError(
                "limited source must carry an explicit reason"
            )
        if self.availability == "unavailable" and (
            self.records or self.total_records != 0
        ):
            raise GovernanceContextProjectionValidationError(
                "unavailable source cannot carry records"
            )
        if self.total_records > len(self.records) and self.availability != "partial":
            raise GovernanceContextProjectionValidationError(
                "truncated source must be marked partial"
            )

    def authority_material(self) -> dict[str, object]:
        """Material whose digest must remain stable across the two reads."""

        return {
            "schema": SOURCE_CAPTURE_SCHEMA,
            "tenant_id": self.tenant_id,
            "source_id": self.source_id,
            "availability": self.availability,
            "records": [record.material() for record in self.records],
            "returned_records": len(self.records),
            "total_records": self.total_records,
            "reason_code": self.reason_code,
        }

    @property
    def authority_sha256(self) -> str:
        return _sha256(self.authority_material())


SourceReader = Callable[[str, int], AuthoritativeSourceCapture]


@dataclass(frozen=True, slots=True)
class ContextSourceDefinition:
    source_id: str
    source_kind: str
    agent_kinds: tuple[str, ...]
    required: bool
    reader: SourceReader

    def __post_init__(self) -> None:
        _id(self.source_id, "source id")
        if self.source_kind not in governance_agents.SOURCE_KINDS:
            raise GovernanceContextProjectionConfigError(
                "source kind is unsupported by governance agents"
            )
        if (
            not isinstance(self.agent_kinds, tuple)
            or not self.agent_kinds
            or self.agent_kinds != tuple(sorted(set(self.agent_kinds)))
            or any(kind not in governance_agents.AGENT_KINDS for kind in self.agent_kinds)
        ):
            raise GovernanceContextProjectionConfigError(
                "source agent-kind binding is invalid"
            )
        if not isinstance(self.required, bool) or not callable(self.reader):
            raise GovernanceContextProjectionConfigError(
                "source definition authority is invalid"
            )


@dataclass(frozen=True, slots=True)
class GovernanceContextProjection:
    schema: str
    tenant_id: str
    tenant_sha256: str
    agent_kind: str
    complete: bool
    sources: tuple[Mapping[str, object], ...]
    items: tuple[governance_agents.GovernanceContextItem, ...]
    generated_at: float
    projection_sha256: str

    @property
    def references(self) -> tuple[dict[str, object], ...]:
        return tuple(
            {
                "item_id": item.item_id,
                "source_kind": item.source_kind,
                "source_ref": item.source_ref,
                "source_revision": item.source_revision,
            }
            for item in self.items
        )

    def public_manifest(self) -> dict[str, object]:
        """Return metadata and pins only; raw projected content stays server-side."""

        return {
            "schema": self.schema,
            "tenant_sha256": self.tenant_sha256,
            "agent_kind": self.agent_kind,
            "complete": self.complete,
            "sources": [dict(source) for source in self.sources],
            "references": list(self.references),
            "generated_at": self.generated_at,
            "projection_sha256": self.projection_sha256,
            "raw_context_returned": False,
            "external_writes_performed": False,
        }


class AuthoritativeCrossSuiteContextProjection:
    """Stateless capture, current-reference resolution, and readiness authority."""

    def __init__(
        self,
        definitions: Sequence[ContextSourceDefinition],
        *,
        settings: GovernanceContextProjectionSettings,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if (
            isinstance(definitions, (str, bytes))
            or not isinstance(definitions, Sequence)
            or not 1 <= len(definitions) <= _MAX_SOURCE_DEFINITIONS
        ):
            raise GovernanceContextProjectionConfigError(
                "cross-suite source definitions are invalid"
            )
        if not isinstance(settings, GovernanceContextProjectionSettings):
            raise GovernanceContextProjectionConfigError(
                "cross-suite context settings are invalid"
            )
        if not callable(clock):
            raise TypeError("cross-suite context clock must be callable")
        normalized = tuple(definitions)
        if any(not isinstance(item, ContextSourceDefinition) for item in normalized):
            raise GovernanceContextProjectionConfigError(
                "cross-suite source definition is invalid"
            )
        source_ids = tuple(item.source_id for item in normalized)
        if source_ids != tuple(sorted(set(source_ids))):
            raise GovernanceContextProjectionConfigError(
                "cross-suite source definitions must be unique and sorted"
            )
        self.definitions = normalized
        self.settings = settings
        self._clock = clock
        self._by_id = {definition.source_id: definition for definition in normalized}
        self._by_ref = {
            self._source_ref(definition.source_id): definition
            for definition in normalized
        }

    def _require_enabled(self) -> None:
        if not self.settings.enable:
            raise GovernanceContextProjectionConfigError(
                "governance-agent cross-suite context projection is disabled"
            )

    @staticmethod
    def _unavailable_capture(
        tenant_id: str,
        source_id: str,
        reason_code: str,
        observed_at: float,
    ) -> AuthoritativeSourceCapture:
        return AuthoritativeSourceCapture(
            tenant_id=tenant_id,
            source_id=source_id,
            availability="unavailable",
            records=(),
            total_records=0,
            observed_at=observed_at,
            reason_code=reason_code,
        )

    def _read_once(
        self,
        definition: ContextSourceDefinition,
        tenant_id: str,
    ) -> AuthoritativeSourceCapture:
        try:
            value = definition.reader(
                tenant_id,
                self.settings.max_records_per_source,
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except SourceUnavailable as exc:
            return self._unavailable_capture(
                tenant_id,
                definition.source_id,
                exc.reason_code,
                _timestamp(self._clock(), "context clock"),
            )
        except GovernanceContextProjectionError:
            raise
        except Exception as exc:
            raise GovernanceContextProjectionConfigError(
                f"cross-suite source {definition.source_id} is unreadable"
            ) from exc
        if not isinstance(value, AuthoritativeSourceCapture):
            raise GovernanceContextProjectionValidationError(
                "cross-suite reader returned an invalid source capture"
            )
        if value.tenant_id != tenant_id or value.source_id != definition.source_id:
            raise GovernanceContextProjectionValidationError(
                "cross-suite reader changed its tenant or source binding"
            )
        if len(value.records) > self.settings.max_records_per_source:
            raise GovernanceContextProjectionValidationError(
                "cross-suite reader exceeded the configured record bound"
            )
        for record in value.records:
            if (
                len(_canonical(dict(record.projection)))
                > self.settings.max_record_projection_bytes
            ):
                raise GovernanceContextProjectionValidationError(
                    "cross-suite record exceeded its configured byte bound"
                )
        return value

    def _stable_capture(
        self,
        definition: ContextSourceDefinition,
        tenant_id: str,
    ) -> AuthoritativeSourceCapture:
        first = self._read_once(definition, tenant_id)
        second = self._read_once(definition, tenant_id)
        if first.authority_sha256 != second.authority_sha256:
            raise GovernanceContextProjectionConflict(
                f"cross-suite source {definition.source_id} changed during capture"
            )
        return second

    @staticmethod
    def _projection_revision(authority_sha256: str) -> int:
        # The content carries the full SHA-256.  This bounded derivative exists
        # only because GovernanceContextItem has a positive-int revision field.
        return (int(authority_sha256[:8], 16) % 2_147_483_647) + 1

    @staticmethod
    def _source_ref(source_id: str) -> str:
        candidate = f"{REFERENCE_PREFIX}{source_id}"
        if len(candidate) > 128:
            return f"{REFERENCE_PREFIX}{hashlib.sha256(source_id.encode()).hexdigest()}"
        return candidate

    @classmethod
    def _item_id(cls, agent_kind: str, source_id: str, revision: int) -> str:
        candidate = f"xsp-{agent_kind}-{source_id}-{revision}"
        if len(candidate) > 128:
            source_id = hashlib.sha256(source_id.encode()).hexdigest()
            candidate = f"xsp-{agent_kind}-{source_id}-{revision}"
        return _id(candidate, "context item id")

    def _item(
        self,
        definition: ContextSourceDefinition,
        capture: AuthoritativeSourceCapture,
        agent_kind: str,
        generated_at: float,
    ) -> tuple[governance_agents.GovernanceContextItem, dict[str, object]]:
        authority_sha256 = capture.authority_sha256
        revision = self._projection_revision(authority_sha256)
        tenant_sha256 = hashlib.sha256(
            f"lightwork.governance-agent.context-tenant.v1:{capture.tenant_id}".encode()
        ).hexdigest()
        content = {
            "schema": PROJECTION_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "agent_kind": agent_kind,
            "source_id": definition.source_id,
            "source_kind": definition.source_kind,
            "required": definition.required,
            "availability": capture.availability,
            "reason_code": capture.reason_code,
            "returned_records": len(capture.records),
            "total_records": capture.total_records,
            "records": [record.material() for record in capture.records],
            "source_authority_sha256": authority_sha256,
            "projection_revision": revision,
            "observed_at": capture.observed_at,
        }
        encoded = _canonical(content, maximum=self.settings.max_total_bytes)
        item = governance_agents.GovernanceContextItem(
            item_id=self._item_id(agent_kind, definition.source_id, revision),
            source_kind=definition.source_kind,
            source_ref=self._source_ref(definition.source_id),
            source_revision=revision,
            collected_at=generated_at,
            content=encoded,
        )
        status = {
            "source_id": definition.source_id,
            "source_kind": definition.source_kind,
            "required": definition.required,
            "availability": capture.availability,
            "reason_code": capture.reason_code,
            "returned_records": len(capture.records),
            "total_records": capture.total_records,
            "source_revision": revision,
            "source_authority_sha256": authority_sha256,
            "context_sha256": hashlib.sha256(encoded).hexdigest(),
        }
        return item, status

    def capture(
        self,
        tenant_id: str,
        agent_kind: str,
    ) -> GovernanceContextProjection:
        self._require_enabled()
        tenant = canonical_tenant_id(tenant_id)
        if agent_kind not in governance_agents.AGENT_KINDS:
            raise GovernanceContextProjectionValidationError(
                "governance-agent kind is unsupported"
            )
        if agent_kind not in self.settings.enabled_agent_kinds:
            raise GovernanceContextProjectionConfigError(
                "governance-agent kind is disabled for this tenant"
            )
        selected = tuple(
            definition
            for definition in self.definitions
            if agent_kind in definition.agent_kinds
        )
        if not selected:
            raise GovernanceContextProjectionConfigError(
                "governance-agent kind has no cross-suite source plan"
            )
        if len(selected) > self.settings.max_context_items:
            raise GovernanceContextProjectionConfigError(
                "cross-suite source plan exceeds the configured item bound"
            )
        generated_at = _timestamp(self._clock(), "context clock")
        items: list[governance_agents.GovernanceContextItem] = []
        statuses: list[dict[str, object]] = []
        total_bytes = 0
        for definition in selected:
            capture = self._stable_capture(definition, tenant)
            item, status = self._item(
                definition,
                capture,
                agent_kind,
                generated_at,
            )
            total_bytes += len(item.content)
            if total_bytes > self.settings.max_total_bytes:
                raise GovernanceContextProjectionConfigError(
                    "cross-suite context exceeds the configured byte bound"
                )
            items.append(item)
            statuses.append(status)
        tenant_sha256 = hashlib.sha256(
            f"lightwork.governance-agent.context-tenant.v1:{tenant}".encode()
        ).hexdigest()
        complete = all(status["availability"] == "available" for status in statuses)
        material = {
            "schema": PROJECTION_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "agent_kind": agent_kind,
            "complete": complete,
            "sources": statuses,
            "item_pins": [
                {
                    "item_id": item.item_id,
                    "source_kind": item.source_kind,
                    "source_ref": item.source_ref,
                    "source_revision": item.source_revision,
                    "content_sha256": hashlib.sha256(item.content).hexdigest(),
                }
                for item in items
            ],
        }
        return GovernanceContextProjection(
            schema=PROJECTION_SCHEMA,
            tenant_id=tenant,
            tenant_sha256=tenant_sha256,
            agent_kind=agent_kind,
            complete=complete,
            sources=tuple(statuses),
            items=tuple(items),
            generated_at=generated_at,
            projection_sha256=_sha256(material),
        )

    def resolve_references(
        self,
        tenant_id: str,
        references: Sequence[Mapping[str, object]],
        expected_agent_kind: str,
    ) -> tuple[governance_agents.GovernanceContextItem, ...]:
        """Resolve only current projection references; reject stale previews."""

        self._require_enabled()
        tenant = canonical_tenant_id(tenant_id)
        if (
            expected_agent_kind not in governance_agents.AGENT_KINDS
            or expected_agent_kind not in self.settings.enabled_agent_kinds
        ):
            raise GovernanceContextProjectionValidationError(
                "cross-suite expected governance-agent kind is invalid"
            )
        if (
            isinstance(references, (str, bytes))
            or not isinstance(references, Sequence)
            or not references
        ):
            raise GovernanceContextProjectionValidationError(
                "cross-suite context references are invalid"
            )
        grouped: dict[str, list[Mapping[str, object]]] = {}
        for reference in references:
            if not isinstance(reference, Mapping):
                raise GovernanceContextProjectionValidationError(
                    "cross-suite context reference is invalid"
                )
            source_ref = reference.get("source_ref")
            if not isinstance(source_ref, str) or not source_ref.startswith(
                REFERENCE_PREFIX
            ):
                raise GovernanceContextProjectionValidationError(
                    "reference is not a cross-suite context reference"
                )
            definition = self._by_ref.get(source_ref)
            if definition is None:
                raise GovernanceContextProjectionConfigError(
                    "cross-suite source authority is not enrolled"
                )
            source_id = definition.source_id
            grouped.setdefault(source_id, []).append(reference)
        if any(len(values) != 1 for values in grouped.values()):
            raise GovernanceContextProjectionValidationError(
                "cross-suite source references must be unique"
            )

        resolved: dict[str, governance_agents.GovernanceContextItem] = {}
        resolved_agent_kind: str | None = None
        for source_id, source_references in grouped.items():
            reference = source_references[0]
            definition = self._by_id[source_id]
            item_id = _id(reference.get("item_id"), "context item id")
            source_kind = reference.get("source_kind")
            if source_kind != definition.source_kind:
                raise GovernanceContextProjectionValidationError(
                    "cross-suite source kind changed"
                )
            expected_revision = _revision(
                reference.get("source_revision"),
                "context source revision",
            )
            capture = self._stable_capture(definition, tenant)
            # The agent kind is encoded in the item id and is recovered only
            # from the closed source plan.  Exactly one kind must match the
            # claimed deterministic id for the current authority.
            current_revision = self._projection_revision(capture.authority_sha256)
            matching_kinds = tuple(
                kind
                for kind in definition.agent_kinds
                if kind in self.settings.enabled_agent_kinds
                if self._item_id(kind, source_id, current_revision) == item_id
            )
            if len(matching_kinds) != 1 or current_revision != expected_revision:
                raise GovernanceContextProjectionConflict(
                    "cross-suite context preview is stale or misbound"
                )
            if resolved_agent_kind is None:
                resolved_agent_kind = matching_kinds[0]
            elif resolved_agent_kind != matching_kinds[0]:
                raise GovernanceContextProjectionValidationError(
                    "cross-suite context references mix governance-agent kinds"
                )
            item, _status = self._item(
                definition,
                capture,
                matching_kinds[0],
                _timestamp(self._clock(), "context clock"),
            )
            resolved[item_id] = item
        if resolved_agent_kind is None:
            raise GovernanceContextProjectionValidationError(
                "cross-suite context agent binding is unavailable"
            )
        if resolved_agent_kind != expected_agent_kind:
            raise GovernanceContextProjectionValidationError(
                "cross-suite context does not match the policy agent kind"
            )
        expected_source_ids = {
            definition.source_id
            for definition in self.definitions
            if resolved_agent_kind in definition.agent_kinds
        }
        if set(grouped) != expected_source_ids:
            raise GovernanceContextProjectionValidationError(
                "cross-suite context references do not match the exact source plan"
            )
        return tuple(resolved[_id(ref.get("item_id"), "context item id")] for ref in references)

    def readiness(self, tenant_id: str) -> dict[str, object]:
        """Read-only, exact source probe; never claims provider acceptance."""

        tenant = canonical_tenant_id(tenant_id)
        result: dict[str, object] = {
            "schema": READINESS_SCHEMA,
            "tenant_sha256": hashlib.sha256(
                f"lightwork.governance-agent.context-tenant.v1:{tenant}".encode()
            ).hexdigest(),
            "enabled": self.settings.enable,
            "ready": False,
            "agent_kinds": {},
            "double_read_stability_verified": False,
            "bounded_current_heads_verified": False,
            "full_source_history_integrity_verified": False,
            "raw_context_persisted": False,
            "external_writes_performed": False,
            "licensed_content_included": False,
            "live_provider_acceptance_verified": False,
        }
        if not self.settings.enable:
            return result
        try:
            manifests: dict[str, object] = {}
            for agent_kind in sorted(governance_agents.AGENT_KINDS):
                if agent_kind not in self.settings.enabled_agent_kinds:
                    manifests[agent_kind] = {
                        "enabled": False,
                        "complete": False,
                        "projection_sha256": None,
                        "sources": [],
                    }
                    continue
                projection = self.capture(tenant, agent_kind)
                manifests[agent_kind] = {
                    "enabled": True,
                    "complete": projection.complete,
                    "projection_sha256": projection.projection_sha256,
                    "sources": [dict(item) for item in projection.sources],
                }
            result.update(
                {
                    "ready": all(
                        value["complete"] is True
                        for value in manifests.values()
                        if isinstance(value, Mapping) and value.get("enabled") is True
                    ),
                    "agent_kinds": manifests,
                    "double_read_stability_verified": True,
                    "bounded_current_heads_verified": True,
                }
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            result["error"] = type(exc).__name__
        return result

    def verify_sources(self, tenant_id: str) -> dict[str, object]:
        """Maintenance is a non-mutating recapture and digest verification."""

        return {
            **self.readiness(tenant_id),
            "maintenance_operation": "bounded_projection_reverification",
            "semantic_writes_performed": False,
        }

    def recover(self, tenant_id: str) -> dict[str, object]:
        """Stateless recovery: discard caller previews and recapture authorities."""

        result = self.readiness(tenant_id)
        return {
            **result,
            "recovery_mode": "stateless_recapture",
            "stale_previews_reused": False,
        }


__all__ = [
    "AuthoritativeContextRecord",
    "AuthoritativeCrossSuiteContextProjection",
    "AuthoritativeSourceCapture",
    "ContextSourceDefinition",
    "GovernanceContextProjection",
    "GovernanceContextProjectionConfigError",
    "GovernanceContextProjectionConflict",
    "GovernanceContextProjectionError",
    "GovernanceContextProjectionSettings",
    "GovernanceContextProjectionValidationError",
    "PROJECTION_SCHEMA",
    "READINESS_SCHEMA",
    "REFERENCE_PREFIX",
    "SourceUnavailable",
]
