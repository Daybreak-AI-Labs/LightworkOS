"""Tenant-private shared governance inventory over six normalized suites.

This is a read model, not a second system of record.  It persists only:

* exact suite revision/head/completeness/retention commitments from
  :mod:`maverick.suite_audit_capture`;
* stable tenant-keyed HMAC references to suite resources; and
* the minimized, exact provenance projection exported by
  :mod:`maverick.entity_graph`.

Raw actors, resource identifiers, names, aliases, record ids, relationship
detail, source payloads and credentials remain in their owning authorities.
Identity is source-qualified or inherited from the entity graph's exact
canonical resolver; this module never performs fuzzy or probabilistic merging.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol

from .entity_graph import (
    CONCEPT_KINDS,
    INVENTORY_ENTITY_SCHEMA,
    INVENTORY_PROVENANCE_SCHEMA,
    INVENTORY_RELATIONSHIP_SCHEMA,
    RECORD_KINDS,
    RELATION_KINDS,
)
from .file_lock import (
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
)
from .paths import InvalidTenantError, canonical_tenant_id
from .sqlite_closing import ClosingConnection
from .suite_audit_capture import (
    SuiteAuditCapture,
    SuiteAuditCaptureError,
    SuiteAuditCaptureProvider,
)
from .unified_audit import REQUIRED_SUITES, SOURCE_ACTION_CODES

INVENTORY_SCHEMA = "lightwork.shared-governance-inventory.v1"
SOURCE_MANIFEST_SCHEMA = "lightwork.shared-governance-source-manifest.v1"
SNAPSHOT_SCHEMA = "lightwork.shared-governance-inventory-snapshot.v1"
SNAPSHOT_METADATA_SCHEMA = (
    "lightwork.shared-governance-inventory-snapshot-metadata.v1"
)
ACTIVE_SCHEMA = "lightwork.shared-governance-inventory-active.v1"
OPERATION_SCHEMA = "lightwork.shared-governance-inventory-operation.v1"
TOMBSTONE_SCHEMA = "lightwork.shared-governance-inventory-tombstone.v1"
RECOVERY_SCHEMA = "lightwork.shared-governance-inventory-recovery.v1"
EXPORT_SCHEMA = "lightwork.shared-governance-inventory-export.v1"
SCHEMA_VERSION = 1
GENESIS_SHA256 = "0" * 64

SOURCE_STATES = frozenset({"available", "partial", "unavailable", "drifted"})
SNAPSHOT_STATES = frozenset({"available", "partial", "unavailable", "drifted"})
ENTITY_KINDS = frozenset(("governance_resource", *CONCEPT_KINDS, *RECORD_KINDS))
ORIGINS = frozenset({"suite_capture", "entity_graph"})
_SOURCE_IDS = tuple(REQUIRED_SUITES)
_SOURCE_SET = frozenset(_SOURCE_IDS)
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_CHECKPOINT_NAME_RE = re.compile(r"inventory-(\d{8,})-[0-9a-f]{16}\.json\Z")
_MAX_QUERY_LIMIT = 1_000
_MAX_RECOVERY_BYTES = 64 * 1024 * 1024


class SharedGovernanceInventoryError(RuntimeError):
    """Base error for the shared governance inventory."""


class SharedGovernanceInventoryConfigError(SharedGovernanceInventoryError):
    """The feature gate, custody, or dependency composition is invalid."""


class SharedGovernanceInventoryValidationError(SharedGovernanceInventoryError):
    """Caller input is outside the closed contract."""


class SharedGovernanceInventoryConflict(SharedGovernanceInventoryError):
    """CAS or idempotency authority changed."""


class SharedGovernanceInventoryIntegrityError(SharedGovernanceInventoryError):
    """Persisted or projected integrity cannot be established."""


class SharedGovernanceInventoryNotFound(SharedGovernanceInventoryError):
    """The requested inventory snapshot does not exist."""


class SharedGovernanceInventoryGone(SharedGovernanceInventoryError):
    """The immutable metadata remains but its payload was retained out."""


class SharedGovernanceInventoryPermissionDenied(SharedGovernanceInventoryError):
    """The operation lacks admitted maintenance authority."""


class ProvenanceManifestReader(Protocol):
    def __call__(
        self,
        *,
        tenant_id: str,
        reference_key: bytes,
        max_entities: int,
        max_relationships: int,
    ) -> Mapping[str, object]: ...


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise SharedGovernanceInventoryIntegrityError(
            "inventory canonical encoding failed"
        ) from exc


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mac(key: bytes, value: object) -> str:
    return hmac.new(key, _canonical(value), hashlib.sha256).hexdigest()


def _tenant(value: object) -> str:
    try:
        return canonical_tenant_id(value)  # type: ignore[arg-type]
    except (InvalidTenantError, TypeError, ValueError) as exc:
        raise SharedGovernanceInventoryValidationError(
            "inventory tenant is invalid"
        ) from exc


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST_RE.fullmatch(value) is None:
        raise SharedGovernanceInventoryIntegrityError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None:
        raise SharedGovernanceInventoryValidationError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, lower: int, upper: int) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not lower <= value <= upper
    ):
        raise SharedGovernanceInventoryValidationError(
            f"{label} is outside its bound"
        )
    return value


def _timestamp(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SharedGovernanceInventoryIntegrityError(f"{label} is invalid")
    selected = float(value)
    if not math.isfinite(selected) or not 0 < selected < 100_000_000_000.0:
        raise SharedGovernanceInventoryIntegrityError(f"{label} is invalid")
    return selected


def _clock_value(clock: Callable[[], float]) -> float:
    try:
        return _timestamp(clock(), "inventory clock")
    except (KeyboardInterrupt, SystemExit):
        raise
    except SharedGovernanceInventoryError:
        raise
    except Exception as exc:
        raise SharedGovernanceInventoryConfigError(
            "inventory clock is unavailable"
        ) from exc


def _strict_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise SharedGovernanceInventoryIntegrityError(f"{label} is invalid")
    if any(not isinstance(key, str) for key in value):
        raise SharedGovernanceInventoryIntegrityError(f"{label} is invalid")
    return dict(value)


def _exact_keys(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise SharedGovernanceInventoryIntegrityError(f"{label} schema changed")


def _capture_fingerprint(capture: SuiteAuditCapture) -> str:
    """Commit to source authority while excluding observation wall-clock time."""

    return _sha256(
        {
            "source_id": capture.source_id,
            "source_revision": capture.source_revision,
            "source_schema_version": capture.source_schema_version,
            "record_count": capture.record_count,
            "head_sha256": capture.head_sha256,
            "complete": capture.complete,
            "retention_complete": capture.retention_complete,
            "integrity_verified": capture.integrity_verified,
            "limitations": list(capture.limitations),
            "record_sha256s": [record.record_sha256 for record in capture.records],
        }
    )


def _unavailable_source_manifest(
    source_id: str,
    *,
    provider_identity_sha256: str,
    reason_code: str,
) -> dict[str, object]:
    return {
        "schema": SOURCE_MANIFEST_SCHEMA,
        "source_id": source_id,
        "state": "unavailable",
        "provider_identity_sha256": provider_identity_sha256,
        "source_revision": None,
        "source_schema_version": None,
        "observed_at": None,
        "record_count": None,
        "projected_record_count": 0,
        "head_sha256": None,
        "capture_sha256": None,
        "complete": False,
        "retention_complete": False,
        "integrity_verified": False,
        "limitations": [reason_code],
        "raw_records_persisted": False,
    }


def _source_manifest(
    capture: SuiteAuditCapture,
    *,
    provider_identity_sha256: str,
    projected_record_count: int,
    state: str | None = None,
    extra_limitations: Sequence[str] = (),
) -> dict[str, object]:
    selected_state = state or (
        "available" if capture.complete and not extra_limitations else "partial"
    )
    if selected_state not in SOURCE_STATES:
        raise SharedGovernanceInventoryIntegrityError("source state is invalid")
    effective_complete = capture.complete and selected_state == "available"
    return {
        "schema": SOURCE_MANIFEST_SCHEMA,
        "source_id": capture.source_id,
        "state": selected_state,
        "provider_identity_sha256": provider_identity_sha256,
        "source_revision": capture.source_revision,
        "source_schema_version": capture.source_schema_version,
        "observed_at": capture.observed_at,
        "record_count": capture.record_count,
        "projected_record_count": projected_record_count,
        "head_sha256": capture.head_sha256,
        "capture_sha256": capture.capture_sha256,
        "complete": effective_complete,
        "retention_complete": capture.retention_complete,
        "integrity_verified": capture.integrity_verified,
        "limitations": sorted(set((*capture.limitations, *extra_limitations))),
        "raw_records_persisted": False,
    }


def _capture_source(
    provider: SuiteAuditCaptureProvider,
    *,
    tenant_id: str,
    source_id: str,
) -> tuple[SuiteAuditCapture | None, str | None]:
    try:
        capture = provider.capture(tenant_id=tenant_id, source_id=source_id)
    except (KeyboardInterrupt, SystemExit):
        raise
    except SuiteAuditCaptureError as exc:
        return None, exc.error_code
    except Exception:
        return None, "source_history_unavailable"
    if (
        not isinstance(capture, SuiteAuditCapture)
        or capture.tenant_id != tenant_id
        or capture.source_id != source_id
    ):
        return None, "source_authority_invalid"
    return capture, None


def _resource_entities(
    *,
    tenant_id: str,
    reference_key: bytes,
    captures: Mapping[str, SuiteAuditCapture],
    max_source_records: int,
    max_entities: int,
) -> tuple[list[dict[str, object]], dict[str, int], list[str]]:
    tenant_sha256 = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
    accumulators: dict[tuple[str, str], dict[str, object]] = {}
    projected_by_source: dict[str, int] = dict.fromkeys(_SOURCE_IDS, 0)
    limitations: set[str] = set()
    for source_id in _SOURCE_IDS:
        capture = captures.get(source_id)
        if capture is None:
            continue
        selected = capture.records[:max_source_records]
        projected_by_source[source_id] = len(selected)
        if capture.record_count > len(selected):
            limitations.add(f"{source_id}:source_record_limit")
        for record in selected:
            key = (source_id, record.resource_sha256)
            current = accumulators.get(key)
            if current is None:
                entity_ref = _mac(
                    reference_key,
                    {
                        "schema": INVENTORY_ENTITY_SCHEMA,
                        "tenant_sha256": tenant_sha256,
                        "origin": "suite_capture",
                        "source_id": source_id,
                        "source_resource_sha256": record.resource_sha256,
                    },
                )
                accumulators[key] = {
                    "schema": INVENTORY_ENTITY_SCHEMA,
                    "entity_ref_sha256": entity_ref,
                    "entity_kind": "governance_resource",
                    "origin": "suite_capture",
                    "source_id": source_id,
                    "first_sequence": record.sequence,
                    "last_sequence": record.sequence,
                    "record_count": 1,
                    "first_observed_at": record.occurred_at,
                    "last_observed_at": record.occurred_at,
                    "latest_action": record.action,
                    "latest_record_sha256": record.record_sha256,
                    "latest_payload_sha256": record.payload_sha256,
                }
            else:
                current["last_sequence"] = record.sequence
                current["record_count"] = int(current["record_count"]) + 1
                current["last_observed_at"] = record.occurred_at
                current["latest_action"] = record.action
                current["latest_record_sha256"] = record.record_sha256
                current["latest_payload_sha256"] = record.payload_sha256
    entities = [accumulators[key] for key in sorted(accumulators)]
    if len(entities) > max_entities:
        entities = entities[:max_entities]
        limitations.add("entity_limit")
    return entities, projected_by_source, sorted(limitations)


def _read_provenance(
    reader: ProvenanceManifestReader,
    *,
    tenant_id: str,
    reference_key: bytes,
    max_entities: int,
    max_relationships: int,
) -> tuple[dict[str, object] | None, str | None]:
    try:
        value = reader(
            tenant_id=tenant_id,
            reference_key=reference_key,
            max_entities=max_entities,
            max_relationships=max_relationships,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return None, "entity_graph_unavailable"
    try:
        manifest = _strict_mapping(value, "entity graph manifest")
        _digest(manifest.get("graph_integrity_sha256"), "entity graph digest")
        if manifest.get("schema") != INVENTORY_PROVENANCE_SCHEMA:
            raise SharedGovernanceInventoryIntegrityError(
                "entity graph manifest schema changed"
            )
        if manifest.get("state") not in {"available", "partial"}:
            raise SharedGovernanceInventoryIntegrityError(
                "entity graph state is invalid"
            )
        if any(
            manifest.get(key) is not False
            for key in (
                "raw_names_included",
                "raw_aliases_included",
                "raw_record_ids_included",
                "raw_relationship_detail_included",
                "fuzzy_identity_merging_performed",
            )
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "entity graph minimization contract failed"
            )
        if not isinstance(manifest.get("entities"), list) or not isinstance(
            manifest.get("relationships"), list
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "entity graph projection is invalid"
            )
        return manifest, None
    except SharedGovernanceInventoryError:
        return None, "entity_graph_integrity_unverified"


def build_inventory_projection(  # noqa: C901 - explicit six-source state machine
    *,
    tenant_id: str,
    provider: SuiteAuditCaptureProvider,
    provenance_reader: ProvenanceManifestReader,
    reference_key: bytes,
    max_source_records: int = 10_000,
    max_entities: int = 20_000,
    max_relationships: int = 40_000,
    clock: Callable[[], float] = time.time,
) -> dict[str, object]:
    """Capture stable suite heads and exact provenance into one minimized view."""

    tenant = _tenant(tenant_id)
    if not isinstance(reference_key, bytes) or len(reference_key) < 32:
        raise SharedGovernanceInventoryConfigError(
            "inventory reference key must contain at least 32 bytes"
        )
    source_limit = _integer(
        max_source_records, "max_source_records", 1, 100_000
    )
    entity_limit = _integer(max_entities, "max_entities", 1, 100_000)
    relationship_limit = _integer(
        max_relationships, "max_relationships", 1, 200_000
    )
    if not callable(getattr(provider, "capture", None)) or not callable(
        provenance_reader
    ):
        raise SharedGovernanceInventoryConfigError(
            "inventory source authority is unavailable"
        )
    try:
        provider_identity = _digest(
            provider.provider_identity_sha256,
            "capture provider identity",
        )
    except (AttributeError, SharedGovernanceInventoryError) as exc:
        raise SharedGovernanceInventoryConfigError(
            "inventory capture provider identity is unavailable"
        ) from exc

    first: dict[str, SuiteAuditCapture] = {}
    first_failures: dict[str, str] = {}
    for source_id in _SOURCE_IDS:
        capture, reason = _capture_source(
            provider,
            tenant_id=tenant,
            source_id=source_id,
        )
        if capture is None:
            first_failures[source_id] = reason or "source_history_unavailable"
        else:
            first[source_id] = capture

    # The graph is captured between the two suite head reads.  A source update
    # on either side becomes explicit drift instead of a mixed-time snapshot.
    graph_first, graph_first_reason = _read_provenance(
        provenance_reader,
        tenant_id=tenant,
        reference_key=reference_key,
        max_entities=entity_limit,
        max_relationships=relationship_limit,
    )

    stable: dict[str, SuiteAuditCapture] = {}
    source_states: dict[str, str] = {}
    second_failures: dict[str, str] = {}
    for source_id in _SOURCE_IDS:
        capture, reason = _capture_source(
            provider,
            tenant_id=tenant,
            source_id=source_id,
        )
        if capture is None:
            second_failures[source_id] = reason or "source_history_unavailable"
            continue
        prior = first.get(source_id)
        if prior is None:
            source_states[source_id] = "drifted"
            second_failures[source_id] = "source_availability_changed"
        elif not hmac.compare_digest(
            _capture_fingerprint(prior), _capture_fingerprint(capture)
        ):
            source_states[source_id] = "drifted"
            second_failures[source_id] = "source_authority_changed"
        else:
            stable[source_id] = capture

    graph_second, graph_second_reason = _read_provenance(
        provenance_reader,
        tenant_id=tenant,
        reference_key=reference_key,
        max_entities=entity_limit,
        max_relationships=relationship_limit,
    )
    graph_state = "unavailable"
    graph_reason = graph_first_reason or graph_second_reason
    graph_selected: dict[str, object] | None = None
    if graph_first is not None and graph_second is not None:
        comparable = (
            "graph_integrity_sha256",
            "entity_count",
            "relationship_count",
            "projected_entity_count",
            "projected_relationship_count",
        )
        if any(graph_first.get(key) != graph_second.get(key) for key in comparable):
            graph_state = "drifted"
            graph_reason = "entity_graph_authority_changed"
        else:
            graph_selected = graph_second
            graph_state = str(graph_second["state"])
    elif graph_first is not None or graph_second is not None:
        graph_state = "drifted"
        graph_reason = "entity_graph_availability_changed"

    suite_entities, projected_by_source, projection_limits = _resource_entities(
        tenant_id=tenant,
        reference_key=reference_key,
        captures=stable,
        max_source_records=source_limit,
        max_entities=entity_limit,
    )
    source_manifests: list[dict[str, object]] = []
    limitations: set[str] = set(projection_limits)
    for source_id in _SOURCE_IDS:
        capture = stable.get(source_id)
        if capture is not None:
            extra: list[str] = []
            if capture.record_count > projected_by_source[source_id]:
                extra.append("inventory_source_record_limit")
            manifest = _source_manifest(
                capture,
                provider_identity_sha256=provider_identity,
                projected_record_count=projected_by_source[source_id],
                extra_limitations=extra,
            )
        elif source_states.get(source_id) == "drifted":
            base = first.get(source_id)
            if base is None:
                manifest = _unavailable_source_manifest(
                    source_id,
                    provider_identity_sha256=provider_identity,
                    reason_code=second_failures[source_id],
                )
                manifest["state"] = "drifted"
            else:
                manifest = _source_manifest(
                    base,
                    provider_identity_sha256=provider_identity,
                    projected_record_count=0,
                    state="drifted",
                    extra_limitations=(second_failures[source_id],),
                )
        else:
            reason = first_failures.get(
                source_id,
                second_failures.get(source_id, "source_history_unavailable"),
            )
            manifest = _unavailable_source_manifest(
                source_id,
                provider_identity_sha256=provider_identity,
                reason_code=reason,
            )
        source_manifests.append(manifest)
        if manifest["state"] != "available":
            limitations.update(
                f"{source_id}:{item}" for item in manifest["limitations"]
            )

    entities = list(suite_entities)
    relationships: list[dict[str, object]] = []
    graph_summary: dict[str, object]
    if graph_selected is None:
        graph_summary = {
            "schema": INVENTORY_PROVENANCE_SCHEMA,
            "state": graph_state,
            "observed_at": None,
            "graph_integrity_sha256": None,
            "entity_count": None,
            "relationship_count": None,
            "projected_entity_count": 0,
            "projected_relationship_count": 0,
            "limitations": [graph_reason or "entity_graph_unavailable"],
            "raw_names_included": False,
            "raw_aliases_included": False,
            "raw_record_ids_included": False,
            "raw_relationship_detail_included": False,
            "fuzzy_identity_merging_performed": False,
        }
        limitations.add(f"entity_graph:{graph_summary['limitations'][0]}")
    else:
        graph_entities = list(graph_selected["entities"])
        remaining = max(0, entity_limit - len(entities))
        selected_graph_entities = graph_entities[:remaining]
        selected_refs = {
            str(item["entity_ref_sha256"])
            for item in selected_graph_entities
            if isinstance(item, Mapping)
        }
        entities.extend(selected_graph_entities)
        if len(graph_entities) > len(selected_graph_entities):
            limitations.add("entity_graph:entity_limit")
        for item in graph_selected["relationships"]:
            if not isinstance(item, Mapping):
                continue
            if (
                item.get("source_entity_ref_sha256") in selected_refs
                and item.get("target_entity_ref_sha256") in selected_refs
            ):
                relationships.append(dict(item))
                if len(relationships) >= relationship_limit:
                    break
        graph_summary = {
            key: value
            for key, value in graph_selected.items()
            if key not in {"entities", "relationships"}
        }
        graph_summary["state"] = graph_state
        graph_summary["projected_entity_count"] = len(selected_graph_entities)
        graph_summary["projected_relationship_count"] = len(relationships)
        for item in graph_summary.get("limitations", []):
            limitations.add(f"entity_graph:{item}")

    states = {str(item["state"]) for item in source_manifests}
    if "drifted" in states or graph_state == "drifted":
        snapshot_state = "drifted"
    elif all(state == "unavailable" for state in states) and graph_state == "unavailable":
        snapshot_state = "unavailable"
    elif states == {"available"} and graph_state == "available" and not limitations:
        snapshot_state = "available"
    else:
        snapshot_state = "partial"
    generated_at = _clock_value(clock)
    return {
        "schema": INVENTORY_SCHEMA,
        "tenant_id": tenant,
        "generated_at": generated_at,
        "state": snapshot_state,
        "source_manifests": source_manifests,
        "entity_graph_manifest": graph_summary,
        "entities": entities,
        "relationships": relationships,
        "limitations": sorted(limitations),
        "limits": {
            "max_source_records": source_limit,
            "max_entities": entity_limit,
            "max_relationships": relationship_limit,
            "raw_source_records_persisted": False,
            "raw_private_fields_persisted": False,
            "fuzzy_identity_merging_performed": False,
            "live_source_interoperability_verified": False,
            "migration_acceptance_verified": False,
            "customer_acceptance_verified": False,
        },
    }


_SOURCE_MANIFEST_KEYS = {
    "schema",
    "source_id",
    "state",
    "provider_identity_sha256",
    "source_revision",
    "source_schema_version",
    "observed_at",
    "record_count",
    "projected_record_count",
    "head_sha256",
    "capture_sha256",
    "complete",
    "retention_complete",
    "integrity_verified",
    "limitations",
    "raw_records_persisted",
}
_RESOURCE_ENTITY_KEYS = {
    "schema",
    "entity_ref_sha256",
    "entity_kind",
    "origin",
    "source_id",
    "first_sequence",
    "last_sequence",
    "record_count",
    "first_observed_at",
    "last_observed_at",
    "latest_action",
    "latest_record_sha256",
    "latest_payload_sha256",
}
_GRAPH_ENTITY_KEYS = {
    "schema",
    "entity_ref_sha256",
    "entity_kind",
    "origin",
}
_RELATIONSHIP_KEYS = {
    "schema",
    "relationship_ref_sha256",
    "relationship_kind",
    "origin",
    "source_entity_ref_sha256",
    "relation_type",
    "target_entity_ref_sha256",
    "provenance_record_type",
    "provenance_ref_sha256",
    "valid_from",
    "valid_to",
    "detail_sha256",
}
_PROJECTION_KEYS = {
    "schema",
    "tenant_id",
    "generated_at",
    "state",
    "source_manifests",
    "entity_graph_manifest",
    "entities",
    "relationships",
    "limitations",
    "limits",
}


def _validate_source_manifest(value: object) -> dict[str, object]:
    item = _strict_mapping(value, "source manifest")
    _exact_keys(item, _SOURCE_MANIFEST_KEYS, "source manifest")
    if item["schema"] != SOURCE_MANIFEST_SCHEMA or item["source_id"] not in _SOURCE_SET:
        raise SharedGovernanceInventoryIntegrityError(
            "source manifest identity is invalid"
        )
    if item["state"] not in SOURCE_STATES:
        raise SharedGovernanceInventoryIntegrityError("source manifest state is invalid")
    _digest(item["provider_identity_sha256"], "source provider identity")
    if type(item["complete"]) is not bool or type(item["retention_complete"]) is not bool:
        raise SharedGovernanceInventoryIntegrityError("source completeness is invalid")
    if type(item["integrity_verified"]) is not bool or item["raw_records_persisted"] is not False:
        raise SharedGovernanceInventoryIntegrityError("source integrity is invalid")
    if not isinstance(item["limitations"], list) or any(
        not isinstance(limit, str) or not limit or len(limit) > 128
        for limit in item["limitations"]
    ):
        raise SharedGovernanceInventoryIntegrityError("source limitations are invalid")
    projected = _integer(
        item["projected_record_count"],
        "projected_record_count",
        0,
        2_147_483_647,
    )
    authority_fields = (
        "source_revision",
        "source_schema_version",
        "observed_at",
        "record_count",
        "head_sha256",
        "capture_sha256",
    )
    authority_absent = all(item[key] is None for key in authority_fields)
    if item["state"] == "unavailable" or authority_absent:
        if (
            not authority_absent
            or projected != 0
            or item["state"] not in {"unavailable", "drifted"}
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "unavailable source manifest carries authority"
            )
    else:
        _integer(item["source_revision"], "source revision", 1, 2_147_483_647)
        _integer(
            item["source_schema_version"],
            "source schema version",
            1,
            2_147_483_647,
        )
        _timestamp(item["observed_at"], "source observed_at")
        count = _integer(item["record_count"], "record_count", 0, 2_147_483_647)
        if projected > count:
            raise SharedGovernanceInventoryIntegrityError(
                "projected source count exceeds source count"
            )
        _digest(item["head_sha256"], "source head")
        _digest(item["capture_sha256"], "source capture")
    if item["complete"] is True and (
        item["state"] != "available"
        or item["retention_complete"] is not True
        or item["integrity_verified"] is not True
        or item["limitations"]
    ):
        raise SharedGovernanceInventoryIntegrityError(
            "complete source manifest is inconsistent"
        )
    return item


def _validate_entity(value: object) -> dict[str, object]:
    item = _strict_mapping(value, "inventory entity")
    origin = item.get("origin")
    expected = _RESOURCE_ENTITY_KEYS if origin == "suite_capture" else _GRAPH_ENTITY_KEYS
    _exact_keys(item, expected, "inventory entity")
    if item["schema"] != INVENTORY_ENTITY_SCHEMA or origin not in ORIGINS:
        raise SharedGovernanceInventoryIntegrityError("inventory entity identity is invalid")
    _digest(item["entity_ref_sha256"], "inventory entity reference")
    if item["entity_kind"] not in ENTITY_KINDS:
        raise SharedGovernanceInventoryIntegrityError("inventory entity kind is invalid")
    if origin == "suite_capture":
        if item["entity_kind"] != "governance_resource" or item["source_id"] not in _SOURCE_SET:
            raise SharedGovernanceInventoryIntegrityError("suite entity identity is invalid")
        first = _integer(item["first_sequence"], "first_sequence", 1, 2_147_483_647)
        last = _integer(item["last_sequence"], "last_sequence", 1, 2_147_483_647)
        count = _integer(item["record_count"], "entity record_count", 1, 2_147_483_647)
        if last < first or count > last - first + 1:
            raise SharedGovernanceInventoryIntegrityError("suite entity sequence is invalid")
        first_at = _timestamp(item["first_observed_at"], "first_observed_at")
        last_at = _timestamp(item["last_observed_at"], "last_observed_at")
        if last_at < first_at or item["latest_action"] not in SOURCE_ACTION_CODES:
            raise SharedGovernanceInventoryIntegrityError("suite entity history is invalid")
        _digest(item["latest_record_sha256"], "latest record")
        _digest(item["latest_payload_sha256"], "latest payload")
    return item


def _validate_relationship(
    value: object,
    *,
    entity_refs: set[str],
) -> dict[str, object]:
    item = _strict_mapping(value, "inventory relationship")
    _exact_keys(item, _RELATIONSHIP_KEYS, "inventory relationship")
    if (
        item["schema"] != INVENTORY_RELATIONSHIP_SCHEMA
        or item["relationship_kind"] != "entity_graph_edge"
        or item["origin"] != "entity_graph"
        or item["relation_type"] not in RELATION_KINDS
        or item["provenance_record_type"] not in RECORD_KINDS
    ):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory relationship identity is invalid"
        )
    for field in (
        "relationship_ref_sha256",
        "source_entity_ref_sha256",
        "target_entity_ref_sha256",
        "provenance_ref_sha256",
        "detail_sha256",
    ):
        _digest(item[field], field)
    if (
        item["source_entity_ref_sha256"] not in entity_refs
        or item["target_entity_ref_sha256"] not in entity_refs
    ):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory relationship endpoint is absent"
        )
    valid_from = _timestamp(item["valid_from"], "relationship valid_from")
    if item["valid_to"] is not None and _timestamp(
        item["valid_to"], "relationship valid_to"
    ) <= valid_from:
        raise SharedGovernanceInventoryIntegrityError(
            "inventory relationship time range is invalid"
        )
    return item


def validate_inventory_projection(
    value: object,
    *,
    tenant_id: str,
) -> dict[str, object]:
    """Validate the closed, minimized projection before persistence or export."""

    tenant = _tenant(tenant_id)
    projection = _strict_mapping(value, "inventory projection")
    _exact_keys(projection, _PROJECTION_KEYS, "inventory projection")
    if projection["schema"] != INVENTORY_SCHEMA or projection["tenant_id"] != tenant:
        raise SharedGovernanceInventoryIntegrityError(
            "inventory projection identity is invalid"
        )
    _timestamp(projection["generated_at"], "inventory generated_at")
    if projection["state"] not in SNAPSHOT_STATES:
        raise SharedGovernanceInventoryIntegrityError("inventory state is invalid")
    manifests = projection["source_manifests"]
    if not isinstance(manifests, list) or len(manifests) != len(_SOURCE_IDS):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory source manifests are incomplete"
        )
    validated_manifests = [_validate_source_manifest(item) for item in manifests]
    if [item["source_id"] for item in validated_manifests] != list(_SOURCE_IDS):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory source manifest order is invalid"
        )
    entities_raw = projection["entities"]
    if not isinstance(entities_raw, list):
        raise SharedGovernanceInventoryIntegrityError("inventory entities are invalid")
    entities = [_validate_entity(item) for item in entities_raw]
    entity_refs = [str(item["entity_ref_sha256"]) for item in entities]
    if len(entity_refs) != len(set(entity_refs)):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory entity references are duplicated"
        )
    relationships_raw = projection["relationships"]
    if not isinstance(relationships_raw, list):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory relationships are invalid"
        )
    relationships = [
        _validate_relationship(item, entity_refs=set(entity_refs))
        for item in relationships_raw
    ]
    relationship_refs = [str(item["relationship_ref_sha256"]) for item in relationships]
    if len(relationship_refs) != len(set(relationship_refs)):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory relationship references are duplicated"
        )
    graph = _strict_mapping(projection["entity_graph_manifest"], "entity graph manifest")
    if graph.get("schema") != INVENTORY_PROVENANCE_SCHEMA or graph.get("state") not in SOURCE_STATES:
        raise SharedGovernanceInventoryIntegrityError(
            "entity graph manifest identity is invalid"
        )
    for key in (
        "raw_names_included",
        "raw_aliases_included",
        "raw_record_ids_included",
        "raw_relationship_detail_included",
        "fuzzy_identity_merging_performed",
    ):
        if graph.get(key) is not False:
            raise SharedGovernanceInventoryIntegrityError(
                "entity graph minimization contract failed"
            )
    limitations = projection["limitations"]
    if not isinstance(limitations, list) or limitations != sorted(set(limitations)) or any(
        not isinstance(item, str) or not item or len(item) > 256 for item in limitations
    ):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory limitations are invalid"
        )
    limits = _strict_mapping(projection["limits"], "inventory limits")
    expected_limits = {
        "max_source_records",
        "max_entities",
        "max_relationships",
        "raw_source_records_persisted",
        "raw_private_fields_persisted",
        "fuzzy_identity_merging_performed",
        "live_source_interoperability_verified",
        "migration_acceptance_verified",
        "customer_acceptance_verified",
    }
    _exact_keys(limits, expected_limits, "inventory limits")
    for key in expected_limits - {
        "max_source_records",
        "max_entities",
        "max_relationships",
    }:
        if limits[key] is not False:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory limit disclosure is invalid"
            )
    if len(entities) > _integer(limits["max_entities"], "max_entities", 1, 100_000):
        raise SharedGovernanceInventoryIntegrityError("inventory entity bound failed")
    if len(relationships) > _integer(
        limits["max_relationships"], "max_relationships", 1, 200_000
    ):
        raise SharedGovernanceInventoryIntegrityError(
            "inventory relationship bound failed"
        )
    return projection


class SharedGovernanceInventoryStore:
    """Durable tenant authority for immutable inventory snapshots."""

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
        retention_seconds: int = 31_536_000,
        max_source_records: int = 10_000,
        max_entities: int = 20_000,
        max_relationships: int = 40_000,
        max_export_bytes: int = 10 * 1024 * 1024,
        max_snapshots: int = 10_000,
        recovery_directory: str | Path | None = None,
    ) -> None:
        if not all(
            callable(item)
            for item in (
                principal_resolver,
                maintenance_authorizer,
                config_gate,
                clock,
            )
        ):
            raise SharedGovernanceInventoryConfigError(
                "inventory dependencies must be callable"
            )
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise SharedGovernanceInventoryConfigError(
                "inventory integrity key must contain at least 32 bytes"
            )
        self.path = Path(path)
        self.tenant_id = _tenant(tenant_id)
        self._key = bytes(integrity_key)
        self._principal_resolver = principal_resolver
        self._maintenance_authorizer = maintenance_authorizer
        self._config_gate = config_gate
        self._clock = clock
        self.retention_seconds = _integer(
            retention_seconds, "retention_seconds", 86_400, 315_360_000
        )
        self.max_source_records = _integer(
            max_source_records, "max_source_records", 1, 100_000
        )
        self.max_entities = _integer(max_entities, "max_entities", 1, 100_000)
        self.max_relationships = _integer(
            max_relationships, "max_relationships", 1, 200_000
        )
        self.max_export_bytes = _integer(
            max_export_bytes, "max_export_bytes", 1_024, 100 * 1024 * 1024
        )
        self.max_snapshots = _integer(max_snapshots, "max_snapshots", 2, 10_000)
        self.recovery_directory = (
            self.path.parent / "recovery"
            if recovery_directory is None
            else Path(recovery_directory)
        )
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self._thread_lock = threading.RLock()
        self._initialize()

    @property
    def reference_key(self) -> bytes:
        """Internal projection key; compositions must never expose it."""

        return self._key

    def _gate(self) -> None:
        try:
            self._config_gate()
        except (KeyboardInterrupt, SystemExit):
            raise
        except SharedGovernanceInventoryError:
            raise
        except Exception as exc:
            raise SharedGovernanceInventoryConfigError(
                "inventory feature gate is unavailable"
            ) from exc

    def _principal(self) -> str:
        try:
            return _identifier(self._principal_resolver(), "principal_ref")
        except (KeyboardInterrupt, SystemExit):
            raise
        except SharedGovernanceInventoryError:
            raise
        except Exception as exc:
            raise SharedGovernanceInventoryPermissionDenied(
                "inventory principal authority is unavailable"
            ) from exc

    def _maintenance(self) -> None:
        try:
            admitted = self._maintenance_authorizer()
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            raise SharedGovernanceInventoryPermissionDenied(
                "inventory maintenance authority is unavailable"
            ) from exc
        if admitted is not True:
            raise SharedGovernanceInventoryPermissionDenied(
                "inventory maintenance authority is required"
            )

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
                    CREATE TABLE IF NOT EXISTS inventory_meta(
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS inventory_snapshots(
                        tenant_id TEXT NOT NULL,
                        snapshot_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        created_by_ref TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        source_count INTEGER NOT NULL,
                        entity_count INTEGER NOT NULL,
                        relationship_count INTEGER NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        previous_integrity_sha256 TEXT NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,snapshot_id),
                        UNIQUE(tenant_id,version)
                    );
                    CREATE TABLE IF NOT EXISTS inventory_payloads(
                        tenant_id TEXT NOT NULL,
                        snapshot_id TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,snapshot_id),
                        FOREIGN KEY(tenant_id,snapshot_id)
                          REFERENCES inventory_snapshots(tenant_id,snapshot_id)
                    );
                    CREATE TABLE IF NOT EXISTS inventory_active(
                        tenant_id TEXT PRIMARY KEY,
                        snapshot_id TEXT NOT NULL,
                        revision INTEGER NOT NULL,
                        updated_at REAL NOT NULL,
                        integrity_sha256 TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS inventory_operations(
                        tenant_id TEXT NOT NULL,
                        operation_id TEXT NOT NULL,
                        request_sha256 TEXT NOT NULL,
                        result_json TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,operation_id)
                    );
                    CREATE TABLE IF NOT EXISTS inventory_tombstones(
                        tenant_id TEXT NOT NULL,
                        snapshot_id TEXT NOT NULL,
                        version INTEGER NOT NULL,
                        payload_sha256 TEXT NOT NULL,
                        purged_by_ref TEXT NOT NULL,
                        purged_at REAL NOT NULL,
                        integrity_sha256 TEXT NOT NULL,
                        PRIMARY KEY(tenant_id,snapshot_id)
                    );
                    CREATE TRIGGER IF NOT EXISTS inventory_snapshots_immutable_update
                    BEFORE UPDATE ON inventory_snapshots BEGIN
                      SELECT RAISE(ABORT,'inventory snapshots are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS inventory_snapshots_immutable_delete
                    BEFORE DELETE ON inventory_snapshots BEGIN
                      SELECT RAISE(ABORT,'inventory snapshots are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS inventory_payloads_immutable_update
                    BEFORE UPDATE ON inventory_payloads BEGIN
                      SELECT RAISE(ABORT,'inventory payloads are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS inventory_operations_immutable_update
                    BEFORE UPDATE ON inventory_operations BEGIN
                      SELECT RAISE(ABORT,'inventory operations are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS inventory_operations_immutable_delete
                    BEFORE DELETE ON inventory_operations BEGIN
                      SELECT RAISE(ABORT,'inventory operations are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS inventory_tombstones_immutable_update
                    BEFORE UPDATE ON inventory_tombstones BEGIN
                      SELECT RAISE(ABORT,'inventory tombstones are immutable');
                    END;
                    CREATE TRIGGER IF NOT EXISTS inventory_tombstones_immutable_delete
                    BEFORE DELETE ON inventory_tombstones BEGIN
                      SELECT RAISE(ABORT,'inventory tombstones are immutable');
                    END;
                    """
                )
                row = connection.execute(
                    "SELECT value FROM inventory_meta WHERE key='schema_version'"
                ).fetchone()
                if row is None:
                    connection.execute(
                        "INSERT INTO inventory_meta(key,value) VALUES('schema_version',?)",
                        (str(SCHEMA_VERSION),),
                    )
                elif row["value"] != str(SCHEMA_VERSION):
                    raise SharedGovernanceInventoryIntegrityError(
                        "inventory schema version is unsupported"
                    )
                connection.commit()
        ensure_private_file(self.path)

    def _metadata_body(self, row: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema": SNAPSHOT_METADATA_SCHEMA,
            "tenant_id": row["tenant_id"],
            "snapshot_id": row["snapshot_id"],
            "version": row["version"],
            "state": row["state"],
            "created_by_ref": row["created_by_ref"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "source_count": row["source_count"],
            "entity_count": row["entity_count"],
            "relationship_count": row["relationship_count"],
            "payload_sha256": row["payload_sha256"],
            "previous_integrity_sha256": row["previous_integrity_sha256"],
        }

    def _validate_metadata(self, row: Mapping[str, object]) -> dict[str, object]:
        body = self._metadata_body(row)
        if body["tenant_id"] != self.tenant_id:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory snapshot tenant changed"
            )
        _identifier(body["snapshot_id"], "snapshot_id")
        _identifier(body["created_by_ref"], "created_by_ref")
        _integer(body["version"], "snapshot version", 1, self.max_snapshots)
        if body["state"] not in SNAPSHOT_STATES:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory snapshot state changed"
            )
        created_at = _timestamp(body["created_at"], "snapshot created_at")
        if _timestamp(body["expires_at"], "snapshot expires_at") <= created_at:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory snapshot retention is invalid"
            )
        if _integer(body["source_count"], "source_count", 1, len(_SOURCE_IDS)) != len(
            _SOURCE_IDS
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory source count changed"
            )
        _integer(body["entity_count"], "entity_count", 0, self.max_entities)
        _integer(
            body["relationship_count"],
            "relationship_count",
            0,
            self.max_relationships,
        )
        _digest(body["payload_sha256"], "snapshot payload")
        _digest(body["previous_integrity_sha256"], "previous snapshot")
        supplied = _digest(row["integrity_sha256"], "snapshot integrity")
        expected = _mac(self._key, body)
        if not hmac.compare_digest(supplied, expected):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory snapshot integrity changed"
            )
        return {**body, "integrity_sha256": supplied}

    def _active_body(self, row: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema": ACTIVE_SCHEMA,
            "tenant_id": row["tenant_id"],
            "snapshot_id": row["snapshot_id"],
            "revision": row["revision"],
            "updated_at": row["updated_at"],
        }

    def _active(
        self,
        connection: sqlite3.Connection,
    ) -> dict[str, object] | None:
        row = connection.execute(
            "SELECT * FROM inventory_active WHERE tenant_id=?",
            (self.tenant_id,),
        ).fetchone()
        if row is None:
            return None
        body = self._active_body(row)
        if body["tenant_id"] != self.tenant_id:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory active tenant changed"
            )
        _identifier(body["snapshot_id"], "active snapshot_id")
        _integer(body["revision"], "active revision", 1, self.max_snapshots)
        _timestamp(body["updated_at"], "active updated_at")
        supplied = _digest(row["integrity_sha256"], "active integrity")
        if not hmac.compare_digest(supplied, _mac(self._key, body)):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory active integrity changed"
            )
        linked = connection.execute(
            "SELECT version FROM inventory_snapshots "
            "WHERE tenant_id=? AND snapshot_id=?",
            (self.tenant_id, body["snapshot_id"]),
        ).fetchone()
        if linked is None or int(linked["version"]) != int(body["revision"]):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory active pointer is not exact"
            )
        return {**body, "integrity_sha256": supplied}

    def _operation(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        request: Mapping[str, object],
    ) -> dict[str, object] | None:
        operation = _identifier(operation_id, "operation_id")
        request_sha256 = _sha256(dict(request))
        row = connection.execute(
            "SELECT * FROM inventory_operations "
            "WHERE tenant_id=? AND operation_id=?",
            (self.tenant_id, operation),
        ).fetchone()
        if row is None:
            return None
        if not hmac.compare_digest(row["request_sha256"], request_sha256):
            raise SharedGovernanceInventoryConflict(
                "operation_id was reused with a different request"
            )
        body = {
            "schema": OPERATION_SCHEMA,
            "tenant_id": self.tenant_id,
            "operation_id": operation,
            "request_sha256": row["request_sha256"],
            "result_json": row["result_json"],
            "created_at": row["created_at"],
        }
        if not hmac.compare_digest(row["integrity_sha256"], _mac(self._key, body)):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory operation integrity changed"
            )
        try:
            result = json.loads(row["result_json"])
        except (TypeError, json.JSONDecodeError) as exc:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory operation result is unreadable"
            ) from exc
        if not isinstance(result, dict):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory operation result is invalid"
            )
        return result

    def _record_operation(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        request: Mapping[str, object],
        result: Mapping[str, object],
        now: float,
    ) -> None:
        operation = _identifier(operation_id, "operation_id")
        request_sha256 = _sha256(dict(request))
        result_json = _canonical(dict(result)).decode("ascii")
        body = {
            "schema": OPERATION_SCHEMA,
            "tenant_id": self.tenant_id,
            "operation_id": operation,
            "request_sha256": request_sha256,
            "result_json": result_json,
            "created_at": now,
        }
        connection.execute(
            "INSERT INTO inventory_operations VALUES(?,?,?,?,?,?)",
            (
                self.tenant_id,
                operation,
                request_sha256,
                result_json,
                now,
                _mac(self._key, body),
            ),
        )

    def _load_snapshot(
        self,
        connection: sqlite3.Connection,
        snapshot_id: str,
        *,
        require_payload: bool = True,
    ) -> dict[str, object]:
        selected = _identifier(snapshot_id, "snapshot_id")
        row = connection.execute(
            "SELECT * FROM inventory_snapshots "
            "WHERE tenant_id=? AND snapshot_id=?",
            (self.tenant_id, selected),
        ).fetchone()
        if row is None:
            raise SharedGovernanceInventoryNotFound("inventory snapshot not found")
        metadata = self._validate_metadata(row)
        payload_row = connection.execute(
            "SELECT payload_json,payload_sha256 FROM inventory_payloads "
            "WHERE tenant_id=? AND snapshot_id=?",
            (self.tenant_id, selected),
        ).fetchone()
        if payload_row is None:
            if require_payload:
                raise SharedGovernanceInventoryGone(
                    "inventory snapshot payload was retained out"
                )
            return {"metadata": metadata, "projection": None}
        if not hmac.compare_digest(
            payload_row["payload_sha256"], str(metadata["payload_sha256"])
        ) or not hmac.compare_digest(
            hashlib.sha256(payload_row["payload_json"].encode("ascii")).hexdigest(),
            str(metadata["payload_sha256"]),
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory payload digest changed"
            )
        try:
            projection = json.loads(payload_row["payload_json"])
        except (TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory payload is unreadable"
            ) from exc
        projection = validate_inventory_projection(
            projection,
            tenant_id=self.tenant_id,
        )
        if (
            projection["state"] != metadata["state"]
            or len(projection["source_manifests"]) != metadata["source_count"]
            or len(projection["entities"]) != metadata["entity_count"]
            or len(projection["relationships"]) != metadata["relationship_count"]
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory snapshot metadata disagrees with payload"
            )
        return {"metadata": metadata, "projection": projection}

    def _snapshot_from_operation_result(
        self,
        result: Mapping[str, object],
    ) -> dict[str, object]:
        if set(result) != {"kind", "snapshot_id", "version", "integrity_sha256"}:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory reconcile replay result is invalid"
            )
        if result["kind"] != "reconcile":
            raise SharedGovernanceInventoryIntegrityError(
                "inventory operation kind is invalid"
            )
        with self._connect() as connection:
            snapshot = self._load_snapshot(
                connection,
                _identifier(result["snapshot_id"], "snapshot_id"),
            )
        if (
            snapshot["metadata"]["version"] != result["version"]
            or not hmac.compare_digest(
                str(snapshot["metadata"]["integrity_sha256"]),
                _digest(result["integrity_sha256"], "replayed snapshot integrity"),
            )
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory replay result changed"
            )
        return snapshot

    def reconcile(
        self,
        *,
        provider: SuiteAuditCaptureProvider,
        provenance_reader: ProvenanceManifestReader,
        expected_active_revision: int,
        expected_active_integrity_sha256: str,
        operation_id: str,
    ) -> dict[str, object]:
        """Publish one stable read-model version under exact CAS/idempotency."""

        self._gate()
        self._maintenance()
        principal = self._principal()
        revision = _integer(
            expected_active_revision,
            "expected_active_revision",
            0,
            self.max_snapshots,
        )
        expected_integrity = _digest(
            expected_active_integrity_sha256,
            "expected_active_integrity_sha256",
        )
        operation = _identifier(operation_id, "operation_id")
        request = {
            "kind": "reconcile",
            "expected_active_revision": revision,
            "expected_active_integrity_sha256": expected_integrity,
        }
        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                replay = self._operation(
                    connection,
                    operation_id=operation,
                    request=request,
                )
        if replay is not None:
            return self._snapshot_from_operation_result(replay)

        projection = build_inventory_projection(
            tenant_id=self.tenant_id,
            provider=provider,
            provenance_reader=provenance_reader,
            reference_key=self._key,
            max_source_records=self.max_source_records,
            max_entities=self.max_entities,
            max_relationships=self.max_relationships,
            clock=self._clock,
        )
        projection = validate_inventory_projection(
            projection,
            tenant_id=self.tenant_id,
        )
        payload_json = _canonical(projection).decode("ascii")
        payload_sha256 = hashlib.sha256(payload_json.encode("ascii")).hexdigest()
        now = _clock_value(self._clock)

        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                self._begin(connection)
                replay = self._operation(
                    connection,
                    operation_id=operation,
                    request=request,
                )
                if replay is not None:
                    connection.commit()
                    replay_result = replay
                else:
                    active = self._active(connection)
                    actual_revision = 0 if active is None else int(active["revision"])
                    actual_integrity = (
                        GENESIS_SHA256
                        if active is None
                        else str(active["integrity_sha256"])
                    )
                    if actual_revision != revision or not hmac.compare_digest(
                        actual_integrity, expected_integrity
                    ):
                        raise SharedGovernanceInventoryConflict(
                            "inventory active pointer changed"
                        )
                    version = actual_revision + 1
                    if version > self.max_snapshots:
                        raise SharedGovernanceInventoryConflict(
                            "inventory snapshot capacity is exhausted"
                        )
                    previous_row = connection.execute(
                        "SELECT integrity_sha256 FROM inventory_snapshots "
                        "WHERE tenant_id=? ORDER BY version DESC LIMIT 1",
                        (self.tenant_id,),
                    ).fetchone()
                    previous = (
                        GENESIS_SHA256
                        if previous_row is None
                        else _digest(previous_row["integrity_sha256"], "previous snapshot")
                    )
                    snapshot_id = (
                        "sgi-"
                        + _mac(
                            self._key,
                            {
                                "schema": SNAPSHOT_SCHEMA,
                                "tenant_id": self.tenant_id,
                                "operation_id": operation,
                                "payload_sha256": payload_sha256,
                            },
                        )[:40]
                    )
                    metadata_body = {
                        "schema": SNAPSHOT_METADATA_SCHEMA,
                        "tenant_id": self.tenant_id,
                        "snapshot_id": snapshot_id,
                        "version": version,
                        "state": projection["state"],
                        "created_by_ref": principal,
                        "created_at": now,
                        "expires_at": now + self.retention_seconds,
                        "source_count": len(projection["source_manifests"]),
                        "entity_count": len(projection["entities"]),
                        "relationship_count": len(projection["relationships"]),
                        "payload_sha256": payload_sha256,
                        "previous_integrity_sha256": previous,
                    }
                    snapshot_integrity = _mac(self._key, metadata_body)
                    connection.execute(
                        "INSERT INTO inventory_snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            self.tenant_id,
                            snapshot_id,
                            version,
                            projection["state"],
                            principal,
                            now,
                            now + self.retention_seconds,
                            len(projection["source_manifests"]),
                            len(projection["entities"]),
                            len(projection["relationships"]),
                            payload_sha256,
                            previous,
                            snapshot_integrity,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO inventory_payloads VALUES(?,?,?,?)",
                        (
                            self.tenant_id,
                            snapshot_id,
                            payload_json,
                            payload_sha256,
                        ),
                    )
                    active_body = {
                        "schema": ACTIVE_SCHEMA,
                        "tenant_id": self.tenant_id,
                        "snapshot_id": snapshot_id,
                        "revision": version,
                        "updated_at": now,
                    }
                    active_integrity = _mac(self._key, active_body)
                    if active is None:
                        connection.execute(
                            "INSERT INTO inventory_active VALUES(?,?,?,?,?)",
                            (
                                self.tenant_id,
                                snapshot_id,
                                version,
                                now,
                                active_integrity,
                            ),
                        )
                    else:
                        cursor = connection.execute(
                            "UPDATE inventory_active SET snapshot_id=?,revision=?,"
                            "updated_at=?,integrity_sha256=? WHERE tenant_id=? "
                            "AND revision=? AND integrity_sha256=?",
                            (
                                snapshot_id,
                                version,
                                now,
                                active_integrity,
                                self.tenant_id,
                                revision,
                                expected_integrity,
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise SharedGovernanceInventoryConflict(
                                "inventory active pointer changed"
                            )
                    replay_result = {
                        "kind": "reconcile",
                        "snapshot_id": snapshot_id,
                        "version": version,
                        "integrity_sha256": snapshot_integrity,
                    }
                    self._record_operation(
                        connection,
                        operation_id=operation,
                        request=request,
                        result=replay_result,
                        now=now,
                    )
                    connection.commit()
        snapshot = self._snapshot_from_operation_result(replay_result)
        # A failed secondary checkpoint must not roll back an already durable
        # SQLite commit; readiness/status will disclose the missing checkpoint.
        try:
            self.write_recovery_checkpoint()
        except (KeyboardInterrupt, SystemExit):
            raise
        except SharedGovernanceInventoryError:
            pass
        return snapshot

    def active_authority(self) -> dict[str, object]:
        self._gate()
        with self._connect() as connection:
            active = self._active(connection)
        if active is None:
            return {
                "snapshot_id": None,
                "revision": 0,
                "updated_at": None,
                "integrity_sha256": GENESIS_SHA256,
            }
        return active

    def current_snapshot(self) -> dict[str, object]:
        self._gate()
        with self._connect() as connection:
            active = self._active(connection)
            if active is None:
                raise SharedGovernanceInventoryNotFound(
                    "inventory has no active snapshot"
                )
            return self._load_snapshot(connection, str(active["snapshot_id"]))

    def get_snapshot(self, snapshot_id: str) -> dict[str, object]:
        self._gate()
        with self._connect() as connection:
            return self._load_snapshot(connection, snapshot_id)

    def list_snapshots(self, *, limit: int = 100) -> list[dict[str, object]]:
        self._gate()
        selected_limit = _integer(limit, "limit", 1, _MAX_QUERY_LIMIT)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM inventory_snapshots WHERE tenant_id=? "
                "ORDER BY version DESC LIMIT ?",
                (self.tenant_id, selected_limit),
            ).fetchall()
            output: list[dict[str, object]] = []
            for row in rows:
                metadata = self._validate_metadata(row)
                payload = connection.execute(
                    "SELECT 1 FROM inventory_payloads "
                    "WHERE tenant_id=? AND snapshot_id=?",
                    (self.tenant_id, metadata["snapshot_id"]),
                ).fetchone()
                output.append({**metadata, "payload_available": payload is not None})
            return output

    def _selected_snapshot(
        self,
        connection: sqlite3.Connection,
        snapshot_id: str | None,
    ) -> dict[str, object]:
        if snapshot_id is not None:
            return self._load_snapshot(connection, snapshot_id)
        active = self._active(connection)
        if active is None:
            raise SharedGovernanceInventoryNotFound(
                "inventory has no active snapshot"
            )
        return self._load_snapshot(connection, str(active["snapshot_id"]))

    def query_entities(
        self,
        *,
        snapshot_id: str | None = None,
        source_id: str | None = None,
        origin: str | None = None,
        entity_kind: str | None = None,
        cursor: int = 0,
        limit: int = 100,
    ) -> dict[str, object]:
        """Return a bounded deterministic page from one immutable snapshot."""

        self._gate()
        selected_source = None
        if source_id is not None:
            if source_id not in _SOURCE_SET:
                raise SharedGovernanceInventoryValidationError(
                    "source_id is invalid"
                )
            selected_source = source_id
        if origin is not None and origin not in ORIGINS:
            raise SharedGovernanceInventoryValidationError("origin is invalid")
        if entity_kind is not None and entity_kind not in ENTITY_KINDS:
            raise SharedGovernanceInventoryValidationError(
                "entity_kind is invalid"
            )
        selected_cursor = _integer(cursor, "cursor", 0, 2_147_483_647)
        selected_limit = _integer(limit, "limit", 1, _MAX_QUERY_LIMIT)
        with self._connect() as connection:
            snapshot = self._selected_snapshot(connection, snapshot_id)
        items = snapshot["projection"]["entities"]
        filtered = [
            item
            for item in items
            if (selected_source is None or item.get("source_id") == selected_source)
            and (origin is None or item["origin"] == origin)
            and (entity_kind is None or item["entity_kind"] == entity_kind)
        ]
        page = filtered[selected_cursor : selected_cursor + selected_limit]
        next_cursor = selected_cursor + len(page)
        return {
            "snapshot_id": snapshot["metadata"]["snapshot_id"],
            "snapshot_version": snapshot["metadata"]["version"],
            "items": page,
            "count": len(page),
            "total_matching": len(filtered),
            "next_cursor": next_cursor if next_cursor < len(filtered) else None,
        }

    def query_relationships(
        self,
        *,
        snapshot_id: str | None = None,
        relation_type: str | None = None,
        entity_ref_sha256: str | None = None,
        cursor: int = 0,
        limit: int = 100,
    ) -> dict[str, object]:
        self._gate()
        if relation_type is not None and relation_type not in RELATION_KINDS:
            raise SharedGovernanceInventoryValidationError(
                "relation_type is invalid"
            )
        selected_ref = (
            None
            if entity_ref_sha256 is None
            else _digest(entity_ref_sha256, "entity_ref_sha256")
        )
        selected_cursor = _integer(cursor, "cursor", 0, 2_147_483_647)
        selected_limit = _integer(limit, "limit", 1, _MAX_QUERY_LIMIT)
        with self._connect() as connection:
            snapshot = self._selected_snapshot(connection, snapshot_id)
        items = snapshot["projection"]["relationships"]
        filtered = [
            item
            for item in items
            if (relation_type is None or item["relation_type"] == relation_type)
            and (
                selected_ref is None
                or item["source_entity_ref_sha256"] == selected_ref
                or item["target_entity_ref_sha256"] == selected_ref
            )
        ]
        page = filtered[selected_cursor : selected_cursor + selected_limit]
        next_cursor = selected_cursor + len(page)
        return {
            "snapshot_id": snapshot["metadata"]["snapshot_id"],
            "snapshot_version": snapshot["metadata"]["version"],
            "items": page,
            "count": len(page),
            "total_matching": len(filtered),
            "next_cursor": next_cursor if next_cursor < len(filtered) else None,
        }

    @staticmethod
    def public_snapshot(snapshot: Mapping[str, object]) -> dict[str, object]:
        """Remove the raw tenant identifier from an API/export representation."""

        metadata = dict(_strict_mapping(snapshot.get("metadata"), "snapshot metadata"))
        projection = dict(_strict_mapping(snapshot.get("projection"), "snapshot projection"))
        tenant = _tenant(projection.pop("tenant_id", None))
        metadata.pop("tenant_id", None)
        return {
            "schema": SNAPSHOT_SCHEMA,
            "tenant_sha256": hashlib.sha256(tenant.encode("utf-8")).hexdigest(),
            "metadata": metadata,
            "projection": projection,
        }

    def export_snapshot(self, snapshot_id: str | None = None) -> dict[str, object]:
        self._gate()
        with self._connect() as connection:
            snapshot = self._selected_snapshot(connection, snapshot_id)
        public = self.public_snapshot(snapshot)
        material = {
            "schema": EXPORT_SCHEMA,
            "snapshot": public,
            "export_sha256": _sha256(public),
        }
        encoded = _canonical(material)
        if len(encoded) > self.max_export_bytes:
            raise SharedGovernanceInventoryValidationError(
                "inventory export exceeds its configured bound"
            )
        return {**material, "export_bytes": len(encoded)}

    def _tombstone_body(self, row: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema": TOMBSTONE_SCHEMA,
            "tenant_id": row["tenant_id"],
            "snapshot_id": row["snapshot_id"],
            "version": row["version"],
            "payload_sha256": row["payload_sha256"],
            "purged_by_ref": row["purged_by_ref"],
            "purged_at": row["purged_at"],
        }

    def _validate_tombstone(self, row: Mapping[str, object]) -> dict[str, object]:
        body = self._tombstone_body(row)
        if body["tenant_id"] != self.tenant_id:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory tombstone tenant changed"
            )
        _identifier(body["snapshot_id"], "tombstone snapshot_id")
        _integer(body["version"], "tombstone version", 1, self.max_snapshots)
        _digest(body["payload_sha256"], "tombstone payload")
        _identifier(body["purged_by_ref"], "purged_by_ref")
        _timestamp(body["purged_at"], "purged_at")
        supplied = _digest(row["integrity_sha256"], "tombstone integrity")
        if not hmac.compare_digest(supplied, _mac(self._key, body)):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory tombstone integrity changed"
            )
        return {**body, "integrity_sha256": supplied}

    def purge_expired(
        self,
        *,
        expected_active_revision: int,
        expected_active_integrity_sha256: str,
        operation_id: str,
        retain_latest: int = 2,
    ) -> dict[str, object]:
        """Purge expired payloads while retaining immutable chain metadata."""

        self._gate()
        self._maintenance()
        principal = self._principal()
        revision = _integer(
            expected_active_revision,
            "expected_active_revision",
            1,
            self.max_snapshots,
        )
        expected_integrity = _digest(
            expected_active_integrity_sha256,
            "expected_active_integrity_sha256",
        )
        keep = _integer(retain_latest, "retain_latest", 1, 100)
        operation = _identifier(operation_id, "operation_id")
        request = {
            "kind": "retention",
            "expected_active_revision": revision,
            "expected_active_integrity_sha256": expected_integrity,
            "retain_latest": keep,
        }
        now = _clock_value(self._clock)
        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                self._begin(connection)
                replay = self._operation(
                    connection,
                    operation_id=operation,
                    request=request,
                )
                if replay is not None:
                    connection.commit()
                    return replay
                active = self._active(connection)
                if active is None:
                    raise SharedGovernanceInventoryConflict(
                        "inventory has no active pointer"
                    )
                if active["revision"] != revision or not hmac.compare_digest(
                    str(active["integrity_sha256"]), expected_integrity
                ):
                    raise SharedGovernanceInventoryConflict(
                        "inventory active pointer changed"
                    )
                cutoff_version = max(0, revision - keep)
                rows = connection.execute(
                    "SELECT s.* FROM inventory_snapshots s "
                    "JOIN inventory_payloads p ON p.tenant_id=s.tenant_id "
                    "AND p.snapshot_id=s.snapshot_id "
                    "WHERE s.tenant_id=? AND s.version<=? AND s.expires_at<=? "
                    "ORDER BY s.version",
                    (self.tenant_id, cutoff_version, now),
                ).fetchall()
                purged: list[str] = []
                for row in rows:
                    metadata = self._validate_metadata(row)
                    body = {
                        "schema": TOMBSTONE_SCHEMA,
                        "tenant_id": self.tenant_id,
                        "snapshot_id": metadata["snapshot_id"],
                        "version": metadata["version"],
                        "payload_sha256": metadata["payload_sha256"],
                        "purged_by_ref": principal,
                        "purged_at": now,
                    }
                    connection.execute(
                        "INSERT INTO inventory_tombstones VALUES(?,?,?,?,?,?,?)",
                        (
                            self.tenant_id,
                            metadata["snapshot_id"],
                            metadata["version"],
                            metadata["payload_sha256"],
                            principal,
                            now,
                            _mac(self._key, body),
                        ),
                    )
                    cursor = connection.execute(
                        "DELETE FROM inventory_payloads "
                        "WHERE tenant_id=? AND snapshot_id=? AND payload_sha256=?",
                        (
                            self.tenant_id,
                            metadata["snapshot_id"],
                            metadata["payload_sha256"],
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise SharedGovernanceInventoryConflict(
                            "inventory payload changed during retention"
                        )
                    purged.append(str(metadata["snapshot_id"]))
                lowest_purged = connection.execute(
                    "SELECT MIN(version) AS version FROM inventory_tombstones "
                    "WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchone()["version"]
                result = {
                    "kind": "retention",
                    "purged_snapshot_ids": purged,
                    "purged_count": len(purged),
                    "active_revision": revision,
                    "completed_at": now,
                }
                self._record_operation(
                    connection,
                    operation_id=operation,
                    request=request,
                    result=result,
                    now=now,
                )
                connection.commit()
        try:
            written = self.write_recovery_checkpoint()
        except (KeyboardInterrupt, SystemExit):
            raise
        except SharedGovernanceInventoryError:
            pass
        else:
            if lowest_purged is not None:
                self._remove_purged_checkpoints(
                    int(lowest_purged), int(written["revision"])
                )
        return result

    def _remove_purged_checkpoints(
        self, lowest_purged_version: int, current_revision: int
    ) -> None:
        """Remove earlier checkpoints that can still embed purged payloads.

        A checkpoint named for revision ``r`` holds every payload that existed
        when it was written, so each file from the lowest purged snapshot
        version up to, but excluding, the checkpoint just rewritten is stale.
        Files with another name are not this store's and are left alone.
        """

        for path in self._checkpoint_paths():
            match = _CHECKPOINT_NAME_RE.match(path.name)
            if match is None:
                continue
            if lowest_purged_version <= int(match.group(1)) < current_revision:
                path.unlink(missing_ok=True)

    def verify_integrity(self) -> dict[str, object]:
        self._gate()
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM inventory_snapshots WHERE tenant_id=? "
                "ORDER BY version",
                (self.tenant_id,),
            ).fetchall()
            previous = GENESIS_SHA256
            expected_version = 1
            payload_count = 0
            tombstone_count = 0
            for row in rows:
                metadata = self._validate_metadata(row)
                if metadata["version"] != expected_version or not hmac.compare_digest(
                    str(metadata["previous_integrity_sha256"]), previous
                ):
                    raise SharedGovernanceInventoryIntegrityError(
                        "inventory snapshot chain changed"
                    )
                payload = connection.execute(
                    "SELECT 1 FROM inventory_payloads "
                    "WHERE tenant_id=? AND snapshot_id=?",
                    (self.tenant_id, metadata["snapshot_id"]),
                ).fetchone()
                tombstone = connection.execute(
                    "SELECT * FROM inventory_tombstones "
                    "WHERE tenant_id=? AND snapshot_id=?",
                    (self.tenant_id, metadata["snapshot_id"]),
                ).fetchone()
                if (payload is None) == (tombstone is None):
                    raise SharedGovernanceInventoryIntegrityError(
                        "inventory payload retention state is ambiguous"
                    )
                if payload is not None:
                    self._load_snapshot(connection, str(metadata["snapshot_id"]))
                    payload_count += 1
                else:
                    validated = self._validate_tombstone(tombstone)
                    if (
                        validated["version"] != metadata["version"]
                        or not hmac.compare_digest(
                            str(validated["payload_sha256"]),
                            str(metadata["payload_sha256"]),
                        )
                    ):
                        raise SharedGovernanceInventoryIntegrityError(
                            "inventory tombstone does not match snapshot"
                        )
                    tombstone_count += 1
                previous = str(metadata["integrity_sha256"])
                expected_version += 1
            active = self._active(connection)
            if rows and active is None:
                raise SharedGovernanceInventoryIntegrityError(
                    "inventory active pointer is absent"
                )
            if active is not None:
                if not rows or active["revision"] != rows[-1]["version"]:
                    raise SharedGovernanceInventoryIntegrityError(
                        "inventory active pointer is stale"
                    )
                active_payload = connection.execute(
                    "SELECT 1 FROM inventory_payloads WHERE tenant_id=? AND snapshot_id=?",
                    (self.tenant_id, active["snapshot_id"]),
                ).fetchone()
                if active_payload is None:
                    raise SharedGovernanceInventoryIntegrityError(
                        "active inventory payload is absent"
                    )
            operation_rows = connection.execute(
                "SELECT * FROM inventory_operations WHERE tenant_id=?",
                (self.tenant_id,),
            ).fetchall()
            for row in operation_rows:
                body = {
                    "schema": OPERATION_SCHEMA,
                    "tenant_id": self.tenant_id,
                    "operation_id": row["operation_id"],
                    "request_sha256": row["request_sha256"],
                    "result_json": row["result_json"],
                    "created_at": row["created_at"],
                }
                _identifier(row["operation_id"], "operation_id")
                _digest(row["request_sha256"], "operation request")
                _timestamp(row["created_at"], "operation created_at")
                if not hmac.compare_digest(
                    row["integrity_sha256"], _mac(self._key, body)
                ):
                    raise SharedGovernanceInventoryIntegrityError(
                        "inventory operation chain changed"
                    )
            return {
                "schema": "lightwork.shared-governance-inventory-integrity.v1",
                "verified": True,
                "snapshot_count": len(rows),
                "payload_count": payload_count,
                "tombstone_count": tombstone_count,
                "operation_count": len(operation_rows),
                "terminal_sha256": previous,
                "active_revision": 0 if active is None else active["revision"],
            }

    def status(self) -> dict[str, object]:
        self._gate()
        with self._connect() as connection:
            active = self._active(connection)
            counts = connection.execute(
                "SELECT COUNT(*) AS snapshots,"
                "SUM(CASE WHEN p.snapshot_id IS NOT NULL THEN 1 ELSE 0 END) AS payloads "
                "FROM inventory_snapshots s LEFT JOIN inventory_payloads p "
                "ON p.tenant_id=s.tenant_id AND p.snapshot_id=s.snapshot_id "
                "WHERE s.tenant_id=?",
                (self.tenant_id,),
            ).fetchone()
            current_state = None
            current_limitations: list[str] = []
            source_states: list[dict[str, object]] = []
            if active is not None:
                snapshot = self._load_snapshot(connection, str(active["snapshot_id"]))
                projection = snapshot["projection"]
                current_state = projection["state"]
                current_limitations = list(projection["limitations"])
                source_states = [
                    {
                        "source_id": item["source_id"],
                        "state": item["state"],
                        "source_revision": item["source_revision"],
                        "head_sha256": item["head_sha256"],
                        "complete": item["complete"],
                        "retention_complete": item["retention_complete"],
                    }
                    for item in projection["source_manifests"]
                ]
        checkpoints = self._checkpoint_paths()
        return {
            "schema": "lightwork.shared-governance-inventory-status.v1",
            "enabled": True,
            "state": current_state or "unavailable",
            "active": active
            or {
                "snapshot_id": None,
                "revision": 0,
                "updated_at": None,
                "integrity_sha256": GENESIS_SHA256,
            },
            "snapshot_count": int(counts["snapshots"] or 0),
            "payload_count": int(counts["payloads"] or 0),
            "sources": source_states,
            "limitations": current_limitations
            or ["inventory_has_no_active_snapshot"],
            "recovery_checkpoint_available": bool(checkpoints),
            "complete": current_state == "available",
            "raw_source_records_persisted": False,
            "raw_private_fields_persisted": False,
            "fuzzy_identity_merging_performed": False,
            "live_source_interoperability_verified": False,
            "migration_acceptance_verified": False,
            "customer_acceptance_verified": False,
        }

    def _checkpoint_paths(self) -> list[Path]:
        try:
            if not self.recovery_directory.is_dir():
                return []
            return sorted(
                (
                    path
                    for path in self.recovery_directory.glob("inventory-*.json")
                    if path.is_file()
                ),
                key=lambda path: path.name,
            )
        except OSError:
            return []

    @staticmethod
    def _rows(connection: sqlite3.Connection, table: str, tenant_id: str) -> list[dict]:
        allowed = {
            "inventory_snapshots",
            "inventory_payloads",
            "inventory_active",
            "inventory_operations",
            "inventory_tombstones",
        }
        if table not in allowed:  # pragma: no cover - closed internal constant
            raise SharedGovernanceInventoryIntegrityError(
                "inventory recovery table is invalid"
            )
        return [
            dict(row)
            for row in connection.execute(
                f"SELECT * FROM {table} WHERE tenant_id=? ORDER BY rowid",
                (tenant_id,),
            ).fetchall()
        ]

    def write_recovery_checkpoint(self) -> dict[str, object]:
        """Write a private, authenticated full-state checkpoint atomically."""

        self._gate()
        self._maintenance()
        integrity = self.verify_integrity()
        with self._connect() as connection:
            active_rows = self._rows(connection, "inventory_active", self.tenant_id)
            if len(active_rows) != 1:
                raise SharedGovernanceInventoryNotFound(
                    "inventory has no active snapshot"
                )
            material = {
                "schema": RECOVERY_SCHEMA,
                "tenant_id": self.tenant_id,
                "created_at": _clock_value(self._clock),
                "snapshots": self._rows(
                    connection, "inventory_snapshots", self.tenant_id
                ),
                "payloads": self._rows(
                    connection, "inventory_payloads", self.tenant_id
                ),
                "active": active_rows[0],
                "operations": self._rows(
                    connection, "inventory_operations", self.tenant_id
                ),
                "tombstones": self._rows(
                    connection, "inventory_tombstones", self.tenant_id
                ),
            }
        envelope = {**material, "recovery_integrity_sha256": _mac(self._key, material)}
        encoded = _canonical(envelope)
        if len(encoded) > _MAX_RECOVERY_BYTES:
            raise SharedGovernanceInventoryValidationError(
                "inventory recovery checkpoint exceeds its bound"
            )
        ensure_private_directory(self.recovery_directory)
        active = material["active"]
        path = self.recovery_directory / (
            f"inventory-{int(active['revision']):08d}-"
            f"{str(active['integrity_sha256'])[:16]}.json"
        )
        atomic_write_text(path, encoded.decode("ascii"), mode=0o600)
        ensure_private_file(path)
        return {
            "schema": RECOVERY_SCHEMA,
            "written": True,
            "revision": active["revision"],
            "checkpoint_sha256": hashlib.sha256(encoded).hexdigest(),
            "checkpoint_bytes": len(encoded),
            "snapshot_count": integrity["snapshot_count"],
        }

    def recover_latest(self) -> dict[str, object]:
        """Restore an empty authority from the newest server-held checkpoint."""

        self._gate()
        self._maintenance()
        paths = self._checkpoint_paths()
        if not paths:
            raise SharedGovernanceInventoryNotFound(
                "inventory recovery checkpoint not found"
            )
        path = paths[-1]
        try:
            size = path.stat().st_size
            if not 1 <= size <= _MAX_RECOVERY_BYTES:
                raise SharedGovernanceInventoryIntegrityError(
                    "inventory recovery checkpoint size is invalid"
                )
            raw = path.read_text(encoding="ascii")
            envelope = json.loads(raw)
        except SharedGovernanceInventoryError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SharedGovernanceInventoryIntegrityError(
                "inventory recovery checkpoint is unreadable"
            ) from exc
        value = _strict_mapping(envelope, "inventory recovery checkpoint")
        expected_keys = {
            "schema",
            "tenant_id",
            "created_at",
            "snapshots",
            "payloads",
            "active",
            "operations",
            "tombstones",
            "recovery_integrity_sha256",
        }
        _exact_keys(value, expected_keys, "inventory recovery checkpoint")
        supplied = _digest(
            value.pop("recovery_integrity_sha256"),
            "recovery integrity",
        )
        if (
            value["schema"] != RECOVERY_SCHEMA
            or value["tenant_id"] != self.tenant_id
            or not hmac.compare_digest(supplied, _mac(self._key, value))
        ):
            raise SharedGovernanceInventoryIntegrityError(
                "inventory recovery checkpoint integrity changed"
            )
        _timestamp(value["created_at"], "recovery created_at")
        for key in ("snapshots", "payloads", "operations", "tombstones"):
            if not isinstance(value[key], list):
                raise SharedGovernanceInventoryIntegrityError(
                    "inventory recovery collection is invalid"
                )
        active = _strict_mapping(value["active"], "recovery active pointer")
        with self._thread_lock, cross_process_lock(self._lock_path):
            with self._connect() as connection:
                self._begin(connection)
                occupied = connection.execute(
                    "SELECT (SELECT COUNT(*) FROM inventory_snapshots WHERE tenant_id=?) + "
                    "(SELECT COUNT(*) FROM inventory_active WHERE tenant_id=?) AS n",
                    (self.tenant_id, self.tenant_id),
                ).fetchone()["n"]
                if occupied:
                    raise SharedGovernanceInventoryConflict(
                        "inventory recovery requires an empty authority"
                    )
                snapshot_columns = (
                    "tenant_id",
                    "snapshot_id",
                    "version",
                    "state",
                    "created_by_ref",
                    "created_at",
                    "expires_at",
                    "source_count",
                    "entity_count",
                    "relationship_count",
                    "payload_sha256",
                    "previous_integrity_sha256",
                    "integrity_sha256",
                )
                payload_columns = (
                    "tenant_id",
                    "snapshot_id",
                    "payload_json",
                    "payload_sha256",
                )
                active_columns = (
                    "tenant_id",
                    "snapshot_id",
                    "revision",
                    "updated_at",
                    "integrity_sha256",
                )
                operation_columns = (
                    "tenant_id",
                    "operation_id",
                    "request_sha256",
                    "result_json",
                    "created_at",
                    "integrity_sha256",
                )
                tombstone_columns = (
                    "tenant_id",
                    "snapshot_id",
                    "version",
                    "payload_sha256",
                    "purged_by_ref",
                    "purged_at",
                    "integrity_sha256",
                )
                for raw_row in value["snapshots"]:
                    row = _strict_mapping(raw_row, "recovery snapshot")
                    _exact_keys(row, set(snapshot_columns), "recovery snapshot")
                    connection.execute(
                        "INSERT INTO inventory_snapshots VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        tuple(row[key] for key in snapshot_columns),
                    )
                for raw_row in value["payloads"]:
                    row = _strict_mapping(raw_row, "recovery payload")
                    _exact_keys(row, set(payload_columns), "recovery payload")
                    connection.execute(
                        "INSERT INTO inventory_payloads VALUES(?,?,?,?)",
                        tuple(row[key] for key in payload_columns),
                    )
                _exact_keys(active, set(active_columns), "recovery active pointer")
                connection.execute(
                    "INSERT INTO inventory_active VALUES(?,?,?,?,?)",
                    tuple(active[key] for key in active_columns),
                )
                for raw_row in value["operations"]:
                    row = _strict_mapping(raw_row, "recovery operation")
                    _exact_keys(row, set(operation_columns), "recovery operation")
                    connection.execute(
                        "INSERT INTO inventory_operations VALUES(?,?,?,?,?,?)",
                        tuple(row[key] for key in operation_columns),
                    )
                for raw_row in value["tombstones"]:
                    row = _strict_mapping(raw_row, "recovery tombstone")
                    _exact_keys(row, set(tombstone_columns), "recovery tombstone")
                    connection.execute(
                        "INSERT INTO inventory_tombstones VALUES(?,?,?,?,?,?,?)",
                        tuple(row[key] for key in tombstone_columns),
                    )
                # Validate every recovered row before the transaction is made
                # visible.  SQLite rollback leaves the empty authority intact.
                previous = GENESIS_SHA256
                rows = connection.execute(
                    "SELECT * FROM inventory_snapshots WHERE tenant_id=? "
                    "ORDER BY version",
                    (self.tenant_id,),
                ).fetchall()
                for index, row in enumerate(rows, start=1):
                    metadata = self._validate_metadata(row)
                    if metadata["version"] != index or metadata[
                        "previous_integrity_sha256"
                    ] != previous:
                        raise SharedGovernanceInventoryIntegrityError(
                            "recovered inventory chain is invalid"
                        )
                    payload = connection.execute(
                        "SELECT 1 FROM inventory_payloads WHERE tenant_id=? AND snapshot_id=?",
                        (self.tenant_id, metadata["snapshot_id"]),
                    ).fetchone()
                    tombstone = connection.execute(
                        "SELECT * FROM inventory_tombstones WHERE tenant_id=? AND snapshot_id=?",
                        (self.tenant_id, metadata["snapshot_id"]),
                    ).fetchone()
                    if (payload is None) == (tombstone is None):
                        raise SharedGovernanceInventoryIntegrityError(
                            "recovered payload state is ambiguous"
                        )
                    if payload is not None:
                        self._load_snapshot(connection, str(metadata["snapshot_id"]))
                    else:
                        validated_tombstone = self._validate_tombstone(tombstone)
                        if (
                            validated_tombstone["version"] != metadata["version"]
                            or not hmac.compare_digest(
                                str(validated_tombstone["payload_sha256"]),
                                str(metadata["payload_sha256"]),
                            )
                        ):
                            raise SharedGovernanceInventoryIntegrityError(
                                "recovered tombstone does not match snapshot"
                            )
                    previous = str(metadata["integrity_sha256"])
                self._active(connection)
                operation_rows = connection.execute(
                    "SELECT * FROM inventory_operations WHERE tenant_id=?",
                    (self.tenant_id,),
                ).fetchall()
                for row in operation_rows:
                    body = {
                        "schema": OPERATION_SCHEMA,
                        "tenant_id": self.tenant_id,
                        "operation_id": row["operation_id"],
                        "request_sha256": row["request_sha256"],
                        "result_json": row["result_json"],
                        "created_at": row["created_at"],
                    }
                    _identifier(row["operation_id"], "operation_id")
                    _digest(row["request_sha256"], "operation request")
                    _timestamp(row["created_at"], "operation created_at")
                    if not hmac.compare_digest(
                        row["integrity_sha256"], _mac(self._key, body)
                    ):
                        raise SharedGovernanceInventoryIntegrityError(
                            "recovered operation integrity changed"
                        )
                connection.commit()
        verified = self.verify_integrity()
        return {
            "schema": RECOVERY_SCHEMA,
            "recovered": True,
            "active_revision": verified["active_revision"],
            "snapshot_count": verified["snapshot_count"],
            "terminal_sha256": verified["terminal_sha256"],
        }


__all__ = [
    "ACTIVE_SCHEMA",
    "ENTITY_KINDS",
    "EXPORT_SCHEMA",
    "GENESIS_SHA256",
    "INVENTORY_SCHEMA",
    "OPERATION_SCHEMA",
    "RECOVERY_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "SOURCE_MANIFEST_SCHEMA",
    "SOURCE_STATES",
    "SharedGovernanceInventoryConfigError",
    "SharedGovernanceInventoryConflict",
    "SharedGovernanceInventoryError",
    "SharedGovernanceInventoryGone",
    "SharedGovernanceInventoryIntegrityError",
    "SharedGovernanceInventoryNotFound",
    "SharedGovernanceInventoryPermissionDenied",
    "SharedGovernanceInventoryStore",
    "SharedGovernanceInventoryValidationError",
    "build_inventory_projection",
    "validate_inventory_projection",
]
