"""Continuous, bounded collection of identity-governance snapshot digests.

The provider adapters return normalized pseudonymous observations.  This
module deliberately narrows that output again before persistence: governed
state contains only hashes, counts, bounded hash deltas, and scheduler health.
Provider payloads, pseudonymous row identifiers, names, email addresses,
credential references, secret values, and tokens are never retained.

Scheduling is opt-in twice: the connector and its provider schedule must both
be enabled.  A successful run remains an explicitly incomplete, read-only
source observation; it is not live-provider acceptance or a complete inventory.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from maverick.ai_identity_governance_connectors import PROVIDERS

log = logging.getLogger(__name__)

# Spelled out so the schedulable providers are visible here; the check below
# keeps this list and the connector module's list the same.
_PROVIDERS = ("entra", "okta", "purview")
if frozenset(_PROVIDERS) != frozenset(PROVIDERS):
    raise RuntimeError("identity-governance scheduler providers are inconsistent")
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_PSEUDONYMOUS_ID_RE = re.compile(r"(?:idn|sub|res|prm|grt|cls|ast)_[0-9a-f]{32}\Z")
_CODE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}\Z")
_ERROR_TYPE_RE = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}\Z")

_SNAPSHOT_KEYS = frozenset(
    {
        "schema",
        "provider",
        "tenant_sha256",
        "configuration_sha256",
        "observed_at",
        "source_sha256",
        "identities",
        "grants",
        "data_classifications",
        "coverage",
        "live_acceptance_verified",
        "complete_inventory_claimed",
    }
)
_IDENTITY_KEYS = frozenset(
    {
        "observation_id",
        "identity_kind",
        "enabled",
        "assignment_required",
        "source_sha256",
    }
)
_GRANT_KEYS = frozenset(
    {
        "observation_id",
        "subject_id",
        "resource_id",
        "grant_kind",
        "subject_kind",
        "permission_id",
        "source_sha256",
    }
)
_CLASSIFICATION_KEYS = frozenset(
    {
        "observation_id",
        "asset_id",
        "entity_type",
        "classification_codes",
        "label_codes",
        "source_sha256",
    }
)
_IDENTITY_KINDS = frozenset(
    {"agent_identity", "application", "managed_identity", "legacy_application"}
)
_GRANT_KINDS = frozenset({"application_role", "application_assignment"})
_SUBJECT_KINDS = frozenset({"user", "group", "service_principal", "unknown"})

_DEFAULT_POLL_SECONDS = 60.0
_MIN_POLL_SECONDS = 5.0
_MAX_POLL_SECONDS = 3600.0
_MIN_INTERVAL_SECONDS = 60
_MAX_INTERVAL_SECONDS = 24 * 60 * 60
_MIN_LEASE_SECONDS = 60
_MAX_LEASE_SECONDS = 24 * 60 * 60
_MAX_RETRY_ATTEMPTS = 10
_MAX_HISTORY = 32
_MAX_SNAPSHOT_ITEMS = 10_000
_MAX_DELTA_DIGESTS = 512
_MAX_PENDING_CHANGES = 8

_STATE_SCHEMA = "lightwork.identity_governance.scheduler-state.v1"
_DIGEST_SCHEMA = "lightwork.identity_governance.snapshot-digest.v1"
_DELTA_SCHEMA = "lightwork.identity_governance.snapshot-delta.v1"
_CHANGE_SCHEMA = "lightwork.identity_governance.normalized-change.v1"
_STATUS_SCHEMA = "lightwork.identity_governance.scheduler-runtime-status.v1"

_HEALTH_VALUES = frozenset({"never_run", "healthy", "degraded", "unavailable"})
_CALLBACK_HEALTH_VALUES = frozenset({"not_configured", "healthy", "degraded"})
_SOURCE_STATE_VALUES = frozenset({"incomplete", "unavailable"})

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None
_provider_locks_guard = threading.Lock()
_provider_locks: dict[tuple[str, str], threading.Lock] = {}
_default_engine_lock = threading.Lock()
_default_engine: IdentityGovernanceScheduler | None = None
_composed_engine_factory_lock = threading.Lock()
_composed_engine_factory: Callable[[object], object | None] | None = None


class IdentityGovernanceScheduleError(ValueError):
    """A scheduler configuration is ambiguous or outside finite bounds."""


class IdentityGovernanceSnapshotError(ValueError):
    """A collected snapshot violates the closed digesting contract."""


@dataclass(frozen=True)
class ProviderSchedule:
    """Finite collection and retention bounds for one provider."""

    provider: str
    interval_seconds: int = 60 * 60
    retry_base_seconds: int = 30
    retry_max_seconds: int = 15 * 60
    max_attempts_per_slot: int = 3
    lease_seconds: int = 60 * 60
    history_limit: int = 8
    max_snapshot_items: int = 5_000
    max_delta_digests: int = 256

    def __post_init__(self) -> None:
        if self.provider not in _PROVIDERS:
            raise IdentityGovernanceScheduleError("scheduler provider is unsupported")
        _bounded_int(
            self.interval_seconds,
            "interval_seconds",
            _MIN_INTERVAL_SECONDS,
            _MAX_INTERVAL_SECONDS,
        )
        _bounded_int(
            self.retry_base_seconds,
            "retry_base_seconds",
            1,
            60 * 60,
        )
        _bounded_int(
            self.retry_max_seconds,
            "retry_max_seconds",
            self.retry_base_seconds,
            _MAX_INTERVAL_SECONDS,
        )
        _bounded_int(
            self.max_attempts_per_slot,
            "max_attempts_per_slot",
            1,
            _MAX_RETRY_ATTEMPTS,
        )
        _bounded_int(
            self.lease_seconds,
            "lease_seconds",
            _MIN_LEASE_SECONDS,
            _MAX_LEASE_SECONDS,
        )
        _bounded_int(self.history_limit, "history_limit", 1, _MAX_HISTORY)
        _bounded_int(
            self.max_snapshot_items,
            "max_snapshot_items",
            1,
            _MAX_SNAPSHOT_ITEMS,
        )
        _bounded_int(
            self.max_delta_digests,
            "max_delta_digests",
            0,
            _MAX_DELTA_DIGESTS,
        )

    @property
    def configuration_sha256(self) -> str:
        return _sha256(
            {
                "schema": "lightwork.identity_governance.schedule.v1",
                "provider": self.provider,
                "interval_seconds": self.interval_seconds,
                "retry_base_seconds": self.retry_base_seconds,
                "retry_max_seconds": self.retry_max_seconds,
                "max_attempts_per_slot": self.max_attempts_per_slot,
                "lease_seconds": self.lease_seconds,
                "history_limit": self.history_limit,
                "max_snapshot_items": self.max_snapshot_items,
                "max_delta_digests": self.max_delta_digests,
            }
        )


def _bounded_int(value: object, name: str, lower: int, upper: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IdentityGovernanceScheduleError(f"scheduler {name} must be an integer")
    if not lower <= value <= upper:
        raise IdentityGovernanceScheduleError(
            f"scheduler {name} must be between {lower} and {upper}"
        )
    return value


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise IdentityGovernanceSnapshotError(
            "identity-governance value is not bounded canonical JSON"
        ) from exc


def _sha256(value: object) -> str:
    payload = value if isinstance(value, bytes) else _canonical_json(value)
    return hashlib.sha256(payload).hexdigest()


def tenant_binding_sha256(*, require_explicit: bool = False) -> str:
    """Return the scheduler's tenant binding without retaining the raw tenant.

    Existing read-only scheduling retains its historical shared fallback.
    Control-plane callbacks can set ``require_explicit`` to fail closed instead
    of admitting mutation or alert state into a shared tenant namespace.
    """

    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict()
    if tenant is None:
        if require_explicit:
            raise IdentityGovernanceScheduleError(
                "identity-governance controls require an explicit tenant"
            )
        tenant = "<shared>"
    return _sha256(b"lightwork-identity-governance-scheduler-tenant-v1\0" + tenant.encode())


def _tenant_sha256() -> str:
    return tenant_binding_sha256()


def _record_id(tenant_sha256: str, provider: str) -> str:
    material = f"{tenant_sha256}\0{provider}".encode("ascii")
    return f"IGSC-{hashlib.sha256(material).hexdigest()[:40]}"


def _provider_lock(tenant_sha256: str, provider: str) -> threading.Lock:
    key = (tenant_sha256, provider)
    with _provider_locks_guard:
        lock = _provider_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _provider_locks[key] = lock
        return lock


def _mapping(value: object, category: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IdentityGovernanceSnapshotError(category)
    return value


def _sequence(value: object, category: str) -> Sequence[Any]:
    if not isinstance(value, (list, tuple)):
        raise IdentityGovernanceSnapshotError(category)
    return value


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str], category: str) -> None:
    if set(value) != expected:
        raise IdentityGovernanceSnapshotError(category)


def _sha(value: object, category: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise IdentityGovernanceSnapshotError(category)
    return value


def _pseudonymous_id(value: object, category: str) -> str:
    if not isinstance(value, str) or not _PSEUDONYMOUS_ID_RE.fullmatch(value):
        raise IdentityGovernanceSnapshotError(category)
    return value


def _closed_text(value: object, admitted: frozenset[str], category: str) -> str:
    if not isinstance(value, str) or value not in admitted:
        raise IdentityGovernanceSnapshotError(category)
    return value


def _codes(value: object, category: str) -> list[str]:
    rows = _sequence(value, category)
    if len(rows) > 128:
        raise IdentityGovernanceSnapshotError(category)
    codes: list[str] = []
    for item in rows:
        if not isinstance(item, str) or not _CODE_RE.fullmatch(item):
            raise IdentityGovernanceSnapshotError(category)
        codes.append(item)
    if codes != sorted(set(codes)):
        raise IdentityGovernanceSnapshotError(category)
    return codes


def _observed_at(value: object) -> None:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise IdentityGovernanceSnapshotError("snapshot observed_at is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise IdentityGovernanceSnapshotError("snapshot observed_at is invalid") from None
    if parsed.tzinfo is None:
        raise IdentityGovernanceSnapshotError("snapshot observed_at is invalid")


def _item_digest(
    value: object,
    *,
    category: str,
    keys: frozenset[str],
    seen: set[str],
) -> str:
    row = _mapping(value, f"snapshot {category} item must be a table")
    _exact_keys(row, keys, f"snapshot {category} item keys are unsupported")
    observation_id = _pseudonymous_id(
        row.get("observation_id"), f"snapshot {category} observation id is invalid"
    )
    if observation_id in seen:
        raise IdentityGovernanceSnapshotError(f"snapshot {category} observation id is duplicated")
    seen.add(observation_id)
    _sha(row.get("source_sha256"), f"snapshot {category} source digest is invalid")

    normalized = dict(row)
    if category == "identities":
        _closed_text(
            row.get("identity_kind"),
            _IDENTITY_KINDS,
            "snapshot identity kind is invalid",
        )
        if not isinstance(row.get("enabled"), bool):
            raise IdentityGovernanceSnapshotError("snapshot identity state is invalid")
        assignment_required = row.get("assignment_required")
        if assignment_required is not None and not isinstance(assignment_required, bool):
            raise IdentityGovernanceSnapshotError("snapshot identity assignment state is invalid")
    elif category == "grants":
        for field in ("subject_id", "resource_id", "permission_id"):
            _pseudonymous_id(row.get(field), f"snapshot grant {field} is not pseudonymous")
        _closed_text(
            row.get("grant_kind"),
            _GRANT_KINDS,
            "snapshot grant kind is invalid",
        )
        _closed_text(
            row.get("subject_kind"),
            _SUBJECT_KINDS,
            "snapshot grant subject kind is invalid",
        )
    else:
        _pseudonymous_id(
            row.get("asset_id"), "snapshot classification asset id is not pseudonymous"
        )
        entity_type = row.get("entity_type")
        if not isinstance(entity_type, str) or not _CODE_RE.fullmatch(entity_type):
            raise IdentityGovernanceSnapshotError("snapshot classification entity type is invalid")
        normalized["classification_codes"] = _codes(
            row.get("classification_codes"),
            "snapshot classification codes are invalid",
        )
        normalized["label_codes"] = _codes(
            row.get("label_codes"), "snapshot label codes are invalid"
        )
    return _sha256(normalized)


def digest_snapshot(
    snapshot: object,
    *,
    provider: str,
    collected_at: float,
    max_snapshot_items: int,
) -> dict[str, Any]:
    """Validate and irreversibly narrow one adapter snapshot for retention."""

    if provider not in _PROVIDERS:
        raise IdentityGovernanceSnapshotError("snapshot provider is unsupported")
    if not math.isfinite(collected_at) or collected_at <= 0:
        raise IdentityGovernanceSnapshotError("collection time is invalid")
    _bounded_int(
        max_snapshot_items,
        "max_snapshot_items",
        1,
        _MAX_SNAPSHOT_ITEMS,
    )
    row = _mapping(snapshot, "snapshot must be a table")
    _exact_keys(row, _SNAPSHOT_KEYS, "snapshot keys are unsupported")
    if row.get("schema") != "lightwork.identity_governance.snapshot.v1":
        raise IdentityGovernanceSnapshotError("snapshot schema is unsupported")
    if row.get("provider") != provider:
        raise IdentityGovernanceSnapshotError("snapshot provider does not match")
    if row.get("coverage") != "bounded_read_only_snapshot":
        raise IdentityGovernanceSnapshotError("snapshot coverage is unsupported")
    if row.get("live_acceptance_verified") is not False:
        raise IdentityGovernanceSnapshotError("snapshot cannot claim live provider acceptance")
    if row.get("complete_inventory_claimed") is not False:
        raise IdentityGovernanceSnapshotError("snapshot cannot claim complete source coverage")
    _observed_at(row.get("observed_at"))
    provider_tenant_sha256 = _sha(row.get("tenant_sha256"), "snapshot tenant digest is invalid")
    configuration_sha256 = _sha(
        row.get("configuration_sha256"),
        "snapshot configuration digest is invalid",
    )
    source_sha256 = _sha(row.get("source_sha256"), "snapshot source digest is invalid")

    values = {
        "identities": _sequence(row.get("identities"), "snapshot identities are invalid"),
        "grants": _sequence(row.get("grants"), "snapshot grants are invalid"),
        "data_classifications": _sequence(
            row.get("data_classifications"),
            "snapshot classifications are invalid",
        ),
    }
    total = sum(len(items) for items in values.values())
    if total > max_snapshot_items:
        raise IdentityGovernanceSnapshotError("snapshot item limit exceeded")

    keys = {
        "identities": _IDENTITY_KEYS,
        "grants": _GRANT_KEYS,
        "data_classifications": _CLASSIFICATION_KEYS,
    }
    item_digests: dict[str, list[str]] = {}
    for category, items in values.items():
        seen: set[str] = set()
        digests = [
            _item_digest(
                item,
                category=category,
                keys=keys[category],
                seen=seen,
            )
            for item in items
        ]
        item_digests[category] = sorted(digests)

    digest_material = {
        "schema": _DIGEST_SCHEMA,
        "provider": provider,
        "provider_tenant_sha256": provider_tenant_sha256,
        "configuration_sha256": configuration_sha256,
        "source_sha256": source_sha256,
        "item_digests": item_digests,
        "coverage": "bounded_read_only_snapshot",
        "source_complete": False,
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
    }
    return {
        "schema": _DIGEST_SCHEMA,
        "provider": provider,
        "provider_tenant_sha256": provider_tenant_sha256,
        "configuration_sha256": configuration_sha256,
        "source_sha256": source_sha256,
        "snapshot_sha256": _sha256(digest_material),
        "collected_at": float(collected_at),
        "counts": {
            "identities": len(item_digests["identities"]),
            "grants": len(item_digests["grants"]),
            "data_classifications": len(item_digests["data_classifications"]),
            "total": total,
        },
        "item_digests": item_digests,
        "coverage": "bounded_read_only_snapshot",
        "source_state": "incomplete",
        "source_complete": False,
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
    }


def _history_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Drop per-item material from history while preserving snapshot evidence."""

    return {key: value for key, value in snapshot.items() if key != "item_digests"}


def _delta_category(
    previous: Sequence[str],
    current: Sequence[str],
    *,
    limit: int,
) -> dict[str, Any]:
    before = set(previous)
    after = set(current)
    added = sorted(after - before)
    removed = sorted(before - after)
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "added_sha256": added[:limit],
        "removed_sha256": removed[:limit],
        "digests_truncated": len(added) > limit or len(removed) > limit,
    }


def snapshot_delta(
    previous: Mapping[str, Any] | None,
    current: Mapping[str, Any],
    *,
    max_delta_digests: int,
) -> dict[str, Any]:
    """Return an exact-count, bounded-digest delta without generating risk."""

    _bounded_int(
        max_delta_digests,
        "max_delta_digests",
        0,
        _MAX_DELTA_DIGESTS,
    )
    previous_items = previous.get("item_digests") if isinstance(previous, Mapping) else None
    if not isinstance(previous_items, Mapping):
        previous_items = {}
    current_items = current.get("item_digests")
    if not isinstance(current_items, Mapping):
        raise IdentityGovernanceSnapshotError("current digest state is invalid")
    categories: dict[str, dict[str, Any]] = {}
    for category in ("identities", "grants", "data_classifications"):
        before = previous_items.get(category, ())
        after = current_items.get(category, ())
        if not isinstance(before, (list, tuple)) or not isinstance(after, (list, tuple)):
            raise IdentityGovernanceSnapshotError("retained digest state is invalid")
        categories[category] = _delta_category(
            before,
            after,
            limit=max_delta_digests,
        )
    previous_sha = (
        str(previous.get("snapshot_sha256") or "") if isinstance(previous, Mapping) else ""
    )
    changed = previous is None or previous_sha != current["snapshot_sha256"]
    return {
        "schema": _DELTA_SCHEMA,
        "change_kind": "baseline" if previous is None else "comparison",
        "changed": changed,
        "previous_snapshot_sha256": previous_sha or None,
        "current_snapshot_sha256": current["snapshot_sha256"],
        "configuration_changed": bool(
            previous is not None
            and previous.get("configuration_sha256") != current["configuration_sha256"]
        ),
        "provider_tenant_changed": bool(
            previous is not None
            and previous.get("provider_tenant_sha256") != current["provider_tenant_sha256"]
        ),
        "categories": categories,
        "risk_generated": False,
    }


def _scheduler_table(section: object) -> Mapping[str, Any] | None:
    if not isinstance(section, Mapping):
        raise IdentityGovernanceScheduleError(
            "identity-governance connector configuration must be a table"
        )
    raw = section.get("scheduler")
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise IdentityGovernanceScheduleError("identity-governance scheduler must be a table")
    if set(raw) - {"enable", "poll_seconds", "providers"}:
        raise IdentityGovernanceScheduleError("identity-governance scheduler key is unsupported")
    enabled = raw.get("enable", False)
    if not isinstance(enabled, bool):
        raise IdentityGovernanceScheduleError(
            "identity-governance scheduler enable must be boolean"
        )
    return raw


def scheduler_poll_seconds(section: object) -> float:
    """Return the finite supervisor poll interval for an enabled scheduler."""

    table = _scheduler_table(section)
    if table is None:
        return _DEFAULT_POLL_SECONDS
    value = table.get("poll_seconds", _DEFAULT_POLL_SECONDS)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IdentityGovernanceScheduleError(
            "identity-governance scheduler poll_seconds must be a number"
        )
    result = float(value)
    if not math.isfinite(result) or result < _MIN_POLL_SECONDS or result > _MAX_POLL_SECONDS:
        raise IdentityGovernanceScheduleError(
            "identity-governance scheduler poll_seconds must be between 5 and 3600"
        )
    return result


def configured_schedules(section: object) -> tuple[ProviderSchedule, ...]:
    """Build explicitly enabled schedules whose connectors are also enabled."""

    table = _scheduler_table(section)
    if table is None or table.get("enable") is not True:
        return ()
    assert isinstance(section, Mapping)
    if set(section) - {"enable", "scheduler", "controls", *_PROVIDERS}:
        raise IdentityGovernanceScheduleError(
            "identity-governance connector section key is unsupported"
        )
    if section.get("enable") is not True:
        raise IdentityGovernanceScheduleError(
            "scheduled identity governance requires the connector section enabled"
        )
    providers = table.get("providers", {})
    if not isinstance(providers, Mapping):
        raise IdentityGovernanceScheduleError(
            "identity-governance scheduler providers must be a table"
        )
    if set(providers) - set(_PROVIDERS):
        raise IdentityGovernanceScheduleError(
            "identity-governance scheduled provider is unsupported"
        )
    allowed = {
        "enable",
        "interval_seconds",
        "retry_base_seconds",
        "retry_max_seconds",
        "max_attempts_per_slot",
        "lease_seconds",
        "history_limit",
        "max_snapshot_items",
        "max_delta_digests",
    }
    result: list[ProviderSchedule] = []
    defaults: dict[str, Any] = {
        "interval_seconds": 60 * 60,
        "retry_base_seconds": 30,
        "retry_max_seconds": 15 * 60,
        "max_attempts_per_slot": 3,
        "lease_seconds": 60 * 60,
        "history_limit": 8,
        "max_snapshot_items": 5_000,
        "max_delta_digests": 256,
    }
    for provider in _PROVIDERS:
        raw = providers.get(provider)
        if raw is None:
            continue
        if not isinstance(raw, Mapping):
            raise IdentityGovernanceScheduleError(
                "identity-governance provider schedule must be a table"
            )
        if set(raw) - allowed:
            raise IdentityGovernanceScheduleError(
                "identity-governance provider schedule key is unsupported"
            )
        enabled = raw.get("enable", False)
        if not isinstance(enabled, bool):
            raise IdentityGovernanceScheduleError(
                "identity-governance provider schedule enable must be boolean"
            )
        if not enabled:
            continue
        connector = section.get(provider)
        if not isinstance(connector, Mapping) or connector.get("enable") is not True:
            raise IdentityGovernanceScheduleError(
                f"scheduled {provider} connector must be explicitly enabled"
            )
        values = {name: raw.get(name, default) for name, default in defaults.items()}
        result.append(ProviderSchedule(provider=provider, **values))
    scheduler_poll_seconds(section)
    return tuple(result)


def _connector_section(section: Mapping[str, Any]) -> dict[str, Any]:
    """Remove scheduler-only keys before invoking the strict runtime adapters."""

    return {key: value for key, value in section.items() if key in {"enable", *_PROVIDERS}}


def _safe_error_type(exc: BaseException) -> str:
    value = type(exc).__name__
    return value if _ERROR_TYPE_RE.fullmatch(value) else "Exception"


def _safe_optional_error_type(value: object) -> str | None:
    if value is None:
        return None
    return value if isinstance(value, str) and _ERROR_TYPE_RE.fullmatch(value) else None


def _safe_time(value: object) -> float | None:
    if (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) >= 0
    ):
        return float(value)
    return None


def _safe_counts(value: object, *, maximum: int) -> dict[str, int] | None:
    if not isinstance(value, Mapping):
        return None
    expected = {"identities", "grants", "data_classifications", "total"}
    if set(value) != expected:
        return None
    result: dict[str, int] = {}
    for key in sorted(expected):
        count = value.get(key)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > maximum:
            return None
        result[key] = count
    if result["total"] != (
        result["identities"] + result["grants"] + result["data_classifications"]
    ):
        return None
    return result


def _state_health(record: Mapping[str, Any]) -> str:
    if record.get("source_state") == "unavailable":
        return str(record.get("collection_health") or "degraded")
    if record.get("callback_health") == "degraded":
        return "degraded"
    return str(record.get("collection_health") or "never_run")


def _change_payload(
    *,
    tenant_sha256: str,
    provider: str,
    slot: int,
    collected_at: float,
    delta: Mapping[str, Any],
) -> dict[str, Any]:
    body = {
        "schema": _CHANGE_SCHEMA,
        "tenant_sha256": tenant_sha256,
        "provider": provider,
        "slot": slot,
        "collected_at": collected_at,
        "source_state": "incomplete",
        "source_complete": False,
        "live_acceptance_verified": False,
        "complete_inventory_claimed": False,
        "delta": dict(delta),
        "risk_generated": False,
    }
    body["change_sha256"] = _sha256(body)
    return body


def _default_store():
    from maverick.governed_records import GovernedRecordStore

    return GovernedRecordStore(
        "identity_governance_scheduler",
        "IGSC",
        "identity_governance_schedule_state",
    )


class IdentityGovernanceScheduler:
    """Tenant-scoped scheduler engine with CAS leases and safe callback retry."""

    def __init__(
        self,
        *,
        store: Any | None = None,
        collector: Callable[[object, str], Mapping[str, Any]] | None = None,
        clock: Callable[[], float] | None = None,
        change_callback: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> None:
        self._store = store if store is not None else _default_store()
        self._collector = collector
        self._clock = clock
        self._change_callback = change_callback
        self._owner_sha256 = _sha256(uuid.uuid4().hex)

    def _now(self) -> float:
        value = self._clock() if self._clock is not None else self._store.authoritative_time()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise RuntimeError("identity-governance scheduler clock is invalid")
        result = float(value)
        if not math.isfinite(result) or result <= 0:
            raise RuntimeError("identity-governance scheduler clock is invalid")
        return result

    def _collect(self, section: Mapping[str, Any], provider: str) -> Mapping[str, Any]:
        collector = self._collector
        if collector is None:
            from .identity_governance_runtime import collect_connector

            collector = collect_connector
        return collector(_connector_section(section), provider)

    def _initial_state(
        self,
        *,
        record_id: str,
        tenant_sha256: str,
        schedule: ProviderSchedule,
    ) -> dict[str, Any]:
        return {
            "id": record_id,
            "schema": _STATE_SCHEMA,
            "tenant_sha256": tenant_sha256,
            "provider": schedule.provider,
            "schedule_sha256": schedule.configuration_sha256,
            "status": "active",
            "health": "never_run",
            "collection_health": "never_run",
            "callback_health": (
                "healthy" if self._change_callback is not None else "not_configured"
            ),
            "source_state": "unavailable",
            "source_complete": False,
            "live_acceptance_verified": False,
            "complete_inventory_claimed": False,
            "last_attempt_at": None,
            "last_success_at": None,
            "last_success_slot": None,
            "attempt_slot": None,
            "attempts_in_slot": 0,
            "consecutive_failures": 0,
            "next_attempt_at": 0.0,
            "last_error_type": None,
            "lease": None,
            "current": None,
            "history": [],
            "last_delta": None,
            "pending_changes": [],
            "pending_changes_dropped": 0,
            "callback_attempts": 0,
            "callback_next_attempt_at": 0.0,
            "callback_last_error_type": None,
            "callback_lease": None,
        }

    def _load_or_create(
        self,
        *,
        record_id: str,
        tenant_sha256: str,
        schedule: ProviderSchedule,
        actor: str,
    ) -> dict[str, Any]:
        current = self._store.get(record_id)
        if current is not None:
            return current
        initial = self._initial_state(
            record_id=record_id,
            tenant_sha256=tenant_sha256,
            schedule=schedule,
        )
        try:
            return self._store.create(
                initial,
                action="initialize_schedule",
                actor=actor,
                max_records=len(_PROVIDERS),
            )
        except Exception as exc:
            from maverick.privacy_ops import RecordConflict

            if not isinstance(exc, RecordConflict):
                raise
            raced = self._store.get(record_id)
            if raced is None:
                raise
            return raced

    @staticmethod
    def _assert_state(state: Mapping[str, Any], *, tenant_sha256: str, provider: str) -> None:
        if (
            state.get("schema") != _STATE_SCHEMA
            or state.get("tenant_sha256") != tenant_sha256
            or state.get("provider") != provider
        ):
            raise RuntimeError("identity-governance scheduler state is invalid")

    def _update(
        self,
        state: Mapping[str, Any],
        mutate: Callable[[dict[str, Any]], None],
        *,
        action: str,
        actor: str,
    ) -> dict[str, Any] | None:
        revision = state.get("revision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise RuntimeError("identity-governance scheduler revision is invalid")
        try:
            return self._store.update(
                str(state["id"]),
                mutate,
                expected_revision=revision,
                action=action,
                actor=actor,
            )
        except Exception as exc:
            from maverick.privacy_ops import RecordConflict

            if isinstance(exc, RecordConflict):
                return None
            raise

    @staticmethod
    def _lease_active(state: Mapping[str, Any], now: float, field: str) -> bool:
        lease = state.get(field)
        if not isinstance(lease, Mapping):
            return False
        expiry = lease.get("expires_at")
        return (
            isinstance(expiry, (int, float))
            and not isinstance(expiry, bool)
            and math.isfinite(float(expiry))
            and float(expiry) > now
        )

    def _claim_collection(
        self,
        state: Mapping[str, Any],
        *,
        schedule: ProviderSchedule,
        slot: int,
        now: float,
        actor: str,
    ) -> dict[str, Any] | None:
        lease_token_sha256 = _sha256(uuid.uuid4().hex)
        previous_slot = state.get("attempt_slot")
        attempts = int(state.get("attempts_in_slot") or 0) if previous_slot == slot else 0

        def mutate(current: dict[str, Any]) -> None:
            current["schedule_sha256"] = schedule.configuration_sha256
            current["attempt_slot"] = slot
            current["attempts_in_slot"] = attempts + 1
            current["last_attempt_at"] = now
            current["lease"] = {
                "owner_sha256": self._owner_sha256,
                "token_sha256": lease_token_sha256,
                "slot": slot,
                "expires_at": now + schedule.lease_seconds,
            }

        return self._update(
            state,
            mutate,
            action="claim_collection_slot",
            actor=actor,
        )

    def _finalize_failure(
        self,
        claimed: Mapping[str, Any],
        *,
        exc: BaseException,
        schedule: ProviderSchedule,
        slot: int,
        now: float,
        actor: str,
    ) -> dict[str, Any] | None:
        lease = claimed.get("lease")
        token = lease.get("token_sha256") if isinstance(lease, Mapping) else None
        attempts = int(claimed.get("attempts_in_slot") or 0)
        failures = int(claimed.get("consecutive_failures") or 0) + 1
        if attempts >= schedule.max_attempts_per_slot:
            next_attempt_at = float((slot + 1) * schedule.interval_seconds)
            collection_health = "unavailable"
        else:
            exponent = min(failures - 1, 30)
            backoff = min(
                schedule.retry_base_seconds * (2**exponent),
                schedule.retry_max_seconds,
            )
            next_attempt_at = now + backoff
            collection_health = "degraded"

        def mutate(current: dict[str, Any]) -> None:
            active = current.get("lease")
            if not isinstance(active, Mapping) or active.get("token_sha256") != token:
                raise RuntimeError("identity-governance collection lease was lost")
            current["lease"] = None
            current["consecutive_failures"] = failures
            current["last_error_type"] = _safe_error_type(exc)
            current["next_attempt_at"] = next_attempt_at
            current["source_state"] = "unavailable"
            current["collection_health"] = collection_health
            current["health"] = collection_health

        return self._update(
            claimed,
            mutate,
            action="record_collection_failure",
            actor=actor,
        )

    def _finalize_success(
        self,
        claimed: Mapping[str, Any],
        *,
        snapshot: Mapping[str, Any],
        delta: Mapping[str, Any],
        schedule: ProviderSchedule,
        slot: int,
        now: float,
        tenant_sha256: str,
        actor: str,
    ) -> dict[str, Any] | None:
        lease = claimed.get("lease")
        token = lease.get("token_sha256") if isinstance(lease, Mapping) else None
        history = list(claimed.get("history") or [])
        history.append(
            {
                "snapshot": _history_snapshot(snapshot),
                "delta": dict(delta),
            }
        )
        history = history[-schedule.history_limit :]
        pending = list(claimed.get("pending_changes") or [])
        dropped = int(claimed.get("pending_changes_dropped") or 0)
        if delta.get("changed") is True and self._change_callback is not None:
            pending.append(
                _change_payload(
                    tenant_sha256=tenant_sha256,
                    provider=schedule.provider,
                    slot=slot,
                    collected_at=now,
                    delta=delta,
                )
            )
            if len(pending) > _MAX_PENDING_CHANGES:
                dropped += len(pending) - _MAX_PENDING_CHANGES
                pending = pending[-_MAX_PENDING_CHANGES:]

        def mutate(current: dict[str, Any]) -> None:
            active = current.get("lease")
            if not isinstance(active, Mapping) or active.get("token_sha256") != token:
                raise RuntimeError("identity-governance collection lease was lost")
            current["lease"] = None
            current["schedule_sha256"] = schedule.configuration_sha256
            current["last_success_at"] = now
            current["last_success_slot"] = slot
            current["next_attempt_at"] = float((slot + 1) * schedule.interval_seconds)
            current["consecutive_failures"] = 0
            current["last_error_type"] = None
            current["source_state"] = "incomplete"
            current["source_complete"] = False
            current["live_acceptance_verified"] = False
            current["complete_inventory_claimed"] = False
            current["collection_health"] = "healthy"
            current["current"] = dict(snapshot)
            current["history"] = history
            current["last_delta"] = dict(delta)
            current["pending_changes"] = pending
            current["pending_changes_dropped"] = dropped
            current["callback_health"] = (
                "healthy" if self._change_callback is not None else "not_configured"
            )
            current["health"] = _state_health(current)

        return self._update(
            claimed,
            mutate,
            action="record_collection_digest",
            actor=actor,
        )

    def _deliver_one_callback(
        self,
        state: Mapping[str, Any],
        *,
        schedule: ProviderSchedule,
        now: float,
        actor: str,
    ) -> tuple[dict[str, Any], str]:
        callback = self._change_callback
        pending = state.get("pending_changes")
        if callback is None or not isinstance(pending, list) or not pending:
            return dict(state), "not_pending"
        next_attempt_at = state.get("callback_next_attempt_at")
        if (
            isinstance(next_attempt_at, (int, float))
            and not isinstance(next_attempt_at, bool)
            and float(next_attempt_at) > now
        ):
            return dict(state), "backoff"
        if self._lease_active(state, now, "callback_lease"):
            return dict(state), "overlap"

        token_sha256 = _sha256(uuid.uuid4().hex)

        def claim(current: dict[str, Any]) -> None:
            current["callback_lease"] = {
                "owner_sha256": self._owner_sha256,
                "token_sha256": token_sha256,
                "expires_at": now + schedule.lease_seconds,
            }

        claimed = self._update(
            state,
            claim,
            action="claim_change_callback",
            actor=actor,
        )
        if claimed is None:
            latest = self._store.get(str(state["id"])) or dict(state)
            return latest, "cas_conflict"
        claimed_pending = claimed.get("pending_changes")
        if not isinstance(claimed_pending, list) or not claimed_pending:
            return claimed, "not_pending"
        payload = claimed_pending[0]
        try:
            callback(payload)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # failure-policy: visible_degradation
            attempts = int(claimed.get("callback_attempts") or 0) + 1
            error_type = _safe_error_type(exc)
            exponent = min(attempts - 1, 30)
            backoff = min(
                schedule.retry_base_seconds * (2**exponent),
                schedule.retry_max_seconds,
            )

            def failed(current: dict[str, Any]) -> None:
                lease = current.get("callback_lease")
                if not isinstance(lease, Mapping) or lease.get("token_sha256") != token_sha256:
                    raise RuntimeError("identity-governance callback lease was lost")
                current["callback_lease"] = None
                current["callback_attempts"] = attempts
                current["callback_next_attempt_at"] = now + backoff
                current["callback_last_error_type"] = error_type
                current["callback_health"] = "degraded"
                current["health"] = "degraded"

            updated = self._update(
                claimed,
                failed,
                action="record_change_callback_failure",
                actor=actor,
            )
            return (updated or dict(claimed)), "failed"

        def delivered(current: dict[str, Any]) -> None:
            lease = current.get("callback_lease")
            if not isinstance(lease, Mapping) or lease.get("token_sha256") != token_sha256:
                raise RuntimeError("identity-governance callback lease was lost")
            queue = list(current.get("pending_changes") or [])
            if queue and queue[0].get("change_sha256") == payload.get("change_sha256"):
                queue.pop(0)
            current["pending_changes"] = queue
            current["callback_lease"] = None
            current["callback_attempts"] = 0
            current["callback_next_attempt_at"] = 0.0
            current["callback_last_error_type"] = None
            current["callback_health"] = "healthy"
            current["health"] = _state_health(current)

        updated = self._update(
            claimed,
            delivered,
            action="record_change_callback_delivery",
            actor=actor,
        )
        return (updated or dict(claimed)), "delivered"

    def _provider_status(
        self,
        *,
        tenant_sha256: str,
        schedule: ProviderSchedule,
        now: float,
    ) -> dict[str, Any]:
        record_id = _record_id(tenant_sha256, schedule.provider)
        state = self._store.get(record_id)
        base: dict[str, Any] = {
            "provider": schedule.provider,
            "configured": True,
            "interval_seconds": schedule.interval_seconds,
            "history_limit": schedule.history_limit,
            "max_snapshot_items": schedule.max_snapshot_items,
            "max_delta_digests": schedule.max_delta_digests,
            "health": "never_run",
            "collection_health": "never_run",
            "callback_health": (
                "healthy" if self._change_callback is not None else "not_configured"
            ),
            "source_state": "unavailable",
            "source_complete": False,
            "last_attempt_at": None,
            "last_success_at": None,
            "next_attempt_at": None,
            "consecutive_failures": 0,
            "last_error_type": None,
            "collection_in_progress": False,
            "callback_in_progress": False,
            "pending_change_count": 0,
            "snapshot_sha256": None,
            "counts": None,
            "live_acceptance_verified": False,
            "complete_inventory_claimed": False,
            "risk_generated": False,
        }
        if state is None:
            return base
        self._assert_state(
            state,
            tenant_sha256=tenant_sha256,
            provider=schedule.provider,
        )
        health = state.get("health")
        collection_health = state.get("collection_health")
        callback_health = state.get("callback_health")
        source_state = state.get("source_state")
        base["health"] = health if health in _HEALTH_VALUES else "degraded"
        base["collection_health"] = (
            collection_health if collection_health in _HEALTH_VALUES else "degraded"
        )
        base["callback_health"] = (
            callback_health if callback_health in _CALLBACK_HEALTH_VALUES else "degraded"
        )
        base["source_state"] = (
            source_state if source_state in _SOURCE_STATE_VALUES else "unavailable"
        )
        base["last_attempt_at"] = _safe_time(state.get("last_attempt_at"))
        base["last_success_at"] = _safe_time(state.get("last_success_at"))
        base["next_attempt_at"] = _safe_time(state.get("next_attempt_at"))
        failures = state.get("consecutive_failures")
        if (
            isinstance(failures, int)
            and not isinstance(failures, bool)
            and 0 <= failures <= 1_000_000
        ):
            base["consecutive_failures"] = failures
        base["last_error_type"] = _safe_optional_error_type(state.get("last_error_type"))
        base["collection_in_progress"] = self._lease_active(state, now, "lease")
        base["callback_in_progress"] = self._lease_active(state, now, "callback_lease")
        pending = state.get("pending_changes")
        if isinstance(pending, list):
            base["pending_change_count"] = min(len(pending), _MAX_PENDING_CHANGES)
        current = state.get("current")
        if isinstance(current, Mapping):
            snapshot_sha256 = current.get("snapshot_sha256")
            if isinstance(snapshot_sha256, str) and _SHA256_RE.fullmatch(snapshot_sha256):
                base["snapshot_sha256"] = snapshot_sha256
            base["counts"] = _safe_counts(
                current.get("counts"),
                maximum=schedule.max_snapshot_items,
            )
        return base

    def status(self, section: object) -> dict[str, Any]:
        """Read sanitized scheduler health for the currently bound tenant."""

        schedules = configured_schedules(section)
        if not schedules:
            return {
                "schema": _STATUS_SCHEMA,
                "enabled": False,
                "tenant_sha256": None,
                "configured_providers": [],
                "providers": [],
                "read_only": True,
                "source_complete": False,
                "live_acceptance_verified": False,
                "complete_inventory_claimed": False,
                "risk_generated": False,
            }
        tenant_sha256 = _tenant_sha256()
        now = self._now()
        providers = [
            self._provider_status(
                tenant_sha256=tenant_sha256,
                schedule=schedule,
                now=now,
            )
            for schedule in schedules
        ]
        return {
            "schema": _STATUS_SCHEMA,
            "enabled": bool(schedules),
            "tenant_sha256": tenant_sha256,
            "configured_providers": [item.provider for item in schedules],
            "providers": providers,
            "read_only": True,
            "source_complete": False,
            "live_acceptance_verified": False,
            "complete_inventory_claimed": False,
            "risk_generated": False,
        }

    def run_provider(
        self,
        section: object,
        schedule: ProviderSchedule,
        *,
        actor: str,
    ) -> dict[str, Any]:
        """Run at most one due collection and one bounded callback attempt."""

        if not isinstance(section, Mapping):
            raise IdentityGovernanceScheduleError(
                "identity-governance connector configuration must be a table"
            )
        configured = {item.provider: item for item in configured_schedules(section)}
        if configured.get(schedule.provider) != schedule:
            raise IdentityGovernanceScheduleError(
                "provider schedule does not match enabled configuration"
            )
        tenant_sha256 = _tenant_sha256()
        lock = _provider_lock(tenant_sha256, schedule.provider)
        if not lock.acquire(blocking=False):
            return {
                "provider": schedule.provider,
                "collected": False,
                "reason": "overlap",
            }
        try:
            now = self._now()
            record_id = _record_id(tenant_sha256, schedule.provider)
            state = self._load_or_create(
                record_id=record_id,
                tenant_sha256=tenant_sha256,
                schedule=schedule,
                actor=actor,
            )
            self._assert_state(
                state,
                tenant_sha256=tenant_sha256,
                provider=schedule.provider,
            )
            state, callback_status = self._deliver_one_callback(
                state,
                schedule=schedule,
                now=now,
                actor=actor,
            )
            slot = int(now // schedule.interval_seconds)
            same_schedule = state.get("schedule_sha256") == schedule.configuration_sha256
            if same_schedule and state.get("last_success_slot") == slot:
                return {
                    "provider": schedule.provider,
                    "collected": False,
                    "reason": "duplicate_slot",
                    "callback_status": callback_status,
                }
            next_attempt_at = state.get("next_attempt_at")
            if (
                same_schedule
                and isinstance(next_attempt_at, (int, float))
                and not isinstance(next_attempt_at, bool)
                and float(next_attempt_at) > now
            ):
                return {
                    "provider": schedule.provider,
                    "collected": False,
                    "reason": "backoff",
                    "callback_status": callback_status,
                }
            if self._lease_active(state, now, "lease"):
                return {
                    "provider": schedule.provider,
                    "collected": False,
                    "reason": "overlap",
                    "callback_status": callback_status,
                }
            claimed = self._claim_collection(
                state,
                schedule=schedule,
                slot=slot,
                now=now,
                actor=actor,
            )
            if claimed is None:
                return {
                    "provider": schedule.provider,
                    "collected": False,
                    "reason": "cas_conflict",
                    "callback_status": callback_status,
                }
            try:
                raw_snapshot = self._collect(section, schedule.provider)
                snapshot = digest_snapshot(
                    raw_snapshot,
                    provider=schedule.provider,
                    collected_at=now,
                    max_snapshot_items=schedule.max_snapshot_items,
                )
                previous = claimed.get("current")
                if previous is not None and not isinstance(previous, Mapping):
                    raise RuntimeError("retained identity-governance digest is invalid")
                delta = snapshot_delta(
                    previous,
                    snapshot,
                    max_delta_digests=schedule.max_delta_digests,
                )
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # failure-policy: visible_degradation
                failed = self._finalize_failure(
                    claimed,
                    exc=exc,
                    schedule=schedule,
                    slot=slot,
                    now=now,
                    actor=actor,
                )
                return {
                    "provider": schedule.provider,
                    "collected": False,
                    "reason": "collection_failed",
                    "error_type": _safe_error_type(exc),
                    "state_updated": failed is not None,
                    "callback_status": callback_status,
                }
            saved = self._finalize_success(
                claimed,
                snapshot=snapshot,
                delta=delta,
                schedule=schedule,
                slot=slot,
                now=now,
                tenant_sha256=tenant_sha256,
                actor=actor,
            )
            if saved is None:
                return {
                    "provider": schedule.provider,
                    "collected": False,
                    "reason": "cas_conflict",
                    "callback_status": callback_status,
                }
            saved, callback_status = self._deliver_one_callback(
                saved,
                schedule=schedule,
                now=now,
                actor=actor,
            )
            return {
                "provider": schedule.provider,
                "collected": True,
                "changed": bool(delta["changed"]),
                "snapshot_sha256": snapshot["snapshot_sha256"],
                "source_state": "incomplete",
                "source_complete": False,
                "risk_generated": False,
                "callback_status": callback_status,
                "health": saved.get("health"),
            }
        finally:
            lock.release()

    def run_configured(self, section: object, *, actor: str) -> dict[str, Any]:
        """Run each explicitly configured provider once, isolating failures."""

        schedules = configured_schedules(section)
        results: list[dict[str, Any]] = []
        failures: list[dict[str, str]] = []
        for schedule in schedules:
            try:
                results.append(self.run_provider(section, schedule, actor=actor))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:  # failure-policy: visible_degradation
                error_type = _safe_error_type(exc)
                log.warning(
                    "Identity-governance scheduler provider %s failed safely: %s",
                    schedule.provider,
                    error_type,
                )
                failures.append({"provider": schedule.provider, "error_type": error_type})
        return {
            "skipped": not schedules,
            "provider_count": len(schedules),
            "results": results,
            "failures": failures,
            "source_complete": False,
            "live_acceptance_verified": False,
        }


def _engine() -> IdentityGovernanceScheduler:
    global _default_engine
    with _default_engine_lock:
        if _default_engine is None:
            _default_engine = IdentityGovernanceScheduler()
        return _default_engine


def default_scheduler() -> IdentityGovernanceScheduler:
    """Return the process singleton shared by manual and supervised cycles."""

    return _engine()


def install_composed_engine_factory(
    factory: Callable[[object], object | None],
) -> None:
    """Install the lazy production engine builder used inside tenant scope."""

    if not callable(factory):
        raise TypeError("identity-governance composed engine factory must be callable")
    global _composed_engine_factory
    with _composed_engine_factory_lock:
        _composed_engine_factory = factory


def _configured_engine(section: object) -> IdentityGovernanceScheduler:
    with _composed_engine_factory_lock:
        factory = _composed_engine_factory
    if factory is None:
        return _engine()
    selected = factory(section)
    if selected is None:
        return _engine()
    if not isinstance(selected, IdentityGovernanceScheduler):
        raise TypeError(
            "identity-governance composed engine factory returned an invalid engine"
        )
    return selected


def configured_scheduler_status(section: object) -> dict[str, Any]:
    """Read sanitized status from the singleton used by the supervisor."""

    return _configured_engine(section).status(section)


def run_configured_collection(
    section: object,
    *,
    actor: str,
) -> dict[str, Any]:
    """Run one current-tenant collection cycle without starting a thread."""

    return _configured_engine(section).run_configured(section, actor=actor)


def _load_tenant_section() -> dict[str, Any]:
    from maverick.config import load_config

    config = load_config() or {}
    if not isinstance(config, Mapping):
        raise IdentityGovernanceScheduleError("tenant configuration must be a table")
    section = config.get("ai_identity_governance_connectors", {})
    if not isinstance(section, Mapping):
        raise IdentityGovernanceScheduleError(
            "identity-governance connector configuration must be a table"
        )
    return dict(section)


def scheduler_cycle(
    actor: str,
    *,
    engine: IdentityGovernanceScheduler | None = None,
    section_loader: Callable[[], Mapping[str, Any]] | None = None,
) -> bool:
    """Collect configured providers in the shared floor and active tenants."""

    from .automation_queue import _run_for_active_tenants

    loader = section_loader if section_loader is not None else _load_tenant_section
    run = (
        (lambda: engine.run_configured(loader(), actor=actor))
        if engine is not None
        else (lambda: run_configured_collection(loader(), actor=actor))
    )
    return _run_for_active_tenants(
        "identity-governance collection",
        run,
    )


def _global_section() -> dict[str, Any] | None:
    from maverick.config import config_source_errors, load_global_config

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        log.warning("Identity-governance scheduler skipped: global config is unreadable")
        return None
    if not isinstance(config, Mapping):
        raise IdentityGovernanceScheduleError("global configuration must be a table")
    section = config.get("ai_identity_governance_connectors", {})
    if not isinstance(section, Mapping):
        raise IdentityGovernanceScheduleError(
            "identity-governance connector configuration must be a table"
        )
    return dict(section)


def _scheduler_loop(
    stop: threading.Event,
    actor: str,
    poll_seconds: float,
    cycle_runner: Callable[[str], object],
) -> None:
    while not stop.is_set():
        try:
            cycle_runner(actor)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning(
                "Identity-governance scheduler failed safely: %s",
                _safe_error_type(exc),
            )
        stop.wait(poll_seconds)


def start_identity_governance_scheduler(
    *,
    section: Mapping[str, Any] | None = None,
    cycle_runner: Callable[[str], object] | None = None,
) -> bool:
    """Start the off-by-default daemon supervisor for configured schedules."""

    selected = dict(section) if section is not None else _global_section()
    if selected is None:
        return False
    scheduler_table = _scheduler_table(selected)
    if (
        selected.get("enable") is not True
        or scheduler_table is None
        or scheduler_table.get("enable") is not True
    ):
        return False
    poll_seconds = scheduler_poll_seconds(selected)
    runner = cycle_runner if cycle_runner is not None else scheduler_cycle
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(
            target=_scheduler_loop,
            args=(
                stop,
                f"system:identity-governance-scheduler:{uuid.uuid4().hex}",
                poll_seconds,
                runner,
            ),
            name="identity-governance-collection",
            daemon=True,
        )
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_identity_governance_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
    """Signal first; retain a stopping worker until its exit is observed."""
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        stop = _scheduler_stop
        worker = _scheduler_thread
        if stop is not None:
            stop.set()
    if stop is None or worker is None:
        return False
    if not wait:
        return not worker.is_alive()
    worker.join(max(0.0, min(float(timeout), 30.0)))
    if worker.is_alive():
        return False
    with _scheduler_lock:
        if _scheduler_thread is worker:
            _scheduler_stop = None
            _scheduler_thread = None
    return True


__all__ = [
    "IdentityGovernanceScheduleError",
    "IdentityGovernanceScheduler",
    "IdentityGovernanceSnapshotError",
    "ProviderSchedule",
    "configured_scheduler_status",
    "configured_schedules",
    "default_scheduler",
    "digest_snapshot",
    "install_composed_engine_factory",
    "run_configured_collection",
    "scheduler_cycle",
    "scheduler_poll_seconds",
    "snapshot_delta",
    "start_identity_governance_scheduler",
    "stop_identity_governance_scheduler",
    "tenant_binding_sha256",
]
