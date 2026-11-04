"""Background polling for deterministic finance regulatory and GRC cycles."""
from __future__ import annotations

import hashlib
import logging
import math
import threading
import time
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_scheduler_lock = threading.Lock()
_scheduler_stop: threading.Event | None = None
_scheduler_thread: threading.Thread | None = None

_MIN_POLL_SECONDS = 300.0
_MAX_POLL_SECONDS = 7 * 24 * 60 * 60.0
_DEFAULT_POLL_SECONDS = 60 * 60.0
_MAX_STATE_FEEDS = 50
_MAX_FIELD_MAP_ENTRIES = 32
_MAX_FIELD_MAP_KEY_CHARS = 64
_MAX_FIELD_MAP_PATH_CHARS = 256


def _section(config: Mapping[str, Any]) -> dict[str, Any]:
    raw = config.get("finance_operations")
    return dict(raw) if isinstance(raw, Mapping) else {}


def _poll_seconds(section: Mapping[str, Any]) -> float:
    value = section.get("regulatory_poll_seconds", _DEFAULT_POLL_SECONDS)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("regulatory_poll_seconds must be a number")
    result = float(value)
    if not math.isfinite(result) or result < 0 or result > _MAX_POLL_SECONDS:
        raise ValueError(
            "regulatory_poll_seconds must be zero or between 300 and 604800"
        )
    if 0 < result < _MIN_POLL_SECONDS:
        raise ValueError(
            "regulatory_poll_seconds must be zero or between 300 and 604800"
        )
    return result


def _preset_sources(section: Mapping[str, Any]) -> list:
    """The built-in official feeds, each behind its boolean opt-in."""
    from maverick.finance.regulatory_change import FeedSource

    presets = (
        ("federal_register_enable", True, FeedSource.federal_register),
        ("texas_register_enable", False, FeedSource.texas_register),
        ("eur_lex_enable", False, FeedSource.eur_lex_legislation),
        ("edpb_enable", False, FeedSource.edpb_news),
    )
    sources = []
    for knob, default, build in presets:
        value = section.get(knob, default)
        if not isinstance(value, bool):
            raise ValueError(f"{knob} must be boolean")
        if value:
            sources.append(build())
    return sources


def _field_map_table(value: object) -> object:
    """``field_map`` as a table. The dashboard writes it as a list of
    ``"field=path.in.feed"`` entries (leaving the key out when there are
    none); anything else, an empty list included, is returned unchanged so
    the checks below refuse it."""
    if not isinstance(value, list) or not value:
        return value
    table: dict[str, str] = {}
    for item in value:
        if not isinstance(item, str) or "=" not in item:
            return value
        key, _, path = item.partition("=")
        if key.strip() in table:
            return value
        table[key.strip()] = path.strip()
    return table


def configured_sources(section: Mapping[str, Any]):
    """Build bounded explicit sources; malformed state-feed config fails closed."""
    from maverick.finance.regulatory_change import FeedSource

    sources = _preset_sources(section)
    raw_state = section.get("state_feeds", [])
    if not isinstance(raw_state, list) or len(raw_state) > _MAX_STATE_FEEDS:
        raise ValueError(f"state_feeds must be a list of no more than {_MAX_STATE_FEEDS} feeds")
    for index, raw in enumerate(raw_state):
        if not isinstance(raw, Mapping):
            raise ValueError(f"state_feeds[{index}] must be an object")
        regimes = raw.get("default_regimes", [])
        domains = raw.get("default_domains", [])
        if not isinstance(regimes, list) or not isinstance(domains, list):
            raise ValueError(f"state_feeds[{index}] scopes must be lists")
        raw_field_map = _field_map_table(raw.get("field_map", {}))
        if not isinstance(raw_field_map, Mapping):
            raise ValueError(f"state_feeds[{index}].field_map must be an object")
        if len(raw_field_map) > _MAX_FIELD_MAP_ENTRIES:
            raise ValueError(
                f"state_feeds[{index}].field_map must have no more than "
                f"{_MAX_FIELD_MAP_ENTRIES} entries"
            )
        field_map: dict[str, str] = {}
        for raw_key, raw_path in raw_field_map.items():
            if not isinstance(raw_key, str) or not isinstance(raw_path, str):
                raise ValueError(
                    f"state_feeds[{index}].field_map keys and paths must be strings"
                )
            key = raw_key.strip()
            path = raw_path.strip()
            if not key or not path:
                raise ValueError(
                    f"state_feeds[{index}].field_map keys and paths must be non-empty"
                )
            if len(key) > _MAX_FIELD_MAP_KEY_CHARS:
                raise ValueError(
                    f"state_feeds[{index}].field_map keys must not exceed "
                    f"{_MAX_FIELD_MAP_KEY_CHARS} characters"
                )
            if len(path) > _MAX_FIELD_MAP_PATH_CHARS:
                raise ValueError(
                    f"state_feeds[{index}].field_map paths must not exceed "
                    f"{_MAX_FIELD_MAP_PATH_CHARS} characters"
                )
            if key in field_map:
                raise ValueError(
                    f"state_feeds[{index}].field_map keys must be unique after trimming"
                )
            field_map[key] = path
        sources.append(
            FeedSource(
                key=str(raw.get("key") or ""),
                name=str(raw.get("name") or ""),
                jurisdiction=str(raw.get("jurisdiction") or ""),
                url=str(raw.get("url") or ""),
                format=str(raw.get("format") or ""),
                default_regimes=tuple(str(value) for value in regimes[:64]),
                default_domains=tuple(str(value) for value in domains[:64]),
                field_map=field_map,
            )
        )
    keys = [source.key for source in sources]
    if len(keys) != len(set(keys)):
        raise ValueError("regulatory feed keys must be unique")
    return tuple(sources)


def _scopes(config: Mapping[str, Any], section: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    finance = config.get("finance")
    raw_regimes = finance.get("regimes", []) if isinstance(finance, Mapping) else []
    raw_domains = section.get(
        "regulatory_domains",
        ["finance", "money_transmitter", "insurance_producer"],
    )
    if not isinstance(raw_regimes, list) or not isinstance(raw_domains, list):
        raise ValueError("finance regimes and regulatory_domains must be lists")
    regimes = tuple(dict.fromkeys(str(value).strip().lower() for value in raw_regimes if str(value).strip()))[:64]
    domains = tuple(dict.fromkeys(str(value).strip().lower() for value in raw_domains if str(value).strip()))[:64]
    return regimes, domains


def _marker(source_key: str) -> Path:
    from maverick import config
    from maverick.paths import current_tenant_id_strict

    tenant = current_tenant_id_strict() or "<shared>"
    digest = hashlib.sha256(f"{tenant}\0{source_key}".encode()).hexdigest()[:32]
    return config.dashboard_overrides_path().parent / "finance-operations-poll" / digest


class _PollLease:
    """One process's exclusive opportunity to complete due poll work."""

    def __init__(self) -> None:
        self._succeeded = False

    def succeed(self) -> None:
        """Advance the cadence only after work and its health receipt commit."""
        self._succeeded = True


@contextmanager
def _poll_lease(
    source_key: str,
    interval: float,
    *,
    now: float | None = None,
):
    """Lease due work cross-process; failed work leaves it immediately retryable.

    The per-tenant, per-source OS lock is held for the work's lifetime. A clean
    process exit, exception, or crash releases that lease without advancing the
    success marker. Concurrent workers wait for the lease, then re-check the
    marker and skip only when the prior worker explicitly recorded success.
    """
    from maverick.file_lock import cross_process_lock

    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise ValueError("poll interval must be a finite positive number")
    bounded_interval = float(interval)
    if not math.isfinite(bounded_interval) or bounded_interval <= 0:
        raise ValueError("poll interval must be a finite positive number")
    supplied_now = None if now is None else float(now)
    if supplied_now is not None and not math.isfinite(supplied_now):
        raise ValueError("poll time must be finite")

    marker = _marker(source_key)
    with cross_process_lock(marker, strict=True):
        checked_at = time.time() if supplied_now is None else supplied_now
        try:
            if checked_at - marker.stat().st_mtime < bounded_interval:
                yield None
                return
        except FileNotFoundError:
            pass
        lease = _PollLease()
        try:
            yield lease
        finally:
            if lease._succeeded:
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()


def _tenant_cycle(owner: str, global_config: Mapping[str, Any]) -> None:
    from maverick.config import load_config
    from maverick.finance import control_testing, operations_health
    from maverick.finance.licensing import (
        ingest_pack_into_regulatory_register,
        load_licensing_pack,
    )
    from maverick.finance.regulatory_change import RegulatoryChangeEngine, fetch_and_ingest
    from maverick.paths import data_dir

    config = load_config() or {}
    section = _section(config)
    # The deployment-global authority bit cannot be enabled by a tenant overlay.
    if _section(global_config).get("enable") is not True:
        return
    regimes, domains = _scopes(config, section)
    interval = _poll_seconds(section)
    if interval > 0:
        engine = RegulatoryChangeEngine(
            data_dir("finance_operations", "regulatory_change.sqlite3")
        )
        with _poll_lease("regulatory:enabled-scope-reconcile", interval) as lease:
            if lease is not None:
                try:
                    reconciliation = engine.reconcile_scopes(
                        enabled_regimes=regimes,
                        enabled_domains=domains,
                    )
                    if reconciliation.complete:
                        operations_health.record_success(
                            "regulatory_scope_reconcile",
                            "enabled-scopes",
                            details={
                                "documents_seen": reconciliation.documents_seen,
                                "alerts_created": reconciliation.alerts_created,
                                "alerts_updated": reconciliation.alerts_updated,
                                "cursor": reconciliation.cursor,
                            },
                        )
                        lease.succeed()
                    else:
                        log.info(
                            "finance regulatory scope reconciliation continuing after "
                            "cursor %d",
                            reconciliation.cursor,
                        )
                except Exception as exc:  # failure-policy: visible_degradation
                    log.warning(
                        "finance regulatory scope reconciliation failed safely: %s",
                        type(exc).__name__,
                    )
        for vertical in ("money_transmitter", "insurance_producer"):
            if vertical not in domains:
                continue
            source_key = f"licensing-pack-{vertical}"
            with _poll_lease(f"regulatory:{source_key}", interval) as lease:
                if lease is None:
                    continue
                try:
                    result = ingest_pack_into_regulatory_register(
                        engine,
                        load_licensing_pack(vertical),
                        enabled_domains=domains,
                    )
                    operations_health.record_success(
                        "regulatory_pack_sync",
                        source_key,
                        details={
                            "items_seen": result.items_seen,
                            "versions_created": result.versions_created,
                            "alerts_created": result.alerts_created,
                        },
                    )
                    lease.succeed()
                except Exception as exc:  # failure-policy: visible_degradation
                    log.warning(
                        "finance regulatory pack %s failed safely: %s",
                        vertical,
                        type(exc).__name__,
                    )
        for source in configured_sources(section):
            with _poll_lease(f"regulatory:{source.key}", interval) as lease:
                if lease is None:
                    continue
                try:
                    result = fetch_and_ingest(
                        engine,
                        source,
                        enabled_regimes=regimes,
                        enabled_domains=domains,
                        timeout=20.0,
                    )
                    log.info(
                        "finance regulatory source %s: %d seen, %d versions, %d alerts",
                        source.key,
                        result.items_seen,
                        result.versions_created,
                        result.alerts_created,
                    )
                    operations_health.record_success(
                        "regulatory_poll",
                        source.key,
                        details={
                            "items_seen": result.items_seen,
                            "versions_created": result.versions_created,
                            "alerts_created": result.alerts_created,
                        },
                    )
                    lease.succeed()
                except Exception as exc:  # failure-policy: visible_degradation
                    log.warning(
                        "finance regulatory source %s failed safely: %s",
                        source.key,
                        type(exc).__name__,
                    )
    schedule = control_testing.schedule_config()
    if schedule["interval_seconds"] > 0:
        try:
            cycle = control_testing.run_control_cycle(actor=owner)
            reconciled = control_testing.reconcile_scheduled_cycles(
                actor=owner,
                scan_limit=100,
                priority_cycle_id=str(cycle.get("id") or ""),
            )
            current = next(
                (row for row in reconciled if row.get("id") == cycle.get("id")),
                cycle,
            )
            operations_health.record_success(
                "grc_control_cycle",
                str(current.get("id") or "scheduled"),
                details={
                    "status": str(current.get("status") or "unknown"),
                    "cycles_reconciled": len(reconciled),
                },
            )
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("finance GRC control cycle failed safely: %s", type(exc).__name__)


def scheduler_cycle(owner: str) -> bool:
    """Run one finance operations turn in the shared floor and active tenants."""
    from maverick.config import config_source_errors, load_global_config

    from .automation_queue import _run_for_active_tenants

    global_config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        log.warning("finance operations scheduler skipped: global config is unreadable")
        return False
    return _run_for_active_tenants(
        "finance operations scheduler",
        lambda: _tenant_cycle(owner, global_config),
    )


def _scheduler_loop(stop: threading.Event, owner: str) -> None:
    while not stop.is_set():
        try:
            scheduler_cycle(owner)
        except Exception as exc:  # failure-policy: visible_degradation
            log.warning("finance operations scheduler failed safely: %s", type(exc).__name__)
        stop.wait(30.0)


def start_finance_scheduler() -> bool:
    """Start the off-by-default finance poller and GRC scheduler."""
    from maverick.config import config_source_errors, load_global_config

    config = load_global_config() or {}
    if config_source_errors(include_tenant=False):
        return False
    section = _section(config)
    if section.get("enable") is not True:
        return False
    # Validate before starting a background thread that would fail every turn.
    _poll_seconds(section)
    configured_sources(section)
    global _scheduler_stop, _scheduler_thread
    with _scheduler_lock:
        if _scheduler_thread is not None and _scheduler_thread.is_alive():
            return False
        stop = threading.Event()
        worker = threading.Thread(
            target=_scheduler_loop,
            args=(stop, f"system:finance-scheduler:{uuid.uuid4().hex}"),
            name="finance-operations-scheduler",
            daemon=True,
        )
        _scheduler_stop = stop
        _scheduler_thread = worker
        worker.start()
        return True


def stop_finance_scheduler(*, timeout: float = 5.0, wait: bool = True) -> bool:
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
    "configured_sources",
    "scheduler_cycle",
    "start_finance_scheduler",
    "stop_finance_scheduler",
]
