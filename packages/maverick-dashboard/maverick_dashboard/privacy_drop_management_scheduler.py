"""Bounded maintenance coordinator for configured California DROP tenants.

The coordinator performs no network I/O.  It invokes only deployment-installed
readiness, reconciliation and retention runners, never imports an external
record or invents a terminal outcome.  Tenant identifiers and private failure
details are excluded from the returned health snapshot.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from maverick.file_lock import cross_process_lock, ensure_private_directory, ensure_private_file
from maverick.paths import canonical_tenant_id
from maverick.sqlite_closing import ClosingConnection

NETWORK_IO = False


class DROPManagementSchedulerError(RuntimeError):
    """A closed maintenance coordinator contract is unavailable."""


@dataclass(frozen=True, slots=True)
class DROPManagementMaintenanceCycle:
    started_at: float
    completed_at: float
    tenants_considered: int
    tenants_ready: int
    tenants_failed: int
    reconciliations_valid: int
    requests_purged: int
    registry_objects_purged: int
    cycle_sha256: str


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as exc:
        raise DROPManagementSchedulerError("DROP maintenance result is invalid") from exc


def _count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 1_000_000:
        raise DROPManagementSchedulerError(f"DROP maintenance {label} is invalid")
    return value


def run_drop_maintenance_cycle(  # noqa: PLR0913 - explicit coordinator seams
    *,
    tenant_supplier: Callable[[], Sequence[str]],
    readiness_probe: Callable[[str], bool],
    reconciliation_runner: Callable[[str], Mapping[str, object]],
    maintenance_runner: Callable[..., Mapping[str, object]],
    tenant_limit: int = 1_000,
    purge_limit: int = 100,
    before: float | None = None,
    clock: Callable[[], float] = time.time,
) -> DROPManagementMaintenanceCycle:
    """Run one bounded, best-effort local reconciliation and retention cycle."""

    if not all(
        callable(value)
        for value in (
            tenant_supplier,
            readiness_probe,
            reconciliation_runner,
            maintenance_runner,
            clock,
        )
    ):
        raise DROPManagementSchedulerError("DROP maintenance dependencies are incomplete")
    if (
        isinstance(tenant_limit, bool)
        or not isinstance(tenant_limit, int)
        or not 1 <= tenant_limit <= 10_000
        or isinstance(purge_limit, bool)
        or not isinstance(purge_limit, int)
        or not 1 <= purge_limit <= 1_000
    ):
        raise DROPManagementSchedulerError("DROP maintenance limits are invalid")
    started_at = float(clock())
    if not math.isfinite(started_at) or started_at <= 0:
        raise DROPManagementSchedulerError("DROP maintenance clock is invalid")
    try:
        supplied = tuple(tenant_supplier())
    except Exception as exc:
        raise DROPManagementSchedulerError("DROP tenant authority is unavailable") from exc
    tenants: list[str] = []
    for raw in supplied:
        try:
            tenant = canonical_tenant_id(raw)
        except (TypeError, ValueError):
            continue
        if tenant not in tenants:
            tenants.append(tenant)
        if len(tenants) >= tenant_limit:
            break

    ready = 0
    failed = 0
    valid = 0
    requests_purged = 0
    registry_purged = 0
    for tenant in tenants:
        try:
            if readiness_probe(tenant) is not True:
                continue
            ready += 1
            reconciliation = reconciliation_runner(tenant)
            if not isinstance(reconciliation, Mapping):
                raise DROPManagementSchedulerError("DROP reconciliation result is invalid")
            integrity_valid = reconciliation.get("registry_integrity_valid")
            if type(integrity_valid) is not bool:
                raise DROPManagementSchedulerError("DROP reconciliation result is invalid")
            if not integrity_valid:
                failed += 1
                continue
            valid += 1
            result = maintenance_runner(
                tenant,
                before=before,
                limit=purge_limit,
            )
            if not isinstance(result, Mapping):
                raise DROPManagementSchedulerError("DROP maintenance result is invalid")
            requests_purged += _count(result.get("requests_purged"), "request count")
            registry_purged += _count(
                result.get("registry_objects_purged"),
                "registry count",
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            failed += 1
    completed_at = float(clock())
    if not math.isfinite(completed_at) or completed_at < started_at:
        raise DROPManagementSchedulerError("DROP maintenance clock changed")
    body = {
        "started_at": started_at,
        "completed_at": completed_at,
        "tenants_considered": len(tenants),
        "tenants_ready": ready,
        "tenants_failed": failed,
        "reconciliations_valid": valid,
        "requests_purged": requests_purged,
        "registry_objects_purged": registry_purged,
    }
    return DROPManagementMaintenanceCycle(
        **body,
        cycle_sha256=hashlib.sha256(_canonical(body)).hexdigest(),
    )


def cycle_payload(cycle: DROPManagementMaintenanceCycle) -> Mapping[str, object]:
    """Return a bounded status payload without tenant identifiers or raw errors."""

    if not isinstance(cycle, DROPManagementMaintenanceCycle):
        raise DROPManagementSchedulerError("DROP maintenance cycle is invalid")
    return {
        "schema": "lightwork.privacy-drop-maintenance-cycle.v1",
        **asdict(cycle),
        "network_io": NETWORK_IO,
        "external_records_imported": 0,
        "terminal_outcomes_inferred": 0,
        "live_interoperability_verified": False,
        "legal_acceptance_verified": False,
    }


class DROPManagedMaintenanceScheduler:
    """Startup-managed durable scheduler with a renewable cross-process lease."""

    def __init__(  # noqa: PLR0913 - explicit production scheduler seams
        self,
        path: str | Path,
        *,
        cycle_runner: Callable[[], DROPManagementMaintenanceCycle],
        enabled: bool = True,
        interval_seconds: int = 3_600,
        jitter_seconds: int = 60,
        retry_max_seconds: int = 900,
        lease_seconds: int = 300,
        clock: Callable[[], float] = time.time,
        jitter_source: Callable[[int], int] | None = None,
        worker_id: str | None = None,
    ) -> None:
        if not callable(cycle_runner) or not callable(clock):
            raise DROPManagementSchedulerError("DROP managed scheduler dependencies are incomplete")
        if not isinstance(enabled, bool):
            raise DROPManagementSchedulerError("DROP scheduler enablement is invalid")
        for value, label, minimum, maximum in (
            (interval_seconds, "interval", 30, 86_400),
            (jitter_seconds, "jitter", 0, 3_600),
            (retry_max_seconds, "retry", 30, 86_400),
            (lease_seconds, "lease", 30, 3_600),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise DROPManagementSchedulerError(f"DROP scheduler {label} is invalid")
        selected_worker = worker_id or f"drop-scheduler-{uuid.uuid4().hex}"
        if not isinstance(selected_worker, str) or not selected_worker or len(selected_worker) > 128:
            raise DROPManagementSchedulerError("DROP scheduler worker id is invalid")
        self.path = Path(path)
        self._cycle_runner = cycle_runner
        self._enabled = enabled
        self._interval_seconds = interval_seconds
        self._jitter_seconds = jitter_seconds
        self._retry_max_seconds = retry_max_seconds
        self._lease_seconds = lease_seconds
        self._clock = clock
        self._jitter_source = jitter_source or (lambda maximum: secrets.randbelow(maximum + 1))
        self._worker_id = selected_worker
        self._lock = threading.RLock()
        self._cycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        ensure_private_directory(self.path.parent)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0, factory=ClosingConnection)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _state_body(row: sqlite3.Row) -> dict[str, object]:
        return {
            "revision": int(row["revision"]),
            "lease_owner": str(row["lease_owner"]),
            "lease_until": float(row["lease_until"]),
            "next_run_at": float(row["next_run_at"]),
            "last_started_at": float(row["last_started_at"]),
            "last_completed_at": float(row["last_completed_at"]),
            "last_success_at": float(row["last_success_at"]),
            "consecutive_failures": int(row["consecutive_failures"]),
            "last_error_sha256": str(row["last_error_sha256"]),
            "last_cycle_json": str(row["last_cycle_json"]),
        }

    @classmethod
    def _state_valid(cls, row: sqlite3.Row) -> bool:
        try:
            body = cls._state_body(row)
            return hmac_compare(_sha256_body(body), str(row["integrity_sha256"]))
        except (KeyError, TypeError, ValueError):
            return False

    def _initialize(self) -> None:
        now = float(self._clock())
        if not math.isfinite(now) or now <= 0:
            raise DROPManagementSchedulerError("DROP scheduler clock is invalid")
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS drop_scheduler_state("
                "singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL,"
                "lease_owner TEXT NOT NULL,lease_until REAL NOT NULL,next_run_at REAL NOT NULL,"
                "last_started_at REAL NOT NULL,last_completed_at REAL NOT NULL,"
                "last_success_at REAL NOT NULL,consecutive_failures INTEGER NOT NULL,"
                "last_error_sha256 TEXT NOT NULL,last_cycle_json TEXT NOT NULL,"
                "integrity_sha256 TEXT NOT NULL)"
            )
            row = connection.execute("SELECT * FROM drop_scheduler_state WHERE singleton=1").fetchone()
            if row is None:
                body = {
                    "revision": 1,
                    "lease_owner": "",
                    "lease_until": 0.0,
                    "next_run_at": now,
                    "last_started_at": 0.0,
                    "last_completed_at": 0.0,
                    "last_success_at": 0.0,
                    "consecutive_failures": 0,
                    "last_error_sha256": "",
                    "last_cycle_json": "",
                }
                connection.execute(
                    "INSERT INTO drop_scheduler_state VALUES(1,?,?,?,?,?,?,?,?,?,?,?)",
                    (*body.values(), _sha256_body(body)),
                )
            elif not self._state_valid(row):
                raise DROPManagementSchedulerError("DROP scheduler state integrity failed")
            connection.commit()
        ensure_private_file(self.path)

    def _state(self) -> dict[str, object]:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM drop_scheduler_state WHERE singleton=1").fetchone()
        if row is None or not self._state_valid(row):
            raise DROPManagementSchedulerError("DROP scheduler state integrity failed")
        return self._state_body(row)

    def _write_state(
        self,
        connection: sqlite3.Connection,
        body: Mapping[str, object],
        *,
        expected_revision: int,
    ) -> bool:
        values = dict(body)
        values["revision"] = expected_revision + 1
        updated = connection.execute(
            "UPDATE drop_scheduler_state SET revision=?,lease_owner=?,lease_until=?,"
            "next_run_at=?,last_started_at=?,last_completed_at=?,last_success_at=?,"
            "consecutive_failures=?,last_error_sha256=?,last_cycle_json=?,"
            "integrity_sha256=? WHERE singleton=1 AND revision=?",
            (*values.values(), _sha256_body(values), expected_revision),
        )
        return updated.rowcount == 1

    def _acquire(self, *, force: bool) -> dict[str, object] | None:
        now = float(self._clock())
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM drop_scheduler_state WHERE singleton=1").fetchone()
            if row is None or not self._state_valid(row):
                raise DROPManagementSchedulerError("DROP scheduler state integrity failed")
            body = self._state_body(row)
            if (
                (body["lease_owner"] and float(body["lease_until"]) > now)
                or (not force and float(body["next_run_at"]) > now)
            ):
                connection.rollback()
                return None
            expected = int(body["revision"])
            body.update(
                {
                    "lease_owner": self._worker_id,
                    "lease_until": now + self._lease_seconds,
                    "last_started_at": now,
                }
            )
            if not self._write_state(connection, body, expected_revision=expected):
                connection.rollback()
                return None
            connection.commit()
            return body

    def _renew_loop(self, stopped: threading.Event) -> None:
        while not stopped.wait(max(5.0, self._lease_seconds / 3)):
            try:
                now = float(self._clock())
                with cross_process_lock(self.path, strict=True), self._connect() as connection:
                    connection.execute("BEGIN IMMEDIATE")
                    row = connection.execute(
                        "SELECT * FROM drop_scheduler_state WHERE singleton=1"
                    ).fetchone()
                    if row is None or not self._state_valid(row):
                        return
                    body = self._state_body(row)
                    if body["lease_owner"] != self._worker_id:
                        return
                    expected = int(body["revision"])
                    body["lease_until"] = now + self._lease_seconds
                    if not self._write_state(connection, body, expected_revision=expected):
                        connection.rollback()
                        return
                    connection.commit()
            except Exception:
                return

    def _complete(
        self,
        *,
        cycle: DROPManagementMaintenanceCycle | None,
        error: BaseException | None,
    ) -> None:
        now = float(self._clock())
        with cross_process_lock(self.path, strict=True), self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM drop_scheduler_state WHERE singleton=1").fetchone()
            if row is None or not self._state_valid(row):
                raise DROPManagementSchedulerError("DROP scheduler state integrity failed")
            body = self._state_body(row)
            if body["lease_owner"] != self._worker_id:
                raise DROPManagementSchedulerError("DROP scheduler lease was lost")
            expected = int(body["revision"])
            body.update(
                {
                    "lease_owner": "",
                    "lease_until": 0.0,
                    "last_completed_at": now,
                }
            )
            if error is None and cycle is not None:
                jitter = self._jitter_source(self._jitter_seconds)
                if (
                    isinstance(jitter, bool)
                    or not isinstance(jitter, int)
                    or not 0 <= jitter <= self._jitter_seconds
                ):
                    raise DROPManagementSchedulerError("DROP scheduler jitter is invalid")
                body.update(
                    {
                        "next_run_at": now + self._interval_seconds + jitter,
                        "last_success_at": now,
                        "consecutive_failures": 0,
                        "last_error_sha256": "",
                        "last_cycle_json": _canonical(asdict(cycle)).decode("ascii"),
                    }
                )
            else:
                failures = min(int(body["consecutive_failures"]) + 1, 31)
                retry = min(self._retry_max_seconds, 30 * (2 ** min(failures - 1, 10)))
                body.update(
                    {
                        "next_run_at": now + retry,
                        "consecutive_failures": failures,
                        "last_error_sha256": hashlib.sha256(
                            type(error).__name__.encode("ascii", errors="ignore")
                        ).hexdigest(),
                    }
                )
            if not self._write_state(connection, body, expected_revision=expected):
                raise DROPManagementSchedulerError("DROP scheduler completion changed concurrently")
            connection.commit()

    def run_once(self, *, force: bool = False) -> DROPManagementMaintenanceCycle | None:
        if not self._enabled:
            return None
        if not self._cycle_lock.acquire(blocking=False):
            return None
        try:
            claimed = self._acquire(force=force)
            if claimed is None:
                return None
            renewal_stop = threading.Event()
            renewal = threading.Thread(
                target=self._renew_loop,
                args=(renewal_stop,),
                name="drop-scheduler-lease",
                daemon=True,
            )
            renewal.start()
            try:
                cycle = self._cycle_runner()
                if not isinstance(cycle, DROPManagementMaintenanceCycle):
                    raise DROPManagementSchedulerError("DROP maintenance cycle is invalid")
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                self._complete(cycle=None, error=exc)
                return None
            finally:
                renewal_stop.set()
                renewal.join(min(5.0, self._lease_seconds / 3))
            self._complete(cycle=cycle, error=None)
            return cycle
        finally:
            self._cycle_lock.release()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
                state = self._state()
                delay = max(0.1, min(60.0, float(state["next_run_at"]) - float(self._clock())))
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                delay = 30.0
            self._stop.wait(delay)

    def start(self) -> bool:
        if not self._enabled:
            return False
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return True
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop,
                name="privacy-drop-maintenance",
                daemon=True,
            )
            self._thread.start()
        return True

    def stop(self, timeout: float = 5.0, *, wait: bool = True) -> None:
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(float(timeout))
            or not 0 <= float(timeout) <= 30
        ):
            raise DROPManagementSchedulerError("DROP scheduler stop timeout is invalid")
        self._stop.set()
        with self._lock:
            thread = self._thread
        if not wait:
            return False
        if thread is not None:
            thread.join(float(timeout))
            if thread.is_alive():
                return
        with self._lock:
            if self._thread is thread and (thread is None or not thread.is_alive()):
                self._thread = None
        try:
            with cross_process_lock(self.path, strict=True), self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM drop_scheduler_state WHERE singleton=1"
                ).fetchone()
                if row is not None and self._state_valid(row):
                    body = self._state_body(row)
                    if body["lease_owner"] == self._worker_id:
                        expected = int(body["revision"])
                        body.update({"lease_owner": "", "lease_until": 0.0})
                        self._write_state(connection, body, expected_revision=expected)
                connection.commit()
        except Exception:
            return

    def health(self) -> Mapping[str, object]:
        state = self._state()
        now = float(self._clock())
        running = self._thread is not None and self._thread.is_alive()
        lease_active = bool(state["lease_owner"] and float(state["lease_until"]) > now)
        return {
            "schema": "lightwork.privacy-drop-scheduler-health.v1",
            "installed": True,
            "enabled": self._enabled,
            "running": running,
            "healthy": bool(self._enabled and int(state["consecutive_failures"]) == 0),
            "lease_active": lease_active,
            "lease_owned_by_this_process": bool(
                lease_active and state["lease_owner"] == self._worker_id
            ),
            "next_run_at": state["next_run_at"],
            "last_started_at": state["last_started_at"],
            "last_completed_at": state["last_completed_at"],
            "last_success_at": state["last_success_at"],
            "consecutive_failures": state["consecutive_failures"],
            "last_error_sha256": state["last_error_sha256"],
            "state_revision": state["revision"],
        }


def _sha256_body(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def hmac_compare(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def attach_drop_managed_scheduler(app: Any, runtime: DROPManagedMaintenanceScheduler) -> None:
    """Attach scheduler start/stop to the app lifespan exactly once."""

    if not isinstance(runtime, DROPManagedMaintenanceScheduler):
        raise TypeError("DROP managed scheduler runtime is invalid")
    previous = getattr(getattr(app, "router", None), "lifespan_context", None)
    if not callable(previous) or getattr(app.state, "privacy_drop_management_scheduler", None):
        raise TypeError("DROP managed scheduler requires an unattached lifespan")

    @asynccontextmanager
    async def lifespan(target: Any):
        from ._lifecycle import supervised_runtime

        async with previous(target):
            async with supervised_runtime(target, "drop_management", runtime):
                yield

    app.router.lifespan_context = lifespan
    app.state.privacy_drop_management_scheduler = runtime


__all__ = [
    "NETWORK_IO",
    "DROPManagementMaintenanceCycle",
    "DROPManagementSchedulerError",
    "DROPManagedMaintenanceScheduler",
    "attach_drop_managed_scheduler",
    "cycle_payload",
    "run_drop_maintenance_cycle",
]
