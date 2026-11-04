"""Background data-use checks: the module's existing checks, on a schedule.

Off by default (``[data_use_governance.scheduler] enable``). When on, one
Lightwork process at a time runs a check pass (a leased claim in a small job
store, so two processes sharing the data folder never run the same pass), for
every workspace where data-use governance is on. A pass runs exactly these
existing, read-only checks:

1. **Change record** -- :meth:`DataUseGovernanceStore.unified_audit_records`:
   every recorded data-use change is re-read and must still be canonical with
   a matching digest (the check the unified audit capture relies on).
2. **Decisions** -- :meth:`DataUsePolicyCompiler.compile` (the same check as
   compiling a decision on the Data use page), when the compiler is on: each
   allowing decision (up to 500 per workspace) is compiled against current
   authority and counted as current, stale (authority expired, changed or
   gone) or refused.
3. **Exceptions** -- approved policy exceptions whose end has passed, and
   requested ones that ran out before review, are counted.

Nothing is written to the data-use records and nothing is sent to a data
platform. Each pass keeps one summary (counts, and which workspaces had
findings) in the job store, which keeps only the latest ``history_limit``
passes; the caller adds one activity-record row per pass.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import math
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .file_lock import ensure_private_directory

_BOUNDS = {"poll_seconds": (5, 3_600), "lease_seconds": (30, 86_400),
           "history_limit": (1, 1_000)}
DEFAULTS = {"poll_seconds": 3_600, "lease_seconds": 900, "history_limit": 50}
_MAX_DECISIONS = 500
_MAX_LISTED_WORKSPACES = 50


class DataUseChecksError(RuntimeError):
    """The background checks cannot run (plain words, no record contents)."""


@dataclass(frozen=True)
class CheckSettings:
    enable: bool = False
    poll_seconds: int = DEFAULTS["poll_seconds"]
    lease_seconds: int = DEFAULTS["lease_seconds"]
    history_limit: int = DEFAULTS["history_limit"]


def check_settings(config: Mapping[str, Any] | None = None) -> CheckSettings:
    """Read ``[data_use_governance.scheduler]`` (unset keys keep the defaults)."""
    if config is None:
        from .config import load_global_config

        config = load_global_config() or {}
    section = config.get("data_use_governance") if isinstance(config, Mapping) else None
    node = section.get("scheduler") if isinstance(section, Mapping) else None
    if node is None:
        return CheckSettings()
    if not isinstance(node, Mapping):
        raise DataUseChecksError("data_use_governance.scheduler must be a table")
    enable = node.get("enable", False)
    if not isinstance(enable, bool):
        raise DataUseChecksError("data_use_governance.scheduler.enable must be true or false")
    values: dict[str, int] = {}
    for key, (low, high) in _BOUNDS.items():
        value = node.get(key, DEFAULTS[key])
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise DataUseChecksError(
                f"data_use_governance.scheduler.{key} must be a whole number from {low} to {high}")
        values[key] = value
    return CheckSettings(enable, **values)


# ---------------------------------------------------------------- job store
class CheckJobStore:
    """One schedule row (next due time and the current claim) and the history."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = Path(path)
        self._clock = clock
        ensure_private_directory(self.path.parent)
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS check_schedule (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    next_due_at REAL NOT NULL,
                    claimed_by TEXT,
                    claim_token TEXT,
                    lease_until REAL
                );
                CREATE TABLE IF NOT EXISTS check_runs (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at REAL NOT NULL,
                    finished_at REAL NOT NULL,
                    outcome TEXT NOT NULL,
                    summary_json TEXT NOT NULL,
                    summary_sha256 TEXT NOT NULL
                );
                INSERT OR IGNORE INTO check_schedule (singleton, next_due_at) VALUES (1, 0);
                """
            )

    @contextlib.contextmanager
    def _connect(self):
        conn = sqlite3.connect(str(self.path), timeout=10.0, isolation_level=None)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout=10000")
            yield conn
        finally:
            conn.close()

    def claim(self, worker_id: str, *, lease_seconds: int) -> str | None:
        """Take the due pass for ``lease_seconds``; None when not due or held."""
        now = float(self._clock())
        token = secrets.token_hex(16)
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM check_schedule WHERE singleton = 1").fetchone()
                held = row["lease_until"] is not None and float(row["lease_until"]) > now
                if float(row["next_due_at"]) > now or held:
                    conn.execute("ROLLBACK")
                    return None
                conn.execute(
                    "UPDATE check_schedule SET claimed_by = ?, claim_token = ?, lease_until = ? "
                    "WHERE singleton = 1", (worker_id[:200], token, now + lease_seconds))
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return token

    def complete(self, token: str, *, started_at: float, outcome: str, summary: Mapping[str, Any],
                 poll_seconds: int, history_limit: int) -> bool:
        """Record a finished pass and schedule the next; False if the claim was lost."""
        now = float(self._clock())
        text = json.dumps(dict(summary), sort_keys=True, separators=(",", ":"))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT claim_token FROM check_schedule WHERE singleton = 1").fetchone()
                if row["claim_token"] != token:
                    conn.execute("ROLLBACK")
                    return False
                conn.execute(
                    "INSERT INTO check_runs (started_at, finished_at, outcome, summary_json, "
                    "summary_sha256) VALUES (?, ?, ?, ?, ?)",
                    (started_at, now, outcome, text, hashlib.sha256(text.encode()).hexdigest()))
                conn.execute(
                    "DELETE FROM check_runs WHERE sequence NOT IN (SELECT sequence FROM check_runs "
                    "ORDER BY sequence DESC LIMIT ?)", (history_limit,))
                conn.execute(
                    "UPDATE check_schedule SET next_due_at = ?, claimed_by = NULL, "
                    "claim_token = NULL, lease_until = NULL WHERE singleton = 1",
                    (now + poll_seconds,))
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return True

    def history(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM check_runs ORDER BY sequence DESC LIMIT ?",
                (max(1, min(int(limit), 1_000)),)).fetchall()
        return [{"started_at": r["started_at"], "finished_at": r["finished_at"],
                 "outcome": r["outcome"], "summary": json.loads(r["summary_json"])} for r in rows]

    def schedule(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM check_schedule WHERE singleton = 1").fetchone()
        return {"next_due_at": row["next_due_at"] or None,
                "running": row["lease_until"] is not None
                and float(row["lease_until"]) > float(self._clock())}


# ---------------------------------------------------------------- the checks
def check_workspace(store: Any, tenant: str, *, compiler: Any | None,
                    now: float | None = None) -> dict[str, int]:
    """Run the three existing checks for one workspace; read-only."""
    from .data_use_governance import DataUseGovernanceError

    now = time.time() if now is None else now
    counts = {"change_record_ok": 0, "change_record_broken": 0, "decisions_current": 0,
              "decisions_stale": 0, "decisions_refused": 0, "decisions_not_checked": 0,
              "exceptions_ended": 0, "exceptions_lapsed": 0}
    try:
        store.unified_audit_records(tenant)
        counts["change_record_ok"] = 1
    except DataUseGovernanceError:
        counts["change_record_broken"] = 1
    decisions = store.list_records(tenant, "decision", limit=_MAX_DECISIONS)
    for decision in decisions:
        if decision.get("outcome") not in {"allow", "mask", "row_filter"}:
            continue
        if compiler is None:
            counts["decisions_not_checked"] += 1
            continue
        try:
            compiler.compile(tenant, str(decision["decision_id"]))
            counts["decisions_current"] += 1
        except Exception as exc:  # noqa: BLE001 - classified, never stored
            stale = type(exc).__name__ in {"DataUseCompilationStale", "DataUseStaleAuthority",
                                           "DataUseMissingAuthority"}
            counts["decisions_stale" if stale else "decisions_refused"] += 1
    for item in store.list_records(tenant, "exception", limit=_MAX_DECISIONS):
        ends = item.get("expires_at")
        if not isinstance(ends, (int, float)) or not math.isfinite(ends) or ends > now:
            continue
        if item.get("state") == "approved":
            counts["exceptions_ended"] += 1
        elif item.get("state") == "requested":
            counts["exceptions_lapsed"] += 1
    return counts


_FINDINGS = ("change_record_broken", "decisions_stale", "decisions_refused",
             "exceptions_ended", "exceptions_lapsed")


def summarize(results: Iterable[tuple[str, Mapping[str, int] | None]]) -> dict[str, Any]:
    """Totals over workspaces; ``None`` counts mean the workspace could not be checked."""
    totals: dict[str, int] = {}
    flagged: list[str] = []
    failed = 0
    checked = 0
    for workspace, counts in results:
        if counts is None:
            failed += 1
            continue
        checked += 1
        for key, value in counts.items():
            totals[key] = totals.get(key, 0) + int(value)
        if any(counts.get(key) for key in _FINDINGS) and len(flagged) < _MAX_LISTED_WORKSPACES:
            flagged.append(workspace or "shared")
    return {"workspaces_checked": checked, "workspaces_failed": failed,
            "findings": sum(totals.get(key, 0) for key in _FINDINGS),
            "workspaces_with_findings": flagged, **totals}


__all__ = ["CheckJobStore", "CheckSettings", "DEFAULTS", "DataUseChecksError", "check_settings",
           "check_workspace", "summarize"]
