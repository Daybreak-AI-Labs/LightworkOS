"""Maintenance that may only run while Lightwork is stopped, run at the next start.

Moving a workspace's chat-agent task records into the shared database
(``maverick a2a migrate-claims``, kernel :func:`maverick.a2a_migration.
migrate_local_tasks`) needs exclusive ownership of the data folder. A running
dashboard holds that ownership for its whole life, so the move can never run
from inside it. A global administrator schedules the move from Settings >
Maintenance instead; the next dashboard start runs it *before* taking
ownership of the data folder (the kernel acquires and releases its own
ownership for the move), records the completion receipt or a plain failure,
and then starts normally. Scheduling, cancelling and the outcome are all in
the activity record.

Nothing here ever blocks startup: every failure is recorded and startup goes on.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

KINDS = ("task_records",)
_MAX_TECHNICAL = 300


class NotReady(RuntimeError):
    """The move cannot be scheduled (plain sentence)."""


def _directory() -> Path:
    from maverick.file_lock import ensure_private_directory
    from maverick.paths import maverick_home
    path = maverick_home() / "offline-maintenance"
    ensure_private_directory(path)
    return path


def _read(name: str) -> dict[str, Any]:
    path = _directory() / name
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(name: str, data: dict[str, Any]) -> None:
    from maverick.file_lock import atomic_write_text
    atomic_write_text(_directory() / name, json.dumps(data, sort_keys=True), mode=0o600)


def schedule(kind: str, workspace: str, actor: str) -> None:
    if kind not in KINDS:
        raise ValueError("unknown offline maintenance")
    data = _read("schedule.json")
    data[kind] = {"workspace": workspace, "requested_by": actor[:200], "requested_at": time.time()}
    _write("schedule.json", data)


def cancel(kind: str) -> None:
    data = _read("schedule.json")
    if data.pop(kind, None) is not None:
        _write("schedule.json", data)


def _source_present(workspace: str) -> bool:
    from maverick.paths import data_dir
    try:
        return data_dir("a2a", "tasks.sqlite3", tenant=workspace).is_file()
    except Exception:  # noqa: BLE001 -- an unreadable path is "unknown", shown as not present
        return False


def _shared_database() -> bool:
    try:
        from maverick.governed_records import configured_governed_records_backend
        return configured_governed_records_backend() == "postgres"
    except Exception:  # noqa: BLE001
        return False


def task_records_ready(workspace: str) -> None:
    if not _shared_database():
        raise NotReady("Chat-agent task records can only move to a shared database, and this installation "
                       "doesn't use one. Nothing was scheduled.")
    if not _source_present(workspace):
        raise NotReady("This workspace has no task records on this computer to move. Nothing was scheduled.")


def task_records_state() -> dict[str, Any]:
    """What the page shows: whether a move is possible, scheduled, or done."""
    scheduled = _read("schedule.json").get("task_records")
    result = _read("results.json").get("task_records")
    shared = _shared_database()
    if scheduled:
        summary = ("The move is scheduled. It runs the next time Lightwork starts, before any other work. "
                   "Restart Lightwork when it is quiet to run it.")
    elif not shared:
        summary = ("This installation doesn't use a shared database, so there are no chat-agent task records "
                   "to move.")
    else:
        summary = ("Moving a workspace's chat-agent task records into the shared database needs Lightwork to be "
                   "stopped, so it is scheduled here and runs at the next start.")
    return {"shared_database": shared, "scheduled": _public_schedule(scheduled),
            "last_result": result or None, "summary": summary}


def _public_schedule(entry: dict[str, Any] | None) -> dict[str, Any] | None:
    if not entry:
        return None
    return {"workspace": entry.get("workspace"), "requested_at": entry.get("requested_at")}


def _still_running(exc: BaseException) -> bool:
    """Another Lightwork process held the control plane: the move has not been tried yet."""
    from maverick import control_plane_lease
    return isinstance(exc, (control_plane_lease.ControlPlaneBusy, control_plane_lease.LeaseUnavailable))


def _plain_failure(exc: BaseException) -> tuple[str, str]:
    from maverick.governed_records import GovernedRecordBackendError
    if _still_running(exc):
        return ("Another Lightwork process was still running, so the move waited. It stays scheduled; stop "
                "every Lightwork process and start again.", "")
    if isinstance(exc, (ValueError, GovernedRecordBackendError)):
        # Kernel refusals name the problem without connection details.
        return ("The records could not be moved safely, so the originals were kept. Share the technical "
                "details with your IT team.", str(exc)[:_MAX_TECHNICAL])
    # Driver/provider exceptions can contain credentials: keep only the type.
    return ("The move did not complete. The original records and the shared database were kept as they "
            "were; ask your IT team to check the shared database.", type(exc).__name__)


def _record(verb: str, **detail: Any) -> None:
    try:
        from maverick.audit import EventKind, audit_event
        audit_event(EventKind.CONTROL_PLANE_ACTION, agent="dashboard", _global=True, verb=verb,
                    principal="*", actor="scheduled maintenance", ok=detail.pop("ok", True), **detail)
    except Exception:  # noqa: BLE001 -- the outcome file still records what happened
        log.warning("offline maintenance could not add %s to the activity record", verb)


def _run_task_records(entry: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    from maverick.a2a_migration import migrate_local_tasks
    workspace = str(entry.get("workspace") or "")
    try:
        receipt = migrate_local_tasks(workspace)
    except Exception as exc:  # noqa: BLE001 -- recorded; startup continues
        summary, technical = _plain_failure(exc)
        return _still_running(exc), {"state": "failed", "workspace": workspace, "finished_at": time.time(),
                      "summary": summary, "technical": technical}
    claims = int(receipt.get("source_claims") or 0)
    return False, {"state": "done", "workspace": workspace, "finished_at": time.time(),
                   "summary": f"Moved {claims:,} task record{'s' if claims != 1 else ''} into the shared "
                              "database. The original records were kept as a private archive.",
                   "receipt": {key: receipt.get(key) for key in
                               ("status", "authority_id", "source_sha256", "source_claims",
                                "target_snapshot_bytes", "archive")}}


def run_scheduled() -> None:
    """Run every scheduled offline move. Called at dashboard start, before the
    data-folder ownership is taken. Never raises."""
    try:
        schedule_data = _read("schedule.json")
        entry = schedule_data.get("task_records")
        if not entry:
            return
        keep, outcome = _run_task_records(entry)
        results = _read("results.json")
        results["task_records"] = outcome
        _write("results.json", results)
        if not keep:
            schedule_data.pop("task_records", None)
            _write("schedule.json", schedule_data)
        _record("task_records_move", ok=outcome["state"] == "done", workspace=outcome["workspace"],
                claims=int((outcome.get("receipt") or {}).get("source_claims") or 0))
    except Exception:  # noqa: BLE001 -- never block startup
        log.exception("scheduled offline maintenance did not run")


__all__ = ["KINDS", "NotReady", "schedule", "cancel", "task_records_ready", "task_records_state",
           "run_scheduled"]
