"""Read-only recovery options; evidence never overrides restore admission."""
from __future__ import annotations

import time

from . import backup
from . import installation_recovery as recovery


def _reason(exc: Exception) -> str:
    """Plans are shared with other administrators, so an operating-system error
    (which names local paths) is replaced by a fixed sentence."""
    if isinstance(exc, (recovery.MaintenanceError, backup.BackupError)):
        return str(exc)[:2000]
    return "The retained recovery evidence could not be read on this computer."


def plan(identifier: str, *, offset: int = 0) -> dict:
    if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= backup.MAX_ARCHIVE_MEMBERS * 2:
        raise recovery.MaintenanceError("Choose a valid recovery evidence page.")
    # Hold the installation lock only to read the record and the blockers. The
    # comparison below can extract a whole retained snapshot; running it under
    # the lock would stall status, authorization and retirement for its duration.
    with recovery._locked():
        directory = recovery._directory(identifier)
        try:
            record = recovery._read(directory / "record.json")
        except FileNotFoundError as exc:
            raise recovery.MaintenanceError("Select an installation recovery point from this computer.") from exc
        try:
            reasons = [{"code": "coordinated_resources", "message": reason} for reason in recovery.blockers()]
        except (OSError, ValueError, recovery.MaintenanceError) as exc:
            reasons = [{"code": "coordinated_resources", "message": _reason(exc)}]
    comparison = None
    if record.get("status") != "upgraded":
        reasons.append({"code": "not_completed_upgrade", "message": "This point is not a completed upgrade. Use Finish interrupted maintenance when offered, or repair the current release."})
    elif not record.get("before"):
        reasons.append({"code": "snapshot_unavailable", "message": "The original application/state pair is unavailable. Repair the current version without restoring older accounting."})
    else:
        try:
            archive = directory / "before.tgz"
            if backup._sha256(archive) != record["before"]["sha256"]:
                raise recovery.MaintenanceError("The retained snapshot identity changed.")
            with recovery._scope():
                comparison = backup.compare_backup(archive)
            if comparison["protected_changes"]:
                reasons.append({"code": "protected_state_changed", "message": "New accounting, reservations, database or action history prevents automatic rollback. Keep this state; do not repeat uncertain actions or reset spending."})
            if backup._sha256(recovery._runtime()) != record.get("new_runtime_sha256"):
                reasons.append({"code": "installed_release_changed", "message": "The current application differs from this retained update. It cannot be paired automatically with this older snapshot."})
        except (OSError, ValueError, backup.BackupError, recovery.MaintenanceError) as exc:
            reasons.append({"code": "evidence_unavailable", "message": _reason(exc)})
    protected = [row for row in (comparison or {}).get("items", []) if row["protected"]]
    return {"schema": "lightwork.installation-recovery-plan.v1", "id": identifier, "observed_at": time.time(),
            "old_version": record.get("old_version"), "new_version": (record.get("new") or {}).get("version"),
            "rollback_candidate": not reasons, "authorization_required": True, "blockers": reasons,
            "affected": protected[offset:offset + 50], "offset": offset, "total_affected": len(protected), "has_more": offset + 50 < len(protected),
            "snapshot_sha256": (record.get("before") or {}).get("sha256"),
            "live_state_sha256": (comparison or {}).get("live_state_sha256"),
            "actions": [{"id": "repair_current", "label": "Repair current version", "effect": "Reinstall verified current application files while preserving work and accounting."},
                        {"id": "workspace_recovery", "label": "Open workspace recovery", "effect": "Use isolated administrator controls to export and drill workspace snapshots. External databases, keys and workers require their owners' coordinated plan."},
                        {"id": "save_plan", "label": "Save coordination plan", "effect": "Save this metadata-only evidence locally for the responsible administrators. Folder names can identify workspaces."}],
            "notice": "This is read-only evidence, not rollback approval. Every mutation rechecks current release, data, authority and quiescence. Workspace export/drill covers the selected workspace, not every external service."}
