"""Old-record clean-up (``maverick gc``) for one world or every workspace.

The prune calls the command has always made -- idle conversations, old task
activity (goal events) and the 30-day duplicate-message checks -- shared with
the dashboard's Settings > Maintenance "Tidy up old records". An unbound
shared (Postgres) database is an administrator read view, never implicit
delete-all authority, so a sweep across workspaces runs each workspace under
its own explicit scope, one at a time.
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from typing import Any

DEDUP_SECONDS = 30 * 24 * 3600


def assert_no_broad_holds() -> None:
    """Refuse a broad purge while a legal hold applies to this workspace.

    Mirrors ``maverick.audit.retention.enforce``: a privacy-rights case hold
    that cannot be verified fails closed, a recorded hold blocks the whole
    workspace, and an active eDiscovery matter blocks it too.  Raises
    :class:`~maverick.ediscovery.LegalHoldApplies` with a plain message that
    names no matter and no case.
    """
    from .audit.preservation import preservation_snapshot
    from .ediscovery import LegalHoldApplies, assert_no_active_matters

    try:
        preservation = preservation_snapshot()
    except Exception as exc:  # failure-policy: fail_closed -- unverified holds prohibit deletion
        raise LegalHoldApplies("Preservation holds could not be verified; no records were deleted.") from exc
    if preservation["blocked"]:
        raise LegalHoldApplies("Recorded preservation holds block broad deletion in this workspace.")
    assert_no_active_matters()


def prune_world(world: Any, *, days: int, events_days: int) -> tuple[int, int, int]:
    """``(conversations, goal events, processed messages)`` removed from ``world``."""
    # Idle-conversation and activity pruning are broad purges: a recorded case
    # hold or an active legal matter in this workspace pauses them, as it pauses
    # retention enforcement.
    assert_no_broad_holds()
    convs = world.prune_conversations(idle_for_seconds=days * 24 * 3600)
    events = world.prune_goal_events(older_than_seconds=events_days * 24 * 3600)
    # Twilio dedup rows accumulate one-per-webhook forever; reap after
    # 30 days (the retry window is minutes so this is generous).
    dedup = world.prune_processed_messages(older_than_seconds=DEDUP_SECONDS)
    return int(convs), int(events), int(dedup)


def _idle_conversations(world: Any, cutoff: float) -> int | None:
    """How many conversations have been idle since ``cutoff`` (None if unknown)."""
    try:
        from .world_model import WorldModel
        if isinstance(world, WorldModel):
            row = world._read_one("SELECT COUNT(*) FROM conversations WHERE last_seen < ?", (cutoff,))
            return int(row[0] or 0) if row is not None else 0
        from .world_model_backends.postgres import _required_retention_tenant
        tenant = _required_retention_tenant("conversation retention")
        with world._tx() as cur:
            cur.execute("SELECT COUNT(*) FROM conversations WHERE last_seen < %s AND tenant_id = %s",
                        (cutoff, tenant))
            row = cur.fetchone()
            return int(row[0] or 0) if row is not None else 0
    except Exception:  # noqa: BLE001 -- a count is advisory; the prune itself is exact
        return None


def preview_world(world: Any, *, days: int, events_days: int, now: float | None = None) -> dict[str, Any]:
    """What :func:`prune_world` would remove, without removing anything."""
    now = time.time() if now is None else now
    return {"conversations": _idle_conversations(world, now - days * 86400),
            "activity": int(world.purge_goal_events_before(now - events_days * 86400, dry_run=True))}


def sweep_workspaces(tenants: Iterable[Any], *, days: int, events_days: int, dry_run: bool = False,
                     open_world: Callable[..., Any] | None = None,
                     skip_empty: bool = False) -> list[dict[str, Any]]:
    """Clean up (or, with ``dry_run``, count) every workspace in ``tenants``.

    Each workspace runs under its own explicit scope. ``skip_empty`` leaves
    out a local workspace whose records database was never created (so a
    preview never creates one). Returns one row per workspace.
    """
    from .ediscovery import LegalHoldApplies
    from .paths import tenant_scope
    from .world_model import close_world_if_owned
    from .world_model_backends import is_postgres_configured
    if open_world is None:
        from .world_model import open_world
    postgres = is_postgres_configured()
    rows: list[dict[str, Any]] = []
    for record in tenants:
        workspace = str(record.id)
        name = getattr(record, "display_name", "") or workspace
        if skip_empty and not postgres:
            from .workspace import Workspace
            if not Workspace(workspace).db_path.exists():
                rows.append({"workspace": workspace, "name": name, "empty": True})
                continue
        with tenant_scope(tenant=workspace):
            world = open_world()
            try:
                if dry_run:
                    try:
                        assert_no_broad_holds()
                        counts = preview_world(world, days=days, events_days=events_days)
                    except LegalHoldApplies:
                        # The preview must not promise removals a legal hold will refuse.
                        counts = {"conversations": 0, "activity": 0, "held": True}
                else:
                    try:
                        convs, events, dedup = prune_world(world, days=days, events_days=events_days)
                        counts = {"conversations": convs, "activity": events, "duplicate_checks": dedup}
                    except LegalHoldApplies:
                        # Skip this workspace only; the other workspaces still sweep.
                        counts = {"conversations": 0, "activity": 0, "duplicate_checks": 0, "held": True}
            finally:
                close_world_if_owned(world)
        rows.append({"workspace": workspace, "name": name, "empty": False, **counts})
    return rows


__all__ = ["assert_no_broad_holds", "prune_world", "preview_world", "sweep_workspaces", "DEDUP_SECONDS"]
