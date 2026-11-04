"""Append-only firing log for event triggers.

Every poll that produced something worth showing -- a fire, a source error, a
template-render skip -- appends one NDJSON row here. The successful *goals* a
trigger spawns are already queryable via ``/automation-runs?kind=event`` (the
goal-origin join); this log adds the part that join can't show: fires that
produced no goal (poll failed, template gone, an event skipped) and a plain
firing count / last-error for each trigger.

Append-only NDJSON (the ``consequence`` store's shape), 0600, best-effort --
never raises, so recording history can't break a poll. Idle polls (nothing new,
no error) are NOT recorded, so the log stays a meaningful fire/error history
rather than a per-tick heartbeat. Owner-stamped for owner-scoped reads.
"""
from __future__ import annotations

import json
import os
import time

from maverick import config

_MAX_ROWS = 2000  # bound the tail we read back; the file itself grows unbounded
                  # (like the consequence log) -- fine for best-effort telemetry

# kinds worth a row -- a fire, or one of the no-goal outcomes
FIRED = "fired"
POLL_ERROR = "poll_error"
TEMPLATE_UNAVAILABLE = "template_unavailable"
EVENT_SKIPPED = "event_skipped"


def _path():
    return config.dashboard_overrides_path().parent / "trigger-events.ndjson"


def record(name: str, owner: str, kind: str, *, new_events: int = 0,
           fired: list | None = None, fired_flows: list | None = None,
           note: str = "", tenant: str | None = None) -> None:
    """Append one firing/err row. Best-effort: never raises. ``fired`` holds
    integer goal ids (template fires); ``fired_flows`` holds string flow run ids
    (flow fires) -- a trigger fires one or the other, never both."""
    from maverick.paths import current_tenant_id
    from maverick.secrets import scrub

    tenant_id = current_tenant_id() if tenant is None else tenant
    row = {
        "ts": time.time(),
        "name": str(name),
        "owner": str(owner or ""),
        "tenant": str(tenant_id or ""),
        "kind": str(kind),
        "new_events": int(new_events),
        "fired": [int(g) for g in (fired or [])],
        "fired_flows": [str(r) for r in (fired_flows or [])],
        "note": scrub(str(note)).strip()[:500],
    }
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(p), os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    except Exception:  # pragma: no cover -- history is best-effort
        return


def _read_rows() -> list[dict]:
    p = _path()
    if not p.exists():
        return []
    try:
        with open(p, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out: list[dict] = []
    for raw in lines[-_MAX_ROWS:]:
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                out.append(d)
        except (ValueError, TypeError):
            continue
    return out


def history(*, name: str | None = None, owner: str | None = None,
            owners: frozenset[str] | None = None,
            tenant: str | None = None, limit: int = 50) -> list[dict]:
    """Recent firing/error rows, newest first. ``owner=None`` (admin/auth-off)
    sees all; a specific owner sees only its own. ``name`` filters to one
    trigger."""
    rows = _read_rows()
    if owner is not None:
        rows = [r for r in rows if r.get("owner", "") == owner]
    if owners is not None:
        rows = [r for r in rows if r.get("owner", "") in owners]
    if tenant is not None:
        # Legacy rows had no tenant field and belong only to the shared floor;
        # never blend them into a named tenant with the same owner/name.
        rows = [r for r in rows if r.get("tenant", "") == tenant]
    if name is not None:
        rows = [r for r in rows if r.get("name", "") == name]
    rows.reverse()  # newest first
    return rows[: max(0, int(limit))]


__all__ = ["record", "history",
           "FIRED", "POLL_ERROR", "TEMPLATE_UNAVAILABLE", "EVENT_SKIPPED"]
