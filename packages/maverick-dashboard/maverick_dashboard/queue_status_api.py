"""Background work at a glance (read-only), for the Action Center.

The same information as ``maverick queue status`` and ``maverick queue failed``:
how much background work is waiting, running, finished or failed, and the
failed items with a plain description. The queue spans everyone's scheduled
and automatic work in this workspace, so it needs the ``admin`` permission.

Parked recurring schedules are reviewed from Automations using the exact
queue reconciliation transaction; this summary itself remains read-only.
"""

from __future__ import annotations

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from .auth import require_permission

router = APIRouter(prefix="/queue", tags=["queue"])

_KIND_LABELS = {
    "start_goal": "Scheduled task",
    "run_goal": "Task run",
    "flow_run": "Workflow run",
    "event_poll": "Check for new items",
}


def _problem(text: str) -> str:
    low = (text or "").lower()
    if not low:
        return "It stopped without saying why."
    if "reconcil" in low:
        return "A repeating schedule is paused until an operator checks it."
    if "timeout" in low or "timed out" in low:
        return "It took too long."
    if "budget" in low or "spend" in low:
        return "It reached a spending limit."
    if "permission" in low or "forbidden" in low or "denied" in low:
        return "It wasn't allowed to run."
    if "lease" in low or "stale" in low or "crash" in low:
        return "The background worker stopped while it was running."
    return "It failed after trying again."


def redacted_error(text: object) -> str:
    """A stopped job's error, on one line, bounded, with secrets masked."""
    from maverick.safety.secret_detector import redact

    detail, _ = redact(" ".join(str(text or "").split())[:500])
    return detail


def _summary(limit: int) -> dict:
    from maverick.job_queue import JobQueue

    queue = JobQueue()
    counts = queue.counts()
    failed = []
    for job in queue.list(status="failed", limit=limit):
        payload = job.payload if isinstance(job.payload, dict) else {}
        title = str(payload.get("title") or payload.get("template") or "")[:200]
        detail = redacted_error(job.last_error)
        failed.append({
            "id": job.id,
            "what": _KIND_LABELS.get(job.kind, job.kind.replace("_", " ").capitalize()),
            "title": title,
            "attempts": job.attempts,
            "failed_at": job.updated_at,
            "problem": _problem(job.last_error),
            "needs_operator": bool(job.recurrence_reconcile_required),
            "detail": detail,
        })
    return {
        "waiting": counts.get("pending", 0),
        "running": counts.get("running", 0),
        "finished": counts.get("done", 0),
        "failed": counts.get("failed", 0),
        "failed_items": failed,
    }


@router.get("/summary")
async def queue_summary(request: Request, limit: int = 50) -> dict:
    """Counts by state plus the most recent failed items, newest first."""
    require_permission(request, "admin")
    return await run_in_threadpool(_summary, max(1, min(int(limit), 200)))


__all__ = ["router", "redacted_error"]
