"""One-tap feedback on flow run results.

A run's owner may mark a finished run useful or not useful. The store keeps
only that: the run, its flow, the owner, the rating and when. It holds no
written text, keeps one rating per run (a new tap replaces the old), lives in
the active workspace's data folder (``paths.data_dir`` is tenant-scoped) and
forgets ratings older than ``KEEP_SECONDS`` or beyond the newest
``MAX_RATINGS``. A rating is a person's signal, not proof the work was right.
"""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, HTTPException, Request
from maverick.file_lock import atomic_write_text, cross_process_lock
from maverick.paths import data_dir
from pydantic import BaseModel, ConfigDict, Field

from .auth import require_permission

RATINGS = ("up", "down")
MAX_RATINGS = 5000
KEEP_SECONDS = 365 * 24 * 3600


def _path():
    return data_dir("dashboard", "flow-run-feedback.json")


def _read() -> list[dict]:
    try:
        rows = json.loads(_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    oldest = time.time() - KEEP_SECONDS
    return [row for row in rows if isinstance(row, dict) and row.get("rating") in RATINGS
            and isinstance(row.get("at"), (int, float)) and row["at"] >= oldest][-MAX_RATINGS:] if isinstance(rows, list) else []


def rows() -> list[dict]:
    """The kept ratings, oldest first."""
    return _read()


def record(run_id: str, *, flow_id: str, owner: str, rating: str) -> dict:
    """Save ``rating`` for this run (replacing an earlier one) and return it."""
    if rating not in RATINGS:
        raise ValueError("rating must be up or down")
    row = {"run_id": str(run_id), "flow_id": str(flow_id), "owner": str(owner or ""), "rating": rating, "at": time.time()}
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with cross_process_lock(path):
        kept = [old for old in _read() if not (old.get("run_id") == row["run_id"] and old.get("owner") == row["owner"])]
        kept.append(row)
        atomic_write_text(path, json.dumps(kept[-MAX_RATINGS:], sort_keys=True))
    return row


def latest(run_id: str, *, owner: str) -> str | None:
    """This owner's kept rating of the run, or ``None``."""
    for row in reversed(_read()):
        if row.get("run_id") == str(run_id) and row.get("owner") == str(owner or ""):
            return row["rating"]
    return None


def summary_by_flow() -> list[dict]:
    """Useful / not useful counts per flow, busiest first."""
    flows: dict[str, dict] = {}
    for row in _read():
        entry = flows.setdefault(str(row.get("flow_id", "")), {"flow_id": str(row.get("flow_id", "")), "up": 0, "down": 0})
        entry[row["rating"]] += 1
    return sorted(flows.values(), key=lambda entry: (-(entry["up"] + entry["down"]), entry["flow_id"]))


router = APIRouter(prefix="/api/v1/flows/runs", tags=["flow-run-feedback"])
_FINISHED = frozenset({"completed", "failed", "rejected"})


class FeedbackIn(BaseModel):
    """A thumbs up or down and nothing else: no written text is kept."""
    model_config = ConfigDict(extra="forbid", strict=True)
    rating: str = Field(pattern=r"^(up|down)$")


def _owned_run(request: Request, run_id: str):
    # The run's own owner-scoped read: someone else's run is "not found".
    from .flows_api import _load_owned_run, _require_flows

    require_permission(request, "operate")
    _require_flows()
    return _load_owned_run(request, run_id)


@router.get("/{run_id}/feedback")
def read_feedback(request: Request, run_id: str) -> dict:
    run = _owned_run(request, run_id)
    return {"eligible": run.status in _FINISHED, "rating": latest(run.run_id, owner=run.owner)}


@router.put("/{run_id}/feedback")
def save_feedback(request: Request, run_id: str, body: FeedbackIn) -> dict:
    run = _owned_run(request, run_id)
    if run.status not in _FINISHED:
        raise HTTPException(status_code=409, detail="Rate this run when it has finished.")
    record(run.run_id, flow_id=run.flow_id, owner=run.owner, rating=body.rating)
    return {"eligible": True, "rating": body.rating}


__all__ = ["KEEP_SECONDS", "MAX_RATINGS", "RATINGS", "latest", "record", "router", "rows", "summary_by_flow"]
