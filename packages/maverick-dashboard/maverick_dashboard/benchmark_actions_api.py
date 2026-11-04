"""Record a benchmark score from the Benchmarks page.

``POST /benchmarks/scores`` appends one score to the same history the
``bench_track`` tool writes (``maverick.continuous_benchmark``), so a person
can log a result without the tool or Python. Same global ``admin`` rung as
``GET /api/v1/benchmarks``; every recorded score is written to the activity
log.
"""
from __future__ import annotations

import math
import re
import threading

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .audit_actions_api import _audit_event
from .auth import require_global_permission

router = APIRouter(tags=["benchmark-actions"])
_LOCK = threading.Lock()
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,79}\Z")


class ScoreIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    score: float
    note: str = Field(default="", max_length=120)


def _append(name: str, score: float, note: str) -> int:
    from maverick import continuous_benchmark as cb
    with _LOCK:
        path = cb._store_path()
        history = cb.load_history(path)
        cb.record_result(history, name, score, commit=note)
        cb.save_history(path, history)
        return sum(1 for row in history if isinstance(row, dict) and row.get("name") == name)


@router.post("/benchmarks/scores")
async def record_score(request: Request, body: ScoreIn) -> dict:
    require_global_permission(request, "admin")
    name = " ".join(body.name.split())
    if not _NAME.match(name):
        raise HTTPException(status_code=422,
                            detail="Use letters, numbers, spaces, dots, dashes or underscores for the test name.")
    if not math.isfinite(body.score):
        raise HTTPException(status_code=422, detail="Enter the score as a number.")
    note = " ".join(body.note.split())
    runs = await run_in_threadpool(_append, name, body.score, note)
    _audit_event(request, "benchmark_score_recorded", benchmark=name, score=body.score)
    return {"name": name, "runs": runs}


__all__ = ["router"]
