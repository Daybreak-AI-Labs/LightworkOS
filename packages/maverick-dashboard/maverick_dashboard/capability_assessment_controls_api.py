"""Authorized selected reads, never decisions, for native assessment controls."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse

from .capability_assessment_controls import read_selection

router = APIRouter(prefix="/capability-assessments", tags=["capability-assessments"])


@router.get("/selection")
def selection(request: Request, kind: Literal["agent", "flow"],
              subject: str = Query(min_length=1, max_length=256),
              expected_context: str = Query(pattern=r"^[0-9a-f]{64}$"),
              expected_revision: int = Query(ge=0, le=2**53 - 1),
              expected_source: str = Query(pattern=r"^[0-9a-f]{64}$"), review: bool = False):
    return JSONResponse(read_selection(request, kind, subject, expected_context=expected_context,
        expected_revision=expected_revision, expected_source=expected_source, review=review),
        headers={"Cache-Control": "private, no-store"})
