"""Metadata only: private report bytes stay in their native download routes."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from . import report_downloads

router = APIRouter()


@router.get("/api/v1/report-downloads")
def catalog(request: Request):
    return JSONResponse(report_downloads.catalog(request), headers={"Cache-Control": "private, no-store"})
