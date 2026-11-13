"""Helpers behind the Research lab's plain controls.

``POST /api/v1/research-files/fingerprint`` reads an uploaded file as a stream and
returns its SHA-256, so the page records a fingerprint from a chosen file
instead of asking anyone to type one. The file is never stored. Same
``operate`` permission as the research workspace it serves.
"""
from __future__ import annotations

import hashlib

from fastapi import APIRouter, HTTPException, Request

from .auth import require_permission

router = APIRouter(tags=["research-files"])
MAX_FINGERPRINT_BYTES = 256 * 1024 * 1024


@router.post("/research-files/fingerprint")
async def fingerprint(request: Request) -> dict:
    require_permission(request, "operate")
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_FINGERPRINT_BYTES:
        raise HTTPException(status_code=413, detail="That file is too large.")
    digest = hashlib.sha256()
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_FINGERPRINT_BYTES:
            raise HTTPException(status_code=413, detail="That file is too large.")
        digest.update(chunk)
    if size == 0:
        raise HTTPException(status_code=422, detail="That file is empty.")
    return {"fingerprint": digest.hexdigest(), "bytes": size}


__all__ = ["MAX_FINGERPRINT_BYTES", "router"]
