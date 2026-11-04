"""Customer-facing platform threat-hunter demo."""
from __future__ import annotations

from pathlib import Path

import backend
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from request_limits import (
    PayloadError,
    read_bounded_json,
    reject_raw_fields,
    require_expected_revision,
    validate_events,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(title="Platform Threat Hunter")
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "[::1]"],
)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


async def _body(request: Request) -> dict:
    try:
        return await read_bounded_json(request)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


def _expected_revision(body: dict) -> int:
    try:
        return require_expected_revision(body)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"records": backend.list_records()[-12:]})


@app.get("/about", response_class=HTMLResponse)
def about(request: Request):
    return templates.TemplateResponse(request, "about.html", {"caps": backend.caps_summary()})


@app.post("/api/hunt")
async def hunt(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        events = validate_events(body.get("events"))
        findings = backend.detect(events)
        saved = backend.save_derived(findings, expected_revision)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    except (TypeError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)
    return {"findings": saved, "raw_events_persisted": False}


@app.post("/api/investigations")
async def investigations(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        reject_raw_fields(body)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    unexpected = set(body).difference({"finding_id", "analyst", "expected_revision"})
    if unexpected:
        raise HTTPException(422, f"unsupported investigation fields: {sorted(unexpected)}")
    finding_id = body.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip() or len(finding_id) > 160:
        raise HTTPException(422, "finding_id is required")
    finding = backend.get_finding(finding_id)
    if finding is None:
        raise HTTPException(404, "stored finding not found")
    analyst = body.get("analyst", "unassigned")
    if not isinstance(analyst, str) or not analyst.strip():
        raise HTTPException(422, "analyst must be a non-empty string")
    investigation = backend.open_investigation(finding, analyst[:160])
    try:
        return backend.save_derived([investigation], expected_revision)[0]
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=409)


@app.get("/healthz")
def healthz():
    return {"ok": True, "product": "platform-threat-hunter"}
