"""Environment threat-hunter standalone demo app."""
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
    validate_sigma_rules,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(title="Environment Threat Hunter")
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


@app.post("/api/ingest")
async def ingest(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        events = validate_events(backend.ingest(body["source_type"], body.get("payload", [])))
        sigma_rules = validate_sigma_rules(body.get("sigma_rules"))
        findings = backend.detect(events, sigma_rules)
        saved = backend.save_derived(findings, expected_revision)
    except KeyError as exc:
        raise HTTPException(422, "source_type is required") from exc
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    except (AttributeError, TypeError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)
    return {"accepted_events": len(events), "findings": saved, "raw_events_persisted": False}


@app.post("/api/investigations")
async def investigations(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        reject_raw_fields(body)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    unexpected = set(body).difference(
        {"finding_id", "related_finding_ids", "expected_revision"}
    )
    if unexpected:
        raise HTTPException(422, f"unsupported investigation fields: {sorted(unexpected)}")
    finding_id = body.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id.strip() or len(finding_id) > 160:
        raise HTTPException(422, "finding_id is required")
    finding = backend.get_finding(finding_id)
    if finding is None:
        raise HTTPException(404, "stored finding not found")
    related_ids = body.get("related_finding_ids", [])
    if not isinstance(related_ids, list) or len(related_ids) > 32 or not all(
        isinstance(item, str) and item.strip() and len(item) <= 160 for item in related_ids
    ):
        raise HTTPException(422, "related_finding_ids must contain at most 32 IDs")
    related = []
    for related_id in related_ids:
        item = backend.get_finding(related_id)
        if item is None:
            raise HTTPException(404, f"stored finding not found: {related_id}")
        related.append(item)
    record = backend.investigate(finding, related)
    try:
        return backend.save_derived([record], expected_revision)[0]
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=409)


@app.post("/api/responses/propose")
async def propose(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        reject_raw_fields(body)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    unexpected = set(body).difference(
        {"investigation_id", "action", "target", "expected_revision"}
    )
    if unexpected:
        raise HTTPException(422, f"unsupported response fields: {sorted(unexpected)}")
    investigation_id = body.get("investigation_id")
    if (
        not isinstance(investigation_id, str)
        or not investigation_id.strip()
        or len(investigation_id) > 160
    ):
        raise HTTPException(422, "investigation_id is required")
    investigation = backend.get_investigation(investigation_id)
    if investigation is None:
        raise HTTPException(404, "stored investigation not found")
    action = body.get("action")
    target = body.get("target")
    if not isinstance(action, str) or not action or len(action) > 80:
        raise HTTPException(422, "action must be a non-empty string")
    if not isinstance(target, str) or not target or len(target) > 500:
        raise HTTPException(422, "target must be a non-empty string")
    try:
        proposal = backend.propose_response(investigation, action, target)
        return backend.save_derived([proposal], expected_revision)[0]
    except ValueError as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "product": "environment-threat-hunter",
        "response_execution": False,
        "response_mode": "proposal-only",
    }
