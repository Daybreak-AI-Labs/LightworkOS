"""Local customer-facing Model Risk & AI Assurance Officer web app."""

from __future__ import annotations

from pathlib import Path

import backend
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from request_limits import (
    PayloadError,
    read_bounded_json,
    reject_sensitive_fields,
    require_expected_revision,
)
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(
    title="Lightwork Model Risk & AI Assurance Officer",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=["127.0.0.1", "localhost", "[::1]"],
)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@app.middleware("http")
async def browser_security_headers(request: Request, call_next):
    """Protect the local human-decision surface from remote content and framing."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; form-action 'self'; "
        "base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


async def _body(request: Request, allowed: set[str]) -> tuple[dict, int]:
    try:
        body = await read_bounded_json(request)
        reject_sensitive_fields(body)
        revision = require_expected_revision(body)
    except PayloadError as exc:
        raise HTTPException(exc.status_code, exc.detail) from exc
    unexpected = set(body).difference(allowed | {"expected_revision"})
    if unexpected:
        raise HTTPException(422, f"unsupported fields: {sorted(unexpected)}")
    return body, revision


def _result(call):
    try:
        return call()
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    records = backend.list_records()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "caps": backend.caps_summary(),
            "records": records[-30:],
            "revision": backend.current_revision(),
            "assessments": [row for row in records if row.get("type") == "assurance_assessment"],
            "readiness_reports": [
                row for row in records if row.get("type") == "dgm_readiness_report"
            ],
        },
    )


@app.get("/about", response_class=HTMLResponse)
def about(request: Request):
    return templates.TemplateResponse(request, "about.html", {"caps": backend.caps_summary()})


@app.get("/api/records")
def records():
    return {
        "revision": backend.current_revision(),
        "records": backend.list_records(),
        "authority": "unsigned-local-advisory-only",
    }


@app.get("/api/frameworks")
def frameworks():
    summary = backend.caps_summary()
    return {
        "frameworks": summary["framework_catalog"],
        "mapping_type": "versioned-advisory-metadata",
        "certification": False,
        "legal_verdict": False,
    }


@app.post("/api/assessments")
async def create_assessment(request: Request):
    body, revision = await _body(request, {"snapshot", "now", "freshness_days"})
    snapshot = body.get("snapshot")
    if not isinstance(snapshot, dict):
        raise HTTPException(422, "snapshot must be an object")
    return _result(
        lambda: backend.create_assessment(
            snapshot,
            revision,
            now=body.get("now"),
            freshness_days=body.get("freshness_days", 90),
        )
    )


@app.post("/api/assessments/{assessment_id}/review")
async def review_assessment(assessment_id: str, request: Request):
    body, revision = await _body(request, {"decision", "reviewer", "rationale", "decided_at"})
    return _result(
        lambda: backend.review_assessment(
            assessment_id,
            body.get("decision"),
            body.get("reviewer"),
            body.get("rationale"),
            body.get("decided_at"),
            revision,
        )
    )


@app.post("/api/assessments/{assessment_id}/risk-acceptances")
async def create_risk_acceptance(assessment_id: str, request: Request):
    body, revision = await _body(
        request,
        {
            "finding_id",
            "decision",
            "reviewer",
            "rationale",
            "expires_at",
            "decided_at",
        },
    )
    return _result(
        lambda: backend.create_risk_acceptance(
            assessment_id,
            body.get("finding_id"),
            body.get("decision"),
            body.get("reviewer"),
            body.get("rationale"),
            body.get("expires_at"),
            body.get("decided_at"),
            revision,
        )
    )


@app.post("/api/dgm/readiness-reports")
async def create_dgm_readiness_report(request: Request):
    body, revision = await _body(
        request,
        {
            "assessment_id",
            "target_asset_ref",
            "candidate_id",
            "candidate_version",
            "requested_by",
            "now",
        },
    )
    return _result(
        lambda: backend.create_dgm_readiness_report(
            body.get("assessment_id"),
            body.get("target_asset_ref"),
            body.get("candidate_id"),
            body.get("candidate_version"),
            body.get("requested_by"),
            body.get("now"),
            revision,
        )
    )


@app.get("/healthz")
def healthz():
    return {
        "ok": True,
        "product": "model-risk-ai-assurance-officer",
        "authority": "unsigned-local-advisory-only",
        "legal_applicability_default": "undetermined",
        "certification": False,
        "dgm_execution": False,
        "external_effects": False,
    }
