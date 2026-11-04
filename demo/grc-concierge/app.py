"""Small customer-facing GRC Concierge web app."""
from __future__ import annotations

from pathlib import Path

import backend
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from request_limits import PayloadError, read_bounded_json, require_expected_revision
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(title="GRC Concierge")
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


def _framework_payload(framework_id: str) -> dict:
    item = backend.get_framework(framework_id)
    return {
        **item,
        "controls": [
            control.__dict__ if hasattr(control, "__dict__") else control
            for control in item["controls"]
        ],
    }


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    frameworks = backend.list_frameworks()
    records = backend.list_records()
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "frameworks": frameworks,
            "framework_details": [
                _framework_payload(item["id"]) for item in frameworks
            ],
            "records": records[-20:],
            "vendor_records": [
                row for row in records if row.get("type") == "vendor_assessment"
            ][-20:],
            "pending_handoffs": [
                row
                for row in records
                if row.get("type") == "mock_handoff_receipt"
                and row.get("status") == "pending_human_review"
            ],
            "speed_story": backend.speed_story(),
            "caps": backend.caps_summary(),
            "revision": backend.current_revision(),
        },
    )


@app.get("/about", response_class=HTMLResponse)
def about(request: Request):
    return templates.TemplateResponse(request, "about.html", {"caps": backend.caps_summary()})


@app.get("/api/frameworks")
def frameworks():
    return backend.list_frameworks()


@app.get("/api/frameworks/{framework}")
def framework(framework: str):
    try:
        return _framework_payload(framework)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


@app.post("/api/assessments")
async def assess(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        unexpected = set(body).difference(
            {"framework", "answers", "subject", "expected_revision"}
        )
        if unexpected:
            raise ValueError(f"unsupported assessment fields: {sorted(unexpected)}")
        result = backend.score_questionnaire(body["framework"], body.get("answers", {}), body.get("subject", ""))
        return backend.save_record(result, expected_revision)
    except (KeyError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.post("/api/evidence")
async def evidence(request: Request):
    body = await _body(request)
    try:
        unexpected = set(body).difference({"framework", "text", "source"})
        if unexpected:
            raise ValueError(f"unsupported evidence fields: {sorted(unexpected)}")
        verdicts = backend.evaluate_evidence(body["framework"], body.get("text", ""), body.get("source", "pasted evidence"))
        return {"verdicts": verdicts, "warning": "Standalone extraction is untrusted and requires human review."}
    except (KeyError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc


@app.post("/api/risks")
async def risks(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        unexpected = set(body).difference(
            {"title", "likelihood", "impact", "owner", "treatment", "expected_revision"}
        )
        if unexpected:
            raise ValueError(f"unsupported risk fields: {sorted(unexpected)}")
        record = backend.create_risk(body["title"], body["likelihood"], body["impact"], body["owner"], body["treatment"])
        return backend.save_record(record, expected_revision)
    except (KeyError, TypeError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.post("/api/poam")
async def poam(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        unexpected = set(body).difference(
            {"finding", "owner", "due_date", "milestone", "expected_revision"}
        )
        if unexpected:
            raise ValueError(f"unsupported POA&M fields: {sorted(unexpected)}")
        record = backend.create_poam(body["finding"], body["owner"], body["due_date"], body["milestone"])
        return backend.save_record(record, expected_revision)
    except (KeyError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.get("/api/vendors")
def vendors():
    return backend.list_records("vendor_assessment")


@app.post("/api/vendors")
async def vendor_assessment(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        unexpected = set(body).difference(
            {"vendor", "owner", "answers", "carry_forward_from", "expected_revision"}
        )
        if unexpected:
            raise ValueError(f"unsupported vendor fields: {sorted(unexpected)}")
        previous = None
        previous_id = body.get("carry_forward_from")
        if previous_id is not None:
            if (
                not isinstance(previous_id, str)
                or not previous_id.strip()
                or len(previous_id) > 160
            ):
                raise ValueError("carry_forward_from must be a non-empty record id")
            previous = backend.get_record(previous_id)
            if previous is None:
                raise KeyError("stored carry-forward source not found")
        record = backend.create_vendor_assessment(
            body["vendor"], body["owner"], body.get("answers", {}), previous
        )
        return backend.save_record(record, expected_revision)
    except KeyError as exc:
        detail = str(exc).strip("'")
        status = 404 if "not found" in detail else 422
        raise HTTPException(status, detail) from exc
    except (TypeError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.post("/api/handoffs/mock")
async def mock_handoff(request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        unexpected = set(body).difference(
            {"record_id", "destination", "prepared_by", "note", "expected_revision"}
        )
        if unexpected:
            raise ValueError(f"unsupported mock handoff fields: {sorted(unexpected)}")
        record_id = body["record_id"]
        if not isinstance(record_id, str) or not record_id.strip() or len(record_id) > 160:
            raise ValueError("record_id must be a non-empty string")
        record = backend.get_record(record_id)
        if record is None:
            raise KeyError("stored source record not found")
        receipt = backend.create_mock_handoff(
            record,
            body["destination"],
            body["prepared_by"],
            body.get("note", ""),
        )
        saved = backend.save_record(receipt, expected_revision)
        return {
            "receipt": saved,
            "speed_story": backend.speed_story(),
            "warning": (
                "Mock receipt only: no network delivery or approval occurred. "
                "It is now pending in this app's local mock tenant review queue."
            ),
        }
    except KeyError as exc:
        detail = str(exc).strip("'")
        status = 404 if "not found" in detail else 422
        raise HTTPException(status, detail) from exc
    except (TypeError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.get("/api/handoffs/mock/queue")
def mock_review_queue():
    receipts = backend.list_records("mock_handoff_receipt")
    return {
        "pending": [
            row for row in receipts if row.get("status") == "pending_human_review"
        ],
        "reviewed": [
            row for row in receipts if row.get("status") != "pending_human_review"
        ],
        "speed_story": backend.speed_story(),
        "warning": "Local mock tenant state only; no external GRC system is connected.",
    }


@app.post("/api/handoffs/mock/{receipt_id}/decision")
async def decide_mock_handoff(receipt_id: str, request: Request):
    body = await _body(request)
    expected_revision = _expected_revision(body)
    try:
        unexpected = set(body).difference(
            {"decision", "reviewer", "rationale", "expected_revision"}
        )
        if unexpected:
            raise ValueError(f"unsupported review fields: {sorted(unexpected)}")
        if not receipt_id or len(receipt_id) > 160:
            raise ValueError("receipt_id must be a non-empty record id")
        receipt = backend.get_record(receipt_id)
        if receipt is None:
            raise KeyError("stored mock handoff receipt not found")
        decision = backend.decide_mock_handoff(
            receipt,
            body["decision"],
            body["reviewer"],
            body.get("rationale", ""),
        )
        saved = backend.replace_record(receipt_id, decision, expected_revision)
        return {
            "receipt": saved,
            "speed_story": backend.speed_story(),
            "warning": (
                "Local mock decision only: it did not approve, reject, or deliver "
                "anything in the named external GRC product."
            ),
        }
    except KeyError as exc:
        detail = str(exc).strip("'")
        status = 404 if "not found" in detail else 422
        raise HTTPException(status, detail) from exc
    except (TypeError, ValueError) as exc:
        status = 409 if "revision changed" in str(exc) else 422
        return JSONResponse({"detail": str(exc)}, status_code=status)


@app.get("/healthz")
def healthz():
    return {"ok": True, "product": "grc-concierge"}
