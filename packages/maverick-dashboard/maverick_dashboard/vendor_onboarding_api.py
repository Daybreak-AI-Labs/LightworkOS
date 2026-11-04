"""Transport validation for the tenant-private vendor onboarding service."""
from __future__ import annotations

import base64
import binascii
import hmac
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from maverick.governed_operations import ActionReviewRequiredError, ApprovalBindingError
from maverick.governed_records import RecordConflict
from maverick.outcome_pilot_start_gate import OutcomePilotAdmissionRequired
from maverick.platform_contracts import PlatformContractError
from maverick.vendor_onboarding import (
    VendorOnboardingContractError,
    VendorOnboardingDeploymentError,
    VendorOnboardingEvidenceReviewRequired,
    VendorOnboardingIdempotencyConflict,
    deployment_readiness,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from .auth import require_api_key_scope, require_permission
from .draft_api import context_for

router = APIRouter(prefix="/vendor-onboarding", tags=["vendor-onboarding"])

# The execute route must let the domain service observe a changed caller role
# before the ordinary HTTP permission gate rejects the request.  The marker is
# scoped to binding construction; every service authorization callback runs
# after it has been cleared.
_EXECUTION_REVALIDATION_STATE = "_lightwork_vendor_execution_revalidation"


class ClosedBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, allow_inf_nan=False)


class IntakeBody(ClosedBody):
    submission_key: str | None = Field(
        default=None,
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]+$",
    )
    vendor_name: str = Field(min_length=1, max_length=200)
    document_id: str = Field(default="", max_length=256)
    document_ids: list[str] | None = Field(default=None, max_length=8)
    project: str = Field(min_length=1, max_length=32)
    purpose: str = Field(min_length=1, max_length=2000)
    freshness_days: int = Field(default=365, ge=1, le=730)
    due_at: float | None = Field(default=None, gt=0)
    renewal_of: str | None = Field(default=None, max_length=128)


class RevisionBody(ClosedBody):
    expected_revision: int = Field(ge=1)


class DocumentsBody(RevisionBody):
    document_ids: list[str] = Field(max_length=8)
    upload_ids: list[str] = Field(default_factory=list, max_length=8)


class DraftBody(RevisionBody):
    project: str = Field(min_length=1, max_length=32, pattern=r"^[A-Z][A-Z0-9_]{1,31}$")
    purpose: str = Field(min_length=1, max_length=2000)
    freshness_days: int = Field(ge=1, le=730)
    due_at: float | None = Field(default=None, gt=0)


class UploadPreviewBody(RevisionBody):
    name: str = Field(min_length=1, max_length=256)
    mime: str = Field(min_length=1, max_length=255)
    document_date: float = Field(gt=0)
    content_base64: str = Field(min_length=1, max_length=22_369_624)
    transcription: str | None = Field(default=None, max_length=120_000)
    expires_at: float | None = None
    review_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    confirm: Literal[True] | None = None


class CorrectionBody(ClosedBody):
    answer: Literal["yes", "no", "na", "unknown"]
    note: str = Field(default="", max_length=2000)


class ReviewBody(RevisionBody):
    decision: Literal["approved", "rejected"]
    rationale: str = Field(min_length=1, max_length=4000)
    corrections: dict[str, CorrectionBody] | None = None
    review_seconds: float | None = Field(default=None, ge=0, le=86400)


class ApprovalBody(RevisionBody):
    confirm: Literal[True]
    approval_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ConfirmationBody(RevisionBody):
    confirm: Literal[True]


class AcceptanceBody(RevisionBody):
    accepted: bool
    rationale: str = Field(min_length=1, max_length=4000)


class CancellationBody(ConfirmationBody):
    rationale: str = Field(min_length=1, max_length=4000)


class EvidenceExportDownloadBody(ConfirmationBody):
    expected_export_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


def _error(status, code, message, *, retryable=False, next_action, current=None):
    detail = {
        "schema": "lightwork.error.v1", "code": code, "message": message,
        "retryable": retryable, "next_action": next_action,
    }
    if current is not None:
        detail["current"] = current
    return HTTPException(status, detail)


def _binding(request: Request, *, revalidate_execution_authority=False):
    if not revalidate_execution_authority:
        require_permission(request, "operate")
    supplied_context = request.headers.get("X-Lightwork-Vendor-Context")
    if supplied_context is not None and (len(supplied_context) != 64 or
            any(char not in "0123456789abcdef" for char in supplied_context) or
            not hmac.compare_digest(supplied_context, context_for(request))):
        raise _error(409, "workspace_context_changed", "The workspace or signed-in account changed.",
                     next_action="Reload this page in the original workspace before reading or changing the request.")
    profile = deployment_readiness()
    if not profile["supported"]:
        raise _error(409, profile["code"], profile["message"], next_action=profile["next_action"])
    factory = getattr(request.app.state, "vendor_onboarding_binding_factory", None)
    if not callable(factory):
        raise _error(503, "composition_unavailable", "Vendor onboarding is unavailable for this workspace.",
                     retryable=True, next_action="Refresh setup, then try again.")
    state = request.state
    if revalidate_execution_authority:
        setattr(state, _EXECUTION_REVALIDATION_STATE, True)
    try:
        return factory(request)
    except HTTPException:
        raise
    except (PermissionError, ValueError) as exc:
        raise _error(403 if isinstance(exc, PermissionError) else 409,
                     "permission_denied" if isinstance(exc, PermissionError) else "workspace_binding_rejected",
                     str(exc), next_action="Review workspace access and saved connections.") from exc
    except Exception as exc:
        raise _error(503, "authority_unavailable", "Vendor onboarding authority is unavailable.",
                     retryable=True, next_action="Refresh setup before retrying.") from exc
    finally:
        if revalidate_execution_authority:
            setattr(state, _EXECUTION_REVALIDATION_STATE, False)


def _safe_current(binding, case_id):
    """Project the current authorized row without returning evidence or provider data."""
    try:
        row = binding.service.get(binding.context, case_id)
    except Exception:
        return None
    work = row.get("work_item") or {}
    return {
        "schema": "lightwork.vendor-onboarding.conflict-current.v1",
        "id": row["id"],
        "revision": row["revision"],
        "stage": row["stage"],
        "updated_at": row.get("updated_at"),
        "vendor_name": row["vendor_name"],
        "work_item": {
            "lifecycle": work.get("lifecycle"),
            "next_action": work.get("next_action"),
            "technical_effect": work.get("technical_effect"),
            "business_outcome": work.get("business_outcome"),
        },
    }


def _call(binding, operation: str, *args, **kwargs):
    try:
        return getattr(binding.service, operation)(binding.context, *args, **kwargs)
    except HTTPException:
        raise
    except VendorOnboardingDeploymentError as exc:
        raise _error(409, exc.code, str(exc), next_action=exc.next_action) from exc
    except VendorOnboardingEvidenceReviewRequired as exc:
        raise _error(
            409,
            exc.code,
            str(exc),
            current=_safe_current(binding, exc.case_id),
            next_action="Open the changed evidence shown in the app and start a reevaluation request.",
        ) from exc
    except (ActionReviewRequiredError, ApprovalBindingError) as exc:
        raise _error(
            409,
            exc.code,
            str(exc),
            next_action="Reload the case, prepare the current action, and review it again.",
        ) from exc
    except PermissionError as exc:
        raise _error(403, "permission_denied", str(exc),
                     next_action="Ask a workspace administrator to review your role and connection access.") from exc
    except KeyError as exc:
        raise _error(404, "record_not_found", "Vendor case or referenced record was not found.",
                     next_action="Refresh requests and select an accessible case.") from exc
    except VendorOnboardingContractError as exc:
        raise _error(409, exc.code, str(exc),
                     next_action="Do not retry this change; update or repair the case contract first.") from exc
    except PlatformContractError as exc:
        raise _error(409, exc.code, str(exc),
                     next_action="Reload this case; repair its incompatible work record before continuing.") from exc
    except VendorOnboardingIdempotencyConflict as exc:
        raise _error(
            409,
            "idempotency_conflict",
            str(exc),
            current=_safe_current(binding, exc.case_id),
            next_action="Open the current request or submit the changed request with a new submission key.",
        ) from exc
    except OutcomePilotAdmissionRequired as exc:
        raise _error(
            409,
            exc.code,
            str(exc),
            current=_safe_current(binding, args[0]) if args else None,
            retryable=True,
            next_action="Open the outcome pilot in the app and retry its admission recovery before collecting evidence.",
        ) from exc
    except RecordConflict as exc:
        raise _error(409, "revision_conflict", str(exc),
                     next_action="Reload the current case, review changes, and submit again.") from exc
    except ValueError as exc:
        raise _error(409, "workflow_rejected", str(exc),
                     next_action="Review the current case state and correct the requested action.") from exc
    except Exception as exc:
        # Never expose provider payloads, credential values or storage paths.
        raise _error(503, "operation_unavailable", "Operation unavailable; reload case status before retrying.",
                     retryable=True, next_action="Reload case status before deciding whether to retry.") from exc


def _call_case(binding, operation, case_id, *args, **kwargs):
    try:
        return _call(binding, operation, case_id, *args, **kwargs)
    except HTTPException as exc:
        detail = exc.detail
        if (exc.status_code == 409 and isinstance(detail, dict)
                and detail.get("code") == "revision_conflict"):
            raise _error(
                409,
                "revision_conflict",
                str(detail.get("message") or "Vendor onboarding case revision changed"),
                current=_safe_current(binding, case_id),
                next_action="Reload or review the current case shown in the app, then submit the change again.",
            ) from exc
        raise


def _revision_conflict(binding, case_id, message, next_action):
    raise _error(
        409,
        "revision_conflict",
        message,
        current=_safe_current(binding, case_id),
        next_action=next_action,
    )


@router.get("/cases")
def cases(
    request: Request,
    limit: int = Query(default=25, ge=1, le=100),
    cursor: str = Query(default="", max_length=768),
    view: Literal["all", "active", "unresolved", "renewal", "closed"] = "all",
):
    return _call(
        _binding(request), "list_page", limit=limit, cursor=cursor, view=view,
    )


@router.get("/documents")
def search_documents(request: Request, query: str = Query(min_length=1, max_length=200)):
    return _call(_binding(request), "search_documents", query)


@router.post("/cases", status_code=201)
def intake(request: Request, body: IntakeBody):
    return _call(_binding(request), "intake", **body.model_dump())


@router.get("/cases/{case_id}")
def case(request: Request, case_id: str):
    return _call(_binding(request), "get", case_id)


@router.post("/cases/{case_id}/documents")
def set_documents(request: Request, case_id: str, body: DocumentsBody):
    return _call_case(_binding(request), "set_documents", case_id, **body.model_dump())


@router.post("/cases/{case_id}/draft")
def update_draft(request: Request, case_id: str, body: DraftBody):
    return _call_case(_binding(request), "update_draft", case_id, **body.model_dump())


@router.post("/cases/{case_id}/upload")
async def upload_document(request: Request, case_id: str,
                          expected_revision: int = Query(ge=1), name: str = Query(min_length=1, max_length=256),
                          document_date: float = Query(gt=0)):
    from maverick.vendor_onboarding_adapters import MAX_PDF_BYTES, MAX_TEXT_BYTES

    binding = _binding(request)
    mime = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if mime not in {"text/plain", "application/pdf"}:
        raise _error(415, "unsupported_media_type",
                     "Upload a UTF-8 text file or a supported digital PDF.",
                     next_action="Choose a plain-text or digital PDF evidence file.")
    limit = MAX_PDF_BYTES if mime == "application/pdf" else MAX_TEXT_BYTES
    chunks, length = [], 0
    async for chunk in request.stream():
        length += len(chunk)
        if length > limit:
            raise _error(413, "upload_too_large", "Document exceeds the supported upload size.",
                         next_action="Choose a smaller evidence file and upload it again.")
        chunks.append(chunk)
    return await run_in_threadpool(_call_case, binding, "upload_document", case_id, expected_revision,
                                   content=b"".join(chunks), name=name, mime=mime, document_date=document_date)


@router.post("/cases/{case_id}/review")
def review(request: Request, case_id: str, body: ReviewBody):
    require_api_key_scope(request, "approvals:decide")
    return _call_case(_binding(request), "review", case_id, **body.model_dump())


async def _reviewed_upload(request, case_id, *, save):
    binding = _binding(request)
    chunks, length = [], 0
    async for chunk in request.stream():
        length += len(chunk)
        if length > 23 * 1024 * 1024:
            raise _error(413, "upload_too_large", "Evidence upload exceeds the supported size.",
                         next_action="Choose a smaller evidence file and review it again.")
        chunks.append(chunk)
    try:
        body = UploadPreviewBody.model_validate_json(b"".join(chunks))
        content = base64.b64decode(body.content_base64, validate=True)
    except (ValidationError, ValueError, binascii.Error) as exc:
        # Validation errors must not echo document bytes or supplied transcription.
        raise _error(422, "invalid_upload_review",
                     "Check the selected file, document date and evidence review fields.",
                     next_action="Correct the highlighted evidence fields and review the file again.") from exc
    arguments = body.model_dump(exclude={"content_base64", "expected_revision", "confirm", "review_digest"})
    if save:
        arguments.update(confirm=body.confirm, review_digest=body.review_digest)
    result = await run_in_threadpool(_call_case, binding, "upload_reviewed" if save else "preview_upload",
                                    case_id, body.expected_revision, content=content, **arguments)
    return JSONResponse(result, headers={"Cache-Control": "no-store"})


@router.post("/cases/{case_id}/upload-preview")
async def preview_upload(request: Request, case_id: str):
    return await _reviewed_upload(request, case_id, save=False)


@router.post("/cases/{case_id}/upload-reviewed")
async def save_reviewed_upload(request: Request, case_id: str):
    return await _reviewed_upload(request, case_id, save=True)


@router.post("/cases/{case_id}/approve-action")
def approve(request: Request, case_id: str, body: ApprovalBody):
    from .approval_authority import require_approval_authority

    require_approval_authority(
        request, action="vendor_onboarding.action.approve", resource=case_id,
    )
    return _call_case(_binding(request), "approve_action", case_id,
                      expected_revision=body.expected_revision,
                      approval_binding_sha256=body.approval_binding_sha256)


@router.post("/cases/{case_id}/execute")
def execute(request: Request, case_id: str, body: ConfirmationBody):
    binding = _binding(request, revalidate_execution_authority=True)
    return _call_case(
        binding, "execute", case_id, expected_revision=body.expected_revision,
    )


@router.post("/cases/{case_id}/reconcile")
def reconcile(request: Request, case_id: str, body: ConfirmationBody):
    return _call_case(_binding(request), "reconcile", case_id)


@router.post("/cases/{case_id}/accept")
def accept(request: Request, case_id: str, body: AcceptanceBody):
    return _call_case(_binding(request), "accept", case_id, **body.model_dump())


@router.post("/cases/{case_id}/evidence-export-preview")
def preview_evidence_export(request: Request, case_id: str, body: RevisionBody):
    result = _call_case(
        _binding(request), "preview_evidence_export", case_id, body.expected_revision,
    )
    return JSONResponse(result, headers={
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })


@router.post("/cases/{case_id}/evidence-export")
def download_evidence_export(request: Request, case_id: str,
                             body: EvidenceExportDownloadBody):
    result = _call_case(
        _binding(request),
        "download_evidence_export",
        case_id,
        body.expected_revision,
        confirm=body.confirm,
        expected_export_sha256=body.expected_export_sha256,
    )
    return JSONResponse(result, media_type="application/json", headers={
        "Cache-Control": "no-store",
        "Content-Disposition": f'attachment; filename="lightwork-evidence-{result["case"]["id"]}.json"',
        "X-Content-Type-Options": "nosniff",
    })


@router.post("/cases/{case_id}/cancel")
def cancel(request: Request, case_id: str, body: CancellationBody):
    return _call_case(
        _binding(request), "cancel", case_id,
        **body.model_dump(exclude={"confirm"}),
    )


@router.post("/cases/{case_id}/check-renewal")
def check_renewal(request: Request, case_id: str, body: RevisionBody):
    binding = _binding(request)
    current = _call(binding, "get", case_id)
    if current["revision"] != body.expected_revision:
        _revision_conflict(
            binding, case_id, "Case changed before the renewal check.",
            "Review the current case shown in the app before checking renewal.",
        )
    return _call(binding, "check_renewal", case_id)


@router.post("/cases/{case_id}/{step}")
def step(request: Request, case_id: str,
         step: Literal["collect-evidence", "assess", "prepare-action"], body: RevisionBody):
    return _call_case(
        _binding(request), step.replace("-", "_"), case_id,
        expected_revision=body.expected_revision,
    )
