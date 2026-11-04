"""Authenticated, store-free assessment-evidence proposal workbench."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, has_permission, require_permission

PAGE_PATH = "/assess/evidence-autopopulation"
API_BASE = "/api/v1/assessment-evidence-autopopulation"
SCRIPT_PATH = "/static/lightwork-assessment-evidence-autopopulation.js"
STYLE_PATH = "/static/lightwork-assessment-evidence-autopopulation.css"

_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src 'self'; manifest-src 'none'; media-src 'none'; "
        "object-src 'none'; script-src 'self'; style-src 'self'; "
        "worker-src 'none'"
    ),
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
        "serial=(), bluetooth=(), clipboard-read=(), clipboard-write=()"
    ),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
}


def assessment_evidence_copilot_context():
    """Return the closed server-owned Copilot context for registry integration."""

    from .copilot_context import CopilotPageContext

    return CopilotPageContext(
        path=PAGE_PATH,
        title="Suggested assessment answers",
        summary=(
            "Suggest questionnaire answers from evidence your team already approved; "
            "a person reviews them before any are added."
        ),
        capabilities=(
            "Generate questionnaire-bound proposals from exact released evidence analyses.",
            "Inspect confidence, eligibility, fact-level digest citations, and authority pins.",
            "Approve or reject an explicit answer subset, then invoke application separately.",
        ),
        boundaries=(
            "Proposal generation never changes an assessment answer or score.",
            "Adding answers fills only unanswered questions, re-checks the assessment is unchanged, and never overwrites an answer.",
            "Evidence-assisted answers remain subject to final assessment review and are not attestations, certifications, legal conclusions, or live provider acceptance.",
        ),
        next_steps=(
            "Confirm the proposal and AI Evidence Analysis compositions are ready.",
            "Choose an open assessment and approved evidence, then press Suggest answers.",
            "Have a different person review the suggestions before adding them.",
        ),
        suggested_questions=(
            "What does proposal eligibility mean?",
            "Why can this answer not be applied?",
            "Which authorities will be rechecked during apply?",
        ),
    )


def _tenant_selected() -> bool:
    """Whether a workspace is selected; every API call still requires one."""
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict() is not None


def create_assessment_evidence_autopopulation_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    """Create the page router; rendering opens no proposal/evidence store."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("assessment evidence workbench requires Jinja templates")
    router = APIRouter(tags=["assessment-evidence-autopopulation-workbench"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        workspace_selected = _tenant_selected() is not False
        if any(
            key not in {"theme", "density", "font", "lang"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="workbench unavailable")
        style_nonce = secrets.token_urlsafe(18)
        from .module_activation import module_activation_enabled

        response = templates.TemplateResponse(
            request,
            "assessment_evidence_autopopulation.html",
            {
                "api_base": API_BASE,
                "page_path": PAGE_PATH,
                "script_path": SCRIPT_PATH,
                "style_path": STYLE_PATH,
                "csp_style_nonce": style_nonce,
                "proposal_workspace_missing": not workspace_selected,
                "proposal_can_operate": has_permission(request, "operate"),
                "proposal_can_audit": has_global_permission(request, "audit"),
                "proposal_can_admin": has_global_permission(request, "admin"),
                "proposal_module_enabled": module_activation_enabled(
                    "assessment_evidence_autopopulation"
                ),
            },
        )
        for name, value in _HEADERS.items():
            if name == "Content-Security-Policy":
                value = value.replace(
                    "style-src 'self'",
                    f"style-src 'self' 'nonce-{style_nonce}'",
                )
            response.headers[name] = value
        return response

    return router


__all__ = [
    "API_BASE",
    "PAGE_PATH",
    "SCRIPT_PATH",
    "STYLE_PATH",
    "assessment_evidence_copilot_context",
    "create_assessment_evidence_autopopulation_page_router",
]
