"""Authenticated, store-free operator workbench for AI evidence analysis."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, has_permission, require_permission

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


def _tenant_selected() -> bool:
    """Whether a workspace is selected; every API call still requires one."""
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict() is not None


def create_ai_evidence_analysis_page_router(templates: Jinja2Templates) -> APIRouter:
    """Create the standalone page router; rendering performs no store access."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("AI evidence workbench requires a Jinja template authority")

    router = APIRouter(tags=["ai-evidence-analysis-workbench"])

    @router.get(
        "/ai-evidence-analysis",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
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
            "ai_evidence_analysis.html",
            {
                "api_base": "/api/v1/ai-evidence-analysis",
                "csp_style_nonce": style_nonce,
                "evidence_workspace_missing": not workspace_selected,
                "evidence_can_operate": has_permission(request, "operate"),
                "evidence_can_audit": has_permission(request, "audit"),
                "evidence_can_admin": has_permission(request, "admin"),
                "evidence_can_activate": has_global_permission(request, "admin"),
                "evidence_module_enabled": module_activation_enabled(
                    "ai_evidence_analysis"
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


__all__ = ["create_ai_evidence_analysis_page_router"]
