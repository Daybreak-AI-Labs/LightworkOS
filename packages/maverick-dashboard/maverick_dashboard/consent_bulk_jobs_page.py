"""Authenticated, store-free consent bulk-job operator workbench."""

from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, require_permission

PAGE_PATH = "/consent/bulk-jobs"
API_BASE = "/api/v1/consent/bulk-jobs"
ASSET_PATH = "/static/lightwork-consent-bulk-jobs.js"

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


def _tenant_selected() -> None:
    from maverick.paths import current_tenant_id_strict

    if current_tenant_id_strict() is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using consent bulk jobs",
        )


def create_consent_bulk_jobs_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    """Create the page router; rendering never opens or seeds the job store."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("consent bulk-job workbench requires a template authority")
    router = APIRouter(tags=["consent-bulk-jobs-workbench"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        _tenant_selected()
        if any(
            key not in {"theme", "density", "font", "lang", "job"}
            for key in request.query_params
        ):
            raise HTTPException(
                status_code=404,
                detail="consent bulk-job workbench unavailable",
            )
        selected = request.query_params.get("job")
        if selected is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", selected):
            raise HTTPException(404, "The saved consent job is unavailable.")
        style_nonce = secrets.token_urlsafe(18)
        from .draft_api import context_for
        from .module_activation import module_activation_enabled

        response = templates.TemplateResponse(
            request,
            "consent_bulk_jobs.html",
            {
                "api_base": API_BASE,
                "page_path": PAGE_PATH,
                "request_context": context_for(request),
                "csp_style_nonce": style_nonce,
                "bulk_jobs_can_audit": has_global_permission(request, "audit"),
                "bulk_jobs_can_admin": has_global_permission(request, "admin"),
                "bulk_jobs_enabled": module_activation_enabled("consent_preferences.bulk_jobs"),
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
    "ASSET_PATH",
    "PAGE_PATH",
    "create_consent_bulk_jobs_page_router",
]
