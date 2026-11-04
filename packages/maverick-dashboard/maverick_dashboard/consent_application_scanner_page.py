"""Authenticated, store-free mobile and OTT/CTV manifest-analysis workbench."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from maverick.paths import current_tenant_id_strict

from .auth import has_permission, require_permission

_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
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


def _content_security_policy(style_nonce: str) -> str:
    return (
        "default-src 'none'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src 'self'; manifest-src 'none'; media-src 'none'; "
        "object-src 'none'; script-src 'self'; "
        f"style-src 'self' 'nonce-{style_nonce}'; worker-src 'none'"
    )


def create_consent_application_scanner_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("consent application-scanner workbench requires Jinja templates")
    router = APIRouter(tags=["consent-application-scanner-workbench"])

    @router.get(
        "/consent/application-scans",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def workbench(request: Request) -> HTMLResponse:
        # The workbench controls only the active tenant's records. Tenant role
        # resolution is intentionally authoritative, including local demotions.
        require_permission(request, "view")
        if current_tenant_id_strict() is None:
            raise HTTPException(
                status_code=409,
                detail="select an active tenant before using application scanning",
            )
        if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
            raise HTTPException(status_code=404, detail="workbench unavailable")
        style_nonce = secrets.token_urlsafe(24)
        from .module_activation import module_activation_enabled

        response = templates.TemplateResponse(
            request,
            "consent_application_scanner.html",
            {
                "api_base": "/api/v1/consent/application-scans",
                "application_scanner_can_admin": has_permission(request, "admin"),
                "application_scanner_can_audit": has_permission(request, "audit"),
                "application_scanner_enabled": module_activation_enabled(
                    "consent_preferences.application_scanner"
                ),
                "csp_style_nonce": style_nonce,
            },
        )
        for name, value in _HEADERS.items():
            response.headers[name] = value
        response.headers["Content-Security-Policy"] = _content_security_policy(style_nonce)
        return response

    return router


__all__ = ["create_consent_application_scanner_page_router"]
