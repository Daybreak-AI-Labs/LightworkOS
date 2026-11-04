"""Authenticated, store-free executive-report workbench page."""

from __future__ import annotations

import re
import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import (
    _dashboard_token_authenticated,
    has_global_permission,
    has_permission,
    require_permission,
)

PAGE_PATH = "/third-party/executive-reports"
API_BASE = "/api/v1/third-party/executive-reports"
ASSET_PATH = "/static/lightwork-third-party-executive-reports.js"

_HEADERS = {
    "Cache-Control": "no-store, private, max-age=0",
    "Pragma": "no-cache",
    "Content-Security-Policy": (
        "default-src 'none'; base-uri 'none'; connect-src 'self'; "
        "font-src 'self'; form-action 'none'; frame-ancestors 'none'; "
        "img-src 'self'; manifest-src 'none'; media-src 'none'; "
        "object-src 'none'; script-src 'self'; style-src 'self'; worker-src 'none'"
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
            detail="select an active tenant before using executive reports",
        )


def _report_has_permission(request: Request, permission: str) -> bool:
    if _dashboard_token_authenticated(request):
        return permission in {"operate", "view"}
    return has_permission(request, permission)


def create_third_party_executive_reports_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("executive reports require a Jinja template authority")
    router = APIRouter(tags=["third-party-executive-report-workbench"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        _tenant_selected()
        if any(
            key not in {"theme", "density", "font", "lang", "report"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="executive report workbench unavailable")
        if "report" in request.query_params and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", request.query_params["report"]):
            raise HTTPException(status_code=404, detail="executive report workbench unavailable")
        style_nonce = secrets.token_urlsafe(18)
        from .module_activation import module_activation_enabled

        response = templates.TemplateResponse(
            request,
            "third_party_executive_reports.html",
            {
                "api_base": API_BASE,
                "page_path": PAGE_PATH,
                "csp_style_nonce": style_nonce,
                "reports_can_create": (
                    _report_has_permission(request, "operate")
                    or _report_has_permission(request, "audit")
                ),
                "reports_can_audit": _report_has_permission(request, "audit"),
                "reports_can_admin": _report_has_permission(request, "admin"),
                "reports_can_download": _report_has_permission(request, "view"),
                "reports_can_activate": has_global_permission(request, "admin"),
                "reports_module_enabled": module_activation_enabled(
                    "third_party_management.executive_reports"
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
    "ASSET_PATH",
    "PAGE_PATH",
    "create_third_party_executive_reports_page_router",
]
