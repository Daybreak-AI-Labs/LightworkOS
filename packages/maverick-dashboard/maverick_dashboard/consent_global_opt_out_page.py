"""Authenticated, store-free Global Opt-Out administration page."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from maverick.paths import current_tenant_id_strict

from .auth import has_global_permission, require_global_permission

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


def create_consent_global_opt_out_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    """Create the page router without resolving or opening tenant authorities."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("Global Opt-Out workbench requires Jinja templates")
    router = APIRouter(tags=["consent-global-opt-out-workbench"])

    @router.get(
        "/consent/global-opt-out",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def workbench(request: Request) -> HTMLResponse:
        require_global_permission(request, "view")
        if current_tenant_id_strict() is None:
            raise HTTPException(
                status_code=409,
                detail="select an active tenant before using Global Opt-Out",
            )
        if any(
            key not in {"theme", "density", "font", "lang"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="workbench unavailable")
        response = templates.TemplateResponse(
            request,
            "consent_global_opt_out.html",
            {
                "api_base": "/api/v1/consent/global-opt-out",
                "global_opt_out_can_admin": has_global_permission(request, "admin"),
                "global_opt_out_can_audit": has_global_permission(request, "audit"),
                "module_off": _module_off('consent_preferences.global_opt_out'),
            },
        )
        for name, value in _HEADERS.items():
            response.headers[name] = value
        return response

    return router


__all__ = ["create_consent_global_opt_out_page_router"]


def _module_off(section: str) -> bool:
    """Whether this feature's on/off switch chain is off, so the page shows
    the standard turned-off banner (with Turn on for administrators)."""
    try:
        from maverick.config import load_config

        from .module_activation import _module_switch_enabled
        return not _module_switch_enabled(load_config() or {}, section)
    except Exception:  # noqa: BLE001 -- the page's own status line still reports
        return False
