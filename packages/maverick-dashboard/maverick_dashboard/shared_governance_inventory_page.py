"""Authenticated operator page for the shared six-suite governance inventory."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_permission, require_permission

PAGE_PATH = "/governance/inventory"
API_BASE = "/api/v1/governance/inventory"
ASSET_PATH = "/static/lightwork-shared-governance-inventory.js"

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
            detail="select an active tenant before using governance inventory",
        )


def create_shared_governance_inventory_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("governance inventory page requires a Jinja template authority")
    router = APIRouter(tags=["shared-governance-inventory-workbench"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        _tenant_selected()
        if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
            raise HTTPException(
                status_code=404,
                detail="governance inventory workbench unavailable",
            )
        nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(
            request,
            "shared_governance_inventory.html",
            {
                "api_base": API_BASE,
                "page_path": PAGE_PATH,
                "csp_style_nonce": nonce,
                "inventory_can_operate": has_permission(request, "operate"),
                "inventory_can_audit": has_permission(request, "audit"),
                "inventory_can_admin": has_permission(request, "admin"),
            },
        )
        for name, value in _HEADERS.items():
            if name == "Content-Security-Policy":
                value = value.replace(
                    "style-src 'self'",
                    f"style-src 'self' 'nonce-{nonce}'",
                )
            response.headers[name] = value
        return response

    return router


__all__ = [
    "API_BASE",
    "ASSET_PATH",
    "PAGE_PATH",
    "create_shared_governance_inventory_page_router",
]
