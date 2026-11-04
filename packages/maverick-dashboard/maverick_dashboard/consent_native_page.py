"""Authenticated operator page for the stock native-consent runtime."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, require_permission

PAGE_PATH = "/consent/native"
ADMIN_API_BASE = "/api/v1/consent/native"
PUBLIC_KEYS_BASE = "/api/v1/public/consent/native/receipt-keys"
ASSET_PATH = "/static/lightwork-consent-native-admin.js"

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
            detail="select an active tenant before managing native consent",
        )


def create_consent_native_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("native consent page requires a Jinja template authority")
    router = APIRouter(tags=["native-consent-workbench"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        _tenant_selected()
        if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
            raise HTTPException(
                status_code=404,
                detail="native consent workbench unavailable",
            )
        nonce = secrets.token_urlsafe(18)
        from .module_activation import module_activation_enabled

        response = templates.TemplateResponse(
            request,
            "consent_native_admin.html",
            {
                "page_path": PAGE_PATH,
                "admin_api_base": ADMIN_API_BASE,
                "public_keys_base": PUBLIC_KEYS_BASE,
                "csp_style_nonce": nonce,
                "native_can_audit": has_global_permission(request, "audit"),
                "native_can_admin": has_global_permission(request, "admin"),
                "native_module_enabled": module_activation_enabled(
                    "consent_preferences.native_sdk"
                ),
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
    "ADMIN_API_BASE",
    "ASSET_PATH",
    "PAGE_PATH",
    "PUBLIC_KEYS_BASE",
    "create_consent_native_page_router",
]
