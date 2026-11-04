"""Authenticated operator page for trust receipts (Audit → Trust Receipts)."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import require_permission

PAGE_PATH = "/audit/receipts"
API_BASE = "/api/v1/audit/receipts"
ASSET_PATH = "/static/lightwork-trust-receipts.js"

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


def create_trust_receipts_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("trust receipts page requires a Jinja template authority")
    router = APIRouter(tags=["trust-receipts-console"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def console(request: Request) -> HTMLResponse:
        # The whole surface is audit-gated, like /audit and the API it drives.
        require_permission(request, "audit")
        if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
            raise HTTPException(status_code=404, detail="trust receipts unavailable")
        nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(
            request,
            "trust_receipts.html",
            {"api_base": API_BASE, "page_path": PAGE_PATH, "csp_style_nonce": nonce},
        )
        for name, value in _HEADERS.items():
            if name == "Content-Security-Policy":
                value = value.replace("style-src 'self'", f"style-src 'self' 'nonce-{nonce}'")
            response.headers[name] = value
        return response

    return router


__all__ = ["API_BASE", "ASSET_PATH", "PAGE_PATH", "create_trust_receipts_page_router"]
