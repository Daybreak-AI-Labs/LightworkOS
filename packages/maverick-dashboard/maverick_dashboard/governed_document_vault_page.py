"""Authenticated, store-free page for governed document custody and delivery."""

from __future__ import annotations

import re
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
        "img-src 'self' blob:; manifest-src 'none'; media-src 'none'; "
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
    """Whether a workspace is selected; the API still refuses without one."""
    from maverick.paths import current_tenant_id_strict

    return current_tenant_id_strict() is not None


def create_governed_document_vault_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("document-vault workbench requires Jinja templates")
    router = APIRouter(tags=["administration-document-vault-workbench"])

    @router.get(
        "/administration/document-vault",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        from .module_activation import module_activation_enabled
        workspace_selected = _tenant_selected() is not False
        if any(
            key not in {"theme", "density", "font", "lang", "document"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="workbench unavailable")
        if "document" in request.query_params and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", request.query_params["document"]):
            raise HTTPException(status_code=404, detail="workbench unavailable")
        style_nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(
            request,
            "governed_document_vault.html",
            {
                "vault_api_base": "/api/v1/administration/document-vault",
                "access_api_base": "/api/v1/administration/document-access",
                "csp_style_nonce": style_nonce,
                "document_vault_can_admin": has_permission(request, "admin"),
                "document_vault_can_operate": has_permission(request, "operate"),
                "document_vault_can_audit": has_permission(request, "audit"),
                "document_vault_module_enabled": module_activation_enabled("governed_document_vault"),
                "document_vault_can_activate": has_global_permission(request, "admin"),
                "document_vault_workspace_missing": not workspace_selected,
            },
        )
        for name, value in _HEADERS.items():
            if name == "Content-Security-Policy":
                value = value.replace(
                    "style-src 'self'", f"style-src 'self' 'nonce-{style_nonce}'"
                )
            response.headers[name] = value
        return response

    return router


__all__ = ["create_governed_document_vault_page_router"]
