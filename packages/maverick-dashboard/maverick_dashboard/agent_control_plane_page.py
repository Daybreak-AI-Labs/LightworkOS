"""Authenticated operator page for the Agent Control Plane."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, has_permission, require_permission

PAGE_PATH = "/agent-control-plane"
API_BASE = "/api/v1/agent-control-plane"
ASSET_PATH = "/static/lightwork-agent-control-plane.js"

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


def _shared_halt_backend() -> bool:
    """Use the same deployment-scope decision as the hardened halt API."""

    from .halt_policy import shared_halt_backend

    return shared_halt_backend()


def _halt_authority(request: Request) -> tuple[bool, str]:
    """Return the exact halt authority and scope, failing closed on uncertainty."""

    try:
        if _shared_halt_backend():
            return has_global_permission(request, "admin"), "cluster"
        return has_global_permission(request, "operate"), "local"
    except Exception:
        return False, "unknown"


def _workspace_scope() -> tuple[bool, str]:
    """The active workspace a group action may target, or unknown (fail closed)."""

    try:
        from maverick.paths import current_tenant_id_strict

        return True, current_tenant_id_strict() or ""
    except Exception:
        return False, ""


def create_agent_control_plane_page_router(templates: Jinja2Templates) -> APIRouter:
    if not isinstance(templates, Jinja2Templates):
        raise TypeError("agent control plane page requires a Jinja template authority")
    router = APIRouter(tags=["agent-control-plane-console"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def console(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        if any(key not in {"theme", "density", "font", "lang"} for key in request.query_params):
            raise HTTPException(status_code=404, detail="agent control plane unavailable")
        nonce = secrets.token_urlsafe(18)
        acp_can_halt, acp_halt_scope = _halt_authority(request)
        acp_workspace_scope_known, acp_workspace_scope = _workspace_scope()
        response = templates.TemplateResponse(
            request,
            "agent_control_plane.html",
            {
                "api_base": API_BASE,
                "page_path": PAGE_PATH,
                "csp_style_nonce": nonce,
                "acp_can_operate": has_permission(request, "operate"),
                "acp_can_audit": has_permission(request, "audit"),
                "acp_can_admin": has_permission(request, "admin"),
                "acp_can_halt": acp_can_halt,
                "acp_halt_scope": acp_halt_scope,
                "acp_workspace_scope_known": acp_workspace_scope_known,
                "acp_workspace_scope": acp_workspace_scope,
            },
        )
        for name, value in _HEADERS.items():
            if name == "Content-Security-Policy":
                value = value.replace("style-src 'self'", f"style-src 'self' 'nonce-{nonce}'")
            response.headers[name] = value
        return response

    return router


__all__ = ["API_BASE", "ASSET_PATH", "PAGE_PATH", "create_agent_control_plane_page_router"]
