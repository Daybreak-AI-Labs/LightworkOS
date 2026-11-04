"""Authenticated, store-free workbench for AI-entity task management."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, has_permission, require_permission

PAGE_PATH = "/ai-entity-tasks"
API_BASE = "/api/v1/ai-entity-tasks"
ASSET_PATH = "/static/lightwork-ai-entity-tasks.js"

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


def create_ai_entity_tasks_page_router(templates: Jinja2Templates) -> APIRouter:
    """Create the page router; rendering never opens task or inventory storage."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("AI-entity task workbench requires a Jinja template authority")

    router = APIRouter(tags=["ai-entity-task-workbench"])

    @router.get(PAGE_PATH, response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        from .module_activation import module_activation_enabled
        workspace_selected = _tenant_selected() is not False
        if any(
            key not in {"theme", "density", "font", "lang"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="task workbench unavailable")

        style_nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(
            request,
            "ai_entity_tasks.html",
            {
                "api_base": API_BASE,
                "page_path": PAGE_PATH,
                "csp_style_nonce": style_nonce,
                "task_workspace_missing": not workspace_selected,
                "task_can_operate": has_permission(request, "operate"),
                "task_can_audit": has_global_permission(request, "audit"),
                "task_can_admin": has_global_permission(request, "admin"),
                "task_module_enabled": module_activation_enabled("ai_entity_tasks"),
                "task_can_activate": has_global_permission(request, "admin"),
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
    "create_ai_entity_tasks_page_router",
]
