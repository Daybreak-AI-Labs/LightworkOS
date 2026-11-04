"""Authenticated operator page for California DROP request management."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_global_permission, has_permission, require_permission


def _tenant_selected() -> None:
    from maverick.paths import current_tenant_id_strict

    if current_tenant_id_strict() is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using DROP management",
        )


def create_privacy_drop_management_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    """Create the store-free DROP page; all operations use the strict API."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("DROP workbench requires a Jinja template authority")
    router = APIRouter(tags=["privacy-drop-management-workbench"])

    @router.get("/privacy/drop", response_class=HTMLResponse, include_in_schema=False)
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        _tenant_selected()
        if any(
            key not in {"theme", "density", "font", "lang"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="DROP workbench unavailable")
        response = templates.TemplateResponse(
            request,
            "privacy_drop_management.html",
            {
                "api_base": "/api/v1/privacy/drop",
                "drop_can_operate": has_permission(request, "operate"),
                "drop_can_audit": has_global_permission(request, "audit"),
                "drop_can_admin": has_global_permission(request, "admin"),
            },
        )
        response.headers["Cache-Control"] = "no-store, private, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Robots-Tag"] = "noindex, nofollow, noarchive"
        return response

    return router


__all__ = ["create_privacy_drop_management_page_router"]
