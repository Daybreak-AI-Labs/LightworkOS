"""Existing-dashboard page for one reviewed vendor onboarding workflow."""
from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from maverick.paths import current_tenant_id_strict
from maverick.vendor_onboarding import deployment_readiness

from .auth import caller_principal, require_permission
from .draft_api import context_for
from .local_owner import available as local_owner_setup_available


def create_vendor_onboarding_page_router(templates: Jinja2Templates) -> APIRouter:
    router = APIRouter()

    @router.get("/third-party/vendor-onboarding", response_class=HTMLResponse,
                include_in_schema=False)
    def workbench(request: Request):
        require_permission(request, "operate")
        if current_tenant_id_strict() is None:
            raise HTTPException(409, "select an active tenant before using vendor onboarding")
        nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(request, "vendor_onboarding.html", {
            "csp_style_nonce": nonce,
            "offline_demo": getattr(request.app.state, "vendor_onboarding_demo", False) is True,
            "deployment": deployment_readiness(),
            "connection_workspace_context": context_for(request),
            "vendor_named_signin": bool((caller_principal(request) or "").startswith("user:")),
            "vendor_local_owner_setup_available": local_owner_setup_available(request),
        })
        response.headers.update({
            "Cache-Control": "no-store, private",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": (
                "default-src 'self'; script-src 'self'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'none'"
            ),
        })
        return response

    return router
