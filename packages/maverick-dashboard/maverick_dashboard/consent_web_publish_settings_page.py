"""Authenticated, store-free workbench for governed website publish settings."""

from __future__ import annotations

import secrets

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .auth import has_permission, require_permission

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


def _default_sdk_version() -> str:
    """The banner code version this server ships, offered as the default."""
    import re

    try:
        from maverick import __version__
    except ImportError:  # pragma: no cover - kernel always exports it
        return "1.0.0"
    version = str(__version__)
    return version if re.fullmatch(r"\d{1,6}\.\d{1,6}\.\d{1,6}", version) else "1.0.0"


def _tenant_selected() -> None:
    from maverick.paths import current_tenant_id_strict

    if current_tenant_id_strict() is None:
        raise HTTPException(
            status_code=409,
            detail="select an active tenant before using web publish settings",
        )


def create_consent_web_publish_settings_page_router(
    templates: Jinja2Templates,
) -> APIRouter:
    """Create the liquid-glass page router without opening any authority."""

    if not isinstance(templates, Jinja2Templates):
        raise TypeError("web publish-settings workbench requires Jinja templates")
    router = APIRouter(tags=["consent-web-publish-settings-workbench"])

    @router.get(
        "/consent/publish-settings",
        response_class=HTMLResponse,
        include_in_schema=False,
    )
    async def workbench(request: Request) -> HTMLResponse:
        require_permission(request, "view")
        _tenant_selected()
        if any(
            key not in {"theme", "density", "font", "lang"}
            for key in request.query_params
        ):
            raise HTTPException(status_code=404, detail="workbench unavailable")
        style_nonce = secrets.token_urlsafe(18)
        response = templates.TemplateResponse(
            request,
            "consent_publish_settings.html",
            {
                "api_base": "/api/v1/consent/publish-settings",
                "csp_style_nonce": style_nonce,
                "publish_settings_can_admin": has_permission(request, "admin"),
                "publish_settings_can_audit": has_permission(request, "audit"),
                "module_off": _module_off('consent_preferences.publishing.web_settings'),
                "publish_settings_sdk_version": _default_sdk_version(),
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


__all__ = ["create_consent_web_publish_settings_page_router"]


def _module_off(section: str) -> bool:
    """Whether this feature's on/off switch chain is off, so the page shows
    the standard turned-off banner (with Turn on for administrators)."""
    try:
        from maverick.config import load_config

        from .module_activation import _module_switch_enabled
        return not _module_switch_enabled(load_config() or {}, section)
    except Exception:  # noqa: BLE001 -- the page's own status line still reports
        return False
