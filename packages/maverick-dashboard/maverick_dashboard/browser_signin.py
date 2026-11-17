"""Send a signed-out browser page load to sign-in; API clients keep the 401.

A browser that opened a page without a session got the raw JSON
``{"detail": "OIDC bearer token required"}`` when its request did not reach
Lightwork with ``Accept: text/html`` (a proxy or CDN can reduce ``Accept`` to
``*/*``). The browser's own navigation markers, which scripts cannot set,
identify a page load as well. Requests with an ``Authorization`` header, a
method other than GET, or an API path always keep the machine-readable 401.
"""
from __future__ import annotations

from urllib.parse import quote

from .auth import route_path

# Paths whose callers expect JSON (the same list the HTML error pages use).
_MACHINE_PATHS = ("/api/", "/openapi", "/healthz", "/livez", "/readyz", "/metrics")


def is_browser_navigation(request) -> bool:
    """Whether ``request`` is a top-level browser page load that may be redirected."""
    if request.method != "GET" or request.headers.get("authorization"):
        return False
    if route_path(request).startswith(_MACHINE_PATHS):
        return False
    if "text/html" in (request.headers.get("accept") or "").lower():
        return True
    return (request.headers.get("sec-fetch-mode") == "navigate"
            and request.headers.get("sec-fetch-dest") in ("document", "iframe"))


def return_path(request) -> str:
    """This page's local path and query, or ``/`` when it is not a safe local path."""
    from .oidc_login import _is_safe_return_to

    path = request.url.path + (f"?{request.url.query}" if request.url.query else "")
    return path if _is_safe_return_to(path) else "/"


def sign_in_url(request, login: str = "/auth/login") -> str:
    return f"{login}?return_to={quote(return_path(request), safe='')}"
