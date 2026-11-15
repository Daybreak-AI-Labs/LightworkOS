"""What the dashboard answers while start-up refused a half-restored folder.

When ``backup.recover_interrupted_restore`` cannot undo a restore that
stopped part-way, the lifespan records the operator message on
``app.state.restore_refusal`` and starts nothing else. This ASGI gate sits
outside every other layer, so no HTTP request or websocket reaches a route
(or the data folder) while that is so:

- ``/livez`` and static files pass through;
- ``/healthz`` and ``/readyz`` answer 503 with the desktop's identity header
  and a short fixed message (no folder paths or workspace names);
- websockets are closed with 1008, as in recovery mode;
- every other request gets the full message only when it comes from the
  static-token holder or the local owner (auth off, loopback); others get
  the short message. When a dashboard token is set, the page offers a form
  where the administrator enters it to see the steps.
"""
from __future__ import annotations

from html import escape

from fastapi.responses import HTMLResponse, JSONResponse
from starlette.requests import Request

from .auth import route_path

PUBLIC_MESSAGE = (
    "An earlier restore stopped part-way, so Lightwork did not start. The next step "
    "is in the Lightwork server log on the computer that runs it."
)
STEPS_PATH = "/restore-recovery/steps"
_HEADERS = {"Cache-Control": "no-store", "X-Lightwork-Service": "dashboard-v1"}
_MAX_FORM_BYTES = 4096


def _trusted(request: Request) -> bool:
    from . import auth as auth_boundary
    from .app import _is_loopback_client, _is_loopback_request_host

    try:
        return auth_boundary._dashboard_token_authenticated(request) or bool(
            not request.headers.get("authorization")
            and _is_loopback_client(request.client.host if request.client else "")
            and _is_loopback_request_host(request)
            and auth_boundary.anonymous_local_access_allowed()
        )
    except Exception:  # an unreadable auth setting never widens what is shown
        return False


def _token_configured() -> bool:
    from ._shared import dashboard_token

    try:
        return bool(dashboard_token())
    except Exception:
        return False


def _page(detail: str, *, form: bool, status: int, note: str = "") -> HTMLResponse:
    body = "<h1>Lightwork did not start</h1><p>" + escape(detail) + "</p>"
    if note:
        body += "<p>" + escape(note) + "</p>"
    if form:
        body += (
            f'<form method="post" action="{STEPS_PATH}">'
            '<label for="token">Administrators: enter the dashboard token to see the steps.</label> '
            '<input id="token" name="token" type="password" autocomplete="off" required> '
            '<button type="submit">Show the steps</button></form>'
        )
    page = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
            "<title>Lightwork did not start</title>"
            '<link rel="stylesheet" href="/static/lightwork.css"></head><body><main>'
            + body + "</main></body></html>")
    return HTMLResponse(page, status_code=status, headers=_HEADERS)


async def _steps(request: Request, refusal: str) -> HTMLResponse:
    """The administrator proves the dashboard token in a form, not a header."""
    from maverick.constant_time import text_equals

    from ._shared import dashboard_token

    raw = await request.body()
    supplied = ""
    if len(raw) <= _MAX_FORM_BYTES:
        from urllib.parse import parse_qs

        supplied = (parse_qs(raw.decode("utf-8", "replace")).get("token") or [""])[0]
    expected = dashboard_token() if _token_configured() else ""
    if expected and supplied and text_equals(supplied, expected):
        return _page(refusal, form=False, status=503)
    return _page(PUBLIC_MESSAGE, form=_token_configured(), status=403,
                 note="That token does not match.")


async def response(request: Request, refusal: str):
    path = route_path(request)
    if path in {"/healthz", "/readyz"}:
        return JSONResponse({"status": "restore_recovery", "detail": PUBLIC_MESSAGE},
                            status_code=503, headers=_HEADERS)
    if path == STEPS_PATH and request.method == "POST":
        return await _steps(request, refusal)
    trusted = _trusted(request)
    detail = refusal if trusted else PUBLIC_MESSAGE
    if "text/html" in request.headers.get("accept", ""):
        return _page(detail, form=not trusted and _token_configured(), status=503)
    return JSONResponse({"detail": detail}, status_code=503, headers=_HEADERS)


class RestoreRefusalGate:
    """Outermost ASGI layer; idle unless start-up was refused."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        refusal = None
        if scope["type"] in {"http", "websocket"}:
            owner = scope.get("app")
            refusal = getattr(getattr(owner, "state", None), "restore_refusal", None)
        if not refusal:
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        request = Request(scope, receive)
        path = route_path(request)
        if path == "/livez" or (path.startswith("/static/") and request.method in {"GET", "HEAD"}):
            await self.app(scope, receive, send)
            return
        answer = await response(request, refusal)
        await answer(scope, receive, send)
