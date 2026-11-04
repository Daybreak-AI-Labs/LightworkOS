"""Field Core Web Vitals ([analytics] web_vitals) in the dashboard.

When the setting is on, every page loads ``lightwork-web-vitals.js``, which
measures a sample of page loads (LCP, INP and CLS, the web-vitals method) and
sends them once, when the page is hidden, to ``/api/v1/telemetry/vitals``. The
server keeps them under the page's route template ("/chat/goal/{goal_id}"),
never the address, in :mod:`maverick.web_vitals`, which stores counts only.
Global administrators read the 75th percentiles at ``/settings/page-speed``.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from .feature_gate import feature_off

router = APIRouter()
_NOT_PAGES = ("/api/", "/static/", "/auth/", "/healthz", "/livez", "/readyz", "/metrics")


def _app():
    from . import app
    return app


class Vitals(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str = Field(min_length=1, max_length=300)
    device: str = Field(max_length=10)
    lcp: float | None = None
    inp: float | None = None
    cls: float | None = None


def _route(path: str) -> str | None:
    """The page route template that serves ``path``, or None if no page does."""
    from starlette.routing import Route

    if not path.startswith("/") or path.startswith(_NOT_PAGES) or "?" in path or "#" in path:
        return None
    for route in _app().app.routes:
        if (isinstance(route, Route) and route.methods and "GET" in route.methods
                and not route.path.startswith(_NOT_PAGES) and route.path_regex.match(path)):
            return route.path
    return None


@router.post("/api/v1/telemetry/vitals", status_code=204)
def receive_vitals(body: Vitals, request: Request) -> Response:
    """One sampled page load's LCP, INP and CLS, kept as counts for its route."""
    from maverick import web_vitals

    _app()._require_same_origin(request)
    auth.require_permission(request, "view")
    if not auth.caller_principal(request):
        raise HTTPException(403, "Sign in to send page speed measurements.")
    if not web_vitals.enabled():
        raise feature_off("analytics", "Page speed measurement")
    route = _route(body.path)
    if route is None:
        raise HTTPException(404, "That is not a page of this dashboard.")
    metrics = {name: value for name, value in (("lcp", body.lcp), ("inp", body.inp), ("cls", body.cls))
               if value is not None}
    try:
        web_vitals.record(route, body.device, metrics)
    except web_vitals.VitalsError as exc:
        raise HTTPException(422, str(exc).capitalize() + ".") from exc
    return Response(status_code=204)


@router.get("/settings/page-speed", response_class=HTMLResponse)
def page_speed(request: Request) -> HTMLResponse:
    """p75 LCP, INP and CLS per page and device over 28 days; global administrators only."""
    from maverick import web_vitals

    auth.require_global_permission(request, "admin")
    return _app().templates.TemplateResponse(request, "web_vitals.html", {
        "enabled": web_vitals.enabled(), "report": web_vitals.report(),
    })


def vitals_context(request: Request) -> dict[str, Any]:
    """Load the measuring script only for signed-in people when measurement is on."""
    try:
        from maverick import web_vitals

        on = web_vitals.enabled() and bool(auth.caller_principal(request))
        rate = web_vitals.sample_rate()
    except Exception:  # noqa: BLE001 -- the shell never fails over optional measurement
        on, rate = False, 0
    return {"web_vitals_on": on, "web_vitals_sample_rate": rate}


__all__ = ["router", "vitals_context"]
