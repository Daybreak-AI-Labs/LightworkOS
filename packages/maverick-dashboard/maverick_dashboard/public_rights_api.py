"""Public rights-request surface: the JSON API and the pages people land on.

``/api/v1/public/rights/*`` and ``/rights/*`` are auth-exempt in the same
way ``/api/v1/public/consent/*`` is (see ``auth._self_authenticated_path``
and the ``bearer_auth`` middleware): nobody filing a request holds a
dashboard credential. What stands in for authentication:

* the module gate -- everything 404s while
  ``[privacy_automation.public_rights_form]`` is off or the property is
  unknown or disabled;
* CSRF safety -- a submission must be ``application/json`` (an HTML form
  cannot send that cross-site) and come from this origin or one of the
  property's ``allowed_origins`` (which then receive CORS headers); the
  verification link is consumed by a same-origin POST, never a GET, so a
  mail scanner that prefetches the link does not burn it;
* anti-abuse -- the kernel's challenge, honeypot and limits, plus a
  per-address cap on token lookups here;
* size -- the body middleware in ``app.py`` caps the JSON before parsing.

Errors never reveal whether an email address is known here.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .rights_form_strings import strings

log = logging.getLogger(__name__)

PUBLIC_API_PREFIX = "/api/v1/public/rights"
PUBLIC_PAGE_PREFIX = "/rights/"
#: JSON submissions are small; the middleware in app.py enforces this cap.
MAX_BODY_BYTES = 32 * 1024
_TOKEN_LOOKUPS_PER_MINUTE = 30

router = APIRouter(prefix=PUBLIC_API_PREFIX, tags=["public-rights"])
pages = APIRouter(tags=["public-rights-pages"])


def _prf():
    from maverick import public_rights_form

    return public_rights_form


def _client_ip(request: Request) -> str:
    """The requester's address for rate limiting and the submission record.

    Proxy-aware through :func:`maverick_dashboard.ip_allowlist.client_ip`: an
    ``X-Forwarded-For`` chain counts only when the peer is one of the pinned
    ``[auth.proxy] trusted_proxies``, so a visitor cannot dodge the per-address
    limit by sending the header themselves.
    """
    from .ip_allowlist import client_ip

    addr = client_ip(request)
    return str(addr) if addr is not None else "unknown"


_TOKEN_LIMIT = None


def _token_limit():
    global _TOKEN_LIMIT
    if _TOKEN_LIMIT is None:
        from maverick.public_rights_form import SlidingWindowLimit

        _TOKEN_LIMIT = SlidingWindowLimit(60.0)
    return _TOKEN_LIMIT


def _limit_token_lookups(request: Request) -> None:
    import time

    if not _token_limit().hit(f"ip:{_client_ip(request)}", _TOKEN_LOOKUPS_PER_MINUTE, time.time()):
        raise HTTPException(status_code=429, detail="too many attempts; try again shortly",
                            headers={"Retry-After": "60"})


def _origin_of(value: str) -> str:
    try:
        parsed = urlparse(value)
        scheme = parsed.scheme.lower()
        host = parsed.hostname
        if scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
            return ""
        host = host.lower()
        if ":" in host:
            host = f"[{host}]"
        port = parsed.port
        suffix = f":{port}" if port and port != (443 if scheme == "https" else 80) else ""
        return f"{scheme}://{host}{suffix}"
    except ValueError:
        return ""


def _public_base_url() -> str:
    """Operator-owned URL used in public verification links and origin checks."""
    import ipaddress
    from urllib.parse import urlsplit

    from maverick.env_setting import env_or_config

    raw = str(env_or_config("MAVERICK_PUBLIC_BASE_URL", "channels", "public_base_url", "") or "").strip().rstrip("/")
    if not raw:
        raw = str(env_or_config("MAVERICK_PUBLIC_URL", "dashboard", "public_url", "") or "").strip().rstrip("/")
    try:
        parsed = urlsplit(raw)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path
                or any(ord(ch) < 33 or ch in '<>"\'\\' for ch in raw)):
            raise ValueError("invalid public URL")
        _ = parsed.port
        if parsed.scheme == "http":
            host = parsed.hostname.lower()
            try:
                local = ipaddress.ip_address(host).is_loopback
            except ValueError:
                local = host == "localhost"
            if not local:
                raise ValueError("public HTTP is permitted only for loopback")
    except ValueError:
        raise HTTPException(status_code=503, detail="public rights form URL is not configured") from None
    return raw


def _request_origin(request: Request) -> str:
    """The browser's stated origin (Origin, else the Referer's origin)."""
    for header in ("origin", "referer"):
        value = request.headers.get(header)
        if value:
            return _origin_of(value)
    return ""


def _allowed_origin(request: Request, prop: dict) -> str | None:
    """``""`` for a same-origin caller, the origin for an allow-listed embed,
    ``None`` when the caller may not submit."""
    origin = _request_origin(request)
    if not origin:
        return None
    self_origin = _origin_of(_public_base_url())
    if origin == self_origin:
        return ""
    if origin in {_origin_of(item) for item in (prop.get("allowed_origins") or [])}:
        return origin
    return None


def _cors(response: Response, origin: str) -> Response:
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    response.headers["Cache-Control"] = "no-store, private"
    return response


def _form_or_404(slug: str) -> dict:
    prf = _prf()
    form = prf.form_definition(slug)
    if form is None:
        raise HTTPException(status_code=404, detail="no such form")
    return form


# --------------------------------------------------------------------------- #
# JSON API
# --------------------------------------------------------------------------- #

@router.get("/{slug}/form")
async def public_form_definition(request: Request, slug: str) -> Response:
    """What the form offers for this property, plus a fresh challenge and
    the public strings (so an embed renders the same words as the page)."""
    form = await run_in_threadpool(_form_or_404, slug[:64])
    prop = await run_in_threadpool(_prf().get_property, slug[:64])
    origin = _allowed_origin(request, prop or {})
    payload = {**form, "strings": strings()}
    return _cors(JSONResponse(payload), origin or "")


@router.options("/{slug}/requests")
async def public_submit_preflight(request: Request, slug: str) -> Response:
    prop = await run_in_threadpool(_prf().get_property, slug[:64])
    if prop is None or not _prf().enabled():
        raise HTTPException(status_code=404, detail="no such form")
    origin = _allowed_origin(request, prop)
    if origin is None:
        raise HTTPException(status_code=403, detail="origin not allowed")
    response = Response(status_code=204)
    response.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Max-Age"] = "600"
    return _cors(response, origin)


@router.post("/{slug}/requests", status_code=202)
async def public_submit(request: Request, slug: str) -> Response:
    """File a request. Always answers the same neutral acceptance on
    success; a failed challenge is a 422 with ``code: challenge`` and a
    fresh sum so the page can try again."""
    prf = _prf()
    if not prf.enabled():
        raise HTTPException(status_code=404, detail="no such form")
    prop = await run_in_threadpool(prf.get_property, slug[:64])
    if prop is None or not prop.get("enabled"):
        raise HTTPException(status_code=404, detail="no such form")
    if "application/json" not in request.headers.get("content-type", ""):
        raise HTTPException(status_code=415, detail="send the form as JSON")
    origin = _allowed_origin(request, prop)
    if origin is None:
        raise HTTPException(
            status_code=403,
            detail="this form only accepts submissions from its own page or an "
                   "allowed website",
        )
    try:
        payload = await request.json()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid JSON body") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="the form must be a JSON object")
    base_url = _public_base_url()
    try:
        result = await run_in_threadpool(
            prf.submit, prop["slug"], payload, client_ip=_client_ip(request),
            base_url=base_url,
        )
    except prf.RateLimited as exc:
        return _cors(JSONResponse({"detail": str(exc), "code": "rate_limit"},
                                  status_code=429, headers={"Retry-After": "600"}), origin)
    except prf.ChallengeFailed as exc:
        return _cors(JSONResponse(
            {"detail": str(exc), "code": "challenge", "challenge": prf.new_challenge()},
            status_code=422), origin)
    except prf.PublicRightsFormError as exc:
        return _cors(JSONResponse({"detail": str(exc), "code": "invalid"}, status_code=422),
                     origin)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="no such form") from exc
    except prf.PublicRightsFormConfigError as exc:
        raise HTTPException(status_code=404, detail="no such form") from exc
    return _cors(JSONResponse(result, status_code=202), origin)


@router.post("/verify/{token}")
async def public_verify(request: Request, token: str) -> Response:
    """Consume a verification link (JSON form of the page button)."""
    _limit_token_lookups(request)
    if _allowed_origin(request, {}) is None:
        raise HTTPException(status_code=403, detail="confirm from the link's own page")
    view = await run_in_threadpool(_prf().verify, token[:128])
    if view is None:
        raise HTTPException(status_code=404, detail="this link is not valid")
    return _cors(JSONResponse(view), "")


@router.get("/status/{token}")
async def public_status(request: Request, token: str) -> Response:
    _limit_token_lookups(request)
    view = await run_in_threadpool(_prf().status, token[:128])
    if view is None:
        raise HTTPException(status_code=404, detail="this link is not valid")
    return _cors(JSONResponse(view), "")


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #

def _page(request: Request, name: str, context: dict, status_code: int = 200) -> HTMLResponse:
    from .app import templates  # the dashboard's one Jinja environment (filters included)

    response = templates.TemplateResponse(
        request, name, {"rf": strings(), **context}, status_code=status_code)
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["X-Robots-Tag"] = "noindex"
    return response


@pages.get("/rights/{slug}", response_class=HTMLResponse)
async def rights_form_page(request: Request, slug: str) -> HTMLResponse:
    """The hosted form. Off, unknown or disabled all read the same 404 page."""
    prf = _prf()
    form = await run_in_threadpool(prf.form_definition, slug[:64]) if prf.enabled() else None
    if form is None:
        return _page(request, "rights_unavailable.html", {}, status_code=404)
    return _page(request, "rights_form.html", {"form": form, "slug": form["property"]["slug"]})


@pages.get("/rights/verify/{token}", response_class=HTMLResponse)
async def rights_verify_page(request: Request, token: str) -> HTMLResponse:
    """Shows a Confirm button; the link is consumed only by the POST below,
    so a mail scanner opening the link does not use it up."""
    if not _prf().enabled():
        return _page(request, "rights_unavailable.html", {}, status_code=404)
    return _page(request, "rights_verify.html", {"token": token[:128]})


@pages.post("/rights/verify/{token}", response_class=HTMLResponse)
async def rights_verify_submit(request: Request, token: str) -> HTMLResponse:
    _limit_token_lookups(request)
    if _allowed_origin(request, {}) is None:
        raise HTTPException(status_code=403, detail="confirm from the link's own page")
    view = await run_in_threadpool(_prf().verify, token[:128]) if _prf().enabled() else None
    if view is None:
        return _page(request, "rights_status.html", {"view": None, "invalid": "verify"},
                     status_code=404)
    return _page(request, "rights_status.html", {"view": view, "just_verified": True})


@pages.get("/rights/status/{token}", response_class=HTMLResponse)
async def rights_status_page(request: Request, token: str) -> HTMLResponse:
    _limit_token_lookups(request)
    view = await run_in_threadpool(_prf().status, token[:128]) if _prf().enabled() else None
    if view is None:
        return _page(request, "rights_status.html", {"view": None, "invalid": "status"},
                     status_code=404)
    return _page(request, "rights_status.html", {"view": view})


__all__ = ["MAX_BODY_BYTES", "PUBLIC_API_PREFIX", "PUBLIC_PAGE_PREFIX", "pages", "router"]
