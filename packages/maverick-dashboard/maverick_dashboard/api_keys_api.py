"""API keys and service accounts: ``/api/v1/api-keys``,
``/api/v1/service-accounts`` and the ``/account/api-keys`` page.

Every signed-in person manages their own keys (scopes limited to their
role); administrators see every key and service account and can create or
disable service accounts. The secret is returned exactly once, in the
response that creates or rotates it. Every mutation is audited by the store
(:mod:`maverick_dashboard.api_keys`). Mutating ``/api/v1`` requests are
already same-origin-checked by the app middleware in cookie / no-token mode.
An API key cannot manage credentials: allowing a read-only key to mint or
rotate a stronger key would bypass its scopes and expiry.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from starlette.concurrency import run_in_threadpool

from . import api_keys, auth

router = APIRouter()

_LOCAL_OWNER = "user:local"


def _caller(request: Request) -> str:
    """The principal that owns keys created on this request.

    A static-token or genuine local auth-off caller has no person behind it;
    its keys belong to ``user:local`` (the identity durable automations use
    for the same case), whose role decides what those keys may do.
    """
    principal = auth.caller_principal(request)
    if principal:
        return principal
    auth.require_permission(request, "view")
    return _LOCAL_OWNER


def _is_admin(request: Request) -> bool:
    return auth.has_global_permission(request, "admin")


def _require_enabled() -> None:
    if not api_keys.enabled():
        raise HTTPException(status_code=404, detail="API keys are turned off on this installation.")


def _require_non_key_caller(request: Request) -> None:
    """Keep bearer keys from minting, renewing or disabling credentials.

    Interactive sign-in and the legacy break-glass token retain key recovery.
    This check runs after authentication, which records key use on the request.
    """
    if auth.api_key_permissions(request) is not None:
        raise HTTPException(
            status_code=403,
            detail="An API key cannot manage access keys or service accounts. "
                   "Sign in and use Account > Access keys.",
        )


async def _body(request: Request) -> dict:
    try:
        data = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Send a JSON object.") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Send a JSON object.")
    return data


def _run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except api_keys.ApiKeyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except api_keys.ApiKeyStoreError as exc:
        raise HTTPException(
            status_code=503,
            detail="The API key store cannot be read right now. Ask an administrator.",
        ) from exc


def _overview(request: Request, everyone: bool) -> dict:
    caller = _caller(request)
    admin = _is_admin(request)
    show_all = admin and everyone
    keys = api_keys.list_keys(owner=None if show_all else caller)
    expiring = {k.id for k in api_keys.expiring_soon(keys)}
    conf = api_keys.settings()
    out = {
        "you": caller,
        "admin": admin,
        "showing_everyone": show_all,
        "keys": [k.to_public() for k in keys],
        "expiring_soon": sorted(expiring),
        "scopes": [{"scope": s, "help": h} for s, (_a, h) in api_keys.SCOPES.items()],
        "scopes_available": api_keys.scopes_available_to(caller),
        "defaults": {
            "default_days": conf["default_days"], "max_days": conf["max_days"],
            "rotation_grace_hours": conf["rotation_grace_hours"], "prefix": conf["prefix"],
            "warning_days": api_keys.EXPIRY_WARNING_DAYS,
        },
    }
    if admin:
        from ._shared import dashboard_token

        accounts = api_keys.list_service_accounts()
        out["service_accounts"] = [
            a.to_public() | {"scopes_available": api_keys.scopes_available_to(a.principal),
                             "keys": [k.to_public() for k in a.keys]}
            for a in accounts
        ]
        out["static_token_set"] = bool(dashboard_token())
        from . import rbac

        out["roles"] = list(rbac.known_roles())
    return out


@router.get("/api/v1/api-keys")
async def list_api_keys(request: Request, all: str = "") -> dict:
    """Your keys (``?all=1``: every key, administrators only)."""
    _require_enabled()
    auth.require_permission(request, "view")
    return await run_in_threadpool(lambda: _run(_overview, request, all in {"1", "true", "yes"}))


@router.post("/api/v1/api-keys", status_code=201)
async def create_api_key(request: Request) -> dict:
    """Create a key. The response is the only time the secret is shown."""
    _require_enabled()
    auth.require_permission(request, "view")
    _require_non_key_caller(request)
    body = await _body(request)
    return await run_in_threadpool(_reviewed_key_change, request, body, "create")


def _reviewed_key_change(request, body, action, key_id=None):
    from .access_key_requests_api import ApplyIn, apply_sealed

    if set(body) != {"token", "confirmed"}:
        raise HTTPException(409, "Open Access keys and review this complete change before confirming. No key was changed.")
    try:
        reviewed = ApplyIn.model_validate(body)
    except ValueError as exc:
        raise HTTPException(422, "Confirm the complete current review in Access keys. No key was changed.") from exc
    result = apply_sealed(request, reviewed, action=action, key_id=key_id)
    if action == "create":
        # The route's documented answer for a key it created (status_code=201);
        # a JSONResponse would otherwise send 200.
        result.status_code = 201
    return result


@router.post("/api/v1/api-keys/{key_id}/rotate")
async def rotate_api_key(request: Request, key_id: str) -> dict:
    """Mint a replacement; the old secret keeps working for the grace period."""
    _require_enabled()
    auth.require_permission(request, "view")
    _require_non_key_caller(request)
    body = await _body(request)
    return await run_in_threadpool(_reviewed_key_change, request, body, "rotate", key_id)


@router.post("/api/v1/api-keys/{key_id}/revoke")
async def revoke_api_key(request: Request, key_id: str) -> dict:
    _require_enabled()
    auth.require_permission(request, "view")
    _require_non_key_caller(request)
    body = await _body(request)
    return await run_in_threadpool(_reviewed_key_change, request, body, "revoke", key_id)


@router.get("/api/v1/service-accounts")
async def list_service_accounts(request: Request) -> dict:
    _require_enabled()
    auth.require_global_permission(request, "admin")

    def _list():
        return {"service_accounts": [
            a.to_public() | {"keys": [k.to_public() for k in a.keys]}
            for a in api_keys.list_service_accounts()
        ]}

    return await run_in_threadpool(lambda: _run(_list))


@router.post("/api/v1/service-accounts", status_code=201)
async def create_service_account(request: Request) -> dict:
    """Register a service account with a role (administrators only)."""
    _require_enabled()
    auth.require_global_permission(request, "admin")
    _require_non_key_caller(request)
    body = await _body(request)
    caller = _caller(request)

    def _create():
        account = api_keys.create_service_account(
            body.get("name"), body.get("role"), description=body.get("description") or "",
            actor=caller,
        )
        return {"service_account": account.to_public()}

    return await run_in_threadpool(lambda: _run(_create))


@router.post("/api/v1/service-accounts/{slug}/disable")
async def disable_service_account(request: Request, slug: str) -> dict:
    """Disable an account: all of its keys stop working at once."""
    _require_enabled()
    auth.require_global_permission(request, "admin")
    _require_non_key_caller(request)
    caller = _caller(request)
    return await run_in_threadpool(
        lambda: _run(lambda: {"service_account": api_keys.disable_service_account(slug, actor=caller).to_public()})
    )


@router.get("/account/api-keys", response_class=HTMLResponse)
def api_keys_page(request: Request) -> HTMLResponse:
    auth.require_permission(request, "view")
    _require_non_key_caller(request)
    from .app import templates

    return templates.TemplateResponse(request, "api_keys.html", {},
                                      headers={"Cache-Control": "private, no-store"})
