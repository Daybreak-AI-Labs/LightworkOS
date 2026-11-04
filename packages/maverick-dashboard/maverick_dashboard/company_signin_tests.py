"""A real provider sign-in check that never changes current sign-in or roles."""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import asdict, replace
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from maverick import config
from maverick.audit.errors import AuditRefused
from maverick.governed_operations import digest
from maverick.governed_records import (
    GovernedRecordBackendError,
    GovernedRecordStore,
    RecordConflict,
)
from maverick.oidc import OIDCError, load_oidc_config, resolve_endpoints, verify_oidc_token
from maverick.privacy_ops import AuditOutboxError, PrivacyStateError
from maverick.web_session import sign_session, verify_session

from . import auth, oidc_login, settings_catalog_requests
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/settings/sign-in-tests", tags=["settings"])
COOKIE = "mvk_company_signin_test"
TTL = 600
STORE = GovernedRecordStore("company-signin-tests", "CST", "company_signin_test")


def authority(request, expected=None, *, write=False):
    current = settings_catalog_requests.authority(request, expected, write=write)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "The saved sign-in settings could not be checked. No test was started.")
    return current


def configuration_key(cfg):
    values = asdict(cfg)
    values.pop("enabled")
    return digest(values)


def current_configuration():
    cfg = load_oidc_config()
    if not all((cfg.issuer, cfg.client_id, cfg.client_secret, cfg.audience, cfg.redirect_uri)) or len(cfg.session_secret) < 32:
        raise HTTPException(409, "Save the provider address, application details, return address and session key before trying a real sign-in.")
    target = urlparse(cfg.redirect_uri)
    if target.path != "/auth/callback" or target.username or target.password or target.query or target.fragment or not target.hostname or not (
            target.scheme == "https" or target.scheme == "http" and target.hostname in {"localhost", "127.0.0.1", "::1"}):
        raise HTTPException(409, "Register this Lightwork site's sign-in return address ending in /auth/callback.")
    return cfg


def _account_label(principal):
    value = principal.claims.get("name")
    if not isinstance(value, str) or not value.strip() or len(value) > 120 or any(ord(char) < 32 for char in value):
        return "Verified company account"
    return value.strip()


def verified_people(request):
    """Current, owned, audited sign-in evidence for the ordinary role picker."""
    current = authority(request)
    key = configuration_key(load_oidc_config())
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The retained company sign-in checks exceed the supported bound.")
    people = {}
    for row in sorted(rows, key=lambda item: item["checked_at"]):
        if row.get("protocol") == "saml":
            continue
        age = time.time() - row["checked_at"]
        if (row.get("actor") == auth.caller_principal(request)
                and row.get("owner") == context_for(request) and row.get("configuration") == key
                and not row.get("_audit_pending") and 0 <= age < TTL):
            people["user:" + row["account"]] = str(row.get("account_label") or "Verified company account") + " (verified company sign-in)"
    authority(request, current)
    from .company_saml_setup import verified_people as saml_people
    people.update(saml_people(request))
    return people


@router.get("")
def status(request: Request):
    current = authority(request)
    actor, owner = auth.caller_principal(request) or "local administrator", context_for(request)
    key = configuration_key(load_oidc_config())
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The retained sign-in checks exceed this view's supported limit. No results were silently omitted.")
    selected = [{"checked_at": row["checked_at"], "provider": row["provider"], "current": row["configuration"] == key,
                 "account": row.get("account_label", "Verified company account"), "scope": "A provider sign-in was verified. Sign-in requirements and administrator access were not changed."}
                for row in rows if row.get("protocol") != "saml" and row.get("actor") == actor
                and row.get("owner") == owner and not row.get("_audit_pending")]
    selected.sort(key=lambda row: row["checked_at"], reverse=True)
    authority(request, current)
    return JSONResponse({"checks": selected, "context": current}, headers={"Cache-Control": "private, no-store"})


@router.post("/start")
async def start(request: Request):
    current = authority(request, write=True)
    cfg = current_configuration()
    key = configuration_key(cfg)
    try:
        endpoints = await asyncio.to_thread(resolve_endpoints, cfg)
    except OIDCError as exc:
        raise HTTPException(409, "The provider's sign-in details could not be read. Check its connection before trying again.") from exc
    authority(request, current, write=True)
    if configuration_key(current_configuration()) != key:
        raise HTTPException(409, "The saved sign-in settings changed. Review them before trying again.")
    state, nonce, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
    now = int(time.time())
    transaction = {"purpose": "lightwork.company-signin-test.v1", "context": current,
        "configuration": key, "actor": auth.caller_principal(request) or "local administrator", "owner": context_for(request),
        "state": state, "nonce": nonce, "cv": verifier, "jti": secrets.token_urlsafe(24), "exp": now + TTL}
    params = {"response_type": "code", "client_id": cfg.client_id, "redirect_uri": cfg.redirect_uri,
        "scope": "openid", "state": state, "nonce": nonce, "code_challenge": oidc_login._code_challenge_s256(verifier),
        "code_challenge_method": "S256", "prompt": "login", "max_age": "0"}
    target = endpoints["authorization_endpoint"] + "?" + urlencode(params)
    response = (JSONResponse({"authorization_url": target, "context": current}, headers={"Cache-Control": "no-store"})
                if "application/json" in request.headers.get("accept", "") else RedirectResponse(target, status_code=302))
    oidc_login._set_cookie(response, COOKIE, sign_session(transaction, cfg.session_secret), max_age=TTL, secure=oidc_login._cookie_secure(request))
    return response


async def finish(request: Request):
    """Reuse native token exchange, nonce and signature verification; mint no session."""
    from httpx import HTTPError
    response = RedirectResponse("/settings/all?signin_test=unconfirmed#settings-signin-guide", status_code=303)
    try:
        cfg = current_configuration()
        transaction = verify_session(request.cookies.get(COOKIE, ""), cfg.session_secret)
        if not transaction or transaction.get("purpose") != "lightwork.company-signin-test.v1":
            return response
        current = transaction["context"]

        def guard():
            authority(request, current)
            if transaction["actor"] != (auth.caller_principal(request) or "local administrator") or transaction["owner"] != context_for(request) or configuration_key(current_configuration()) != transaction["configuration"] or time.time() >= transaction["exp"]:
                raise HTTPException(409, "The original sign-in check changed or expired. Nothing was enabled.")

        guard()
        state = request.query_params.get("state", "")
        if not state or not secrets.compare_digest(state.encode(), transaction["state"].encode()):
            return response
        code = request.query_params.get("code", "")
        if not code or not await oidc_login._consume_tx_once(transaction["jti"], transaction["exp"]):
            return response
        endpoints = await asyncio.to_thread(resolve_endpoints, cfg)
        guard()
        data = await oidc_login._exchange_code_for_tokens(endpoints["token_endpoint"], cfg=cfg, code=code, code_verifier=transaction["cv"])
        guard()
        principal = await asyncio.to_thread(verify_oidc_token, str(data.get("id_token", "")), config=replace(cfg, enabled=True))
        guard()
        nonce = str(principal.claims.get("nonce", ""))
        if not nonce or not secrets.compare_digest(nonce.encode(), transaction["nonce"].encode()):
            return response
        from .mfa_policy import claims_prove_mfa, require_mfa
        if require_mfa() and not claims_prove_mfa(principal.claims):
            return response
        row = STORE.create({"id": "CST-" + digest(transaction["jti"])[:32], "actor": transaction["actor"], "owner": transaction["owner"], "configuration": transaction["configuration"],
            "checked_at": time.time(), "provider": principal.issuer, "account": principal.sub,
            "account_label": _account_label(principal)},
            action="company_signin_test_verified", actor=transaction["actor"],
            max_records=100, effect_guard=guard)
        guard()
        if row.get("_audit_pending"):
            return response
        response = RedirectResponse("/settings/all?signin_test=verified#settings-signin-guide", status_code=303)
    except (HTTPException, HTTPError, OIDCError, GovernedRecordBackendError, RecordConflict,
            AuditRefused, AuditOutboxError, PrivacyStateError, OSError, ValueError, TypeError, KeyError):
        pass  # The fixed result cannot echo a token, code, credential or provider error.
    finally:
        oidc_login._clear_cookie(response, COOKIE)
    return response
