"""Controls behind the /trust page that were only reachable from the CLI.

* ``GET  /api/v1/trust/pubkey`` -- this installation's public security key to
  share with partners (``maverick trust pubkey``).
* ``POST /api/v1/trust/enforcement`` -- turn blocking of unlisted outside
  agents on or off (``[agent_trust] enforce``), administrators only.
* ``POST /api/v1/trust/agents/{id}/check`` -- replay the access decision for
  one agent without changing anything (``maverick trust verify``).
* ``PUT  /api/v1/trust/agents/{id}`` -- change an app-managed agent's limits
  while keeping its connection tokens, expiry and block state (re-registering
  would drop them).

* ``POST /api/v1/trust/federation/{peer}/limit`` -- raise a federation
  peer's request limit or start its count again, installation administrators
  only, in the installation's own tenant where the federation server admits
  requests (``maverick trust admission-limit``).
* ``POST /api/v1/trust/federation/limits/storage`` -- raise how many partner
  requests the workspace keeps before refusing every peer (``--storage``).
* ``POST /api/v1/trust/federation/limits/start-over`` -- set an unreadable
  limits file aside so the default limits apply (``--start-over``).

Restoring a blocked agent (``maverick trust unrevoke``) already has an API.
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_global_permission, require_permission

router = APIRouter(prefix="/api/v1/trust", tags=["agent-trust-page"])

_EDITABLE = ("pubkey", "direction", "allow_tools", "deny_tools", "max_risk",
             "max_dollars", "max_wall_seconds", "data_scopes")


class EnforcementIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enforced: bool
    # Turning blocking off lowers a protection: like Settings > All settings,
    # the server refuses it unless the request says the person confirmed.
    confirm: bool = False


class CheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    direction: Literal["inbound", "outbound"] = "inbound"
    tools: list[str] = Field(default_factory=list, max_length=64)
    risk: Literal["low", "medium", "high"] | None = None


class AgentLimitsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    pubkey: str = Field(default="", max_length=64)
    direction: Literal["inbound", "outbound", "both"] = "both"
    allow_tools: list[str] = Field(default_factory=list, max_length=256)
    deny_tools: list[str] = Field(default_factory=list, max_length=256)
    max_risk: Literal["low", "medium", "high"] | None = None
    max_dollars: float | None = Field(default=None, ge=0)
    max_wall_seconds: float | None = Field(default=None, ge=0)
    data_scopes: list[str] = Field(default_factory=list, max_length=256)


class PeerLimitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int | None = Field(default=None, ge=1, le=2_000_000)
    reset: bool = False


class StorageLimitIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    limit: int = Field(ge=1, le=2_000_000)


_REASONS = {
    "allow": "This agent would be let in.",
    "disabled": "Blocking is turned off, so every outside agent is let in.",
    "not_in_registry": "This agent is not on the list, so it would be turned away.",
    "direction": "This agent is not allowed to connect in that direction.",
    "capability": "This agent is not allowed to use one of the chosen tools or risk levels.",
    "revoked": "This agent is blocked.",
    "expired": "This agent's access has expired.",
    "not_yet_valid": "This agent's access has not started yet.",
    "data_scope": "This agent may not read that data.",
}


def managed_ids() -> set[str]:
    from maverick import agent_trust

    try:
        return {str(e.get("id") or "") for e in agent_trust._load_managed()}
    except Exception:
        return set()


@router.get("/pubkey")
async def public_key(request: Request) -> dict:
    require_permission(request, "view")
    from maverick import agent_trust

    key = await run_in_threadpool(agent_trust.local_pubkey)
    if not key:
        raise HTTPException(status_code=503, detail="This installation has no security key yet.")
    return {"key": key}


def _enforced_now() -> bool | None:
    from maverick import agent_trust, config

    config.reset_config_cache()
    try:
        return agent_trust.agent_trust_enforced()
    except agent_trust.AgentTrustError:
        return None


@router.post("/enforcement")
async def set_enforcement(request: Request, body: EnforcementIn):
    require_global_permission(request, "admin")
    from maverick.audit import AuditRefused

    from . import settings_catalog as catalog
    from . import settings_store
    from .settings_audit import record_setting_change

    setting = catalog.BY_ID["agent_trust.enforce"]
    before = await run_in_threadpool(_enforced_now)
    if not body.enforced and before is not False and not body.confirm:
        return JSONResponse(
            {"detail": "confirmation required",
             "confirm": [{"id": setting.id, "label": setting.label, "warning": setting.warning}]},
            status_code=409, headers={"Cache-Control": "no-store"})

    def write() -> bool:
        settings_store.set_agent_trust_enforce(body.enforced)
        effective = _enforced_now()
        if effective is not body.enforced:
            # Something with higher precedence pins it: leave the saved value
            # matching what is really in force.
            if effective is not None:
                settings_store.set_agent_trust_enforce(effective)
                _enforced_now()
            return False
        return True

    if not await run_in_threadpool(write):
        raise HTTPException(
            status_code=409,
            detail="Your installation controls this setting, so it cannot be changed here.")
    if before is not body.enforced:
        try:
            await run_in_threadpool(
                lambda: record_setting_change(
                    request, section="agent_trust", key="enforce", old=before,
                    new=body.enforced,
                    confirmed=body.confirm and catalog.weakens(setting, before, body.enforced)))
        except AuditRefused as exc:
            # No change without a record of it: put the previous value back.
            if before is not None:
                await run_in_threadpool(settings_store.set_agent_trust_enforce, before)
                await run_in_threadpool(_enforced_now)
            raise HTTPException(
                status_code=503,
                detail="The change could not be recorded, so it was undone.") from exc
    return {"enforced": body.enforced}


@router.post("/agents/{agent_id}/check")
async def check_agent(request: Request, agent_id: str, body: CheckIn) -> dict:
    require_permission(request, "view")
    from maverick import agent_trust

    if not agent_trust.valid_agent_id(agent_id):
        raise HTTPException(status_code=404, detail="That agent is not on the list.")

    def decide():
        if body.direction == "outbound":
            return agent_trust.decide_outbound(agent_id, enforced=True)
        return agent_trust.decide_inbound(agent_id, requested_tools=body.tools,
                                          max_risk=body.risk, enforced=True)

    try:
        decision = await run_in_threadpool(decide)
    except agent_trust.AgentTrustError as exc:
        raise HTTPException(status_code=503, detail="The list of outside agents could not be read.") from exc
    return {"allowed": bool(decision.allowed),
            "reason": _REASONS.get(decision.rule, "This agent would be turned away."
                                   if not decision.allowed else "This agent would be let in.")}


@router.put("/agents/{agent_id}")
async def update_agent(request: Request, agent_id: str, body: AgentLimitsIn) -> dict:
    require_permission(request, "admin")
    from maverick import agent_trust

    def write() -> None:
        if not agent_trust.valid_agent_id(agent_id):
            raise HTTPException(status_code=404, detail="That agent is not on the list.")
        pubkey = body.pubkey.strip()
        if pubkey and not agent_trust._PUBKEY_RE.fullmatch(pubkey):
            raise HTTPException(status_code=422, detail="That security key is not valid.")
        with agent_trust._managed_locked():
            entries = agent_trust._load_managed()
            current = next((dict(e) for e in entries if str(e.get("id") or "") == agent_id), None)
            if current is None:
                raise HTTPException(
                    status_code=404,
                    detail="This agent was set up by your installation and can't be edited here.")
            update = body.model_dump()
            update["pubkey"] = pubkey
            for key in _EDITABLE:
                current.pop(key, None)
            current.update({k: v for k, v in update.items() if v not in (None, "", [], {})})
            current["id"] = agent_id
            if agent_trust._agent_from_entry(current) is None:
                raise HTTPException(status_code=422, detail="Some of the limits are not valid.")
            kept = [e for e in entries if str(e.get("id") or "") != agent_id]
            kept.append(current)
            agent_trust._save_managed(kept)

    try:
        await run_in_threadpool(write)
    except agent_trust.AgentTrustError as exc:
        raise HTTPException(status_code=503, detail="The list of outside agents could not be saved.") from exc
    return {"ok": True, "id": agent_id}


def _in_federation_scope(fn):
    """Run ``fn`` in the installation's own tenant: the inbound federation
    server admits requests there, not in the workspace a page has open."""
    from maverick.paths import implicit_tenant_id, reset_tenant, set_tenant

    token = set_tenant(implicit_tenant_id())
    try:
        return fn()
    finally:
        reset_tenant(token)


def federation_limits() -> dict | None:
    """Each federation peer's request use against its limit, for the page:
    ``{"peers": [...], "unreadable": bool}``. ``None`` when the counts could
    not be read for another reason."""
    from maverick import federation
    from maverick import federation_admission as admission
    from maverick.world_model import open_world

    peers = [p.name for p in federation.load_peers()]
    if not peers:
        return {"peers": [], "unreadable": False}

    def read() -> list[dict]:
        with open_world() as world:
            return [admission.admission_usage(world, name) for name in peers]

    try:
        return {"peers": _in_federation_scope(read), "unreadable": False}
    except admission.LimitsUnreadable:
        return {"peers": [], "unreadable": True}
    except Exception:
        return None


_UNREADABLE = ("The saved limits could not be read, so nothing was changed. "
               "Start over to use the default limits.")
_UNRECORDED = "The change could not be recorded, so it was not made."


def _actor(request: Request) -> str:
    return str(caller_principal(request) or "authorized-local-operator")


def start_over_limits(request: Request) -> bool:
    """Set unreadable partner limits aside. Shared by the page and Copilot:
    installation administrators only, in the installation's own tenant; the
    kernel writes the audit row first. The actor is the signed-in person."""
    require_global_permission(request, "admin")
    from maverick import federation_admission as admission
    from maverick.audit import AuditRefused

    actor = _actor(request)
    try:
        aside = _in_federation_scope(lambda: admission.start_over_limits(actor=actor))
    except (AuditRefused, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=_UNRECORDED) from exc
    return aside is not None


def apply_storage_limit(request: Request, limit: int) -> int:
    """Set the workspace storage limit (same checks as :func:`start_over_limits`)."""
    require_global_permission(request, "admin")
    from maverick import federation_admission as admission
    from maverick.audit import AuditRefused

    actor = _actor(request)
    try:
        return _in_federation_scope(lambda: admission.set_storage_limit(limit, actor=actor))
    except admission.LimitsUnreadable as exc:
        raise HTTPException(status_code=409, detail=_UNREADABLE) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="That limit is not allowed. Choose a whole number from 1 to 2,000,000.") from exc
    except (AuditRefused, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=_UNRECORDED) from exc


def apply_peer_limit(request: Request, peer: str, *, limit: int | None, reset: bool) -> dict:
    """Raise a partner's limit and/or restart its count (same checks as
    :func:`start_over_limits`). Returns the partner's current use."""
    require_global_permission(request, "admin")
    from maverick import federation
    from maverick import federation_admission as admission
    from maverick.audit import AuditRefused
    from maverick.world_model import open_world

    if peer not in {p.name for p in federation.load_peers()}:
        raise HTTPException(status_code=404, detail="That partner is not set up on this installation.")
    if limit is None and not reset:
        raise HTTPException(status_code=422, detail="Choose a new limit or start the count again.")
    actor = _actor(request)

    def write() -> dict:
        admission.set_admission_limit(peer, limit=limit, reset=reset, actor=actor)
        with open_world() as world:
            return admission.admission_usage(world, peer)

    try:
        return _in_federation_scope(write)
    except admission.LimitsUnreadable as exc:
        raise HTTPException(status_code=409, detail=_UNREADABLE) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="That limit is not allowed. Choose a whole number from 1 to 2,000,000.") from exc
    except (AuditRefused, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=_UNRECORDED) from exc


@router.post("/federation/limits/start-over")
async def start_over_peer_limits(request: Request) -> dict:
    return {"started_over": await run_in_threadpool(start_over_limits, request)}


@router.post("/federation/limits/storage")
async def set_storage_limit(request: Request, body: StorageLimitIn) -> dict:
    return {"storage_limit": await run_in_threadpool(apply_storage_limit, request, body.limit)}


@router.post("/federation/{peer}/limit")
async def set_peer_limit(request: Request, peer: str, body: PeerLimitIn) -> dict:
    return await run_in_threadpool(
        lambda: apply_peer_limit(request, peer, limit=body.limit, reset=body.reset))
