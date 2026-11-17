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
Each change runs one shared function, which Copilot also calls
(``product_operations_agent_trust`` and ``product_operations_partner_limits``).
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth
from .auth import require_global_permission, require_permission

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
    # No key, or an empty one, keeps the key on file; only remove_key clears it.
    pubkey: str | None = Field(default=None, max_length=64)
    remove_key: bool = False
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


class ConfirmationNeeded(Exception):
    """Turning blocking off lowers a protection and was not confirmed."""


_PINNED = "Your installation controls this setting, so it cannot be changed here."


def apply_enforcement(request: Request, enforced: bool, *, confirm: bool) -> None:
    """Turn blocking of unlisted outside agents on or off. Shared by the page
    and Copilot: installation administrators only, turning it off needs the
    person's confirmation, and a change that cannot be recorded is undone."""
    require_global_permission(request, "admin")
    from maverick.audit import AuditRefused

    from . import settings_catalog as catalog
    from . import settings_store
    from .settings_audit import record_setting_change

    setting = catalog.BY_ID["agent_trust.enforce"]
    before = _enforced_now()
    if not enforced and before is not False and not confirm:
        raise ConfirmationNeeded

    settings_store.set_agent_trust_enforce(enforced)
    effective = _enforced_now()
    if effective is not enforced:
        # Something with higher precedence pins it: leave the saved value
        # matching what is really in force.
        if effective is not None:
            settings_store.set_agent_trust_enforce(effective)
            _enforced_now()
        raise HTTPException(status_code=409, detail=_PINNED)
    if before is enforced:
        return
    try:
        record_setting_change(
            request, section="agent_trust", key="enforce", old=before, new=enforced,
            confirmed=confirm and catalog.weakens(setting, before, enforced))
    except AuditRefused as exc:
        # No change without a record of it: put the previous value back.
        if before is not None:
            settings_store.set_agent_trust_enforce(before)
            _enforced_now()
        raise HTTPException(
            status_code=503,
            detail="The change could not be recorded, so it was undone.") from exc


@router.post("/enforcement")
async def set_enforcement(request: Request, body: EnforcementIn):
    try:
        await run_in_threadpool(lambda: apply_enforcement(request, body.enforced, confirm=body.confirm))
    except ConfirmationNeeded:
        from . import settings_catalog as catalog

        setting = catalog.BY_ID["agent_trust.enforce"]
        return JSONResponse(
            {"detail": "confirmation required",
             "confirm": [{"id": setting.id, "label": setting.label, "warning": setting.warning}]},
            status_code=409, headers={"Cache-Control": "no-store"})
    return {"enforced": body.enforced}


def check_access(request: Request, agent_id: str, body: CheckIn) -> dict:
    """Replay the access decision for one agent without changing anything.
    Shared by the page and Copilot; anyone who may view the page."""
    require_permission(request, "view")
    from maverick import agent_trust

    if not agent_trust.valid_agent_id(agent_id):
        raise HTTPException(status_code=404, detail="That agent is not on the list.")
    try:
        if body.direction == "outbound":
            decision = agent_trust.decide_outbound(agent_id, enforced=True)
        else:
            decision = agent_trust.decide_inbound(agent_id, requested_tools=body.tools,
                                                  max_risk=body.risk, enforced=True)
    except agent_trust.AgentTrustError as exc:
        raise HTTPException(status_code=503, detail="The list of outside agents could not be read.") from exc
    return {"allowed": bool(decision.allowed),
            "reason": _REASONS.get(decision.rule, "This agent would be turned away."
                                   if not decision.allowed else "This agent would be let in.")}


@router.post("/agents/{agent_id}/check")
async def check_agent(request: Request, agent_id: str, body: CheckIn) -> dict:
    return await run_in_threadpool(check_access, request, agent_id, body)


def _not_recorded() -> HTTPException:
    return HTTPException(status_code=503, detail=_UNRECORDED)


def apply_agent_limits(request: Request, agent_id: str, body: AgentLimitsIn) -> None:
    """Change an app-managed agent's limits, keeping its connection tokens,
    expiry, block state and security key (unless ``remove_key``). Shared by
    the page and Copilot: workspace administrators only, in the caller's
    workspace, with the audit row written before the change is saved."""
    require_permission(request, "admin")
    from maverick import agent_trust
    from maverick.audit import AuditRefused

    actor = _actor(request)

    def write() -> None:
        if not agent_trust.valid_agent_id(agent_id):
            raise HTTPException(status_code=404, detail="That agent is not on the list.")
        pubkey = (body.pubkey or "").strip()
        if pubkey and body.remove_key:
            raise HTTPException(status_code=422, detail="Paste a new security key or remove the one on file, not both.")
        if pubkey and not agent_trust._PUBKEY_RE.fullmatch(pubkey):
            raise HTTPException(status_code=422, detail="That security key is not valid.")
        with agent_trust._managed_locked():
            entries = agent_trust._load_managed()
            current = next((dict(e) for e in entries if str(e.get("id") or "") == agent_id), None)
            if current is None:
                raise HTTPException(
                    status_code=404,
                    detail="This agent was set up by your installation and can't be edited here.")
            update = body.model_dump(exclude={"remove_key"})
            update["pubkey"] = pubkey or ("" if body.remove_key else str(current.get("pubkey") or ""))
            for key in _EDITABLE:
                current.pop(key, None)
            current.update({k: v for k, v in update.items() if v not in (None, "", [], {})})
            current["id"] = agent_id
            if agent_trust._agent_from_entry(current) is None:
                raise HTTPException(status_code=422, detail="Some of the limits are not valid.")
            kept = [e for e in entries if str(e.get("id") or "") != agent_id]
            kept.append(current)
            agent_trust.record_change("limits_changed", agent_id, actor)
            agent_trust._save_managed(kept)

    try:
        write()
    except (AuditRefused, agent_trust.ChangeNotRecorded) as exc:
        raise _not_recorded() from exc
    except agent_trust.AgentTrustError as exc:
        raise HTTPException(status_code=503, detail="The list of outside agents could not be saved.") from exc


def register_agent(request: Request, body: BaseModel) -> str:
    """Add (or replace) an app-managed agent. Shared by the page and Copilot:
    workspace administrators only, audit row first. Returns its id."""
    require_permission(request, "admin")
    from maverick import agent_trust
    from maverick.audit import AuditRefused

    try:
        return agent_trust.put_agent(body.model_dump(), actor=_actor(request)).id
    except (AuditRefused, agent_trust.ChangeNotRecorded) as exc:
        raise _not_recorded() from exc
    except agent_trust.AgentTrustError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def set_agent_blocked(request: Request, agent_id: str, blocked: bool) -> None:
    """Block or unblock an app-managed agent (same checks as
    :func:`register_agent`). Unblocking is refused while security has
    contained the agent."""
    require_permission(request, "admin")
    from maverick import agent_trust
    from maverick.audit import AuditRefused
    from maverick.revocation import ProtectedRevocationError, shared

    actor = _actor(request)
    try:
        changed = (
            agent_trust.set_revoked(agent_id, True, actor=actor)
            if blocked
            else shared().run_if_unprotected(
                f"agent:{agent_id}",
                lambda: agent_trust.set_revoked(agent_id, False, actor=actor),
            )
        )
    except (AuditRefused, agent_trust.ChangeNotRecorded) as exc:
        raise _not_recorded() from exc
    except ProtectedRevocationError as exc:
        raise HTTPException(
            status_code=409,
            detail="agent is security-contained; use the control-plane release",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="containment authority is unavailable; restore refused",
        ) from exc
    if not changed:
        raise HTTPException(
            status_code=404,
            detail="this agent is defined in the server's config file, not in "
            "the app-managed registry. Register the same id here to "
            "override it, or ask your administrator to edit the config.",
        )


def remove_managed_agent(request: Request, agent_id: str) -> None:
    """Remove an app-managed agent (same checks as :func:`register_agent`)."""
    require_permission(request, "admin")
    from maverick import agent_trust
    from maverick.audit import AuditRefused

    try:
        removed = agent_trust.remove_agent(agent_id, actor=_actor(request))
    except (AuditRefused, agent_trust.ChangeNotRecorded) as exc:
        raise _not_recorded() from exc
    except agent_trust.RevokedAgentRemovalRefused as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if not removed:
        raise HTTPException(
            status_code=404,
            detail="this agent is not in the app-managed registry (it may be "
            "defined in the server's config file).",
        )


@router.put("/agents/{agent_id}")
async def update_agent(request: Request, agent_id: str, body: AgentLimitsIn) -> dict:
    await run_in_threadpool(apply_agent_limits, request, agent_id, body)
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
    return str(auth.caller_principal(request) or "authorized-local-operator")


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
