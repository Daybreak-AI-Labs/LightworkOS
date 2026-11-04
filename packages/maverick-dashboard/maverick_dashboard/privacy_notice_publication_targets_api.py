"""Where approved privacy notices are published (publication targets).

The privacy notice publication runtime reads named targets from
``[privacy_automation.notice_governance.publication_runtime] bindings`` and the
workspaces allowed to publish from ``active_tenants``. This router lets a
global administrator list, add, change and remove those targets from the
Privacy notices page, writing the dashboard settings overlay. Every change is
checked with the runtime's own parser against the whole resulting section, so
a saved target can never leave the runtime unable to start; adding or changing
a target needs an explicit confirmation (it changes where notices go); each
change writes one ``setting_changed`` audit row. Targets set by the installer
can be changed here but not removed; targets set by the server's deployment
settings cannot be changed here.
"""
from __future__ import annotations

import copy
import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from . import auth

router = APIRouter(prefix="/api/v1/privacy/notice-publication/targets",
                   tags=["privacy-notice-publication"])

_PATH = ("privacy_automation", "notice_governance", "publication_runtime")
_ID = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"
_ID_RE = re.compile(_ID)
_FIELDS = ("tenant_id", "notice_id", "consent_publication_ref", "property_id",
           "rule_group_id", "rule_group_version", "notice_resource_id",
           "notice_resource_version")


class TargetIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = Field(min_length=1, max_length=128)
    notice_id: str = Field(pattern=_ID)
    consent_publication_ref: str = Field(pattern=_ID)
    property_id: str = Field(pattern=_ID)
    rule_group_id: str = Field(pattern=_ID)
    rule_group_version: int = Field(ge=1, le=2**31 - 1)
    notice_resource_id: str = Field(pattern=_ID)
    notice_resource_version: int = Field(ge=1, le=2**31 - 1)
    confirm: bool = False


class _Refused(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _section(tree: object) -> dict:
    node = tree
    for part in _PATH:
        node = node.get(part) if isinstance(node, dict) else None
    return node if isinstance(node, dict) else {}


def _layers() -> dict[str, dict]:
    from maverick import config

    from . import settings_store

    config.reset_config_cache()
    try:
        base = config._load_config_file(config.config_path())
    except Exception:  # an unreadable installer file offers no targets
        base = {}
    operator: dict = {}
    overlay_env = os.environ.get(config.CONFIG_OVERLAY_ENV, "").strip()
    if overlay_env:
        try:
            operator = config._load_config_file(Path(overlay_env).expanduser())
        except Exception:
            operator = {}
    return {"base": _section(base), "here": _section(settings_store.load_overlay()),
            "operator": _section(operator)}


def _bindings(section: dict) -> dict:
    value = section.get("bindings")
    return value if isinstance(value, dict) else {}


def _state() -> dict[str, Any]:
    layers = _layers()
    merged: dict[str, dict] = {}
    sources: dict[str, str] = {}
    for name, label in (("base", "installer"), ("here", "here"), ("operator", "deployment")):
        for binding_id, row in _bindings(layers[name]).items():
            if isinstance(row, dict):
                merged[binding_id] = {**merged.get(binding_id, {}), **row}
                sources[binding_id] = label
    tenants: list = []
    for name in ("base", "here", "operator"):
        if "active_tenants" in layers[name]:
            tenants = layers[name]["active_tenants"]
    targets = [
        {"binding_id": binding_id, **{k: row.get(k) for k in _FIELDS},
         "source": sources[binding_id], "locked": binding_id in _bindings(layers["operator"]),
         "removable": binding_id not in _bindings(layers["base"])
         and binding_id not in _bindings(layers["operator"])}
        for binding_id, row in sorted(merged.items())
    ]
    return {"targets": targets,
            "workspaces": [t for t in tenants if isinstance(t, str)] if isinstance(tenants, list)
            else []}


def _check(section: dict) -> None:
    """Run the publication runtime's own parser over the resulting settings."""
    from maverick import config

    from .privacy_notice_publication_composition import (
        PrivacyNoticePublicationCompositionError,
        settings_from_config,
    )

    loaded = copy.deepcopy(config.load_config() or {})
    node = loaded
    for part in _PATH[:-1]:
        node = node.setdefault(part, {})
    node[_PATH[-1]] = section
    try:
        settings_from_config(loaded)
    except PrivacyNoticePublicationCompositionError as exc:
        reason = _PLAIN.get(str(exc), "check the details and try again")
        raise _Refused(400, "This change can't be saved: " + reason + ".") from exc


# The runtime parser's refusals, in words for the page.
_PLAIN = {
    "tenant consent publication references must be unique":
        "each banner release can be used by only one target in a workspace",
    "every active publication tenant requires an exact binding":
        "every workspace that publishes notices needs a target",
    "enabled publication runtime requires active tenants and bindings":
        "publishing is on and needs at least one target; turn publishing off first",
    "publication binding tenant_id is invalid": "choose a valid workspace",
    "each publication binding must contain only the exact required fields":
        "fill in every detail of the target",
}


def _effective_section() -> dict:
    from maverick import config

    config.reset_config_cache()
    return copy.deepcopy(_section(config.load_config() or {}))


def _write(mutate) -> dict:
    """Apply ``mutate(runtime_table)`` to the overlay in one locked save and
    return the table as it was, so a refused audit can put it back."""
    from maverick import config

    from . import settings_store

    with settings_store._locked():
        data = settings_store._load_overlay_for_update()
        node = data
        for part in _PATH:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        previous = copy.deepcopy(node)
        mutate(node)
        settings_store._write(data)
    config.reset_config_cache()
    return previous


def _restore(previous: dict) -> None:
    def put_back(node: dict) -> None:
        node.clear()
        node.update(previous)

    _write(put_back)


async def _record(request: Request, previous: dict, binding_id: str, old: object, new: object,
                  confirmed: bool) -> None:
    """One audit row; a refused audit undoes the change."""
    from maverick.audit import AuditRefused

    try:
        await run_in_threadpool(_audit, request, binding_id, old, new, confirmed)
    except AuditRefused as exc:
        await run_in_threadpool(_restore, previous)
        raise HTTPException(status_code=503,
                            detail="The change could not be recorded, so it was undone.") from exc


def _audit(request: Request, binding_id: str, old: object, new: object, confirmed: bool) -> None:
    from maverick.audit import EventKind, audit_event

    audit_event(
        EventKind.SETTING_CHANGED,
        agent="dashboard",
        _global=True,
        actor=auth.caller_principal(request) or "local administrator",
        section=".".join((*_PATH, "bindings")),
        key=binding_id,
        old=old,
        new=new,
        confirmed=confirmed,
    )


def _save(binding_id: str, body: TargetIn) -> tuple[dict | None, dict, dict]:
    from maverick.paths import canonical_tenant_id

    if not _ID_RE.fullmatch(binding_id):
        raise _Refused(400, "Give the publishing target a short name made of letters, "
                            "numbers, dots, dashes or colons.")
    try:
        tenant = canonical_tenant_id(body.tenant_id)
    except (TypeError, ValueError) as exc:
        raise _Refused(400, "Choose a valid workspace.") from exc
    layers = _layers()
    if binding_id in _bindings(layers["operator"]):
        raise _Refused(409, "This publishing target is set by your server's deployment "
                            "settings, so it can't be changed here.")
    row = {k: getattr(body, k) for k in _FIELDS}
    row["tenant_id"] = tenant
    section = _effective_section()
    old = _bindings(section).get(binding_id)
    bindings = {**_bindings(section), binding_id: row}
    tenants = [t for t in section.get("active_tenants", []) if isinstance(t, str)]
    if tenant not in tenants:
        tenants.append(tenant)
    _check({**section, "bindings": bindings, "active_tenants": tenants})
    return (dict(old) if isinstance(old, dict) else None), row, {"active_tenants": tenants}


@router.get("")
async def list_targets(request: Request) -> JSONResponse:
    auth.require_global_permission(request, "admin")
    return JSONResponse(await run_in_threadpool(_state), headers={"Cache-Control": "no-store"})


@router.put("/{binding_id}")
async def save_target(request: Request, binding_id: str, body: TargetIn) -> JSONResponse:
    from .app import _require_same_origin

    _require_same_origin(request)
    auth.require_global_permission(request, "admin")
    try:
        old, row, extra = await run_in_threadpool(_save, binding_id, body)
    except _Refused as exc:
        return JSONResponse({"detail": exc.message}, status_code=exc.status)
    if old == row:
        return JSONResponse({"changed": False, **await run_in_threadpool(_state)})
    if not body.confirm:
        return JSONResponse(
            {"detail": "confirmation required",
             "confirm": "Approved notices will be published to this target."},
            status_code=409,
        )

    def mutate(node: dict) -> None:
        node.setdefault("bindings", {})
        if not isinstance(node["bindings"], dict):
            node["bindings"] = {}
        node["bindings"][binding_id] = row
        node["active_tenants"] = extra["active_tenants"]

    previous = await run_in_threadpool(_write, mutate)
    await _record(request, previous, binding_id, old, row, True)
    return JSONResponse({"changed": True, **await run_in_threadpool(_state)})


def _remove(binding_id: str) -> tuple[dict, list]:
    layers = _layers()
    if binding_id in _bindings(layers["operator"]):
        raise _Refused(409, "This publishing target is set by your server's deployment "
                            "settings, so it can't be removed here.")
    if binding_id in _bindings(layers["base"]):
        raise _Refused(409, "This publishing target was set by your installer, so it can be "
                            "changed here but not removed.")
    section = _effective_section()
    bindings = dict(_bindings(section))
    old = bindings.pop(binding_id, None)
    if not isinstance(old, dict):
        raise _Refused(404, "That publishing target does not exist.")
    tenant = old.get("tenant_id")
    tenants = [t for t in section.get("active_tenants", []) if isinstance(t, str)]
    if tenant in tenants and not any(isinstance(b, dict) and b.get("tenant_id") == tenant
                                     for b in bindings.values()):
        tenants.remove(tenant)
    _check({**section, "bindings": bindings, "active_tenants": tenants})
    return old, tenants


@router.delete("/{binding_id}")
async def remove_target(request: Request, binding_id: str) -> JSONResponse:
    from .app import _require_same_origin

    _require_same_origin(request)
    auth.require_global_permission(request, "admin")
    try:
        old, tenants = await run_in_threadpool(_remove, binding_id)
    except _Refused as exc:
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    def mutate(node: dict) -> None:
        bindings = node.get("bindings")
        if isinstance(bindings, dict):
            bindings.pop(binding_id, None)
            if not bindings:
                node.pop("bindings", None)
        node["active_tenants"] = tenants

    previous = await run_in_threadpool(_write, mutate)
    await _record(request, previous, binding_id, old, None, False)
    return JSONResponse({"changed": True, **await run_in_threadpool(_state)})


__all__ = ["router"]
