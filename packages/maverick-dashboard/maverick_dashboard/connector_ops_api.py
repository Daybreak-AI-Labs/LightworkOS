"""Tool servers from the registry and governed connectors, as buttons
(``maverick mcp-registry add`` with a look first, ``connectors list`` /
``simulate`` / ``plan``).

* Tool server registry: before a server is added, the page shows the exact
  program it starts (or the web address it connects to), and -- only when the
  person asks and confirms -- starts it once to list the tools it offers.
  Adding still goes through ``/api/v1/mcp-registry/add`` with the same
  installation ``admin`` + same-origin rules as the other Tool servers routes.
* Governed connectors: the systems of record Lightwork may change, and a
  preview of one change -- its effect, risk, whether an approver is needed and
  whether it could be undone -- WITHOUT making it. Planning may read the
  record's current values once (the kernel's GET-only restore read).

All routes need the installation ``admin`` permission: connectors and tool
servers are installation-wide and run with the installation's credentials.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission
from .tools_ops_api import record, same_origin, technical

router = APIRouter(prefix="/api/v1")


# ---- Tool server registry: look before adding ------------------------------

def spec_fingerprint(spec_dict: dict) -> str:
    """A fingerprint of a registry server's full details, so what is added is
    exactly what the person looked at."""
    blob = json.dumps(spec_dict, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class RegistryNameIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)


class RegistryProbeIn(RegistryNameIn):
    fingerprint: str = Field(min_length=64, max_length=64)
    confirm: bool = False


def _registry_spec(name: str):
    from maverick import mcp_registry
    try:
        return mcp_registry.install_mcp_from_registry(name)
    except Exception as exc:  # noqa: BLE001 -- unsafe and unreadable entries read the same
        try:
            listed = any(entry.name == name for entry in mcp_registry.load_mcp_registry())
        except Exception:  # noqa: BLE001 -- an unreadable registry is not "not found"
            listed = True
        if not listed:
            raise HTTPException(409, "That server was not found in the registry. Show the available "
                                     "servers again and choose one from the list.") from exc
        raise HTTPException(409, "Registry server installation is unavailable until publisher "
                                 "authentication is implemented. Independently review and configure the server.") from exc


@router.post("/mcp-registry/preview")
async def registry_preview(body: RegistryNameIn, request: Request) -> dict:
    require_global_permission(request, "admin")
    spec = await run_in_threadpool(_registry_spec, body.name)
    return {
        "name": spec.name, "online": spec.is_http,
        "address": spec.url or "", "program": "" if spec.is_http else spec.command,
        "arguments": [] if spec.is_http else [str(a)[:400] for a in spec.args[:50]],
        "settings": sorted(str(k)[:80] for k in (spec.env or {}))[:50],
        "extra_headers": sorted(str(k)[:80] for k in (spec.headers or {}))[:50],
        "program_checked": bool(spec.pin_sha256),
        # The program is handed every setting of this server (passwords and
        # keys included), not only the ones listed above.
        "gets_every_server_setting": bool(not spec.is_http and spec.inherit_env),
        "fingerprint": spec_fingerprint(spec.to_dict()),
    }


def _pinned_transport(spec):
    """An online server must be a public address, like every guarded fetch
    (``MAVERICK_FETCH_ALLOW_PRIVATE`` / ``[tools] fetch_allow_private`` allow
    internal ones). Registry entries come from outside this installation. The
    address is looked up once, here, and the probe connects to exactly that
    address, so a name that changes afterwards cannot move it inside."""
    from maverick.tools._ssrf import BlockedHost, pinned_async_transport
    try:
        return pinned_async_transport(spec.url or "")
    except BlockedHost as exc:
        raise HTTPException(422, "Lightwork will not contact this tool server: its web address is "
                                 "inside this server's own network, or cannot be found.") from exc


async def _list_tools(spec, transport=None) -> list[dict[str, str]]:
    from maverick.mcp_client import MCPClient, StreamableHttpMCPClient
    client = (StreamableHttpMCPClient(spec, timeout=8.0, transport=transport) if spec.is_http
              else MCPClient(spec, timeout=8.0))
    try:
        await asyncio.wait_for(client.start(), timeout=12.0)
        return [{"name": str(t.get("name") or "")[:120],
                 "description": str(t.get("description") or "")[:300]}
                for t in list(client.tools)[:100] if isinstance(t, dict)]
    finally:
        try:
            await client.stop()
        except Exception:  # noqa: BLE001 -- stopping a probe never fails the answer
            pass


@router.post("/mcp-registry/tools")
async def registry_tools(body: RegistryProbeIn, request: Request) -> dict:
    """Start the server once, ask which tools it offers, and stop it. Nothing
    is added."""
    same_origin(request)
    require_global_permission(request, "admin")
    if not body.confirm:
        raise HTTPException(422, "Confirm that Lightwork may start the tool server once.")
    spec = await run_in_threadpool(_registry_spec, body.name)
    if spec_fingerprint(spec.to_dict()) != body.fingerprint:
        raise HTTPException(409, "This tool server's details changed since you looked. Look again first.")
    transport = await run_in_threadpool(_pinned_transport, spec) if spec.is_http else None
    record(request, "mcp_registry_probe", installation=True, server=spec.name)
    try:
        tools = await _list_tools(spec, transport)
    except Exception as exc:  # noqa: BLE001 -- a probe failure is one plain answer
        raise HTTPException(502, "The tool server did not answer. Nothing was added.") from exc
    return {"tools": tools}


# ---- Governed connectors: list and preview a change ------------------------

_RISK = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
_CHANGE = {"create": "post", "update": "patch", "replace": "put", "delete": "delete"}
_FIELD = re.compile(r"[A-Za-z0-9_]{1,80}\Z")


def _configured():
    from maverick.governed_rest import configured_governed_actions
    return configured_governed_actions()


def _connectors() -> dict[str, Any]:
    from maverick.connector_previews import dialect_for, restore_points_enabled
    from maverick.governed_rest import available_rest_connectors, connector_rows
    ga, registered = _configured()
    rows = connector_rows(ga, registered) if registered else []
    return {
        "enabled": bool(registered),
        "available": available_rest_connectors(),
        "can_read_prior": bool(restore_points_enabled()),
        "connectors": [{
            "name": r["connector"],
            "change_risk": _RISK.get(str(r["write_risk"]), str(r["write_risk"]).capitalize()),
            "needs_approval": bool(r["write_requires_approval"]),
            "can_address_records": bool(dialect_for(r["connector"]).path_template),
        } for r in rows],
    }


@router.get("/governed-connectors")
async def governed_connectors(request: Request) -> dict:
    require_global_permission(request, "admin")
    return await run_in_threadpool(_connectors)


class FieldIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    value: str = Field(default="", max_length=2000)
    kind: Literal["text", "number", "yes_no", "empty"] = "text"


class ChangeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    connector: str = Field(min_length=1, max_length=40)
    change: Literal["create", "update", "replace", "delete"]
    record_type: str = Field(min_length=1, max_length=80)
    record_id: str = Field(default="", max_length=80)
    fields: list[FieldIn] = Field(default_factory=list, max_length=50)
    read_current_values: bool = False


def _value(f: FieldIn) -> Any:
    if f.kind == "empty":
        return None
    if f.kind == "yes_no":
        return f.value.strip().lower() in {"yes", "true", "1"}
    if f.kind == "number":
        try:
            number = float(f.value)
        except ValueError as exc:
            raise HTTPException(422, f"“{f.name}” needs a number.") from exc
        return int(number) if number.is_integer() else number
    return f.value


def _params(body: ChangeIn) -> dict:
    from maverick.connector_previews import dialect_for
    needs_record = body.change != "create"
    if needs_record == (not body.record_id.strip()):
        raise HTTPException(422, "Choose the record to change." if needs_record
                            else "A new record has no record number yet; leave it empty.")
    try:
        path = dialect_for(body.connector).path_for(body.record_type, body.record_id)
    except ValueError as exc:
        raise HTTPException(422, "Check the record type and record number.") from exc
    fields = {}
    for f in body.fields:
        if not _FIELD.fullmatch(f.name.strip()):
            raise HTTPException(422, "Field names may only use letters, numbers and underscores.")
        fields[f.name.strip()] = _value(f)
    if body.change != "delete" and not fields:
        raise HTTPException(422, "Add at least one field to change.")
    return {"op": _CHANGE[body.change], "path": path, "body": fields if body.change != "delete" else {}}


def _sentence(body: ChangeIn, params: dict) -> str:
    what = f"{body.record_type} record" + (f" {body.record_id}" if body.record_id else "")
    fields = ", ".join(sorted(params["body"])) or "no fields"
    verb = {"create": f"create a new {body.record_type} record with {fields}",
            "update": f"change {fields} on the {what}",
            "replace": f"replace the {what}, setting {fields}",
            "delete": f"delete the {what}"}[body.change]
    return f"Lightwork would {verb} in {body.connector.capitalize()}."


def _preview_change(body: ChangeIn) -> dict[str, Any]:
    from maverick.governed_actions import ActionError
    ga, registered = _configured()
    names = {str(k).strip().lower(): k for k in registered}
    key = body.connector.strip().lower()
    if key not in names:
        raise HTTPException(404, "That system is not connected.")
    params = _params(body)
    try:
        preview = ga.simulate(f"{names[key]}.write", params)
    except ActionError as exc:
        raise HTTPException(422, "Lightwork cannot preview that change. Check the details.") from exc
    out: dict[str, Any] = {
        "summary": _sentence(body, params), "risk": _RISK.get(preview.risk, preview.risk.capitalize()),
        "needs_approval": bool(preview.requires_approval), "changed_anything": False,
        "read_current_values": False, "technical": technical([preview.effect])}
    if body.read_current_values:
        from maverick.connector_previews import plan_write
        from maverick.governed_rest import GOVERNED_REST_FACTORIES
        plan = plan_write(GOVERNED_REST_FACTORIES[key](), params)
        card = plan.preview.card_view()
        out.update({
            "read_current_values": True, "can_undo": bool(card.get("reversible")),
            "money_at_stake": card.get("exposure_dollars"),
            "undo_note": ("Lightwork holds what it needs to undo this change." if card.get("reversible") else
                          "This change could not be undone automatically, so a person would have to approve it."),
            "technical": technical([preview.effect, plan.restore.detail, *plan.warnings]),
        })
    return out


@router.post("/governed-connectors/preview")
async def governed_connector_preview(body: ChangeIn, request: Request) -> dict:
    """Show what one change would do. Nothing is changed in the other system."""
    same_origin(request)
    require_global_permission(request, "admin")
    return await run_in_threadpool(_preview_change, body)


__all__ = ["router", "spec_fingerprint"]
