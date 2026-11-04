"""Current account/container choices and dated native event-source previews."""
from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request
from maverick import automation_connected_events as native
from maverick import automation_events, connections, crypto_at_rest
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from .draft_api import context_for
from .plain_labels import datetime_text

router = APIRouter(prefix="/connected-event-sources", tags=["connected-event-sources"])
NOTICE = ("Checking reads only the selected source. Review the dated snapshot and current account before creating the automation. "
          "Items already seen during the preview are remembered; later arrivals can start the chosen work once armed. "
          "This does not confirm future event delivery. Each check reads at most 32 pages and 5,000 items; larger sources are refused without advancing their position.")


class Choices(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    source: str = Field(min_length=1, max_length=64)
    connection: str = Field(min_length=1, max_length=64)
    selection: dict = Field(default_factory=dict, max_length=4)


class PickerIn(Choices):
    step: str = Field(pattern=r"^(sites|drives|folders|teams|channels)$")


class OriginalIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    review_token: str = Field(min_length=1, max_length=3000000)
    name: str = Field(min_length=1, max_length=48)
    template: str = Field(default="", max_length=128)
    flow: str = Field(default="", max_length=128)
    params: dict[str, str] = Field(default_factory=dict, max_length=128)
    interval_seconds: int = Field(default=0, ge=0, le=86400)


class OriginalReadIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    original_token: str = Field(min_length=1, max_length=3000000)


def authority(request, context=None):
    auth.require_permission(request, "admin")
    actor = auth.caller_principal(request)
    if not actor:
        raise HTTPException(403, "Sign in to your workspace before choosing a private connected account.")
    from maverick.paths import current_tenant_id_strict
    tenant = current_tenant_id_strict()
    if not tenant:
        raise HTTPException(409, "Select your workspace before reviewing this source.")
    from maverick.tenant.registry import assert_tenant_active
    assert_tenant_active(tenant)
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, "Your account, workspace or access changed. Review the source again.")
    return actor, current


def call(function):
    try:
        return function()
    except HTTPException:
        raise
    except (automation_events.EventSourceError, PermissionError, ValueError, connections.ConnectionVersionConflict) as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "The connected source could not be checked. Review its connection and try again; nothing was armed.") from exc


def catalog(request):
    actor, context = authority(request)
    saved = []
    if connections.enabled():
        for row in connections.list_connections():
            current = connections.get_connection(row["name"])
            if current and connections._may_use(current, actor) and current.get("token"):
                sources = [name for name, spec in native.SOURCES.items() if spec["connector"] == current.get("connector")]
                for source in sources:
                    try:
                        base = native.origin(source, current.get("base_url"))
                    except (automation_events.EventSourceError, ValueError):
                        continue
                    saved.append({"value": row["name"], "label": row["name"].replace("-", " "), "source": source, "destination": base})
    authority(request, context)
    return {"context": context, "sources": [{"value": name, "label": spec["label"]} for name, spec in native.SOURCES.items()], "connections": saved,
            "objects": [{"value": key, "label": value} for key, value in native.OBJECTS.items()], "tables": [{"value": key, "label": value} for key, value in native.TABLES.items()], "notice": NOTICE}


def binding(request, choices):
    actor, context = authority(request, choices.context)
    if not automation_events.enabled():
        raise HTTPException(403, "Event automations are turned off. An administrator can turn them on in Settings.")
    if choices.source not in native.SOURCES:
        raise HTTPException(422, "Choose a supported connected-system event.")
    row = connections.get_connection(choices.connection)
    spec = native.SOURCES[choices.source]
    if not connections.enabled() or not row or not connections._may_use(row, actor) or not row.get("token") or row.get("connector") != spec["connector"]:
        raise HTTPException(409, "This account is unavailable to you. Select a current account in Connections.")
    selected = ({"site": "pending", "drive": "pending", "folder": "root"} if choices.source == "sharepoint_files" else
                {"team": "pending", "channel": "pending"} if choices.source == "teams_messages" else
                {"object": "Opportunity", "closed_only": False} if choices.source == "salesforce_records" else {"table": "incident"})
    cfg = {"connection": row["name"], "revision": row["revision"], "connector": spec["connector"], "origin": native.origin(choices.source, row["base_url"]), "selection": selected}
    cfg["_lightwork_authority_check"] = lambda: authority(request, context)
    return actor, cfg


def pick(request, choices):
    actor, cfg = binding(request, choices)
    source, selected = choices.source, choices.selection
    def esc(value):
        return quote(native.identifier(value), safe="")
    if source == "sharepoint_files":
        if choices.step == "sites" and not selected:
            path = "/v1.0/sites?search=*"
        elif choices.step == "drives" and set(selected) == {"site"}:
            path = "/v1.0/sites/" + esc(selected["site"]) + "/drives"
        elif choices.step == "folders" and set(selected) in ({"drive"}, {"drive", "folder"}):
            parent = selected.get("folder", "root")
            suffix = "root" if parent == "root" else "items/" + esc(parent)
            path = "/v1.0/drives/" + esc(selected["drive"]) + "/" + suffix + "/children?$top=200"
        else:
            raise HTTPException(422, "Choose the site, then the library and folder.")
    elif source == "teams_messages":
        if choices.step == "teams" and not selected:
            path = "/v1.0/me/joinedTeams"
        elif choices.step == "channels" and set(selected) == {"team"}:
            path = "/v1.0/teams/" + esc(selected["team"]) + "/channels"
        else:
            raise HTTPException(422, "Choose the team, then the channel.")
    else:
        raise HTTPException(422, "This source uses the named record choices in the form.")
    with connections.bind_principal(actor):
        rows = native.collection(source, cfg, path)
        connections.resolve_named(cfg["connection"], expected_revision=cfg["revision"], connector=cfg["connector"], origin=cfg["origin"])
    if choices.step == "folders":
        rows = [row for row in rows if row.get("folder") is not None]
    result = [{"value": native.identifier(row.get("id")), "label": str(row.get("displayName") or row.get("name") or "Unnamed item")[:200]} for row in rows]
    authority(request, choices.context)
    return {"context": choices.context, "choices": result}


def preview(request, choices):
    actor, cfg = binding(request, choices)
    cfg["selection"] = native.selection(choices.source, choices.selection)
    labels = {}
    with connections.bind_principal(actor):
        if choices.source == "sharepoint_files":
            site = native.read_json(choices.source, cfg, "/v1.0/sites/" + quote(cfg["selection"]["site"], safe=""))
            drives = native.collection(choices.source, cfg, "/v1.0/sites/" + quote(cfg["selection"]["site"], safe="") + "/drives")
            drive = next((row for row in drives if row.get("id") == cfg["selection"]["drive"]), None)
            if not drive:
                raise HTTPException(409, "The selected library is no longer in this site. Choose it again.")
            folder = {"name": "Library root"} if cfg["selection"]["folder"] == "root" else native.read_json(choices.source, cfg, "/v1.0/drives/" + quote(cfg["selection"]["drive"], safe="") + "/items/" + quote(cfg["selection"]["folder"], safe=""))
            if cfg["selection"]["folder"] != "root" and folder.get("folder") is None:
                raise HTTPException(409, "Choose a folder in the selected library.")
            labels = {"Site": site.get("displayName") or site.get("name"), "Library": drive.get("name"), "Folder": folder.get("name")}
        elif choices.source == "teams_messages":
            team = native.read_json(choices.source, cfg, "/v1.0/teams/" + quote(cfg["selection"]["team"], safe=""))
            channels = native.collection(choices.source, cfg, "/v1.0/teams/" + quote(cfg["selection"]["team"], safe="") + "/channels")
            channel = next((row for row in channels if row.get("id") == cfg["selection"]["channel"]), None)
            if not channel:
                raise HTTPException(409, "The selected channel is no longer in this team. Choose it again.")
            labels = {"Team": team.get("displayName"), "Channel": channel.get("displayName")}
        elif choices.source == "salesforce_records":
            labels = {"Records": native.OBJECTS[cfg["selection"]["object"]], "When": "First observed as closed" if cfg["selection"]["closed_only"] else "New records"}
        else:
            labels = {"Tickets": native.TABLES[cfg["selection"]["table"]]}
        rows, id_field, _date = native.read_items(choices.source, cfg)
        connections.resolve_named(cfg["connection"], expected_revision=cfg["revision"], connector=cfg["connector"], origin=cfg["origin"])
    ids = [str(row.get(id_field) or "") for row in rows]
    if any(not value or len(value) > 512 for value in ids) or len(set(ids)) != len(ids):
        raise HTTPException(409, "The source's item identities could not be verified. Nothing was armed.")
    cfg.pop("_lightwork_authority_check")
    cfg["baseline"] = automation_events._encode_cursor("connected_app", sorted(hashlib.sha256(value.encode()).hexdigest() for value in ids))
    now = time.time()
    reviewed = {"purpose": "connected-event-source-preview-v1", "source": choices.source, "context": choices.context, "config": cfg, "expires": now + 600}
    token = crypto_at_rest.seal_to_str(json.dumps(reviewed, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "Enable stored-data encryption before retaining this private source review.")
    authority(request, choices.context)
    return {"review_token": token, "source": choices.source, "checked_at": datetime_text(now), "account": choices.connection.replace("-", " "), "destination": cfg["origin"], "details": labels, "existing_items": len(rows), "sample_names": [str(row.get("name") or row.get("Name") or row.get("number") or row.get("CaseNumber") or row.get("subject") or row.get("Subject") or "Item")[:200] for row in rows[:5]], "notice": NOTICE}


def canonical_config(request, source, config, *, review_required=False):
    actor, context = authority(request)
    if review_required:
        if not isinstance(config, dict) or set(config) != {"review_token"}:
            raise HTTPException(409, "Check and review this connected source before creating the automation.")
        try:
            token = config["review_token"]
            if not isinstance(token, str) or not crypto_at_rest.is_sealed_str(token) or len(token) > 3000000:
                raise ValueError
            reviewed = json.loads(crypto_at_rest.unseal_from_str(token))
            if reviewed["purpose"] != "connected-event-source-preview-v1" or reviewed["source"] != source or reviewed["context"] != context or reviewed["expires"] <= time.time():
                raise ValueError
            cfg = native.validate(source, reviewed["config"])
        except (ValueError, KeyError, TypeError, automation_events.EventSourceError) as exc:
            raise HTTPException(409, "The source review expired or changed. Check it again before creating the automation.") from exc
    else:
        cfg = native.validate(source, config)
    with connections.bind_principal(actor):
        connections.resolve_named(cfg["connection"], expected_revision=cfg["revision"], connector=cfg["connector"], origin=cfg["origin"])
    authority(request, context)
    return cfg


def original(request, value):
    _actor, context = authority(request)
    try:
        if not crypto_at_rest.is_sealed_str(value.review_token):
            raise ValueError
        reviewed = json.loads(crypto_at_rest.unseal_from_str(value.review_token))
        if reviewed["purpose"] != "connected-event-source-preview-v1" or reviewed["context"] != context:
            raise ValueError
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(409, "This original source review is unavailable to your current account and workspace.") from exc
    from maverick.paths import current_tenant_id_strict

    from . import api, event_triggers_store
    row = event_triggers_store.get_trigger(event_triggers_store.slugify(value.name), tenant=current_tenant_id_strict())
    if row and row.get("owner", "") not in api._event_trigger_allowed_owners(request):
        raise HTTPException(404, "This original automation is unavailable to your account.")
    same = bool(row and row.get("source") == reviewed["source"] and row.get("config") == reviewed["config"]
                and (row.get("template") or "") == value.template and (row.get("flow") or "") == value.flow
                and (row.get("params") or {}) == value.params and int(row.get("interval_seconds") or 0) == value.interval_seconds)
    authority(request, context)
    return {"confirmed": same, "found": row is not None, "name": value.name,
            "message": "The exact reviewed source and selected work are saved. Reading did not create or check the source again. Future event delivery remains unconfirmed." if same else
            "The exact original save is unconfirmed. Nothing was created, rearmed or polled by reading this result. Refresh the automation list before deciding what to do next."}


@router.get("/catalog")
def get_catalog(request: Request):
    return call(lambda: catalog(request))


@router.post("/pickers")
def post_picker(request: Request, choices: PickerIn):
    return call(lambda: pick(request, choices))


@router.post("/preview")
def post_preview(request: Request, choices: Choices):
    return call(lambda: preview(request, choices))


@router.post("/original")
def post_original(request: Request, value: OriginalIn):
    return call(lambda: original(request, value))


@router.post("/original-plan")
def post_original_plan(request: Request, value: OriginalIn):
    _actor, context = authority(request)
    # Validate account/workspace ownership without sending, arming or polling.
    call(lambda: original(request, value))
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": "connected-event-original-plan-v1", "context": context, "request": value.model_dump()}, separators=(",", ":"), allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "This original creation plan could not be retained privately. Nothing was armed.")
    return {"original_token": token, "name": value.name}


@router.post("/original-read")
def post_original_read(request: Request, value: OriginalReadIn):
    _actor, context = authority(request)
    try:
        if not crypto_at_rest.is_sealed_str(value.original_token):
            raise ValueError
        plan = json.loads(crypto_at_rest.unseal_from_str(value.original_token))
        if plan["purpose"] != "connected-event-original-plan-v1" or plan["context"] != context:
            raise ValueError
        request_value = OriginalIn.model_validate(plan["request"])
    except (ValueError, KeyError, TypeError) as exc:
        raise HTTPException(409, "This original creation plan is unavailable to your current account and workspace.") from exc
    return call(lambda: original(request, request_value))
