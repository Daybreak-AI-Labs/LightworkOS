"""Ordinary complete reviews for saved remote Knowledge and native attachment."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from maverick import connections, crypto_at_rest
from maverick import knowledge_source_readers as readers
from maverick import knowledge_sources as native
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field

from . import auth, research_workspace_api, specialist_drafts, tools_ops_api
from .draft_api import context_for

router = APIRouter(prefix="/knowledge/sources", tags=["knowledge-sources"])
TTL = 600


class SourceChoice(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    kind: Literal["sharepoint", "onedrive", "drive", "confluence"]
    connection: str = Field(min_length=1, max_length=64)
    selection: dict[str, str] = Field(default_factory=dict, max_length=3)


class PickerIn(SourceChoice):
    step: Literal["sites", "drives", "folders", "spaces"]


class SaveIn(SourceChoice):
    name: str = Field(min_length=1, max_length=120)
    decision_id: str = Field(min_length=1, max_length=64)
    purpose: str = Field(min_length=1, max_length=64)
    interval_seconds: Literal[0, 3600, 21600, 86400] = 0
    max_dollars: float = Field(default=0, ge=0, le=100, allow_inf_nan=False)
    expected_revision: int = Field(default=0, ge=0)
    paused: bool = False


class BoundIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")


class RefreshIn(BoundIn):
    acknowledge_unknown: bool = False


class AttachIn(BoundIn):
    specialist: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
    acknowledge_previous: bool = False


class ApplyIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=2000000)
    confirmed: Literal[True]


def response(value, status=200):
    return JSONResponse(value, status_code=status, headers={"Cache-Control": "private, no-store"})


def authority(request, context=None, *, write=False):
    auth.require_permission(request, "admin")
    actor = auth.caller_principal(request)
    tenant = current_tenant_id_strict()
    if not actor or not tenant:
        raise HTTPException(403, "Sign in with a named account and select your Knowledge workspace.")
    from maverick import config
    from maverick.tenant.registry import assert_tenant_active

    from .scim_groups import active_for_principal
    if active_for_principal(actor) is False:
        raise HTTPException(403, "Your current account is inactive.")
    assert_tenant_active(tenant)
    if not native.enabled():
        raise HTTPException(404, "Turn on Knowledge and governed Knowledge access in Settings before adding remote sources.")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Current Knowledge settings could not be checked.")
    current = context_for(request)
    if context is not None and current != context:
        raise HTTPException(409, "Your account, workspace or access changed. Reload Knowledge sources.")
    if write:
        tools_ops_api.same_origin(request)
    return tenant, actor, current


def service(request, context=None, *, write=False):
    tenant, actor, current = authority(request, context, write=write)
    return native.KnowledgeSources(tenant, actor, registry=research_workspace_api._registry_service(request.app.state),
                                   authority=lambda: authority(request, current, write=write)), current


def call(function):
    try:
        return function()
    except HTTPException:
        raise
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except (ValueError, readers.SourceReadError, connections.ConnectionVersionConflict) as exc:
        raise HTTPException(409, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(503, "This source outcome could not be confirmed. Read its original; nothing will be repeated automatically.") from exc


def _binding(request, body, *, picking=False):
    _, actor, current = authority(request, body.context)
    account = connections.get_connection(body.connection)
    if (not connections.enabled() or not account or not account.get("token") or not connections._may_use(account, actor)
            or account.get("connector") != readers.SOURCES[body.kind]["connector"]):
        raise HTTPException(409, "Select a current permitted account from Connections.")
    pending = {"sharepoint": {"site": "pending", "drive": "pending", "folder": "root"},
               "onedrive": {"drive": "pending", "folder": "root"}, "drive": {"folder": "root"}, "confluence": {"space": "pending"}}
    chosen = {**pending[body.kind], **body.selection} if picking else body.selection
    chosen = readers.selection(body.kind, chosen)
    return {"kind": body.kind, "connection": account["name"], "revision": account["revision"], "connector": account["connector"],
            "origin": readers.origin(body.kind, account["base_url"]), "selection": chosen}, actor, current


def _seal(request, kind, prepared, changes):
    tenant, actor, current = authority(request, write=True)
    operation = secrets.token_hex(16)
    envelope = {"schema": "lightwork.knowledge-source-review.v1", "kind": kind, "tenant": tenant, "actor": actor,
                "context": current, "expires": time.time() + TTL, "operation": operation, "prepared": prepared}
    token = crypto_at_rest.seal_to_str(json.dumps(envelope, sort_keys=True, allow_nan=False))
    if not crypto_at_rest.is_sealed_str(token):
        raise HTTPException(503, "Enable at-rest encryption before retaining a complete Knowledge source review.")
    return {"context": current, "operation": operation, "token": token, "changes": changes, "notice": native.notice()}


def _preparation_review(value):
    return {"How search is prepared": value["price_basis"], "Maximum preparation cost in USD": value["max_dollars"],
            "Current preparation model": value["identity"].get("model", "Local search preparation")}


def _source_review(row):
    plan = row["plan"]
    return {"Source name": row["name"], "Saved account": plan["binding"]["connection"], "Destination": plan["binding"]["origin"],
            "Selected folder or space": plan["binding"]["selection"], "Actual approved asset": plan["asset_id"],
            "Approved use decision": plan["decision_id"], "Purpose": plan["purpose"], "Refresh state": row["state"],
            "Schedule": {0: "Manual only", 3600: "Hourly", 21600: "Every six hours", 86400: "Daily"}[plan["interval_seconds"]],
            "Scheduled refreshes paused": row["paused"], "Maximum preparation cost in USD": plan["max_dollars"],
            "Imported documents or pages": row["item_count"], "Dataset approval": row["registry_state"],
            "Exact dataset version": row["reference"], "Earlier active original": row["active_job"]}


def _publish_link(name, original):
    if original.get("confirmed") and re.fullmatch(r"SPD-[a-f0-9]{32}", str(original.get("draft") or "")):
        return "/agents?name=" + name + "&specialist_draft=" + original["draft"] + "#specialist-drafts"
    return None


def _open(request, token, *, original=False):
    tenant, actor, context = authority(request, write=not original)
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError("The source review is not sealed.")
        value = json.loads(crypto_at_rest.unseal_from_str(token))
    except Exception as exc:
        raise HTTPException(409, "The complete source review is unavailable. Read current source history.") from exc
    if (not isinstance(value, dict) or value.get("schema") != "lightwork.knowledge-source-review.v1" or value.get("tenant") != tenant
            or value.get("actor") != actor or value.get("context") != context or not re.fullmatch(r"[a-f0-9]{32}", str(value.get("operation") or ""))):
        raise HTTPException(409, "This source review belongs to another account or workspace.")
    if not original and (type(value.get("expires")) not in {int, float} or not time.time() < value["expires"] <= time.time() + TTL):
        raise HTTPException(409, "The complete source review expired. Read its original before a new intent.")
    return value


@router.get("")
def catalog(request: Request):
    def action():
        current, context = service(request)
        accounts = []
        if connections.enabled():
            for row in connections.list_connections():
                record = connections.get_connection(row["name"])
                if not record or not record.get("token") or not connections._may_use(record, current.actor):
                    continue
                for kind, spec in readers.SOURCES.items():
                    if record.get("connector") == spec["connector"]:
                        try:
                            destination = readers.origin(kind, record.get("base_url"))
                        except readers.SourceReadError:
                            continue
                        accounts.append({"kind": kind, "value": record["name"], "label": record["name"].replace("-", " "), "destination": destination})
        decisions = research_workspace_api._data_use_choices(current.tenant)
        choices = [row for row in decisions["items"] if row["action"] == "analyze"]
        from maverick import domain
        specialists = [{"value": name, "label": profile.description or name.replace("_", " ")} for name, profile in sorted(domain.available_domains().items())
                       if auth.domain_suites_allowed(request, name)]
        authority(request, context)
        return response({"context": context, "sources": current.catalog(), "accounts": accounts,
                         "kinds": [{"value": name, "label": spec["label"]} for name, spec in readers.SOURCES.items()],
                         "permissions": choices, "permission_state": decisions["state"], "specialists": specialists, "notice": native.notice()})
    return call(action)


@router.post("/pick")
def picker(request: Request, body: PickerIn):
    def action():
        cfg, actor, context = _binding(request, body, picking=True)
        rows = readers.picker(cfg, actor, body.step, body.selection, lambda: authority(request, context))
        authority(request, context)
        return response({"context": context, "items": rows})
    return call(action)


@router.post("/save-review")
def save_review(request: Request, body: SaveIn):
    def action():
        current, _ = service(request, body.context, write=True)
        cfg, _, _ = _binding(request, body)
        choice = next((row for row in research_workspace_api._data_use_choices(current.tenant)["items"] if row["decision_id"] == body.decision_id), None)
        if choice is None:
            raise HTTPException(409, "This actual data-use approval is no longer current. Select its current decision.")
        plan = native.canonical_plan(current.tenant, current.actor, {"name": body.name, "binding": cfg, "decision_id": choice["decision_id"],
                                     "decision_sha256": choice["decision_sha256"], "purpose": body.purpose,
                                     "interval_seconds": body.interval_seconds, "max_dollars": body.max_dollars}, current.registry)
        identifier = native.source_id(current.tenant, current.actor, plan["asset_id"])
        existing = current.sources.get(identifier)
        if existing and existing["revision"] != body.expected_revision and (existing["plan_sha256"] != native.digest(plan) or existing.get("paused") != body.paused):
            raise HTTPException(409, "This source is already saved. Open its current settings before changing it.")
        prepared = {"plan": plan, "source": identifier, "expected_revision": body.expected_revision, "paused": body.paused}
        changes = {"Decision": "Save source settings", "Source name": plan["name"], "Account and destination": {"Account": cfg["connection"], "Destination": cfg["origin"], "Source": readers.SOURCES[cfg["kind"]]["label"], "Chosen container": cfg["selection"]},
                   "Actual approved use": {"Asset": plan["asset_id"], "Decision": plan["decision_id"], "Purpose": plan["purpose"], "Action": "Analyze only"},
                   "Refresh": {"Schedule": {0: "Manual only", 3600: "Hourly", 21600: "Every six hours", 86400: "Daily"}[plan["interval_seconds"]], "Paused": body.paused, "Maximum AI search preparation cost per refresh in USD": plan["max_dollars"]},
                   "Consequences": "Saves this complete source plan. No remote documents are read or approved by this save. Scheduled refreshes use this owner and current grants; imported versions require a separate registry reviewer. Specialist publication remains a separate complete review.", "Limits": native.notice()}
        return response(_seal(request, "save", prepared, changes))
    return call(action)


@router.get("/{identifier}/history")
def history(request: Request, identifier: str, offset: int = Query(default=0, ge=0, le=native.MAX_JOBS)):
    return call(lambda: response(service(request)[0].history(identifier, offset=offset)))


@router.get("/originals/{identifier}")
def original_refresh(request: Request, identifier: str):
    return call(lambda: response(service(request)[0].original_job(identifier)))


@router.post("/{identifier}/refresh-review")
def refresh_review(request: Request, identifier: str, body: RefreshIn):
    def action():
        current, _ = service(request, body.context, write=True)
        prepared = current.refresh_review(identifier)
        prepared["acknowledge_unknown"] = body.acknowledge_unknown
        changes = {"Decision": "Refresh saved source", "Complete current source": _source_review(current.public(current.owned(identifier))),
                   "Dated remote file inventory": {"Checked at": prepared["snapshot_at"], "Items": prepared["inventory"]},
                   "Current AI search preparation and limit": _preparation_review(prepared["embedding"]), "Earlier uncertain refresh": prepared["previous"],
                   "Earlier uncertainty acknowledged as a separate new intent": body.acknowledge_unknown, "Limits": native.notice()}
        return response(_seal(request, "refresh", prepared, changes))
    return call(action)


@router.post("/{identifier}/attachment-review")
def attachment_review(request: Request, identifier: str, body: AttachIn):
    def action():
        current, context = service(request, body.context, write=True)
        row = current.owned(identifier)
        current._plan_guard(row["plan"])
        if row["plan"]["purpose"] != "product_research":
            raise HTTPException(409, "Specialists use company Knowledge for product research. Choose an actual product research approval before attaching this source.")
        state = specialist_drafts.inventory(request, body.specialist)
        profile = state["current"]
        if profile is None:
            raise HTTPException(409, "Choose a current specialist before adding Knowledge.")
        selectors = list(profile.get("knowledge_sources") or [])
        asset = row["plan"]["asset_id"]
        if asset not in selectors:
            selectors.append(asset)
        prepared = specialist_drafts.prepare(request, body.specialist, "save", entered={"knowledge_sources": selectors},
                                               title="Knowledge: " + row["plan"]["name"][:100], context=context,
                                               acknowledge_previous=body.acknowledge_previous)
        changes = {"Decision": "Save a complete specialist attachment draft", "Source": _source_review(current.public(row)),
                   "Complete specialist draft review": specialist_drafts.changes(request, prepared),
                   "Publication boundary": "Confirming only retains this complete draft. Open its existing Publish review to change the specialist in use. Current account and data-use rights remain required for each Knowledge use."}
        return response(_seal(request, "attach", {"source": identifier, "source_plan": row["plan_sha256"], "draft": prepared}, changes))
    return call(action)


@router.post("/apply")
def apply(request: Request, body: ApplyIn):
    def action():
        value = _open(request, body.token)
        current, _ = service(request, value["context"], write=True)
        prepared, kind = value["prepared"], value["kind"]
        if kind == "save":
            result = current.save(prepared["plan"], expected_revision=prepared["expected_revision"], paused=prepared["paused"], operation=value["operation"])
            return response({"kind": kind, **result})
        if kind == "refresh":
            job = current.start(prepared, value["operation"], acknowledge_unknown=prepared["acknowledge_unknown"])
            if job.get("state") == "queued":
                from .knowledge_sources_scheduler import wake
                wake()
            return response({"kind": kind, "job": job, "message": job["message"]}, 202)
        if kind == "attach":
            row = current.owned(prepared["source"])
            current._plan_guard(row["plan"])
            if row["plan_sha256"] != prepared["source_plan"]:
                raise HTTPException(409, "The selected source changed. Review its attachment again.")
            original = specialist_drafts.apply(request, prepared["draft"], value["operation"])
            return response({"kind": kind, "draft": original, "message": original["message"],
                             "publish": _publish_link(prepared["draft"]["name"], original)})
        raise HTTPException(409, "This source review has an unsupported decision.")
    return call(action)


@router.post("/read-original")
def read_original(request: Request, body: ApplyIn):
    def action():
        value = _open(request, body.token, original=True)
        current, _ = service(request, value["context"])
        if value["kind"] == "save":
            return response({"kind": "save", **current.original_save(value["operation"])})
        if value["kind"] == "refresh":
            identifier = "KNJ-" + value["operation"]
            if current.jobs.get(identifier) is None:
                return response({"kind": "refresh", "message": "No retained refresh receipt was found. Admission may be incomplete; inspect current source history before a separately reviewed request."})
            return response({"kind": "refresh", "job": current.original_job(identifier), "message": "Read the original refresh. No documents were fetched or reindexed by this read."})
        if value["kind"] == "attach":
            original = specialist_drafts.original(request, value["operation"], prepared=value["prepared"]["draft"])
            return response({"kind": "attach", "draft": original, "message": original["message"],
                             "publish": _publish_link(value["prepared"]["draft"]["name"], original)})
        raise HTTPException(409, "This original decision is unavailable.")
    return call(action)
