"""Named business fields with complete reviewed writes and pure originals."""
from __future__ import annotations

import json
import math
import time
import uuid
from typing import Literal

from fastapi import APIRouter, HTTPException, Request, Response
from maverick import crypto_at_rest, security_ops
from maverick import work_record_details as native
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordBackendError, RecordConflict
from pydantic import BaseModel, ConfigDict, Field

from . import auth, task_search
from .draft_api import context_for
from .task_model_selection_api import current_authority

router = APIRouter(prefix="/api/v1/work-details", tags=["business-details"])
_PURPOSE = "business-details-review.v1"
_TTL = 600
_ZERO = "0" * 64


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ChoicesIn(Closed):
    context: str = Field(pattern=r"^[0-9a-f]{64}$")
    kind: str = Field(max_length=40)
    query: str = Field(default="", max_length=256)
    cursor: str = Field(default="", max_length=2000)


class ReviewIn(ChoicesIn):
    record: str = Field(default="", max_length=64)
    mode: Literal["schema", "details"]
    expected_schema_revision: int = Field(ge=0)
    expected_details_revision: int = Field(ge=0)
    expected_source: str = Field(pattern=r"^[0-9a-f]{64}$")
    draft: dict


class OriginalIn(Closed):
    context: str = Field(pattern=r"^[0-9a-f]{64}$")
    token: str = Field(min_length=1, max_length=500000)


class SaveIn(OriginalIn):
    confirmed: Literal[True]


def context(request):
    current_authority(request)
    return task_search.context(request)


def _enabled():
    try:
        return native.enabled()
    except ValueError as exc:
        raise HTTPException(503, "Business details settings could not be read. Your draft is kept.") from exc


def _authority(request, kind, expected="", *, historical=False, define=False):
    from .app import require_page_visible

    if kind not in native.KINDS:
        raise HTTPException(422, "Choose a supported work category.")
    current = context(request)
    if expected and expected != current:
        raise HTTPException(409, "Your account, workspace or access changed. Reload the current business details.")
    page = "/goals" if kind == "task" else "/security/assurance"
    auth.require_page_permission(request, page)
    require_page_visible(request, page)
    require_page_visible(request, "/work-details")
    if define:
        auth.require_permission(request, "admin")
    if kind != "task" and not security_ops.enabled():
        raise HTTPException(403, "Security records are turned off. Your saved details have not been changed.")
    if not historical and not _enabled():
        raise HTTPException(403, "Business details are turned off. An administrator can turn them on in Settings.")
    return current


def _source(request, kind, target, *, edit=False):
    if not target:
        return None
    if kind == "task":
        from ._shared import _world

        try:
            number = int(target)
            if str(number) != target or number <= 0:
                raise ValueError
        except ValueError as exc:
            raise HTTPException(404, "This task is not available.") from exc
        world = _world()
        goal = world.get_goal(number)
        auth.assert_goal_access(request, goal)
        if edit:
            from maverick.task_handoffs import require_open

            require_open(world, number)
        return {"value": target, "label": goal.title, "status": str(goal.status),
                "revision": task_search._identity(goal)}
    stores = dict(security_ops._STORES)
    row = stores[kind].load(target)
    if row is None:
        raise HTTPException(404, "This record is not available.")
    return {"value": target, "label": _record_label(row),
            "status": str(row.get("status") or row.get("phase") or "Saved"),
            "revision": digest(row)}


def _record_label(row):
    return str(row.get("title") or row.get("name") or row.get("label")
               or row.get("control_id") or row.get("summary") or "Saved record")[:500]


def page_context(request):
    _authority(request, "task", historical=True)
    return {"work_details_context": context(request)}


def state(request, kind="task", record=""):
    current = _authority(request, kind, historical=True)
    source = _source(request, kind, record)
    schema, detail = native.read(kind, record)
    enabled = _enabled()
    _authority(request, kind, current, historical=True)
    if source != _source(request, kind, record):
        raise HTTPException(409, "The selected work changed during this read. Refresh before reviewing.")
    schema_value = native.schema_public(schema)
    return {"context": current, "enabled": enabled, "notice": native.NOTICE,
            "kind": kind, "kinds": [{"value": key, "label": label} for key, label in native.KINDS.items()],
            "schema": schema_value, "can_define": enabled and auth.has_permission(request, "admin"),
            "can_edit": enabled and source is not None,
            "source": source, "details": native.details_public(detail, schema_value),
            "original_notice": native.ORIGINAL_NOTICE}


def _sealed(value):
    result = crypto_at_rest.seal_to_str(json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
    if not crypto_at_rest.is_sealed_str(result):
        raise HTTPException(503, "The review could not be protected. Nothing was saved.")
    return result


def _review_token(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        keys = {"purpose", "owner", "actor", "context", "operation", "kind", "record", "mode",
                "schema", "details", "source", "draft", "summary", "expires"}
        if (not isinstance(value, dict) or set(value) != keys or value["purpose"] != _PURPOSE
                or type(value["expires"]) not in (int, float) or not math.isfinite(value["expires"])
                or value["kind"] not in native.KINDS or value["mode"] not in {"schema", "details"}):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise HTTPException(409, "This protected review is no longer available. Keep the draft and review it again.") from exc


def choices(request, body):
    current = _authority(request, body.kind, body.context)
    if body.kind == "task":
        value = task_search.page(request, body.query, cursor=body.cursor, expected=current, allow_empty=True)
        return {"context": current, "items": [{"value": str(goal.id), "label": goal.title, "status": str(goal.status)} for goal in value["goals"]],
                "cursor": value["continuation"], "complete": value["complete"], "notice": value["notice"]}
    rows = dict(security_ops._STORES)[body.kind].list_bounded(limit=10001)
    if len(rows) > 10000:
        raise HTTPException(409, "This category exceeds the current 10,000-record choice window. No incomplete list was substituted.")
    rows.sort(key=lambda row: (_record_label(row).casefold(), row["id"]))
    rows = [row for row in rows if body.query.strip().casefold() in _record_label(row).casefold()]
    start = 0
    inventory = digest(rows)
    if body.cursor:
        try:
            position = json.loads(crypto_at_rest.unseal_from_str(body.cursor))
            if (set(position) != {"purpose", "context", "kind", "query", "inventory", "start"}
                    or position["purpose"] != "business-details-choices.v1" or position["context"] != current
                    or position["kind"] != body.kind or position["query"] != body.query
                    or position["inventory"] != inventory or type(position["start"]) is not int
                    or not 0 <= position["start"] <= len(rows)):
                raise ValueError
            start = position["start"]
        except (ValueError, TypeError, KeyError) as exc:
            raise HTTPException(409, "The named records changed. Find current work again.") from exc
    selected = rows[start:start + 100]
    more = start + len(selected) < len(rows)
    cursor = _sealed({"purpose": "business-details-choices.v1", "context": current,
                      "kind": body.kind, "query": body.query, "inventory": inventory, "start": start + len(selected)}) if more else ""
    _authority(request, body.kind, current)
    for row in selected:
        if digest(dict(security_ops._STORES)[body.kind].load(row["id"])) != digest(row):
            raise HTTPException(409, "A named record changed. Find the current work again.")
    return {"context": current, "items": [{"value": row["id"], "label": _record_label(row), "status": str(row.get("status") or row.get("phase") or "Saved")} for row in selected],
            "cursor": cursor, "complete": not more, "notice": "Current named records, in name order. Each part shows up to 100 records."}


def review(request, body):
    current = _authority(request, body.kind, body.context, define=body.mode == "schema")
    if body.query or body.cursor or body.mode == "schema" and (body.record or body.expected_details_revision or body.expected_source != _ZERO):
        raise HTTPException(422, "Review the complete field setup or one selected record.")
    if body.mode == "details" and not body.record:
        raise HTTPException(422, "Choose named work before reviewing its details.")
    source = _source(request, body.kind, body.record, edit=body.mode == "details")
    schema, detail = native.read(body.kind, body.record)
    if (native.schema_public(schema)["revision"] != body.expected_schema_revision
            or int((detail or {}).get("revision", 0)) != body.expected_details_revision
            or (source["revision"] if source else _ZERO) != body.expected_source):
        raise HTTPException(409, "The saved work or field setup changed. Refresh and review your preserved draft again.")
    draft = native.normalize_schema(body.draft) if body.mode == "schema" else native.normalize_details(body.draft, native.schema_public(schema))
    summary = {"heading": "Save category setup" if body.mode == "schema" else "Save business details",
               "kind": native.KINDS[body.kind], "record": source["label"] if source else "Category setup",
               "status": source["status"] if source else "Separate business labels",
               "changes": native.changes(body.mode, draft, schema, detail), "notice": native.NOTICE + " " + native.ORIGINAL_NOTICE}
    _authority(request, body.kind, current, define=body.mode == "schema")
    if source != _source(request, body.kind, body.record, edit=body.mode == "details"):
        raise HTTPException(409, "The selected work changed while its review was prepared.")
    value = {"purpose": _PURPOSE, "owner": context_for(request), "actor": _actor(request),
             "context": current, "operation": uuid.uuid4().hex, "kind": body.kind, "record": body.record,
             "mode": body.mode, "schema": body.expected_schema_revision, "details": body.expected_details_revision,
             "source": body.expected_source, "draft": draft, "summary": summary, "expires": time.time() + _TTL}
    return {"context": current, "operation": value["operation"], "token": _sealed(value),
            "expires_at": value["expires"], "normalized_draft": draft, "summary": summary}


def _actor(request):
    from .request_identity import request_actor as _request_actor

    return _request_actor(request)


def _owned(request, body, value, *, historical=False):
    current = _authority(request, value["kind"], body.context, historical=historical, define=value["mode"] == "schema")
    if value["owner"] != context_for(request) or value["actor"] != _actor(request):
        raise HTTPException(404, "This original review is not available to the current account and workspace.")
    _source(request, value["kind"], value["record"], edit=not historical and value["mode"] == "details")
    return current


def _result(current, result):
    return {"context": current, "found": result is not None,
            "confirmed": bool(result and result["confirmed"]),
            "state": result["state"] if result else "unavailable",
            "message": ("Your change is saved. Its audit record is still waiting to be written." if result and result["state"] == "audit_pending" else
                        "The original save is confirmed." if result and result["confirmed"] else
                        "This original is not retained or not confirmed. Matching current values cannot prove that save."),
            **({"original": result} if result else {})}


def original(request, body):
    value = _review_token(body.token)
    current = _owned(request, body, value, historical=True)
    result = native.original(value["kind"], "" if value["mode"] == "schema" else value["record"],
                             value["operation"], digest(value), value["actor"], value["owner"])
    _owned(request, body, value, historical=True)
    return _result(current, result)


def save(request, body):
    value = _review_token(body.token)
    historical_context = _owned(request, body, value, historical=True)
    prior = native.original(value["kind"], "" if value["mode"] == "schema" else value["record"],
                            value["operation"], digest(value), value["actor"], value["owner"])
    if prior is not None:
        _owned(request, body, value, historical=True)
        return _result(historical_context, prior)
    try:
        current = _owned(request, body, value)
        if value["context"] != current or value["expires"] <= time.time():
            raise HTTPException(409, "The review expired or current access changed. Review the preserved draft again.")
        source = _source(request, value["kind"], value["record"], edit=value["mode"] == "details")
        schema, detail = native.read(value["kind"], value["record"])
        if (native.schema_public(schema)["revision"] != value["schema"]
                or int((detail or {}).get("revision", 0)) != value["details"]
                or (source["revision"] if source else _ZERO) != value["source"]):
            raise HTTPException(409, "The selected work changed. Read it and review your preserved draft again.")
    except HTTPException as exc:
        raise HTTPException(exc.status_code, {"message": exc.detail, "not_saved": True}) from exc
    def guard():
        latest = _owned(request, body, value)
        if latest != value["context"] or value["expires"] <= time.time():
            raise HTTPException(409, "The review or access changed before saving. Check the original before making another change.")
        if source != _source(request, value["kind"], value["record"], edit=value["mode"] == "details"):
            raise HTTPException(409, "The selected work changed during saving. Check the original save.")
    with authority_effect_fence():
        result = native.save(kind=value["kind"], target=value["record"], mode=value["mode"], draft=value["draft"],
                             expected_schema=value["schema"], expected_details=value["details"],
                             operation=value["operation"], request_hash=digest(value), actor=value["actor"], owner=value["owner"],
                             heading=value["summary"]["heading"], review_changes=value["summary"]["changes"], effect_guard=guard)
        guard()
    return _result(current, result)


def _call(fn, *args):
    try:
        return fn(*args)
    except HTTPException:
        raise
    except RecordConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    except (GovernedRecordBackendError, OSError, RuntimeError) as exc:
        raise HTTPException(503, "Business details could not be confirmed. Your draft is kept; check the original after any save.") from exc


@router.get("/state")
def read_state(request: Request, response: Response, kind: str = "task", record: str = ""):
    response.headers["Cache-Control"] = "private, no-store"
    return _call(state, request, kind, record)


@router.post("/choices")
def read_choices(request: Request, body: ChoicesIn):
    return _call(choices, request, body)


@router.post("/review")
def prepare_review(request: Request, body: ReviewIn):
    return _call(review, request, body)


@router.post("/save")
def save_review(request: Request, body: SaveIn):
    return _call(save, request, body)


@router.post("/original")
def read_original(request: Request, body: OriginalIn):
    return _call(original, request, body)
