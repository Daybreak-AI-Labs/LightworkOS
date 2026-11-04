"""Ordinary reviewed location and one-time native unseen-question record setup."""
from __future__ import annotations

import json
import math
import os
import secrets
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from maverick import config, crypto_at_rest, self_harness
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import data_dir
from maverick.self_harness_holdout import HoldoutLedgerError, HoldoutQueryLedger
from pydantic import BaseModel, ConfigDict, Field

from . import learning_ops_api as native
from . import learning_test_cases_api as questions
from . import settings_all_page as settings_page
from . import settings_catalog, settings_experience, settings_store

router = APIRouter(prefix="/learning-holdout-setup", tags=["learning-holdout-setup"])
PAGE = "/learned#learning-holdout-setup"
PURPOSE = "lightwork.learning-holdout-setup.v1"
SCOPE = "Installation administrators manage this shared learning record. It stays on this server; this setup does not establish independently controlled storage. No AI runs or spending occurs."
TTL = 600


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    action: Literal["location", "initialize"]
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    revision: str = Field(pattern=r"^[a-f0-9]{64}$")


class SaveIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=24000)
    confirmed: Literal[True]


def _requests():
    return GovernedRecordStore("learning-holdout-requests", "LHO", "learning_holdout_request", authority_scope="deployment_global")


def _anchors():
    return GovernedRecordStore("learning-holdout-initializations", "LHI", "learning_holdout_initialization", authority_scope="deployment_global")


def _anchor_id(source):
    return "LHI-" + source[:60]


def _state(request):
    context = questions._authority(request)
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(503, "Learning settings cannot be read right now. Your original setup receipts are kept.")
    with settings_store._locked(strict=True):
        layers = settings_page._sources()
        setting = settings_catalog.BY_ID["self_harness.holdout_ledger"]
        configured = str(self_harness.settings().get("holdout_ledger") or "").strip()
        # Native runtime opens the lexical setting and rejects symlink custody.
        # Resolve only its attempted-once identity, never to bypass those checks.
        path = str(Path(configured).absolute()) if configured else str(data_dir("self-coaching-unseen-checks.sqlite3", tenant=None).absolute())
        source = digest(os.path.normcase(str(Path(path).resolve())))
        anchor = _anchors().get(_anchor_id(source))
        if anchor and anchor["source"] != source:
            raise HTTPException(409, "The original initialization record cannot be matched safely. Nothing is replaced.")
        exists = os.path.lexists(path)
        verified, record_number, queries = False, "", 0
        if configured and exists:
            try:
                checked = HoldoutQueryLedger(Path(path)).verify()
                verified, record_number, queries = True, checked.ledger_id, checked.queries
                if anchor and anchor.get("record_number") and anchor["record_number"] != record_number:
                    verified = False
            except (HoldoutLedgerError, OSError, ValueError):
                pass
        owned = settings_page._resolve(setting, layers)["locked"] or settings_catalog.lookup(layers["tenant"], setting.path)[0]
        location_blocked = ("A location is already selected. Keep it and review initialization instead." if configured else
                            "Your installation or workspace controls this choice. Guided setup cannot replace it; ask its administrator to make the setting available in Lightwork." if owned else "")
        initialize_blocked = ("Choose the managed location first." if not configured else
                              "The current record is ready and is never initialized again." if verified else
                              "An existing record cannot be verified or matched to its original initialization. It is kept and never overwritten." if exists else
                              "An earlier initialization was requested at this location. The record is missing or its outcome is unconfirmed. It cannot be initialized again from this control." if anchor else "")
        try:
            settings_catalog.coerce(setting, path)
            native._halt_preflight("self-harness")
        except Exception as exc:
            blocked = str(exc.detail) if isinstance(exc, HTTPException) else "The managed learning location is unavailable under this installation's storage rules. Restore its access before continuing."
            location_blocked = location_blocked or blocked
            initialize_blocked = initialize_blocked or blocked
        state = {"context": context, "settings_revision": settings_page._revision(layers), "path": path,
                 "source": source, "configured": bool(configured), "exists": exists, "ready": verified,
                 "record_number": record_number, "checks_used": int(queries), "anchor_revision": anchor["revision"] if anchor else None,
                 "location_blocked": location_blocked, "initialize_blocked": initialize_blocked}
        state["revision"] = digest(state)
        questions._authority(request, context)
        return state


def current(request):
    state = _state(request)
    return {key: state[key] for key in ("context", "revision", "configured", "ready", "checks_used", "location_blocked", "initialize_blocked")} | {
        "scope": SCOPE, "message": "Ready. The current record was checked successfully." if state["ready"] else
        state["initialize_blocked"] if state["configured"] else state["location_blocked"] or "Select Lightwork's managed location, then review one-time initialization."}


def changes(prepared):
    initialize = prepared["action"] == "initialize"
    return [{"label": "Action", "after": "Initialize the selected record once" if initialize else "Choose Lightwork's managed learning location"},
            {"label": "Storage", "after": "The current approved learning location on this server" if initialize else "Lightwork's own managed data on this server; no location entry is needed"},
            {"label": "Existing information", "after": "An existing record, including an incomplete one, is never replaced. A missing record after an earlier request cannot be automatically recreated."},
            {"label": "Who manages it", "after": SCOPE},
            {"label": "Effect", "after": "Create only the record of unseen-question use. No question is used, no check runs and no learning switch, schedule, model or provider changes." if initialize else
             "Change only the existing unseen-question record location setting. Initialization is a separate reviewed step. No learning switch, schedule, model or provider changes."}]


def prepare(request, action, *, context=None, revision=None):
    if action not in {"location", "initialize"}:
        raise HTTPException(422, "Choose location setup or one-time initialization.")
    with settings_store._locked(strict=True):
        state = _state(request)
        questions._authority(request, context or state["context"], write=True)
        if revision is not None and revision != state["revision"]:
            raise HTTPException(409, "The learning setting or record changed. Refresh and review again.")
        if state[action + "_blocked"]:
            raise HTTPException(409, state[action + "_blocked"])
        if action == "location":
            body = settings_page.CatalogUpdate(expected_revision=state["settings_revision"], confirm=True,
                changes=[settings_page.SettingChange(id="self_harness.holdout_ledger", value=state["path"])])
            reviewed = settings_experience.review(request, body)
            if reviewed.status_code != 200 or [row["id"] for row in json.loads(reviewed.body)["items"]] != ["self_harness.holdout_ledger"]:
                raise HTTPException(409, "This setting changed. Refresh and review again.")
        if _state(request) != state:
            raise HTTPException(409, "The learning setting or record changed during review. Refresh before continuing.")
        return {"action": action, **{key: state[key] for key in ("context", "revision", "settings_revision", "source", "path")},
                "expires": time.time() + TTL}


def _deadline(prepared):
    expires = prepared.get("expires")
    if (type(expires) not in {int, float} or not math.isfinite(expires)
            or not time.time() < expires <= time.time() + TTL):
        raise HTTPException(409, "This review expired. Review the current setup again. Nothing was initialized or changed.")


def _owned(request, operation):
    context = questions._authority(request)
    questions._request_id(operation)
    row = _requests().get("LHO-" + operation)
    if row and (row["context"] != context or row["actor"] != native._actor(request)):
        raise HTTPException(404, "This original setup request is not available to this account and workspace.")
    questions._authority(request, context)
    return row


def original(request, operation, *, prepared=None):
    row = _owned(request, operation)
    if row and prepared is not None and row["request_digest"] != digest([operation, prepared, native._actor(request)]):
        raise HTTPException(409, "This original request belongs to another reviewed change.")
    try:
        state = current(request)
    except (HTTPException, OSError, ValueError):
        state = {"configured": False, "ready": False, "message": "Current readiness is unavailable. The original receipt is kept."}
    confirmed = bool(row and row["state"] == "saved")
    action = row["action"] if row else "setup"
    message = ("The original " + ("one-time initialization" if action == "initialize" else "location setup") + " was recorded. Nothing was repeated." if confirmed else
               row["message"] if row and row["state"] in {"refused", "queued"} else
               "The original change is unconfirmed. Current readiness is shown separately; it does not confirm the outcome of this request. Nothing was repeated.")
    context = questions._authority(request, row["context"] if row else None)
    return {"operation": operation, "context": context, "confirmed": confirmed, "action": action, "message": message,
            "current": state["message"], "configured": state["configured"], "ready": state["ready"], "scope": SCOPE}


def save(request, prepared, operation):
    questions._request_id(operation)
    actor, context = native._actor(request), prepared["context"]
    with settings_store._locked(strict=True):
        questions._authority(request, context, write=True)
        if _owned(request, operation) is not None:
            return original(request, operation, prepared=prepared)
        _deadline(prepared)
        checked = prepare(request, prepared["action"], context=context, revision=prepared["revision"])
        if {key: value for key, value in checked.items() if key != "expires"} != {key: value for key, value in prepared.items() if key != "expires"}:
            raise HTTPException(409, "The reviewed learning setup changed. Review it again.")
        _deadline(prepared)
        native._record(request, "self_harness_holdout_" + prepared["action"], phase="prepared", operation=operation,
                       reviewed_revision=prepared["revision"])
        requests = _requests()
        claim = requests.create({"id": "LHO-" + operation, "actor": actor, "context": context, "action": prepared["action"],
                                "request_digest": digest([operation, prepared, actor]), "state": "writing"},
                                action="learning.holdout.prepare", actor=actor, max_records=10000)
        try:
            questions._authority(request, context, write=True)
            if prepared["action"] == "location":
                _deadline(prepared)
                response = settings_page._catalog_update_locked(request, settings_page.CatalogUpdate(
                    expected_revision=prepared["settings_revision"], confirm=True,
                    changes=[settings_page.SettingChange(id="self_harness.holdout_ledger", value=prepared["path"])]))
                outcome = "saved" if response.status_code == 200 and json.loads(response.body).get("changed") == ["self_harness.holdout_ledger"] else "queued" if response.status_code == 202 else "refused"
                record_number, anchor = "", None
            else:
                # This installation-wide attempted-once anchor survives a lost
                # final reply or file deletion and is never a completed receipt.
                _deadline(prepared)
                anchors = _anchors()
                anchor = anchors.create({"id": _anchor_id(prepared["source"]), "source": prepared["source"], "operation": operation,
                                         "state": "writing"}, action="learning.holdout.initialize.prepare", actor=actor, max_records=10000)
                questions._authority(request, context, write=True)
                state = _state(request)
                if state["settings_revision"] != prepared["settings_revision"] or state["source"] != prepared["source"] or state["exists"]:
                    raise HTTPException(409, "The learning location or record changed. No initialization was repeated.")
                _deadline(prepared)
                record_number = HoldoutQueryLedger.provision(Path(prepared["path"])).verify().ledger_id
                outcome = "saved"
            message = "This setup is waiting for independent approval. Open Approvals, then review current setup." if outcome == "queued" else "The settings service did not apply this change. Refresh and review current setup." if outcome == "refused" else ""
            requests.update(claim["id"], lambda row: row.update(state=outcome, message=message), expected_revision=claim["revision"], action="learning.holdout.result", actor=actor)
            if anchor is not None:
                anchors.update(anchor["id"], lambda row: row.update(state="saved", record_number=record_number), expected_revision=anchor["revision"], action="learning.holdout.initialize.result", actor=actor)
        except Exception:
            return original(request, operation, prepared=prepared)
        return original(request, operation, prepared=prepared)


@router.get("")
def state(request: Request):
    return questions._response(current(request))


@router.get("/context")
def recovery_context(request: Request):
    return questions._response({"context": questions._authority(request)})


@router.get("/requests/{operation}")
def receipt(request: Request, operation: str):
    return questions._response(original(request, operation))


@router.post("/review")
def review(request: Request, body: ReviewIn):
    prepared = prepare(request, body.action, context=body.context, revision=body.revision)
    material = {"purpose": PURPOSE, "prepared": prepared, "operation": secrets.token_hex(16), "expires": prepared["expires"]}
    token = crypto_at_rest.seal_to_str(json.dumps(material, ensure_ascii=False, allow_nan=False, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(token) or len(token) > 24000:
        raise HTTPException(503, "This review could not be kept securely. Nothing was changed.")
    return questions._response({"context": prepared["context"], "operation": material["operation"], "token": token, "changes": changes(prepared)})


@router.post("/save")
def apply(request: Request, body: SaveIn):
    questions._authority(request, write=True)
    try:
        if not crypto_at_rest.is_sealed_str(body.token):
            raise ValueError
        material = json.loads(crypto_at_rest.unseal_from_str(body.token))
        if (set(material) != {"purpose", "prepared", "operation", "expires"} or material["purpose"] != PURPOSE
                or type(material["expires"]) not in {int, float} or not math.isfinite(material["expires"])
                or material["prepared"].get("expires") != material["expires"]):
            raise ValueError
    except Exception as exc:
        raise HTTPException(409, "This review changed. Prepare it again.") from exc
    if _owned(request, material["operation"]) is None and not time.time() < material["expires"] <= time.time() + TTL:
        raise HTTPException(409, "This review expired. Prepare it again.")
    return questions._response(save(request, material["prepared"], material["operation"]))
