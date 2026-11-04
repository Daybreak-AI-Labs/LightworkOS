"""Reviewed owner-only private-topic setup and original effect results."""
from __future__ import annotations

import json
import re
import secrets
import time
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import config, crypto_at_rest
from maverick import personal_push_devices as devices
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.personal_notification_delivery import Refused, Unconfirmed
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import personal_notifications_api as native
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/notifications/personal/destinations", tags=["notifications"])
TTL = 600


def _authority(request, context=None):
    with auth.fresh_configuration():
        actor = native._identity(request)
        resolved = auth._resolve_principal(request=request)
        if resolved is None or resolved.principal != actor:
            raise HTTPException(401, "Your sign-in is no longer current. Reload your notifications.")
        current = context_for(request)
        native._binding(request, context or current)
        if config.config_source_errors(include_tenant=True):
            raise HTTPException(503, "Notification settings could not be read. Nothing was changed.")
        return actor, current, digest(config.load_config().get("notifications") or {})


def state(request):
    actor, current, _policy = _authority(request)
    try:
        devices._settings()
        available, note = True, "Private delivery follows your personal subscriptions and each destination's quiet hours."
    except ValueError:
        available, note = False, "External personal delivery is off. An administrator can enable background checking and private delivery in All settings. Pausing and removing saved destinations remains available."
    result = {"context": current, "devices": [devices.public(row) for row in devices.rows(actor)],
              "external_available": available, "note": note}
    _authority(request, current)
    return result


def _row(actor, identifier):
    try:
        return devices.owned(actor, identifier)
    except (Refused, ValueError) as exc:
        raise HTTPException(409, str(exc)) from exc


def _guard(request, value):
    actor, current, policy = _authority(request, value["context"])
    if (actor != value["actor"] or current != value["context"] or policy != value["policy"]
            or not time.time() < value["expires"] <= time.time() + TTL):
        raise HTTPException(409, "Your account, workspace, notification settings or review time limit changed. Review again.")
    if value["action"] != "register":
        row = _row(actor, value["device"])
        if digest(row) != value["source"]:
            raise HTTPException(409, "This saved destination changed. Reload and review the current version.")
        return row
    if devices.duplicate(actor, value["target"]):
        raise HTTPException(409, "This private topic is already registered to your account. Use its existing controls.")
    if len(devices.rows(actor)) >= 20:
        raise HTTPException(409, "Your account already has 20 private destinations. Remove one before registering another.")
    return None


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    action: Literal["register", "enable", "pause", "withdraw", "test", "quiet"]
    device: str = Field(default="", max_length=40)
    expected_revision: int = Field(default=0, ge=0)
    name: str = Field(default="", max_length=100)
    topic: str = Field(default="", max_length=64, repr=False)
    access_token: str = Field(default="", max_length=128, repr=False)
    timezone: str = Field(default="UTC", max_length=100)
    quiet_enabled: bool = False
    quiet_start: str = Field(default="22:00", max_length=5)
    quiet_end: str = Field(default="08:00", max_length=5)


def review(request, body):
    with authority_effect_fence():
        actor, current, policy = _authority(request, body.context)
        operation = "pnr-" + secrets.token_hex(16)
        value = {"purpose": "lightwork.private-topic-review.v1", "operation": operation, "actor": actor,
                 "context": current, "policy": policy, "action": body.action,
                 "device": body.device, "expires": time.time() + TTL}
        details = []
        try:
            if body.action == "register":
                devices._settings()
                name = body.name.strip()
                if not name or not name.isprintable():
                    raise ValueError("Give this private destination a name you will recognize.")
                target = devices.credentials(body.topic, body.access_token)
                target["account"] = devices.validate_provider(target, effect_guard=lambda: _authority(request, current))
                value.update(device="pnd-" + secrets.token_hex(16), name=name, target=target,
                             quiet=devices.quiet({key: getattr(body, key) for key in
                                 ("timezone", "quiet_enabled", "quiet_start", "quiet_end")}))
                _guard(request, value)
                details = ["Register " + name + " to your account, initially paused.",
                           "Private topic: " + target["topic"],
                           "ntfy currently confirms that your authenticated account owns this reservation and everyone else is denied access."]
            else:
                row = _row(actor, body.device)
                if row["revision"] != body.expected_revision:
                    raise HTTPException(409, "This destination changed. Reload before reviewing it.")
                value["source"] = digest(row)
                details = [body.action.capitalize() + " " + row["name"] + ".", "Private topic: " + devices.target(row)["topic"]]
                if body.action in {"enable", "test"}:
                    devices._settings()
                    devices.validate_provider(devices.target(row), effect_guard=lambda: _guard(request, value))
                if body.action == "quiet":
                    value["quiet"] = devices.quiet({key: getattr(body, key) for key in
                        ("timezone", "quiet_enabled", "quiet_start", "quiet_end")})
                if body.action == "test":
                    details.extend([devices.TEST_TEXT, "One separately confirmed test, including when the destination is paused. Quiet hours still apply."])
                elif body.action == "enable":
                    details.append("Enable eligible unread private task updates, following your saved timing and subscriptions. Earlier attempts for this same private topic are not automatically repeated; messages contain no task text.")
                elif body.action == "withdraw":
                    details.append("Stop future delivery and remove its saved access token and topic. Retain content-free original effect results to prevent duplicate sends.")
                elif body.action == "pause":
                    details.append("Stop future delivery while keeping your protected setup. Already submitted messages cannot be recalled.")
            choice = value.get("quiet") or (row["quiet"] if body.action != "register" else None)
            if choice:
                details.append("Time zone: " + choice["timezone"] + ". " +
                    ("Quiet hours: " + choice["quiet_start"] + " to " + choice["quiet_end"] + "." if choice["quiet_enabled"] else "No additional destination quiet hours."))
        except Refused as exc:
            raise HTTPException(409, str(exc)) from exc
        except Unconfirmed as exc:
            raise HTTPException(503, "The service's current private-topic permission could not be confirmed. No message was sent; your draft remains here.") from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        details.extend(["All devices subscribed to this topic may receive notifications. Use a separate private topic for each phone if you want separate destinations.",
                        "Service acceptance does not prove receipt or reading. Unknown sends are not automatically repeated."])
        return {"context": current, "token": devices.protect(value), "details": details,
                "action": body.action, "operation": operation}


def _open(token):
    try:
        if not crypto_at_rest.is_sealed_str(token):
            raise ValueError
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        common = {"purpose", "operation", "actor", "context", "policy", "action", "device", "expires"}
        extra = {"name", "target", "quiet"} if value["action"] == "register" else {"source"}
        if value["action"] == "quiet":
            extra.add("quiet")
        if (set(value) != common | extra or value["purpose"] != "lightwork.private-topic-review.v1"
                or value["action"] not in {"register", "enable", "pause", "withdraw", "test", "quiet"}
                or not re.fullmatch(r"pnr-[a-f0-9]{32}", value["operation"])
                or not re.fullmatch(r"pnd-[a-f0-9]{32}", value["device"])
                or any(not re.fullmatch(r"[a-f0-9]{64}", value[key]) for key in ("context", "policy"))
                or not isinstance(value["actor"], str) or not value["actor"].startswith("user:")
                or type(value["expires"]) not in {float, int}):
            raise ValueError
        return value
    except (KeyError, ValueError, TypeError) as exc:
        raise HTTPException(409, "This protected review could not be verified. Nothing was repeated.") from exc


def _result(value, row):
    status = row.get("state", "unknown") if row and not row.get("_audit_pending") else "unknown"
    messages = {"confirmed": "The original destination change was saved. Refresh to see its current state.",
                "accepted": "ntfy accepted this original test for the exact topic. This does not mean a device received or read it.",
                "refused": "This original action was refused. Nothing was automatically repeated."}
    return {"context": value["context"], "operation": value["operation"], "state": status,
            "message": messages.get(status, "The original outcome is unconfirmed. Check your private topic before separately reviewing a new test. Nothing was repeated.")}


def original(request, token):
    value = _open(token)
    actor, current, _policy = _authority(request, value["context"])
    if actor != value["actor"] or current != value["context"]:
        raise HTTPException(404, "This original result belongs to a different account or workspace.")
    receipts = devices.store(actor, receipts=True)
    row = receipts.get(value["operation"])
    if row and (row.get("review") != digest(value) or row.get("actor") != actor):
        raise HTTPException(404, "This original result could not be matched to your review.")
    if row and row.get("_audit_pending"):
        with authority_effect_fence():
            _authority(request, current)
            row = receipts._flush(row)
    if row and row["state"] in {"started", "unknown"} and value["action"] != "test":
        saved = devices.store(actor).get(value["device"])
        if saved and saved.get("last_operation") == value["operation"] and saved.get("last_review") == digest(value):
            if not saved.get("_audit_pending"):
                row = {**row, "state": "confirmed"}
    _authority(request, current)
    return _result(value, row)


def apply(request, token):
    from maverick import practice
    from maverick.personal_notification_recipients import enroll

    value = _open(token)
    with authority_effect_fence():
        prior = original(request, token)
        receipts = devices.store(value["actor"], receipts=True)
        if receipts.get(value["operation"]):
            return prior
        row = _guard(request, value)
        if practice.active():
            raise HTTPException(409, "Leave practice mode before changing a private notification destination.")
        if value["action"] in {"register", "enable"}:
            destination = value["target"] if row is None else devices.target(row)
            try:
                devices._settings()
                devices.validate_provider(destination, effect_guard=lambda: _guard(request, value))
            except (Refused, ValueError) as exc:
                raise HTTPException(409, str(exc)) from exc
            except Unconfirmed as exc:
                raise HTTPException(503, "The current private-topic permission could not be confirmed. Nothing was changed.") from exc
        receipt = receipts.create({"id": value["operation"], "actor": value["actor"], "context": value["context"],
                                   "device": value["device"], "review": digest(value), "action": value["action"], "state": "started"},
                                  actor=value["actor"], action="private_destination_action_started", max_records=1000,
                                  effect_guard=lambda: _guard(request, value))
        if receipt.get("_audit_pending"):
            return _result(value, receipt)
        outcome, reference = "unknown", ""
        try:
            if value["action"] == "test":
                reference = devices.send(value["actor"], row, devices.TEST_TEXT, test=True,
                                         effect_guard=lambda: _guard(request, value))
                outcome = "accepted"
            else:
                changes = {"last_operation": value["operation"], "last_review": digest(value)}
                if value["action"] == "register":
                    enroll(value["actor"])
                    saved = devices.store(value["actor"]).create({"id": value["device"], "owner": value["actor"],
                        "name": value["name"], "protected": devices.protect(value["target"]),
                        "delivery_identity": digest([value["actor"], value["target"]["account"], value["target"]["topic"]]),
                        "quiet": value["quiet"], "active": False, "withdrawn": False, **changes},
                        actor=value["actor"], action="private_destination_registered", max_records=1000,
                        effect_guard=lambda: _guard(request, value))
                else:
                    if value["action"] == "quiet":
                        changes["quiet"] = value["quiet"]
                    else:
                        changes["active"] = value["action"] == "enable"
                        if value["action"] == "withdraw":
                            changes.update(withdrawn=True, protected="")
                    saved = devices.store(value["actor"]).update(row["id"], lambda record: record.update(changes),
                        expected_revision=row["revision"], actor=value["actor"], action="private_destination_" + value["action"],
                        effect_guard=lambda: _guard(request, value))
                outcome = "confirmed" if saved and not saved.get("_audit_pending") else "unknown"
        except (Refused, HTTPException):
            outcome = "refused"
        except Exception:
            pass  # Never retain token-bearing provider or storage errors.
        try:
            receipt = receipts.update(receipt["id"], lambda record: record.update(state=outcome, provider_reference=reference),
                expected_revision=receipt["revision"], actor=value["actor"], action="private_destination_action_finished")
        except Exception:
            receipt = None
        return _result(value, receipt)


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=16384, repr=False)


class ApplyIn(TokenIn):
    confirmed: bool


@router.get("")
def state_endpoint(request: Request):
    return JSONResponse(state(request), headers={"Cache-Control": "private, no-store"})


@router.post("/review")
def review_endpoint(request: Request, body: ReviewIn):
    return JSONResponse(review(request, body), headers={"Cache-Control": "private, no-store"})


@router.post("/apply")
def apply_endpoint(request: Request, body: ApplyIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Read and confirm the complete destination review first.")
    return JSONResponse(apply(request, body.token), headers={"Cache-Control": "private, no-store"})


@router.post("/original")
def original_endpoint(request: Request, body: TokenIn):
    return JSONResponse(original(request, body.token), headers={"Cache-Control": "private, no-store"})
