"""One reviewed private test, with an owner-bound original and no blind resend."""
from __future__ import annotations

import json
import math
import re
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from maverick import crypto_at_rest, personal_identity
from maverick import personal_notification_delivery as delivery
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from pydantic import BaseModel, ConfigDict, Field

from . import auth
from . import personal_notifications_api as native
from .draft_api import context_for

router = APIRouter(prefix="/api/v1/notifications/personal/tests", tags=["notifications"])
STORE = GovernedRecordStore("personal-alert-tests", "PAT", "personal_alert_test")
TEXT = "This is a private test notification from Lightwork. Service acceptance does not mean you have read it."
TTL = 600


def _authority(request, context=None):
    with auth.fresh_configuration():
        actor = native._identity(request)
        resolved = auth._resolve_principal(request=request)
        if resolved is None or resolved.principal != actor:
            raise HTTPException(401, "Your sign-in is no longer current. Reload notifications.")
        current = context_for(request)
        native._binding(request, context or current)
        return actor, current


def _source(request, identifier, context=None):
    actor, current = _authority(request, context)
    settings = delivery._settings()
    link = next((row for row in personal_identity.linked_channels(actor) if row["id"] == identifier), None)
    if not link:
        raise HTTPException(409, "Choose a currently verified private account from My data.")
    try:
        transport = delivery._transport(link)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    if transport[0] == "teams":
        cfg, destination = transport[1]
        transport = ["teams", {key: sorted(item) if isinstance(item, set) else item for key, item in cfg.items()}, destination]
    return actor, current, link, digest([settings, link, transport])


def review(request, identifier, context):
    with authority_effect_fence():
        actor, current, link, source = _source(request, identifier, context)
        value = {"purpose": "lightwork.private-alert-test.v1", "operation": "PAT-" + secrets.token_hex(16),
                 "actor": actor, "context": current, "link": identifier, "source": source, "expires": time.time() + TTL}
        token = crypto_at_rest.seal_to_str(json.dumps(value, separators=(",", ":")))
        if not crypto_at_rest.is_sealed_str(token):
            raise HTTPException(503, "The protected test review could not be retained. Nothing was sent.")
        return {"context": current, "token": token, "operation": value["operation"],
                "recipient": "Your verified private " + link["channel"].title() + " account",
                "text": TEXT, "notice": "Send one fixed test. It does not subscribe you, include task content or prove you saw the message. No uncertain send is automatically repeated."}


def _open(token):
    try:
        value = json.loads(crypto_at_rest.unseal_from_str(token))
        if (not isinstance(value, dict) or set(value) != {"purpose", "operation", "actor", "context", "link", "source", "expires"}
                or value["purpose"] != "lightwork.private-alert-test.v1"
                or not re.fullmatch(r"PAT-[a-f0-9]{32}", value["operation"])
                or not isinstance(value["actor"], str) or not value["actor"].startswith("user:")
                or any(not re.fullmatch(r"[a-f0-9]{64}", value[key]) for key in ("context", "source"))
                or not re.fullmatch(r"[a-f0-9]{32}", value["link"])
                or type(value["expires"]) not in {int, float} or not math.isfinite(value["expires"])):
            raise ValueError
        return value
    except (ValueError, TypeError, KeyError) as exc:
        raise HTTPException(409, "This test review could not be verified. Nothing was repeated.") from exc


def owned_inventory(actor):
    """Content-free replay evidence is separate from seven-day alert history."""
    rows = STORE.list(limit=1001)
    selected = [row for row in rows if row.get("actor") == actor]
    return {"count": len(selected), "partial": len(rows) > 1000,
            "outcomes": {state: sum(row.get("state") == state for row in selected) for state in ("accepted", "refused", "unknown", "sending")},
            "retained": "Original test receipts retain account, destination reference, review digest and service outcome to prevent repeat sends. The fixed message contains no task content; removing ordinary alert history does not remove these separate receipts."}


def _guard(request, value):
    with auth.fresh_configuration():
        resolved = auth._resolve_principal(request=request)
        if resolved is None or resolved.principal != value["actor"]:
            raise HTTPException(401, "Your sign-in is no longer current. Nothing was sent.")
        actor, _context, link, source = _source(request, value["link"], value["context"])
        if actor != value["actor"] or source != value["source"] or not time.time() < value["expires"] <= time.time() + TTL:
            raise HTTPException(409, "The reviewed account, access, settings or time limit changed. Review a current test.")
        return link


def _result(row, current, operation):
    state = row.get("state", "unknown") if row and not row.get("_audit_pending") else "unknown"
    messages = {"accepted": "The service accepted this original test. This does not mean you saw it.",
                "refused": "This original test was refused. Review current account and channel settings before a new test."}
    return {"context": current, "operation": operation, "state": state,
            "message": messages.get(state, "Acceptance of this original test is unconfirmed. Check the private chat before a separately reviewed new test. Nothing was repeated.")}


def original(request, token):
    value = _open(token)
    actor, current = _authority(request, value["context"])
    if actor != value["actor"]:
        raise HTTPException(404, "This original test belongs to a different account.")
    row = STORE.get(value["operation"])
    if row and (row["actor"] != actor or row["context"] != current or row["link"] != value["link"]):
        raise HTTPException(404, "This original test is unavailable to the current account.")
    if row and row.get("_audit_pending"):
        with authority_effect_fence():
            _authority(request, current)
            row = STORE._flush(row)
    _authority(request, current)
    return _result(row, current, value["operation"])


def send(request, token):
    from maverick import practice

    value = _open(token)
    with authority_effect_fence():
        prior = original(request, token)
        if STORE.get(value["operation"]):
            return prior
        link = _guard(request, value)
        if practice.active():
            raise HTTPException(409, "Leave practice mode before sending a real private test.")
        row = STORE.create({"id": value["operation"], "actor": value["actor"], "context": value["context"],
                            "link": value["link"], "source": value["source"], "state": "sending"},
                           actor=value["actor"], action="personal_alert_test_started", max_records=1000,
                           effect_guard=lambda: _guard(request, value))
        if row.get("_audit_pending"):
            return _result(row, value["context"], value["operation"])
        state, reference = "unknown", ""
        try:
            reference = delivery.send_private(link, TEXT, effect_guard=lambda: _guard(request, value))
            state = "accepted" if reference else "unknown"
        except (delivery.Refused, HTTPException, ValueError):
            state = "refused"
        except Exception:
            pass  # Never retain a credential-bearing transport exception.
        try:
            row = STORE.update(row["id"], lambda saved: saved.update(state=state, provider_reference=reference),
                               expected_revision=row["revision"], actor=value["actor"], action="personal_alert_test_completed")
        except Exception:
            return _result(None, value["context"], value["operation"])
        return _result(row, value["context"], value["operation"])


class ReviewIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    context: str = Field(pattern=r"^[a-f0-9]{64}$")
    link: str = Field(pattern=r"^[a-f0-9]{32}$")


class TokenIn(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    token: str = Field(min_length=1, max_length=16384, repr=False)


class SendIn(TokenIn):
    confirmed: bool


@router.post("/review")
def review_endpoint(request: Request, body: ReviewIn):
    return JSONResponse(review(request, body.link, body.context), headers={"Cache-Control": "private, no-store"})


@router.post("/send")
def send_endpoint(request: Request, body: SendIn):
    if body.confirmed is not True:
        raise HTTPException(422, "Read and confirm the complete test message first.")
    return JSONResponse(send(request, body.token), headers={"Cache-Control": "private, no-store"})


@router.post("/original")
def original_endpoint(request: Request, body: TokenIn):
    return JSONResponse(original(request, body.token), headers={"Cache-Control": "private, no-store"})
