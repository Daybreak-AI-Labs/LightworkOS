"""Owned private ntfy topics, separate from organization notification settings.

A destination is a provider-owned restricted topic, not a verified physical
phone. Provider acceptance never establishes receipt, reading or exclusive
subscription. All effects use exact current owner/revision and no blind retry.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from . import crypto_at_rest
from .governed_records import GovernedRecordStore
from .personal_notification_delivery import DeliveryStore, Refused, Unconfirmed, _settings
from .personal_notifications import delivery_window, validate_preferences

ORIGIN = "https://ntfy.sh"
TEST_TEXT = "This is a private test notification from Lightwork. Service acceptance does not mean you received or read it."


def store(principal: str, *, receipts=False) -> GovernedRecordStore:
    if (not isinstance(principal, str) or not principal.startswith("user:")
            or not 5 < len(principal) <= 256):
        raise ValueError("Sign in with your own account to use private notification destinations.")
    scope = hashlib.sha256(principal.encode()).hexdigest()[:32]
    kind = "private-push-results" if receipts else "private-push-destinations"
    return GovernedRecordStore(kind + "-" + scope, "pnr" if receipts else "pnd", kind)


def _http(method: str, token: str, payload=None) -> dict:
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            if req.get_method() == "POST":
                raise Unconfirmed
            raise Refused("The notification service redirected the request. Nothing was repeated.")

    url = ORIGIN + ("/v1/account" if method == "GET" else "/")
    request = Request(url, data=None if payload is None else json.dumps(payload).encode(), method=method,
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "application/json"})
    started = time.monotonic()
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=5) as response:
            raw = response.read(65537)
            if len(raw) > 65536 or time.monotonic() - started > 5:
                raise Unconfirmed
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise Unconfirmed
        return result
    except HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code != 408:
            raise Refused("The notification service refused this request. Nothing was repeated.") from None
        raise Unconfirmed from None
    except (URLError, TimeoutError, OSError, ValueError):
        raise Unconfirmed from None


def credentials(topic: str, token: str) -> dict:
    if not isinstance(topic, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", topic):
        raise ValueError("Enter the exact private topic name from your ntfy account.")
    if not isinstance(token, str) or not re.fullmatch(r"tk_[A-Za-z0-9]{20,120}", token):
        raise ValueError("Enter an access token from your own ntfy account in the protected field.")
    return {"topic": topic, "token": token}


def validate_provider(target: dict, *, effect_guard=None) -> str:
    credentials(target["topic"], target["token"])
    if effect_guard:
        effect_guard()
    account = _http("GET", target["token"])
    if effect_guard:
        effect_guard()
    username, reservations = account.get("username"), account.get("reservations")
    if (not isinstance(username, str) or not 1 <= len(username) <= 256 or username == "*"
            or account.get("role") not in {"user", "admin"} or not isinstance(reservations, list)
            or len(reservations) > 1000
            or not any(isinstance(row, dict) and row.get("topic") == target["topic"]
                       and row.get("everyone") == "deny-all" for row in reservations)
            or (target.get("account") and target["account"] != username)):
        raise Refused("Choose a topic reserved by your own ntfy account with access for everyone else set to Deny all. No message was sent.")
    return username


def protect(value: dict) -> str:
    result = crypto_at_rest.seal_to_str(json.dumps(value, sort_keys=True, separators=(",", ":")))
    if not crypto_at_rest.is_sealed_str(result):
        raise ValueError("Protected notification storage is unavailable. Nothing was changed.")
    return result


def target(row: dict) -> dict:
    if not crypto_at_rest.is_sealed_str(row.get("protected")):
        raise ValueError("The protected notification destination could not be verified.")
    result = json.loads(crypto_at_rest.unseal_from_str(row["protected"]))
    if not isinstance(result, dict) or set(result) != {"topic", "token", "account"}:
        raise ValueError("The protected notification destination could not be verified.")
    credentials(result["topic"], result["token"])
    return result


def quiet(value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"timezone", "quiet_enabled", "quiet_start", "quiet_end"}:
        raise ValueError("Choose a time zone and the supported quiet-hour controls.")
    choice = validate_preferences(value)
    return {key: choice[key] for key in value}


def owned(principal: str, identifier: str) -> dict:
    row = store(principal).get(identifier)
    if not row or row.get("owner") != principal or row.get("withdrawn") is True:
        raise Refused("This private notification destination is no longer available to your account.")
    if row.get("_audit_pending"):
        raise Refused("This destination's saved result needs review before it can send.")
    return row


def rows(principal: str) -> list[dict]:
    records = store(principal).list(limit=1001)
    if len(records) > 1000:
        raise ValueError("Private destination history is full. No incomplete list was returned.")
    return [row for row in records if row.get("owner") == principal and row.get("withdrawn") is not True]


def owned_inventory(principal: str) -> dict:
    """Exact owner metadata only; protected addresses and tokens never export."""
    destinations = store(principal).list(limit=1001)
    originals = store(principal, receipts=True).list(limit=1001)
    if len(destinations) > 1000 or len(originals) > 1000:
        raise ValueError("Private destination records exceed the complete review window.")
    if any(row.get("_audit_pending") for row in [*destinations, *originals]):
        raise ValueError("Private destination records need their original result reconciled before erasure review.")
    owned_rows = [row for row in destinations if row.get("owner") == principal]
    records = sorted(({"id": row["id"], "revision": row["revision"]} for row in owned_rows
                      if row.get("erased") is not True), key=lambda item: item["id"])
    return {"records": records, "count": len(records),
            "active": sum(row.get("active") is True for row in owned_rows),
            "originals": sum(row.get("actor") == principal for row in originals),
            "barriers": sum(row.get("erased") is True for row in owned_rows)}


def erase_owned(principal: str, records: list[dict], *, actor: str, effect_guard) -> dict:
    """Remove reviewed local setup, retaining content-free no-replay barriers."""
    removed = 0
    for item in records:
        def change(row):
            if row.get("owner") != principal or row.get("erased") is True or row.get("_audit_pending"):
                raise ValueError("The private destination erasure scope changed.")
            row.update(name="", protected="", active=False, withdrawn=True, erased=True,
                       quiet={"timezone": "UTC", "quiet_enabled": False, "quiet_start": "22:00", "quiet_end": "08:00"})
        saved = store(principal).update(item["id"], change, expected_revision=item["revision"], actor=actor,
                                        action="private_destination_personal_data_erased", effect_guard=effect_guard)
        if not saved or saved.get("_audit_pending"):
            raise ValueError("Private destination erasure could not be confirmed. Inspect the original request before any new action.")
        removed += 1
    return {"removed": removed, "retained": "Content-free original outcomes, owner and destination references, and route hashes remain to prevent repeated sends. Delivery receipts and the provider account are separate."}


def duplicate(principal: str, candidate: dict) -> bool:
    return any(target(row)["account"] == candidate["account"] and target(row)["topic"] == candidate["topic"]
               for row in rows(principal))


def link(row: dict) -> dict:
    # Re-registering the same owned provider/topic must not erase duplicate
    # protection for still-current unread alerts, including unknown sends.
    return {"id": row["delivery_identity"], "verified_at": 0, "channel": "private-topic", "destination": row}


def public(row: dict) -> dict:
    history = DeliveryStore(row["owner"], link(row)).recent()
    return {"id": row["id"], "name": row["name"], "revision": row["revision"], "active": row["active"],
            "quiet": row["quiet"], "receipts": history,
            "notice": "All devices subscribed to this private topic may receive its notifications. Acceptance does not prove receipt or reading."}


def active(principal: str, *, now=None) -> list[dict]:
    now = time.time() if now is None else now
    return [link(row) for row in rows(principal) if row["active"] is True
            and delivery_window(validate_preferences(row["quiet"]), now=now)[0]]


def send(principal: str, row: dict, text: str, *, effect_guard=None, test=False) -> str:
    from . import practice
    from .personal_identity import principal_current

    policy = _settings()
    if practice.active():
        raise Refused("Leave practice mode before sending a private notification.")

    def guard():
        from .experience_preferences import enabled as preferences_enabled
        if effect_guard:
            effect_guard()
        current = owned(principal, row["id"])
        if (not preferences_enabled() or not principal_current(principal) or _settings() != policy or current != row
                or (not test and current["active"] is not True)
                or not delivery_window(validate_preferences(current["quiet"]), now=time.time())[0]):
            raise Refused("The destination, access or quiet-hour policy changed. No new message was sent.")

    destination = target(row)
    validate_provider(destination, effect_guard=guard)
    guard()
    value = _http("POST", destination["token"], {"topic": destination["topic"], "message": text,
                                               "title": "Lightwork", "priority": 3})
    # A local withdrawal after bytes were submitted cannot recall them.
    if (value.get("event") != "message" or value.get("topic") != destination["topic"]
            or not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", str(value.get("id") or ""))):
        raise Unconfirmed
    return value["id"]
