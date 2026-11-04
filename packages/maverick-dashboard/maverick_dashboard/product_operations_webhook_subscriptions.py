"""Read saved webhook status and open the existing private subscription form."""
from __future__ import annotations

from collections import Counter

from fastapi import HTTPException
from maverick import webhook_subscriptions as subscriptions
from maverick.governed_operations import digest
from maverick.webhooks import _load_config_outbound

from . import auth
from ._shared import _world
from .product_operations import Adapter, EmptyInput, Preview, Snapshot

PAGE = "/settings/webhooks/manage"


def _state(request, selection):
    if selection:
        raise HTTPException(422, "Open the current Webhooks page to review its subscriptions.")
    auth.require_global_permission(request, "admin")
    try:
        world = _world()
        rows = subscriptions.list_subscriptions(world=world)
        deliveries = subscriptions.list_deliveries(world=world, limit=101)
        addresses, secret = _load_config_outbound()
    except (OSError, ValueError) as exc:
        raise HTTPException(503, "Saved webhook status could not be verified. Your subscription draft is kept.") from exc
    auth.require_global_permission(request, "admin")
    details = {
        "Saved subscriptions": len(rows),
        "Turned on": sum(bool(row["enabled"]) for row in rows),
        "Turned off": sum(not row["enabled"] for row in rows),
        "Subscriptions with their own signing secret": sum(bool(row["secret_set"]) for row in rows),
        "Installation address list": len(addresses),
        "Installation signing secret present": bool(secret),
        "Recent deliveries included": min(len(deliveries), 100),
        "Recent delivery states": dict(Counter(
            {"pending": "Waiting or retrying", "sending": "Being sent; acceptance unconfirmed",
             "unknown": "Acceptance unconfirmed", "delivered": "Accepted by the destination",
             "dead": "Needs attention"}
            .get(row["status"], "Other retained state") for row in deliveries[:100])),
        "More retained deliveries": len(deliveries) > 100,
        "Scope": "Saved settings and the newest 100 retained deliveries at most. "
                 "A saved subscription does not prove that another system has received an event.",
        "Next step": "Review addresses, event choices and signing secrets in the existing private form. "
                     "Saving, sending a test event and retrying a delivery remain separate actions there.",
    }
    # No address, description, secret, event body or receiver response leaves
    # the native reader. Revisions use only retained state metadata.
    revision = digest({"workspace": subscriptions.workspace_id(), "subscriptions": [
        {key: row[key] for key in ("id", "enabled", "secret_set", "events", "updated_at")}
        for row in rows], "deliveries": [
        {key: row[key] for key in ("id", "status", "attempts", "updated_at")}
        for row in deliveries], "installation": [len(addresses), bool(secret)]})
    return revision, details


def snapshot(request, selection):
    revision, details = _state(request, selection)
    return Snapshot(revision, "Saved webhook settings and recent deliveries in this workspace",
                    "Read current status and open the complete private subscription form.", details)


def prepare(request, selection, _arguments):
    _, details = _state(request, selection)
    return Preview("Current saved webhook status. No subscription was changed and no event was sent.", native={
        **details, "webhook_subscription_review": {"scope": "current_page"},
    })


def entries():
    return (Adapter("connections.webhook_subscription_status", "Read webhook status and open subscription controls",
                    "connections", PAGE + "#wh-form", (PAGE,), EmptyInput, snapshot, prepare,
                    aliases=("add a webhook subscription", "edit webhook subscriptions", "review webhook settings",
                             "show webhook delivery status", "open webhook subscription controls",
                             "read current work updates", "open the complete update controls")),)
