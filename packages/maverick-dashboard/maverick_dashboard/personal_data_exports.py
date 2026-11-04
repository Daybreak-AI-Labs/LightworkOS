"""Short-lived owner-bound downloads without a second retained content copy."""
from __future__ import annotations

import json
import time
from urllib.parse import urlencode

from fastapi import HTTPException
from fastapi.responses import Response
from maverick import crypto_at_rest, personal_memory
from maverick.audit import audit_event
from maverick.authority_effects import authority_effect_fence

from . import personal_data_api as native
from .draft_api import context_for

PURPOSE = "lightwork.personal-data-download.v1"


def link(request, *, channel=None, user_id=None, store=None):
    actor = native._actor(request)
    if store is None:
        personal_memory.require_scope(actor, channel, user_id)
    elif store not in {"model_test_history", "conversation_inbox", "saved_views_and_pins"}:
        raise ValueError("Choose an available owned account store.")
    token = crypto_at_rest.seal_to_str(json.dumps({"purpose": PURPOSE, "owner": actor,
        "context": context_for(request), "channel": channel, "user_id": user_id,
        "store": store, "expires_at": time.time() + 600}))
    if not crypto_at_rest.is_sealed_str(token):
        raise ValueError("Private export links require the configured encryption service.")
    return {"href": "/api/v1/my-data/download?" + urlencode({"token": token}),
            "label": "Download current authorized records (link expires in ten minutes)"}


def download(request, token):
    with authority_effect_fence():
        actor = native._actor(request)
        try:
            if not crypto_at_rest.is_sealed_str(token):
                raise ValueError
            bound = json.loads(crypto_at_rest.unseal_from_str(token))
            if (bound.get("purpose") != PURPOSE or bound.get("owner") != actor
                    or bound.get("context") != context_for(request)
                    or type(bound.get("expires_at")) not in (int, float)
                    or not time.time() < bound["expires_at"] <= time.time() + 600):
                raise ValueError
        except Exception as exc:
            raise HTTPException(409, "The private download expired or belongs to another account or workspace. Prepare a new export.") from exc
        store = bound.get("store")
        if store is None:
            from maverick.dsar import export_subject_data
            channel, user_id = bound["channel"], bound["user_id"]
            personal_memory.require_scope(actor, channel, user_id)
            bundle = export_subject_data(user_id, channel=channel, strict=True, world=native._app()._world())
            bundle["personal_notes"] = personal_memory.records(channel, user_id)
            bundle["memory_controls"] = personal_memory.controls(channel, user_id)
            bundle["limits"] = "Selected verified conversation scope only; account stores, derivatives, shared packets and external copies are separate."
        elif store == "saved_views_and_pins":
            from maverick.ux_store import shared
            bundle = shared().export_owned_navigation(actor)
        elif store == "model_test_history":
            from maverick.model_test_retention import export_owned
            bundle = export_owned(actor)
        elif store == "conversation_inbox":
            from maverick import conversation_inbox
            records = conversation_inbox.owned_inventory(actor)
            bundle = {"store": store, "records": [conversation_inbox.export_owned(actor, row["id"], row["revision"]) for row in records],
                      "limits": "Owned queued conversation records only; submitted tasks, attachments and accounting have their separate retained records."}
        else:
            raise HTTPException(404, "This owned export is unavailable.")
        if native._actor(request) != actor or context_for(request) != bound["context"]:
            raise HTTPException(409, "Your account or workspace changed while preparing the download.")
        if audit_event("personal_data_exported", actor=actor, store=store or "verified_conversation_scope") is not True:
            raise RuntimeError("The export audit receipt was not acknowledged.")
        return Response(json.dumps(bundle, indent=2, default=str), media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="lightwork-personal-records.json"',
                     "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer"})
