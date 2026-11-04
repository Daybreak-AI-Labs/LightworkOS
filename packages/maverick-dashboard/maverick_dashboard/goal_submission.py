"""Same-key admission and read-only reconciliation for optional HTTP clients."""
from __future__ import annotations

import hashlib
import json

from fastapi import HTTPException
from maverick.attachment_submissions import SubmissionConflict, SubmissionStore

LEGACY_CHANNEL = "idempotency:api:goals"


def api_token(key):
    if not isinstance(key, str) or not 1 <= len(key) <= 255 or any(ord(c) < 32 for c in key):
        raise HTTPException(status_code=400, detail="Invalid Idempotency-Key (maximum 255 characters)")
    return "api-goal:" + hashlib.sha256(key.encode()).hexdigest()


def reserve_api(world, *, key, owner, payload, title, description, domain, caps, connection_references=None, effect_guard=None, task_selection=None):
    token = api_token(key)
    # Historical processed-message rows did not bind full request payloads.
    # They remain readable for reconciliation, but cannot authorize new work.
    legacy = world.lookup_processed_message(LEGACY_CHANNEL, f"{owner}:{key}")
    if legacy is not None:
        raise HTTPException(status_code=409, detail=(
            "A legacy goal receipt exists for this key. Read /api/v1/goal-submissions/receipt "
            "with the same Idempotency-Key to reconcile it; no new work was dispatched."
        ))
    payload_data = payload.model_dump(mode="json")
    if not payload_data.get("connection_references"):
        payload_data.pop("connection_references", None)
    if not payload_data.get("task_model") and not payload_data.get("task_effort"):
        for field in ("task_model", "task_effort", "task_model_context"):
            payload_data.pop(field, None)
    fingerprint = hashlib.sha256(json.dumps({
        "schema": "api-goal-request.v1", "payload": payload_data,
        "title": title, "description": description, "domain": domain, "caps": caps,
        **({"connection_references": connection_references} if connection_references else {}),
    }, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    try:
        return SubmissionStore(world).create(token=token, fingerprint=fingerprint, owner=owner,
            title=title[:200], description=description, domain=domain or "", manifest=[],
            kind="source_analysis" if payload.knowledge_context is not None else "api",
            connection_references=connection_references,
            submission_detail={"task_model_selection": task_selection} if task_selection is not None else None,
            **({"effect_guard": effect_guard} if effect_guard is not None else {}))
    except SubmissionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


def lookup_receipt(world, *, key, owner, kind):
    if kind not in {"api", "chat"}:
        raise HTTPException(status_code=400, detail="Unknown submission kind")
    try:
        receipt = SubmissionStore(world).lookup(token=api_token(key) if kind == "api" else key, owner=owner)
    except SubmissionConflict as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if receipt is None and kind == "api":
        goal_id = world.lookup_processed_message(LEGACY_CHANNEL, f"{owner}:{key}")
        if goal_id is not None:
            receipt = {"goal_id": goal_id, "state": "legacy_unverified"}
    if receipt is None:
        raise HTTPException(status_code=404, detail=(
            "No matching receipt is visible. The original request may still be in flight; do not submit a new key."
        ))
    goal = world.get_goal(receipt["goal_id"])
    if goal is None:
        raise HTTPException(status_code=409, detail="Submission receipt exists but its goal is unavailable; reconcile before retrying")
    # A token receipt is not a share link and never grants administrator-wide
    # lookup of another user's request identity.
    if (goal.owner or "") != owner:
        raise HTTPException(status_code=404, detail="No matching submission receipt")
    return receipt, goal


def try_claim_api_dispatch(world, receipt, intent, *, effect_guard=None) -> bool:
    """Move an admitted request's draft goal to pending exactly once. ``False``
    when another request (a concurrent replay) already claimed it."""
    store = SubmissionStore(world)
    store.record_dispatch_intent(receipt["key"], intent, **({"effect_guard": effect_guard} if effect_guard is not None else {}))
    store.update(receipt["key"], state="ready", message="Request accepted; execution admission is pending.", **({"effect_guard": effect_guard} if effect_guard is not None else {}))
    return store.claim_dispatch(receipt["key"], **({"effect_guard": effect_guard} if effect_guard is not None else {}))
