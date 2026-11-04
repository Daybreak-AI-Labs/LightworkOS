"""Complete retained-example review and original native decision receipts."""
from __future__ import annotations

import json
import re
import time

from fastapi import HTTPException
from maverick.authority_effects import authority_effect_fence
from maverick.governed_operations import digest

from .api_flow_action_episodes import _call, _service
from .draft_api import context_for
from .plain_labels import capability_label
from .tools_ops_api import same_origin

TTL = 600
MAX_FIELDS = 16384
MAX_REVIEW_BYTES = 600000
NOTICE = "Acceptance records your review of this complete example. Permission for future learning is separate. Withdrawing it stops future use; retained derived copies and completed work remain."


def authority(request, flow, context=None, *, write=False, receipt=False):
    current = context_for(request)
    if context is not None and context != current:
        raise HTTPException(409, {"code": "example_context_changed", "message": "Your account or workspace changed. Reload before reviewing this example."})
    if write:
        same_origin(request)
    service, ctx = _call(lambda: _service(request, flow, human=write, receipt=receipt))
    return current, service, ctx


def current(request, flow, run, *, context=None):
    scope, service, ctx = authority(request, flow, context)
    row = _call(lambda: service.get(ctx, flow, run, detail=True))
    authority(request, flow, scope)
    if row.get("status") == "audit_pending":
        raise HTTPException(503, "This example's last decision is waiting for its activity record. Check current status; do not repeat it.")
    return scope, row


def _source(row):
    return {key: row.get(key) for key in ("id", "revision", "episode_sha256", "review_sha256", "grant_sha256", "status", "retain_until", "binding", "teaching_sha256")}


def evidence_changes(row):
    """Closed plain rows: every retained value, without a truncated preview."""
    evidence = row.get("evidence")
    if not isinstance(evidence, dict):
        raise HTTPException(409, "This example has no available complete evidence. Check its current status.")
    rows = []

    def visit(value, label):
        if len(rows) >= MAX_FIELDS:
            raise HTTPException(413, "This example has too many details for a complete in-product review. Nothing was approved. For a future example, retain fewer necessary details before its first action; existing work is not repeated.")
        if isinstance(value, dict) and value:
            for key, child in value.items():
                visit(child, label + " › " + str(key).replace("_", " "))
        elif isinstance(value, list) and value:
            for index, child in enumerate(value):
                visit(child, label + " › Item " + str(index + 1))
        else:
            shown = "Yes" if value is True else "No" if value is False else "Nothing" if value is None else "No details" if value == {} else "Empty list" if value == [] else str(value)
            rows.append({"label": label, "after": shown})

    visit(evidence["inputs"], "Starting information")
    for index, slot in enumerate(evidence["slots"]):
        name = capability_label(slot["tool"])
        visit(slot["arguments"], "Action " + str(index + 1) + " · " + name + " · Sent")
        visit(slot["result"], "Action " + str(index + 1) + " · " + name + " · Received")
    def describe(schema, label):
        kind = schema["type"]
        if kind == "object":
            if not schema["properties"]:
                visit("No details", label)
            for name, child in schema["properties"].items():
                describe(child, label + " › " + name.replace("_", " "))
        elif kind == "array":
            visit("List of exactly " + str(schema["minItems"]) + " items", label)
            describe(schema["items"], label + " › Each item")
        else:
            text = "Text, " + str(schema.get("minLength", 0)) + " to " + str(schema["maxLength"]) + " characters" if kind == "string" else (
                ("Whole number" if kind == "integer" else "Number") + ", " + str(schema["minimum"]) + " to " + str(schema["maximum"]) if kind in {"number", "integer"} else "Yes or no" if kind == "boolean" else "Nothing")
            visit(text, label)
    contract = evidence["contract"]
    describe(contract["input_schema"], "Allowed starting information")
    for tool in contract["allowed_tools"]:
        describe(contract["tool_data_schemas"][tool]["arguments"], "Allowed details sent to " + capability_label(tool))
        describe(contract["tool_data_schemas"][tool]["result"], "Allowed result from " + capability_label(tool))
    teaching = evidence.get("teaching")
    if teaching is not None:
        question = teaching["question"]
        for index, option in enumerate(question["options"]):
            visit({"Action": capability_label(option["tool"]), "Sent": option["arguments"]}, "Recorded choice " + str(index + 1))
        visit({"Chosen action": capability_label(teaching["tool"]), "Chosen option": int(teaching["route"]) + 1,
               "Available explanations": question["guard_candidate_count"], "Predictions": question["guard_partitions"]}, "Recorded teaching decision")
    if len(json.dumps(rows, ensure_ascii=False).encode("utf-8")) > MAX_REVIEW_BYTES:
        raise HTTPException(413, "This complete review is too large to display safely. Nothing was approved. Choose a future example that retains fewer necessary details; existing work is not repeated.")
    return rows


def prepare(request, flow, run, kind, reason, *, use_until=None, retain_copies=False, context=None):
    scope, service, ctx = authority(request, flow, context, write=True)
    row = _call(lambda: service.get(ctx, flow, run, detail=True))
    if kind not in {"accept", "reject", "grant"} or not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
        raise HTTPException(422, "Choose a review decision and enter a brief reason.")
    if row.get("status") != ("accepted" if kind == "grant" else "awaiting_review") or row.get("grant_sha256") or row.get("source_current") is not True:
        raise HTTPException(409, "This example already changed or cannot receive this decision. Check current status.")
    changes = evidence_changes(row)
    if kind == "grant":
        if retain_copies is not True or type(use_until) not in (int, float) or not time.time() < use_until <= row["retain_until"]:
            raise HTTPException(422, "Choose an end date before the example expires and explicitly allow keeping the derived copies until then.")
    prepared = {"flow": flow, "run": run, "kind": kind, "reason": reason.strip(), "use_until": use_until,
                "retain_copies": retain_copies, "context": scope, "actor": ctx.actor, "source": _source(row), "expires": time.time() + TTL}
    changes.extend([{"label": "Decision", "after": {"accept": "Accept this example", "reject": "Do not use this example", "grant": "Allow future learning"}[kind]},
                    {"label": "Your reason", "after": prepared["reason"]}, {"label": "Effect", "after": NOTICE}])
    if kind == "grant":
        from datetime import datetime, timezone
        changes.extend([{"label": "Allow learning and keep derived copies until", "after": datetime.fromtimestamp(use_until, timezone.utc).strftime("%b %d, %Y at %H:%M UTC")}])
    authority(request, flow, scope, write=True)
    return prepared, changes


def original(request, flow, run, operation, *, context=None, prepared=None):
    scope, service, ctx = authority(request, flow, context, receipt=True)
    if not isinstance(operation, str) or not re.fullmatch(r"[a-f0-9]{32}", operation):
        raise HTTPException(404, "This original example decision is unavailable.")
    value = _call(lambda: service.original_decision(ctx, flow, run, operation=operation, context=scope))
    receipt = value["receipt"]
    if receipt and prepared is not None and receipt["binding"] != digest(prepared):
        raise HTTPException(409, "This original decision belongs to a different review.")
    confirmed = receipt is not None and not value["audit_pending"]
    state = "accepted" if receipt and receipt["accepted"] else "rejected"
    kind = "grant" if receipt and receipt["action"] == "flow.episode.grant" else state
    message = ("Your original permission to learn was recorded." if kind == "grant" else "Your original example acceptance was recorded." if kind == "accepted" else "Your original decision not to use this example was recorded.") if confirmed else "The original decision is unconfirmed. Current example status does not establish your original outcome. Nothing was repeated."
    if receipt and value["audit_pending"]:
        message = "Your original decision is saved but its activity receipt is pending. Check current status without submitting it again."
    authority(request, flow, scope, receipt=True)
    return {"context": scope, "operation": operation, "confirmed": confirmed, "message": message + " Nothing was repeated." if confirmed else message,
            "kind": kind if receipt else None, "current_status": value["current_status"], "historical": True, "notice": NOTICE}


def apply(request, prepared, operation):
    with authority_effect_fence():
        scope, service, ctx = authority(request, prepared["flow"], prepared["context"], write=True)
        if ctx.actor != prepared["actor"]:
            raise HTTPException(409, "The account that reviewed this example changed. Nothing was repeated.")
        existing = original(request, prepared["flow"], prepared["run"], operation, context=scope, prepared=prepared)
        if existing["kind"] is not None:
            return existing

        def guard():
            authority(request, prepared["flow"], scope, write=True)
            if not time.time() < prepared["expires"]:
                raise HTTPException(409, "This complete review expired. Review the current example again.")
            if prepared["kind"] == "grant" and not time.time() < prepared["use_until"]:
                raise HTTPException(409, "The chosen learning end date passed before the permission was recorded. Review a current date.")

        guard()
        decision = {"operation": operation, "context": scope, "binding": digest(prepared)}
        values = {"expected_revision": prepared["source"]["revision"], "expected_episode_sha256": prepared["source"]["episode_sha256"],
                  "rationale": prepared["reason"], "decision": decision, "before_write": guard}
        if prepared["kind"] == "grant":
            _call(lambda: service.grant_training(ctx, prepared["flow"], prepared["run"], use_until=prepared["use_until"],
                  retain_derived_copies=prepared["retain_copies"], **values))
        else:
            _call(lambda: service.review(ctx, prepared["flow"], prepared["run"], accepted=prepared["kind"] == "accept", **values))
        return original(request, prepared["flow"], prepared["run"], operation, context=scope, prepared=prepared)
