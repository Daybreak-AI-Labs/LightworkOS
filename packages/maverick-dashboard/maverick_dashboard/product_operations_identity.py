"""Native reviewed identity controls shared with the closed Copilot registry."""
from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from pydantic import Field

from . import (
    auth,
    content_access_api,
    employee_departures,
    employee_departures_api,
    permission_requests,
    permission_requests_api,
)
from .product_operations import Adapter, EmptyInput, Outcome, Preview, Snapshot, StrictInput


class DepartureBegin(StrictInput):
    principal: str = Field(min_length=6, max_length=400)
    custodian: str = Field(min_length=6, max_length=400)
    confirm_preservation: Literal[True]


class DepartureCase(StrictInput):
    case_id: str = Field(min_length=5, max_length=100)


class DepartureHandoff(DepartureCase):
    item_key: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=6, max_length=400)
    disposition: Literal["retained", "transfer_reported", "revocation_reported"]
    evidence: str = Field(min_length=10, max_length=1000)


class DepartureClose(DepartureCase):
    confirm_retained_obligations: Literal[True]


class ContentRequest(content_access_api.AccessIn):
    pass


class ContentDecision(StrictInput):
    request_id: str = Field(min_length=5, max_length=100)
    decision: Literal["approve", "deny", "revoke", "retry_audit"]


class PermissionRequest(permission_requests_api.ExplainIn):
    reason: str = Field(min_length=10, max_length=1000)
    confirm_shared_with_reviewer: Literal[True]


class PermissionDecision(StrictInput):
    request_id: str = Field(min_length=5, max_length=100)
    decision: Literal["reviewing", "deny", "confirm_effective"]
    note: str = Field(min_length=10, max_length=1000)


def _field(name, label, kind="text", *, choices=None, **kwargs):
    return {"name": name, "label": label, "kind": kind, "required": True,
            **({"choices": choices} if choices is not None else {}), **kwargs}


def _choices(values):
    return [{"value": value, "label": label} for value, label in values]


def _outcome(row, message):
    pending = bool(row.get("audit_pending") or row.get("_audit_pending"))
    return Outcome("unconfirmed" if pending else "confirmed",
                   "The case is saved but its activity receipt is pending; inspect native status before relying on it." if pending else message,
                   {"id": row.get("id"), "revision": row.get("revision"), "status": row.get("status")})


def _departures(request):
    employee_departures_api._authority(request)
    rows = employee_departures.STORE.list(limit=101)
    return employee_departures.candidates(), rows[:100], len(rows) > 100


def _departure_case(request, identifier, *, write=False):
    employee_departures_api._authority(request, write=write)
    row = employee_departures.STORE.get(identifier)
    if row is None:
        raise HTTPException(404, "Choose an available departure case.")
    return row


def departure_snapshot(request, _selection, *, action="status"):
    people, rows, partial = _departures(request)
    cases = [{"id": row["id"], "revision": row["revision"], "principal": row["principal"], "status": row["status"]} for row in rows]
    fields = []
    if action == "begin":
        fields = [_field("principal", "Employee", "select", choices=_choices((p["principal"], p["label"]) for p in people if not p["admin"] and not p["departed"])),
                  _field("custodian", "Retained-data administrator", "select", choices=_choices((p["principal"], p["label"]) for p in people if p["active"] and p["admin"])),
                  _field("confirm_preservation", "Retain all data and preservation holds; this does not grant private-content access or verify provider revocation", "boolean", value=False)]
    elif action != "status":
        fields = [_field("case_id", "Departure case", "select", choices=_choices((r["id"], r["principal"] + " — " + r["status"]) for r in rows))]
        if action == "handoff":
            by_case = {row["id"]: _choices([("external", "External identities, provider consent and unverified outcomes")] +
                       [(employee_departures._item_key(item), (item.get("tenant") or "Main") + ": " + item["kind"] + " " + item["id"]) for item in row["inventory"]["items"]]) for row in rows}
            fields += [_field("item_key", "Reviewed item", "select", depends_on="case_id", choices_by=by_case),
                       _field("owner", "Responsible administrator", "select", choices=_choices((p["principal"], p["label"]) for p in people if p["active"] and p["admin"])),
                       _field("disposition", "Reported disposition", "select", choices=_choices((x, x.replace("_", " ")) for x in ("retained", "transfer_reported", "revocation_reported"))),
                       _field("evidence", "Evidence/reference, shared with administrators; no employee content or secrets", "textarea")]
        if action == "close":
            fields.append(_field("confirm_retained_obligations", "Accept named responsibility for all retained work, holds and unverified external outcomes", "boolean", value=False))
    details = {"cases": cases, "partial": partial, "coverage": "Latest 100 cases; all cases remain available in native departure controls."}
    return Snapshot(permission_requests.digest([people, cases, employee_departures.enabled()]),
        "Current installation departure governance metadata", "Departure never grants employee-content access. Closure records explicit retained obligations, not verified external revocation.",
        details, fields, "Departure actions are disabled." if action != "status" and not employee_departures.enabled() else "")


def departure_prepare(request, _selection, args, *, action):
    actor = employee_departures_api._authority(request, write=action != "status")
    if action == "status":
        return Preview("Current departure metadata; no identity or work was changed.", native=departure_snapshot(request, {}).details)
    if action == "begin":
        reviewed = employee_departures.preview(args["principal"])
        if reviewed["truncated"]:
            raise HTTPException(409, "Departure inventory is incomplete; use the native controls to resolve coverage.")
        if len(reviewed["items"]) > 150:
            raise HTTPException(422, "This inventory is too large for the Copilot review. Use the complete native departure editor.")
        return Preview("Deactivate this named identity, retire reviewed schedules, remove reviewed local credentials and retain all data/holds. Provider revocation and running-work outcomes remain separately owned obligations.",
                       [{"employee": args["principal"], "custodian": args["custodian"], "reviewed_items": reviewed["items"]}],
                       {"snapshot": reviewed["snapshot"], "actor": actor})
    row = _departure_case(request, args["case_id"], write=True)
    native = {"revision": row["revision"], "actor": actor}
    if action == "close":
        review = employee_departures.closure_preview(row["id"], row["revision"])
        if not review["can_close"]:
            raise HTTPException(409, " ".join(review["blockers"]))
        native["snapshot"] = review["snapshot"]
        return Preview(review["notice"], [{"case": row["id"], "result": review["outcome"], "handoffs": row.get("handoffs", {})}], native)
    return Preview("Record this explicit retained responsibility and human evidence." if action == "handoff" else "Retry the saved activity receipt only; no identity, credential or scheduler effect is repeated." if action == "retry_audit" else "Refresh the case inventory, preserving existing evidence and adding newly found obligations.",
                   [{"case": row["id"], **{key: value for key, value in args.items() if key != "case_id"}}], native)


def departure_execute(request, _selection, args, prepared, _operation_id, *, action):
    actor = employee_departures_api._authority(request, write=True)
    def authorize():
        return employee_departures_api._authority(request, write=True)
    if action == "begin":
        row = employee_departures.begin(args["principal"], args["custodian"], prepared["snapshot"], actor, authorize)
    elif action == "handoff":
        row = employee_departures.record_handoff(args["case_id"], prepared["revision"], item_key=args["item_key"], owner=args["owner"], disposition=args["disposition"], evidence=args["evidence"], actor=actor, authorize=authorize)
    elif action == "refresh":
        row = employee_departures.refresh_inventory(args["case_id"], prepared["revision"], actor, authorize)
    elif action == "retry_audit":
        row = employee_departures.STORE.update(args["case_id"], lambda current: None,
            expected_revision=prepared["revision"], action="departure_audit_retry", actor=actor)
    else:
        row = employee_departures.close_case(args["case_id"], prepared["revision"], prepared["snapshot"], actor, authorize)
    if row is None:
        raise HTTPException(404, "Departure case is unavailable.")
    return _outcome(row, "Departure case saved: " + row["status"].replace("_", " ") + ". External outcomes remain explicitly retained obligations.")


def departure_recover(request, _selection, args, prepared, _operation_id, *, action):
    employee_departures_api._authority(request, write=True)
    if action == "begin":
        identifier = "EDP-" + employee_departures._digest([args["principal"], prepared["snapshot"], prepared["actor"]])[:32]
        row = employee_departures.STORE.get(identifier)
        if row:
            return Outcome("unconfirmed", "This departure already has a saved dispatch record. Inspect its native case for confirmed versus uncertain steps; no effects were repeated.", {"id": row["id"], "status": row["status"]})
    elif action == "close":
        row = _departure_case(request, args["case_id"], write=True)
        closure = row.get("closure", {})
        if closure.get("snapshot") == prepared["snapshot"] and closure.get("reviewed_by") == prepared["actor"]:
            return Outcome("unconfirmed" if row.get("_audit_pending") else "replayed", "The reviewed closure is already saved. Retained obligations remain with their named owners.", {"id": row["id"], "status": row["status"]})
    return None


def content_snapshot(request, _selection, *, action="status"):
    state = content_access_api.access_state(request)
    fields = []
    if action == "request":
        fields = [_field("resource_kind", "Resource type", "select", choices=_choices((v, v.replace("_", " ")) for v in sorted({r["resource_kind"] for r in state["resources"]}))),
                  _field("resource_id", "Exact resource", "select", depends_on="resource_kind", choices_by={kind: _choices((r["resource_id"], r["label"]) for r in state["resources"] if r["resource_kind"] == kind) for kind in ("goal", "approval", "subject_data")}),
                  _field("purpose", "Reviewed purpose", "select", choices=_choices((v, v.replace("_", " ")) for v in ("employee_support", "incident_investigation", "rights_request", "action_review"))),
                  _field("minutes", "Expiry in minutes (5–60)", "number", value=15, min=5, max=60)]
    elif action == "decide":
        fields = [_field("request_id", "Access request", "select", choices=_choices((r["id"], r["label"] + " — " + r["status"]) for r in state["records"])),
                  _field("decision", "Reviewed decision", "select", choices=_choices((v, v.replace("_", " ")) for v in ("approve", "deny", "revoke", "retry_audit")))]
    blocked = "Content-access requests are disabled." if action == "request" and not state["enabled"] else ""
    if action == "request" and not state["can_request"]:
        blocked = "Your current role cannot request exceptional content access."
    return Snapshot(permission_requests.digest(state), "Current tenant-scoped content-access metadata", "Private content remains unreadable until a different current reviewer grants this exact resource, purpose and expiry. Every exceptional read gets a receipt.", state, fields, blocked)


def content_prepare(request, _selection, args, *, action):
    state = content_access_api.access_state(request)
    if action == "status":
        return Preview("Current resource-scoped requests only; no private employee content was opened.", native=state)
    if action == "request":
        resource = next((r for r in state["resources"] if r["resource_kind"] == args["resource_kind"] and r["resource_id"] == args["resource_id"]), None)
        if resource is None:
            raise HTTPException(404, "Choose an available governance resource.")
        return Preview("Request a separate review; this does not grant content access or permission to act on the resource.", [{**resource, "purpose": args["purpose"], "minutes": args["minutes"]}], {"resource": resource})
    row = next((r for r in state["records"] if r["id"] == args["request_id"]), None)
    if row is None:
        raise HTTPException(404, "Choose an available content-access request.")
    return Preview("Record this decision for the exact requested content, purpose and expiry. Reading it still requires a current scoped grant and a read receipt; action authority remains separate.",
                   [{"request": row, "decision": args["decision"]}], {"revision": row["revision"]})


def content_execute(request, _selection, args, prepared, operation_id, *, action):
    if action == "request":
        row = content_access_api.create_access(request, ContentRequest(**args), operation_id=operation_id)
    else:
        row = content_access_api.decide_current_access(request, args["request_id"], content_access_api.DecisionIn(expected_revision=prepared["revision"], decision=args["decision"]), operation_id=operation_id)
    return _outcome(row, "The scoped content-access request is " + row["status"] + ". No private content was opened by this action.")


def content_recover(request, _selection, args, _prepared, operation_id, *, action):
    actor = content_access_api._actor(request, write=True)
    for row in content_access_api.content_access.STORE.list():
        key = "operation_id" if action == "request" else "decision_operation_id"
        if (row.get(key) == operation_id and row.get("tenant") == content_access_api.content_access.tenant()
                and (actor in {row.get("requester"), row.get("owner")} or auth.has_global_permission(request, "admin"))):
            return Outcome("unconfirmed" if row.get("_audit_pending") else "replayed", "This exact content-access operation is already recorded; no grant duration was extended.", {"id": row["id"], "status": row["status"]})
    return None


def permission_snapshot(request, _selection, *, action="status"):
    state = permission_requests_api.state(request, include_choices=action == "request")
    fields = []
    if action == "request":
        choices = state["choices"]
        fields = [_field("kind", "Action type", "select", value="permission", choices=_choices((("permission", "Dashboard action"), ("tool", "Tool action")))),
                  _field("capability", "Action to review", "select", depends_on="kind",
                         choices_by={kind: [{"value": "", "label": "Choose an action"}] + choices[kind] for kind in ("permission", "tool")}),
                  _field("reason", "Business need, explicitly shared with the policy reviewer; no private content or secrets", "textarea"),
                  _field("confirm_shared_with_reviewer", "Share this business reason with the policy owner", "boolean", value=False)]
    elif action == "decide":
        fields = [_field("request_id", "Permission request", "select", choices=_choices((r["id"], r["owner"] + ": " + r["label"]) for r in state["records"] if r["can_review"])),
                  _field("decision", "Reviewed result", "select", choices=_choices((v, v.replace("_", " ")) for v in ("reviewing", "deny", "confirm_effective"))),
                  _field("note", "Review explanation, shared with the employee", "textarea")]
    details = {key: value for key, value in state.items() if key != "choices"}
    summary = "Reviews never grant access; effective completion checks the real current policy."
    if action == "request":
        details["Tool choices"] = state["choices"]["tools_notice"]
        summary += " " + state["choices"]["tools_notice"]
    return Snapshot(permission_requests.digest(state), "Current account permissions and authorized requests", summary, details, fields,
                    "Permission requests are disabled." if action != "status" and not state["enabled"] else "")


def permission_prepare(request, _selection, args, *, action):
    actor = permission_requests_api.authority(request, write=action != "status")
    if action == "status":
        return Preview("Current action permissions and your authorized request cases.", native=permission_requests_api.state(request))
    if action == "request":
        explanation = permission_requests.explain(actor, args["kind"], args["capability"])
        if explanation["allowed"]:
            raise HTTPException(409, "Your current policy already allows this action. Check the task's other permissions, data access and consent separately.")
        public = permission_requests_api.public_explanation(explanation)
        return Preview("Share this business need with the actual policy owner for review. No permission is granted automatically.",
                       [{"label": "Action", "after": permission_requests_api.action_label(args["kind"], args["capability"])},
                        {"label": "Current permission", "after": "Your current policy blocks this action."},
                        {"label": "Responsible administrator", "after": explanation["owner"]},
                        {"label": "Scope of this check", "after": public["limit"]},
                        {"label": "Current policies", "after": [{"Policy": layer["source"], "Result": layer["reason"]} for layer in public["layers"]]},
                        {"label": "Shared business need", "after": args["reason"]}], {"snapshot": explanation["snapshot"]})
    row = permission_requests.STORE.get(args["request_id"])
    if row is None or not permission_requests.can_review(request, row):
        raise HTTPException(404, "Choose a permission request you may independently review.")
    return Preview("Record this review. Permission can be confirmed only after the actual current policy allows the action. This review does not change a role or access policy.", [{"request": permission_requests.public(request, row), "decision": args["decision"], "note": args["note"]}], {"revision": row["revision"]})


def permission_execute(request, _selection, args, prepared, operation_id, *, action):
    if action == "request":
        row = permission_requests.submit(request, args["kind"], args["capability"], args["reason"], prepared["snapshot"], operation_id=operation_id)
    else:
        row = permission_requests.decide(request, args["request_id"], prepared["revision"], args["decision"], args["note"], operation_id=operation_id)
    return _outcome(row, "Permission request saved as " + row["status"] + "; actual policy remains authoritative.")


def permission_recover(request, _selection, args, _prepared, operation_id, *, action):
    permission_requests_api.authority(request, write=True)
    for row in permission_requests.STORE.list(limit=10001):
        key = "operation_id" if action == "request" else "decision_operation_id"
        if row.get(key) == operation_id and permission_requests.visible(request, row):
            return Outcome("unconfirmed" if row.get("_audit_pending") else "replayed", "This exact permission-review operation is already saved; no grant was changed.", {"id": row["id"], "status": row["status"]})
    return None


def permission_read_recovery(request, _selection, _args, _prepared, operation_id, *, action):
    bound = permission_requests_api._binding(request)
    actor = permission_requests_api.authority(request)
    rows = permission_requests.STORE.list(limit=10001)
    if len(rows) > 10000:
        raise HTTPException(409, "Saved permission-request history could not be read completely. Check the current native requests; no action was repeated.")
    key = "operation_id" if action == "request" else "decision_operation_id"
    owner = "owner" if action == "request" else "reviewed_by"
    row = next((row for row in rows if row.get(key) == operation_id and row.get(owner) == actor and permission_requests.visible(request, row)), None)
    if permission_requests_api._binding(request) != bound:
        raise HTTPException(409, "Your account or workspace changed while checking the original request.")
    if row is None:
        return None
    pending = bool(row.get("_audit_pending"))
    return Outcome("unconfirmed" if pending else "replayed",
                   "This exact request is saved, but its activity receipt is pending. No action was repeated." if pending else
                   "This exact permission-review operation is already saved. Read its current case; no request or decision was repeated.",
                   {"Action": permission_requests_api.action_label(row["kind"], row["capability"]),
                    "Current request": {"requested": "Requested", "reviewing": "Under review", "denied": "Declined", "effective": "Permission confirmed"}.get(row["status"], "Saved")})


def entries():
    result = []
    groups = [
        ("departures", "/users/departures", ("/users/departures",), departure_snapshot, departure_prepare, departure_execute, departure_recover,
         [("status", "Show employee departure cases", EmptyInput), ("begin", "Begin reviewed employee departure", DepartureBegin), ("handoff", "Record departure responsibility", DepartureHandoff), ("refresh", "Refresh departure inventory", DepartureCase), ("close", "Close departure with retained obligations", DepartureClose), ("retry_audit", "Retry departure activity recording", DepartureCase)]),
        ("content_access", "/content-access", ("/content-access", "/account"), content_snapshot, content_prepare, content_execute, content_recover,
         [("status", "Show content-access requests", EmptyInput), ("request", "Request exceptional content access", ContentRequest), ("decide", "Review scoped content access", ContentDecision)]),
        ("permissions", "/access-requests", ("/access-requests", "/account"), permission_snapshot, permission_prepare, permission_execute, permission_recover,
         [("status", "Explain my effective permissions", EmptyInput), ("request", "Request permission review", PermissionRequest), ("decide", "Review a permission request", PermissionDecision)]),
    ]
    for prefix, direct, pages, snapshot, prepare, execute, recover, operations in groups:
        for action, label, model in operations:
            result.append(Adapter(id=prefix + "." + action, label=label, family="reviews", direct_ui=direct, pages=pages, input_model=model,
                snapshot=lambda request, selection, fn=snapshot, value=action: fn(request, selection, action=value),
                prepare=lambda request, selection, args, fn=prepare, value=action: fn(request, selection, args, action=value),
                execute=(lambda request, selection, args, prepared, operation_id, fn=execute, value=action: fn(request, selection, args, prepared, operation_id, action=value)) if action != "status" else None,
                recover=(lambda request, selection, args, prepared, operation_id, fn=recover, value=action: fn(request, selection, args, prepared, operation_id, action=value)) if action != "status" else None,
                read_recovery=(lambda request, selection, args, prepared, operation_id, value=action: permission_read_recovery(request, selection, args, prepared, operation_id, action=value)) if prefix == "permissions" and action != "status" else None))
    return tuple(result)
