"""Owned Promise economics, complete current-source admission and originals."""
from __future__ import annotations

import contextlib
import copy
import hmac
import json
import re
import time
from dataclasses import replace

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget
from maverick.commitment_capability_learning import current_observation
from maverick.commitment_economic_alternatives import SCHEMA, evaluate, permission_current, validate
from maverick.commitment_viability import assess
from maverick.file_lock import cross_process_lock
from maverick.flow import store as flows
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import commitment_capability_store as capability
from . import commitment_viability_store as promises

STORE = GovernedRecordStore("commitment-economic-alternatives", "CEA", "commitment_economic_alternatives", required_backend="local")
FEATURE, TTL, CHECK_LIMIT = "commitment_economic_alternatives", 600, 4
NOTICE = "Compare combinations of entered additional offers and possible additions while protecting all accepted work. Every price, cost, customer permission and availability basis is a report, not an independently verified business fact. Reported contribution includes all costs you enter in one selected currency and unit. Cost points remain separate. Nothing is purchased, reserved, accepted or sent."
ACTIONS = {"create": "Entered financial comparison", "edit": "Replaced financial assumptions", "check": "Compared conditional alternatives",
    "scope": "Reviewed use permission", "withdraw": "Withdrew financial use permission", "acknowledge": "Stopped waiting for an unknown original", "remove": "Removed current financial comparison"}


def authority(request, context=None, *, historical=False):
    actor, current = capability.authority(request, context, historical=historical)
    if not historical and (config.config_source_errors(include_tenant=True) or config.get_features().get(FEATURE) is not True):
        raise HTTPException(403, "Financial comparisons are off. Earlier originals remain readable.")
    return actor, current


def _id(actor, context, parent):
    return "CEA-" + digest([actor, context, parent])[:32]


@contextlib.contextmanager
def _writer(request, parent):
    with authority_effect_fence():
        actor, context = authority(request)
        with capability._parent_guard(parent):
            backend = capability.STORE._backend()
            path = backend._store._path(capability._id(actor, context, parent))
            with flows._definitions_lock(), cross_process_lock(path, strict=True):
                own = STORE._backend()
                with cross_process_lock(own._store._dir() / ".economic-admission", strict=True):
                    yield


def _source(request, parent_id, budget):
    budget.check()
    parent = capability._parent(request, parent_id)
    actor, context = authority(request)
    qualification_id = capability._id(actor, context, parent_id)
    if not capability.STORE.get(qualification_id):
        raise HTTPException(409, "Enter an additional-work review above before comparing its financial alternatives.")
    row = capability._owned(request, qualification_id)
    payload = capability._open(row)
    observed = capability._observations(request, payload)
    now = time.time()
    live = [item for item in observed if current_observation(item, payload["model"], now)]
    source = {"parent": parent_id, "parent_revision": parent["revision"], "parent_binding": capability._binding(parent),
        "parent_review": {key: parent.get(key) for key in ("title", "model", "sources", "traces", "labels")},
        "qualification": row["id"], "qualification_revision": row["revision"], "qualification_binding": digest(payload),
        "qualification_review": payload, "observations": observed, "live_observations": [item["id"] for item in live],
        "capability_current": payload["consent"] and not payload["removed"] and not payload.get("pending") and not payload.get("reservation")
            and not row.get("_audit_pending") and payload["parent_binding"] == capability._binding(parent) and now < payload["model"]["expires_at"]
            and all(now < offer["due_at"] for offer in payload["model"]["offers"]),
        "accepted_state": assess(replace(promises._snapshot(parent["model"]), options=()), now=now, current_source_revisions=promises._current_versions(parent)).status}
    rules = []
    for item in live:
        budget.check()
        if item["quality"] == "native_local_rule":
            native = capability._test_source(request, item["flow_id"])
            rules.append({"observation": item["id"], "definition": native["flow"].to_dict(),
                "included": [flow.to_dict() for flow in native["bundle"]["flows"][1:]], "source": capability._source_identity(native)})
    source["rules"] = rules
    budget.check()
    return source


def _seal(row, payload):
    value = json.dumps({"identity": [row["id"], row["actor"], row["context"], row["parent"]], "payload": payload}, allow_nan=False, separators=(",", ":"))
    if len(value.encode()) > 1500000:
        raise HTTPException(413, "The complete financial record exceeds its custody bound. Nothing was shortened.")
    row["envelope"] = crypto_at_rest.seal_to_str(value)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(409, "Enable stored-data encryption before saving private financial assumptions.")


def _open(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if value["identity"] != [row["id"], row["actor"], row["context"], row["parent"]]:
        raise HTTPException(409, "The retained financial owner could not be verified.")
    return value["payload"]


def _owned(request, identifier, *, historical=False):
    actor, context = authority(request, historical=historical)
    if type(identifier) is not str or not re.fullmatch(r"CEA-[a-f0-9]{32}", identifier):
        raise HTTPException(404, "This financial comparison is unavailable.")
    row = STORE.get(identifier)
    if not row or (row.get("actor"), row.get("context")) != (actor, context):
        raise HTTPException(404, "This comparison is unavailable to your account and workspace.")
    return STORE._flush(row) if row.get("_audit_pending") else row


def _used(parent, budget):
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The complete one-hundred-Promise custody bound is full. No history was omitted.")
    used = 0
    for row in rows:
        budget.check()
        if row.get("parent") == parent:
            used += _open(row)["checks_used"]
    return used


def _ready(payload, action):
    if payload["removed"] or payload["pending"] and action not in {"acknowledge", "withdraw", "remove"}:
        raise HTTPException(409, "Read the unknown original and review stopping its wait before a separate intent.")
    if action == "acknowledge" and not payload["pending"]:
        raise HTTPException(409, "No original wait needs acknowledgment.")


def _monetary_model(model):
    """Human currency strings become exact integer accounting, never floats."""
    value = copy.deepcopy(model)
    if type(value) is not dict or type(value.get("unit_scale")) is not int or value["unit_scale"] not in {1, 100}:
        raise HTTPException(422, "Choose whole currency amounts or amounts with up to two decimal places.")
    if any(type(value.get(name)) is not list or any(type(row) is not dict for row in value[name]) for name in ("offers", "additions")):
        raise HTTPException(422, "Enter each complete offer and possible-addition financial row.")
    rows = [(value, ("shared_cost", "maximum_outlay"))]
    rows.extend((row, ("unit_price", "unit_cost", "fixed_cost")) for row in value.get("offers", []))
    rows.extend((row, ("cost",)) for row in value.get("additions", []))
    for row, keys in rows:
        for key in keys:
            amount = row.get(key)
            if type(amount) is str:
                if re.fullmatch(r"(?:0|[1-9][0-9]{0,15})(?:\.[0-9]{1,2})?", amount) is None:
                    raise HTTPException(422, "Enter a nonnegative currency amount such as 1.25, without commas or an exponent.")
                whole, dot, fraction = amount.partition(".")
                if value["unit_scale"] == 1 and dot:
                    raise HTTPException(422, "Whole currency amounts cannot contain a decimal fraction.")
                row[key] = int(whole) * value["unit_scale"] + (int(fraction.ljust(2, "0")) if dot else 0)
    return value


def _arguments(action, arguments, source):
    allowed = {"create": {"model"}, "edit": {"model", "acknowledge_new_intent"}, "check": set(),
        "scope": {"allowed", "basis", "expires_at"}, "withdraw": set(), "remove": set(), "acknowledge": {"acknowledge_unknown"}}
    if action not in allowed or type(arguments) is not dict or set(arguments) != allowed[action]:
        raise HTTPException(422, "Enter exactly the complete fields for this supported action.")
    if action in {"create", "edit"}:
        arguments = {**arguments, "model": _monetary_model(arguments["model"])}
        validate(arguments["model"], source["qualification_review"]["model"])
        if not time.time() < arguments["model"]["expires_at"] <= time.time() + 30 * 86400:
            raise HTTPException(422, "Review source permission again within thirty days.")
    if action == "edit" and arguments["acknowledge_new_intent"] is not True:
        raise HTTPException(409, "A changed price, cost or scope is a separate intent. Acknowledge that earlier originals and spent allowance remain.")
    if action == "scope":
        from maverick.commitment_economic_alternatives import _permission
        _permission(arguments)
        if arguments["allowed"] and not time.time() < arguments["expires_at"] <= time.time() + 30 * 86400:
            raise HTTPException(422, "Choose a future permission-review date within thirty days.")
    if action == "acknowledge" and arguments["acknowledge_unknown"] is not True:
        raise HTTPException(409, "Acknowledge that the original remains unknown and its allowance is not refunded.")
    return arguments


def prepare(request, parent, action, arguments):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    with _writer(request, parent):
        actor, context = authority(request)
        source = _source(request, parent, budget)
        identifier = _id(actor, context, parent)
        row = STORE.get(identifier)
        if (action == "create") != (row is None):
            raise HTTPException(409, "Open this Promise's retained comparison or create its first one.")
        payload = _open(_owned(request, identifier)) if row else None
        arguments = _arguments(action, arguments, source)
        if payload:
            _ready(payload, action)
            if action == "check":
                validate(payload["model"], source["qualification_review"]["model"])
        used = _used(parent, budget)
        if action == "check" and (used >= CHECK_LIMIT or not payload["consent"] or digest(source) != payload["source_binding"]):
            raise HTTPException(409, "Review complete current sources and permission first; a spent allowance cannot be reset.")
        return {"id": identifier, "parent": parent, "actor": actor, "context": context, "action": action, "arguments": copy.deepcopy(arguments),
            "source": source, "revision": row["revision"] if row else None, "before": digest(payload), "current": payload,
            "checks_used": used, "expires": time.time() + TTL}


def _guard(request, prepared, budget):
    authority(request, prepared["context"])
    budget.check()
    if time.time() >= prepared["expires"]:
        raise HTTPException(409, "This full review expired before the native writer. Read any admitted original; nothing repeats.")
    source = _source(request, prepared["parent"], budget)
    if digest(source) != digest(prepared["source"]):
        raise HTTPException(409, "The accepted work, additional-work record, rule source or current permission changed. Review current sources.")
    if prepared["action"] == "check":
        model = prepared["current"]["model"]
        if not source["capability_current"] or source["accepted_state"] != "feasible" or not permission_current(model, time.time()):
            raise HTTPException(409, "Complete current demand, cost and use permission or accepted-work support is missing. No old alternatives can be used.")
    return source


def _receipt(prepared):
    return {"action": prepared["action"], "actor": prepared["actor"], "context": prepared["context"], "binding": digest(prepared),
        "recorded_at": time.time(), "state": "unconfirmed", "business_verified": False}


def _reserve(request, prepared, operation, budget):
    receipt = _receipt(prepared)
    if prepared["action"] == "create":
        row = {"id": prepared["id"], "actor": prepared["actor"], "context": prepared["context"], "parent": prepared["parent"], "schema": SCHEMA}
        payload = {"model": prepared["arguments"]["model"], "source_binding": digest(prepared["source"]), "consent": False,
            "removed": False, "checks_used": 0, "pending": operation, "result": None, "operations": {operation: receipt}}
        _seal(row, payload)
        backend = STORE._backend()
        with cross_process_lock(backend._store._dir() / ".namespace-admission", strict=True):
            with cross_process_lock(backend._store._path(prepared["id"]), strict=True):
                _guard(request, prepared, budget)
                return STORE.create(row, action="economics_reserved", actor=prepared["actor"], max_records=100)
    def reserve(row):
        _guard(request, prepared, budget)
        payload = _open(row)
        if row.get("_audit_pending") or digest(payload) != prepared["before"] or len(payload["operations"]) >= 200:
            raise HTTPException(409, "The exact current intent or original custody changed. Read current state.")
        _ready(payload, prepared["action"])
        if prepared["action"] == "check":
            if _used(prepared["parent"], budget) >= CHECK_LIMIT:
                raise HTTPException(409, "The shared lifetime comparison allowance is exhausted.")
            payload["checks_used"] += 1
        payload.update(pending=operation, result=None)
        payload["operations"][operation] = receipt
        _seal(row, payload)
        _guard(request, prepared, budget)
    return STORE.update(prepared["id"], reserve, expected_revision=prepared["revision"], action="economics_reserved", actor=prepared["actor"])


def _finish_payload(payload, prepared, operation, result):
    action, arguments = prepared["action"], prepared["arguments"]
    if action in {"create", "edit"}:
        payload.update(model=arguments["model"], source_binding=digest(prepared["source"]), consent=True)
    elif action == "check":
        payload["result"] = result
    elif action == "scope":
        payload["model"].update(arguments)
        payload.update(consent=arguments["allowed"], source_binding=digest(prepared["source"]))
    elif action in {"withdraw", "remove", "acknowledge"}:
        payload["consent"] = False
        payload["removed"] = action == "remove"
    held = prepared["current"]["pending"] if prepared["current"] else None
    if held and action in {"withdraw", "remove", "acknowledge"}:
        payload["operations"][held]["wait_acknowledged_by"] = operation
    payload["pending"] = None
    payload["operations"][operation].update(state="confirmed", status=result["status"] if result else "recorded",
        alternative_count=len(result["alternatives"]) if result else 0, checks_used=payload["checks_used"])


def apply(request, prepared, operation):
    if type(operation) is not str or re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "An exact original request reference is required.")
    prior = recover(request, prepared, operation)
    if prior:
        return prior
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    with _writer(request, prepared["parent"]):
        prior = recover(request, prepared, operation)
        if prior:
            return prior
        _guard(request, prepared, budget)
        reserved = _reserve(request, prepared, operation, budget)
        if not reserved or reserved.get("_audit_pending"):
            return original(request, prepared["id"], operation)
        result = None
        if prepared["action"] == "check":
            source = _guard(request, prepared, budget)
            result = evaluate(promises._snapshot(source["parent_review"]["model"]), promises._current_versions(source["parent_review"]),
                source["qualification_review"]["model"], source["observations"], prepared["current"]["model"],
                now=time.time(), consent=True, budget=budget)
        def finish(row):
            _guard(request, prepared, budget)
            payload = _open(row)
            if row.get("_audit_pending") or payload["pending"] != operation:
                raise HTTPException(409, "The original completion remains uncertain. Read it without repeating.")
            _finish_payload(payload, prepared, operation, result)
            _seal(row, payload)
            _guard(request, prepared, budget)
        STORE.update(prepared["id"], finish, expected_revision=reserved["revision"], action="economics_" + prepared["action"], actor=prepared["actor"])
        return original(request, prepared["id"], operation)


def view(request, parent):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    with _writer(request, parent):
        actor, context = authority(request)
        source = _source(request, parent, budget)
        identifier = _id(actor, context, parent)
        row = STORE.get(identifier)
        payload = _open(_owned(request, identifier)) if row else None
        current = bool(payload and not payload["removed"] and not payload["pending"] and payload["consent"] and permission_current(payload["model"], time.time())
            and payload["source_binding"] == digest(source) and source["capability_current"] and source["accepted_state"] == "feasible")
        return public({"id": identifier, "parent": parent, "context": context, "source": source, "exists": row is not None,
            "model": payload["model"] if payload and not payload["removed"] else None, "current": current,
            "result": payload["result"] if current else None, "pending": payload["pending"] if payload else None,
            "removed": payload["removed"] if payload else False, "remaining_checks": max(0, CHECK_LIMIT - _used(parent, budget)),
            "author_binding": digest([payload, source]), "notice": NOTICE})


def public(value, *, financial=False):
    """Keep exact integer units through JSON, without converting effort points."""
    if type(value) is list:
        return [public(item, financial=financial) for item in value]
    if type(value) is not dict:
        return value
    financial = financial or ("currency" in value and "unit_scale" in value)
    monetary = {"unit_price", "unit_cost", "fixed_cost", "cost", "shared_cost", "maximum_outlay", "revenue", "variable_cost", "all_in_cost", "total_cost", "contribution"}
    return {key: str(item) if financial and key in monetary and type(item) is int else public(item, financial=financial)
        for key, item in value.items()}


def original(request, identifier, operation, *, binding=None):
    row = _owned(request, identifier, historical=True)
    receipt = _open(row)["operations"].get(operation)
    if receipt is None or binding is not None and not hmac.compare_digest(receipt["binding"], binding):
        raise HTTPException(404, "This exact original is unavailable.")
    authority(request, row["context"], historical=True)
    confirmed = receipt["state"] == "confirmed" and not row.get("_audit_pending")
    return {"context": row["context"], "id": identifier, "parent": row["parent"], "operation": operation, "confirmed": confirmed, "receipt": receipt,
        "message": "The exact original was recorded; no comparison repeated." if confirmed else "The original remains unknown and will not repeat. Its admitted allowance stays spent."}


def recover(request, prepared, operation):
    try:
        return original(request, prepared["id"], operation, binding=digest(prepared))
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise


def history(request):
    actor, context = authority(request, historical=True)
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "The complete original-history bound is exceeded; nothing was omitted.")
    values = [{"value": row["id"] + "|" + operation, "label": ACTIONS[receipt["action"]] + " · " + ("Recorded result" if receipt["state"] == "confirmed" and not row.get("_audit_pending") else "Original unknown")}
        for row in rows if (row.get("actor"), row.get("context")) == (actor, context) for operation, receipt in _open(row)["operations"].items()]
    authority(request, context, historical=True)
    return {"context": context, "choices": values}


def author_handoff(request, parent, context=None, binding=None):
    authority(request, context)
    value = view(request, parent)
    if binding is not None and not hmac.compare_digest(binding, value["author_binding"]):
        raise HTTPException(409, "The complete selected source changed before opening its form.")
    return {"context": value["context"], "parent": parent, "binding": value["author_binding"]}


def changes(prepared):
    rows = [{"label": "Action", "after": ACTIONS[prepared["action"]]}, {"label": "Meaning and limit", "after": NOTICE}]
    rows.extend(capability._parent_business_review(prepared["source"]["parent_review"]))
    rows.extend(capability._current_business_review(prepared["source"]["qualification_review"]))
    if prepared["current"]:
        rows.append({"label": "Earlier complete entered financial assumptions", "after": prepared["current"]["model"]})
    rows.extend([{"label": "Every selected change", "after": prepared["arguments"]},
        {"label": "Shared lifetime comparison allowance", "after": str(prepared["checks_used"]) + " of " + str(CHECK_LIMIT) + " comparisons used. No replacement, removal or stopped wait refunds them."},
        {"label": "Recorded source details", "after": prepared}])
    return public(rows)
