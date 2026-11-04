"""Linked Promise capability learning with scoped sources and exact originals."""
from __future__ import annotations

import contextlib
import copy
import hmac
import json
import math
import re
import time

from fastapi import HTTPException
from maverick import config, crypto_at_rest
from maverick.authority_effects import authority_effect_fence
from maverick.budget import Budget, BudgetExceeded
from maverick.commitment_capability_learning import INPUTS, SCHEMA, evaluate, validate
from maverick.flow import runner
from maverick.flow import store as flows
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore

from . import auth
from . import commitment_viability_store as promises
from .draft_api import context_for

STORE = GovernedRecordStore("commitment-capability", "CCL", "commitment_capability", required_backend="local")
FEATURE = "commitment_capability_learning"
TTL = 600
NOTICE = "Review possible additions for this Promise review. All accepted work is checked together. Reported quantities, availability and permission are your team's assertions; local tests establish only what the selected saved rules return. Choose one consistent unit for all addition cost points and one effort-point scale within this Promise review. Points compare additions and limit tests or trial reports; they are not a charge. No purchase, reservation, acceptance or connected action occurs."
ACTION_NAMES = {"create": "Entered additional-work review", "edit": "Replaced additional-work review", "report": "Recorded completed trial report",
    "test": "Ran local rule qualification", "scope": "Reviewed source permission", "withdraw": "Withdrew observation use",
    "release": "Released waiting for unknown result", "remove": "Removed current qualification"}


def authority(request, context=None, *, historical=False):
    auth.require_permission(request, "operate")
    actor, current = auth.caller_principal(request) or "local:dashboard", context_for(request)
    if context is not None and not hmac.compare_digest(context, current):
        raise HTTPException(409, "Your account or workspace changed. Reload this Promise review.")
    if not historical and (config.config_source_errors(include_tenant=True)
            or config.get_features().get("commitment_viability") is not True
            or config.get_features().get(FEATURE) is not True):
        raise HTTPException(403, "Additional-work learning is off. An administrator can enable it in Settings.")
    return actor, current


def _id(actor, context, parent):
    return "CCL-" + digest([actor, context, parent])[:32]


def _parent(request, identifier):
    actor, context = authority(request)
    try:
        row = promises.get(identifier, context)
    except LookupError as exc:
        raise HTTPException(404, "This Promise review is unavailable.") from exc
    if row.get("owner") != actor:
        raise HTTPException(404, "Only the owner can qualify additions using this Promise review.")
    if row.get("_audit_pending") or row.get("retirement"):
        raise HTTPException(409, "The Promise review is archived or its original activity receipt is pending.")
    return row


def _binding(parent):
    return digest({key: parent.get(key) for key in ("id", "revision", "owner", "context", "model", "sources", "traces", "labels", "retirement")})


def author_handoff(request, parent_id, context=None, parent_binding=None):
    """Read current form authority; never replace a draft or mutate custody."""
    with authority_effect_fence():
        actor, current = authority(request, context)
        with _parent_guard(parent_id):
            parent = _parent(request, parent_id)
            binding = _binding(parent)
            if parent_binding is not None and not hmac.compare_digest(parent_binding, binding):
                raise HTTPException(409, "The accepted-work source changed. Review the current Promise before opening its full form.")
            row = STORE.get(_id(actor, current, parent_id))
            if row and (_open(row).get("removed") or row.get("_audit_pending")):
                raise HTTPException(409, "This qualification is removed or its original activity is pending. Read its earlier original results.")
            authority(request, current)
            return {"context": current, "parent": parent_id, "parent_binding": binding}


@contextlib.contextmanager
def _parent_guard(identifier):
    from maverick.file_lock import cross_process_lock
    backend = promises.STORE._backend()
    if backend.kind != "local":
        raise HTTPException(503, "This bounded qualification currently requires the native local Promise store; a shared source cannot be protected by this local admission.")
    path = backend._store._path(identifier)
    if path is None:
        raise HTTPException(404, "This Promise source is unavailable.")
    with cross_process_lock(path, strict=True):
        yield


def _owned(request, identifier, *, historical=False):
    actor, context = authority(request, historical=historical)
    if not isinstance(identifier, str) or not re.fullmatch(r"CCL-[a-f0-9]{32}", identifier):
        raise HTTPException(404, "This additional-work review is unavailable.")
    row = STORE.get(identifier)
    if not row or (row.get("actor"), row.get("context")) != (actor, context):
        raise HTTPException(404, "This additional-work review is unavailable to your account and workspace.")
    if row.get("_audit_pending"):
        row = STORE._flush(row)
    return row


def _open(row):
    value = json.loads(crypto_at_rest.unseal_from_str(row["envelope"]))
    if value["identity"] != [row["id"], row["actor"], row["context"], row["parent"]]:
        raise HTTPException(409, "The retained source binding could not be verified.")
    return value["payload"]


def _seal(row, payload):
    value = json.dumps({"identity": [row["id"], row["actor"], row["context"], row["parent"]], "payload": payload}, allow_nan=False, separators=(",", ":"))
    if len(value.encode("utf-8")) > 800000:
        raise HTTPException(413, "This complete review exceeds the custody bound. No observations were dropped.")
    row["envelope"] = crypto_at_rest.seal_to_str(value)
    if not crypto_at_rest.is_sealed_str(row["envelope"]):
        raise HTTPException(409, "Turn on stored-data encryption before saving this review.")


def _test_source(request, flow_id):
    from maverick.paths import current_tenant_id_strict

    from . import local_flow_promotions as release
    actor, _context = authority(request)
    release._learning_allowed()
    flow = release._current(current_tenant_id_strict(), actor, flow_id)
    published = flows.load_published_bundle(flow_id)
    if published is None or published[0].owner != actor or published[0].to_dict() != flow.to_dict():
        raise HTTPException(409, "Choose current owned published rules, with Use learned rules only enabled.")
    bundle = release.qualified_bundle(flow)
    # Any complete bounded pure bundle is supported. The owner explicitly
    # chooses its Boolean output; all exact rule source appears in review.
    return {"flow": flow, "bundle": bundle, "publication": published[1], "authority": release._owner_authority(current_tenant_id_strict(), actor),
        "meaning": "Local saved rule execution; not independently verified physical availability."}


def test_choices(request):
    from maverick.paths import current_tenant_id_strict

    from . import local_flow_promotions as release
    actor, context = authority(request)
    if not actor.startswith("user:"):
        return {"context": context, "choices": [], "meaning": "Sign in as an owned workflow account to select published local rules."}
    release._owner_authority(current_tenant_id_strict(), actor)
    rows = flows.list_flow_summaries(owner=actor, bounded=True)
    if len(rows) > 100:
        raise HTTPException(409, "The local picker supports at most one hundred owned workflows. No choices were silently omitted.")
    choices = []
    for row in rows:
        try:
            value = _test_source(request, row["id"])
        except (HTTPException, ValueError, RuntimeError):
            continue
        choices.append({"value": row["id"], "label": value["flow"].name,
            "outputs": sorted({node.output for node in value["flow"].nodes.values() if node.output})})
    return {"context": context, "choices": choices}


def _observations(request, payload):
    rows = copy.deepcopy(payload["observations"])
    for row in rows:
        row["source_current"] = row["quality"] == "operator_reported_trial"
        if row["quality"] == "native_local_rule":
            try:
                source = _test_source(request, row["flow_id"])
                row["source_current"] = row["source"] == _source_identity(source)
            except Exception:
                row["source_current"] = False
    return rows


def _source_identity(source):
    return {"root": source["bundle"]["root"], "bundle": source["bundle"]["bundle_sha"], "manifest": source["bundle"]["manifest"],
        "publication": source["publication"], "authority": source["authority"]}


def _evaluation(request, parent, payload):
    budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
    try:
        observed = _observations(request, payload)
        budget.check()
        return evaluate(promises._snapshot(parent["model"]), promises._current_versions(parent), payload["model"], observed,
            now=time.time(), consent=payload["consent"] and payload["parent_binding"] == _binding(parent) and not payload["removed"] and not payload.get("reservation"),
            tests_used=payload["tests_used"], effort_used=payload["effort_used"], budget=budget)
    except BudgetExceeded:
        return {"accepted_state": "unknown", "surviving_models": [], "current_observations": 0,
            "allowance": {"tests": max(0, payload["model"]["test_limit"] - payload["tests_used"]),
                "effort_points": max(0, payload["model"]["test_effort"] - payload["effort_used"])},
            "frontier": [], "already_supported": [], "next_test": None, "status": "unknown",
            "meaning": "The complete current calculation did not finish within its local time allowance. No previous support result was reused.",
            "reason": "No additional work or useful next test is confirmed until the whole current calculation completes.",
            "comparison": {"method": "Complete current comparison unavailable within its local time allowance", "algorithm_advantage_claimed": False}}


def view(request, parent_id):
    parent = _parent(request, parent_id)
    actor, context = authority(request)
    identifier = _id(actor, context, parent_id)
    row = STORE.get(identifier)
    if not row:
        return {"id": identifier, "parent": parent_id, "context": context, "exists": False, "notice": NOTICE}
    row = _owned(request, identifier)
    payload = _open(row)
    result = {"id": identifier, "parent": parent_id, "context": context, "exists": True, "revision": row["revision"],
        "model": payload["model"], "consent": payload["consent"], "removed": payload["removed"], "observations": _observations(request, payload),
        "evaluation": _evaluation(request, parent, payload), "source_changed": payload["parent_binding"] != _binding(parent),
        "pending": payload.get("pending") or payload.get("reservation"), "originals": [{"operation": key, "action": value["action"], "state": value["state"]} for key, value in payload["operations"].items()],
        "notice": NOTICE}
    authority(request, context)
    return result


def original(request, identifier, operation, *, binding=None):
    row = _owned(request, identifier, historical=True)
    receipt = _open(row)["operations"].get(operation)
    if receipt is None:
        raise HTTPException(404, "This original request has no retained admission.")
    if binding is not None and receipt["binding"] != binding:
        raise HTTPException(409, "This original reference belongs to a different reviewed action.")
    authority(request, row["context"], historical=True)
    confirmed = receipt["state"] == "confirmed" and not row.get("_audit_pending")
    return {"id": identifier, "parent": row["parent"], "context": row["context"], "operation": operation,
        "confirmed": confirmed, "receipt": receipt,
        "message": "This exact original result was recorded. Nothing ran or changed again." if confirmed else
            "The original attempt is unconfirmed. It will not repeat. Review current sources and explicitly release its wait before a separate intentional test."}


def history(request):
    actor, context = authority(request, historical=True)
    rows = STORE.list(limit=101)
    if len(rows) > 100:
        raise HTTPException(409, "This workspace exceeds the one-hundred-review custody bound; no history was dropped.")
    result = []
    for row in rows:
        if (row.get("actor"), row.get("context")) == (actor, context):
            result.extend({"value": row["id"] + "|" + op, "label": receipt.get("parent_name", "Saved Promise review") + " · " + ACTION_NAMES[receipt["action"]] + " · " +
                ("Recorded result" if receipt["state"] == "confirmed" and not row.get("_audit_pending") else "Original result unknown")}
                for op, receipt in _open(row)["operations"].items())
    authority(request, context, historical=True)
    return {"context": context, "choices": result}


def _arguments(action, arguments, payload=None):
    allowed = {"create": None, "edit": None, "report": {"inputs", "outcome", "basis", "expires_at"},
        "test": {"flow_id", "output", "meaning"}, "scope": {"allowed", "expires_at", "basis"},
        "withdraw": {"observation"}, "release": {"acknowledge_unknown"}, "remove": set()}
    if action not in allowed or type(arguments) is not dict:
        raise HTTPException(422, "Choose one complete supported qualification action.")
    if action in {"create", "edit"}:
        validate(arguments)
        now = time.time()
        if not now < arguments["expires_at"] <= now + 30 * 86400 or any(row["due_at"] <= now for row in arguments["offers"]):
            raise HTTPException(422, "Choose future offer and source-review dates, within thirty days for the source.")
        return
    if set(arguments) != allowed[action]:
        raise HTTPException(422, "Enter the complete bounded operation; no fields are silently ignored.")
    if action == "scope":
        if (type(arguments["allowed"]) is not bool or type(arguments["expires_at"]) not in (float, int)
                or not math.isfinite(arguments["expires_at"]) or arguments["expires_at"] <= 0
                or type(arguments["basis"]) is not str or not 10 <= len(arguments["basis"].strip()) <= 2000):
            raise HTTPException(422, "Enter exact source permission, expiry and its basis.")
        if arguments["allowed"] and not time.time() < arguments["expires_at"] <= time.time() + 30 * 86400:
            raise HTTPException(422, "Choose a future source-review time within thirty days.")
    if action == "report":
        inputs = arguments["inputs"]
        if (type(inputs) is not dict or set(inputs) != set(INPUTS) or any(type(value) is not int or not 0 <= value <= 2000000 for value in inputs.values())
                or not 1 <= inputs["offers"] <= 4 or not inputs["offers"] <= inputs["quantity"] <= 4000
                or type(arguments["outcome"]) is not bool or type(arguments["basis"]) is not str or not 10 <= len(arguments["basis"].strip()) <= 2000
                or type(arguments["expires_at"]) not in (float, int) or not time.time() < arguments["expires_at"] <= payload["model"]["expires_at"]):
            raise HTTPException(422, "Enter a completed scoped trial's exact input quantities, Yes/No outcome, basis and current expiry.")
    if action == "test" and (type(arguments["flow_id"]) is not str or type(arguments["output"]) is not str
            or type(arguments["meaning"]) is not str or not 10 <= len(arguments["meaning"].strip()) <= 2000):
        raise HTTPException(422, "Choose current owned rules, their named Yes/No result and exact test meaning.")
    if action == "withdraw" and arguments["observation"] not in {row["id"] for row in payload["observations"]}:
        raise HTTPException(422, "Choose this review's exact observation.")
    if action == "release" and arguments["acknowledge_unknown"] is not True:
        raise HTTPException(422, "Acknowledge that the earlier local attempt remains unknown and a new test would be separate.")


def prepare(request, parent_id, action, arguments):
    with authority_effect_fence():
        actor, context = authority(request)
        parent = _parent(request, parent_id)
        identifier = _id(actor, context, parent_id)
        row = STORE.get(identifier)
        payload = _open(_owned(request, identifier)) if row else None
        if (action == "create") != (row is None):
            raise HTTPException(409, "Open the saved additional-work review or create its first one.")
        _arguments(action, arguments, payload)
        if payload and (row.get("_audit_pending") or payload.get("reservation") and action != "release" or payload["removed"]):
            raise HTTPException(409, "The review is removed or its original admission is unconfirmed. Read its original request.")
        if payload and payload.get("pending") and action not in {"withdraw", "scope", "release", "remove"}:
            raise HTTPException(409, "Read the original local attempt and explicitly release its wait before another observation.")
        selection, test = None, None
        if action in {"test", "report"}:
            from .local_flow_promotions import _learning_allowed
            _learning_allowed()
            evaluation = _evaluation(request, parent, payload)
            if not payload["consent"] or payload["parent_binding"] != _binding(parent) or time.time() >= payload["model"]["expires_at"]:
                raise HTTPException(409, "Review current accepted work and source permission before qualifying another observation.")
            if not evaluation["allowance"]["tests"] or evaluation["allowance"]["effort_points"] < payload["model"]["test_cost"] or len(payload["observations"]) >= 32:
                raise HTTPException(409, "No qualification allowance remains. The result stays unknown; no budget is inferred.")
            if action == "test":
                selection = evaluation["next_test"]
                if not selection:
                    raise HTTPException(409, "No permitted affordable Yes/No test separates the current entered explanations.")
                source = _test_source(request, arguments["flow_id"])
                if arguments["output"] not in {node.output for node in source["flow"].nodes.values() if node.output}:
                    raise HTTPException(422, "Choose a named result from these exact owned rules.")
                test = {**_source_identity(source), "definition": source["flow"].to_dict(),
                    "included": [flow.to_dict() for flow in source["bundle"]["flows"][1:]]}
        return {"id": identifier, "parent": parent_id, "actor": actor, "context": context, "action": action, "arguments": copy.deepcopy(arguments),
            "revision": row["revision"] if row else None, "source": digest(payload) if payload else None, "parent_binding": _binding(parent),
            "parent_review": {key: parent.get(key) for key in ("title", "model", "sources", "traces", "labels")},
            "current_review": copy.deepcopy(payload), "selection": selection, "test": test, "expires": time.time() + TTL}


def _review_value(value, key=""):
    from datetime import datetime, timezone

    from .flow_requalification import _display
    if type(value) is dict:
        return "\n".join(str(name).replace("_", " ") + ": " + _review_value(child, name) for name, child in value.items())
    if type(value) is list:
        return "\n".join(str(index + 1) + ". " + _review_value(child, key) for index, child in enumerate(value))
    if key in {"due_at", "ready_at", "expires_at", "observed_at", "recorded_at", "published_at", "entered_at", "review_by"} and type(value) in (int, float):
        try:
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            return "Date outside supported display range"
    return _display(value)


def _business_model_review(model, prefix):
    result = []
    for offer in model["offers"]:
        result.append({"label": prefix + " · additional offer", "after": offer["label"] + ": " + str(offer["units"]) + " work units, due " + _review_value(offer["due_at"], "due_at")})
    for key, label in (("material_per_unit", "Possible material units per work unit"), ("capacity_per_unit", "Possible work-capacity units per work unit"), ("shared_setup", "Possible setup capacity when offers are combined")):
        result.append({"label": prefix + " · " + label, "after": ", ".join(map(str, model["requirements"][key]))})
    for addition in model["additions"]:
        result.append({"label": prefix + " · possible addition", "after": addition["label"] + ": " + str(addition["units"]) +
            (" material units" if addition["kind"] == "material" else " work-capacity units") + ", possibly ready " + _review_value(addition["ready_at"], "ready_at") +
            "; declared cost " + str(addition["cost"]) + " points. Reported availability and permission: " + addition["basis"]})
    for key, label in (("max_addition_cost", "Maximum declared addition cost points"), ("test_limit", "Shared test allowance"), ("test_effort", "Shared effort allowance"), ("test_cost", "Effort points per test or trial report"), ("expires_at", "Review source permission again by"), ("basis", "Reported facts and source-permission basis")):
        result.append({"label": prefix + " · " + label, "after": _review_value(model[key], key)})
    return result


def _parent_business_review(parent):
    result = []
    labels = parent["labels"]
    result.append({"label": "Promise review whose accepted work is protected", "after": parent["title"]})
    for order in parent["model"]["commitments"]:
        result.append({"label": "Accepted order · " + labels.get(order["id"], "Accepted work"), "after": "Due " + _review_value(order["due_at"], "due_at") +
            ". Entered requirements: " + "; ".join(str(part["units"]) + " units of " + labels.get(part["key"], part["kind"]) for part in order["demands"]) +
            ". Review its acceptance source again by " + _review_value(order["acceptance"]["expires_at"], "expires_at")})
    for lot in parent["model"]["lots"]:
        result.append({"label": "Reported resource · " + labels.get(lot["key"], lot["kind"]), "after": str(lot["units"]) +
            " units; " + {"confirmed": "team reports available", "unknown": "availability unknown", "unavailable": "team reports unavailable"}[lot["certainty"]] +
            "; ready " + _review_value(lot["ready_at"], "ready_at") + "; review source again by " + _review_value(lot["evidence"]["expires_at"], "expires_at")})
    for source in parent["sources"]:
        result.append({"label": "Reported source and permission", "after": source["basis"] + "\nEntered by " + source["entered_by"] +
            " on " + _review_value(source["entered_at"], "entered_at") + "; review again by " + _review_value(source["review_by"], "review_by")})
    for edge in parent["model"]["dependencies"]:
        result.append({"label": "Confirmed shared work requirement", "after": labels.get(edge["left_id"], "Accepted order") + " needs " + str(edge["left_units"]) +
            " units and " + labels.get(edge["right_id"], "Accepted order") + " needs " + str(edge["right_units"]) + " units of " + labels.get(edge["resource_key"], "Work capacity")})
    for option in parent["model"]["options"]:
        result.append({"label": "Existing conditional choice excluded from this calculation", "after": labels.get(option["id"], "Conditional choice") +
            ": " + str(option["units"]) + " possible " + option["kind"] + " units, ready " + _review_value(option["ready_at"], "ready_at") +
            ", expires " + _review_value(option["expires_at"], "expires_at") + ". " + option["cost_note"] + ". Recording or owner intent does not establish availability."})
    return result


def _current_business_review(payload):
    result = _business_model_review(payload["model"], "Current entered review")
    result.append({"label": "Current qualification permission and used allowance", "after": ("Allowed" if payload["consent"] else "Withdrawn") +
        "; " + str(payload["tests_used"]) + " tests and " + str(payload["effort_used"]) + " effort points already used. These are not refunded by a replacement or release."})
    for observation in payload["observations"]:
        result.append({"label": "Recorded local rule result" if observation["quality"] == "native_local_rule" else "Reported completed trial", "after":
            ("Yes" if observation["outcome"] else "No") + ". " + observation["basis"] + ". Recorded " + _review_value(observation["observed_at"], "observed_at") +
            "; review again by " + _review_value(observation["expires_at"], "expires_at") + "; reuse permission " + ("allowed only while its exact source remains current" if observation["consent"] else "withdrawn") +
            ". Trial inputs: " + _review_value(observation["inputs"])})
    return result


def changes(prepared):
    from .flow_requalification import _source_review
    result = [{"label": "Action", "after": {"create": "Enter competing explanations and possible additions", "edit": "Replace the entered review; prior observations become historical", "report": "Record a completed local trial report", "test": "Run one owned published local rule test", "scope": "Review source permission and expiry", "withdraw": "Stop using one observation", "release": "Release the wait for an unknown original attempt", "remove": "Remove current qualification permission"}[prepared["action"]]},
        {"label": "Meaning and limit", "after": NOTICE}]
    result.extend(_parent_business_review(prepared["parent_review"]))
    if prepared["current_review"]:
        result.extend(_current_business_review(prepared["current_review"]))
    if prepared["action"] in {"create", "edit"}:
        result.extend(_business_model_review(prepared["arguments"], "Proposed entered review"))
    else:
        ordinary = {"allowed": "Permission to use the current entered facts", "expires_at": "Review this source again by", "basis": "Exact report and permission basis",
            "outcome": "Completed trial supported the entered work", "inputs": "Completed trial input quantities", "flow_id": "Selected owned local rules", "output": "Named Yes/No result", "meaning": "Exact local-test meaning and permission", "acknowledge_unknown": "Acknowledged that the earlier outcome remains unknown"}
        for key, value in prepared["arguments"].items():
            if key == "observation":
                observation = next(row for row in prepared["current_review"]["observations"] if row["id"] == value)
                result.append({"label": "Observation whose future use stops", "after": observation["basis"] + "; recorded " + _review_value(observation["observed_at"], "observed_at")})
            else:
                result.append({"label": ordinary[key], "after": prepared["test"]["definition"]["name"] if key == "flow_id" else _review_value(value, key)})
    if prepared["action"] == "release":
        payload = prepared["current_review"]
        held = payload.get("pending") or payload.get("reservation")
        original = payload["operations"][held]
        result.append({"label": "Earlier unknown original attempt", "after": ACTION_NAMES[original["action"]] + "; recorded " + _review_value(original["recorded_at"], "recorded_at") +
            ". The earlier outcome remains unknown. This release does not confirm it or refund its qualification allowance. Any next test is a separate intentional attempt after current source review."})
    if prepared["selection"]:
        selected = prepared["selection"]
        model = prepared["current_review"]["model"]
        names = {row["id"]: row["label"] for row in model["offers"] + model["additions"]}
        result.append({"label": "One useful local test and its exact shared allowance", "after": "Combined additional offers: " + ", ".join(names[identity] for identity in selected["offers"]) +
            ". Hypothetical additions: " + (", ".join(names[identity] for identity in selected["additions"]) or "None") +
            ". Total additional work: " + str(selected["inputs"]["quantity"]) + "; combined offer count: " + str(selected["inputs"]["offers"]) +
            "; remaining material: " + str(selected["inputs"]["material"]) + "; remaining work capacity: " + str(selected["inputs"]["capacity"]) +
            ". Consumes one qualification test and " + str(selected["effort_points"]) + " effort points. " + selected["objective"]})
    if prepared["test"]:
        result.extend(_source_review(flows.load_flow_snapshot(prepared["test"]["root"]), prepared["test"]["manifest"], "Owned published test source"))
    # Preserve the complete exact native material behind an ordinary collapsed
    # source-details view; no opaque identity replaces the business review.
    result.append({"label": "Recorded source details · exact accepted-work record", "after": _review_value(prepared["parent_review"])})
    if prepared["current_review"]:
        result.append({"label": "Recorded source details · complete earlier qualification record", "after": _review_value(prepared["current_review"])})
    result.append({"label": "Recorded source details · exact reviewed identity and source binding", "after": _review_value({key: value for key, value in prepared.items() if key not in {"parent_review", "current_review"}})})
    return result


def recover(request, prepared, operation):
    try:
        return original(request, prepared["id"], operation, binding=digest(prepared))
    except HTTPException as exc:
        if exc.status_code == 404:
            return None
        raise


def _guard_admission(request, prepared, context, *, deadline=True, source=True):
    authority(request, context)
    parent = _parent(request, prepared["parent"])
    if source and _binding(parent) != prepared["parent_binding"]:
        raise HTTPException(409, "The entire accepted-work source or its grants changed. Review current sources again.")
    if deadline and time.time() >= prepared["expires"]:
        raise HTTPException(409, "The complete review expired before the native change. Nothing will repeat.")
    if prepared["action"] in {"create", "edit", "report", "test"}:
        model = prepared["arguments"] if prepared["action"] in {"create", "edit"} else prepared["current_review"]["model"]
        if time.time() >= model["expires_at"] or any(time.time() >= row["due_at"] for row in model["offers"]):
            raise HTTPException(409, "The reviewed offer or source permission expired before its native admission.")
    if prepared["test"]:
        if _source_identity(_test_source(request, prepared["arguments"]["flow_id"])) != {key: prepared["test"][key] for key in ("root", "bundle", "manifest", "publication", "authority")}:
            raise HTTPException(409, "The owned rule source, publication or permission changed before this local test.")
    if prepared["action"] in {"report", "test"}:
        from dataclasses import replace

        from maverick.commitment_viability import assess

        from .local_flow_promotions import _learning_allowed
        _learning_allowed()
        if assess(replace(promises._snapshot(parent["model"]), options=()), now=time.time(),
                current_source_revisions=promises._current_versions(parent)).status != "feasible":
            raise HTTPException(409, "Accepted work or its source freshness is no longer confirmed. The qualification stays unknown.")
    return parent


def _claim_qualification_allowance(request, prepared, parent, payload):
    action = prepared["action"]
    current_check = _evaluation(request, parent, payload)
    if not payload["consent"] or payload["parent_binding"] != _binding(parent) or payload.get("pending"):
        raise HTTPException(409, "The current source grant or original attempt changed.")
    if not current_check["allowance"]["tests"] or current_check["allowance"]["effort_points"] < payload["model"]["test_cost"] or len(payload["observations"]) >= 32:
        raise HTTPException(409, "The qualification allowance is exhausted. The result stays unknown.")
    if action == "test" and current_check["next_test"] != prepared["selection"]:
        raise HTTPException(409, "The useful test or source freshness changed. Review the exact current test.")
    payload["tests_used"] += 1
    payload["effort_used"] += payload["model"]["test_cost"]


def _updated_action(current, *, request, prepared, operation, actor, receipt, guard, complete):
    parent = guard()
    payload = _open(current)
    if current.get("_audit_pending") or digest(payload) != prepared["source"] or len(payload["operations"]) >= 200:
        raise HTTPException(409, "The observation, original custody or allowance changed. Review current sources.")
    _arguments(prepared["action"], prepared["arguments"], payload)
    action, arguments = prepared["action"], prepared["arguments"]
    if action in {"report", "test"}:
        _claim_qualification_allowance(request, prepared, parent, payload)
    if action == "edit":
        payload.update(model=copy.deepcopy(arguments), parent_binding=prepared["parent_binding"], consent=True)
        for observation in payload["observations"]:
            observation["consent"] = False
    elif action == "scope":
        payload["consent"] = arguments["allowed"]
        payload["model"]["expires_at"] = arguments["expires_at"]
        payload["model"]["basis"] = arguments["basis"]
        payload["parent_binding"] = prepared["parent_binding"]
        # Changed meaning/freshness is a new grant, never an
        # inferred renewal of an old observation's permission.
        for observation in payload["observations"]:
            observation["consent"] = False
    elif action == "withdraw":
        next(row for row in payload["observations"] if row["id"] == arguments["observation"])["consent"] = False
    elif action == "release":
        held = payload.get("pending") or payload.get("reservation")
        if not held:
            raise HTTPException(409, "There is no retained unknown attempt to release.")
        payload["operations"][held]["wait_released_by"] = operation
        payload["pending"] = None
        if payload.pop("reservation", None):
            # A released create reservation is still not an
            # admitted source grant. A fresh complete edit or
            # scope review must intentionally admit current use.
            payload["consent"] = False
    elif action == "remove":
        payload.update(removed=True, consent=False)
        for observation in payload["observations"]:
            observation["consent"] = False
    elif action == "report":
        payload["observations"].append({"id": operation, "inputs": arguments["inputs"], "outcome": arguments["outcome"],
            "basis": arguments["basis"], "observed_at": time.time(), "expires_at": arguments["expires_at"], "consent": True,
            "model": digest(payload["model"]), "quality": "operator_reported_trial", "source_current": True, "entered_by": actor})
    elif action == "test":
        payload["pending"] = operation
        payload["operations"][operation] = {**receipt, "state": "unconfirmed", "test_inputs": prepared["selection"]["inputs"],
            "source": {key: prepared["test"][key] for key in ("root", "bundle", "manifest", "publication", "authority")}}
        _seal(current, payload)
        guard()
        return
    complete(current, payload, {"action": action, "observation": operation if action == "report" else None})


def apply(request, prepared, operation):
    if type(operation) is not str or re.fullmatch(r"[a-f0-9]{32}", operation) is None:
        raise HTTPException(422, "The exact original request reference is missing.")
    with authority_effect_fence(), _parent_guard(prepared["parent"]), flows._definitions_lock():
        actor, context = authority(request, prepared["context"])
        if actor != prepared["actor"]:
            raise HTTPException(403, "Only the person who reviewed this exact change may confirm it.")
        prior = recover(request, prepared, operation)
        if prior:
            return prior
        def guard(*, deadline=True, source=True):
            return _guard_admission(request, prepared, context, deadline=deadline, source=source)
        guard()
        receipt = {"action": prepared["action"], "binding": digest(prepared), "actor": actor, "context": context,
            "parent_name": prepared["parent_review"].get("title", "Saved Promise review"),
            "reviewed_parent": prepared["parent_binding"], "recorded_at": time.time(), "state": "unconfirmed", "business_verified": False}
        def complete(row, payload, result):
            payload["operations"][operation] = {**receipt, "state": "confirmed", "result": result,
                "tests_used": payload["tests_used"], "effort_points_used": payload["effort_used"]}
            _seal(row, payload)
            guard()
        if prepared["action"] == "create":
            payload = {"model": copy.deepcopy(prepared["arguments"]), "parent_binding": prepared["parent_binding"], "consent": True,
                "observations": [], "tests_used": 0, "effort_used": 0, "pending": None, "removed": False,
                "operations": {operation: receipt}, "reservation": operation}
            row = {"id": prepared["id"], "actor": actor, "context": context, "parent": prepared["parent"], "schema": SCHEMA}
            _seal(row, payload)
            guard()
            reserved = STORE.create(row, action="capability_reserved", actor=actor, max_records=100)
            def admit(current):
                guard()
                value = _open(current)
                if current.get("_audit_pending") or value.get("reservation") != operation:
                    raise HTTPException(409, "The original admission is uncertain. Read its original request.")
                del value["reservation"]
                complete(current, value, {"entered": True})
            STORE.update(row["id"], admit, expected_revision=reserved["revision"], action="capability_entered", actor=actor)
        else:
            from functools import partial

            effect = partial(_updated_action, request=request, prepared=prepared, operation=operation, actor=actor,
                             receipt=receipt, guard=guard, complete=complete)
            claimed = STORE.update(prepared["id"], effect, expected_revision=prepared["revision"], action="capability_" + prepared["action"], actor=actor)
            if prepared["action"] == "test" and claimed and not claimed.get("_audit_pending"):
                budget = Budget(max_wall_seconds=15, max_dollars=0, max_tool_calls=0)
                count = [0]
                def execution_guard(*_args):
                    budget.check()
                    count[0] += 1
                    if count[0] > 512:
                        raise ValueError("This local test exceeded its bounded step allowance.")
                    guard()
                def refuse(*_args):
                    raise ValueError("This qualification never calls AI or connected actions.")
                pinned = flows.load_flow_snapshot(prepared["test"]["root"])
                execution_guard()
                result = runner.run_flow(pinned, data=prepared["selection"]["inputs"], agent_fn=refuse, action_fn=refuse,
                    resolve_flow=lambda identity: flows.load_flow_snapshot(prepared["test"]["manifest"].get(identity, "")),
                    run_id=prepared["id"] + "-" + operation, on_node=execution_guard)
                execution_guard()
                output = result.data.get(prepared["arguments"]["output"])
                known = result.status == runner.STATUS_COMPLETED and type(output) is bool
                def finish(current):
                    guard()
                    payload = _open(current)
                    if payload.get("pending") != operation or current.get("_audit_pending"):
                        raise HTTPException(409, "The exact original local admission changed. Its result remains unknown.")
                    if known:
                        payload["observations"].append({"id": operation, "inputs": prepared["selection"]["inputs"], "outcome": output,
                            "basis": prepared["arguments"]["meaning"], "observed_at": time.time(), "expires_at": payload["model"]["expires_at"],
                            "consent": True, "model": digest(payload["model"]), "quality": "native_local_rule", "source_current": True,
                            "flow_id": prepared["arguments"]["flow_id"], "source": {key: prepared["test"][key] for key in ("root", "bundle", "manifest", "publication", "authority")},
                            "entered_by": actor, "native_receipt": digest([result.status, result.data, prepared["selection"]["inputs"], prepared["test"]["root"]])})
                    payload["pending"] = None
                    complete(current, payload, {"native_state": result.status, "outcome": output if known else None,
                        "known": known, "local_steps": count[0], "native_request": prepared["id"] + "-" + operation,
                        "meaning": "Saved local rules returned this result; no physical resource or revenue was verified."})
                STORE.update(prepared["id"], finish, expected_revision=claimed["revision"], action="capability_test_recorded", actor=actor)
        return original(request, prepared["id"], operation, binding=digest(prepared))
